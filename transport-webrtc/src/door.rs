// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `webrtc` DOOR: this transport as a DATAGRAM FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`, its datagram lane `abi::transport::datagram`). Every slot is
//! a [`SafeSlot`] over the SDK's generic lifecycle: no `unsafe` here.
//!
//! * `begin`: [`SIDE_ACCEPT`] (answers an offer) or [`SIDE_DIAL`] (yields its offer at once, on
//!   stream 0). The host's certificate comes in [`ConnFacts::local_certificate`] (public DER; its
//!   fingerprint is what the description states), the host port's address in the lane. A dialling
//!   framing's opening fields name what it offers: one `channel` field per data channel (its label,
//!   streams `1, 2, ...` in order) and `media: audio` for one Opus line (stream `MEDIA_BASE`).
//! * `ingest`: one datagram, or the far end's description, as the lane names it; the lane's host
//!   state (bound path, verified bit, keying-material item, new paths) is read first, on every call
//!   that carries a lane.
//! * `emit`: one message for a stream (a channel's message, an Opus frame for a media line),
//!   gathered until `end_of_frame`; [`EMIT_TEXT`] marks a channel message as text. A channel whose
//!   held messages reach the framing's high-water mark answers [`YIELD_STREAM_FULL`] and is
//!   writable again with a [`PIECE_WRITABLE`] piece; a channel that cannot carry a message fails
//!   alone, with a [`PIECE_STREAM_FAILED`] piece.
//! * `timer`: the clock; `finish`: the association closes.
//! * `locate`, `encode`, `refuse`, `detach`, `adopt`: FAILED with the reason (no authority to dial,
//!   no envelope, no upgrade); every carrier op: REFUSED (`not_served!`).
//!
//! A full host buffer is back-pressure: READY with [`YIELD_MORE`], and the re-call carries no new
//! bytes. No op pends.

use core::net::SocketAddr;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::settings_reading;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::check::check_keying;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnFacts, ConnIn,
    ConnOut, DatagramLane, DatagramRoute, DatagramYield, DialIn, EmitIn, EncodeIn, FinishIn,
    FramePiece, FrameSpan, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, RendezvousTerms, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, EMIT_TEXT, FRAME_PIECE_SIZE, FRAMING_DATAGRAM, HANDSHAKE_ANSWERS,
    HANDSHAKE_INITIATES, LANE_CLEAR, LANE_RENDEZVOUS, LANE_SECURED, PATH_REQUEST_BIND,
    PATH_REQUEST_REBIND, PIECE_CONTINUED, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS,
    PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL,
    UNIT0_FIRST_DATAGRAM, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};

use crate::framing::{Framing, Lane, Opening, Piece, Request, Side, MAX_MESSAGE};

/// The claim this entry answers for.
pub const KEY: &str = "webrtc";

const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// The claim's row: no selector forms (an association is reached through the rendezvous, never
/// selected on its datagrams), a session whose first unit opens on its first datagram.
const CLAIMS: &[Claim] = &[{
    let mut c = Claim::EMPTY;
    c.selector_forms = abi_str("");
    c.egress_selector_forms = abi_str("");
    c.session = 1;
    c.session_bound = 1;
    c.unit0_trigger = UNIT0_FIRST_DATAGRAM;
    c
}];

/// The transport kind's tail: a datagram framer, composing over nothing (the port is the host's).
const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY.with_claim_rows(CLAIMS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_DATAGRAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};

/// The door's Statement.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

/// One association's framing and the host clock it is read against.
struct Held1 {
    f: Framing,
    base_ns: u64,
    base: Instant,
    /// A message being gathered, per stream (whether it is text is its completing call's).
    gathering: HashMap<u64, Vec<u8>>,
    /// A piece split across calls: the bytes not yet written, and whether they continue a field
    /// line an earlier piece began.
    partial: Option<(Piece, bool)>,
}

impl Held1 {
    fn at(&self, ns: u64) -> Instant {
        self.base + Duration::from_nanos(ns.saturating_sub(self.base_ns))
    }

    fn ns(&self, t: Instant) -> u64 {
        let d = t.saturating_duration_since(self.base);
        self.base_ns
            .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .max(1)
    }
}

/// One association behind its own lock, so one association's crypto never waits on another's:
/// `None` once it is forgotten.
type Slot = Arc<Mutex<Option<Held1>>>;

/// The framings one instance holds.
pub struct Framings {
    framings: Mutex<HashMap<u64, Slot>>,
    next: AtomicU64,
}

type State = Held<Framings>;

/// This framer reads no setting: a JSON object (or empty), every key refused.
fn no_settings(settings: &[u8]) -> Result<(), Refusal> {
    settings_reading(settings, &[]).map(drop)
}

impl Life for Framings {
    /// No framer op pends, so a cancel finds nothing in flight.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        no_settings(settings)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        no_settings(settings)?;
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        no_settings(settings)?;
        Ok(Refreshed::default())
    }
}

impl Framings {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Slot>> {
        self.framings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slot(&self, token: u64) -> Option<Slot> {
        self.lock().get(&token).cloned()
    }
}

/// The association's lock. A panic that unwound while an op held it left the state torn: the
/// association is forgotten (its slot emptied, the poison cleared), never served torn.
fn hold(slot: &Mutex<Option<Held1>>) -> MutexGuard<'_, Option<Held1>> {
    slot.lock().unwrap_or_else(|torn| {
        let mut held = torn.into_inner();
        *held = None;
        slot.clear_poison();
        held
    })
}

fn framings<'a>(i: &Instance<'a, State>) -> Result<&'a Framings, Refusal> {
    i.get()
        .map(Held::life)
        .ok_or_else(|| Refusal::failed("no open instance"))
}

fn addr(s: Lent<'_, AbiStr>) -> Option<SocketAddr> {
    s.as_str().ok()?.parse().ok()
}

/// Read the lane's host state into the framing: new paths, the bound path, the verified bit and
/// the keying-material item.
fn host_state(h: &mut Held1, lane: Lent<'_, DatagramLane>, now: Instant) -> Result<(), String> {
    if let Some(a) = addr(lane.field(|l| &l.local_addr)) {
        h.f.local(a);
    }
    h.f.paths(
        lane.paths()
            .iter()
            .filter_map(|p| Some((p.path, addr(p.field(|x| &x.addr))?))),
    );
    let keying = match lane.keying() {
        Some(k) => {
            check_keying(&k)
                .map_err(|f| format!("the keying-material item is malformed: {}", f.field))?;
            Some((k.profile, k.bytes()))
        }
        None => None,
    };
    h.f.host(lane.bound, lane.verified == 1, keying, now)
}

/// Answer into the sink and the lane what the framing owes: routes (bytes in `wire`), pieces (bytes
/// in `frame`), the rendezvous terms, one path request, the deadline, and the flags.
///
/// # Errors
///
/// A datagram that even an empty wire buffer, or rendezvous terms that even an empty frame buffer,
/// could not hold whole: the framing fails rather than answer YIELD_MORE with no progress.
fn answer(
    h: &mut Held1,
    sink: Lent<'_, FramerSink>,
    lane: Option<Lent<'_, DatagramLane>>,
    now_ns: u64,
    o: &mut Out<'_, FramerOut>,
) -> Result<(), String> {
    let mut wire = sink.wire();
    let mut frame = sink.frame();
    let mut pieces = sink.pieces();
    let mut d = DatagramYield::default();
    let mut more = false;

    // Routes: only through a lane's buffer; a stream host gets none.
    if let Some(lane) = lane {
        let mut routes = lane.routes();
        while let Some(r) = h.f.next_route() {
            if r.bytes.len() > wire.cap() {
                // Even an empty wire buffer could never hold it: YIELD_MORE would be a re-call
                // loop with no progress.
                return Err(
                    "a datagram the media stack sends does not fit the host's wire buffer".into(),
                );
            }
            let room = wire.cap().saturating_sub(wire.asked());
            if routes.asked() >= routes.cap() || room < r.bytes.len() {
                h.f.unroute(r);
                more = true;
                break;
            }
            let at = wire.extend(&r.bytes);
            routes.push(DatagramRoute {
                offset: at as u64,
                len: r.bytes.len() as u64,
                path: r.path,
                lane: match r.lane {
                    Lane::Clear => LANE_CLEAR,
                    Lane::Secured => LANE_SECURED,
                },
            });
        }
        d.routes_len = u32::try_from(routes.asked()).unwrap_or(u32::MAX);
        if let Some(req) = h.f.take_request() {
            (d.request, d.request_from, d.request_to) = match req {
                Request::Bind(p) => (PATH_REQUEST_BIND, 0, p),
                Request::Rebind(a, b) => (PATH_REQUEST_REBIND, a, b),
            };
        }
    }

    // The terms first, whole, so their spans are in this answer's frame.
    if let Some(t) = h.f.take_terms() {
        let parts: [&[u8]; 6] = [
            t.local_user.as_bytes(),
            t.local_secret.as_bytes(),
            t.remote_user.as_bytes(),
            t.remote_secret.as_bytes(),
            &t.peer_fingerprint,
            &[],
        ];
        let candidates: String = t.candidates.iter().map(|c| format!("{c}\n")).collect();
        let total: usize = parts.iter().map(|p| p.len()).sum::<usize>() + candidates.len();
        if frame.cap().saturating_sub(frame.asked()) >= total {
            let mut span = |b: &[u8]| FrameSpan {
                offset: frame.extend(b) as u64,
                len: b.len() as u64,
            };
            d.terms = RendezvousTerms {
                role: if t.initiates {
                    HANDSHAKE_INITIATES
                } else {
                    HANDSHAKE_ANSWERS
                },
                _reserved: 0,
                local_user: span(parts[0]),
                local_secret: span(parts[1]),
                remote_user: span(parts[2]),
                remote_secret: span(parts[3]),
                peer_fingerprint: span(parts[4]),
                candidates: if candidates.is_empty() {
                    FrameSpan::default()
                } else {
                    span(candidates.as_bytes())
                },
            };
        } else if total > frame.cap() {
            return Err("the rendezvous terms do not fit the host's frame buffer".into());
        } else {
            // Not room for them whole: the host drains and calls again.
            h.f.restore_terms(t);
            more = true;
        }
    }

    // Pieces.
    while let Some((mut p, continued)) = h
        .partial
        .take()
        .or_else(|| h.f.next_piece().map(|p| (p, false)))
    {
        let room = frame.cap().saturating_sub(frame.asked());
        if p.failed && p.bytes.len() > room && frame.asked() == 0 {
            // A failure's reason is never split: one longer than the whole buffer is cut to it.
            p.bytes.truncate(room);
        }
        if pieces.asked() >= pieces.cap() || (room == 0 && !p.bytes.is_empty()) {
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let whole = p.bytes.len() <= room;
        if !whole && (p.fields || p.failed) && frame.asked() != 0 {
            // A field block, or a failure's reason, starts a fresh answer rather than be split
            // (or cut) mid-buffer.
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let n = p.bytes.len().min(room);
        let at = frame.extend(&p.bytes[..n]);
        let flags = piece_flags(&p, continued, whole);
        pieces.push(FramePiece {
            stream: p.stream,
            offset: at as u64,
            len: n as u64,
            code: 0,
            status_class: 0,
            fault: 0,
            flags,
            retry_after_secs: 0,
            declared_len: 0,
        });
        if !whole {
            p.bytes.drain(..n);
            // The rest of a field block continues the line this piece may have split.
            let continues = p.fields;
            h.partial = Some((p, continues));
            more = true;
            break;
        }
    }
    o.set(|o| &o.yielded.wire_len, wire.asked() as u64);
    o.set(|o| &o.yielded.frame_len, frame.asked() as u64);
    o.set(
        |o| &o.yielded.pieces_len,
        u32::try_from(pieces.asked()).unwrap_or(u32::MAX),
    );
    o.set(|o| &o.datagram, d);
    let mut flags = 0;
    more |= h.f.owes() || h.partial.is_some();
    if more {
        flags |= YIELD_MORE;
    } else if h.f.ended() {
        flags |= YIELD_ENDED;
    }
    if let Some(t) = h.f.next_timeout() {
        let ns = h.ns(t).max(now_ns.saturating_add(1));
        flags |= YIELD_HAS_DEADLINE;
        o.set(|o| &o.yielded.next_deadline_ns, ns);
    }
    o.set(|o| &o.yielded.flags, flags);
    Ok(())
}

/// Run `op` on the framing `token` names, then answer what it owes, with the yield flags `op`
/// answers besides.
fn with(
    inst: &Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    lane: Option<Lent<'_, DatagramLane>>,
    o: &mut Out<'_, FramerOut>,
    op: impl FnOnce(&mut Held1, Instant) -> Result<u32, String>,
) -> Outcome {
    let s = match framings(inst) {
        Ok(s) => s,
        Err(r) => return o.fail(r),
    };
    let Some(slot) = s.slot(token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    let torn = slot.is_poisoned();
    let mut held = hold(&slot);
    let Some(h) = held.as_mut() else {
        if torn {
            s.lock().remove(&token);
            return o.fail(Refusal::failed(
                "the association's state was torn by a panic: it is forgotten",
            ));
        }
        return o.fail(Refusal::failed("no such framing"));
    };
    let now_ns = sink.now_monotonic_ns;
    let now = h.at(now_ns);
    let run = match lane {
        Some(l) => host_state(h, l, now).and_then(|()| op(h, now)),
        None => op(h, now),
    }
    .and_then(|extra| match h.f.failure() {
        Some(why) => Err(why.to_owned()),
        None => answer(h, sink, lane, now_ns, o).map(|()| extra),
    });
    match run {
        Ok(extra) => {
            if extra != 0 {
                let flags = o.get().yielded.flags;
                o.set(|o| &o.yielded.flags, flags | extra);
            }
            Outcome::Ready
        }
        Err(why) => {
            *held = None;
            s.lock().remove(&token);
            o.fail(Refusal::failed(why))
        }
    }
}

busbar_contract::not_served! {
    state: State, role: "webrtc framer";
    /// `listen`: the port is the host's.
    NoListen(ListenIn => ListenOut) "listen";
    /// `accept`: the port is the host's.
    NoAccept(AcceptIn => AcceptOut) "accept";
    /// `dial`: the port is the host's.
    NoDial(DialIn => ConnOut) "dial";
    /// `read`: the port is the host's.
    NoRead(ReadIn => IoOut) "read";
    /// `write`: the port is the host's.
    NoWrite(WriteIn => IoOut) "write";
    /// `flush`: the port is the host's.
    NoFlush(ConnIn => OutHead) "flush";
    /// `shut`: the port is the host's.
    NoShut(ShutIn => OutHead) "shut";
    /// `arrival`: the port is the host's.
    NoArrival(ArrivalIn => ArrivalOut) "arrival";
}

/// A framer op this framer has no use for: FAILED with its reason.
pub struct Unused<I>(PhantomData<I>);

/// Why each unused op is refused.
pub trait Why {
    /// The reason.
    const WHY: &'static str;
}

impl Why for EncodeIn {
    const WHY: &'static str = "encode: an association carries no envelope";
}
impl Why for RefuseIn {
    const WHY: &'static str = "refuse: an association's refusal is the signalling unit's";
}
impl Why for AdoptIn {
    const WHY: &'static str = "adopt: an association is begun at its rendezvous, never adopted";
}

impl<I: AbiIn + Why> SafeSlot for Unused<I> {
    type In = I;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, mut o: Out<'_, FramerOut>) -> Outcome {
        o.fail(Refusal::failed(I::WHY))
    }
}

/// `locate`: FAILED. An association's far end comes from its description, judged by the host.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, LocateIn>, mut o: Out<'_, LocateOut>) -> Outcome {
        o.fail(Refusal::failed(
            "locate: an association's far end comes from its description, not a target",
        ))
    }
}

/// What a dialling framing's opening fields offer.
fn opening(i: &Lent<'_, BeginIn>) -> Opening {
    let mut o = Opening::default();
    for f in i.fields().iter() {
        let (Ok(name), Ok(value)) = (
            f.field(|x| &x.name).as_str(),
            f.field(|x| &x.value).as_str(),
        ) else {
            continue;
        };
        match name {
            "channel" if !value.is_empty() => o.channels.push(value.to_owned()),
            "media" if value == "audio" => o.audio = true,
            _ => {}
        }
    }
    o
}

/// The host's public certificate, from the facts.
fn certificate<'a>(i: &Lent<'a, BeginIn>) -> Option<&'a [u8]> {
    let facts: Lent<'a, ConnFacts> = i.facts()?;
    if (facts.size as usize) < std::mem::size_of::<ConnFacts>() {
        return None;
    }
    let der = facts.field(|f| &f.local_certificate).bytes();
    (!der.is_empty()).then_some(der)
}

/// `begin`: an accepting framing waits for the offer; a dialling one yields its offer now.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, BeginIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let side = match i.side {
            SIDE_ACCEPT => Side::Accept,
            SIDE_DIAL => Side::Dial,
            _ => {
                return o.fail(Refusal::failed(
                    "begin: an association is accepted or dialled, never one stream",
                ))
            }
        };
        let Some(lane) = i.lane() else {
            return o.fail(Refusal::failed("begin: a datagram framer reads its lane"));
        };
        let Some(cert) = certificate(&i) else {
            return o.fail(Refusal::failed("begin: the host presented no certificate"));
        };
        let sink = i.field(|x| &x.sink);
        let now_ns = sink.now_monotonic_ns;
        let base = Instant::now();
        let local = addr(lane.field(|l| &l.local_addr));
        let f = match Framing::begin(side, cert, local, &opening(&i), base) {
            Ok(f) => f,
            Err(why) => return o.fail(Refusal::failed(why)),
        };
        let mut h = Held1 {
            f,
            base_ns: now_ns,
            base,
            gathering: HashMap::new(),
            partial: None,
        };
        if let Err(why) = host_state(&mut h, lane, base) {
            return o.fail(Refusal::failed(why));
        }
        if let Err(why) = answer(&mut h, sink, Some(lane), now_ns, &mut o) {
            return o.fail(Refusal::failed(why));
        }
        let token = s.next.fetch_add(1, Ordering::Relaxed);
        s.lock().insert(token, Arc::new(Mutex::new(Some(h))));
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// `ingest`: one datagram, or the far end's description.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(lane) = i.lane() else {
            return o.fail(Refusal::failed("ingest: a datagram framer reads its lane"));
        };
        let bytes = i.bytes();
        let ended = i.end != 0;
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            Some(lane),
            &mut o,
            |h, now| {
                // Bytes first (none on the YIELD_MORE re-call or a host-state-only call), then the
                // far side's end, whichever call carries it.
                if !bytes.is_empty() {
                    match lane.lane {
                        LANE_RENDEZVOUS => h.f.rendezvous(bytes, now)?,
                        LANE_CLEAR | LANE_SECURED => {
                            let from = addr(lane.field(|l| &l.path_addr))
                                .ok_or("ingest: a datagram with no address")?;
                            let l = if lane.lane == LANE_CLEAR {
                                Lane::Clear
                            } else {
                                Lane::Secured
                            };
                            h.f.datagram(lane.path, from, l, bytes, now);
                        }
                        _ => return Err("ingest: bytes on no lane".into()),
                    }
                }
                if ended {
                    h.f.finish(now);
                }
                Ok(0)
            },
        )
    }
}

/// `emit`: a message's pieces, gathered; its last piece sends it.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, EmitIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let bytes = i.bytes();
        let end = i.end_of_frame != 0;
        let text = i.flags & EMIT_TEXT != 0;
        let stream = i.stream;
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            i.lane(),
            &mut o,
            |h, now| emit(h, stream, bytes, end, text, now),
        )
    }
}

/// One piece of a message for `stream` from the host (`end`: it completes the message), gathered
/// until its last; the yield flags the call answers besides.
fn emit(
    h: &mut Held1,
    stream: u64,
    bytes: &[u8],
    end: bool,
    text: bool,
    now: Instant,
) -> Result<u32, String> {
    let full = |h: &Held1| {
        if h.f.stream_full(stream) {
            YIELD_STREAM_FULL
        } else {
            0
        }
    };
    // The re-call after YIELD_MORE carries nothing new.
    if bytes.is_empty() && !end {
        return Ok(full(h));
    }
    // A stream the framing does not carry is refused at a message's first piece, never gathered.
    if !h.f.carries(stream) {
        h.gathering.remove(&stream);
        return Err(format!("no stream {stream} on this association"));
    }
    // A failed stream's host was told: what it still emits there, and what was gathered, goes.
    if h.f.stream_failed(stream) {
        h.gathering.remove(&stream);
        return Ok(full(h));
    }
    let gathered = h.gathering.get(&stream).map_or(0, Vec::len);
    if gathered + bytes.len() > MAX_MESSAGE {
        // A message no channel could carry: its stream fails, alone, and nothing more
        // of it is gathered.
        h.gathering.remove(&stream);
        h.f.fail_stream(stream, "a message larger than the channel can ever send");
        return Ok(0);
    }
    if !end {
        h.gathering
            .entry(stream)
            .or_default()
            .extend_from_slice(bytes);
        return Ok(full(h));
    }
    // A message in one piece is sent from the host's bytes, never gathered.
    match h.gathering.remove(&stream) {
        // Text or binary is what the call that completes the message says.
        Some(mut message) => {
            message.extend_from_slice(bytes);
            h.f.emit(stream, &message, text, now)?;
        }
        // An empty message too: the framing says what becomes of it.
        None => h.f.emit(stream, bytes, text, now)?,
    }
    Ok(full(h))
}

/// `timer`: the deadline the framing asked for passed.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(
            &inst,
            i.framing,
            i.field(|x| &x.sink),
            i.lane(),
            &mut o,
            |h, now| {
                h.f.timeout(now);
                Ok(0)
            },
        )
    }
}

/// `detach`: FAILED (an association is never handed to another framer).
pub struct Detach;
impl SafeSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, FramingIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        o.fail(Refusal::failed(
            "detach: an association is never handed to another framer",
        ))
    }
}

/// `finish`: the association closes, its last datagrams answered; the framing is forgotten.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        // The map's lock is let go before the association's is taken: `with` takes them the other
        // way round.
        let slot = s.lock().remove(&i.framing);
        let Some(mut h) = slot.and_then(|slot| hold(&slot).take()) else {
            return o.fail(Refusal::failed("finish: no such framing"));
        };
        let sink = i.field(|x| &x.sink);
        let now_ns = sink.now_monotonic_ns;
        let now = h.at(now_ns);
        h.f.finish(now);
        // What the close owes is answered once; what does not fit is dropped with the framing.
        let _ = answer(&mut h, sink, i.lane(), now_ns, &mut o);
        let flags = o.get().yielded.flags & !(YIELD_MORE | YIELD_HAS_DEADLINE);
        o.set(|o| &o.yielded.next_deadline_ns, 0);
        o.set(|o| &o.yielded.flags, flags | YIELD_ENDED);
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framings),
    kind_ops: {
        listen: Safe<NoListen>,
        accept: Safe<NoAccept>,
        dial: Safe<NoDial>,
        read: Safe<NoRead>,
        write: Safe<NoWrite>,
        flush: Safe<NoFlush>,
        shut: Safe<NoShut>,
        arrival: Safe<NoArrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Unused<EncodeIn>>,
        refuse: Safe<Unused<RefuseIn>>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Unused<AdoptIn>>,
        timer: Safe<Timer>,
    },
}

/// The `PIECE_*` bits of one piece of the framing's `p`: `whole` when it carries the last of its
/// bytes, `continued` when a split field block's earlier piece came first. A closed data
/// channel is the stream's END: its own empty piece with [`PIECE_END`] and [`PIECE_END_OF_FRAME`]
/// (the transport contract's "streams end by flag"); an empty piece without it is an empty message.
fn piece_flags(p: &Piece, continued: bool, whole: bool) -> u16 {
    if p.end {
        return PIECE_END | PIECE_END_OF_FRAME;
    }
    if p.failed {
        // A failed stream's last piece: its reason, whole (the door never splits it).
        return PIECE_STREAM_FAILED | PIECE_END_OF_FRAME;
    }
    if p.writable {
        return PIECE_WRITABLE;
    }
    let mut flags = 0_u16;
    if p.fields {
        flags |= PIECE_FIELDS;
        if continued {
            flags |= PIECE_CONTINUED;
        }
    }
    // Every piece of a text message, an empty one's one piece too.
    if p.text && !p.fields {
        flags |= PIECE_TEXT;
    }
    if whole {
        flags |= PIECE_END_OF_FRAME;
    }
    flags
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
