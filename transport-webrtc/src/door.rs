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
//!   streams `1, 2, ...` in order) and `media: audio` for one Opus line (stream [`MEDIA_BASE`]).
//! * `ingest`: one datagram, or the far end's description, as the lane names it; the lane's host
//!   state (bound path, verified bit, keying-material item, new paths) is read first, on every call
//!   that carries a lane.
//! * `emit`: one message for a stream (a channel's message, an Opus frame for a media line),
//!   gathered until `end_of_frame`; [`EMIT_TEXT`] marks a channel message as text. A channel whose
//!   held messages reach the framing's high-water mark answers [`YIELD_STREAM_FULL`] and is
//!   writable again with a [`PIECE_WRITABLE`] piece; a channel that cannot carry a message fails
//!   alone, with a [`PIECE_STREAM_FAILED`] piece.
//! * `timer`: the clock; `finish`: the association closes.
//! * THE BINDING'S AUTH (ruling 23; THE DESIGN §6, "Auth points and guest lists", items 5 and 7):
//!   a dialled `begin` whose binding has an auth ([`BeginIn::points`], [`BeginIn::auth`]) calls it
//!   through the host ([`op::AUTH_CALL`](busbar_contract::abi::host::service::op::AUTH_CALL)) at
//!   [`POINT_PEER`] ONCE, before the association exists (`auth_gate`). An association carries no
//!   head: its session description goes up as the body of the signalling exchange, whose head the
//!   framer serving that exchange renders and signs. So a binding that needs [`POINT_HEAD`] or
//!   [`POINT_HEAD_BODY`] on this media path is refused, as is an unknown point, a stop, a host that
//!   serves no auth call, and a ref the host refuses (stale or foreign).
//! * `locate`, `encode`, `refuse`, `detach`, `adopt`: REFUSED (no authority to dial, no envelope,
//!   no upgrade); every carrier op: REFUSED.
//!
//! A full host buffer is back-pressure: READY with [`YIELD_MORE`], and the re-call carries no new
//! bytes. Only a dialled `begin` pends, on its own peer-point auth call: nothing of the association
//! exists yet, so the pend parks that one dial and no other stream; the resumed `begin` re-issues
//! the same completion handle and reads the stored answer.

use core::net::SocketAddr;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Poll;
use std::time::{Duration, Instant};

use busbar_contract::abi::auth::{POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{AuthRef, UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::services::{HeadViewArgs, ServiceError, Services};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::check::check_keying;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnFacts, ConnIn,
    ConnOut, DatagramLane, DatagramRoute, DatagramYield, DialIn, EmitIn, EncodeIn, FinishIn,
    FramePiece, FrameSpan, FramerOut, FramerSink, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, RendezvousTerms, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, EMIT_TEXT, EXT_OFFERED_POINTS, FACT_ACCEPTS, FACT_DIALS,
    FRAME_PIECE_SIZE, FRAMING_DATAGRAM, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, LANE_CLEAR,
    LANE_RENDEZVOUS, LANE_SECURED, PATH_REQUEST_BIND, PATH_REQUEST_REBIND, PIECE_CONTINUED,
    PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE,
    ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL, UNIT0_FIRST_DATAGRAM, YIELD_ENDED, YIELD_HAS_DEADLINE,
    YIELD_MORE, YIELD_STREAM_FULL,
};

use crate::framing::{Framing, Lane, Opening, Piece, Request, Side, MAX_MESSAGE, MEDIA_BASE};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The claim this entry answers for.
pub const KEY: &str = "webrtc";

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// The claim's row: no selector forms (an association is reached through the rendezvous, never
/// selected on its datagrams), a session whose first unit opens on its first datagram.
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: NONE,
    session: 1,
    session_bound: 1,
    unit0_trigger: UNIT0_FIRST_DATAGRAM,
    status_at: 0,
    _reserved: 0,
}];

/// The transport kind's tail: a datagram framer, composing over nothing (the port is the host's).
const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_DATAGRAM,
    // The ops it declares: an association is accepted (it answers an offer) or dialled (it offers).
    facts: FACT_ACCEPTS | FACT_DIALS,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
    // A datagram lane states no status rows, so it states no fault table either: its pieces carry
    // no reading (`FAULT_NONE`), as the byte-stream carrier's do.
    fault_rows: std::ptr::null(),
    fault_rows_len: 0,
    // The stride this framer writes its pieces at: the contract's it was built against.
    frame_piece_size: FRAME_PIECE_SIZE,
    _reserved: 0,
};

/// THE AUTH POINTS THIS TRANSPORT OFFERS ([`EXT_OFFERED_POINTS`], THE DESIGN §6 "Auth points and
/// guest lists", item 1): [`POINT_PEER`] alone. An association carries no head, so it offers
/// neither [`POINT_HEAD`] nor [`POINT_HEAD_BODY`] (the default of a transport that states no record).
const OFFERED_POINTS: [u8; 4] = POINT_PEER.to_le_bytes();

/// The Statement's extensions: the offered-points record, built at compile time.
const EXTENSIONS: &[u8] = &extensions::entry::<
    { extensions::entry_len(EXT_OFFERED_POINTS, &OFFERED_POINTS) },
>(EXT_OFFERED_POINTS, &OFFERED_POINTS);

/// The door's Statement.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    extensions: Blob {
        ptr: EXTENSIONS.as_ptr(),
        len: EXTENSIONS.len(),
        fmt: BLOB_OCTETS,
        ..Blob::ZERO
    },
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// One association's framing and the host clock it is read against.
struct Held1 {
    f: Framing,
    base_ns: u64,
    base: Instant,
    /// A message being gathered, per stream, and whether it is text.
    gathering: HashMap<u64, (Vec<u8>, bool)>,
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

/// The framings one instance holds.
pub struct Framings {
    framings: Mutex<HashMap<u64, Held1>>,
    next: AtomicU64,
}

type State = Held<Framings>;

impl Life for Framings {
    /// Only a dialled `begin` pends (its peer-point auth call), before its association exists, so a
    /// cancel finds nothing of this framer's moved.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This framer reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Framings {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Held1>> {
        self.framings.lock().unwrap_or_else(PoisonError::into_inner)
    }
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
/// Rendezvous terms that even an empty frame buffer could not hold whole: the framing fails rather
/// than answer YIELD_MORE with no progress.
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
            h.partial_terms(t);
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
        if p.failed && p.bytes.len() > room && room > 0 {
            // A failure's reason is never split: what fits of it is the reason.
            p.bytes.truncate(room);
        }
        if pieces.asked() >= pieces.cap() || (room == 0 && !p.bytes.is_empty()) {
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let whole = p.bytes.len() <= room;
        if !whole && p.fields && frame.asked() != 0 {
            // A field block starts a fresh answer rather than split mid-buffer.
            h.partial = Some((p, continued));
            more = true;
            break;
        }
        let n = p.bytes.len().min(room);
        let at = frame.extend(&p.bytes[..n]);
        let flags = piece_flags(&p, continued, whole, n);
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

impl Held1 {
    fn partial_terms(&mut self, t: crate::framing::Terms) {
        self.f.restore_terms(t);
    }
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
    let mut held = s.lock();
    let Some(h) = held.get_mut(&token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    let now_ns = sink.now_monotonic_ns;
    let now = h.at(now_ns);
    let run = match lane {
        Some(l) => host_state(h, l, now).and_then(|()| op(h, now)),
        None => op(h, now),
    };
    let extra = match run {
        Ok(extra) => extra,
        Err(why) => {
            held.remove(&token);
            return o.fail(Refusal::failed(why));
        }
    };
    if let Some(why) = h.f.failure() {
        let why = why.to_owned();
        held.remove(&token);
        return o.fail(Refusal::failed(why));
    }
    if let Err(why) = answer(h, sink, lane, now_ns, o) {
        held.remove(&token);
        return o.fail(Refusal::failed(why));
    }
    if extra != 0 {
        let flags = o.get().yielded.flags;
        o.set(|o| &o.yielded.flags, flags | extra);
    }
    Outcome::Ready
}

// ── the carrier ops: refused ─────────────────────────────────────────────────────────────────────

/// A carrier op: REFUSED. The port is the host's.
pub struct NotACarrier<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotACarrier<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
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

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`: REFUSED. An association's far end comes from its description, judged by the host.
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

// ── the binding's auth ───────────────────────────────────────────────────────────────────────────

// This crate's own seal over what an auth call answers (`Services::auth_call`). At the peer point
// the answer carries no field, so nothing is ever read under it.
busbar_contract::own_seal!(Own);

/// The completion handle's sequence the peer-point call is made under, on the `begin`'s ticket.
const SEQ_PEER: u32 = 1;

/// The binding's auth at [`POINT_PEER`], through the host: the flow it answers
/// ([`FLOW_CONTINUE`] goes on), PENDING while it is not ready.
pub(crate) trait PeerAuth {
    /// One call at the peer point on `handle`, for `auth`.
    fn peer(&self, handle: CompletionHandle, auth: AuthRef) -> Poll<Result<u32, ServiceError>>;
}

impl PeerAuth for Services {
    fn peer(&self, handle: CompletionHandle, auth: AuthRef) -> Poll<Result<u32, ServiceError>> {
        self.auth_call::<Own>(
            handle,
            auth,
            UnitRef::NONE,
            POINT_PEER,
            0,
            0,
            &HeadViewArgs::default(),
            None,
        )
        .map(|answer| answer.map(|called| called.flow))
    }
}

/// What the binding's auth lets a `begin` do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Begin the association.
    Go,
    /// The auth's answer is not ready: the `begin` pends on its ticket and nothing is begun.
    Pend,
    /// Refused, with why: no association, nothing sent.
    Refuse(&'static str),
}

/// THE BINDING'S AUTH ON A `begin` (ruling 23; THE DESIGN §6 "Auth points and guest lists", items
/// 5 and 7; [`BeginIn::points`], [`BeginIn::auth`]).
///
/// * An accepting side carries no binding: points or a ref there are refused.
/// * A dial with no points goes on with no call; points and a ref come together or not at all.
/// * [`POINT_HEAD`] and [`POINT_HEAD_BODY`] are refused: an association is media (ICE, SRTP, SCTP)
///   and carries no head. Its description goes up as the body of the signalling exchange, and the
///   framer serving that exchange renders its head and calls the auth over it.
/// * A point outside [`POINT_PEER`] | [`POINT_HEAD`] | [`POINT_HEAD_BODY`] is refused.
/// * [`POINT_PEER`]: the auth is called ONCE, at this `begin`, before the association exists, on
///   the op's ticket. A host that serves no auth call refuses the dial; PENDING pends only this
///   `begin`; a stop refuses; a call the host refuses (a stale or foreign ref, one it did not
///   mint) refuses.
pub(crate) fn auth_gate(
    dial: bool,
    points: u32,
    auth: AuthRef,
    ticket: Ticket,
    host: Option<&dyn PeerAuth>,
) -> Gate {
    if !dial {
        return if points == 0 && auth.is_none() {
            Gate::Go
        } else {
            Gate::Refuse("begin: an accepted association carries no binding auth")
        };
    }
    if points == 0 && auth.is_none() {
        return Gate::Go;
    }
    if points == 0 || auth.is_none() {
        return Gate::Refuse("begin: the binding's auth points and its ref do not agree");
    }
    if points & !(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY) != 0 {
        return Gate::Refuse("begin: the binding's auth needs a point this framer does not serve");
    }
    if points & (POINT_HEAD | POINT_HEAD_BODY) != 0 {
        return Gate::Refuse(
            "begin: an association carries no head; the signalling exchange's framer signs it",
        );
    }
    let Some(host) = host else {
        return Gate::Refuse("begin: the binding has an auth and the host serves no auth call");
    };
    let handle = CompletionHandle {
        ticket,
        seq: SEQ_PEER,
        _reserved: 0,
    };
    match host.peer(handle, auth) {
        Poll::Pending => Gate::Pend,
        Poll::Ready(Ok(FLOW_CONTINUE)) => Gate::Go,
        Poll::Ready(Ok(_)) => Gate::Refuse("begin: the binding's auth stopped the connection"),
        Poll::Ready(Err(_)) => Gate::Refuse("begin: the host refused the binding's auth call"),
    }
}

/// `begin`: an accepting framing waits for the offer; a dialling one yields its offer now, once
/// its binding's auth lets it (`auth_gate`).
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
        let services = inst.get().and_then(Held::host).and_then(|h| h.services());
        match auth_gate(
            matches!(side, Side::Dial),
            i.points,
            i.auth,
            i.head.ticket,
            services.as_ref().map(|s| s as &dyn PeerAuth),
        ) {
            Gate::Go => {}
            Gate::Pend => return Outcome::Pending,
            Gate::Refuse(why) => return o.fail(Refusal::failed(why)),
        }
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
        s.lock().insert(token, h);
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
            |h, now| {
                let full = |h: &Held1| {
                    if h.f.stream_full(stream) {
                        YIELD_STREAM_FULL
                    } else {
                        0
                    }
                };
                if (bytes.is_empty() && !end) || h.f.stream_failed(stream) {
                    return Ok(full(h));
                }
                let g = h.gathering.entry(stream).or_default();
                if g.0.len() + bytes.len() > MAX_MESSAGE {
                    // A message no channel could carry: its stream fails, alone, and nothing more
                    // of it is gathered.
                    h.gathering.remove(&stream);
                    h.f.fail_stream(stream, "a message larger than the channel can ever send");
                    return Ok(0);
                }
                g.0.extend_from_slice(bytes);
                g.1 |= text;
                if !end {
                    return Ok(full(h));
                }
                let (message, text) = h.gathering.remove(&stream).unwrap_or_default();
                if message.is_empty() {
                    return Ok(full(h));
                }
                h.f.emit(stream, &message, text, now)?;
                Ok(full(h))
            },
        )
    }
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

/// `detach`: REFUSED (an association is never handed to another framer).
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
        let mut held = s.lock();
        let Some(mut h) = held.remove(&i.framing) else {
            return o.fail(Refusal::failed("finish: no such framing"));
        };
        drop(held);
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
        listen: Safe<NotACarrier<ListenIn, ListenOut>>,
        accept: Safe<NotACarrier<AcceptIn, AcceptOut>>,
        dial: Safe<NotACarrier<DialIn, ConnOut>>,
        read: Safe<NotACarrier<ReadIn, IoOut>>,
        write: Safe<NotACarrier<WriteIn, IoOut>>,
        flush: Safe<NotACarrier<ConnIn, OutHead>>,
        shut: Safe<NotACarrier<ShutIn, OutHead>>,
        arrival: Safe<NotACarrier<ArrivalIn, ArrivalOut>>,
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

/// The `PIECE_*` bits of one piece of the framing's `p`: `n` of its bytes taken, `whole` when that
/// is all of them, `continued` when a split field block's earlier piece came first. A closed data
/// channel is the stream's END: its own empty piece with [`PIECE_END`] and [`PIECE_END_OF_FRAME`]
/// (the transport contract's "streams end by flag"); an empty piece without it is an empty message.
fn piece_flags(p: &Piece, continued: bool, whole: bool, n: usize) -> u16 {
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
    if p.text && n > 0 && !p.fields {
        flags |= PIECE_TEXT;
    }
    if whole {
        flags |= PIECE_END_OF_FRAME;
    }
    flags
}

/// The first media stream, for a host that names streams.
pub const FIRST_MEDIA_STREAM: u64 = MEDIA_BASE;

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
