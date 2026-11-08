// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TWO DOORS, ONE ASSOCIATION, THROUGH THE TABLE: a dialling and an accepting framing of the
//! linked door, each behind its own simulated host. The host carries the descriptions on the
//! rendezvous lane, carries every route to the other end on its lane, binds the path a framing
//! asks for, marks the far end verified, and presents one keying-material item. A message and a
//! timer then run over the keyed association, and `finish` ends both.

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute, EmitIn, FinishIn,
    FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, KeyingMaterial, HANDSHAKE_ANSWERS,
    HANDSHAKE_INITIATES, LANE_CLEAR, LANE_RENDEZVOUS, LANE_SECURED, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_TEXT, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
    YIELD_STREAM_FULL,
};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    load_linked, DispatchConfig, Dispatcher, Frame, InFrame, LinkedRow, Plugin,
};
const MEDIA_BASE: u64 = 0x1_0000_0000;

#[path = "support/abi.rs"]
pub mod conf;

const CERT: &[u8] = b"the host's public certificate, DER";
/// `SRTP_AEAD_AES_128_GCM` and its keying material's length.
const PROFILE: u32 = 0x0007;
const KEYING_LEN: usize = 56;

fn door() -> Plugin<Transport> {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let row = LinkedRow::of(busbar_transport_webrtc::linked::door).expect("real door statement");
    let p = load_linked::<Transport>(&row, conf::bind(&d, "webrtc")).expect("loads");
    assert_eq!(conf::open(&p).outcome, Outcome::Ready);
    p
}

/// What one call answered, copied out of the host's buffers.
#[derive(Debug, Default)]
struct Answer {
    outcome: Option<Outcome>,
    why: String,
    flags: u32,
    framing: u64,
    deadline: u64,
    /// `(stream, flags, bytes)` per piece.
    pieces: Vec<(u64, u16, Vec<u8>)>,
    /// `(path, lane, bytes)` per route.
    routes: Vec<(u32, u32, Vec<u8>)>,
}

/// One end's host: its buffers and what it has told the framing.
struct End {
    addr: &'static str,
    side: u32,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    routes: Vec<DatagramRoute>,
    path_addrs: Vec<Vec<u8>>,
    paths: Vec<DatagramPath>,
    bound: u32,
    verified: bool,
    keying: Option<Vec<u8>>,
    token: u64,
    now_ns: u64,
    heard: Vec<(u64, u16, Vec<u8>)>,
    terms: Option<(u32, Vec<Vec<u8>>)>,
    /// Every route this end's door answered, carried to the far end on this end's next turn.
    wire_back: Vec<(u32, u32, Vec<u8>)>,
    /// Datagrams this end was handed on the secured lane.
    secured: usize,
}

impl End {
    fn new(addr: &'static str, side: u32) -> Self {
        Self {
            addr,
            side,
            wire: vec![0; 64 * 1024],
            frame: vec![0; 64 * 1024],
            pieces: vec![
                FramePiece {
                    stream: 0,
                    offset: 0,
                    len: 0,
                    code: 0,
                    status_class: 0,
                    fault: 0,
                    flags: 0,
                    retry_after_secs: 0,
                    declared_len: 0,
                };
                64
            ],
            routes: vec![DatagramRoute::default(); 64],
            path_addrs: Vec::new(),
            paths: Vec::new(),
            bound: 0,
            verified: false,
            keying: None,
            token: 0,
            now_ns: 1_000_000,
            heard: Vec::new(),
            terms: None,
            wire_back: Vec::new(),
            secured: 0,
        }
    }

    /// The path the host numbers `addr` under, newly told when first seen.
    fn path_of(&mut self, addr: &str) -> u32 {
        if let Some(i) = self.path_addrs.iter().position(|a| a == addr.as_bytes()) {
            return i as u32 + 1;
        }
        self.path_addrs.push(addr.as_bytes().to_vec());
        self.path_addrs.len() as u32
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: self.now_ns,
            now_unix_ns: self.now_ns,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// The lane of one call: `lane`, the datagram's path and address, and the host's state.
    fn lane(
        &mut self,
        lane: u32,
        from: Option<(u32, &[u8])>,
        keying: *const KeyingMaterial,
    ) -> DatagramLane {
        self.paths = self
            .path_addrs
            .iter()
            .enumerate()
            .map(|(i, a)| DatagramPath {
                path: i as u32 + 1,
                _reserved: 0,
                addr: AbiStr::over(a),
            })
            .collect();
        DatagramLane {
            size: std::mem::size_of::<DatagramLane>() as u32,
            lane,
            path: from.map_or(0, |(p, _)| p),
            bound: self.bound,
            path_addr: from.map_or(AbiStr::ABSENT, |(_, a)| AbiStr::over(a)),
            local_addr: AbiStr::of_bytes(self.addr.as_bytes()),
            verified: u32::from(self.verified),
            _reserved: 0,
            keying,
            routes: self.routes.as_mut_ptr(),
            routes_cap: self.routes.len(),
            paths: if self.paths.is_empty() {
                std::ptr::null()
            } else {
                self.paths.as_ptr()
            },
            paths_len: self.paths.len(),
        }
    }

    /// Copy one call's answer out, keep what it heard and its terms, and act on its path request.
    fn take(&mut self, outcome: Outcome, why: String, o: &FramerOut) -> Answer {
        let y = &o.yielded;
        let n = (y.pieces_len as usize).min(self.pieces.len());
        let pieces: Vec<(u64, u16, Vec<u8>)> = self.pieces[..n]
            .iter()
            .map(|p| {
                let at = p.offset as usize;
                (
                    p.stream,
                    p.flags,
                    self.frame[at..at + p.len as usize].to_vec(),
                )
            })
            .collect();
        let d = &o.datagram;
        let routes: Vec<(u32, u32, Vec<u8>)> = self.routes[..d.routes_len as usize]
            .iter()
            .map(|r| {
                let at = r.offset as usize;
                (r.path, r.lane, self.wire[at..at + r.len as usize].to_vec())
            })
            .collect();
        let t = &d.terms;
        let span = |s: busbar_contract::abi::transport::FrameSpan| {
            self.frame[s.offset as usize..(s.offset + s.len) as usize].to_vec()
        };
        let terms = vec![
            span(t.local_user),
            span(t.local_secret),
            span(t.remote_user),
            span(t.remote_secret),
            span(t.peer_fingerprint),
            span(t.candidates),
        ];
        if t.role != 0 {
            self.terms = Some((t.role, terms));
        }
        if d.request != 0 {
            self.bound = d.request_to;
        }
        self.heard.extend(pieces.iter().cloned());
        self.wire_back.extend(routes.iter().cloned());
        Answer {
            outcome: Some(outcome),
            why,
            flags: y.flags,
            framing: o.framing,
            deadline: y.next_deadline_ns,
            pieces,
            routes,
        }
    }
}

fn go<I: InFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Outcome, String, FramerOut) {
    let mut f = Frame::new(i, conf::output::<FramerOut>());
    let c = p.call(s, &mut f);
    let called = conf::called(&c);
    let why = called
        .split_once(" lease=")
        .and_then(|(_, rest)| rest.split_once(' '))
        .map(|(_, w)| w.to_string())
        .unwrap_or_default();
    (c.outcome, why, f.out)
}

fn begin(p: &Plugin<Transport>, e: &mut End, fields: &[(&[u8], &[u8])]) -> Answer {
    begin_presenting(p, e, fields, CERT)
}

/// `begin`, the host presenting `cert` as its public certificate.
fn begin_presenting(
    p: &Plugin<Transport>,
    e: &mut End,
    fields: &[(&[u8], &[u8])],
    cert: &[u8],
) -> Answer {
    let facts = ConnFacts {
        size: std::mem::size_of::<ConnFacts>() as u32,
        _reserved: 0,
        offered_name: AbiStr::ABSENT,
        agreed_protocol: AbiStr::ABSENT,
        peer_subject: AbiStr::ABSENT,
        peer_issuer: AbiStr::ABSENT,
        peer_fingerprint: AbiStr::ABSENT,
        claim: AbiStr::ABSENT,
        local_certificate: AbiStr::over(cert),
    };
    let fields: Vec<Field> = fields
        .iter()
        .map(|(n, v)| Field {
            name: AbiStr::over(n),
            value: AbiStr::over(v),
        })
        .collect();
    let l = e.lane(0, None, std::ptr::null());
    let mut i: BeginIn = conf::input();
    i.side = e.side;
    i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    i.facts = &facts;
    i.sink = e.sink();
    (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    i.lane = &l;
    let (outcome, why, o) = go(p, slot::BEGIN, i);
    let a = e.take(outcome, why, &o);
    e.token = a.framing;
    a
}

/// `ingest` of `bytes` on `lane` from `from`, presenting the keying item once if the host holds one.
fn ingest(
    p: &Plugin<Transport>,
    e: &mut End,
    lane: u32,
    from: Option<(u32, &[u8])>,
    bytes: &[u8],
) -> Answer {
    let material = e.keying.take();
    let item = material.as_ref().map(|m| KeyingMaterial {
        size: std::mem::size_of::<KeyingMaterial>() as u32,
        profile: PROFILE,
        bytes: m.as_ptr(),
        len: m.len(),
    });
    let k = item.as_ref().map_or(std::ptr::null(), std::ptr::from_ref);
    let l = e.lane(lane, from, k);
    let mut i: IngestIn = conf::input();
    (i.framing, i.bytes, i.len, i.sink, i.lane) =
        (e.token, bytes.as_ptr(), bytes.len(), e.sink(), &l);
    let (outcome, why, o) = go(p, slot::INGEST, i);
    e.take(outcome, why, &o)
}

fn timer(p: &Plugin<Transport>, e: &mut End) -> Answer {
    let l = e.lane(0, None, std::ptr::null());
    let mut i: FramingIn = conf::input();
    (i.framing, i.sink, i.lane) = (e.token, e.sink(), &l);
    let (outcome, why, o) = go(p, slot::TIMER, i);
    e.take(outcome, why, &o)
}

fn emit(
    p: &Plugin<Transport>,
    e: &mut End,
    stream: u64,
    bytes: &[u8],
    end: bool,
    text: bool,
) -> Answer {
    let l = e.lane(0, None, std::ptr::null());
    let mut i: EmitIn = conf::input();
    (i.framing, i.stream, i.bytes, i.len) = (e.token, stream, bytes.as_ptr(), bytes.len());
    i.end_of_frame = u32::from(end);
    i.flags = if text {
        busbar_contract::abi::transport::EMIT_TEXT
    } else {
        0
    };
    (i.sink, i.lane) = (e.sink(), &l);
    let (outcome, why, o) = go(p, slot::EMIT, i);
    e.take(outcome, why, &o)
}

fn finish(p: &Plugin<Transport>, e: &mut End) -> Answer {
    let l = e.lane(0, None, std::ptr::null());
    let mut i: FinishIn = conf::input();
    (i.framing, i.sink, i.lane) = (e.token, e.sink(), &l);
    let (outcome, why, o) = go(p, slot::FINISH, i);
    e.take(outcome, why, &o)
}

/// The description a framing yielded, from what its host heard on stream 0.
fn description(e: &End) -> Vec<u8> {
    e.heard
        .iter()
        .filter(|(s, _, _)| *s == 0)
        .flat_map(|(_, _, b)| b.clone())
        .collect()
}

/// Carry `a`'s routes to `b`, each on its lane from `a`'s address.
fn carry(p: &Plugin<Transport>, routes: Vec<(u32, u32, Vec<u8>)>, from: &'static str, b: &mut End) {
    for (_, lane, bytes) in routes {
        if lane == LANE_SECURED {
            b.secured += 1;
        }
        let path = b.path_of(from);
        let a = ingest(p, b, lane, Some((path, from.as_bytes())), &bytes);
        assert_eq!(a.outcome, Some(Outcome::Ready), "{}", a.why);
        assert!(a.flags & YIELD_ENDED == 0);
        assert!(a.routes.iter().all(|(path, _, _)| *path != 0));
    }
}

/// One end's turn: its clock advances 10 ms, its timer runs, and everything it owes is carried.
fn turn(p: &Plugin<Transport>, x: &mut End, y: &mut End) {
    x.now_ns += 10_000_000;
    let t = timer(p, x);
    assert_eq!(t.outcome, Some(Outcome::Ready), "{}", t.why);
    let owed = std::mem::take(&mut x.wire_back);
    let from = x.addr;
    carry(p, owed, from, y);
}

/// Both ends take `steps` turns each.
fn run(p: &Plugin<Transport>, a: &mut End, b: &mut End, steps: usize) {
    for _ in 0..steps {
        turn(p, a, b);
        turn(p, b, a);
    }
}

const DIAL: &str = "198.51.100.1:40000";
const ACCEPT: &str = "203.0.113.9:3478";

#[test]
fn two_doors_settle_bind_key_and_carry_a_message_through_the_table() {
    let p = door();
    let mut dial = End::new(DIAL, SIDE_DIAL);
    let mut accept = End::new(ACCEPT, SIDE_ACCEPT);

    let opened = begin(
        &p,
        &mut dial,
        &[(b"channel", b"events"), (b"media", b"audio")],
    );
    assert_eq!(opened.outcome, Some(Outcome::Ready), "{}", opened.why);
    assert!(opened
        .pieces
        .iter()
        .any(|(s, f, _)| *s == 0 && f & PIECE_TEXT != 0));
    assert!(
        opened.pieces.iter().any(|(s, f, b)| *s == MEDIA_BASE
            && f & PIECE_FIELDS != 0
            && b.starts_with(b"kind: audio")),
        "the offered audio line is headed on the first media stream"
    );
    let waiting = begin(&p, &mut accept, &[]);
    assert_eq!(waiting.outcome, Some(Outcome::Ready), "{}", waiting.why);
    assert_ne!(
        accept.token, dial.token,
        "each association has its own token"
    );

    let offer = description(&dial);
    let answered = ingest(&p, &mut accept, LANE_RENDEZVOUS, None, &offer);
    assert_eq!(answered.outcome, Some(Outcome::Ready), "{}", answered.why);
    let answer = description(&accept);
    assert!(
        answer.starts_with(b"v=0"),
        "the accepting end answers with its description"
    );
    let settled = ingest(&p, &mut dial, LANE_RENDEZVOUS, None, &answer);
    assert_eq!(settled.outcome, Some(Outcome::Ready), "{}", settled.why);

    let (dial_role, dial_terms) = dial.terms.clone().expect("the dialling end's terms");
    let (accept_role, accept_terms) = accept.terms.clone().expect("the accepting end's terms");
    assert_ne!(dial_role, accept_role, "one end opens the handshake");
    assert!([HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES].contains(&dial_role));
    assert_eq!(
        dial_terms[0], accept_terms[2],
        "each end's user is the other's remote user"
    );
    assert_eq!(
        dial_terms[1], accept_terms[3],
        "and its secret the other's remote secret"
    );
    assert_eq!(dial_terms[4].len(), 32, "a SHA-256 fingerprint");
    assert_eq!(
        dial_terms[5],
        format!("{ACCEPT}\n").into_bytes(),
        "the far end's one candidate"
    );
    for t in &dial_terms[..5] {
        assert!(!t.is_empty());
    }

    // The dialling host numbers the far end's candidate and the checks run.
    dial.path_of(ACCEPT);
    run(&p, &mut dial, &mut accept, 300);
    assert_ne!(
        dial.bound, 0,
        "the dialling end asked its host to bind the nominated path"
    );
    assert_ne!(accept.bound, 0, "and so did the accepting end");

    // The host's secure layer verifies the far end and exports one keying material to each.
    let material: Vec<u8> = (0..KEYING_LEN as u8).collect();
    for e in [&mut dial, &mut accept] {
        e.verified = true;
        e.keying = Some(material.clone());
        let keyed = ingest(&p, e, LANE_CLEAR, None, &[]);
        assert_eq!(keyed.outcome, Some(Outcome::Ready), "{}", keyed.why);
    }
    run(&p, &mut dial, &mut accept, 300);
    let channel = accept
        .heard
        .iter()
        .find(|(s, f, b)| *s != 0 && f & PIECE_FIELDS != 0 && b.starts_with(b"label: events"))
        .map(|(s, _, _)| *s)
        .expect("the accepting end heard the channel open");

    let sent = emit(&p, &mut dial, 1, b"hel", false, true);
    assert_eq!(sent.outcome, Some(Outcome::Ready), "{}", sent.why);
    let sent = emit(&p, &mut dial, 1, b"lo", true, true);
    assert_eq!(sent.outcome, Some(Outcome::Ready), "{}", sent.why);
    run(&p, &mut dial, &mut accept, 50);
    assert!(
        accept.heard.iter().any(|(s, f, b)| *s == channel
            && b == b"hello"
            && f & PIECE_TEXT != 0
            && f & PIECE_END_OF_FRAME != 0),
        "the message gathered from two pieces arrived whole, as text"
    );

    assert!(
        dial.secured > 0 && accept.secured > 0,
        "the channel ran over the secured lane both ways"
    );

    // One Opus frame (a 20 ms CELT frame) on the audio line reaches the far end's media stream.
    let audio = emit(
        &p,
        &mut dial,
        MEDIA_BASE,
        &[0xF8, 0x01, 0x02, 0x03, 0x04],
        true,
        false,
    );
    assert_eq!(audio.outcome, Some(Outcome::Ready), "{}", audio.why);
    run(&p, &mut dial, &mut accept, 20);
    assert!(
        accept
            .heard
            .iter()
            .any(|(s, _, b)| *s == MEDIA_BASE && b == &[0xF8, 0x01, 0x02, 0x03, 0x04]),
        "the media frame arrived on the accepting end's audio stream"
    );

    let t = timer(&p, &mut dial);
    assert!(
        t.flags & YIELD_HAS_DEADLINE != 0 && t.deadline > dial.now_ns,
        "a live association asks for its next deadline"
    );

    for e in [&mut dial, &mut accept] {
        let mut ended = false;
        for _ in 0..16 {
            let a = finish(&p, e);
            assert_eq!(a.outcome, Some(Outcome::Ready), "{}", a.why);
            assert_eq!(
                a.flags & YIELD_HAS_DEADLINE,
                0,
                "a finishing association asks for no deadline"
            );
            if a.flags & YIELD_MORE == 0 {
                assert_ne!(a.flags & YIELD_ENDED, 0);
                ended = true;
                break;
            }
        }
        assert!(ended, "finish ends the association");
        let gone = timer(&p, e);
        assert_eq!(
            gone.outcome,
            Some(Outcome::Failed),
            "a finished association is forgotten"
        );
        assert!(gone.why.contains("no such framing"), "{}", gone.why);
    }
}

#[test]
fn begin_refuses_a_side_a_certificate_or_an_opening_it_cannot_serve() {
    let p = door();
    let mut odd = End::new(DIAL, 9);
    let a = begin(&p, &mut odd, &[(b"channel", b"events")]);
    assert_eq!(a.outcome, Some(Outcome::Failed));
    assert_eq!(
        a.why,
        "begin: an association is accepted or dialled, never one stream"
    );

    let mut uncertified = End::new(DIAL, SIDE_DIAL);
    let a = begin_presenting(&p, &mut uncertified, &[(b"channel", b"events")], b"");
    assert_eq!(a.outcome, Some(Outcome::Failed));
    assert_eq!(a.why, "begin: the host presented no certificate");

    let mut empty = End::new(DIAL, SIDE_DIAL);
    let a = begin(
        &p,
        &mut empty,
        &[(b"x-unknown", b"ignored"), (&[0xff], b"not a name")],
    );
    assert_eq!(a.outcome, Some(Outcome::Failed));
    assert_eq!(
        a.why, "begin: a dialling framing offers nothing",
        "unknown fields offer nothing"
    );
}

#[test]
fn ingest_refuses_bytes_on_no_lane_and_its_end_flag_ends_the_association() {
    let p = door();
    let mut e = End::new(DIAL, SIDE_DIAL);
    assert_eq!(
        begin(&p, &mut e, &[(b"channel", b"events")]).outcome,
        Some(Outcome::Ready)
    );
    let a = ingest(&p, &mut e, 9, None, b"stray");
    assert_eq!(a.outcome, Some(Outcome::Failed));
    assert_eq!(a.why, "ingest: bytes on no lane");
    assert_eq!(
        timer(&p, &mut e).outcome,
        Some(Outcome::Failed),
        "the refused association is forgotten"
    );

    let mut e = End::new(DIAL, SIDE_DIAL);
    assert_eq!(
        begin(&p, &mut e, &[(b"channel", b"events")]).outcome,
        Some(Outcome::Ready)
    );
    let mut ended = None;
    for _ in 0..16 {
        let l = e.lane(0, None, std::ptr::null());
        let mut i: IngestIn = conf::input();
        (i.framing, i.end, i.sink, i.lane) = (e.token, 1, e.sink(), &l);
        let (outcome, why, o) = go(&p, slot::INGEST, i);
        let a = e.take(outcome, why, &o);
        assert_eq!(a.outcome, Some(Outcome::Ready), "{}", a.why);
        if a.flags & YIELD_MORE == 0 {
            ended = Some(a.flags);
            break;
        }
    }
    assert_ne!(
        ended.expect("drained") & YIELD_ENDED,
        0,
        "the far end's end ends the association"
    );
}

#[test]
fn a_channel_that_cannot_send_yet_turns_full_and_an_empty_piece_is_only_a_question() {
    let p = door();
    let mut e = End::new(DIAL, SIDE_DIAL);
    assert_eq!(
        begin(&p, &mut e, &[(b"channel", b"events")]).outcome,
        Some(Outcome::Ready)
    );
    let asked = emit(&p, &mut e, 1, b"", false, false);
    assert_eq!(asked.outcome, Some(Outcome::Ready), "{}", asked.why);
    assert_eq!(
        asked.flags & YIELD_STREAM_FULL,
        0,
        "an empty non-final piece only asks"
    );
    let mut full_at = None;
    for n in 1..=64 {
        let a = emit(&p, &mut e, 1, b"held until the channel opens", true, true);
        assert_eq!(a.outcome, Some(Outcome::Ready), "{}", a.why);
        if a.flags & YIELD_STREAM_FULL != 0 {
            full_at = Some(n);
            break;
        }
    }
    assert_eq!(
        full_at,
        Some(64),
        "the stream is full at the high-water mark of held messages"
    );
    let asked = emit(&p, &mut e, 1, b"", false, false);
    assert_ne!(
        asked.flags & YIELD_STREAM_FULL,
        0,
        "and stays full while asked"
    );
}

#[test]
fn rendezvous_terms_larger_than_the_whole_frame_buffer_fail_the_association() {
    let p = door();
    let mut dial = End::new(DIAL, SIDE_DIAL);
    let mut accept = End::new(ACCEPT, SIDE_ACCEPT);
    assert_eq!(
        begin(&p, &mut dial, &[(b"channel", b"events")]).outcome,
        Some(Outcome::Ready)
    );
    assert_eq!(begin(&p, &mut accept, &[]).outcome, Some(Outcome::Ready));
    accept.frame = vec![0; 64];
    let a = ingest(&p, &mut accept, LANE_RENDEZVOUS, None, &description(&dial));
    assert_eq!(a.outcome, Some(Outcome::Failed));
    assert_eq!(
        a.why,
        "ingest: the rendezvous terms do not fit the host's frame buffer"
    );
}
