// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S OWN DUTIES THROUGH THE TABLE: what `begin`, `ingest`, `emit` and `timer` answer into
//! host buffers of a size the test chooses, driven through the one loader as the host drives them
//! (the linked door; `datagram_witness.rs` holds the dropped-in one to the same transcript). The
//! far end, where one is needed, is a framing of this crate's own, driven directly.

use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, DatagramLane, DatagramPath, DatagramRoute, EmitIn, FinishIn,
    FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, LANE_RENDEZVOUS, PIECE_CONTINUED,
    PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_STREAM_FAILED, PIECE_TEXT, SIDE_DIAL, YIELD_MORE,
};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{Frame, Plugin};
use busbar_test_kit::conformance::{self as conf, Leg, Subject};
use busbar_transport_webrtc::framing::{Framing, Opening, Side, DESCRIPTION};

const CDYLIB: &str = "busbar_transport_webrtc_plugin";
const LOCAL: &str = "198.51.100.1:40000";
const FAR: &str = "203.0.113.9:3478";
const CERT: &[u8] = b"the host's public certificate, DER";

/// The linked door, loaded and opened.
fn door() -> Plugin<Transport> {
    let s = Subject::new(busbar_transport_webrtc::linked::door, CDYLIB, "{}");
    let d = conf::dispatcher();
    let p = conf::load::<Transport>(&s, Leg::Linked, s.bind(&d, "webrtc")).expect("loads");
    assert_eq!(conf::open(&p, &s.settings()).outcome, Outcome::Ready);
    p
}

/// The host's buffers for one call, of the capacities a test chooses.
struct Host {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    routes: Vec<DatagramRoute>,
    local: Vec<u8>,
    paths: Vec<DatagramPath>,
    path_addrs: Vec<Vec<u8>>,
    now_ns: u64,
}

/// One call's answer, copied out.
#[derive(Debug)]
struct Answer {
    outcome: Outcome,
    /// The refusal's words, when it failed.
    why: String,
    flags: u32,
    framing: u64,
    /// `(stream, flags, bytes)` per piece.
    pieces: Vec<(u64, u16, Vec<u8>)>,
}

impl Host {
    fn new(wire: usize, frame: usize) -> Self {
        Self {
            wire: vec![0; wire],
            frame: vec![0; frame],
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
            local: LOCAL.as_bytes().to_vec(),
            paths: Vec::new(),
            path_addrs: Vec::new(),
            now_ns: 1,
        }
    }

    /// The host knows path `path` at `addr` (told on every call).
    fn path(&mut self, path: u32, addr: &str) {
        self.path_addrs.push(addr.as_bytes().to_vec());
        self.paths.clear();
        for (i, a) in self.path_addrs.iter().enumerate() {
            self.paths.push(DatagramPath {
                path: i as u32 + 1,
                _reserved: 0,
                addr: AbiStr::over(a),
            });
        }
        assert_eq!(self.paths.last().map(|p| p.path), Some(path));
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

    fn lane(&mut self, lane: u32) -> DatagramLane {
        DatagramLane {
            size: std::mem::size_of::<DatagramLane>() as u32,
            lane,
            path: 0,
            bound: 0,
            path_addr: AbiStr::ABSENT,
            local_addr: if self.local.is_empty() {
                AbiStr::ABSENT
            } else {
                AbiStr::over(&self.local)
            },
            verified: 0,
            _reserved: 0,
            keying: std::ptr::null(),
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

    fn answer(&self, outcome: Outcome, why: String, o: &FramerOut) -> Answer {
        let n = (o.yielded.pieces_len as usize).min(self.pieces.len());
        let pieces = self.pieces[..n]
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
        Answer {
            outcome,
            why,
            flags: o.yielded.flags,
            framing: o.framing,
            pieces,
        }
    }
}

fn go<I: busbar_plugin_loader::dispatch::InFrame>(
    p: &Plugin<Transport>,
    s: u32,
    i: I,
) -> (Outcome, String, FramerOut) {
    let mut f = Frame::new(i, conf::output::<FramerOut>());
    let c = p.call(s, &mut f);
    let called = conf::called(&c);
    // `called` is "<Outcome> lease=<bool> <words>": the words are what follows the lease.
    let why = called
        .split_once(" lease=")
        .and_then(|(_, rest)| rest.split_once(' '))
        .map(|(_, w)| w.to_string())
        .unwrap_or_default();
    (c.outcome, why, f.out)
}

/// `begin` dialling, offering `channels` (one `channel` field each).
fn begin(p: &Plugin<Transport>, host: &mut Host, channels: &[&[u8]]) -> Answer {
    let fields: Vec<(&[u8], &[u8])> = channels.iter().map(|c| (&b"channel"[..], *c)).collect();
    begin_with(p, host, &fields)
}

/// `begin` dialling, with these opening fields, `(name, value)` each.
fn begin_with(p: &Plugin<Transport>, host: &mut Host, opening: &[(&[u8], &[u8])]) -> Answer {
    let facts = ConnFacts {
        size: std::mem::size_of::<ConnFacts>() as u32,
        _reserved: 0,
        offered_name: AbiStr::ABSENT,
        agreed_protocol: AbiStr::ABSENT,
        peer_subject: AbiStr::ABSENT,
        peer_issuer: AbiStr::ABSENT,
        peer_fingerprint: AbiStr::ABSENT,
        claim: AbiStr::ABSENT,
        local_certificate: AbiStr::of_bytes(CERT),
    };
    let fields: Vec<Field> = opening
        .iter()
        .map(|(n, v)| Field {
            name: AbiStr::over(n),
            value: AbiStr::over(v),
        })
        .collect();
    let l = host.lane(0);
    let mut i: BeginIn = conf::input();
    i.side = SIDE_DIAL;
    i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    i.facts = &facts;
    i.sink = host.sink();
    (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    i.lane = &l;
    let (outcome, why, o) = go(p, slot::BEGIN, i);
    host.answer(outcome, why, &o)
}

/// `ingest` of `bytes` on `lane` (`0` and no bytes: the host-state call and the re-call).
fn ingest(p: &Plugin<Transport>, host: &mut Host, token: u64, lane: u32, bytes: &[u8]) -> Answer {
    let l = host.lane(lane);
    let mut i: IngestIn = conf::input();
    (i.framing, i.bytes, i.len, i.sink, i.lane) =
        (token, bytes.as_ptr(), bytes.len(), host.sink(), &l);
    let (outcome, why, o) = go(p, slot::INGEST, i);
    host.answer(outcome, why, &o)
}

/// `emit` of a whole message (`end_of_frame`) on `stream`.
fn emit(p: &Plugin<Transport>, host: &mut Host, token: u64, stream: u64, bytes: &[u8]) -> Answer {
    let l = host.lane(0);
    let mut i: EmitIn = conf::input();
    (i.framing, i.stream, i.bytes, i.len, i.end_of_frame) =
        (token, stream, bytes.as_ptr(), bytes.len(), 1);
    (i.sink, i.lane) = (host.sink(), &l);
    let (outcome, why, o) = go(p, slot::EMIT, i);
    host.answer(outcome, why, &o)
}

fn timer(p: &Plugin<Transport>, host: &mut Host, token: u64) -> Answer {
    let l = host.lane(0);
    let mut i: FramingIn = conf::input();
    (i.framing, i.sink, i.lane) = (token, host.sink(), &l);
    let (outcome, why, o) = go(p, slot::TIMER, i);
    host.answer(outcome, why, &o)
}

/// The words a framing that fails at `begin` answers, or the first answer's.
fn begun(host: &mut Host, channels: &[&[u8]]) -> Answer {
    let p = door();
    begin(&p, host, channels)
}

/// A DIALLING FRAMING'S CHANNELS ARE STREAMS 1, 2, ... IN FIELD ORDER (the door's doc; codeaudit
/// door.rs:482): a `channel` field the framer cannot offer (an empty label, or one that is not
/// UTF-8) refuses the `begin` in words, rather than be skipped and shift every later channel's
/// stream number. RED before the fix: `["", "b"]` began, `b` on stream 1.
#[test]
fn a_channel_field_it_cannot_offer_refuses_the_begin() {
    for bad in [&b""[..], &[0xff, 0xfe][..]] {
        let a = begun(&mut Host::new(4096, 4096), &[bad, b"b"]);
        assert_eq!(
            (a.outcome, a.why.as_str()),
            (
                Outcome::Failed,
                "begin: a channel field whose label is empty or not text"
            ),
            "{bad:?}"
        );
    }
    let a = begun(&mut Host::new(4096, 4096), &[b"a", b"b"]);
    assert_eq!(a.outcome, Outcome::Ready);
}

/// THE HOST PORT'S ADDRESS IS READ AT BEGIN (codeaudit door.rs:529): with none, or one that does
/// not parse, the framing could advertise no candidate and would read no datagram, so `begin` is
/// refused in words. RED before the fix: it began, and hung until its timers.
#[test]
fn a_begin_without_the_host_ports_address_is_refused() {
    for local in [&b""[..], b"not an address"] {
        let mut host = Host::new(4096, 4096);
        host.local = local.to_vec();
        let a = begun(&mut host, &[b"events"]);
        assert_eq!(
            (a.outcome, a.why.as_str()),
            (
                Outcome::Failed,
                "begin: the lane names no address of the host's port"
            ),
            "{local:?}"
        );
    }
}

/// A HOST PATH IS READ WHOLE OR REFUSED (codeaudit door.rs:187): a path whose address does not
/// parse fails the call in words, rather than be dropped and its checks lost. RED before the fix:
/// the path was skipped and the framing began.
#[test]
fn a_host_path_whose_address_does_not_parse_is_refused() {
    let mut host = Host::new(4096, 4096);
    host.path(1, "nonsense");
    let a = begun(&mut host, &[b"events"]);
    assert_eq!(
        (a.outcome, a.why.as_str()),
        (Outcome::Failed, "the host's path 1 names no address")
    );
}

/// A DATAGRAM THE HOST'S WIRE BUFFER CAN NEVER HOLD FAILS THE FRAMING IN WORDS (codeaudit W4), as
/// rendezvous terms that never fit do: answering YIELD_MORE for it would be a re-call loop with no
/// progress. RED before the fix: every re-call answered YIELD_MORE and routed nothing, forever.
#[test]
fn a_datagram_larger_than_the_whole_wire_buffer_fails_the_framing() {
    let p = door();
    // The wire holds 16 bytes: no connectivity check (20 bytes of header alone) ever fits.
    let mut host = Host::new(16, 16 * 1024);
    let a = begin(&p, &mut host, &[b"events"]);
    assert_eq!(a.outcome, Outcome::Ready);
    let token = a.framing;
    let offer = a
        .pieces
        .iter()
        .find(|x| x.0 == DESCRIPTION)
        .map(|x| x.2.clone())
        .expect("the offer");
    // The far end answers; the host knows the far end's address as path 1.
    let now = Instant::now();
    let mut far = Framing::begin(
        Side::Accept,
        CERT,
        FAR.parse().ok(),
        &Opening::default(),
        now,
    )
    .expect("begins");
    far.rendezvous(&offer, now).expect("the offer is taken");
    let answer = far.next_piece().expect("the answer").bytes;
    host.path(1, FAR);
    let mut last = ingest(&p, &mut host, token, LANE_RENDEZVOUS, &answer);
    for step in 0..200 {
        if last.outcome != Outcome::Ready {
            break;
        }
        if last.flags & YIELD_MORE != 0 {
            assert!(step < 199, "a re-call loop with no progress: {last:?}");
            last = ingest(&p, &mut host, token, 0, &[]);
        } else {
            host.now_ns += Duration::from_millis(50).as_nanos() as u64;
            last = timer(&p, &mut host, token);
        }
    }
    assert_eq!(
        (last.outcome, last.why.as_str()),
        (
            Outcome::Failed,
            "a datagram the media stack sends does not fit the host's wire buffer"
        ),
        "{last:?}"
    );
}

/// A STREAM'S FAILURE REASON IS NEVER CUT TO THE ROOM LEFT (codeaudit W5): like a field block, a
/// failure piece that does not fit beside the pieces before it waits for a fresh answer, and only
/// a reason longer than the whole buffer is cut. RED before the fix: it was cut to whatever room
/// the answer had left, and the rest was lost.
#[test]
fn a_failure_reason_waits_for_a_fresh_answer_rather_than_be_cut() {
    let why = b"an empty message, which the media stack cannot send".to_vec();
    let p = door();
    // Across frame buffers of these sizes, the offer's last chunk leaves every room from 1 to the
    // reason's length beside it in some answer.
    for cap in 100..=200 {
        let mut host = Host::new(4096, cap);
        let a = begin(&p, &mut host, &[b"events"]);
        assert_eq!(a.outcome, Outcome::Ready, "{a:?}");
        let token = a.framing;
        // The empty message fails stream 1 while the offer is still being answered.
        let mut answers = vec![emit(&p, &mut host, token, 1, b"")];
        while answers.last().is_some_and(|a| a.flags & YIELD_MORE != 0) {
            assert!(answers.len() < 100, "no progress at frame cap {cap}");
            answers.push(timer(&p, &mut host, token));
        }
        let failed: Vec<&(u64, u16, Vec<u8>)> = answers
            .iter()
            .flat_map(|a| a.pieces.iter())
            .filter(|x| x.1 & PIECE_STREAM_FAILED != 0)
            .collect();
        assert_eq!(failed.len(), 1, "frame cap {cap}: {answers:?}");
        assert_eq!(failed[0].1, PIECE_STREAM_FAILED | PIECE_END_OF_FRAME);
        assert_eq!(
            String::from_utf8_lossy(&failed[0].2),
            String::from_utf8_lossy(&why),
            "frame cap {cap}: the reason, whole"
        );
    }
}

/// WHAT DOES NOT FIT ONE ANSWER CONTINUES IN THE NEXT, ONCE (codeaudit tests door.rs:651): over a
/// frame buffer of 10 bytes, the dialled offer comes in pieces that reassemble to a description
/// the far end accepts, each piece text and only the last ending the frame; the audio line's
/// head comes as a field block whose first piece starts a line and every later one continues it.
#[test]
fn what_does_not_fit_one_answer_continues_in_the_next() {
    let p = door();
    let mut host = Host::new(4096, 10);
    let mut answers = vec![begin_with(
        &p,
        &mut host,
        &[(b"channel", b"events"), (b"media", b"audio")],
    )];
    let token = answers[0].framing;
    while answers.last().is_some_and(|a| a.flags & YIELD_MORE != 0) {
        assert!(answers.len() < 1000, "no progress");
        answers.push(timer(&p, &mut host, token));
    }
    let pieces: Vec<&(u64, u16, Vec<u8>)> = answers.iter().flat_map(|a| a.pieces.iter()).collect();
    let of = |stream: u64| -> Vec<&(u64, u16, Vec<u8>)> {
        pieces.iter().copied().filter(|x| x.0 == stream).collect()
    };
    let offer = of(DESCRIPTION);
    let (last, rest) = offer.split_last().expect("the offer");
    assert!(rest.iter().all(|x| x.1 == PIECE_TEXT), "{rest:?}");
    assert_eq!(last.1, PIECE_TEXT | PIECE_END_OF_FRAME);
    let whole: Vec<u8> = offer.iter().flat_map(|x| x.2.clone()).collect();
    let now = Instant::now();
    let mut far = Framing::begin(
        Side::Accept,
        CERT,
        FAR.parse().ok(),
        &Opening::default(),
        now,
    )
    .expect("begins");
    far.rendezvous(&whole, now)
        .expect("the reassembled offer is the description");
    let head = of(1 << 32);
    let (first, later) = head.split_first().expect("the audio line's head");
    assert_eq!(first.1, PIECE_FIELDS, "the first piece starts the block");
    let (end, middle) = later.split_last().expect("split");
    assert!(middle.iter().all(|x| x.1 == PIECE_FIELDS | PIECE_CONTINUED));
    assert_eq!(end.1, PIECE_FIELDS | PIECE_CONTINUED | PIECE_END_OF_FRAME);
    let block: Vec<u8> = head.iter().flat_map(|x| x.2.clone()).collect();
    assert_eq!(block, b"kind: audio\r\ncodec: opus\r\n".to_vec());
}

fn finish(p: &Plugin<Transport>, host: &mut Host, token: u64) -> Answer {
    let l = host.lane(0);
    let mut i: FinishIn = conf::input();
    (i.framing, i.sink, i.lane) = (token, host.sink(), &l);
    let (outcome, why, o) = go(p, slot::FINISH, i);
    host.answer(outcome, why, &o)
}

/// ONE ASSOCIATION'S LOCK AND THE MAP'S ARE NEVER TAKEN IN OPPOSITE ORDERS (codeaudit tests
/// door.rs:718; PL11): an op that fails (and so forgets its framing, taking the map's lock while it
/// holds the association's) racing `finish` on the same framing (which lets the map's lock go
/// before it takes the association's) never deadlocks. A watchdog fails the test rather than hang.
#[test]
fn a_failing_op_racing_finish_never_deadlocks() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let p = door();
        for _ in 0..2000 {
            let token = begin(&p, &mut Host::new(4096, 16 * 1024), &[b"events"]).framing;
            std::thread::scope(|s| {
                s.spawn(|| {
                    ingest(
                        &p,
                        &mut Host::new(4096, 4096),
                        token,
                        LANE_RENDEZVOUS,
                        b"junk",
                    )
                });
                s.spawn(|| finish(&p, &mut Host::new(4096, 4096), token));
            });
        }
        let _ = done.send(());
    });
    finished
        .recv_timeout(Duration::from_secs(120))
        .expect("a failing op and finish deadlocked");
}
