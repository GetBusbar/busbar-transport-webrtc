// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Two framings, a dialling one and an accepting one, over a simulated host: the host assigns path
//! numbers, binds what a framing asks for (these tests judge the FRAMER's guards; the host's own
//! round-trip proof is the connector's, `busbar-core-connector/src/dtls/tests.rs`), stands in for
//! the secure layer (secured routes arrive as the far side's secured lane) and presents one keying
//! material to both ends once it marks them verified.

use core::net::SocketAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::*;

/// A placeholder certificate: the framer states its SHA-256 and nothing else reads it.
const CERT: &[u8] = b"public certificate bytes";

const PROFILE: u32 = PROFILE_AEAD_AES_128_GCM;

/// An Opus packet's bytes: one 20 ms CELT frame (config 31, code 0) and a payload.
const OPUS: &[u8] = &[0xF8, 0x01, 0x02, 0x03, 0x04];

/// One end: its framing and its host's view.
struct End {
    f: Framing,
    addr: SocketAddr,
    paths: HashMap<SocketAddr, u32>,
    by_id: HashMap<u32, SocketAddr>,
    bound: u32,
    verified: bool,
    keyed: bool,
    pieces: Vec<Piece>,
    requests: Vec<Request>,
    sent: Vec<Route>,
}

impl End {
    fn new(side: Side, addr: &str, opening: &Opening, now: Instant) -> Self {
        let addr: SocketAddr = addr.parse().expect("an address");
        End {
            f: Framing::begin(side, CERT, Some(addr), opening, now).expect("begins"),
            addr,
            paths: HashMap::new(),
            by_id: HashMap::new(),
            bound: 0,
            verified: false,
            keyed: false,
            pieces: Vec::new(),
            requests: Vec::new(),
            sent: Vec::new(),
        }
    }

    fn path(&mut self, a: SocketAddr) -> u32 {
        let n = self.paths.len() as u32 + 1;
        let p = *self.paths.entry(a).or_insert(n);
        self.by_id.insert(p, a);
        p
    }

    /// The description this end yielded on stream 0.
    fn description(&mut self) -> Vec<u8> {
        self.collect();
        let at = self
            .pieces
            .iter()
            .position(|p| p.stream == DESCRIPTION)
            .expect("a description");
        self.pieces.remove(at).bytes.to_vec()
    }

    fn collect(&mut self) {
        while let Some(p) = self.f.next_piece() {
            self.pieces.push(p);
        }
        while let Some(r) = self.f.take_request() {
            self.requests.push(r);
        }
    }

    /// Take the terms; a dialling end's host judges and numbers the far end's candidates.
    fn terms(&mut self) -> Terms {
        let t = self.f.take_terms().expect("terms");
        let known: Vec<(u32, SocketAddr)> =
            t.candidates.iter().map(|a| (self.path(*a), *a)).collect();
        self.f.paths(known);
        t
    }

    fn host(&mut self, keying: Option<&[u8]>, now: Instant) -> Result<(), Failed> {
        let r = self
            .f
            .host(self.bound, self.verified, keying.map(|k| (PROFILE, k)), now);
        if keying.is_some() && r.is_ok() {
            self.keyed = true;
        }
        self.collect();
        r
    }

    fn bind_what_was_asked(&mut self, now: Instant) {
        self.collect();
        for r in std::mem::take(&mut self.requests) {
            self.bound = match r {
                Request::Bind(p) | Request::Rebind(_, p) => p,
            };
        }
        let _ = self.host(None, now);
    }
}

/// Carry every route each end owes to the other, until both are quiet.
fn pump(a: &mut End, b: &mut End, now: Instant) {
    for _ in 0..200 {
        let mut moved = false;
        for flip in [false, true] {
            let (from, to) = if flip {
                (&mut *b, &mut *a)
            } else {
                (&mut *a, &mut *b)
            };
            while let Some(r) = from.f.next_route() {
                moved = true;
                from.sent.push(r.clone());
                let path = to.path(from.addr);
                let lane = r.lane;
                if lane == Lane::Secured && !(from.verified && to.verified) {
                    continue;
                }
                to.f.datagram(path, from.addr, lane, &r.bytes, now);
            }
            from.collect();
        }
        if !moved {
            break;
        }
    }
}

/// Run the clock and the pump for `ms`, in 10 ms steps.
fn run(a: &mut End, b: &mut End, start: &mut Instant, ms: u64) {
    for _ in 0..ms / 10 {
        *start += Duration::from_millis(10);
        for e in [&mut *a, &mut *b] {
            if e.f.next_timeout().is_some_and(|t| t <= *start) {
                e.f.timeout(*start);
            }
            e.bind_what_was_asked(*start);
        }
        pump(a, b, *start);
    }
}

fn opening() -> Opening {
    Opening {
        channels: vec!["events".into()],
        audio: true,
    }
}

/// Two ends through the rendezvous, ICE, verification and keying: a connected association.
fn connected() -> (End, End, Instant) {
    let mut now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let offer = dial.description();
    accept
        .f
        .rendezvous(&offer, now)
        .expect("the offer is accepted");
    let answer = accept.description();
    dial.f
        .rendezvous(&answer, now)
        .expect("the answer is accepted");
    let (ta, td) = (accept.terms(), dial.terms());
    assert_ne!(ta.initiates, td.initiates, "one end opens the handshake");
    assert_eq!(ta.remote_user, td.local_user);
    assert_eq!(td.remote_user, ta.local_user);
    run(&mut dial, &mut accept, &mut now, 3000);
    assert_ne!(dial.bound, 0, "the dialling end's nomination was bound");
    assert_ne!(accept.bound, 0, "the accepting end's nomination was bound");
    let material: Vec<u8> = (0..56).collect();
    for e in [&mut dial, &mut accept] {
        e.verified = true;
        e.host(Some(&material), now).expect("keyed");
    }
    run(&mut dial, &mut accept, &mut now, 3000);
    (dial, accept, now)
}

fn heard(e: &End, stream: u64) -> Vec<Vec<u8>> {
    e.pieces
        .iter()
        .filter(|p| p.stream == stream && !p.fields && !p.bytes.is_empty())
        .map(|p| p.bytes.to_vec())
        .collect()
}

#[test]
fn an_offer_and_an_answer_settle_terms_and_a_session_carries_messages_and_media_both_ways() {
    let (mut dial, mut accept, mut now) = connected();
    let head = |e: &End| {
        e.pieces
            .iter()
            .find(|p| p.fields && p.bytes.starts_with(b"label: "))
            .map(|p| (p.stream, p.bytes.to_vec()))
    };
    let (accept_stream, label) = head(&accept).expect("the accepting end opened the channel");
    assert_eq!(label, b"label: events\r\n");
    dial.f
        .emit(1, b"{\"type\":\"hello\"}", true, now)
        .expect("sent");
    accept
        .f
        .emit(accept_stream, b"{\"type\":\"world\"}", true, now)
        .expect("sent");
    run(&mut dial, &mut accept, &mut now, 500);
    assert_eq!(
        heard(&accept, accept_stream),
        [b"{\"type\":\"hello\"}".to_vec()]
    );
    assert_eq!(heard(&dial, 1), [b"{\"type\":\"world\"}".to_vec()]);
    // Opus passes through, byte for byte.
    let media = accept
        .pieces
        .iter()
        .find(|p| p.fields && p.bytes.starts_with(b"kind: audio"))
        .map(|p| p.stream)
        .expect("the accepting end saw the audio line");
    for _ in 0..5 {
        dial.f.emit(MEDIA_BASE, OPUS, false, now).expect("a frame");
        run(&mut dial, &mut accept, &mut now, 20);
    }
    assert!(
        heard(&accept, media).iter().any(|b| b == OPUS),
        "the frame arrived as sent"
    );
}

#[test]
fn a_keying_material_item_under_aes_cm_fails_the_framing() {
    let now = Instant::now();
    let mut e = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    e.verified = true;
    let material = [7_u8; 60];
    let refused = e.f.host(0, true, Some((0x0001, &material)), now);
    assert_eq!(refused, Err(crate::crypto::AES_CM_REFUSED.to_string()));
    assert!(
        !e.f.holds_keying(),
        "nothing of the refused material is held"
    );
    // Any profile outside the two GCM ones is refused the same way.
    assert!(e.f.host(0, true, Some((0x0002, &material)), now).is_err());
}

#[test]
fn keying_before_the_far_end_is_verified_is_refused() {
    let now = Instant::now();
    let mut e = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let material = [7_u8; 56];
    assert_eq!(
        e.f.host(0, false, Some((PROFILE, &material)), now),
        Err("keying material before the far end was verified".to_string())
    );
}

#[test]
fn application_data_before_peer_verification_is_dropped_unread() {
    let mut now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let offer = dial.description();
    accept.f.rendezvous(&offer, now).expect("accepted");
    let answer = accept.description();
    dial.f.rendezvous(&answer, now).expect("accepted");
    let _ = (accept.terms(), dial.terms());
    run(&mut dial, &mut accept, &mut now, 3000);
    // The far end's host has NOT verified: a secured datagram (an SCTP packet, say) and protected
    // media from the bound path reach the framer, and nothing is read or handed up.
    let path = accept.bound;
    assert_ne!(path, 0);
    let from = accept.by_id[&path];
    accept.f.datagram(
        path,
        from,
        Lane::Secured,
        &[0x13, 0x88, 0x13, 0x88, 0, 0, 0, 0, 0, 0, 0, 0],
        now,
    );
    accept.f.datagram(
        path,
        from,
        Lane::Clear,
        &[0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 9, 9, 9, 9],
        now,
    );
    accept.collect();
    assert!(
        accept
            .pieces
            .iter()
            .all(|p| p.fields || p.stream == DESCRIPTION),
        "no application data before verification: {:?}",
        accept.pieces
    );
    // And this end sends nothing secured or protected either.
    run(&mut dial, &mut accept, &mut now, 500);
    assert!(
        accept
            .sent
            .iter()
            .chain(dial.sent.iter())
            .all(|r| r.lane == Lane::Clear && stun::is_stun(&r.bytes)),
        "only checks and their answers cross before verification"
    );
}

/// The accepting end's own copy of the dialling end's last nominating check.
fn last_nomination(dial: &End) -> Vec<u8> {
    dial.sent
        .iter()
        .rev()
        .find(|r| {
            matches!(
                stun::read(&r.bytes),
                Some(Check::Request {
                    nominates: true,
                    ..
                })
            )
        })
        .map(|r| r.bytes.clone())
        .expect("the dialling end nominated")
}

#[test]
fn a_spoofed_migration_never_moves_media_off_the_bound_path() {
    let (mut dial, mut accept, mut now) = connected();
    let bound = accept.bound;
    let spoof: SocketAddr = "192.0.2.66:5555".parse().expect("an address");
    let spoof_path = accept.path(spoof);

    // A check with a forged MESSAGE-INTEGRITY from a new path: the ICE agent refuses it, no path
    // request is made.
    let mut forged = last_nomination(&dial);
    let n = forged.len();
    forged[n - 9] ^= 0xFF;
    accept
        .f
        .datagram(spoof_path, spoof, Lane::Clear, &forged, now);
    accept.collect();
    assert!(
        accept.requests.is_empty(),
        "a forged check asks for no path: {:?}",
        accept.requests
    );

    // A REPLAYED nomination (its integrity intact, its source spoofed) is only a request: media
    // stays on the bound path until the host proves the new one by its own round trip.
    let replayed = last_nomination(&dial);
    accept
        .f
        .datagram(spoof_path, spoof, Lane::Clear, &replayed, now);
    accept.collect();
    assert_eq!(
        accept.requests,
        [Request::Rebind(bound, spoof_path)],
        "a request, never a move"
    );
    accept.requests.clear();
    let media = accept
        .pieces
        .iter()
        .find(|p| p.fields && p.bytes.starts_with(b"kind: audio"))
        .map(|p| p.stream)
        .expect("the audio line");
    accept.sent.clear();
    for _ in 0..5 {
        accept.f.emit(media, OPUS, false, now).expect("a frame");
        now += Duration::from_millis(20);
        accept.f.timeout(now);
        while let Some(r) = accept.f.next_route() {
            accept.sent.push(r);
        }
    }
    let media_routes: Vec<&Route> = accept
        .sent
        .iter()
        .filter(|r| !stun::is_stun(&r.bytes))
        .collect();
    assert!(!media_routes.is_empty(), "media was sent");
    assert!(
        media_routes.iter().all(|r| r.path == bound),
        "every media datagram went to the bound path, none to the spoofed one"
    );
    // Protected media arriving from the unproven path is not read.
    let before = accept.pieces.len();
    accept.f.datagram(
        spoof_path,
        spoof,
        Lane::Clear,
        &[0x80, 0x6f, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 9, 9, 9, 9],
        now,
    );
    accept.collect();
    assert_eq!(
        accept.pieces.len(),
        before,
        "nothing read from an unbound path"
    );
    let _ = &mut dial;
}

#[test]
fn the_keying_material_is_handed_on_and_not_held() {
    let (dial, accept, _) = connected();
    assert!(!dial.f.holds_keying() && !accept.f.holds_keying());
}

#[test]
fn opus_frame_lengths_come_from_the_toc_byte() {
    // CELT 20 ms, one frame.
    assert_eq!(opus_samples(&[0xF8]), 960);
    // SILK 10 ms (config 0), two frames (code 1).
    assert_eq!(opus_samples(&[0x01]), 960);
    // Hybrid 20 ms (config 13), one frame.
    assert_eq!(opus_samples(&[13 << 3]), 960);
    // CELT 2.5 ms (config 16), code 3 with 6 frames.
    assert_eq!(opus_samples(&[(16 << 3) | 3, 6]), 720);
    assert_eq!(opus_samples(&[]), 0);
}

#[test]
fn a_dialling_framing_with_nothing_to_offer_is_refused() {
    let r = Framing::begin(Side::Dial, CERT, None, &Opening::default(), Instant::now());
    assert_eq!(
        r.err(),
        Some("a dialling framing offers nothing".to_string())
    );
}

/// A CHANNEL DELIVERS IN ORDER (an ordered data channel; the contract's stream is a sequence of
/// frames). A message the media stack has no room for is held, and a smaller one written after it
/// never overtakes it: it queues behind.
#[test]
fn a_held_message_is_never_overtaken() {
    let (mut dial, mut accept, mut now) = connected();
    let (stream, _) = accept
        .pieces
        .iter()
        .find(|p| p.fields && p.bytes.starts_with(b"label: "))
        .map(|p| (p.stream, p.bytes.to_vec()))
        .expect("the accepting end opened the channel");
    // The first two fill most of the stack's send buffer, the third does not fit beside them and
    // is held, the fourth would fit.
    let sent = [
        vec![1_u8; 60_000],
        vec![2_u8; 60_000],
        vec![3_u8; 20_000],
        b"fourth".to_vec(),
    ];
    for m in &sent {
        dial.f.emit(1, m, false, now).expect("taken");
    }
    run(&mut dial, &mut accept, &mut now, 3000);
    let got: Vec<usize> = heard(&accept, stream).iter().map(Vec::len).collect();
    let want: Vec<usize> = sent.iter().map(Vec::len).collect();
    assert_eq!(got, want, "the channel delivered out of order");
}

/// A FAILED STREAM FAILS ALONE (the transport contract: "A failed stream fails alone: its siblings
/// on the connection carry on"). A host that keeps emitting on a channel past what the framer
/// holds for it costs that channel, never the association.
#[test]
fn one_channels_overflow_never_fails_the_association() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    // The channel is not open yet: every message is held.
    for n in 0..(MAX_HELD + 50) {
        if let Err(e) = dial.f.emit(1, &[n as u8; 8], false, now) {
            panic!("one channel's overflow failed the whole association: {e}");
        }
    }
    assert_eq!(dial.f.failure(), None, "the association carries on");
}

/// THE RENDEZVOUS TERMS ARE BOUNDED: a far end's description that advertises any number of
/// candidates yields terms of a bounded size, so they always fit a host's frame buffer whole.
#[test]
fn a_far_ends_candidates_are_read_up_to_a_bound() {
    let mut d = String::from(
        "v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef0123456789\r\n\
         a=fingerprint:sha-256 ",
    );
    d.push_str(&["AB"; 32].join(":"));
    d.push_str("\r\n");
    for n in 0..5000_u32 {
        d.push_str(&format!(
            "a=candidate:{n} 1 udp 2130706431 10.{}.{}.{} 9 typ host\r\n",
            (n >> 16) & 0xff,
            (n >> 8) & 0xff,
            n & 0xff
        ));
    }
    let (_, _, _, candidates) = read_remote(&d).expect("terms");
    assert!(!candidates.is_empty(), "candidates are read");
    assert!(
        candidates.len() <= 64,
        "{} candidates read from one description: the terms grow without bound",
        candidates.len()
    );
}

/// ICE'S "DISCONNECTED" IS RECOVERABLE (Q128 transport-webrtc LOW, reader r171 on 78941e3; RFC
/// 8445 and the media stack's own state: a disconnected agent may come back as it checks pairs
/// again): the association holds through it, comes back on its own when the path returns, and
/// ends only when the path stays gone past [`ICE_FAILED_AFTER`]. RED before the fix: the first
/// "disconnected" ended the association, so a network switch slower than the pair timeout ended
/// the call.
#[test]
fn an_ice_disconnect_holds_the_association_until_it_fails() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Disconnected,
    ));
    assert!(!dial.f.ended(), "a disconnect is not an end");
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Connected,
    ));
    dial.f
        .timeout(now + ICE_FAILED_AFTER + Duration::from_secs(1));
    assert!(!dial.f.ended(), "a path that came back carries on");

    let at = now + ICE_FAILED_AFTER + Duration::from_secs(2);
    dial.f.timeout(at);
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Disconnected,
    ));
    dial.f
        .timeout(at + ICE_FAILED_AFTER - Duration::from_secs(1));
    assert!(!dial.f.ended(), "inside the window the association holds");
    dial.f
        .timeout(at + ICE_FAILED_AFTER + Duration::from_secs(1));
    assert!(
        dial.f.ended(),
        "a path gone past the window has failed: the association ends"
    );
}

/// AN ACKNOWLEDGED MESSAGE IS NEVER DROPPED SILENTLY (Q128 transport-webrtc LOW, reader r171 on
/// 78941e3): a data channel's message the reliable channel has already acknowledged, arriving
/// while the framer's piece queue is at its cap, fails its stream loudly (its failure piece), so
/// the layer above knows the stream lost data. RED before the fix: the message vanished.
#[test]
fn a_channel_message_at_the_queue_cap_fails_its_stream_loudly() {
    let (mut dial, _accept, _now) = connected();
    let (&id, &stream) = dial.f.channels.iter().next().expect("an open channel");
    while dial.f.pieces.len() < MAX_HELD * 4 {
        dial.f.pieces.push_back(Piece {
            stream: 99,
            bytes: vec![0].into(),
            fields: false,
            text: false,
            end: false,
            failed: false,
            writable: false,
        });
    }
    dial.f
        .event(Event::ChannelData(str0m::channel::ChannelData {
            id,
            binary: true,
            data: vec![7],
        }));
    assert!(
        dial.f.stream_failed(stream),
        "the stream that lost data fails"
    );
    assert!(
        dial.f.pieces.iter().any(|p| p.stream == stream && p.failed),
        "with its failure piece"
    );
}

/// THE CHECK SECRET NEVER REACHES A LOG (THE DESIGN §5, "keys are zeroised"; the same class of
/// secret): the media stack logs its ICE credentials with `{:?}` (debug and trace), and a busbar
/// that links this framer has its log subscriber installed, so their Debug form must not state the
/// password. RED before the fix: str0m's IceCreds derived Debug and printed it in clear.
#[test]
fn the_ice_credentials_debug_form_never_states_the_password() {
    let f = Framing::begin(
        Side::Accept,
        CERT,
        Some("203.0.113.9:3478".parse().expect("an address")),
        &Opening::default(),
        Instant::now(),
    )
    .expect("begins");
    let pass = f.local_creds.pass.clone();
    assert_eq!(pass.len(), 32, "a 128-bit secret, hex");
    let shown = format!("{:?}", f.local_creds);
    assert!(
        !shown.contains(&pass),
        "the password is in the Debug form: {shown}"
    );
    assert!(
        shown.contains(&f.local_creds.ufrag),
        "the user name is shown: {shown}"
    );
}
