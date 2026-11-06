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
    /// The protection profile its host keys under.
    profile: u32,
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
            profile: PROFILE,
        }
    }

    fn path(&mut self, a: SocketAddr) -> u32 {
        let n = self.paths.len() as u32 + 1;
        let p = *self.paths.entry(a).or_insert(n);
        self.by_id.insert(p, a);
        p
    }

    /// The description this end yielded on stream 0.
    fn description(&mut self) -> zeroize::Zeroizing<Vec<u8>> {
        self.collect();
        let at = self
            .pieces
            .iter()
            .position(|p| p.stream == DESCRIPTION)
            .expect("a description");
        self.pieces.remove(at).into_bytes()
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
        let r = self.f.host(
            self.bound,
            self.verified,
            keying.map(|k| (self.profile, k)),
            now,
        );
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
    connected_under(PROFILE, 56)
}

/// [`connected`], keyed under `profile` with `len` bytes of material.
fn connected_under(profile: u32, len: u8) -> (End, End, Instant) {
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
    let material: Vec<u8> = (0..len).collect();
    for e in [&mut dial, &mut accept] {
        e.profile = profile;
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
        .map(|p| p.bytes.clone())
        .collect()
}

fn report_feedback(to: &mut End, from: SocketAddr, bytes: &[u8], now: Instant) -> usize {
    let receive = Receive::new(Protocol::Udp, from, to.addr, bytes).unwrap();
    to.f.rtc.handle_input(Input::Receive(now, receive)).unwrap();
    let mut reports = 0;
    loop {
        match to.f.rtc.poll_output().unwrap() {
            Output::Event(Event::SenderFeedback(_)) => reports += 1,
            Output::Timeout(_) => break,
            _ => {}
        }
    }
    reports
}

#[test]
fn an_authenticated_srtcp_replay_does_not_reapply_sender_report_state() {
    for (profile, key_len) in [
        (PROFILE_AEAD_AES_128_GCM, 56),
        (PROFILE_AEAD_AES_256_GCM, 88),
    ] {
        let (mut dial, mut accept, mut now) = connected_under(profile, key_len);
        dial.f.emit(MEDIA_BASE, OPUS, false, now).unwrap();
        accept.f.emit(MEDIA_BASE, OPUS, false, now).unwrap();
        run(&mut dial, &mut accept, &mut now, 12_000);
        for flip in [false, true] {
            let (from, to) = if flip {
                (&mut accept, &mut dial)
            } else {
                (&mut dial, &mut accept)
            };
            let reports: Vec<_> = from
                .sent
                .iter()
                .filter(|r| r.lane == Lane::Clear && r.bytes.get(1) == Some(&200))
                .collect();
            assert!(
                reports.len() >= 2,
                "two actual protected sender reports required"
            );
            let old = reports[reports.len() - 2].bytes.clone();
            let recent = reports.last().unwrap().bytes.clone();
            assert_ne!(old, recent);
            now += Duration::from_millis(1);
            assert_eq!(
                report_feedback(to, from.addr, &old, now),
                0,
                "old authenticated report reapplied"
            );
            assert_eq!(
                report_feedback(to, from.addr, &recent, now),
                0,
                "latest authenticated report reapplied"
            );

            now += Duration::from_secs(6);
            from.f.emit(MEDIA_BASE, OPUS, false, now).unwrap();
            from.f.timeout(now);
            let mut new_reports = Vec::new();
            while let Some(route) = from.f.next_route() {
                if route.lane == Lane::Clear && route.bytes.get(1) == Some(&200) {
                    new_reports.push(route.bytes);
                }
            }
            assert!(!new_reports.is_empty(), "new sender report required");
            for fresh in new_reports {
                assert_eq!(report_feedback(to, from.addr, &fresh, now), 1);
                assert_eq!(report_feedback(to, from.addr, &fresh, now), 0);
            }
        }
    }
}

#[test]
fn an_exhausted_srtcp_sender_ends_the_real_transmitter_without_further_wire_output() {
    for (profile, key_len) in [
        (PROFILE_AEAD_AES_128_GCM, 56),
        (PROFILE_AEAD_AES_256_GCM, 88),
    ] {
        let injection = crate::crypto::sender_tests::ExhaustSender::start();
        let (mut dial, mut accept, mut now) = connected_under(profile, key_len);
        dial.f.emit(MEDIA_BASE, OPUS, false, now).unwrap();
        accept.f.emit(MEDIA_BASE, OPUS, false, now).unwrap();
        run(&mut dial, &mut accept, &mut now, 20_000);
        let (ssrc, attempts, primed) = injection.snapshot();
        assert!(
            primed,
            "the real transmitter must make two protected RTCP calls"
        );
        assert_eq!(
            attempts, 2,
            "a failed association must stop invoking its sender cipher"
        );
        let failed = if dial.f.failure().is_some() {
            &mut dial
        } else {
            &mut accept
        };
        assert!(
            failed.f.failure().is_some(),
            "upstream encryption failure must end the association"
        );
        let reports: Vec<_> = failed
            .sent
            .iter()
            .filter(|route| {
                route.lane == Lane::Clear
                    && route.bytes.len() >= 8
                    && route.bytes[1] == 200
                    && route.bytes[4..8] == ssrc
            })
            .collect();
        assert_eq!(reports.len(), 1, "only the first genuine report reaches the wire; the synthetic terminal seal never does");
        let first_index = u32::from_be_bytes(
            reports[0].bytes[reports[0].bytes.len() - 4..]
                .try_into()
                .unwrap(),
        );
        assert!(first_index & 0x8000_0000 != 0 && first_index != u32::MAX);
        let failure = failed.f.failure().unwrap().to_owned();
        failed.f.timeout(now + Duration::from_secs(60));
        failed.f.finish(now + Duration::from_secs(61));
        assert_eq!(failed.f.failure(), Some(failure.as_str()));
        assert!(
            failed.f.next_route().is_none(),
            "a failed transmitter must never resume output"
        );
        assert_eq!(injection.snapshot().1, attempts);
    }
}

#[test]
fn an_offer_and_an_answer_settle_terms_and_a_session_carries_messages_and_media_both_ways() {
    let (mut dial, mut accept, mut now) = connected();
    let head = |e: &End| {
        e.pieces
            .iter()
            .find(|p| p.fields && p.bytes.starts_with(b"label: "))
            .map(|p| (p.stream, p.bytes.clone()))
    };
    let (accept_stream, label) = head(&accept).expect("the accepting end opened the channel");
    assert_eq!(label, b"label: events\r\nopening-pending: 0\r\n");
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

    let binary = [0, 255, 1, 2];
    dial.f.emit(1, &binary, false, now).unwrap();
    accept.f.emit(accept_stream, &binary, false, now).unwrap();
    run(&mut dial, &mut accept, &mut now, 500);
    for end in [&dial, &accept] {
        assert!(end.pieces.iter().any(|p| p.bytes == binary && !p.text));
        assert!(end
            .pieces
            .iter()
            .any(|p| p.text && p.bytes.starts_with(b"{\"type\":")));
    }

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
    let (dial, mut accept, mut now) = connected();
    let bound = accept.bound;
    let spoof: SocketAddr = "192.0.2.66:5555".parse().expect("an address");
    let spoof_path = accept.path(spoof);

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
}

#[test]
fn the_keying_material_is_handed_on_and_not_held() {
    let (dial, accept, _) = connected();
    assert!(!dial.f.holds_keying() && !accept.f.holds_keying());
}

#[test]
fn opus_frame_lengths_come_from_the_toc_byte() {
    assert_eq!(opus_samples(&[0xF8]), 960);

    assert_eq!(opus_samples(&[0x01]), 960);

    assert_eq!(opus_samples(&[13 << 3]), 960);

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
        .map(|p| (p.stream, p.bytes.clone()))
        .expect("the accepting end opened the channel");

    let sent = [
        vec![1_u8; 60_000],
        vec![2_u8; 59_999],
        vec![3_u8; 20_000],
        b"fourth".to_vec(),
    ];
    for (n, m) in sent.iter().enumerate() {
        if n == 3 {
            assert!(
                !dial.f.held(1).is_empty(),
                "the third is held when the fourth comes, or this proves nothing"
            );
        }
        dial.f.emit(1, m, false, now).expect("taken");
    }
    run(&mut dial, &mut accept, &mut now, 3000);
    assert_eq!(
        heard(&accept, stream),
        sent.to_vec(),
        "the channel delivered out of order"
    );
}

/// A FAILED STREAM FAILS ALONE (the transport contract: "A failed stream fails alone: its siblings
/// on the connection carry on"). A host that keeps emitting on a channel past what the framer
/// holds for it costs that channel, never the association.
#[test]
fn one_channels_overflow_never_fails_the_association() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);

    for n in 0..(MAX_HELD + 50) {
        if let Err(e) = dial.f.emit(1, &[n as u8; 8], false, now) {
            panic!("one channel's overflow failed the whole association: {e}");
        }
        assert!(dial.f.held(1).len() <= MAX_HELD, "held past the cap");
    }
    assert_eq!(dial.f.failure(), None, "the association carries on");

    assert!(dial.f.stream_failed(1), "the channel that overflowed fails");
    dial.collect();
    let failed: Vec<&Piece> = dial
        .pieces
        .iter()
        .filter(|p| p.stream == 1 && p.failed)
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].bytes,
        b"too many messages held for the channel".to_vec()
    );
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

    assert_eq!(
        candidates.len(),
        MAX_CANDIDATES,
        "{} candidates read from one description",
        candidates.len()
    );
}

/// An ICE disconnect retains the association while recovery is still possible.
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

/// Payload admission leaves room inside the queue cap for the stream's failure.
#[test]
fn a_channel_message_at_the_queue_cap_fails_its_stream_loudly() {
    let (mut dial, _accept, _now) = connected();
    let (&id, &stream) = dial.f.channels.iter().next().expect("an open channel");
    assert!(dial.f.pieces.is_empty());
    for _ in 0..MAX_QUEUED - 1 {
        dial.f
            .event(Event::ChannelData(str0m::channel::ChannelData {
                id,
                binary: true,
                data: vec![0],
            }));
    }
    assert_eq!(dial.f.pieces.len(), MAX_QUEUED - 1);
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
    assert!(dial.f.failure().is_none(), "the association carries on");
    assert_eq!(dial.f.pieces.len(), MAX_QUEUED, "the cap is unchanged");
    // Further events on the failed stream neither append data nor repeat the failure.
    dial.f
        .event(Event::ChannelData(str0m::channel::ChannelData {
            id,
            binary: true,
            data: vec![8],
        }));
    for _ in 0..MAX_QUEUED - 1 {
        let piece = dial.f.next_piece().expect("previously admitted data");
        assert_eq!(piece.stream, stream);
        assert_eq!(piece.bytes, [0]);
        assert!(!piece.failed);
    }
    let failure = dial.f.next_piece().expect("one terminal failure");
    assert_eq!(failure.stream, stream);
    assert!(failure.failed);
    assert_eq!(
        failure.bytes,
        b"the data channel's messages outran the host: its queue reached the cap"
    );
    assert!(dial.f.next_piece().is_none());
}

/// A channel label containing a line break fails its stream without forging a field.
#[test]
fn a_channel_label_with_a_line_break_fails_its_stream_and_forges_no_field() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let (&id, &stream) = dial.f.channels.iter().next().expect("the offered channel");
    for label in ["x\r\n:status: 200", "a\nb", "c\rd"] {
        dial.f.event(Event::ChannelOpen(id, label.to_string()));
    }
    dial.collect();
    assert!(
        dial.pieces
            .iter()
            .all(|p| !(p.stream == stream && p.fields)),
        "no field block carries the label: {:?}",
        dial.pieces
    );
    assert!(dial.f.stream_failed(stream), "the channel is refused");
    let failed: Vec<&Piece> = dial
        .pieces
        .iter()
        .filter(|p| p.stream == stream && p.failed)
        .collect();
    assert_eq!(failed.len(), 1, "one failure piece");
    assert_eq!(
        failed[0].bytes,
        b"the far end's channel label holds a line break".to_vec()
    );
}

/// An empty message fails its channel with an explanation rather than wedging it.
#[test]
fn an_empty_message_fails_its_channel_in_words_rather_than_wedge_it() {
    let (mut dial, mut accept, mut now) = connected();
    dial.f.emit(1, b"", true, now).expect("taken");
    run(&mut dial, &mut accept, &mut now, 500);
    assert!(
        dial.f.stream_failed(1),
        "the channel that cannot carry it fails"
    );
    assert!(
        dial.pieces.iter().any(|p| p.stream == 1
            && p.failed
            && p.bytes == b"an empty message, which the media stack cannot send"),
        "with its failure piece, in words: {:?}",
        dial.pieces
    );
    assert_eq!(dial.f.failure(), None, "the association carries on");
}

/// A channel closed by the far end accepts no further messages.
#[test]
fn a_channel_the_far_end_closed_takes_no_more_messages() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let (&id, &stream) = dial.f.channels.iter().next().expect("the offered channel");
    dial.f.event(Event::ChannelClose(id));
    assert_eq!(dial.f.emit(stream, b"late", false, now), Ok(()));
    assert!(dial.f.held(stream).is_empty(), "nothing is held for it");
    assert_eq!(dial.f.failure(), None, "the association carries on");
    assert_eq!(
        dial.f.emit(99, b"never", false, now),
        Err("no stream 99 on this association".to_string())
    );
    dial.f.fail_stream(stream, "too late");
    dial.collect();
    let ours: Vec<&Piece> = dial.pieces.iter().filter(|p| p.stream == stream).collect();
    assert_eq!(ours.len(), 1, "the END piece alone: {ours:?}");
    assert!(ours[0].end);
}

/// Closing a channel and repointing a path release their bookkeeping.
#[test]
fn a_closed_channel_and_a_repointed_path_leave_no_bookkeeping() {
    let now = Instant::now();
    let two = Opening {
        channels: vec!["a".into(), "b".into()],
        audio: false,
    };
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &two, now);
    let ids: Vec<(str0m::channel::ChannelId, u64)> =
        dial.f.channels.iter().map(|(i, s)| (*i, *s)).collect();

    dial.f.fail_stream(ids[0].1, "refused");
    for (id, _) in &ids {
        dial.f.event(Event::ChannelClose(*id));
    }
    for (id, s) in &ids {
        assert!(!dial.f.channels.contains_key(id), "channel {s} forgotten");
        assert!(
            !dial.f.channel_by_stream.contains_key(s),
            "stream {s} forgotten"
        );
        assert!(!dial.f.failed_sids.contains(s), "failure of {s} forgotten");
    }
    let addr = |s: &str| s.parse::<SocketAddr>().expect("an address");
    dial.f.paths([(7, addr("192.0.2.1:1000"))]);
    dial.f.paths([(7, addr("192.0.2.2:1000"))]);
    let junk = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
    dial.f
        .datagram(8, addr("192.0.2.3:1000"), Lane::Clear, &junk, now);
    dial.f
        .datagram(8, addr("192.0.2.4:1000"), Lane::Clear, &junk, now);
    assert_eq!(
        dial.f.addrs.len(),
        2,
        "only the addresses paths now point at: {:?}",
        dial.f.addrs
    );
    assert_eq!(dial.f.addrs.get(&addr("192.0.2.2:1000")), Some(&7));
    assert_eq!(dial.f.addrs.get(&addr("192.0.2.4:1000")), Some(&8));
}

/// A forged STUN binding success nominates no path, as RFC 8489 and RFC 8445 require.
#[test]
fn a_forged_binding_success_nominates_nothing() {
    let (mut dial, _accept, now) = connected();
    dial.requests.clear();
    let other: SocketAddr = "192.0.2.77:6000".parse().expect("an address");
    let p2 = dial.path(other);
    dial.f.paths([(p2, other)]);
    let txid = [7_u8; 12];
    dial.f.track(txid, p2);
    let mut forged = vec![0x01, 0x01, 0, 24, 0x21, 0x12, 0xA4, 0x42];
    forged.extend_from_slice(&txid);
    forged.extend_from_slice(&[0, 8, 0, 20]);
    forged.extend_from_slice(&[0_u8; 20]);
    dial.f.datagram(p2, other, Lane::Clear, &forged, now);
    dial.collect();
    assert!(
        dial.requests.is_empty(),
        "a forged answer asks for no path: {:?}",
        dial.requests
    );
}

/// A STUN message as RFC 8489 §5 frames it: `kind`, a body of `attrs`, the header's length `len`.
fn stun_message(kind: u16, len: u16, attrs: &[u8]) -> Vec<u8> {
    let mut m = kind.to_be_bytes().to_vec();
    m.extend_from_slice(&len.to_be_bytes());
    m.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    m.extend_from_slice(&[9_u8; 12]);
    m.extend_from_slice(attrs);
    m
}

/// Only a well-framed STUN check is read, as RFC 8489 requires.
#[test]
fn only_a_well_framed_check_is_read() {
    let use_candidate = [0x00, 0x25, 0, 0];
    assert_eq!(
        stun::read(&stun_message(1, 4, &use_candidate)),
        Some(Check::Request {
            txid: [9; 12],
            nominates: true
        }),
        "a well-framed nominating request is read"
    );

    assert_eq!(stun::read(&stun_message(1, 1, &use_candidate[..1])), None);

    let mut trailing = stun_message(1, 4, &use_candidate);
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(stun::read(&trailing), None);

    let valued = [0x00, 0x25, 0, 4, 1, 2, 3, 4];
    assert_eq!(
        stun::read(&stun_message(1, 8, &valued)),
        Some(Check::Request {
            txid: [9; 12],
            nominates: false
        })
    );
}

/// Each fingerprint octet is exactly two hexadecimal digits, as RFC 4572 requires.
#[test]
fn a_fingerprint_octet_is_exactly_two_hex_digits() {
    let with = |octets: &str| {
        format!(
            "v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef0123456789\r\n\
             a=fingerprint:sha-256 {octets}\r\n"
        )
    };
    assert!(read_remote(&with(&["AB"; 32].join(":"))).is_ok());
    for bad in ["+F", "1", "-1", "ABC"] {
        let mut octets = vec!["AB"; 31];
        octets.insert(0, bad);
        assert_eq!(
            read_remote(&with(&octets.join(":"))).err(),
            Some("a malformed fingerprint".to_string()),
            "{bad:?} is no octet"
        );
    }
}

/// A host port address refused by the media stack refuses the framing.
#[test]
fn a_host_port_address_the_stack_refuses_refuses_the_framing() {
    for addr in ["0.0.0.0:3478", "[::]:3478", "224.0.0.1:3478"] {
        let local: SocketAddr = addr.parse().expect("an address");
        for (side, opening) in [(Side::Accept, Opening::default()), (Side::Dial, opening())] {
            let r = Framing::begin(side, CERT, Some(local), &opening, Instant::now());
            assert_eq!(
                r.err(),
                Some(format!(
                    "the host port's address {local} is no candidate the media stack takes"
                )),
                "{side:?} at {addr}"
            );
        }
    }
}

/// Every route `e` owes, taken and not carried.
fn owed(e: &mut End) -> Vec<Route> {
    std::iter::from_fn(|| e.f.next_route()).collect()
}

/// The stream whose head starts `with`, on `e`.
fn stream_headed(e: &End, with: &[u8]) -> u64 {
    e.pieces
        .iter()
        .find(|p| p.fields && p.bytes.starts_with(with))
        .map(|p| p.stream)
        .expect("a stream with that head")
}

/// Application data is not read before verification.
#[test]
fn valid_application_data_is_not_read_before_verification() {
    let (mut dial, mut accept, now) = connected();
    let (channel, media) = (
        stream_headed(&accept, b"label: "),
        stream_headed(&accept, b"kind: audio"),
    );
    let _ = owed(&mut accept);
    dial.f
        .emit(1, b"before verification", true, now)
        .expect("taken");
    dial.f.emit(MEDIA_BASE, OPUS, false, now).expect("a frame");

    let now = now + Duration::from_millis(20);
    dial.f.timeout(now);
    let datagrams = owed(&mut dial);
    assert!(datagrams.iter().any(|r| r.lane == Lane::Secured));
    assert!(datagrams
        .iter()
        .any(|r| r.lane == Lane::Clear && !stun::is_stun(&r.bytes)));
    let path = accept.path(dial.addr);
    let before = (heard(&accept, channel).len(), heard(&accept, media).len());
    accept.f.verified = false;
    for r in &datagrams {
        accept.f.datagram(path, dial.addr, r.lane, &r.bytes, now);
    }
    accept.collect();
    assert_eq!(
        (heard(&accept, channel).len(), heard(&accept, media).len()),
        before,
        "nothing read before verification"
    );

    accept.f.verified = true;
    for r in &datagrams {
        accept.f.datagram(path, dial.addr, r.lane, &r.bytes, now);
    }
    accept.collect();
    assert_eq!(
        heard(&accept, channel).last(),
        Some(&b"before verification".to_vec())
    );
    assert_eq!(heard(&accept, media).last(), Some(&OPUS.to_vec()));
}

/// A genuine media frame from an unbound path is not read.
#[test]
fn a_genuine_media_frame_from_an_unbound_path_is_not_read() {
    let (mut dial, mut accept, now) = connected();
    let media = stream_headed(&accept, b"kind: audio");
    let spoof: SocketAddr = "192.0.2.66:5555".parse().expect("an address");
    let spoof_path = accept.path(spoof);
    dial.f.emit(MEDIA_BASE, OPUS, false, now).expect("a frame");
    let now = now + Duration::from_millis(20);
    dial.f.timeout(now);
    let frames: Vec<Route> = owed(&mut dial)
        .into_iter()
        .filter(|r| r.lane == Lane::Clear && !stun::is_stun(&r.bytes))
        .collect();
    assert!(!frames.is_empty(), "a protected frame");
    let before = heard(&accept, media).len();
    for r in &frames {
        accept
            .f
            .datagram(spoof_path, spoof, Lane::Clear, &r.bytes, now);
    }
    accept.collect();
    assert_eq!(
        heard(&accept, media).len(),
        before,
        "not read from a spoofed path"
    );
    let bound = accept.bound;
    for r in &frames {
        accept
            .f
            .datagram(bound, dial.addr, Lane::Clear, &r.bytes, now);
    }
    accept.collect();
    assert_eq!(
        heard(&accept, media).len(),
        before + 1,
        "read from the bound path"
    );
}

/// A far-end datagram in the relay range is never fed to the shim.
#[test]
fn a_far_ends_datagram_in_the_relay_range_is_never_fed() {
    let (mut dial, mut accept, mut now) = connected();
    let media = stream_headed(&accept, b"kind: audio");
    let bound = accept.bound;
    let mut forged_keying = vec![20, 7];
    forged_keying.extend_from_slice(&[0x55; 56]);
    for d in [forged_keying, vec![21], vec![22, 0x13, 0x88, 0x13, 0x88]] {
        accept.f.datagram(bound, dial.addr, Lane::Clear, &d, now);
    }
    assert_eq!(accept.f.failure(), None);
    let before = heard(&accept, media).len();
    for _ in 0..5 {
        dial.f.emit(MEDIA_BASE, OPUS, false, now).expect("a frame");
        run(&mut dial, &mut accept, &mut now, 20);
    }
    assert!(
        heard(&accept, media).len() > before,
        "the genuine media is still read: nothing re-keyed it"
    );
}

/// A disconnect after recovery starts a fresh outage window.
#[test]
fn a_disconnect_after_a_return_is_timed_from_the_second_outage() {
    let t0 = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), t0);
    let s = Duration::from_secs;
    dial.f.timeout(t0);
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Disconnected,
    ));
    dial.f.timeout(t0 + s(5));
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Connected,
    ));
    dial.f.timeout(t0 + s(25));
    dial.f.event(Event::IceConnectionStateChange(
        IceConnectionState::Disconnected,
    ));
    dial.f.timeout(t0 + s(31));
    assert!(!dial.f.ended(), "5 s into the second outage it holds");
    dial.f.timeout(t0 + s(25) + ICE_FAILED_AFTER + s(1));
    assert!(
        dial.f.ended(),
        "past the window from the second outage it ends"
    );
}

/// A full channel becomes writable again after it drains.
#[test]
fn a_full_channel_is_writable_again_once_drained() {
    let (mut dial, mut accept, mut now) = connected();

    for m in [vec![1_u8; 60_000], vec![2_u8; 60_000]] {
        dial.f.emit(1, &m, false, now).expect("taken");
    }
    for n in 0..HIGH_WATER {
        assert!(!dial.f.stream_full(1), "full only at the mark");
        dial.f
            .emit(1, &[n as u8; 20_000], false, now)
            .expect("taken");
    }
    assert!(dial.f.stream_full(1), "FULL at the high-water mark");
    run(&mut dial, &mut accept, &mut now, 3000);
    assert!(!dial.f.stream_full(1), "writable once drained");
    let writable = dial
        .pieces
        .iter()
        .filter(|p| p.stream == 1 && p.writable)
        .count();
    assert_eq!(writable, 1, "one writable piece");
}

/// Closing a data channel ends the corresponding far-end stream.
#[test]
fn a_channel_closed_by_one_end_ends_the_far_ends_stream() {
    let (mut dial, mut accept, mut now) = connected();
    let stream = stream_headed(&accept, b"label: ");
    let (&id, _) = dial.f.channels.iter().next().expect("the channel");
    dial.f.rtc.direct_api().close_data_channel(id);
    run(&mut dial, &mut accept, &mut now, 3000);
    let ours: Vec<&Piece> = accept
        .pieces
        .iter()
        .filter(|p| p.stream == stream)
        .collect();
    assert_eq!(ours.iter().filter(|p| p.end).count(), 1, "{ours:?}");
    assert!(
        ours.last().is_some_and(|p| p.end),
        "the END is its last piece"
    );
}

/// Route, nomination, and message caps bound retained work.
#[test]
fn the_route_nominating_and_message_caps_hold() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let far: SocketAddr = "203.0.113.9:3478".parse().expect("an address");
    dial.f.paths([(1, far)]);
    while dial.f.routes.len() < MAX_QUEUED {
        dial.f.routes.push_back(Route {
            bytes: vec![0],
            path: 1,
            lane: Lane::Clear,
        });
    }
    dial.f.transmit(far, stun_message(1, 0, &[]));
    assert_eq!(dial.f.routes.len(), MAX_QUEUED, "no route past the cap");
    for n in 0..(3 * MAX_NOMINATING) {
        dial.f.track([n as u8; 12], 1);
        assert!(dial.f.nominating.len() <= MAX_NOMINATING);
    }

    let (mut dial, mut accept, mut now) = connected();
    dial.f
        .emit(1, &vec![7; MAX_MESSAGE], false, now)
        .expect("taken");
    assert!(!dial.f.stream_failed(1), "a message at the cap is sent");
    run(&mut dial, &mut accept, &mut now, 3000);
    dial.f
        .emit(1, &vec![7; MAX_MESSAGE + 1], false, now)
        .expect("taken");
    assert!(
        dial.f.stream_failed(1),
        "one byte past it fails the channel"
    );
    dial.collect();
    assert!(dial.pieces.iter().any(|p| p.stream == 1
        && p.failed
        && p.bytes == b"a message larger than the channel can ever send"));
}

/// The local description states its certificate's SHA-256 fingerprint.
#[test]
fn the_description_states_the_certificates_sha_256() {
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), Instant::now());
    let offer = dial.description();
    let offer = std::str::from_utf8(&offer).expect("text");
    let want: Vec<String> = ring::digest::digest(&ring::digest::SHA256, CERT)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let stated = values(offer, "a=fingerprint:sha-256 ")
        .next()
        .expect("a fingerprint line");
    assert_eq!(stated.trim().to_ascii_uppercase(), want.join(":"));
}

/// An association keyed with AEAD-AES-256-GCM carries media and messages in both directions.
#[test]
fn an_association_keyed_under_aes_256_gcm_carries_both_ways() {
    let (mut dial, mut accept, mut now) = connected_under(PROFILE_AEAD_AES_256_GCM, 88);
    let (channel, media) = (
        stream_headed(&accept, b"label: "),
        stream_headed(&accept, b"kind: audio"),
    );
    dial.f.emit(1, b"over 256", true, now).expect("sent");
    for _ in 0..5 {
        dial.f.emit(MEDIA_BASE, OPUS, false, now).expect("a frame");
        run(&mut dial, &mut accept, &mut now, 20);
    }
    run(&mut dial, &mut accept, &mut now, 500);
    assert_eq!(heard(&accept, channel), [b"over 256".to_vec()]);
    assert!(heard(&accept, media).iter().any(|b| b == OPUS));
}

#[test]
fn a_failed_association_refuses_host_updates_and_both_emit_paths() {
    for (profile, key_len) in [
        (PROFILE_AEAD_AES_128_GCM, 56),
        (PROFILE_AEAD_AES_256_GCM, 88),
    ] {
        let (mut dial, _accept, now) = connected_under(profile, key_len);
        assert!(dial.f.carries(MEDIA_BASE));
        assert!(dial.f.carries(1));
        let bound = dial.f.bound;
        let clocks = dial.f.media_clock.clone();
        let held = dial.f.held(1);
        let why = "the media stack panicked while producing output";
        dial.f.fail(why.into());
        assert_eq!(
            dial.f.host(bound + 1, true, None, now),
            Err(why.into()),
            "a failed host-state step must short-circuit the door's following operation"
        );
        assert_eq!(dial.f.bound, bound, "failed host state is immutable");
        for (stream, bytes) in [(MEDIA_BASE, OPUS), (1, &b"late message"[..])] {
            assert_eq!(
                dial.f.emit(stream, bytes, false, now),
                Err(why.into()),
                "neither emit path may reenter a quarantined media stack"
            );
        }
        assert_eq!(dial.f.media_clock, clocks, "no late media was accepted");
        assert_eq!(dial.f.held(1), held, "no late data was queued");
        assert_eq!(dial.f.failure(), Some(why));
        assert!(dial.f.next_route().is_none());
    }
}

#[test]
fn a_mixed_offer_marks_its_opening_pending_until_the_channel_is_known() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    accept.f.rendezvous(&dial.description(), now).unwrap();
    accept.collect();
    assert!(accept.f.opening_channel_pending);
    accept.f.event(Event::MediaAdded(str0m::media::MediaAdded {
        mid: *dial.f.medias.keys().next().unwrap(),
        kind: MediaKind::Audio,
        direction: Direction::SendRecv,
        simulcast: None,
    }));
    accept.collect();
    let head = accept.pieces.iter().find(|p| p.fields).unwrap();
    assert!(head
        .bytes
        .windows(b"opening-pending: 1".len())
        .any(|s| s == b"opening-pending: 1"));
    let (_, connected, _) = connected();
    assert!(!connected.f.opening_channel_pending);
    assert!(connected.pieces.iter().any(|p| p.fields
        && p.bytes.starts_with(b"label:")
        && p.bytes
            .windows(b"opening-pending: 0".len())
            .any(|s| s == b"opening-pending: 0")));
}

#[test]
fn rendezvous_terms_debug_redacts_both_ice_passwords() {
    let terms = Terms {
        initiates: true,
        local_user: "local-user".into(),
        local_secret: Zeroizing::new("local-password-must-not-appear".into()),
        remote_user: "remote-user".into(),
        remote_secret: Zeroizing::new("remote-password-must-not-appear".into()),
        peer_fingerprint: [0; 32],
        candidates: Vec::new(),
    };
    for rendered in [format!("{terms:?}"), format!("{terms:#?}")] {
        assert!(!rendered.contains(terms.local_secret.as_str()));
        assert!(!rendered.contains(terms.remote_secret.as_str()));
        assert!(rendered.contains("local-user"));
        assert!(rendered.contains("remote-user"));
        assert_eq!(rendered.matches("<redacted>").count(), 2);
    }
}

impl Framing {
    /// The messages held for `stream`, `(text, bytes)` each, in order: what a test reads of the
    /// queue.
    pub(crate) fn held(&self, stream: u64) -> Vec<(bool, Vec<u8>)> {
        self.held
            .get(&stream)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[test]
fn unauthenticated_trailing_use_candidate_never_nominates() {
    let secret = b"test-ice-secret";
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    for authenticated_nomination in [false, true] {
        let mut attrs = Vec::new();
        if authenticated_nomination {
            attrs.extend_from_slice(&[0, 0x25, 0, 0]);
        }
        let mut message = stun_message(1, (attrs.len() + 24) as u16, &attrs);
        let mac = ring::hmac::sign(&key, &message);
        message.extend_from_slice(&[0, 8, 0, 20]);
        message.extend_from_slice(mac.as_ref());
        assert!(stun::integrity_holds(&message, secret));
        message.extend_from_slice(&[0, 0x25, 0, 0]);
        let length = (message.len() - 20) as u16;
        message[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(stun::integrity_holds(&message, secret));
        assert_eq!(
            stun::read(&message),
            Some(Check::Request {
                txid: [9; 12],
                nominates: authenticated_nomination,
            })
        );
    }
    let mut attrs = vec![0, 0x1c, 0, 32];
    attrs.extend_from_slice(&[0; 32]);
    attrs.extend_from_slice(&[0, 0x25, 0, 0]);
    assert_eq!(
        stun::read(&stun_message(1, attrs.len() as u16, &attrs)),
        Some(Check::Request {
            txid: [9; 12],
            nominates: false
        })
    );
}

#[test]
fn media_transport_parameters_override_session_defaults_on_both_peers() {
    fn with_defaults(description: zeroize::Zeroizing<Vec<u8>>) -> zeroize::Zeroizing<Vec<u8>> {
        let at = std::str::from_utf8(&description)
            .expect("SDP is text")
            .find("m=")
            .expect("a media section");
        let defaults = format!("a=ice-ufrag:unusedSessionUser\r\na=ice-pwd:unusedSessionPassword0123456789\r\na=fingerprint:sha-256 {}\r\na=setup:passive\r\n", ["00"; 32].join(":"));
        let mut text =
            zeroize::Zeroizing::new(Vec::with_capacity(description.len() + defaults.len()));
        text.extend_from_slice(&description[..at]);
        text.extend_from_slice(defaults.as_bytes());
        text.extend_from_slice(&description[at..]);
        text
    }
    let mut now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    accept
        .f
        .rendezvous(&with_defaults(dial.description()), now)
        .unwrap();
    dial.f
        .rendezvous(&with_defaults(accept.description()), now)
        .unwrap();
    let (ta, td) = (accept.terms(), dial.terms());
    assert_eq!(ta.remote_user, td.local_user);
    assert_eq!(td.remote_user, ta.local_user);
    assert_eq!(ta.remote_secret, td.local_secret);
    assert_eq!(td.remote_secret, ta.local_secret);
    assert_ne!(ta.initiates, td.initiates);
    assert_eq!(
        ta.peer_fingerprint.as_slice(),
        ring::digest::digest(&ring::digest::SHA256, CERT).as_ref()
    );
    assert_eq!(td.peer_fingerprint, ta.peer_fingerprint);
    run(&mut dial, &mut accept, &mut now, 3000);
    assert_ne!(dial.bound, 0);
    assert_ne!(accept.bound, 0);
}

#[test]
fn path_history_refuses_growth_past_its_capacity() {
    let now = Instant::now();
    let mut f = Framing::begin(Side::Accept, CERT, None, &Opening::default(), now).unwrap();
    for n in 1..=MAX_QUEUED {
        f.point(n as u32, SocketAddr::from(([192, 0, 2, 1], n as u16)));
    }
    assert_eq!(f.paths.len(), MAX_QUEUED);
    assert!(f.failure().is_none());
    f.point(1, SocketAddr::from(([192, 0, 2, 2], 1)));
    assert!(f.failure().is_none(), "existing paths may change addresses");
    f.datagram(
        (MAX_QUEUED + 1) as u32,
        SocketAddr::from(([192, 0, 2, 3], 1)),
        Lane::Clear,
        &[0],
        now,
    );
    assert!(f.failure().is_some());
    assert_eq!(f.paths.len(), MAX_QUEUED);
    assert_eq!(f.addrs.len(), MAX_QUEUED);
}

#[test]
fn channel_control_events_cannot_overrun_the_piece_queue() {
    let (mut dial, _accept, _now) = connected();
    let id = *dial.f.channels.keys().next().unwrap();
    dial.f.pieces.clear();
    for _ in 0..MAX_QUEUED / 2 {
        dial.f.event(Event::ChannelOpen(id, "events".into()));
        dial.f.event(Event::ChannelClose(id));
    }
    assert_eq!(dial.f.pieces.len(), MAX_QUEUED);
    assert!(dial.f.failure().is_none());
    dial.f.event(Event::ChannelOpen(id, "events".into()));
    assert!(dial.f.failure().is_some());
    assert_eq!(dial.f.pieces.len(), MAX_QUEUED);
}

/// `description` with its audio line refused (port 0) and carrying PCMU alone: no Opus.
fn audio_refused(description: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(description).expect("SDP is text");
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with("m=audio ") {
            let f: Vec<&str> = line.trim_end().split(' ').collect();
            out.push_str(&format!("m=audio 0 {} 0\r\n", f[2]));
        } else if !line.starts_with("a=rtpmap:")
            && !line.starts_with("a=fmtp:")
            && !line.starts_with("a=rtcp-fb:")
        {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

#[test]
fn a_media_line_without_opus_fails_its_stream_and_never_the_association() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    accept
        .f
        .rendezvous(&dial.description(), now)
        .expect("offer");
    let answer = audio_refused(&accept.description());
    dial.f
        .rendezvous(&answer, now)
        .expect("an answer refusing the audio line settles");
    dial.verified = true;
    dial.host(Some(&[7; 56]), now).expect("keyed");
    dial.f
        .emit(MEDIA_BASE, OPUS, false, now)
        .expect("a frame on a line without Opus fails that line alone");
    dial.collect();
    assert!(dial.f.failure().is_none(), "the association carries on");
    assert!(dial.f.stream_failed(MEDIA_BASE));
    assert!(
        dial.pieces
            .iter()
            .any(|p| p.stream == MEDIA_BASE && p.failed),
        "the host is told the line failed"
    );
    assert!(dial.f.carries(1), "the data channel is still carried");
}

/// `description` with every line starting `prefix` replaced by `line`.
fn with_line(description: &[u8], prefix: &str, line: &str) -> Vec<u8> {
    let text = std::str::from_utf8(description).expect("SDP is text");
    let mut out = String::new();
    for l in text.split_inclusive('\n') {
        if l.starts_with(prefix) {
            out.push_str(line);
            out.push_str("\r\n");
        } else {
            out.push_str(l);
        }
    }
    out.into_bytes()
}

#[test]
fn a_blank_ice_credential_is_refused_as_the_far_ends_description() {
    for (prefix, blank) in [
        ("a=ice-ufrag:", "a=ice-ufrag: "),
        ("a=ice-pwd:", "a=ice-pwd: "),
    ] {
        let now = Instant::now();
        let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
        let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
        let offer = with_line(&dial.description(), prefix, blank);
        assert!(
            accept.f.rendezvous(&offer, now).is_err(),
            "an offer whose {prefix} is blank settles no terms"
        );
        assert!(accept.f.take_terms().is_none());
    }
}

#[test]
fn the_handshake_role_agrees_with_the_media_stacks_reading_of_setup() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    // The media stack reads `a=setup:` values exactly, so `PASSIVE` leaves it passive itself.
    let offer = with_line(&dial.description(), "a=setup:", "a=setup:PASSIVE");
    accept.f.rendezvous(&offer, now).expect("offer");
    let terms = accept.f.take_terms().expect("terms");
    assert!(
        !terms.initiates,
        "the host must not open the handshake while the media stack stays passive"
    );
}

#[test]
fn an_unparsable_description_is_refused_without_a_memory_address() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let mut offer = dial.description().to_vec();
    offer.extend_from_slice(b"m=audio x UDP/TLS/RTP/SAVPF 111\r\n");
    let why = accept.f.rendezvous(&offer, now).expect_err("refused");
    assert!(why.starts_with("the offer did not parse"), "{why}");
    assert!(
        !why.contains("0x") && !why.contains("PointerOffset"),
        "a refusal never carries an address: {why}"
    );
}

#[test]
fn the_handshake_role_follows_the_first_setup_value_the_media_stack_reads() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    // The media stack skips a value it cannot read and takes the next: `passive`, so it is active.
    let offer = with_line(
        &dial.description(),
        "a=setup:",
        "a=setup:Passive\r\na=setup:passive",
    );
    accept.f.rendezvous(&offer, now).expect("offer");
    let terms = accept.f.take_terms().expect("terms");
    assert!(
        terms.initiates,
        "the host opens the handshake as the media stack, active, expects"
    );
    let answer = accept.description();
    assert!(
        String::from_utf8_lossy(&answer).contains("a=setup:active"),
        "the media stack took the active role the host was told"
    );
}

#[test]
fn a_framings_debug_names_its_state_and_never_its_credentials() {
    let f = Framing::begin(
        Side::Accept,
        CERT,
        None,
        &Opening::default(),
        Instant::now(),
    )
    .unwrap();
    let pass = f.local_creds.pass.clone();
    let shown = format!("{f:?}");
    assert!(shown.starts_with("Framing { side: Accept"), "{shown}");
    assert!(
        !shown.contains(&pass) && !shown.contains(&f.local_creds.ufrag),
        "{shown}"
    );
}

#[test]
fn a_pieces_debug_shows_channel_bytes_but_never_a_description() {
    let message = Piece {
        stream: 1,
        bytes: b"hi".to_vec(),
        fields: false,
        text: true,
        end: false,
        failed: false,
        writable: false,
    };
    assert!(format!("{message:?}").contains("[104, 105]"));
    let description = Piece {
        stream: DESCRIPTION,
        bytes: b"a=ice-pwd:secret".to_vec(),
        ..message.clone()
    };
    let shown = format!("{description:?}");
    assert!(shown.contains("<redacted session description>"), "{shown}");
}

#[test]
fn the_far_ends_udp_candidates_are_read_in_either_address_family_and_others_skipped() {
    let print = ["ab"; 32].join(":");
    let description = format!(
        "v=0\r\na=ice-ufrag:user\r\na=ice-pwd:passwordpasswordpassword\r\na=fingerprint:sha-256 {print}\r\n\
         a=candidate:1 1 tcp 1 192.0.2.1 9 typ host tcptype passive\r\n\
         a=candidate:2 1 udp 1 2001:db8::1 5000 typ host\r\n\
         a=candidate:3 1 UDP 1 192.0.2.7 6000 typ host\r\n\
         a=candidate:4 1 udp 1 not-an-address 7000 typ host\r\n\
         a=candidate:5 1 udp\r\n"
    );
    let (user, _, fingerprint, candidates) = read_remote(&description).expect("read");
    assert_eq!(user, "user");
    assert_eq!(fingerprint, [0xab; 32]);
    assert_eq!(
        candidates,
        vec![
            "[2001:db8::1]:5000".parse::<SocketAddr>().unwrap(),
            "192.0.2.7:6000".parse().unwrap()
        ],
        "TCP, unparsable and truncated candidates are skipped"
    );
}

#[test]
fn a_second_offer_on_one_association_is_refused() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let offer = dial.description();
    accept.f.rendezvous(&offer, now).expect("the first offer");
    assert_eq!(
        accept.f.rendezvous(&offer, now),
        Err("a second offer on one association".to_owned())
    );
}

#[test]
fn an_address_a_new_path_takes_over_is_forgotten_by_its_old_path() {
    let mut f = Framing::begin(
        Side::Accept,
        CERT,
        None,
        &Opening::default(),
        Instant::now(),
    )
    .unwrap();
    let a: SocketAddr = "192.0.2.1:1000".parse().unwrap();
    f.paths([(1, a)]);
    f.paths([(2, a)]);
    assert_eq!(f.addrs.get(&a), Some(&2));
    assert!(
        !f.paths.contains_key(&1),
        "path 1 no longer names the address path 2 took"
    );
    f.paths([(0, a)]);
    assert_eq!(f.addrs.get(&a), Some(&2), "path 0 names nothing");
}

#[test]
fn the_host_ports_address_is_taken_once() {
    let mut f = Framing::begin(
        Side::Accept,
        CERT,
        None,
        &Opening::default(),
        Instant::now(),
    )
    .unwrap();
    f.local("192.0.2.1:1000".parse().unwrap()).unwrap();
    f.local("192.0.2.2:2000".parse().unwrap()).unwrap();
    assert_eq!(f.local, Some("192.0.2.1:1000".parse().unwrap()));
}

#[test]
fn an_answer_states_the_host_candidate_even_when_the_stack_puts_it_on_no_line() {
    let now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let offer = String::from_utf8(dial.description().to_vec()).unwrap();
    // A first media line of a type the media stack skips (a copy of the channel's line, retyped):
    // it states its candidates only on its first line, which it then never keeps.
    let at = offer.find("m=application").expect("the channel's line");
    let section = &offer[at..];
    let section = &section[..section[1..].find("\nm=").map_or(section.len(), |n| n + 2)];
    let mid = section
        .lines()
        .find_map(|l| l.strip_prefix("a=mid:"))
        .expect("a mid");
    let skipped = section
        .replacen("m=application", "m=text", 1)
        .replace(&format!("a=mid:{mid}"), "a=mid:skipped");
    let bundle = offer
        .lines()
        .find(|l| l.starts_with("a=group:BUNDLE "))
        .expect("a bundle group");
    let offer = offer.replacen(
        bundle,
        &format!("a=group:BUNDLE skipped {}", &bundle[15..]),
        1,
    );
    let first = offer.find("m=").expect("a media line");
    let offer = format!("{}{skipped}{}", &offer[..first], &offer[first..]);
    accept.f.rendezvous(offer.as_bytes(), now).expect("offer");
    let answer = String::from_utf8(accept.description().to_vec()).unwrap();
    assert!(
        answer.contains("udp 2130706431 203.0.113.9 3478 typ host"),
        "the host port is stated as this end's candidate"
    );
}
