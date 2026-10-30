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
    fn description(&mut self) -> Vec<u8> {
        self.collect();
        let at = self
            .pieces
            .iter()
            .position(|p| p.stream == DESCRIPTION)
            .expect("a description");
        self.pieces.remove(at).bytes
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
        .map(|p| (p.stream, p.bytes.clone()))
        .expect("the accepting end opened the channel");
    // The first two fill most of the stack's send buffer, the third does not fit beside them and
    // is held, the fourth would fit. Each is its own content, so a swap of any two shows
    // (codeaudit tests framing_tests.rs:469).
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
    // The channel is not open yet: every message is held, up to the cap and never past it.
    for n in 0..(MAX_HELD + 50) {
        if let Err(e) = dial.f.emit(1, &[n as u8; 8], false, now) {
            panic!("one channel's overflow failed the whole association: {e}");
        }
        assert!(dial.f.held(1).len() <= MAX_HELD, "held past the cap");
    }
    assert_eq!(dial.f.failure(), None, "the association carries on");
    // What it costs is that channel (codeaudit tests framing_tests.rs:485): failed, once, in words.
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
    // Exactly the bound (codeaudit tests framing_tests.rs:509): raising it shows.
    assert_eq!(
        candidates.len(),
        MAX_CANDIDATES,
        "{} candidates read from one description",
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
    while dial.f.pieces.len() < MAX_QUEUED {
        dial.f.pieces.push_back(Piece {
            stream: 99,
            bytes: vec![0],
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

/// A FIELD VALUE NEVER HOLDS CR OR LF (the transport contract's field block; codeaudit W1): a far
/// end's data channel label is any UTF-8 (RFC 8832 §5.1), so one with a line break would forge
/// field lines in the stream's head. That channel is refused: its stream fails, in words, and no
/// field block carries the label. RED before the fix: the head held `x\r\n:status: 200`.
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

/// AN EMPTY MESSAGE IS NEVER DROPPED SILENTLY, AND NEVER WEDGES ITS CHANNEL (codeaudit W3). The
/// media stack cannot send one: its SCTP writes no chunk for an empty message yet spends the
/// ordered stream's next sequence number, so every later message on that channel waits forever
/// for the one never sent (measured: after an empty write, "after" never arrived). The channel
/// cannot carry the message, so its stream fails, alone, in words, and the association carries on.
/// RED before the fix: the write was taken, nothing was said, and the channel was stuck.
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

/// A CHANNEL THE FAR END CLOSED TAKES NO MORE MESSAGES (codeaudit W6): its stream ended with its
/// END piece, so a later emit there (racing the close) is dropped as for a failed stream, never
/// held forever and never failing the association, and nothing of the stream (no failure piece)
/// follows its end. A stream never carried is still refused. RED before the fix: the message was
/// taken and held unsent, and the held queue's cap later failed the ended stream.
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

/// A CLOSED CHANNEL AND A RE-POINTED PATH LEAVE NOTHING BEHIND (codeaudit W12): a far end that
/// opens and closes channels, or roams across addresses, grows no bookkeeping for the life of the
/// association. RED before the fix: every closed stream's entries and every stale address stayed.
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
    // One stream fails before its channel closes; the other just closes.
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

/// A FORGED BINDING SUCCESS NOMINATES NOTHING (codeaudit W8; RFC 8489 §14.5, RFC 8445 §7.2.5.2:
/// a response counts only if its MESSAGE-INTEGRITY verifies). An on-path observer who saw a
/// nominating check's transaction id answers it from a new path with no valid integrity: the
/// dialling end asks for no path. (`connected()` proves a genuine answer still nominates: the
/// dialling end's bound path is its own nomination.) RED before the fix: the transaction id alone
/// counted, and the forged answer asked to move the association.
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

/// ONLY A WELL-FRAMED STUN MESSAGE IS READ AS A CHECK (codeaudit stun.rs:35; RFC 8489 §5: the
/// length is a multiple of 4 and the datagram's size less the header; RFC 8445 §16.1:
/// USE-CANDIDATE has no value): junk the ICE agent rejects never reaches the nomination
/// bookkeeping. RED before the fix: each of these was read as a nominating request.
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
    // A length that is no multiple of 4.
    assert_eq!(stun::read(&stun_message(1, 1, &use_candidate[..1])), None);
    // Bytes past the length the header states.
    let mut trailing = stun_message(1, 4, &use_candidate);
    trailing.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(stun::read(&trailing), None);
    // A USE-CANDIDATE that carries a value nominates nothing.
    let valued = [0x00, 0x25, 0, 4, 1, 2, 3, 4];
    assert_eq!(
        stun::read(&stun_message(1, 8, &valued)),
        Some(Check::Request {
            txid: [9; 12],
            nominates: false
        })
    );
}

/// A FINGERPRINT IS TWO HEX DIGITS PER OCTET (codeaudit framing.rs:246; RFC 4572 §5): a token of
/// one digit or with a sign is a malformed fingerprint, refused at the rendezvous. RED before the
/// fix: `+F` and `1` were read as octets.
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

/// THE ONE CANDIDATE ADVERTISED IS ONE THE MEDIA STACK TAKES (codeaudit framing.rs:463/483): a
/// host port's address the stack refuses as a host candidate (unspecified, multicast) refuses the
/// framing in words, rather than be advertised while the stack's ICE agent holds no candidate.
/// RED before the fix: the framing began and its description advertised `0.0.0.0`.
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

/// VALID APPLICATION DATA IS NOT READ BEFORE VERIFICATION (codeaudit tests framing_tests.rs:288):
/// a real SCTP packet and a real protected media frame of this association, arriving while the
/// host has not verified the far end, are dropped unread; the same datagrams once it has are read.
/// A gate that let them through would have the stack take them then, so their second arrival is a
/// duplicate (SCTP) or a replay (SRTP) it never hands up: the red arm below fails.
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
    // The stack paces media: the frame goes out on its next tick.
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
    // The red arm: verified, the very same datagrams are read.
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

/// A REPLAYED MEDIA FRAME FROM AN UNPROVEN PATH IS NOT READ (codeaudit tests
/// framing_tests.rs:403): a genuine protected frame of this association, arriving from a path the
/// host has not bound, is dropped; the same frame from the bound path is read (the red arm: a
/// frame read from the spoofed path first would be a replay there, never handed up).
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

/// THE FRAMER'S LINE TO ITS SHIM IS ITS OWN (codeaudit tests framing.rs:646): a far end's
/// datagram in the relay range (keying, "connected", opened plaintext) from the bound path of a
/// verified, keyed association is never fed. Fed, a forged keying frame would re-key the
/// association's media under the far end's choice, and the genuine media after it would no
/// longer be read.
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

/// "DISCONNECTED" THAT COMES BACK STARTS THE WINDOW AFRESH (codeaudit tests framing.rs:1057): a
/// path that disconnects, comes back, and disconnects again is judged from the second outage. The
/// clock is stamped first, so the window really starts. RED for a framing that forgot the return:
/// it would end 5 s into the second outage.
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

/// BACK-PRESSURE IS A PROTOCOL (codeaudit tests framing.rs:977): a channel whose held messages
/// reach the high-water mark is FULL; drained to the low-water mark it is writable again, with its
/// writable piece, once.
#[test]
fn a_full_channel_is_writable_again_once_drained() {
    let (mut dial, mut accept, mut now) = connected();
    // Two fill the stack's buffer; the rest are held behind them.
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

/// A CLOSED DATA CHANNEL ENDS ITS STREAM (codeaudit tests framing.rs:1106): one end closes the
/// channel; the far end's stream ends with exactly one END piece, its last.
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

/// THE NAMED CAPS HOLD (codeaudit tests framing.rs:991): the route queue never grows past
/// `MAX_QUEUED`, the nominating set never past `MAX_NOMINATING`, and a message one byte past
/// `MAX_MESSAGE` fails its channel in words while one at it is sent.
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

/// THIS END'S DESCRIPTION STATES ITS CERTIFICATE'S OWN FINGERPRINT (codeaudit tests
/// crypto.rs:357): the SHA-256 of the host's certificate, which a browser checks the handshake
/// against.
#[test]
fn the_description_states_the_certificates_sha_256() {
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), Instant::now());
    let offer = String::from_utf8(dial.description()).expect("text");
    let want: Vec<String> = ring::digest::digest(&ring::digest::SHA256, CERT)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let stated = values(&offer, "a=fingerprint:sha-256 ")
        .next()
        .expect("a fingerprint line");
    assert_eq!(stated.trim().to_ascii_uppercase(), want.join(":"));
}

/// AN ASSOCIATION KEYED UNDER AEAD-AES-256-GCM CARRIES MEDIA AND MESSAGES (codeaudit tests
/// crypto.rs:70: every end-to-end run used the 128-bit profile).
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
