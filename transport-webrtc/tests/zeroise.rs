// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KEYS ARE ZEROISED (THE DESIGN l.753): the keying material the framer holds is cleared before
//! its memory goes back to the allocator, whether it was held to the end or refused.
//!
//! THE WITNESS is this binary's allocator: every block freed is read first, and a block still
//! holding a marked key (eight marker bytes, then the key's id 48 times) is counted against that
//! id. Each test marks its own id, so tests running side by side never count each other's frees.
//!
//! THE RED ARM, kept: the same marked key in a plain `Vec`, dropped, IS seen, so a zero count
//! below is the zeroising, never a witness that cannot see.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use core::net::SocketAddr;
use std::collections::HashMap;
use std::time::Duration;

use busbar_transport_webrtc::framing::{
    Failed, Framing, Lane, Opening, Piece, Request, Route, Side, Terms, DESCRIPTION,
    PROFILE_AEAD_AES_128_GCM,
};
use busbar_transport_webrtc::shim::Shim;

const MARK: [u8; 8] = *b"ZEROISE!";
/// A key: the marker and 48 bytes of its id (the AEAD-AES-128-GCM material's 56 bytes).
const KEY_LEN: usize = 56;
const IDS: usize = 8;

static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];

/// The system allocator, reading every block it frees for a marked key.
struct Watch;

/// The id of the marked key at the start of `w`, if one is there whole.
fn marked(w: &[u8]) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK
        && rest.len() >= KEY_LEN - MARK.len()
        && rest[..KEY_LEN - MARK.len()].iter().all(|b| *b == id))
    .then_some(usize::from(id))
    .filter(|id| *id < IDS)
}

// SAFETY: every call is forwarded to `System` with its own arguments; `dealloc` only reads the
// block it is handed before forwarding.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= KEY_LEN {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System` frees it below,
            // and its owner has given it up: nothing else reads or writes it during `dealloc`. It
            // is read as plain bytes and nothing read is kept.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            for at in 0..=block.len() - KEY_LEN {
                if block[at] == MARK[0] {
                    if let Some(id) = marked(&block[at..]) {
                        FREED_UNZEROED[id].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static WATCH: Watch = Watch;

/// The marked key `id`, on the stack (the stack is not the allocator's to watch).
fn key(id: u8) -> [u8; KEY_LEN] {
    let mut k = [id; KEY_LEN];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

#[test]
fn keying_material_held_by_the_shim_is_zeroised_when_it_drops() {
    let material = key(1);
    let shim = Shim::default();
    shim.keyed(&material, PROFILE_AEAD_AES_128_GCM)
        .expect("AEAD-AES-128-GCM is taken");
    assert!(shim.holds_keying(), "the material was held, on the heap");
    drop(shim);
    assert_eq!(freed_unzeroed(1), 0, "the held material was freed unzeroed");
}

#[test]
fn keying_material_a_framing_refuses_is_zeroised() {
    let material = key(2);
    let now = Instant::now();
    let mut f = Framing::begin(
        Side::Accept,
        b"public certificate bytes",
        Some("203.0.113.9:3478".parse().expect("an address")),
        &Opening::default(),
        now,
    )
    .expect("begins");
    // Keying before verification: the framing copies the item, refuses it, and holds nothing.
    assert!(f
        .host(0, false, Some((PROFILE_AEAD_AES_128_GCM, &material)), now)
        .is_err());
    assert!(!f.holds_keying());
    // AES_CM, verified: refused the same way.
    assert!(f.host(0, true, Some((0x0001, &material)), now).is_err());
    assert!(!f.holds_keying());
    drop(f);
    assert_eq!(freed_unzeroed(2), 0, "a refused item was freed unzeroed");
}

#[test]
fn red_arm_a_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let material = key(3);
    let plain: Vec<u8> = material.to_vec();
    drop(std::hint::black_box(plain));
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a key freed without zeroising"
    );
    // And a zeroising holder of the same bytes is not seen.
    let held = zeroize::Zeroizing::new(key(4).to_vec());
    drop(std::hint::black_box(held));
    assert_eq!(freed_unzeroed(4), 0);
}

// ── the accepted path ────────────────────────────────────────────────────────────────────────────

/// A placeholder certificate: the framer states its SHA-256 and nothing else reads it.
const CERT: &[u8] = b"public certificate bytes";

const PROFILE: u32 = PROFILE_AEAD_AES_128_GCM;

/// One end: its framing and its host's view (the unit tests' shape; not every field is read here).
#[allow(dead_code)]
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

/// Two ends through the rendezvous, ICE, verification and keying with `material`: a connected
/// association (the framer's own unit tests' simulated host, `src/tests/framing_tests.rs`).
fn connected_with(material: &[u8]) -> (End, End, Instant) {
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
    for e in [&mut dial, &mut accept] {
        e.verified = true;
        e.host(Some(material), now).expect("keyed");
    }
    run(&mut dial, &mut accept, &mut now, 3000);
    (dial, accept, now)
}

/// KNOWN RESIDUAL, NOT A GATE: keying material presented to a verified association is handed to the
/// media stack, which derives its SRTP contexts from it. The published str0m 0.24.1 copies the
/// material into a plain `Vec`, and dimpl 0.7.4's `KeyingMaterial` frees its bytes unzeroed (the
/// zeroize-on-drop fork patches were dropped, OWNER 2026-10-25). This witness stays so the residual is
/// measurable: run it with `--ignored` to see the upstream copies; it passes once upstream zeroises.
/// What the plugin itself holds is gated by the other tests in this file.
#[test]
#[ignore = "known residual: str0m/dimpl do not zeroise their internal copies of the keying material"]
fn keying_material_on_the_accepted_path_is_never_freed_unzeroed() {
    let material = key(5);
    let (dial, accept, _) = connected_with(&material);
    assert!(dial.keyed && accept.keyed, "both ends took the material");
    drop((dial, accept));
    assert_eq!(
        freed_unzeroed(5),
        0,
        "a copy of the keying material was freed unzeroed"
    );
}
