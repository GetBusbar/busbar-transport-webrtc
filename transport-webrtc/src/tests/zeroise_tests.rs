// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KEYS ARE ZEROISED (THE DESIGN l.753): the keying material the framer holds is cleared before
//! its memory goes back to the allocator, whether it was held to the end or refused.
//!
//! THE WITNESS is this crate's one test allocator (busbar-contract's `alloc_counter`): every block
//! freed is read first, and a block still holding ANY 16 consecutive bytes of a watched secret
//! (all of a shorter one) is counted against that secret's id. A test watches its marked keying
//! material and every secret the media stack derives from it: each master key and salt split out
//! of it, each SRTP session key and session salt (RFC 3711 §4.3, the derivation the media stack
//! runs) and each session key's AES round keys (FIPS-197 §5.2, the schedule the AEAD cipher
//! expands). Each test marks its own id, so tests running side by side never count each other's
//! frees.
//!
//! THE RED ARMS, kept: the marked key, a master key split out of it and a salt alone, each in a
//! plain `Vec`, dropped, ARE seen, so a zero count below is the zeroising, never a witness that
//! cannot see.

use std::time::Instant;

use core::net::SocketAddr;
use std::collections::HashMap;
use std::time::Duration;

use crate::framing::{
    Failed, Framing, Lane, Opening, Piece, Request, Route, Side, Terms, DESCRIPTION,
    PROFILE_AEAD_AES_128_GCM,
};
use crate::shim::Shim;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use busbar_contract::alloc_counter::{freed_unzeroed, last_seen, marked_key, watch};

/// A key: the marker and 48 bytes of its id (the AEAD-AES-128-GCM material's 56 bytes).
const KEY_LEN: usize = 56;

/// The marked key `id`, on the stack (the stack is not the allocator's to watch).
fn key(id: u8) -> [u8; KEY_LEN] {
    marked_key::<KEY_LEN>(id)
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

/// THE RED ARM FOR A SPLIT COPY: a master key split out of the material (16 of its bytes, no
/// marker) and a salt alone (12 bytes, shorter than a window), each in a plain `Vec`, are seen.
#[test]
fn red_arm_a_split_master_key_and_a_salt_in_a_plain_vec_are_seen() {
    let material = key(6);
    let server_master: Vec<u8> = material[MASTER..2 * MASTER].to_vec();
    drop(std::hint::black_box(server_master));
    assert!(
        freed_unzeroed(6) >= 1,
        "the witness must see a split master key freed without zeroising"
    );
    let material = key(7);
    watch(7, &material[2 * MASTER..2 * MASTER + SALT]);
    let salt: Vec<u8> = material[2 * MASTER..2 * MASTER + SALT].to_vec();
    drop(std::hint::black_box(salt));
    assert!(
        freed_unzeroed(7) >= 1,
        "the witness must see a salt freed without zeroising"
    );
}

// ── what the media stack derives from the material ───────────────────────────────────────────────

/// The AEAD-AES-128-GCM material's layout (RFC 5764 §4.2): client key, server key, client salt,
/// server salt.
const MASTER: usize = 16;
const SALT: usize = 12;

/// The SRTP key-derivation labels (RFC 3711 §4.3.1).
const LABEL_RTP_KEY: u8 = 0;
const LABEL_RTP_SALT: u8 = 2;
const LABEL_RTCP_KEY: u8 = 3;
const LABEL_RTCP_SALT: u8 = 5;

/// One AES-128 block of the SRTP key derivation: `AES_master(salt XOR label << 48 || 0)`, the
/// first block of the counter-mode stream (a session key or salt is at most 16 bytes).
fn derive(master: &[u8], salt: &[u8], label: u8) -> [u8; 16] {
    let mut input = [0_u8; 16];
    input[..SALT].copy_from_slice(salt);
    input[7] ^= label;
    let cipher = aes::Aes128::new(GenericArray::from_slice(master));
    let mut block = GenericArray::clone_from_slice(&input);
    cipher.encrypt_block(&mut block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    out
}

/// GF(2^8) multiplication (FIPS-197 §4.2).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// The AES S-box (FIPS-197 §5.1.1): the multiplicative inverse, then the affine transform.
fn sbox(x: u8) -> u8 {
    // x^254 is x's inverse (0 maps to 0).
    let mut inv = 1_u8;
    for _ in 0..254 {
        inv = gf_mul(inv, x);
    }
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

/// The eleven AES-128 round keys of `key` (FIPS-197 §5.2), round 0 being the key itself.
fn round_keys(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0_u8; 4]; 44];
    for (i, word) in w.iter_mut().take(4).enumerate() {
        word.copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    let mut rcon = 1_u8;
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [sbox(t[1]) ^ rcon, sbox(t[2]), sbox(t[3]), sbox(t[0])];
            rcon = gf_mul(rcon, 2);
        }
        w[i] = std::array::from_fn(|j| w[i - 4][j] ^ t[j]);
    }
    let mut out = [[0_u8; 16]; 11];
    for (r, rk) in out.iter_mut().enumerate() {
        for c in 0..4 {
            rk[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    out
}

/// The key expansion is FIPS-197's: Appendix A.1's key gives its round keys 1 and 10.
#[test]
fn the_witness_key_schedule_is_fips_197() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let rk = round_keys(&key);
    assert_eq!(rk[0], key);
    assert_eq!(
        rk[1],
        [
            0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
            0x76, 0x05
        ]
    );
    assert_eq!(
        rk[10],
        [
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
            0x0c, 0xa6
        ]
    );
}

/// Watch, under `id`, every secret the media stack derives from `material`: both salts split out
/// of it, and per direction the RTP and RTCP session salts and every round key of the RTP and
/// RTCP session keys. The material itself (so each master key, any window of it) is watched by
/// [`marked_key`].
fn watch_derived(id: u8, material: &[u8; KEY_LEN]) {
    for half in 0..2 {
        let master = &material[half * MASTER..(half + 1) * MASTER];
        let salt = &material[2 * MASTER + half * SALT..2 * MASTER + (half + 1) * SALT];
        watch(id, salt);
        for label in [LABEL_RTP_SALT, LABEL_RTCP_SALT] {
            watch(id, &derive(master, salt, label)[..SALT]);
        }
        for label in [LABEL_RTP_KEY, LABEL_RTCP_KEY] {
            for rk in round_keys(&derive(master, salt, label)) {
                watch(id, &rk);
            }
        }
    }
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

/// KEYS ARE ZEROISED ON THE ACCEPTED PATH (THE DESIGN §5, "Datagram media": "keys are zeroised";
/// busbar Q128 transport-webrtc H2): keying material presented to a verified association is handed
/// to the media stack, which derives its SRTP contexts from it; when both ends are dropped no freed
/// block holds the material, any part of it, or any key, salt or round key derived from it. RED on
/// the unpatched media stack (str0m 0.24.1 copied the material into a plain `Vec`, dimpl 0.7.4's
/// `KeyingMaterial` freed its bytes unzeroed) and on ring 0.17.14, whose AES-GCM key freed its
/// expanded schedule, round 0 being the session key itself, unzeroed.
#[test]
fn keying_material_on_the_accepted_path_is_never_freed_unzeroed() {
    let material = key(5);
    watch_derived(5, &material);
    let (dial, accept, _) = connected_with(&material);
    assert!(dial.keyed && accept.keyed, "both ends took the material");
    drop((dial, accept));
    // `nth` names the secret (watch order): 0 the material; per half (+25 for the second) 1 the
    // master salt, 2 and 3 the RTP and RTCP session salts, 4..=14 and 15..=25 the RTP and RTCP
    // session keys' round keys.
    assert_eq!(
        freed_unzeroed(5),
        0,
        "a copy of the keying material was freed unzeroed, last: {:?}",
        last_seen(5)
    );
}
