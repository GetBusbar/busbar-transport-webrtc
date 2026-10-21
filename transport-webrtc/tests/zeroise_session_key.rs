// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SRTP SESSION KEY IS ZEROISED (THE DESIGN §5, "Datagram media": "keys are zeroised"): the
//! media stack derives a session key from the keying material and hands it to this crate's crypto
//! provider, which keys a ring AEAD with it and boxes the cipher. ring keeps the AES key schedule,
//! whose first round key(s) are the session key itself, inside that box; when the cipher drops, no
//! freed block may still hold the key.
//!
//! THE WITNESS is this binary's allocator: every block freed is read first, and a block still
//! holding a marked session key (eight marker bytes, then the key's id to the key's length) is
//! counted against that id. Each test marks its own id, so tests running side by side never count
//! each other's frees.
//!
//! THE RED ARM, kept: the same marked key in a plain `Vec`, dropped, IS seen, so a zero count below
//! is the zeroising, never a witness that cannot see.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm,
};

const MARK: [u8; 8] = *b"SESSKEY!";
/// The shortest marked key: an AEAD-AES-128-GCM session key.
const SHORTEST: usize = 16;
const IDS: usize = 8;

static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];

/// The system allocator, reading every block it frees for a marked session key.
struct Watch;

/// The id of the marked session key at the start of `w`, if one is there whole (its marker, then
/// its id at least to the shortest key's length).
fn marked(w: &[u8]) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK
        && rest.len() >= SHORTEST - MARK.len()
        && rest[..SHORTEST - MARK.len()].iter().all(|b| *b == id))
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
        if layout.size() >= SHORTEST {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System` frees it below,
            // and its owner has given it up: nothing else reads or writes it during `dealloc`. It
            // is read as plain bytes and nothing read is kept.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            for at in 0..=block.len() - SHORTEST {
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

/// The marked session key `id` of `N` bytes, on the stack (the stack is not the allocator's to
/// watch).
fn key<const N: usize>(id: u8) -> [u8; N] {
    let mut k = [id; N];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

const IV: [u8; 12] = [7; 12];
const HEADER: [u8; 12] = [0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
const PAYLOAD: [u8; 64] = [0x5a; 64];

#[test]
fn an_aes_128_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = busbar_transport_webrtc::crypto::provider();
    let gcm = SrtpProvider::aead_aes_128_gcm(p.srtp_provider);
    let mut seal = SupportedAeadAes128Gcm::create_cipher(gcm, key::<16>(1), true);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    AeadAes128GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed)
        .expect("the key seals");
    drop(seal);
    assert_eq!(
        freed_unzeroed(1),
        0,
        "the AES-128-GCM session key was freed unzeroed"
    );
}

#[test]
fn an_aes_256_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = busbar_transport_webrtc::crypto::provider();
    let gcm = SrtpProvider::aead_aes_256_gcm(p.srtp_provider);
    let mut open = SupportedAeadAes256Gcm::create_cipher(gcm, key::<32>(2), false);
    // A forged packet: the cipher is used, and refuses it.
    let mut out = [0_u8; PAYLOAD.len() + 16];
    assert!(AeadAes256GcmCipher::decrypt(
        &mut *open,
        &IV,
        &[&HEADER],
        &[0_u8; PAYLOAD.len() + 16],
        &mut out
    )
    .is_err());
    drop(open);
    assert_eq!(
        freed_unzeroed(2),
        0,
        "the AES-256-GCM session key was freed unzeroed"
    );
}

#[test]
fn red_arm_a_session_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let plain: Vec<u8> = key::<16>(3).to_vec();
    drop(std::hint::black_box(plain));
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a session key freed without zeroising"
    );
    let held = zeroize::Zeroizing::new(key::<16>(4).to_vec());
    drop(std::hint::black_box(held));
    assert_eq!(freed_unzeroed(4), 0);
}
