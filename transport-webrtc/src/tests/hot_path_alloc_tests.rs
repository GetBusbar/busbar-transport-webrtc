// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO ALLOCATION ON THE HOT PATH (THE DESIGN §11.2): sealing and opening one SRTP packet, the
//! per-packet work this crate's crypto provider does for the media stack, takes nothing from the
//! allocator.
//!
//! THE WITNESS is this crate's one test allocator (busbar-contract's `alloc_counter`): it counts the allocations made on the measuring thread
//! while a measurement is armed. THE RED ARM, kept: a `Vec` made under the same measurement is
//! counted, so a zero below is the code, never a witness that cannot see.

use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm,
};

use busbar_contract::alloc_counter::allocations_with;

const IV: [u8; 12] = [3; 12];
/// An RTP header (the AAD of an SRTP packet) and a payload.
const HEADER: [u8; 12] = [0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
const PAYLOAD: [u8; 160] = [0x5a; 160];

#[test]
fn opening_and_sealing_an_srtp_packet_allocates_nothing() {
    let p = crate::crypto::provider();
    let gcm = SrtpProvider::aead_aes_128_gcm(p.srtp_provider);
    let mut seal = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], true);
    let mut open = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], false);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    let (n, r) = allocations_with(|| {
        AeadAes128GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed)
    });
    r.expect("sealed");
    assert_eq!(n, 0, "an SRTP seal allocated {n} times on the hot path");

    // Opened into a buffer as long as the packet (the media stack's RTP scratch) ...
    let mut out = [0_u8; PAYLOAD.len() + 16];
    let (n, r) = allocations_with(|| {
        AeadAes128GcmCipher::decrypt(&mut *open, &IV, &[&HEADER], &sealed, &mut out)
    });
    assert_eq!(r.expect("opened"), PAYLOAD.len());
    assert_eq!(&out[..PAYLOAD.len()], &PAYLOAD[..]);
    assert_eq!(n, 0, "an SRTP open allocated {n} times on the hot path");

    // ... and into one exactly as long as the plaintext, with the AAD in two parts (SRTCP).
    let (head, tail) = HEADER.split_at(8);
    let mut seal2 = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], true);
    AeadAes128GcmCipher::encrypt(&mut *seal2, &IV, &HEADER, &PAYLOAD, &mut sealed).expect("sealed");
    let mut exact = [0_u8; PAYLOAD.len()];
    let (n, r) = allocations_with(|| {
        AeadAes128GcmCipher::decrypt(&mut *open, &IV, &[head, tail], &sealed, &mut exact)
    });
    assert_eq!(r.expect("opened"), PAYLOAD.len());
    assert_eq!(exact, PAYLOAD);
    assert_eq!(n, 0, "an SRTCP open allocated {n} times on the hot path");
}

#[test]
fn a_forged_packet_is_refused_and_leaves_no_plaintext() {
    let p = crate::crypto::provider();
    let gcm = SrtpProvider::aead_aes_256_gcm(p.srtp_provider);
    let mut seal = SupportedAeadAes256Gcm::create_cipher(gcm, [4; 32], true);
    let mut open = SupportedAeadAes256Gcm::create_cipher(gcm, [4; 32], false);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    AeadAes256GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed).expect("sealed");
    sealed[5] ^= 1;
    let mut out = [0_u8; PAYLOAD.len() + 16];
    assert!(AeadAes256GcmCipher::decrypt(&mut *open, &IV, &[&HEADER], &sealed, &mut out).is_err());
    assert!(
        out.iter().all(|b| *b == 0),
        "nothing unauthenticated is left"
    );
}

#[test]
fn red_arm_an_allocation_is_counted() {
    let (n, v) = allocations_with(|| std::hint::black_box(vec![1_u8; 64]));
    assert_eq!(v.len(), 64);
    assert!(n >= 1, "the witness must count an allocation");
}
