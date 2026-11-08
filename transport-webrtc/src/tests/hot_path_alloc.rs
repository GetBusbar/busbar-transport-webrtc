// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Sealing and opening SRTP packets allocate nothing on the hot path.

use std::cell::Cell;

use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm,
};

std::thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn on_alloc() {
    let _ = ARMED.try_with(|a| {
        if a.get() {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
    });
}

/// How many allocations `f` made on this thread.
fn allocations<R>(f: impl FnOnce() -> R) -> (usize, R) {
    COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    let r = f();
    ARMED.with(|a| a.set(false));
    (COUNT.with(Cell::get), r)
}

const IV: [u8; 12] = [3; 12];
/// An RTP header (the AAD of an SRTP packet) and a payload.
const HEADER: [u8; 12] = [0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
const PAYLOAD: [u8; 160] = [0x5a; 160];
/// RFC 7714 encrypted SRTCP: clear RTCP header and SSRC, followed by the encrypted-bit index.
const FIRST_REPORT_AAD: [u8; 12] = [0x80, 200, 0, 6, 0, 0, 0, 1, 0x80, 0, 0, 0];
const NEXT_REPORT_AAD: [u8; 12] = [0x80, 200, 0, 6, 0, 0, 0, 1, 0x80, 0, 0, 1];
const FIRST_REPORT_IV: [u8; 12] = [4; 12];
const NEXT_REPORT_IV: [u8; 12] = [5; 12];

#[test]
fn opening_and_sealing_an_srtp_packet_allocates_nothing() {
    let p = crate::crypto::provider();
    let gcm = SrtpProvider::aead_aes_128_gcm(p.srtp_provider);
    let mut seal = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], true);
    let mut open = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], false);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    let (n, r) = allocations(|| {
        AeadAes128GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed)
    });
    r.expect("sealed");
    assert_eq!(n, 0, "an SRTP seal allocated {n} times on the hot path");

    let mut out = [0_u8; PAYLOAD.len() + 16];
    let (n, r) = allocations(|| {
        AeadAes128GcmCipher::decrypt(&mut *open, &IV, &[&HEADER], &sealed, &mut out)
    });
    assert_eq!(r.expect("opened"), PAYLOAD.len());
    assert_eq!(&out[..PAYLOAD.len()], &PAYLOAD[..]);
    assert_eq!(n, 0, "an SRTP open allocated {n} times on the hot path");

    let mut seal2 = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], true);
    let mut open2 = SupportedAeadAes128Gcm::create_cipher(gcm, [9; 16], false);
    let mut exact = [0_u8; PAYLOAD.len()];
    AeadAes128GcmCipher::encrypt(
        &mut *seal2,
        &FIRST_REPORT_IV,
        &FIRST_REPORT_AAD,
        &PAYLOAD,
        &mut sealed,
    )
    .expect("first report sealed");
    AeadAes128GcmCipher::decrypt(
        &mut *open2,
        &FIRST_REPORT_IV,
        &[&FIRST_REPORT_AAD, &[]],
        &sealed,
        &mut exact,
    )
    .expect("first report registered its source");
    AeadAes128GcmCipher::encrypt(
        &mut *seal2,
        &NEXT_REPORT_IV,
        &NEXT_REPORT_AAD,
        &PAYLOAD,
        &mut sealed,
    )
    .expect("next report sealed");
    let (n, r) = allocations(|| {
        AeadAes128GcmCipher::decrypt(
            &mut *open2,
            &NEXT_REPORT_IV,
            &[&NEXT_REPORT_AAD, &[]],
            &sealed,
            &mut exact,
        )
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
    let (n, v) = allocations(|| std::hint::black_box(vec![1_u8; 64]));
    assert_eq!(v.len(), 64);
    assert!(n >= 1, "the witness must count an allocation");
}
