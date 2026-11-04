// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SRTP supports AEAD-AES-GCM profiles; the `AES_CM` provider refuses unsupported operations.

use super::*;
use crate::framing::{PROFILE_AEAD_AES_128_GCM, PROFILE_AEAD_AES_256_GCM};
use crate::shim::Shim;

#[path = "srtcp_replay_tests.rs"]
mod srtcp_replay;

#[path = "aead_provider_tests.rs"]
mod aead_provider;

/// `SRTP_AES128_CM_HMAC_SHA1_80` (RFC 5764 §4.1.2).
const PROFILE_AES_CM_SHA1_80: u32 = 0x0001;
/// `SRTP_AES128_CM_HMAC_SHA1_32`.
const PROFILE_AES_CM_SHA1_32: u32 = 0x0002;

fn is_aes_cm_refusal(e: &CryptoError) -> bool {
    matches!(e, CryptoError::Other(why) if why == AES_CM_REFUSED)
}

#[test]
fn the_aes_cm_cipher_refuses_every_packet_both_ways() {
    for encrypt in [true, false] {
        let mut c = Ring.aes_128_cm_sha1_80().create_cipher([9_u8; 16], encrypt);
        let mut out = [0_u8; 64];
        let sealed = c.encrypt(&[1_u8; 16], b"a protected payload", &mut out);
        assert!(sealed.as_ref().is_err_and(is_aes_cm_refusal), "{sealed:?}");
        assert_eq!(out, [0_u8; 64], "nothing was written");
        let opened = c.decrypt(&[1_u8; 16], b"a protected payload", &mut out);
        assert!(opened.as_ref().is_err_and(is_aes_cm_refusal), "{opened:?}");
    }
}

#[test]
fn red_arm_the_gcm_ciphers_of_the_same_provider_seal_and_open() {
    let (iv, aad, plain) = ([3_u8; 12], b"rtp header", b"an opus frame");
    let mut sealed = vec![0_u8; plain.len() + 16];
    let mut opened = vec![0_u8; plain.len()];
    let mut seal = Ring.aead_aes_128_gcm().create_cipher([5_u8; 16], true);
    seal.encrypt(&iv, aad, plain, &mut sealed).expect("sealed");
    let mut open = Ring.aead_aes_128_gcm().create_cipher([5_u8; 16], false);
    let n = open
        .decrypt(&iv, &[aad], &sealed, &mut opened)
        .expect("opened");
    assert_eq!(&opened[..n], plain);

    sealed[plain.len()] ^= 1;
    assert!(open.decrypt(&iv, &[aad], &sealed, &mut opened).is_err());

    let mut sealed = vec![0_u8; plain.len() + 16];
    let mut seal = Ring.aead_aes_256_gcm().create_cipher([6_u8; 32], true);
    seal.encrypt(&iv, aad, plain, &mut sealed).expect("sealed");
    let mut open = Ring.aead_aes_256_gcm().create_cipher([6_u8; 32], false);
    let n = open
        .decrypt(&iv, &[aad], &sealed, &mut opened)
        .expect("opened");
    assert_eq!(&opened[..n], plain);
}

#[test]
fn an_aes_cm_profile_is_refused_at_the_keying_material_and_nothing_is_held() {
    let material = [7_u8; 60];
    for (profile, why) in [
        (PROFILE_AES_CM_SHA1_80, AES_CM_REFUSED),
        (PROFILE_AES_CM_SHA1_32, AES_CM_REFUSED),
        (0x0003, crate::shim::PROFILE_REFUSED),
        (0xFFFF, crate::shim::PROFILE_REFUSED),
    ] {
        let shim = Shim::default();
        assert_eq!(shim.keyed(&material, profile), Err(why));
        assert!(!shim.holds_keying(), "profile {profile:#06x}: nothing held");
    }

    for (profile, len) in [
        (PROFILE_AEAD_AES_128_GCM, 56),
        (PROFILE_AEAD_AES_256_GCM, 88),
    ] {
        let shim = Shim::default();
        assert_eq!(shim.keyed(&[7_u8; 88][..len], profile), Ok(()));
        assert!(shim.holds_keying(), "profile {profile:#06x}: held");
    }
}

/// Keying material whose length is not its profile's never reaches the media stack's key
/// schedule (which asserts the length): it is refused, and nothing is held.
#[test]
fn keying_material_of_the_wrong_length_is_refused_and_nothing_is_held() {
    for (profile, len) in [
        (PROFILE_AEAD_AES_128_GCM, 55),
        (PROFILE_AEAD_AES_128_GCM, 88),
        (PROFILE_AEAD_AES_256_GCM, 56),
        (PROFILE_AEAD_AES_256_GCM, 0),
    ] {
        let shim = Shim::default();
        assert_eq!(
            shim.keyed(&[7_u8; 88][..len], profile),
            Err(crate::shim::KEYING_LENGTH_REFUSED)
        );
        assert!(!shim.holds_keying());
        assert_eq!(
            crate::shim::keying_frame(&[7_u8; 88][..len], profile).err(),
            Some(crate::shim::KEYING_LENGTH_REFUSED)
        );
    }
}

#[test]
fn the_srtp_key_derivation_block_is_aes() {
    let key: Vec<u8> = (0..16).collect();
    let input: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
    let mut out = [0_u8; 16];
    Ring.srtp_aes_128_ecb_round(&key, &input, &mut out);
    assert_eq!(
        out,
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a
        ]
    );

    Ring.srtp_aes_128_ecb_round(&key[..15], &input, &mut out);
    assert_eq!(out, [0_u8; 16]);
}

/// `Debug` of a keyed shim prints neither the SRTP keying material nor an opened plaintext: a
/// `{:?}` in a log line carries no key bytes.
#[test]
fn debug_of_a_keyed_shim_prints_no_key_or_plaintext_bytes() {
    let canary: [u8; 4] = [0xCA, 0x4A, 0x21, 0x7E];
    let material: Vec<u8> = canary
        .iter()
        .copied()
        .cycle()
        .take(2 * 16 + 2 * 12)
        .collect();
    let shim = Shim::default();
    shim.keyed(&material, PROFILE_AEAD_AES_128_GCM).unwrap();
    shim.opened(&canary.repeat(4));
    assert!(shim.holds_keying());
    let out = format!("{shim:?}");
    let dec = canary
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let hex = canary.iter().map(|b| format!("{b:x}")).collect::<String>();
    assert!(
        !out.contains(&dec),
        "keying/plaintext bytes in Debug: {out}"
    );
    assert!(
        !out.contains(&hex),
        "keying/plaintext bytes in Debug: {out}"
    );
    assert!(out.contains("<redacted"), "no redaction marker: {out}");
}

/// Sending through a closed shim reports closed rather than pending.
#[test]
fn a_send_on_a_closed_shim_is_refused_as_closed_not_pending() {
    use str0m::crypto::dtls::{DtlsImplError, DtlsInstance};
    let mut shim = Shim::default();
    assert!(matches!(
        shim.send_application_data(b"early"),
        Err(DtlsImplError::HandshakePending)
    ));
    shim.handle_packet(&crate::shim::CONNECTED_FRAME)
        .expect("the relay is taken");
    assert!(shim.send_application_data(b"open").is_ok());
    shim.close().expect("closes");
    assert!(matches!(
        shim.send_application_data(b"late"),
        Err(DtlsImplError::ConnectionClosed)
    ));
}

/// An unknown protection profile is not identified as AES_CM.
#[test]
fn an_unknown_protection_profile_is_not_called_aes_cm() {
    let why = "the keying material's protection profile is not AEAD-AES-GCM";
    for code in [0x0005_u32, 0x0006, 0x1234] {
        let material = [7_u8; 56];
        assert_eq!(
            crate::shim::keying_frame(&material, code).err(),
            Some(why),
            "{code:#x}"
        );
        assert_eq!(
            Shim::default().keyed(&material, code),
            Err(why),
            "{code:#x}"
        );
    }
    for code in [PROFILE_AES_CM_SHA1_80, PROFILE_AES_CM_SHA1_32] {
        assert_eq!(
            crate::shim::keying_frame(&[7_u8; 56], code).err(),
            Some(AES_CM_REFUSED)
        );
    }
}

/// The AEAD-AES-256-GCM profile derives keys with an AES-256 block.
#[test]
fn the_256_bit_key_derivation_block_is_aes_256() {
    let key: Vec<u8> = (0..32).collect();
    let input: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
    let mut out = [0_u8; 16];
    Ring.srtp_aes_256_ecb_round(&key, &input, &mut out);
    assert_eq!(
        out,
        [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89
        ]
    );
}

/// SHA-256 and HMAC-SHA1 match their standard test vectors.
#[test]
fn the_digests_meet_their_vectors() {
    assert_eq!(
        Ring.sha256(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(
        Ring.sha1_hmac(&[0x0b; 20], &[b"Hi ", b"There"]),
        [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
        ]
    );
}
