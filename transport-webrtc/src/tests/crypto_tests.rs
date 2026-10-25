// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SRTP IS AEAD-AES-GCM ONLY (THE DESIGN l.753): the provider's `AES_CM` cipher refuses every
//! packet, and the shim refuses keying material under any profile but the two GCM ones. The RED
//! arm beside each refusal is the same call under AEAD-AES-GCM, which goes through: the refusal is
//! the profile's, not a broken path.

use super::*;
use crate::framing::{PROFILE_AEAD_AES_128_GCM, PROFILE_AEAD_AES_256_GCM};
use crate::shim::Shim;

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
    // A flipped tag bit fails authentication: the GCM path judges, it does not wave through.
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
    for profile in [
        PROFILE_AES_CM_SHA1_80,
        PROFILE_AES_CM_SHA1_32,
        0x0003,
        0xFFFF,
    ] {
        let shim = Shim::default();
        assert_eq!(shim.keyed(&material, profile), Err(AES_CM_REFUSED));
        assert!(!shim.holds_keying(), "profile {profile:#06x}: nothing held");
    }
    // RED arm: the two AEAD-AES-GCM profiles are taken, at their own lengths.
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
    // FIPS-197 Appendix C.1: AES-128 of 00112233445566778899aabbccddeeff under 000102…0f.
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
    // A key of the wrong length derives nothing (a zeroed block), and nothing panics.
    Ring.srtp_aes_128_ecb_round(&key[..15], &input, &mut out);
    assert_eq!(out, [0_u8; 16]);
}

/// `Debug` of a keyed shim prints neither the SRTP keying material nor an opened plaintext: a
/// `{:?}` in a log line carries no key bytes.
#[test]
fn debug_of_a_keyed_shim_prints_no_key_or_plaintext_bytes() {
    // 0xCA 0x4A 0x21 0x7E: a canary no other field holds; Debug prints bytes in decimal.
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
