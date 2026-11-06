// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The few STUN facts the framer reads itself: what a malformed check reads as, and when a
//! MESSAGE-INTEGRITY does not hold.

use super::*;

const KEY: &[u8] = b"the far end's check secret";

/// A STUN message of `kind` whose header length is `len`, then `attrs`.
fn message(kind: u16, len: u16, attrs: &[u8]) -> Vec<u8> {
    let mut m = kind.to_be_bytes().to_vec();
    m.extend_from_slice(&len.to_be_bytes());
    m.extend_from_slice(&MAGIC);
    m.extend_from_slice(&[7_u8; TRANSACTION_ID_LEN]);
    m.extend_from_slice(attrs);
    m
}

/// A Binding success signed under `key`: a USERNAME-sized attribute then MESSAGE-INTEGRITY.
fn signed_success(key: &[u8]) -> Vec<u8> {
    let first = [0x00, 0x06, 0, 4, b'u', b's', b'e', b'r'];
    let through = (first.len() + INTEGRITY_ATTRIBUTE_LEN) as u16;
    let mut m = message(BINDING_SUCCESS, through, &first);
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let mac = ring::hmac::sign(&k, &m);
    m.extend_from_slice(&[0x00, 0x08, 0, 20]);
    m.extend_from_slice(mac.as_ref());
    m
}

#[test]
fn a_well_signed_success_holds_and_any_other_key_or_byte_does_not() {
    let m = signed_success(KEY);
    assert!(integrity_holds(&m, KEY));
    assert!(!integrity_holds(&m, b"another secret"));
    let mut flipped = m.clone();
    flipped[HEADER_LEN + 5] ^= 1;
    assert!(
        !integrity_holds(&flipped, KEY),
        "a byte the MAC covers was changed"
    );
}

#[test]
fn integrity_never_holds_on_a_message_that_cannot_carry_it() {
    let m = signed_success(KEY);
    assert!(
        !integrity_holds(&m[..HEADER_LEN - 1], KEY),
        "shorter than a header"
    );
    let mut long = m.clone();
    long[2..4].copy_from_slice(&200_u16.to_be_bytes());
    assert!(!integrity_holds(&long, KEY), "a length past the datagram");
    let mut cut = m.clone();
    cut.truncate(m.len() - 4);
    let body = (cut.len() - HEADER_LEN) as u16;
    cut[2..4].copy_from_slice(&body.to_be_bytes());
    assert!(!integrity_holds(&cut, KEY), "a MESSAGE-INTEGRITY cut short");
    let mut wrong_len = m.clone();
    let at = wrong_len.len() - INTEGRITY_ATTRIBUTE_LEN + 3;
    wrong_len[at] = 16;
    assert!(
        !integrity_holds(&wrong_len, KEY),
        "a MESSAGE-INTEGRITY not 20 bytes long"
    );
    let unsigned = message(
        BINDING_SUCCESS,
        8,
        &[0x00, 0x06, 0, 4, b'u', b's', b'e', b'r'],
    );
    assert!(
        !integrity_holds(&unsigned, KEY),
        "no MESSAGE-INTEGRITY at all"
    );
}

#[test]
fn only_a_binding_request_or_success_is_a_check() {
    assert_eq!(
        read(&message(0x0111, 0, &[])),
        None,
        "a Binding error response"
    );
    assert_eq!(read(&message(0x0011, 0, &[])), None, "a Binding indication");
    assert_eq!(
        read(&message(BINDING_SUCCESS, 0, &[])),
        Some(Check::Success {
            txid: [7; TRANSACTION_ID_LEN]
        })
    );
}

#[test]
fn an_attribute_running_past_the_body_ends_the_attributes_before_it_is_read() {
    let body = [
        0x00, 0x06, 0, 4, b'u', b's', b'e', b'r', 0x00, 0x25, 0, 64, 0, 0, 0, 0,
    ];
    assert_eq!(attributes(&body).collect::<Vec<_>>(), vec![(0x0006, 4)]);
    assert_eq!(
        attributes(&body[..8]).collect::<Vec<_>>(),
        vec![(0x0006, 4)]
    );
}
