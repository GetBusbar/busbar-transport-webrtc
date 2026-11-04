// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The few facts of a connectivity check the framer reads itself (RFC 8489 framing, RFC 8445
//! attributes): its class, its transaction id and whether it nominates. Integrity is the media
//! stack's ICE agent's to judge (it answers only a check whose MESSAGE-INTEGRITY verifies), and the
//! host's, independently. The one verdict judged here is the dialling end's: whether a Binding
//! success it acts on carries a MESSAGE-INTEGRITY that verifies ([`integrity_holds`]), since the
//! stack's own verdict on a response is not observable.

/// The STUN magic cookie.
const MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
/// Binding request.
const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response.
const BINDING_SUCCESS: u16 = 0x0101;
/// USE-CANDIDATE (RFC 8445 §16.1).
const USE_CANDIDATE: u16 = 0x0025;
/// MESSAGE-INTEGRITY (RFC 8489 §14.5): an HMAC-SHA1, 20 bytes.
const MESSAGE_INTEGRITY: u16 = 0x0008;
/// MESSAGE-INTEGRITY-SHA256 (RFC 8489 §14.6).
const MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;

const HEADER_LEN: usize = 20;
const TRANSACTION_ID_LEN: usize = 12;
const MESSAGE_LENGTH_FIELD: std::ops::Range<usize> = 2..4;
const COOKIE_FIELD: std::ops::Range<usize> = 4..8;
const TRANSACTION_ID_FIELD: std::ops::Range<usize> = 8..HEADER_LEN;
const RESERVED_TYPE_BITS: u8 = 0xC0;

const ATTRIBUTE_HEADER_LEN: usize = 4;
const ATTRIBUTE_ALIGNMENT: usize = 4;
const ATTRIBUTE_PADDING_MASK: usize = ATTRIBUTE_ALIGNMENT - 1;

const INTEGRITY_VALUE_LEN: usize = 20;
const INTEGRITY_ATTRIBUTE_LEN: usize = ATTRIBUTE_HEADER_LEN + INTEGRITY_VALUE_LEN;

const STUN_FIRST_BYTE_MIN: u8 = 0;
const STUN_FIRST_BYTE_MAX: u8 = 3;

/// What a datagram is, as far as nomination goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// A Binding request; `nominates` = it carries USE-CANDIDATE.
    Request {
        /// The transaction id.
        txid: [u8; TRANSACTION_ID_LEN],
        /// It nominates the pair it travels on.
        nominates: bool,
    },
    /// A Binding success response.
    Success {
        /// The transaction id.
        txid: [u8; TRANSACTION_ID_LEN],
    },
}

/// Read `datagram` as a Binding request or success response; `None` for anything else, a message
/// RFC 8489 §5 does not frame among it (a length that is no multiple of 4, or not the datagram's
/// size less the header).
#[must_use]
pub fn read(datagram: &[u8]) -> Option<Check> {
    let head = datagram.get(..HEADER_LEN)?;
    if head[0] & RESERVED_TYPE_BITS != 0 || head[COOKIE_FIELD] != MAGIC {
        return None;
    }
    let kind = u16::from_be_bytes([head[0], head[1]]);
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    if len % ATTRIBUTE_ALIGNMENT != 0 || datagram.len() != HEADER_LEN + len {
        return None;
    }
    let body = &datagram[HEADER_LEN..];
    let mut txid = [0_u8; TRANSACTION_ID_LEN];
    txid.copy_from_slice(&head[TRANSACTION_ID_FIELD]);
    match kind {
        BINDING_REQUEST => Some(Check::Request {
            txid,

            nominates: attributes(body)
                .take_while(|(kind, _)| {
                    !matches!(*kind, MESSAGE_INTEGRITY | MESSAGE_INTEGRITY_SHA256)
                })
                .any(|a| a == (USE_CANDIDATE, 0)),
        }),
        BINDING_SUCCESS => Some(Check::Success { txid }),
        _ => None,
    }
}

/// The attributes of a STUN body, `(type, value length)` each, in order, stopping at the first
/// malformed one.
fn attributes(body: &[u8]) -> impl Iterator<Item = (u16, usize)> + '_ {
    let mut at = 0_usize;
    std::iter::from_fn(move || {
        let h = body.get(at..at + ATTRIBUTE_HEADER_LEN)?;
        let t = u16::from_be_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        let padded = len.checked_add(ATTRIBUTE_PADDING_MASK)? & !ATTRIBUTE_PADDING_MASK;
        at = at.checked_add(ATTRIBUTE_HEADER_LEN)?.checked_add(padded)?;
        if at > body.len() {
            return None;
        }
        Some((t, len))
    })
}

/// Whether `datagram`'s MESSAGE-INTEGRITY verifies under the short-term credential `key` (RFC 8489
/// §14.5: HMAC-SHA1 over the message up to the attribute, its header's length counting through
/// it). `false` for a message without one.
#[must_use]
pub fn integrity_holds(datagram: &[u8], key: &[u8]) -> bool {
    let Some(head) = datagram.get(..HEADER_LEN) else {
        return false;
    };
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let Some(body) = datagram.get(HEADER_LEN..HEADER_LEN + len) else {
        return false;
    };
    let mut at = 0_usize;
    while let Some(h) = body.get(at..at + ATTRIBUTE_HEADER_LEN) {
        let t = u16::from_be_bytes([h[0], h[1]]);
        let n = usize::from(u16::from_be_bytes([h[2], h[3]]));
        if t == MESSAGE_INTEGRITY {
            let (Some(mac), Ok(through)) = (
                body.get(at + ATTRIBUTE_HEADER_LEN..at + INTEGRITY_ATTRIBUTE_LEN),
                u16::try_from(at + INTEGRITY_ATTRIBUTE_LEN),
            ) else {
                return false;
            };
            if n != INTEGRITY_VALUE_LEN {
                return false;
            }
            let mut signed = head.to_vec();
            signed[MESSAGE_LENGTH_FIELD].copy_from_slice(&through.to_be_bytes());
            signed.extend_from_slice(&body[..at]);
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
            return ring::hmac::verify(&key, &signed, mac).is_ok();
        }
        at += ATTRIBUTE_HEADER_LEN + ((n + ATTRIBUTE_PADDING_MASK) & !ATTRIBUTE_PADDING_MASK);
    }
    false
}

/// Whether `datagram` is a STUN message at all (RFC 7983: first byte 0..=3).
#[must_use]
pub fn is_stun(datagram: &[u8]) -> bool {
    matches!(
        datagram.first(),
        Some(STUN_FIRST_BYTE_MIN..=STUN_FIRST_BYTE_MAX)
    )
}
