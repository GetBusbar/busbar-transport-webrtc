// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct Packet {
    iv: [u8; 12],
    aad: Vec<u8>,
    index: [u8; 4],
    sealed: Vec<u8>,
    encrypted: bool,
}

impl Packet {
    fn new(alg: &'static ring::aead::Algorithm, ssrc: u32, index: u32, encrypted: bool) -> Self {
        Self::with_key(alg, &[9; 32][..alg.key_len()], ssrc, index, encrypted)
    }

    fn with_key(
        alg: &'static ring::aead::Algorithm,
        key: &[u8],
        ssrc: u32,
        index: u32,
        encrypted: bool,
    ) -> Self {
        let mut header = vec![0x80, 200, 0, 6];
        header.extend_from_slice(&ssrc.to_be_bytes());
        let mut iv = [0; 12];
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[8..].copy_from_slice(&index.to_be_bytes());
        let index = (index | if encrypted { 0x8000_0000 } else { 0 }).to_be_bytes();
        let plain = [42; 20];
        let aad = if encrypted {
            header.extend_from_slice(&index);
            header
        } else {
            header.extend_from_slice(&plain);
            header
        };
        let authenticated = if encrypted {
            aad.clone()
        } else {
            [aad.as_slice(), &index].concat()
        };
        let input = if encrypted { plain.as_slice() } else { &[] };
        let mut sealed = vec![0; input.len() + 16];
        Gcm::new(alg, key)
            .unwrap()
            .seal(&iv, &authenticated, input, &mut sealed)
            .unwrap();
        Self {
            iv,
            aad,
            index,
            sealed,
            encrypted,
        }
    }

    fn open(&self, receiver: &mut Gcm) -> Result<usize, CryptoError> {
        let tail = if self.encrypted {
            &[][..]
        } else {
            &self.index[..]
        };
        let mut out = [0xa5; 20];
        let result = receiver.open(&self.iv, &[&self.aad, tail], &self.sealed, &mut out);
        let n = self.sealed.len() - 16;
        if result.is_err() {
            assert!(
                out[..n].iter().all(|&b| b == 0),
                "refused plaintext remains"
            );
        } else {
            assert!(out[..n].iter().all(|&b| b == 42), "wrong plaintext");
        }
        result
    }
}

fn receiver(alg: &'static ring::aead::Algorithm) -> Gcm {
    Gcm::new(alg, &[9; 32][..alg.key_len()]).unwrap()
}

#[test]
fn authenticated_srtcp_duplicates_and_old_packets_are_refused() {
    for alg in [&AES_128_GCM, &AES_256_GCM] {
        for encrypted in [true, false] {
            let mut receiver = receiver(alg);
            let first = Packet::new(alg, 7, 10, encrypted);
            assert!(first.open(&mut receiver).is_ok());
            assert!(
                first.open(&mut receiver).is_err(),
                "duplicate report admitted"
            );
            assert!(Packet::new(alg, 7, 12, encrypted)
                .open(&mut receiver)
                .is_ok());
            let reordered = Packet::new(alg, 7, 11, encrypted);
            assert!(
                reordered.open(&mut receiver).is_ok(),
                "unseen reordered report refused"
            );
            assert!(reordered.open(&mut receiver).is_err());
            assert!(Packet::new(alg, 7, 74, encrypted)
                .open(&mut receiver)
                .is_ok());
            assert!(
                first.open(&mut receiver).is_err(),
                "report outside window admitted"
            );
            assert!(
                Packet::new(alg, 7, 9, encrypted)
                    .open(&mut receiver)
                    .is_err(),
                "unseen stale report admitted"
            );
            assert!(Packet::new(alg, 8, 74, encrypted)
                .open(&mut receiver)
                .is_ok());
            assert!(Packet::new(alg, 8, 11, encrypted)
                .open(&mut receiver)
                .is_ok());
            assert!(Packet::new(alg, 8, 10, encrypted)
                .open(&mut receiver)
                .is_err());
        }
    }
}

#[test]
fn invalid_srtcp_tags_neither_advance_nor_consume_the_receive_window() {
    for alg in [&AES_128_GCM, &AES_256_GCM] {
        for encrypted in [true, false] {
            let mut receiver = receiver(alg);
            assert!(Packet::new(alg, 7, 10, encrypted)
                .open(&mut receiver)
                .is_ok());
            let mut invalid = Packet::new(alg, 7, 1000, encrypted);
            invalid.sealed[0] ^= 1;
            assert!(invalid.open(&mut receiver).is_err());
            let next = Packet::new(alg, 7, 11, encrypted);
            assert!(next.open(&mut receiver).is_ok());
            let mut invalid = Packet::new(alg, 7, 12, encrypted);
            invalid.sealed[0] ^= 1;
            assert!(invalid.open(&mut receiver).is_err());
            assert!(Packet::new(alg, 7, 12, encrypted)
                .open(&mut receiver)
                .is_ok());
            assert!(next.open(&mut receiver).is_err());
        }
    }
}

#[test]
fn srtcp_sources_and_receive_contexts_are_independent() {
    for alg in [&AES_128_GCM, &AES_256_GCM] {
        let mut first = receiver(alg);
        let mut other_direction = receiver(alg);
        let new_key = &[8; 32][..alg.key_len()];
        let mut next_epoch = Gcm::new(alg, new_key).unwrap();
        let packet = Packet::new(alg, 7, 0, true);
        assert!(packet.open(&mut first).is_ok());
        assert!(packet.open(&mut other_direction).is_ok());
        assert!(
            packet.open(&mut next_epoch).is_err(),
            "old key accepted in new epoch"
        );
        let new_packet = Packet::with_key(alg, new_key, 7, 0, true);
        assert!(new_packet.open(&mut next_epoch).is_ok());
        assert!(Packet::new(alg, 8, 0, true).open(&mut first).is_ok());
        assert!(packet.open(&mut first).is_err());
        assert!(packet.open(&mut other_direction).is_err());
        assert!(new_packet.open(&mut next_epoch).is_err());
    }
}

#[test]
fn srtcp_encryption_modes_share_the_index_and_counter_wrap_needs_a_new_key() {
    for alg in [&AES_128_GCM, &AES_256_GCM] {
        let mut receiver = receiver(alg);
        assert!(Packet::new(alg, 7, 0, true).open(&mut receiver).is_ok());
        assert!(Packet::new(alg, 7, 0, false).open(&mut receiver).is_err());
        assert!(Packet::new(alg, 7, 0x7fff_ffff, true)
            .open(&mut receiver)
            .is_ok());
        assert!(Packet::new(alg, 7, 0, true).open(&mut receiver).is_err());
        assert!(Packet::new(alg, 7, 0x7fff_fffe, false)
            .open(&mut receiver)
            .is_ok());
    }
}

#[test]
fn rtp_with_a_twelve_byte_header_does_not_enter_the_srtcp_window() {
    let mut receiver = receiver(&AES_128_GCM);
    let packet = Packet::new(&AES_128_GCM, 7, 0, true);
    for _ in 0..2 {
        assert!(receiver
            .open(&packet.iv, &[&packet.aad], &packet.sealed, &mut [0; 20])
            .is_ok());
    }
    assert!(packet.open(&mut receiver).is_ok());
    assert!(packet.open(&mut receiver).is_err());
}

#[test]
fn srtcp_source_saturation_never_forgets_an_accepted_index() {
    let alg = &AES_128_GCM;
    let mut receiver = receiver(alg);
    for source in 0..crate::framing::MAX_QUEUED as u32 {
        let mut invalid = Packet::new(alg, source, 1000, true);
        invalid.sealed[0] ^= 1;
        assert!(invalid.open(&mut receiver).is_err());
    }
    for source in 0..crate::framing::MAX_QUEUED as u32 {
        assert!(Packet::new(alg, source, 0, true)
            .open(&mut receiver)
            .is_ok());
    }
    let overflow = Packet::new(alg, crate::framing::MAX_QUEUED as u32, 0, true);
    assert!(overflow.open(&mut receiver).is_err());
    assert!(Packet::new(alg, 0, 0, true).open(&mut receiver).is_err());
    assert!(Packet::new(alg, 0, 1, true).open(&mut receiver).is_ok());
}
