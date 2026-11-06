// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::Cell;

use super::*;

fn aad(ssrc: u32, index: u32) -> [u8; 12] {
    let mut header = [0x80, 200, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0];
    header[4..8].copy_from_slice(&ssrc.to_be_bytes());
    header[8..].copy_from_slice(&(index | 0x8000_0000).to_be_bytes());
    header
}

fn nonce(ssrc: u32, index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[2..6].copy_from_slice(&ssrc.to_be_bytes());
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

#[test]
fn srtcp_sender_refuses_wrap_before_reusing_a_key_and_nonce() {
    for algorithm in [&AES_128_GCM, &AES_256_GCM] {
        let key = vec![9; algorithm.key_len()];
        let mut cipher = Gcm::new(algorithm, &key).unwrap();
        let mut output = [0; 36];
        cipher
            .seal(&nonce(7, 0), &aad(7, 0), &[42; 20], &mut output)
            .unwrap();
        cipher
            .seal(
                &nonce(7, 0x7fff_ffff),
                &aad(7, 0x7fff_ffff),
                &[42; 20],
                &mut output,
            )
            .unwrap();
        output.fill(0xa5);
        assert!(
            cipher
                .seal(&nonce(7, 0), &aad(7, 0), &[43; 20], &mut output)
                .is_err(),
            "wrapped SRTCP nonce was encrypted again"
        );
        assert_eq!(output, [0; 36], "refused output must be cleared");
        assert!(
            cipher
                .seal(&nonce(7, 1), &aad(7, 1), &[42; 20], &mut output)
                .is_err(),
            "exhaustion must remain terminal for this sender key"
        );
        let new_key = vec![8; algorithm.key_len()];
        let mut rekeyed = Gcm::new(algorithm, &new_key).unwrap();
        rekeyed
            .seal(&nonce(7, 0), &aad(7, 0), &[42; 20], &mut output)
            .expect("a genuinely new key starts its own index epoch");
    }
}

#[test]
fn srtcp_sender_index_is_global_across_sources_and_receive_state_is_separate() {
    for algorithm in [&AES_128_GCM, &AES_256_GCM] {
        let mut cipher = Gcm::new(algorithm, &vec![9; algorithm.key_len()]).unwrap();
        let mut first = [0; 36];
        cipher
            .seal(&nonce(7, 0), &aad(7, 0), &[42; 20], &mut first)
            .unwrap();
        let mut output = [0; 36];
        cipher
            .seal(&nonce(8, 1), &aad(8, 1), &[42; 20], &mut output)
            .unwrap();
        assert!(cipher
            .seal(&nonce(7, 1), &aad(7, 1), &[42; 20], &mut output)
            .is_err());
        let mut plain = [0; 20];
        assert_eq!(
            cipher
                .open(&nonce(7, 0), &[&aad(7, 0), &[]], &first, &mut plain)
                .unwrap(),
            20
        );
        assert_eq!(plain, [42; 20]);
        cipher
            .seal(&nonce(7, 2), &aad(7, 2), &[42; 20], &mut output)
            .unwrap();
    }
}

#[test]
fn twelve_byte_rtp_headers_do_not_consume_the_srtcp_sender_index() {
    for algorithm in [&AES_128_GCM, &AES_256_GCM] {
        let mut cipher = Gcm::new(algorithm, &vec![9; algorithm.key_len()]).unwrap();
        for payload_type in [0_u8, 63, 96, 111, 127] {
            for marker in [0, 0x80] {
                let mut header = aad(7, 0x7fff_ffff);
                header[1] = payload_type | marker;
                let mut output = [0; 36];

                cipher
                    .seal(
                        &nonce(7, u32::from(payload_type) + u32::from(marker)),
                        &header,
                        &[42; 20],
                        &mut output,
                    )
                    .unwrap();
            }
        }
        cipher
            .seal(&nonce(8, 0), &aad(8, 0), &[42; 20], &mut [0; 36])
            .unwrap();
    }
}

#[derive(Clone, Copy, Default)]
struct Injection {
    active: bool,
    selected: Option<usize>,
    ssrc: [u8; 4],
    attempts: usize,
    primed: bool,
    priming: bool,
}

thread_local! {
    static INJECTION: Cell<Injection> = const { Cell::new(Injection {
        active: false, selected: None, ssrc: [0; 4], attempts: 0, primed: false, priming: false,
    }) };
}

pub(crate) struct ExhaustSender;

impl ExhaustSender {
    pub(crate) fn start() -> Self {
        INJECTION.with(|slot| {
            assert!(!slot.get().active);
            slot.set(Injection {
                active: true,
                ..Injection::default()
            });
        });
        Self
    }

    pub(crate) fn snapshot(&self) -> ([u8; 4], usize, bool) {
        INJECTION.with(|slot| {
            let state = slot.get();
            (state.ssrc, state.attempts, state.primed)
        })
    }
}

impl Drop for ExhaustSender {
    fn drop(&mut self) {
        INJECTION.with(|slot| slot.set(Injection::default()));
    }
}

pub(super) fn before_seal(cipher: &mut Gcm, iv: &[u8; 12], header: &[u8], input: &[u8]) {
    let prime = INJECTION.with(|slot| {
        let mut state = slot.get();
        if !state.active
            || state.priming
            || header.len() != 12
            || header[0] & 0xc0 != 0x80
            || header[1] != 200
            || header[8] & 0x80 == 0
        {
            return false;
        }
        let address = std::ptr::from_ref(cipher).addr();
        if let Some(selected) = state.selected {
            if selected != address || state.ssrc != header[4..8] {
                return false;
            }
        } else {
            state.selected = Some(address);
            state.ssrc.copy_from_slice(&header[4..8]);
        }
        state.attempts += 1;
        let prime = state.attempts == 2;
        if prime {
            state.priming = true;
        }
        slot.set(state);
        prime
    });
    if !prime {
        return;
    }

    let index = u32::from_be_bytes(header[8..12].try_into().unwrap()) & 0x7fff_ffff;
    let mut terminal_header = [0; 12];
    terminal_header.copy_from_slice(header);
    terminal_header[8..].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut terminal_iv = *iv;
    for (offset, (old, new)) in index
        .to_be_bytes()
        .into_iter()
        .zip(0x7fff_ffff_u32.to_be_bytes())
        .enumerate()
    {
        terminal_iv[8 + offset] ^= old ^ new;
    }
    let mut discarded = Zeroizing::new(vec![0; input.len() + 16]);
    cipher
        .seal(&terminal_iv, &terminal_header, input, &mut discarded)
        .unwrap();
    INJECTION.with(|slot| {
        let mut state = slot.get();
        state.priming = false;
        state.primed = true;
        slot.set(state);
    });
}

/// A plain 12-byte RTP header (V=2, no CSRC, no extension, marker clear) whose payload type a far
/// end mapped into 64..=95 and whose SSRC has its top bit set: the AAD is SRTCP-shaped in every
/// byte but the second, which is an RTP payload type (< 128), never an RTCP packet type.
fn rtp_aad(pt: u8, seq: u16, ssrc: u32) -> [u8; 12] {
    let mut header = [0x80, pt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    header[2..4].copy_from_slice(&seq.to_be_bytes());
    header[8..].copy_from_slice(&ssrc.to_be_bytes());
    header
}

#[test]
fn rtp_under_a_payload_type_in_the_rtcp_range_is_never_held_to_the_srtcp_sender_index() {
    for algorithm in [&AES_128_GCM, &AES_256_GCM] {
        let mut cipher = Gcm::new(algorithm, &vec![9; algorithm.key_len()]).unwrap();
        let ssrc = 0x9234_5678;
        let mut output = [0; 36];
        for seq in 0..3 {
            cipher
                .seal(
                    &nonce(ssrc, seq.into()),
                    &rtp_aad(77, seq, ssrc),
                    &[42; 20],
                    &mut output,
                )
                .expect("an RTP packet of one source seals under each sequence number");
        }
    }
}

#[test]
fn every_rtcp_packet_type_in_the_mux_range_is_held_to_the_sender_index() {
    for packet_type in [192_u8, 200, 205, 206, 223] {
        let mut cipher = Gcm::new(&AES_128_GCM, &[9; 16]).unwrap();
        let mut header = aad(7, 5);
        header[1] = packet_type;
        let mut output = [0; 36];
        cipher
            .seal(&nonce(7, 5), &header, &[42; 20], &mut output)
            .unwrap();
        assert!(
            cipher
                .seal(&nonce(7, 5), &header, &[42; 20], &mut output)
                .is_err(),
            "a reused SRTCP index under packet type {packet_type} is refused"
        );
    }
}

#[test]
fn second_bytes_beside_the_rtcp_mux_range_are_never_held_to_the_sender_index() {
    for second in [191_u8, 224, 255] {
        let mut cipher = Gcm::new(&AES_128_GCM, &[9; 16]).unwrap();
        let mut header = aad(7, 5);
        header[1] = second;
        let mut output = [0; 36];
        for _ in 0..2 {
            cipher
                .seal(&nonce(7, 5), &header, &[42; 20], &mut output)
                .expect("a header outside the RTCP range is RTP, never index-checked");
        }
    }
}
