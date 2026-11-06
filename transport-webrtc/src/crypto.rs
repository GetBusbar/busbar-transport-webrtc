// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The framer's crypto provider for the media stack.

use std::{collections::HashMap, fmt};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use busbar_contract::abi::sdk::aead::{AesGcm, GCM_TAG_LEN};
use ring::aead::{AES_128_GCM, AES_256_GCM};
use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher, CryptoError, CryptoProvider,
    Sha1HmacProvider, Sha256Provider, SrtpProvider, SupportedAeadAes128Gcm, SupportedAeadAes256Gcm,
    SupportedAes128CmSha1_80,
};
use zeroize::{Zeroize as _, Zeroizing};

/// The provider. It holds nothing: every reference to it is a promoted constant, never a `static`
/// (a plugin holds no process-global state).
#[derive(Debug)]
pub struct Ring;

/// The crypto provider every framing's media stack runs on (its handshake slot is the host shim's,
/// [`crate::shim::provider`]).
#[must_use]
pub fn provider() -> CryptoProvider {
    crate::shim::provider(&Ring)
}

/// The most AAD bytes an open gathers on the stack (an SRTP header with its extensions, an SRTCP
/// header and index); more spill to the heap.
const AAD_ON_STACK: usize = 1024;

const RTP_VERSION_MASK: u8 = 0xc0;
const RTP_VERSION_2: u8 = 0x80;
/// The RTCP packet types that share the RTP/RTCP demultiplexing range (RFC 5761 §4): the whole
/// second byte, never masked. An RTP header's second byte is its marker bit and payload type, so
/// an unmarked RTP packet (the media stack never marks Opus) is never taken for SRTCP, even under
/// a payload type a far end mapped into 64..=95.
const RTCP_PACKET_TYPE_MIN: u8 = 192;
const RTCP_PACKET_TYPE_MAX: u8 = 223;

const SRTCP_HEADER_LEN: usize = 8;
const SRTCP_INDEX_LEN: usize = 4;
const SRTCP_AAD_LEN: usize = SRTCP_HEADER_LEN + SRTCP_INDEX_LEN;
const SRTCP_ENCRYPTED_FLAG: u32 = 0x8000_0000;
const SRTCP_ENCRYPTED_BYTE_FLAG: u8 = (SRTCP_ENCRYPTED_FLAG >> 24) as u8;
const SRTCP_INDEX_MASK: u32 = !SRTCP_ENCRYPTED_FLAG;
const SSRC_FIELD: std::ops::Range<usize> = 4..SRTCP_HEADER_LEN;
const SRTCP_SOURCE_LIMIT: usize = crate::framing::MAX_QUEUED;
const SRTCP_LAYOUT_REFUSED: &str = "SRTCP authentication layout refused";
const SRTCP_SENDER_EXHAUSTED: &str = "SRTCP sender index exhausted or reused";
const SRTCP_REPLAY_REFUSED: &str = "SRTCP replay or source capacity exceeded";

fn refused(why: &str) -> CryptoError {
    CryptoError::Other(why.into())
}

/// The refusal an `AES_CM` packet meets.
pub const AES_CM_REFUSED: &str = "SRTP AES_CM is refused: AEAD-AES-GCM only";

impl SrtpProvider for Ring {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &Ring
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &Ring
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &Ring
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<aes::Aes128>(key, input, output);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<aes::Aes256>(key, input, output);
    }
}

/// One AES block of the SRTP key derivation: `output[..16] = AES_key(input[..16])`. A key of the
/// wrong length, or a block shorter than 16 bytes, leaves `output` zeroed (the derived key is then
/// useless and every packet fails authentication; nothing panics across the door).
fn ecb_round<C: KeyInit + BlockEncrypt>(key: &[u8], input: &[u8], output: &mut [u8]) {
    output.iter_mut().for_each(|b| *b = 0);
    let (Ok(cipher), Some(block), true) =
        (C::new_from_slice(key), input.get(..16), output.len() >= 16)
    else {
        return;
    };
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    output[..16].copy_from_slice(&b);
    b.as_mut_slice().zeroize();
}

impl SupportedAes128CmSha1_80 for Ring {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        let _ = Zeroizing::new(key);
        Box::new(AesCmRefused)
    }
}

/// The `AES_CM` cipher: it refuses every packet.
#[derive(Debug)]
pub struct AesCmRefused;

impl Aes128CmSha1_80Cipher for AesCmRefused {
    fn encrypt(&mut self, _: &[u8; 16], _: &[u8], _: &mut [u8]) -> Result<(), CryptoError> {
        Err(refused(AES_CM_REFUSED))
    }

    fn decrypt(&mut self, _: &[u8; 16], _: &[u8], _: &mut [u8]) -> Result<(), CryptoError> {
        Err(refused(AES_CM_REFUSED))
    }
}

/// An AEAD-AES-GCM cipher with provider-owned key state destroyed on drop.
pub struct Gcm {
    key: AesGcm,
    srtcp: HashMap<u32, ReplayWindow>,
    last_sent_srtcp: Option<u32>,
}

#[derive(Debug)]
struct ReplayWindow {
    highest: u32,
    seen: u64,
}

impl ReplayWindow {
    fn accept(&mut self, index: u32) -> bool {
        if index > self.highest {
            let shift = index - self.highest;
            self.seen = self.seen.checked_shl(shift).unwrap_or(0) | 1;
            self.highest = index;
            return true;
        }
        let Some(bit) = 1_u64.checked_shl(self.highest - index) else {
            return false;
        };
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

/// str0m 0.24.1 gives RTP one AAD slice and SRTCP two: [header+index, empty]
/// for encryption, or [whole report, index] for authentication only. Keep the
/// two modes in the same SSRC/index space. A 12-byte RTP header is not SRTCP.
fn srtcp_index(aads: &[&[u8]]) -> Result<Option<(u32, u32)>, CryptoError> {
    let [head, tail] = aads else {
        return Ok(None);
    };
    let (header, index) = if head.len() == SRTCP_AAD_LEN
        && tail.is_empty()
        && head[SRTCP_HEADER_LEN] & SRTCP_ENCRYPTED_BYTE_FLAG != 0
    {
        (&head[..SRTCP_HEADER_LEN], &head[SRTCP_HEADER_LEN..])
    } else if head.len() >= SRTCP_HEADER_LEN
        && tail.len() == SRTCP_INDEX_LEN
        && tail[0] & SRTCP_ENCRYPTED_BYTE_FLAG == 0
    {
        (&head[..SRTCP_HEADER_LEN], *tail)
    } else {
        return Err(refused(SRTCP_LAYOUT_REFUSED));
    };
    let ssrc = u32::from_be_bytes(
        header[SSRC_FIELD]
            .try_into()
            .map_err(|_| refused(SRTCP_LAYOUT_REFUSED))?,
    );
    let index = u32::from_be_bytes([index[0], index[1], index[2], index[3]]) & SRTCP_INDEX_MASK;
    Ok(Some((ssrc, index)))
}

impl fmt::Debug for Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl Gcm {
    fn new(alg: &'static ring::aead::Algorithm, key: &[u8]) -> Option<Self> {
        if key.len() != alg.key_len() {
            return None;
        }
        AesGcm::new(key).ok().map(|key| Gcm {
            key,
            srtcp: HashMap::new(),
            last_sent_srtcp: None,
        })
    }

    fn accept_srtcp(&mut self, ssrc: u32, index: u32) -> bool {
        if let Some(window) = self.srtcp.get_mut(&ssrc) {
            return window.accept(index);
        }

        if self.srtcp.len() >= SRTCP_SOURCE_LIMIT {
            return false;
        }
        self.srtcp.insert(
            ssrc,
            ReplayWindow {
                highest: index,
                seen: 1,
            },
        );
        true
    }

    /// `output = ciphertext(input) || tag`, `output.len() >= input.len() + 16`.
    fn seal(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        #[cfg(test)]
        sender_tests::before_seal(self, iv, aad, input);
        let Some(needed) = input.len().checked_add(GCM_TAG_LEN) else {
            return Err(refused("SRTP seal: output too short"));
        };
        if output.len() < needed {
            return Err(refused("SRTP seal: output too short"));
        }

        if aad.len() == SRTCP_AAD_LEN
            && aad[0] & RTP_VERSION_MASK == RTP_VERSION_2
            && (RTCP_PACKET_TYPE_MIN..=RTCP_PACKET_TYPE_MAX).contains(&aad[1])
            && aad[SRTCP_HEADER_LEN] & SRTCP_ENCRYPTED_BYTE_FLAG != 0
        {
            let index = u32::from_be_bytes(
                aad[SRTCP_HEADER_LEN..]
                    .try_into()
                    .map_err(|_| refused(SRTCP_LAYOUT_REFUSED))?,
            ) & SRTCP_INDEX_MASK;
            if self.last_sent_srtcp.is_some_and(|last| index <= last) {
                output.zeroize();
                return Err(refused(SRTCP_SENDER_EXHAUSTED));
            }

            self.last_sent_srtcp = Some(index);
        }
        self.key
            .seal(iv, aad, input, &mut output[..needed])
            .map_err(|_| refused("SRTP seal failed"))?;
        Ok(())
    }

    /// `input = ciphertext || tag`; the plaintext into `output`, its length answered. Opened in
    /// place in `output` with the AAD gathered on the stack: no allocation per packet.
    fn open(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let Some(n) = input.len().checked_sub(GCM_TAG_LEN) else {
            return Err(refused("SRTP open: shorter than its tag"));
        };
        if output.len() < n {
            return Err(refused("SRTP open: output too short"));
        }
        let mut gathered = [0_u8; AAD_ON_STACK];
        let total: usize = aads.iter().map(|a| a.len()).sum();
        let spilled: Vec<u8>;
        let aad: &[u8] = match aads {
            [one] => one,
            _ if total <= AAD_ON_STACK => {
                let mut at = 0;
                for a in aads {
                    gathered[at..at + a.len()].copy_from_slice(a);
                    at += a.len();
                }
                &gathered[..total]
            }
            _ => {
                spilled = aads.concat();
                &spilled
            }
        };
        let out = &mut output[..n];
        if self.key.open(iv, aad, input, out).is_err() {
            out.zeroize();
            return Err(refused("SRTP authentication failed"));
        }

        match srtcp_index(aads) {
            Ok(Some((ssrc, index))) if !self.accept_srtcp(ssrc, index) => {
                out.zeroize();
                return Err(refused(SRTCP_REPLAY_REFUSED));
            }
            Err(error) => {
                out.zeroize();
                return Err(error);
            }
            _ => {}
        }
        Ok(n)
    }
}

impl AeadAes128GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

impl AeadAes256GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

/// A key ring refused (it cannot happen for a key of the profile's length): every packet fails.
#[derive(Debug)]
struct Unkeyed;

impl AeadAes128GcmCipher for Unkeyed {
    fn encrypt(
        &mut self,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(refused("SRTP key refused"))
    }

    fn decrypt(
        &mut self,
        _: &[u8; 12],
        _: &[&[u8]],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(refused("SRTP key refused"))
    }
}

impl AeadAes256GcmCipher for Unkeyed {
    fn encrypt(
        &mut self,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(refused("SRTP key refused"))
    }

    fn decrypt(
        &mut self,
        _: &[u8; 12],
        _: &[&[u8]],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(refused("SRTP key refused"))
    }
}

impl SupportedAeadAes128Gcm for Ring {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let key = Zeroizing::new(key);
        match Gcm::new(&AES_128_GCM, key.as_slice()) {
            Some(c) => Box::new(c),
            None => Box::new(Unkeyed),
        }
    }
}

impl SupportedAeadAes256Gcm for Ring {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let key = Zeroizing::new(key);
        match Gcm::new(&AES_256_GCM, key.as_slice()) {
            Some(c) => Box::new(c),
            None => Box::new(Unkeyed),
        }
    }
}

impl Sha1HmacProvider for Ring {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let mut ctx = ring::hmac::Context::with_key(&key);
        for p in payloads {
            ctx.update(p);
        }
        let mut out = [0_u8; 20];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }
}

impl Sha256Provider for Ring {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
        out
    }
}

/// Random bytes from the OS, through ring.
#[must_use]
pub fn random<const N: usize>() -> Option<[u8; N]> {
    use ring::rand::SecureRandom as _;
    let mut out = [0_u8; N];
    ring::rand::SystemRandom::new().fill(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/srtcp_sender_tests.rs"]
pub(crate) mod sender_tests;
