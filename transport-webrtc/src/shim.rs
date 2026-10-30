// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host shim: what the media stack sees in place of its own DTLS (DTLS runs in the host's
//! secure layer; the framer holds no DTLS state).
//!
//! It runs no handshake, parses no record and holds no DTLS key. It only RELAYS what the host's
//! secure layer reported through the datagram lane:
//!
//! * the exported keying material (the keying-material item), handed up once, then zeroed;
//! * "connected", once the host verified the far end;
//! * plaintext the secure layer opened (the secured lane), handed up as application data;
//!
//! and takes the application data the media stack wants sealed, for the framer to route on the
//! secured lane, which the host seals. Before the host's "connected", nothing is taken for sealing
//! (the media stack retries: `DtlsImplError::HandshakePending`).
//!
//! The relay runs in-band, through the media stack itself, so nothing outside one association's
//! `Rtc` holds any of it (a plugin holds no process-global state). The stack
//! builds its handshake slot itself ([`Host::new_dtls`], a fresh [`Shim`] per association, owned by
//! that association's stack) and hands that slot every datagram in the RFC 7983 range 20..=63. The
//! framer speaks to its shim with such datagrams of its own ([`keying_frame`], [`CONNECTED_FRAME`],
//! [`opened_frame`]), and drops every far-end datagram in that range before the stack sees it
//! ([`is_relay_range`]); the shim hands what is to be sealed back as one such datagram, which the
//! framer takes off the stack's output ([`sealed`]) and routes on the secured lane.
//!
//! This file is the ONE place the framer names the media stack's DTLS interface (its provider and
//! instance traits, the certificate it is configured with, the profile type of the keying
//! material). The DTLS engine the media stack depends on is linked transitively; its keying type,
//! re-exported by the stack, is the one thing of it this crate names, here (`tests/no_dtls.rs`
//! holds that no engine is named as code or as a dependency).

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use str0m::crypto::dtls::{
    DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider, DtlsVersion, KeyingMaterial,
    ProtocolVersion, SrtpProfile,
};
use str0m::crypto::{CryptoError, CryptoProvider};
use str0m::RtcConfig;
use zeroize::{Zeroize as _, Zeroizing};

use crate::framing::{PROFILE_AEAD_AES_128_GCM, PROFILE_AEAD_AES_256_GCM};

/// The DTLS factory of [`crate::crypto::provider`]: a fresh [`Shim`] for each association the media
/// stack builds, owned by that association's stack; never a DTLS engine. It holds nothing.
#[derive(Debug)]
pub struct Host;

impl DtlsProvider for Host {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        None
    }

    fn new_dtls(
        &self,
        _cert: &DtlsCert,
        _now: Instant,
        _version: DtlsVersion,
        _mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        Ok(Box::new(Shim::default()))
    }
}

/// The media stack's crypto provider: every primitive on `ring` ([`crate::crypto::Ring`]), the
/// DTLS factory the host shim's.
#[must_use]
pub fn provider(ring: &'static crate::crypto::Ring) -> CryptoProvider {
    CryptoProvider {
        srtp_provider: ring,
        sha1_hmac_provider: ring,
        sha256_provider: ring,
        dtls_provider: &Host,
    }
}

/// `config` presenting the host's PUBLIC certificate (its fingerprint is what this end's description
/// states; there is no private key, nothing here signs), with the media stack's own fingerprint
/// check off: the host's secure layer verified the far end's certificate, and the media stack never
/// sees one.
#[must_use]
pub fn present(config: RtcConfig, certificate: &[u8]) -> RtcConfig {
    config
        .set_dtls_cert(DtlsCert {
            certificate: certificate.to_vec(),
            private_key: Vec::new(),
        })
        .set_fingerprint_verification(false)
}

/// Framer to shim: `[KEYING, profile code, material...]`.
const KEYING: u8 = 20;
/// Framer to shim: the host verified the far end and keyed.
const CONNECTED: u8 = 21;
/// Framer to shim: `[OPENED, plaintext...]`, plaintext the host's secure layer opened.
const OPENED: u8 = 22;
/// Shim to framer: `[SEAL, plaintext...]`, application data for the host to seal.
const SEAL: u8 = 23;

/// The keying material's length under each admitted profile (RFC 7714 §12: two master keys and two
/// 12-byte master salts).
const KEYING_LEN_128: usize = 2 * 16 + 2 * 12;
/// `SRTP_AEAD_AES_256_GCM`'s.
const KEYING_LEN_256: usize = 2 * 32 + 2 * 12;

/// The refusal a keying-material item whose length is not its profile's meets.
pub const KEYING_LENGTH_REFUSED: &str =
    "the keying material's length is not its protection profile's";

/// The datagram that tells the shim the host verified the far end and keyed.
pub const CONNECTED_FRAME: [u8; 1] = [CONNECTED];

/// Whether `datagram` lies in the RFC 7983 range the media stack hands its handshake slot. A far
/// end's datagram in it never reaches the stack: the host's secure layer keeps every such record,
/// and that range is the framer's own line to its shim.
#[must_use]
pub fn is_relay_range(datagram: &[u8]) -> bool {
    matches!(datagram.first(), Some(20..=63))
}

/// The refusal keying material under a profile that is neither AEAD-AES-GCM nor AES_CM meets.
pub const PROFILE_REFUSED: &str = "the keying material's protection profile is not AEAD-AES-GCM";

/// THE ONE TABLE of admitted protection profiles: the profile whose registry code is `code`, and
/// its keying material's length, for `material` of that length.
///
/// # Errors
///
/// [`crate::crypto::AES_CM_REFUSED`] for an AES_CM profile, [`PROFILE_REFUSED`] for any other but
/// the two AEAD-AES-GCM ones, [`KEYING_LENGTH_REFUSED`] for material that is not its length.
fn admitted(code: u32, material: &[u8]) -> Result<(SrtpProfile, usize), &'static str> {
    /// `SRTP_AES128_CM_HMAC_SHA1_80` and `_32` (RFC 5764 §4.1.2).
    const AES_CM: [u32; 2] = [0x0001, 0x0002];
    let (profile, len) = match code {
        PROFILE_AEAD_AES_128_GCM => (SrtpProfile::AEAD_AES_128_GCM, KEYING_LEN_128),
        PROFILE_AEAD_AES_256_GCM => (SrtpProfile::AEAD_AES_256_GCM, KEYING_LEN_256),
        c if AES_CM.contains(&c) => return Err(crate::crypto::AES_CM_REFUSED),
        _ => return Err(PROFILE_REFUSED),
    };
    if material.len() != len {
        return Err(KEYING_LENGTH_REFUSED);
    }
    Ok((profile, len))
}

/// The datagram that hands the shim `material`, exported under the protection profile whose
/// registry code is `profile`. AEAD-AES-GCM only, at its profile's length; it is zeroed on drop.
///
/// # Errors
///
/// What [`admitted`] refuses.
pub fn keying_frame(material: &[u8], profile: u32) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (_, len) = admitted(profile, material)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(2 + len));
    frame.push(KEYING);
    frame.push(u8::try_from(profile).unwrap_or_default());
    frame.extend_from_slice(material);
    Ok(frame)
}

/// Whether `frame` is a keying datagram not yet handed to the shim.
#[must_use]
pub fn is_keying(frame: &[u8]) -> bool {
    frame.first() == Some(&KEYING)
}

/// Write into `frame` (a buffer the framer reuses, zeroed between uses) the datagram that hands
/// the shim `plaintext`.
pub fn opened_frame(frame: &mut Zeroizing<Vec<u8>>, plaintext: &[u8]) {
    frame.zeroize();
    frame.push(OPENED);
    frame.extend_from_slice(plaintext);
}

/// The plaintext to seal, when `datagram` (one the media stack transmits) is the shim's; the
/// datagram back otherwise.
///
/// # Errors
///
/// `datagram`, unchanged, when it is not the shim's.
pub fn sealed(mut datagram: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    if datagram.first() == Some(&SEAL) {
        datagram.remove(0);
        Ok(datagram)
    } else {
        Err(datagram)
    }
}

/// The most spent buffers a shim keeps for reuse, each way.
const SPARE: usize = 8;

/// How far ahead the shim's timer lies: it has nothing to time.
const IDLE: Duration = Duration::from_secs(3600);

/// The relay's state. Its `Debug` prints the SRTP keying material and every queued plaintext as
/// `<redacted>` (with lengths and counts only): `Zeroizing`'s own `Debug` prints the bytes.
#[derive(Default)]
pub struct Relay {
    active: Option<bool>,
    keying: Option<(Zeroizing<Vec<u8>>, SrtpProfile)>,
    connected: bool,
    connected_owed: bool,
    opened: VecDeque<Zeroizing<Vec<u8>>>,
    spare_opened: Vec<Zeroizing<Vec<u8>>>,
    to_seal: VecDeque<Zeroizing<Vec<u8>>>,
    spare_seal: Vec<Zeroizing<Vec<u8>>>,
    closed: bool,
    now: Option<Instant>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            active,
            keying,
            connected,
            connected_owed,
            opened,
            spare_opened,
            to_seal,
            spare_seal,
            closed,
            now,
        } = self;
        f.debug_struct("Relay")
            .field("active", active)
            .field(
                "keying",
                &keying
                    .as_ref()
                    .map(|(k, p)| (format!("<redacted {} bytes>", k.len()), p)),
            )
            .field("connected", connected)
            .field("connected_owed", connected_owed)
            .field(
                "opened",
                &format_args!("<redacted {} frames>", opened.len()),
            )
            .field("spare_opened", &spare_opened.len())
            .field(
                "to_seal",
                &format_args!("<redacted {} frames>", to_seal.len()),
            )
            .field("spare_seal", &spare_seal.len())
            .field("closed", closed)
            .field("now", now)
            .finish()
    }
}

/// One association's shim: the media stack's handshake slot, owned by that association's stack.
#[derive(Debug, Default)]
pub struct Shim(Mutex<Relay>);

impl Shim {
    fn lock(&self) -> MutexGuard<'_, Relay> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The host's secure layer exported `material` under the protection profile whose registry code
    /// is `profile`. AEAD-AES-GCM only, at its profile's length: anything else is refused and
    /// nothing of the material is held.
    ///
    /// # Errors
    ///
    /// What [`admitted`] refuses.
    pub fn keyed(&self, material: &[u8], profile: u32) -> Result<(), &'static str> {
        let (profile, _) = admitted(profile, material)?;
        self.lock().keying = Some((Zeroizing::new(material.to_vec()), profile));
        Ok(())
    }

    /// The host verified the far end: the handshake is, for the media stack, connected.
    pub fn connected(&self) {
        let mut r = self.lock();
        if !r.connected {
            r.connected = true;
            r.connected_owed = true;
        }
    }

    /// Plaintext the host's secure layer opened (dropped before "connected").
    pub fn opened(&self, plaintext: &[u8]) {
        let mut r = self.lock();
        if !r.connected {
            return;
        }
        let mut b = r.spare_opened.pop().unwrap_or_default();
        b.extend_from_slice(plaintext);
        r.opened.push_back(b);
    }

    /// Whether material is still held (not yet handed to the media stack).
    #[must_use]
    pub fn holds_keying(&self) -> bool {
        self.lock().keying.is_some()
    }
}

impl DtlsInstance for Shim {
    fn set_active(&mut self, active: bool) {
        self.lock().active = Some(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        // The host's secure layer keeps every record: none reaches the framer, and the framer drops
        // a far end's datagram in this range. What arrives here is the framer's own relay.
        match packet.split_first() {
            Some((&KEYING, rest)) => {
                if let Some((&code, material)) = rest.split_first() {
                    let _ = self.keyed(material, u32::from(code));
                }
            }
            Some((&CONNECTED, _)) => self.connected(),
            Some((&OPENED, plaintext)) => self.opened(plaintext),
            _ => {}
        }
        Ok(())
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        let mut r = self.lock();
        if let Some((material, profile)) = r.keying.take() {
            return DtlsOutput::KeyingMaterial(KeyingMaterial::new(&material), profile);
        }
        if r.connected_owed {
            r.connected_owed = false;
            return DtlsOutput::Connected;
        }
        while let Some(mut data) = r.opened.pop_front() {
            let n = data.len();
            let fits = buf.len() >= n;
            if fits {
                buf[..n].copy_from_slice(&data);
            }
            // A plaintext larger than the stack's record buffer is no message it can read.
            data.zeroize();
            if r.spare_opened.len() < SPARE {
                r.spare_opened.push(data);
            }
            if fits {
                drop(r);
                return DtlsOutput::ApplicationData(&buf[..n]);
            }
        }
        while let Some(mut data) = r.to_seal.pop_front() {
            let n = data.len() + 1;
            let fits = buf.len() >= n;
            if fits {
                buf[0] = SEAL;
                buf[1..n].copy_from_slice(&data);
            }
            // A packet larger than the stack's record buffer is no datagram the port can carry.
            data.zeroize();
            if r.spare_seal.len() < SPARE {
                r.spare_seal.push(data);
            }
            if fits {
                drop(r);
                return DtlsOutput::Packet(&buf[..n]);
            }
        }
        let at = r.now.unwrap_or_else(Instant::now) + IDLE;
        DtlsOutput::Timeout(at)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.lock().now = Some(now);
        Ok(())
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        let mut r = self.lock();
        // A session that is over says so: "pending" would have the stack keep the data and retry.
        if r.closed {
            return Err(DtlsImplError::ConnectionClosed);
        }
        if !r.connected {
            return Err(DtlsImplError::HandshakePending);
        }
        let mut b = r.spare_seal.pop().unwrap_or_default();
        b.extend_from_slice(data);
        r.to_seal.push_back(b);
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.lock().active.unwrap_or(false)
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        None
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.lock().closed = true;
        Ok(())
    }
}
