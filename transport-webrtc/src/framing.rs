// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE ASSOCIATION'S FRAMING: the media stack (ICE, SRTP, SCTP) over the host's datagram port and
//! secure layer, with no ABI type in it ([`crate::door`] lowers it onto the transport kind's table).
//!
//! # What goes in
//!
//! * the far end's session description ([`Framing::rendezvous`]): the offer on the accepting side,
//!   the answer on the dialling side;
//! * the host's state on every call ([`Framing::host`]): the bound path, the verified bit, the
//!   keying-material item once;
//! * datagrams ([`Framing::datagram`]): clear (a connectivity check, protected media) or secured
//!   (plaintext the host's secure layer opened);
//! * messages to send ([`Framing::emit`]) and the clock ([`Framing::timeout`]).
//!
//! # What comes out
//!
//! * routes ([`Route`]): a check or its answer to the path it concerns; protected media and
//!   secured plaintext to the BOUND path only — the host's choice, never the media stack's;
//! * pieces ([`Piece`]): stream [`DESCRIPTION`] carries this end's own description; each data
//!   channel and each media line is a stream whose first frame is a field block naming it
//!   (`label` for a channel; `kind`, `codec` for media), then one frame per message;
//! * at most one path request: bind the path the far end nominated (or this end did, dialling),
//!   or move to it from the bound one;
//! * the rendezvous terms the host's secure layer runs under.
//!
//! # The guards
//!
//! * AEAD-AES-GCM only: a keying-material item under any other profile fails the framing.
//! * Application data waits for peer verification: until the host's verified bit, a secured
//!   datagram or protected media is dropped unread, and nothing is handed up.
//! * A path the host has not bound receives no media: a nomination the media stack's ICE agent
//!   accepted is only a REQUEST; media follows the host's bound path, which moves only after the
//!   host's own verified round trip.
//! * Keys are zeroised: the keying material this framing holds is cleared once handed on.

use core::net::SocketAddr;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::format::Codec;
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, IceCreds, Input, Output, Rtc};
use zeroize::{Zeroize as _, Zeroizing};

use crate::shim;
use crate::stun::{self, Check};

/// The stream this end's own session description is yielded on.
pub const DESCRIPTION: u64 = 0;
/// The first media stream: media line `n` (in the order it appeared) is `MEDIA_BASE + n`.
pub const MEDIA_BASE: u64 = 1 << 32;

/// The registry codes of the protection profiles this framer admits (RFC 7714 §14.2).
pub const PROFILE_AEAD_AES_128_GCM: u32 = 0x0007;
/// `SRTP_AEAD_AES_256_GCM`.
pub const PROFILE_AEAD_AES_256_GCM: u32 = 0x0008;

/// The most messages held for one channel (not yet open, or with no room in the stack).
const MAX_HELD: usize = 256;
/// The most routes, and the most data pieces, queued for the host at once: past it a route is
/// dropped (a datagram network loses them anyway) and a data piece fails its stream.
const MAX_QUEUED: usize = MAX_HELD * 4;

/// How long ICE may stay "disconnected" before its path counts as failed and the association ends
/// (the media stack has no "failed" state of its own: a disconnected agent may come back as it
/// checks pairs again). Browsers fail a connection after the same 30 seconds without a working
/// pair.
const ICE_FAILED_AFTER: Duration = Duration::from_secs(30);
/// The most nominating checks awaiting their answer.
const MAX_NOMINATING: usize = 64;
/// The most candidates read from the far end's description: the rendezvous terms stay small enough
/// to fit a host's frame buffer whole.
const MAX_CANDIDATES: usize = 32;
/// The largest message a channel carries: the media stack's send buffer (its default), which a
/// larger message could never enter.
pub const MAX_MESSAGE: usize = 128 * 1024;
/// Why an empty message fails its stream: the media stack cannot send one (its SCTP writes no
/// chunk for it, yet spends the ordered stream's next sequence number, wedging the channel; an
/// empty Opus frame is no packet).
const EMPTY_REFUSED: &str = "an empty message, which the media stack cannot send";
/// A channel's held messages at which its stream is FULL (the host emits nothing more on it until
/// its writable piece) ...
const HIGH_WATER: usize = 64;
/// ... and at or below which a full stream is writable again.
const LOW_WATER: usize = 16;

/// Which end of the association this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Answers the far end's offer (ICE-lite).
    Accept,
    /// Offers (full ICE, controlling).
    Dial,
}

/// The lane a datagram travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// As the port carried it.
    Clear,
    /// Plaintext of the host's secure layer.
    Secured,
}

/// One datagram for the host to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// Its path.
    pub path: u32,
    /// Its lane.
    pub lane: Lane,
}

/// One piece for the layer above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// The stream.
    pub stream: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// A field block (a stream's head).
    pub fields: bool,
    /// The message was text.
    pub text: bool,
    /// The stream ENDS here (its data channel closed): the door states it as its own empty piece
    /// with `PIECE_END`. An empty piece without it is an empty message, never the end.
    pub end: bool,
    /// The stream FAILED here, alone; the bytes are the reason (never secret material).
    pub failed: bool,
    /// The stream is WRITABLE again after it was full: an empty piece, alone.
    pub writable: bool,
}

/// A path request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Bind this path.
    Bind(u32),
    /// Move from the first (bound) path to the second.
    Rebind(u32, u32),
}

/// What the host's secure layer runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    /// This end opens the handshake.
    pub initiates: bool,
    /// The user name the far end's checks carry first (ours).
    pub local_user: String,
    /// Our secret.
    pub local_secret: Zeroizing<String>,
    /// The far end's user name.
    pub remote_user: String,
    /// The far end's secret.
    pub remote_secret: Zeroizing<String>,
    /// The far end's certificate fingerprint.
    pub peer_fingerprint: [u8; 32],
    /// The far end's datagram candidates, `ip:port` each.
    pub candidates: Vec<SocketAddr>,
}

/// What a dialling framing offers: its channels' labels and whether it carries audio.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opening {
    /// The data channels, by label, in stream order (stream `1 + i`).
    pub channels: Vec<String>,
    /// One audio line (Opus, sent and received).
    pub audio: bool,
}

/// Why a framing failed. Never secret material.
pub type Failed = String;

/// One association's framing.
pub struct Framing {
    side: Side,
    rtc: Rtc,
    /// The description pair settled: the media stack's handshake slot takes the relay.
    settled: bool,
    /// What the framer owes its shim and could not hand it yet (the description pair is not
    /// settled): keying, then "connected". Zeroed on drop.
    relay: VecDeque<Zeroizing<Vec<u8>>>,
    told_connected: bool,
    /// The buffer an opened plaintext is relayed in, reused (zeroed between uses).
    opened_buf: Zeroizing<Vec<u8>>,
    local: Option<SocketAddr>,
    local_creds: IceCreds,
    /// The far end's check secret: the key its answers to this end's checks are signed under.
    remote_secret: Option<Zeroizing<String>>,
    pending: Option<SdpPendingOffer>,
    described: bool,
    paths: HashMap<u32, SocketAddr>,
    addrs: HashMap<SocketAddr, u32>,
    bound: u32,
    verified: bool,
    keyed: bool,
    ice: IceConnectionState,
    /// Checks that nominate, by transaction id, and the path each travels.
    nominating: HashMap<[u8; 12], u32>,
    asked: Option<Request>,
    request: Option<Request>,
    terms: Option<Terms>,
    routes: VecDeque<Route>,
    pieces: VecDeque<Piece>,
    channels: HashMap<ChannelId, u64>,
    channel_by_stream: HashMap<u64, ChannelId>,
    held: HashMap<u64, VecDeque<(bool, Vec<u8>)>>,
    /// Streams answered FULL and not yet writable again.
    full: HashSet<u64>,
    /// SCTP stream ids (one per data channel) that failed alone.
    failed_sids: HashSet<u64>,
    next_channel: u64,
    medias: HashMap<Mid, u64>,
    media_by_stream: HashMap<u64, Mid>,
    media_clock: HashMap<u64, u64>,
    next_timeout: Option<Instant>,
    /// When ICE went "disconnected" and has not come back; past [`ICE_FAILED_AFTER`] the path has
    /// failed and the association ends.
    disconnected_since: Option<Instant>,
    /// The clock the last call ran at: an event the media stack hands up is stamped with it.
    now: Option<Instant>,
    failed: Option<Failed>,
    ended: bool,
}

impl std::fmt::Debug for Framing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Framing")
            .field("side", &self.side)
            .field("bound", &self.bound)
            .field("verified", &self.verified)
            .field("keyed", &self.keyed)
            .finish_non_exhaustive()
    }
}

impl Drop for Framing {
    /// This framing's own copy of its check secret is cleared with it (the keying material it has
    /// not yet relayed is held zeroising).
    fn drop(&mut self) {
        self.local_creds.pass.zeroize();
    }
}

/// One fingerprint octet: exactly two hex digits (RFC 4572 §5), never one digit or a sign.
fn hex_pair(s: &str) -> Option<u8> {
    if s.len() != 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

/// A description's line values for `prefix` (`a=ice-ufrag:` and the like), in order.
fn values<'a>(description: &'a str, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    description
        .lines()
        .filter_map(move |l| l.trim_end_matches('\r').strip_prefix(prefix))
}

/// The far end's half of the terms: check user, check secret, certificate fingerprint, candidates.
type Remote = (String, Zeroizing<String>, [u8; 32], Vec<SocketAddr>);

/// The terms a description pair settles, read from the far end's description text.
fn read_remote(description: &str) -> Result<Remote, Failed> {
    let user = values(description, "a=ice-ufrag:")
        .next()
        .ok_or("the far end's description has no check user")?
        .trim()
        .to_owned();
    let secret = Zeroizing::new(
        values(description, "a=ice-pwd:")
            .next()
            .ok_or("the far end's description has no check secret")?
            .trim()
            .to_owned(),
    );
    let print = values(description, "a=fingerprint:")
        .find_map(|v| {
            let (alg, hex) = v.trim().split_once(' ')?;
            alg.eq_ignore_ascii_case("sha-256").then_some(hex)
        })
        .ok_or("the far end's description has no sha-256 fingerprint")?;
    let bytes: Vec<u8> = print
        .split(':')
        .map(hex_pair)
        .collect::<Option<_>>()
        .ok_or("a malformed fingerprint")?;
    let fingerprint: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "a fingerprint that is not 32 bytes")?;
    let candidates = values(description, "a=candidate:")
        .filter_map(|v| {
            let f: Vec<&str> = v.split_whitespace().collect();
            let (proto, ip, port) = (f.get(2)?, f.get(4)?, f.get(5)?);
            if !proto.eq_ignore_ascii_case("udp") {
                return None;
            }
            format!("{ip}:{port}")
                .parse::<SocketAddr>()
                .ok()
                .or_else(|| {
                    let ip: core::net::IpAddr = ip.parse().ok()?;
                    Some(SocketAddr::new(ip, port.parse().ok()?))
                })
        })
        .take(MAX_CANDIDATES)
        .collect();
    Ok((user, secret, fingerprint, candidates))
}

/// Whether this end opens the handshake. The media stack takes the role opposite the far end's
/// `a=setup:` (an `actpass` or absent one leaves this end passive), so this end initiates exactly
/// when the far end said `passive`.
fn initiates(description: &str) -> bool {
    values(description, "a=setup:")
        .next()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("passive"))
}

/// A fresh check credential: `n` random bytes as lower-case hex (RFC 8445 §5.3: the user at least
/// 24 bits, the secret at least 128).
fn credential(n: usize) -> Result<String, Failed> {
    let bytes: [u8; 32] = crate::crypto::random().ok_or("the host has no randomness")?;
    Ok(bytes[..n].iter().map(|b| format!("{b:02x}")).collect())
}

/// How many 48 kHz samples an Opus packet spans, from its table-of-contents byte (RFC 6716 §3.1).
/// No codec runs: the frame is passed through, and this is only its length in time.
#[must_use]
pub fn opus_samples(packet: &[u8]) -> u64 {
    let Some(&toc) = packet.first() else {
        return 0;
    };
    let config = toc >> 3;
    // Frame length in units of 2.5 ms (120 samples).
    let unit = match config {
        0..=11 => [4, 8, 16, 24][usize::from(config % 4)],
        12..=15 => [4, 8][usize::from(config % 2)],
        _ => [1, 2, 4, 8][usize::from(config % 4)],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => packet.get(1).map_or(0, |b| u64::from(b & 0x3f)),
    };
    120 * unit * frames
}

impl Framing {
    /// Begin a framing on `side`. `certificate` is the host's public certificate (its fingerprint is
    /// what this end's description states); `opening` is what a dialling end offers.
    ///
    /// # Errors
    ///
    /// No randomness, a host port's address the media stack takes as no candidate, or a dialling
    /// end with nothing to offer.
    pub fn begin(
        side: Side,
        certificate: &[u8],
        local: Option<SocketAddr>,
        opening: &Opening,
        now: Instant,
    ) -> Result<Self, Failed> {
        let local_creds = IceCreds {
            ufrag: credential(4)?,
            pass: credential(16)?,
        };
        let config = Rtc::builder().set_crypto_provider(Arc::new(crate::crypto::provider()));
        let mut config = shim::present(config, certificate)
            .set_local_ice_credentials(local_creds.clone())
            .set_ice_lite(side == Side::Accept)
            .clear_codecs()
            .enable_opus(true, false);
        config = config.set_stats_interval(None);
        let rtc = config.build(now);
        let mut f = Framing {
            side,
            rtc,
            settled: false,
            relay: VecDeque::new(),
            told_connected: false,
            opened_buf: Zeroizing::new(Vec::new()),
            local: None,
            local_creds,
            remote_secret: None,
            pending: None,
            described: false,
            paths: HashMap::new(),
            addrs: HashMap::new(),
            bound: 0,
            verified: false,
            keyed: false,
            ice: IceConnectionState::New,
            nominating: HashMap::new(),
            asked: None,
            request: None,
            terms: None,
            routes: VecDeque::new(),
            pieces: VecDeque::new(),
            channels: HashMap::new(),
            channel_by_stream: HashMap::new(),
            held: HashMap::new(),
            full: HashSet::new(),
            failed_sids: HashSet::new(),
            next_channel: 1,
            medias: HashMap::new(),
            media_by_stream: HashMap::new(),
            media_clock: HashMap::new(),
            next_timeout: None,
            disconnected_since: None,
            now: None,
            failed: None,
            ended: false,
        };
        if let Some(addr) = local {
            f.local(addr)?;
        }
        if side == Side::Dial {
            if opening.channels.is_empty() && !opening.audio {
                return Err("a dialling framing offers nothing".into());
            }
            let mut api = f.rtc.sdp_api();
            let mut mids = Vec::new();
            if opening.audio {
                mids.push(api.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None));
            }
            let mut ids = Vec::new();
            for label in &opening.channels {
                ids.push(api.add_channel(label.clone()));
            }
            let (offer, pending) = api.apply().ok_or("the offer could not be built")?;
            f.pending = Some(pending);
            f.describe(offer.to_sdp_string());
            for (n, mid) in mids.into_iter().enumerate() {
                let s = f.media(mid, n as u64);
                f.head(s, &[("kind", "audio"), ("codec", "opus")]);
            }
            for id in ids {
                f.channel_stream(id);
            }
        }
        Ok(f)
    }

    fn describe(&mut self, description: String) {
        let description = self.with_candidate(description);
        self.described = true;
        self.pieces.push_back(Piece {
            stream: DESCRIPTION,
            bytes: description.into_bytes(),
            fields: false,
            text: true,
            end: false,
            failed: false,
            writable: false,
        });
    }

    /// A description with this end's one host candidate, when the host has told it its port.
    fn with_candidate(&self, description: String) -> String {
        let Some(local) = self.local else {
            return description;
        };
        if description.contains("a=candidate:") {
            return description;
        }
        let line = format!(
            "a=candidate:1 1 udp 2130706431 {} {} typ host\r\n",
            local.ip(),
            local.port()
        );
        let mut out = String::with_capacity(description.len() + line.len() * 2);
        for l in description.split_inclusive('\n') {
            out.push_str(l);
            if l.starts_with("a=ice-pwd:") {
                out.push_str(&line);
            }
        }
        out
    }

    /// The host port's own address: the one candidate this end advertises, once.
    ///
    /// # Errors
    ///
    /// An address the media stack takes as no host candidate (unspecified, multicast and the
    /// like): advertising it would name a candidate its ICE agent never holds.
    pub fn local(&mut self, addr: SocketAddr) -> Result<(), Failed> {
        if self.local.is_some() {
            return Ok(());
        }
        let c = Candidate::host(addr, "udp").map_err(|_| {
            format!("the host port's address {addr} is no candidate the media stack takes")
        })?;
        self.rtc.add_local_candidate(c);
        self.local = Some(addr);
        Ok(())
    }

    /// Paths the host knows.
    pub fn paths(&mut self, paths: impl IntoIterator<Item = (u32, SocketAddr)>) {
        for (path, addr) in paths {
            self.point(path, addr);
        }
    }

    /// Path `path` is at `addr` (path `0` is none): an address it pointed at before, or a path
    /// `addr` belonged to before, is forgotten, so the two maps hold only what is current.
    fn point(&mut self, path: u32, addr: SocketAddr) {
        if path == 0 {
            return;
        }
        if let Some(old) = self.paths.insert(path, addr) {
            if old != addr && self.addrs.get(&old) == Some(&path) {
                self.addrs.remove(&old);
            }
        }
        if let Some(prev) = self.addrs.insert(addr, path) {
            if prev != path && self.paths.get(&prev) == Some(&addr) {
                self.paths.remove(&prev);
            }
        }
    }

    /// The far end's session description.
    ///
    /// # Errors
    ///
    /// A description the media stack refuses, or one with no terms.
    pub fn rendezvous(&mut self, description: &[u8], now: Instant) -> Result<(), Failed> {
        let text =
            std::str::from_utf8(description).map_err(|_| "a description that is not text")?;
        let (remote_user, remote_secret, peer_fingerprint, candidates) = read_remote(text)?;
        match self.side {
            Side::Accept => {
                if self.described {
                    return Err("a second offer on one association".into());
                }
                let offer = SdpOffer::from_sdp_string(text)
                    .map_err(|e| format!("the offer did not parse: {e}"))?;
                let answer = self
                    .rtc
                    .sdp_api()
                    .accept_offer(offer)
                    .map_err(|e| format!("the offer was refused: {e}"))?;
                self.describe(answer.to_sdp_string());
            }
            Side::Dial => {
                let pending = self.pending.take().ok_or("an answer with no offer out")?;
                let answer = SdpAnswer::from_sdp_string(text)
                    .map_err(|e| format!("the answer did not parse: {e}"))?;
                self.rtc
                    .sdp_api()
                    .accept_answer(pending, answer)
                    .map_err(|e| format!("the answer was refused: {e}"))?;
            }
        }
        self.settled = true;
        self.remote_secret = Some(remote_secret.clone());
        self.terms = Some(Terms {
            initiates: initiates(text),
            local_user: self.local_creds.ufrag.clone(),
            local_secret: Zeroizing::new(self.local_creds.pass.clone()),
            remote_user,
            remote_secret,
            peer_fingerprint,
            candidates,
        });
        self.flush_relay(now);
        self.drain(now);
        Ok(())
    }

    /// The host's state at this call: the bound path, the verified bit, and the keying-material item
    /// when it presents one (`(profile, material)`).
    ///
    /// # Errors
    ///
    /// Keying under a profile other than AEAD-AES-GCM, keying before verification, or a second
    /// keying.
    pub fn host(
        &mut self,
        bound: u32,
        verified: bool,
        keying: Option<(u32, &[u8])>,
        now: Instant,
    ) -> Result<(), Failed> {
        if bound != self.bound {
            self.bound = bound;
            if self.asked.is_some_and(|r| target(r) == bound) {
                self.asked = None;
            }
        }
        if verified && !self.verified {
            self.verified = true;
        }
        if let Some((profile, material)) = keying {
            if !self.verified {
                return Err("keying material before the far end was verified".into());
            }
            if self.keyed {
                return Err("keying material twice".into());
            }
            self.relay.push_back(shim::keying_frame(material, profile)?);
            self.keyed = true;
        }
        if self.verified && self.keyed && !self.told_connected {
            self.told_connected = true;
            self.relay
                .push_back(Zeroizing::new(shim::CONNECTED_FRAME.to_vec()));
        }
        self.flush_relay(now);
        self.drain(now);
        Ok(())
    }

    /// Hand the shim what it is owed, once the description pair settled (before that, the media
    /// stack's handshake slot takes nothing).
    fn flush_relay(&mut self, now: Instant) {
        if !self.settled {
            return;
        }
        while let Some(frame) = self.relay.pop_front() {
            self.relay_one(&frame, now);
        }
    }

    /// One datagram of the framer's own to its shim, through the media stack.
    fn relay_one(&mut self, frame: &[u8], now: Instant) {
        if self.failed.is_some() {
            return;
        }
        let at = self
            .local
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let Ok(receive) = Receive::new(Protocol::Udp, at, at, frame) else {
            return;
        };
        if let Err(e) = self.rtc.handle_input(Input::Receive(now, receive)) {
            self.fail(format!("the media stack refused the relay: {e}"));
        }
    }

    /// One datagram from `path` on `lane`.
    pub fn datagram(
        &mut self,
        path: u32,
        from: SocketAddr,
        lane: Lane,
        bytes: &[u8],
        now: Instant,
    ) {
        if self.failed.is_some() || bytes.is_empty() {
            return;
        }
        self.point(path, from);
        match lane {
            Lane::Secured => {
                // Application data waits for peer verification.
                if self.verified && self.keyed && self.settled {
                    let mut b = std::mem::replace(&mut self.opened_buf, Zeroizing::new(Vec::new()));
                    shim::opened_frame(&mut b, bytes);
                    self.relay_one(&b, now);
                    self.opened_buf = b;
                    self.drain(now);
                }
            }
            // The range the media stack hands its handshake slot is the framer's own line to its
            // shim: a far end's datagram in it is never fed (the host's secure layer keeps every
            // record).
            Lane::Clear if shim::is_relay_range(bytes) => {}
            Lane::Clear if stun::is_stun(bytes) => {
                match stun::read(bytes) {
                    Some(Check::Request {
                        txid,
                        nominates: true,
                    }) if self.side == Side::Accept => {
                        self.track(txid, path);
                    }
                    Some(Check::Success { txid })
                        if self.side == Side::Dial && self.nominating.get(&txid) == Some(&path) =>
                    {
                        // The stack's verdict on the answer is not observable: it counts only when
                        // its integrity verifies under the far end's check secret.
                        let genuine = self
                            .remote_secret
                            .as_ref()
                            .is_some_and(|k| stun::integrity_holds(bytes, k.as_bytes()));
                        if genuine {
                            self.nominating.remove(&txid);
                        }
                        self.feed(from, bytes, now);
                        if genuine
                            && matches!(
                                self.ice,
                                IceConnectionState::Connected | IceConnectionState::Completed
                            )
                        {
                            self.nominate(path);
                        }
                        return;
                    }
                    _ => {}
                }
                self.feed(from, bytes, now);
            }
            Lane::Clear => {
                // Protected media: read only once verified and keyed, and only from the bound path.
                if self.verified && self.keyed && path == self.bound && path != 0 {
                    self.feed(from, bytes, now);
                }
            }
        }
    }

    fn feed(&mut self, from: SocketAddr, bytes: &[u8], now: Instant) {
        let Some(local) = self.local else {
            return;
        };
        let Ok(receive) = Receive::new(Protocol::Udp, from, local, bytes) else {
            return;
        };
        if let Err(e) = self.rtc.handle_input(Input::Receive(now, receive)) {
            self.fail(format!("the media stack refused a datagram: {e}"));
            return;
        }
        self.drain(now);
    }

    /// Remember a nominating check, holding the set bounded (a flood of checks evicts the set,
    /// never grows it).
    fn track(&mut self, txid: [u8; 12], path: u32) {
        if self.nominating.len() >= MAX_NOMINATING {
            self.nominating.clear();
        }
        self.nominating.insert(txid, path);
    }

    fn nominate(&mut self, path: u32) {
        let want = if self.bound == 0 {
            Request::Bind(path)
        } else if self.bound != path {
            Request::Rebind(self.bound, path)
        } else {
            return;
        };
        if self.asked != Some(want) {
            self.asked = Some(want);
            self.request = Some(want);
        }
    }

    /// A message for the far end on `stream`.
    ///
    /// # Errors
    ///
    /// A stream this framing does not carry, or a media line that carries no Opus. (What a stream
    /// cannot carry fails that stream alone: its failure piece, never an error.)
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        text: bool,
        now: Instant,
    ) -> Result<(), Failed> {
        if let Some(mid) = self.media_by_stream.get(&stream).copied() {
            if bytes.is_empty() && !self.failed_sids.contains(&stream) {
                self.fail_stream(stream, EMPTY_REFUSED);
                self.drain(now);
                return Ok(());
            }
            if !(self.verified && self.keyed) || self.failed_sids.contains(&stream) {
                return Ok(());
            }
            let clock = self.media_clock.entry(stream).or_insert(0);
            let at = *clock;
            *clock = clock.wrapping_add(opus_samples(bytes));
            let Some(writer) = self.rtc.writer(mid) else {
                return Ok(());
            };
            let pt: Option<Pt> = writer
                .payload_params()
                .find(|p| p.spec().codec == Codec::Opus)
                .map(|p| p.pt());
            let Some(pt) = pt else {
                return Err("the media line carries no Opus".into());
            };
            if let Err(e) = writer.write(
                pt,
                now,
                MediaTime::new(at, Frequency::FORTY_EIGHT_KHZ),
                bytes,
            ) {
                self.fail_stream(stream, &format!("the media frame was refused: {e}"));
            }
            self.drain(now);
            return Ok(());
        }
        let Some(id) = self.channel_by_stream.get(&stream).copied() else {
            return Err(format!("no stream {stream} on this association"));
        };
        if self.failed_sids.contains(&stream) {
            // The host was told; what it still emits there is dropped.
            return Ok(());
        }
        if bytes.is_empty() {
            // The stack writes no chunk for an empty message yet spends the ordered stream's next
            // sequence number: every later message would wait for it forever.
            self.fail_stream(stream, EMPTY_REFUSED);
            self.drain(now);
            return Ok(());
        }
        if bytes.len() > MAX_MESSAGE {
            self.fail_stream(stream, "a message larger than the channel can ever send");
            self.drain(now);
            return Ok(());
        }
        // A message never overtakes one held before it: while any is held, it queues behind.
        let queued = self.held.get(&stream).is_some_and(|q| !q.is_empty());
        let sent = match self.rtc.channel(id) {
            Some(mut ch) if !queued => match ch.write(!text, bytes) {
                Ok(sent) => sent,
                Err(e) => {
                    self.fail_stream(stream, &format!("the channel refused the message: {e}"));
                    self.drain(now);
                    return Ok(());
                }
            },
            _ => false,
        };
        if !sent {
            let held = self.held.entry(stream).or_default();
            if held.len() >= MAX_HELD {
                // A host that kept emitting past the FULL mark: the stream fails, alone.
                self.fail_stream(stream, "too many messages held for the channel");
                self.drain(now);
                return Ok(());
            }
            held.push_back((text, bytes.to_vec()));
            if held.len() >= HIGH_WATER {
                self.full.insert(stream);
            }
        }
        self.drain(now);
        Ok(())
    }

    /// Stream `stream` fails, alone: its held messages are dropped and the layer above gets its
    /// failure piece, once. The association and every other stream carry on.
    pub fn fail_stream(&mut self, stream: u64, why: &str) {
        // A stream this framing no longer carries ended already: nothing of it follows its end.
        if !self.carries(stream) || !self.failed_sids.insert(stream) {
            return;
        }
        self.held.remove(&stream);
        self.full.remove(&stream);
        self.pieces.push_back(Piece {
            stream,
            bytes: why.as_bytes().to_vec(),
            fields: false,
            text: false,
            end: false,
            failed: true,
            writable: false,
        });
    }

    /// Whether this framing carries `stream` (a data channel or a media line).
    #[must_use]
    pub fn carries(&self, stream: u64) -> bool {
        self.channel_by_stream.contains_key(&stream) || self.media_by_stream.contains_key(&stream)
    }

    /// Whether `stream` is FULL: the host emits nothing more on it until its writable piece.
    #[must_use]
    pub fn stream_full(&self, stream: u64) -> bool {
        self.full.contains(&stream)
    }

    /// Whether `stream` failed.
    #[must_use]
    pub fn stream_failed(&self, stream: u64) -> bool {
        self.failed_sids.contains(&stream)
    }

    /// The clock reached `now`.
    pub fn timeout(&mut self, now: Instant) {
        if self.failed.is_some() {
            return;
        }
        if let Err(e) = self.rtc.handle_input(Input::Timeout(now)) {
            self.fail(format!("the media stack failed: {e}"));
            return;
        }
        self.drain(now);
    }

    /// Close the association.
    pub fn finish(&mut self, now: Instant) {
        let _ = self.rtc.close();
        self.drain(now);
        self.ended = true;
    }

    fn fail(&mut self, why: Failed) {
        self.rtc.disconnect();
        self.failed = Some(why);
        self.routes.clear();
    }

    fn channel_stream(&mut self, id: ChannelId) -> u64 {
        if let Some(s) = self.channels.get(&id) {
            return *s;
        }
        let s = self.next_channel;
        self.next_channel += 1;
        self.channels.insert(id, s);
        self.channel_by_stream.insert(s, id);
        s
    }

    fn media(&mut self, mid: Mid, n: u64) -> u64 {
        let s = MEDIA_BASE + n;
        self.medias.insert(mid, s);
        self.media_by_stream.insert(s, mid);
        s
    }

    fn head(&mut self, stream: u64, fields: &[(&str, &str)]) {
        let mut block = Vec::new();
        for (n, v) in fields {
            block.extend_from_slice(n.as_bytes());
            block.extend_from_slice(b": ");
            block.extend_from_slice(v.as_bytes());
            block.extend_from_slice(b"\r\n");
        }
        self.pieces.push_back(Piece {
            stream,
            bytes: block,
            fields: true,
            text: false,
            end: false,
            failed: false,
            writable: false,
        });
    }

    /// Run the media stack until it waits, collecting what it owes.
    fn drain(&mut self, now: Instant) {
        self.now = Some(now);
        // Messages held for channels that have since opened (or that had no room), in order.
        if !self.held.is_empty() {
            let sids: Vec<u64> = self.held.keys().copied().collect();
            for stream in sids {
                self.flush_held(stream);
            }
        }
        for _ in 0..10_000 {
            let out = match self.rtc.poll_output() {
                Ok(o) => o,
                Err(e) => {
                    self.fail(format!("the media stack failed: {e}"));
                    return;
                }
            };
            let waits = match out {
                Output::Timeout(t) => {
                    self.next_timeout = Some(t.max(now));
                    true
                }
                Output::Transmit(t) => {
                    self.transmit(t.destination, t.contents.into());
                    false
                }
                Output::Event(e) => {
                    self.event(e);
                    false
                }
            };
            if waits {
                break;
            }
        }
        if !self.rtc.is_alive() && self.failed.is_none() {
            self.ended = true;
        }
        // A path disconnected past the window has failed; inside it, wake when it would.
        if let Some(since) = self.disconnected_since {
            let fails_at = since + ICE_FAILED_AFTER;
            if now >= fails_at {
                self.ended = true;
            } else {
                self.next_timeout = Some(self.next_timeout.map_or(fails_at, |t| t.min(fails_at)));
            }
        }
    }

    /// A held queue's messages, in order, while the media stack takes them. A full stream drained
    /// to its low-water mark is writable again; a write the stack refuses fails the stream alone.
    fn flush_held(&mut self, stream: u64) {
        let Some(id) = self.channel_by_stream.get(&stream).copied() else {
            return;
        };
        let mut refused = None;
        while let Some((text, bytes)) = self.held.get_mut(&stream).and_then(VecDeque::pop_front) {
            let sent = match self.rtc.channel(id) {
                Some(mut ch) => match ch.write(!text, &bytes) {
                    Ok(sent) => sent,
                    Err(e) => {
                        refused = Some(format!("the channel refused the message: {e}"));
                        break;
                    }
                },
                None => false,
            };
            if !sent {
                if let Some(q) = self.held.get_mut(&stream) {
                    q.push_front((text, bytes));
                }
                break;
            }
        }
        if let Some(why) = refused {
            self.fail_stream(stream, &why);
            return;
        }
        let left = self.held.get(&stream).map_or(0, VecDeque::len);
        if left == 0 {
            self.held.remove(&stream);
        }
        if left <= LOW_WATER && self.full.remove(&stream) {
            self.pieces.push_back(Piece {
                stream,
                bytes: Vec::new(),
                fields: false,
                text: false,
                end: false,
                failed: false,
                writable: true,
            });
        }
    }

    fn transmit(&mut self, to: SocketAddr, bytes: Vec<u8>) {
        if self.routes.len() >= MAX_QUEUED {
            return;
        }
        if stun::is_stun(&bytes) {
            let Some(path) = self.addrs.get(&to).copied() else {
                // An address the host never judged or heard: nothing goes there.
                return;
            };
            match stun::read(&bytes) {
                Some(Check::Success { txid })
                    if self.side == Side::Accept && self.nominating.remove(&txid) == Some(path) =>
                {
                    self.nominate(path);
                }
                Some(Check::Request {
                    txid,
                    nominates: true,
                }) if self.side == Side::Dial => {
                    self.track(txid, path);
                }
                _ => {}
            }
            self.routes.push_back(Route {
                bytes,
                path,
                lane: Lane::Clear,
            });
            return;
        }
        match shim::sealed(bytes) {
            // What the media stack handed its shim to seal (an SCTP packet): the host seals it, to
            // the bound path.
            Ok(plain) => {
                if self.bound != 0 {
                    self.routes.push_back(Route {
                        bytes: plain,
                        path: self.bound,
                        lane: Lane::Secured,
                    });
                }
            }
            // Protected media goes to the host's bound path, whatever the stack chose.
            Err(bytes) => {
                if self.bound != 0 && self.verified && self.keyed {
                    self.routes.push_back(Route {
                        bytes,
                        path: self.bound,
                        lane: Lane::Clear,
                    });
                }
            }
        }
    }

    fn event(&mut self, e: Event) {
        match e {
            Event::IceConnectionStateChange(s) => {
                self.ice = s;
                // "Disconnected" may come back as the agent checks pairs again (a network switch
                // slower than the pair timeout): it holds the association, and only a path gone
                // past ICE_FAILED_AFTER ends it (`drain`).
                if s == IceConnectionState::Disconnected {
                    if self.disconnected_since.is_none() {
                        self.disconnected_since = self.now;
                    }
                } else {
                    self.disconnected_since = None;
                }
            }
            Event::ChannelOpen(id, label) => {
                let s = self.channel_stream(id);
                // A field value never holds CR or LF: a label with a line break (any UTF-8 is a
                // label on the wire) would forge field lines, so that channel is refused.
                if label.contains(['\r', '\n']) {
                    self.fail_stream(s, "the far end's channel label holds a line break");
                    return;
                }
                self.head(s, &[("label", &label)]);
            }
            Event::ChannelData(d) => {
                // Application data waits for peer verification (the shim hands none up before it,
                // so this is the second lock on the same door).
                if !(self.verified && self.keyed) {
                    return;
                }
                // A channel that closed (or never opened) carries nothing up.
                let Some(s) = self.channels.get(&d.id).copied() else {
                    return;
                };
                if self.failed_sids.contains(&s) {
                    return;
                }
                // The reliable channel already acknowledged this message to the peer: dropping it
                // loses it unseen, so the stream that cannot take it fails, loudly, alone.
                if self.pieces.len() >= MAX_QUEUED {
                    self.fail_stream(
                        s,
                        "the data channel's messages outran the host: its queue reached the cap",
                    );
                    return;
                }
                self.pieces.push_back(Piece {
                    stream: s,
                    bytes: d.data,
                    fields: false,
                    text: !d.binary,
                    end: false,
                    failed: false,
                    writable: false,
                });
            }
            Event::ChannelClose(id) => {
                // The stream ends: the framing carries it no more, so a later emit there is refused
                // and nothing of it follows its end.
                if let Some(s) = self.channels.remove(&id) {
                    self.channel_by_stream.remove(&s);
                    self.held.remove(&s);
                    self.full.remove(&s);
                    if self.failed_sids.remove(&s) {
                        // A failed stream already ended, failed.
                        return;
                    }
                    self.pieces.push_back(Piece {
                        stream: s,
                        bytes: Vec::new(),
                        fields: false,
                        text: false,
                        end: true,
                        failed: false,
                        writable: false,
                    });
                }
            }
            Event::MediaAdded(m)
                if m.kind == MediaKind::Audio && !self.medias.contains_key(&m.mid) =>
            {
                let n = self.medias.len() as u64;
                let s = self.media(m.mid, n);
                self.head(s, &[("kind", "audio"), ("codec", "opus")]);
            }
            Event::MediaData(d) => {
                if !(self.verified && self.keyed) || self.pieces.len() >= MAX_QUEUED {
                    return;
                }
                if let Some(s) = self
                    .medias
                    .get(&d.mid)
                    .copied()
                    .filter(|s| !self.failed_sids.contains(s))
                {
                    self.pieces.push_back(Piece {
                        stream: s,
                        bytes: d.data.to_vec(),
                        fields: false,
                        text: false,
                        end: false,
                        failed: false,
                        writable: false,
                    });
                }
            }
            Event::Closed => self.ended = true,
            _ => {}
        }
    }

    /// The next route.
    pub fn next_route(&mut self) -> Option<Route> {
        self.routes.pop_front()
    }

    /// Put a route back at the front (the host's buffer was full).
    pub fn unroute(&mut self, r: Route) {
        self.routes.push_front(r);
    }

    /// The next piece.
    pub fn next_piece(&mut self) -> Option<Piece> {
        self.pieces.pop_front()
    }

    /// Whether anything is still owed.
    #[must_use]
    pub fn owes(&self) -> bool {
        !self.routes.is_empty() || !self.pieces.is_empty() || self.terms.is_some()
    }

    /// The path request, taken.
    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The rendezvous terms, taken.
    pub fn take_terms(&mut self) -> Option<Terms> {
        self.terms.take()
    }

    /// Put the terms back (the host's frame buffer could not hold them whole).
    pub fn restore_terms(&mut self, t: Terms) {
        self.terms = Some(t);
    }

    /// When [`Self::timeout`] is next owed.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        self.next_timeout
    }

    /// Why the framing failed.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Whether the association ended.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// The messages held for `stream`, `(text, bytes)` each, in order: what a test reads of the
    /// queue.
    #[cfg(test)]
    pub(crate) fn held(&self, stream: u64) -> Vec<(bool, Vec<u8>)> {
        self.held
            .get(&stream)
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether keying material is held un-handed (it is cleared once relayed to the stack).
    #[must_use]
    pub fn holds_keying(&self) -> bool {
        self.relay.iter().any(|f| shim::is_keying(f))
    }
}

fn target(r: Request) -> u32 {
    match r {
        Request::Bind(p) | Request::Rebind(_, p) => p,
    }
}

#[cfg(test)]
#[path = "tests/framing_tests.rs"]
mod tests;
