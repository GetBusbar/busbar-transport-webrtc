// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `webrtc` transport: a datagram framer holding ICE, SRTP and SCTP.
//!
//! WebRTC mirrors HTTPS layering. The datagram port is the host's (the connector's, no carrier
//! plugin); DTLS runs in the host's secure layer with the host certificate, demultiplexing the port
//! and gating each association on ICE. This framer holds what is left: the ICE agent (it answers and
//! nominates; the host binds only a path it has proven), SRTP (AEAD-AES-GCM only, on ring, with the
//! keying material the host's secure layer exported) and SCTP data channels. It holds no DTLS state
//! ([`shim`]). Opus passes through; no codec runs.
//!
//! ## One entry: the door
//!
//! [`door()`] is the memory-ABI door, the same table compiled in (the `linked` row) and dropped
//! in (the sibling `busbar-transport-webrtc-plugin` cdylib exports it as its image's one symbol,
//! `export_door!`). This crate exports nothing, so linking it adds no door symbol and it holds no
//! `unsafe` at all.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claims;
mod door;
mod meta;
mod stun;

// Public for this repo's allocator-witness tests alone (`tests/zeroise*.rs`, `tests/hot_path_alloc.rs`
// install their own global allocator, so they cannot run as unit tests): no busbar build names them.
pub mod crypto;
pub mod framing;
pub mod shim;

/// The door: the one entry, linked here and exported by the dropped-in build alike.
pub use door::door;

/// The transport axis entry: the row's key, the layers it declares and its door.
pub mod linked {
    pub use crate::door::{door, MACRO_DOOR};
    /// The row's registry key.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this wire declares it can be built over: none (the datagram port is the host's).
    pub const COMPOSES_OVER: &[&str] = crate::meta::COMPOSES_OVER;
    /// Whether this wire carries sessions: yes, an association is one (its claim row's `session`).
    pub const SESSION: bool = crate::meta::SESSION;
}
