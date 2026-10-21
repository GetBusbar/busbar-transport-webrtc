// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `webrtc` TRANSPORT: a datagram framer holding ICE, SRTP and SCTP (`BUSBAR-1.6.0.md` THE
//! DESIGN §5, "Datagram media", l.756-765).
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
//! [`door`] is the memory-ABI door, the same table compiled in and dropped
//! in (the sibling `busbar-transport-webrtc-plugin` cdylib exports it as its image's one symbol,
//! `export_door!`). This crate exports nothing, so linking it adds no door symbol and it holds no
//! `unsafe` at all.

// Shipped builds forbid `unsafe`; the unit tests carry one allocator (`tests/alloc_counter.rs`).
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]

mod crypto;
mod door;
mod framing;
mod shim;
mod stun;

/// THE DOOR: this plugin's one public item (BUSBAR-1.6.0.md l.3567, Crate shape).
pub use door::door;

#[cfg(test)]
#[path = "tests/alloc_counter.rs"]
mod alloc_counter;

#[cfg(test)]
#[path = "tests/hot_path_alloc_tests.rs"]
mod hot_path_alloc_tests;

#[cfg(test)]
#[path = "tests/zeroise_tests.rs"]
mod zeroise_tests;
