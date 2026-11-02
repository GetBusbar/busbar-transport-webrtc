// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `webrtc` transport: a datagram framer holding ICE, SRTP and SCTP.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]
#![deny(missing_docs)]

mod claims;
mod door;
mod meta;
mod stun;

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/zeroise_tests.rs"]
mod zeroise_tests;

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
