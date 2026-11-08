// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`webrtc` transport as a droppable busbar plugin**: the `cdylib` a signed tarball of the
//! framer carries (`kind: transport`, key `webrtc`). The logic crate is re-exported whole, and its
//! door (`busbar_transport_webrtc::door`) is exported as this image's ONE symbol,
//! `busbar_plugin_door` (`export_door!`), so the library carries exactly the door
//! a busbar build links.

#![deny(unsafe_code)]

pub use busbar_transport_webrtc::{door, linked, MACRO_DOOR};

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_transport_webrtc::door);
}
