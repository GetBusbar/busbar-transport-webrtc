// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (OWNER 2026-10-03: plugins test
//! themselves against busbar; ARCHITECT 2026-10-14: one contract, one suite, no exemption for a
//! datagram framer). busbar's suite, at the commit this repo pins (`.busbar-ref`), drives the
//! `webrtc` framer two ways through the one loader: LINKED (the logic crate's `door`) and
//! DROPPED IN (this crate's built cdylib), over the transport kind's DATAGRAM script (the framer's
//! tail states `FRAMING_DATAGRAM`) with the inputs in `conformance.json`: `locate` and `encode`
//! failed, a dialled `begin` offering one text piece that is a session description, and a
//! rendezvous that is no description failing the framing. Every step's crossings exactly at the
//! script's pin, the two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under
//! `--release`. The framer's own both-ways drive is `tests/datagram_witness.rs`.

use busbar_plugin_loader::dispatch::LoadedDoor;

/// This plugin's own door, named for the loader.
fn loaded_door() -> LoadedDoor {
    // SAFETY: `busbar_transport_webrtc::door` is this crate's own door: it answers the `'static`
    // door of this plugin.
    #[allow(unused_unsafe)]
    let loaded = unsafe { LoadedDoor::from_raw(busbar_transport_webrtc::door) };
    loaded
}

busbar_plugin_loader::conformance_suite! {
    loaded: loaded_door(),
    cdylib: "busbar_transport_webrtc_plugin",
    inputs: include_str!("conformance.json"),
}
