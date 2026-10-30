// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN**: one contract, one suite, no exemption
//! for a datagram framer. busbar's suite, at the commit this repo pins (`.busbar-ref`), drives the
//! `webrtc` framer two ways through the one loader: LINKED (the logic crate's `door::door`) and
//! DROPPED IN (this crate's built cdylib), over the transport kind's DATAGRAM script (the framer's
//! tail states `FRAMING_DATAGRAM`) with the inputs in `conformance.json`: `locate` and `encode`
//! failed, a dialled `begin` offering one text piece that is a session description, and a
//! rendezvous that is no description failing the framing. Every step's crossings exactly at the
//! script's pin, the two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under
//! `--release`. The framer's own both-ways drive is `tests/datagram_witness.rs`.

busbar_test_kit::conformance_suite! {
    door: busbar_transport_webrtc::door::door,
    cdylib: "busbar_transport_webrtc_plugin",
    inputs: include_str!("conformance.json"),
}
