// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN**: one contract, one suite, no exemption
//! for a datagram framer. busbar's suite, at the commit this repo pins (`.busbar-ref`), drives the
//! `webrtc` framer two ways through the one loader: LINKED (the logic crate's `door::door`) and
//! DROPPED IN (this crate's built cdylib), over the transport kind's DATAGRAM script (the framer's
//! tail states `FRAMING_DATAGRAM`) with the inputs in `conformance.json`: `locate` and `encode`
//! refused (`not_served!`), a dialled `begin` offering one text piece that is a session description, and a
//! rendezvous that is no description failing the framing. Every step's crossings exactly at the
//! script's pin, the two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under
//! `--release`. The framer's own both-ways drive is `tests/datagram_witness.rs`.

busbar_test_kit::conformance_suite! {
    door: busbar_transport_webrtc::door::door,
    cdylib: "busbar_transport_webrtc_plugin",
    inputs: include_str!("conformance.json"),
}

use busbar_plugin_loader::dispatch::LinkedRow;

/// THE STATEMENT CARRIES THE DECLARES DOCUMENT (sibling alignment D11): the plugin's whole
/// `declares.json`, so it is read, as every transport's is. RED before: it was never embedded.
#[test]
fn the_statement_carries_the_declares_document() {
    let row = LinkedRow::of(busbar_transport_webrtc::door::door).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../transport-webrtc/declares.json")[..]),
    );
}

/// THE FRAMER OFFERS NO AUTH POINT (sibling alignment D12, ruling R2): an association has no head
/// and the door makes no auth call, so its Statement states an explicit EMPTY offered-points
/// record, and boot refuses a guest line whose auth needs a point here. RED before: no record,
/// which the host reads as `{Head, HeadBody}`.
#[test]
fn the_statement_offers_no_auth_point() {
    use busbar_contract::abi::mechanism::extensions::get;
    use busbar_contract::abi::transport::check::check_offered_points;
    use busbar_contract::abi::transport::EXT_OFFERED_POINTS;
    let row = LinkedRow::of(busbar_transport_webrtc::door::door).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        get(&read.extensions.bytes, EXT_OFFERED_POINTS),
        Some(&[0_u8; 4][..]),
        "an explicit empty record"
    );
    assert_eq!(
        check_offered_points(&read.extensions.bytes).map(|p| p.0),
        Ok(0)
    );
}
