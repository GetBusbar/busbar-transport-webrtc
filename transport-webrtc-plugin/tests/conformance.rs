// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN**: one contract, one suite, no exemption

busbar_test_kit::conformance_suite! {
    door: busbar_transport_webrtc::door,
    cdylib: "busbar_transport_webrtc_plugin",
    inputs: include_str!("conformance.json"),
}

use busbar_plugin_loader::dispatch::LinkedRow;

/// THE STATEMENT CARRIES THE DECLARES DOCUMENT (sibling alignment D11): the plugin's whole

#[test]
fn the_statement_carries_the_declares_document() {
    let row = LinkedRow::of(busbar_transport_webrtc::door).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../transport-webrtc/declares.json")[..]),
    );
}

/// The WebRTC framer offers no authentication point.

#[test]
fn the_statement_offers_no_auth_point() {
    use busbar_contract::abi::mechanism::extensions::get;
    use busbar_contract::abi::transport::check::check_offered_points;
    use busbar_contract::abi::transport::EXT_OFFERED_POINTS;
    let row = LinkedRow::of(busbar_transport_webrtc::door).unwrap();
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
