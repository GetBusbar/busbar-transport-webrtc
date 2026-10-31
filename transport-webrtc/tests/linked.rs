// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `linked` entry the composition root folds, tied to what the door's Statement declares
//! (sibling alignment D14): its key, layers and session are the Statement's own facts.

use busbar_contract::abi::transport::{TransportTail, UNIT0_FIRST_DATAGRAM};
use busbar_transport_webrtc::{door, linked};

#[test]
fn the_linked_entry_states_the_framers_key_layers_and_session() {
    assert_eq!(linked::KEY, "webrtc");
    assert!(linked::COMPOSES_OVER.is_empty());
    let session = linked::SESSION;
    assert!(session);
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d = unsafe { (linked::door)() };
    assert!(!d.ops().is_null());
}

#[test]
fn linked_session_is_the_claim_rows_session() {
    // SAFETY: the door's Statement is this crate's `'static` one, and its kind tail a `'static`
    // `TransportTail` whose claim rows are `'static`.
    let (statement, tail) = unsafe {
        let st = &*(*door()).statement();
        (st, &*st.kind_tail().cast::<TransportTail>())
    };
    // SAFETY: the tail's claim rows, `claim_rows_len` of them.
    let rows = unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    assert_eq!(statement.claims_len, 1);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.session != 0, linked::SESSION);
    assert_eq!(row.session_bound, 1);
    assert_eq!(row.unit0_trigger, UNIT0_FIRST_DATAGRAM);
    // SAFETY: the row's strings are `'static`.
    assert!(unsafe { row.selector_forms.bytes() }.is_empty());
    assert!(unsafe { row.egress_selector_forms.bytes() }.is_empty());
}
