// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claims this transport declares: the scheme it answers for and the row over it. A
//! declaration and nothing else, read once at registration.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::transport::{Claim, UNIT0_FIRST_DATAGRAM};

/// The schemes `webrtc` claims, by name: the Statement's `claims`, the one place they are stated.
pub(crate) const CLAIM_NAMES: &[AbiStr] = &[abi_str(crate::meta::KEY)];

/// The claim's row: no selector forms (an association is reached through the rendezvous, never
/// selected on its datagrams), a session whose first unit opens on its first datagram.
pub(crate) const CLAIMS: &[Claim] = &[{
    let mut c = Claim::EMPTY;
    c.selector_forms = abi_str("");
    c.egress_selector_forms = abi_str("");
    c.session = 1;
    c.session_bound = 1;
    c.unit0_trigger = UNIT0_FIRST_DATAGRAM;
    c
}];
