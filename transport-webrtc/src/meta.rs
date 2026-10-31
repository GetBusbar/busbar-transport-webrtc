// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: the key it answers on and the transport kind's tail
//! its door states. Read once at registration and sealed, so it is data, held apart from the
//! framer code it describes.

use busbar_contract::abi::transport::{
    TransportTail, FACT_ACCEPTS, FACT_DIALS, FRAME_PIECE_SIZE, FRAMING_DATAGRAM, ROLE_FRAMER,
};

/// The claim this entry answers for.
pub const KEY: &str = "webrtc";

/// The layers this framer is built over: none (the datagram port is the host's).
pub(crate) const COMPOSES_OVER: &[&str] = &[];

/// Whether this transport carries sessions: yes, an association is one (its claim row states
/// `session = 1`).
pub(crate) const SESSION: bool = true;

/// The transport kind's tail: a datagram framer, composing over nothing (the port is the host's),
/// whose framings begin accepted or dialled (never detached or adopted).
pub(crate) const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY.with_claim_rows(crate::claims::CLAIMS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_DATAGRAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t.facts = FACT_ACCEPTS | FACT_DIALS;
    t
};
