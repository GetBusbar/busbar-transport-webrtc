//! Tests for `door.rs`: the piece bits the door states for what its framing yields.

use super::*;
use busbar_contract::abi::transport::PIECE_STREAM_FAILED;

fn piece(bytes: &[u8], fields: bool, text: bool, end: bool) -> Piece {
    Piece {
        stream: 1,
        bytes: bytes.to_vec().into(),
        fields,
        text,
        end,
        failed: false,
        writable: false,
    }
}

/// A CLOSED DATA CHANNEL ENDS ITS STREAM BY FLAG (the transport contract: "streams end by flag";
/// an empty piece without `PIECE_END` is an empty message). The end is its own empty piece with
/// `PIECE_END` and `PIECE_END_OF_FRAME`, and never text, a field block, a failure or a continuation,
/// which `check_framer` refuses beside an end.
#[test]
fn a_closed_channel_is_the_streams_end_by_flag_never_an_empty_message() {
    let end = piece(b"", false, false, true);
    let flags = piece_flags(&end, false, true, 0);
    assert_eq!(flags, PIECE_END | PIECE_END_OF_FRAME);
    assert_eq!(
        flags & (PIECE_TEXT | PIECE_FIELDS | PIECE_CONTINUED | PIECE_STREAM_FAILED),
        0
    );
    // An empty binary message is a frame, and it does not end the stream.
    let empty = piece(b"", false, false, false);
    assert_eq!(piece_flags(&empty, false, true, 0), PIECE_END_OF_FRAME);
    // An empty text message is a frame too: not text (it carries no bytes), not the end.
    let empty_text = piece(b"", false, true, false);
    assert_eq!(piece_flags(&empty_text, false, true, 0), PIECE_END_OF_FRAME);
}

/// The other pieces keep the bits they had: a message's text, a field block and its continuation,
/// and the frame's end only on the piece that carries its last byte.
#[test]
fn messages_and_field_blocks_keep_their_bits() {
    let text = piece(b"{\"type\":\"hello\"}", false, true, false);
    assert_eq!(
        piece_flags(&text, false, true, text.bytes.len()),
        PIECE_TEXT | PIECE_END_OF_FRAME
    );
    assert_eq!(piece_flags(&text, false, false, 4), PIECE_TEXT);
    let head = piece(b"label: events\r\n", true, false, false);
    assert_eq!(
        piece_flags(&head, false, true, head.bytes.len()),
        PIECE_FIELDS | PIECE_END_OF_FRAME
    );
    assert_eq!(
        piece_flags(&head, true, true, head.bytes.len()),
        PIECE_FIELDS | PIECE_CONTINUED | PIECE_END_OF_FRAME
    );
}

/// AN EMPTY OUTBOUND MESSAGE IS DELIVERED, as an empty inbound one is (WebRTC data channels carry
/// empty messages, RFC 8831 §6.6): the layer above emits a message with no bytes and the far end's
/// channel yields it as an empty frame, never nothing. RED before the fix: the door dropped it
/// silently, and the media stack sent no chunk for a message of no bytes.
#[test]
fn an_empty_outbound_channel_message_reaches_the_far_end() {
    use crate::framing::tests::{connected, run};

    let (mut dial, mut accept, mut now) = connected();
    let far = accept
        .pieces
        .iter()
        .find(|p| p.fields && p.bytes.starts_with(b"label: "))
        .map(|p| p.stream)
        .expect("the accepting end opened the channel");
    let stand_in = Framing::begin(Side::Accept, b"cert", None, &Opening::default(), now)
        .expect("a stand-in framing");
    let mut h = Held1 {
        f: std::mem::replace(&mut dial.f, stand_in),
        base_ns: 1,
        base: now,
        gathering: HashMap::new(),
        partial: None,
    };
    emit_on(&mut h, 1, b"", true, false, now).expect("the empty message is emitted");
    dial.f = h.f;
    run(&mut dial, &mut accept, &mut now, 500);
    assert!(
        accept.pieces.iter().any(|p| p.stream == far
            && p.bytes.is_empty()
            && !(p.fields || p.end || p.failed || p.writable)),
        "the far end heard the empty message"
    );
}
