//! Tests for `door.rs`: the piece bits the door states for what its framing yields.

use super::*;
use busbar_contract::abi::transport::PIECE_STREAM_FAILED;

fn piece(bytes: &[u8], fields: bool, text: bool, end: bool) -> Piece {
    Piece {
        stream: 1,
        bytes: bytes.to_vec(),
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
    let flags = piece_flags(&end, false, true);
    assert_eq!(flags, PIECE_END | PIECE_END_OF_FRAME);
    assert_eq!(
        flags & (PIECE_TEXT | PIECE_FIELDS | PIECE_CONTINUED | PIECE_STREAM_FAILED),
        0
    );
    // An empty binary message is a frame, and it does not end the stream.
    let empty = piece(b"", false, false, false);
    assert_eq!(piece_flags(&empty, false, true), PIECE_END_OF_FRAME);
    // An empty text message is a frame too, and text (the contract: PIECE_TEXT rides "an EMPTY text
    // message's one piece too"; codeaudit W2), never the end. RED before the fix: the bit was
    // dropped because the piece carried no bytes, so the host read an empty BINARY message.
    let empty_text = piece(b"", false, true, false);
    assert_eq!(
        piece_flags(&empty_text, false, true),
        PIECE_TEXT | PIECE_END_OF_FRAME
    );
}

/// The framer reads no setting: empty and `{}` are its settings; a key, or a blob that is no JSON
/// object, is refused at validate, open and refresh, in the transport family's words.
#[test]
fn a_setting_the_framer_does_not_read_is_refused() {
    for ok in [&b""[..], b"{}"] {
        assert!(Framings::validate(ok).is_ok());
        let f = Framings::open(ok, &[], 0).expect("opens");
        assert!(f.refresh(ok, &[], 1).is_ok());
    }
    let keyed = br#"{"ice_lite":true}"#;
    let why = "settings: ice_lite is not a setting this transport reads";
    let r = Framings::validate(keyed).expect_err("a key is refused");
    assert_eq!((r.outcome(), r.text()), (Outcome::Failed, Some(why)));
    let r = Framings::open(keyed, &[], 0)
        .err()
        .expect("open refuses a key");
    assert_eq!(r.text(), Some(why));
    let f = Framings::open(b"{}", &[], 0).expect("opens");
    assert_eq!(
        f.refresh(keyed, &[], 1)
            .expect_err("refresh refuses a key")
            .text(),
        Some(why)
    );
    let r = Framings::validate(b"[]").expect_err("not an object");
    assert_eq!(r.text(), Some("settings: must be a JSON object"));
}

/// The other pieces keep the bits they had: a message's text, a field block and its continuation,
/// and the frame's end only on the piece that carries its last byte.
#[test]
fn messages_and_field_blocks_keep_their_bits() {
    let text = piece(b"{\"type\":\"hello\"}", false, true, false);
    assert_eq!(
        piece_flags(&text, false, true),
        PIECE_TEXT | PIECE_END_OF_FRAME
    );
    assert_eq!(piece_flags(&text, false, false), PIECE_TEXT);
    let head = piece(b"label: events\r\n", true, false, false);
    assert_eq!(
        piece_flags(&head, false, true),
        PIECE_FIELDS | PIECE_END_OF_FRAME
    );
    assert_eq!(
        piece_flags(&head, true, true),
        PIECE_FIELDS | PIECE_CONTINUED | PIECE_END_OF_FRAME
    );
}

/// One association's state over a dialling framing that offers channel `events` (stream 1), not
/// yet open: what the host emits on it is held.
fn held1() -> Held1 {
    let now = Instant::now();
    let opening = Opening {
        channels: vec!["events".into()],
        audio: false,
    };
    let local = "198.51.100.1:40000".parse().ok();
    Held1 {
        f: Framing::begin(Side::Dial, b"cert", local, &opening, now).expect("begins"),
        base_ns: 1,
        base: now,
        gathering: HashMap::new(),
        partial: None,
    }
}

/// AN EMPTY MESSAGE THE HOST EMITS IS NEVER DROPPED SILENTLY (codeaudit W3): the door hands it to
/// the framing, whose channel cannot carry it and fails, in words. RED before the fix: the door
/// answered READY and nothing more.
#[test]
fn an_empty_message_from_the_host_reaches_the_framing() {
    let mut h = held1();
    let now = h.base;
    assert_eq!(emit(&mut h, 1, b"", true, true, now), Ok(0));
    assert!(h.f.stream_failed(1), "the empty message was not dropped silently");
}
