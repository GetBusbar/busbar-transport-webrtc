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

    let empty = piece(b"", false, false, false);
    assert_eq!(piece_flags(&empty, false, true), PIECE_END_OF_FRAME);

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

/// An empty message emitted by the host reaches the framing.
#[test]
fn an_empty_message_from_the_host_reaches_the_framing() {
    let mut h = held1();
    let now = h.base;
    assert_eq!(emit(&mut h, 1, b"", true, true, now), Ok(0));
    assert!(
        h.f.stream_failed(1),
        "the empty message was not dropped silently"
    );
}

/// EMIT_TEXT IS READ ON THE CALL THAT COMPLETES THE FRAME (the contract's `EmitIn::flags`;
/// codeaudit door.rs:651): an earlier piece's flag says nothing. RED before the fix: the bit was
/// OR-ed across every piece, so a message the completing call called binary went as text.
#[test]
fn the_text_bit_is_the_completing_calls() {
    let mut h = held1();
    let now = h.base;
    assert_eq!(emit(&mut h, 1, b"ab", false, true, now), Ok(0));
    assert_eq!(emit(&mut h, 1, b"cd", true, false, now), Ok(0));
    assert_eq!(emit(&mut h, 1, b"ef", false, false, now), Ok(0));
    assert_eq!(emit(&mut h, 1, b"gh", true, true, now), Ok(0));
    assert_eq!(
        h.f.held(1),
        [(false, b"abcd".to_vec()), (true, b"efgh".to_vec())],
        "each message is what its completing call said"
    );
}

/// Messages are gathered only for streams able to receive them.
#[test]
fn nothing_is_gathered_for_a_stream_that_cannot_take_it() {
    let mut h = held1();
    let now = h.base;
    assert_eq!(
        emit(&mut h, 99, b"part", false, false, now),
        Err("no stream 99 on this association".to_string())
    );
    assert!(h.gathering.is_empty(), "nothing gathered for stream 99");

    assert_eq!(emit(&mut h, 1, b"part", false, false, now), Ok(0));
    h.f.fail_stream(1, "the channel refused the message");
    assert_eq!(emit(&mut h, 1, b"more", false, false, now), Ok(0));
    assert!(
        h.gathering.is_empty(),
        "a failed stream's gathered bytes are let go"
    );
}

/// A poisoned association is refused rather than served with partial state.
#[test]
fn a_poisoned_association_is_never_served_torn() {
    let slot: Slot = Arc::new(Mutex::new(Some(held1())));
    let torn = Arc::clone(&slot);
    let unwound = std::thread::spawn(move || {
        let _held = torn.lock().expect("unpoisoned");
        panic!("an op unwound mid-way");
    })
    .join();
    assert!(unwound.is_err() && slot.is_poisoned());
    {
        let (held, torn) = hold_torn(&slot);
        assert!(held.is_none(), "the torn state is not served");
        assert!(
            torn,
            "the caller is told the state was torn, so it forgets the token"
        );
    }
    assert!(
        !slot.is_poisoned(),
        "the poison is cleared once the state is forgotten"
    );
    let (held, torn) = hold_torn(&slot);
    assert!(
        held.is_none() && !torn,
        "a forgotten association is gone, not torn again"
    );
}

/// Failure and writable pieces retain their respective flags.
#[test]
fn a_failure_and_a_writable_piece_keep_their_bits() {
    let mut failed = piece(b"the channel refused the message", false, false, false);
    failed.failed = true;
    assert_eq!(
        piece_flags(&failed, false, true),
        PIECE_STREAM_FAILED | PIECE_END_OF_FRAME
    );
    let mut writable = piece(b"", false, false, false);
    writable.writable = true;
    assert_eq!(piece_flags(&writable, false, true), PIECE_WRITABLE);
}

/// A gathered message beyond the channel cap fails its stream and releases its buffer.
#[test]
fn a_message_gathered_past_the_cap_fails_its_stream_and_is_let_go() {
    let mut h = held1();
    let now = h.base;
    let half = vec![1_u8; MAX_MESSAGE / 2 + 1];
    assert_eq!(emit(&mut h, 1, &half, false, false, now), Ok(0));
    assert_eq!(emit(&mut h, 1, &half, false, false, now), Ok(0));
    assert!(h.f.stream_failed(1), "past the cap, the stream fails");
    assert!(h.gathering.is_empty(), "and nothing of it is kept");
}

/// A message gathered to exactly the channel cap is sent whole: the cap is inclusive.
#[test]
fn a_message_gathered_to_exactly_the_cap_is_sent() {
    let mut h = held1();
    let now = h.base;
    let half = vec![1_u8; MAX_MESSAGE / 2];
    assert_eq!(emit(&mut h, 1, &half, false, false, now), Ok(0));
    assert_eq!(emit(&mut h, 1, &half, true, false, now), Ok(0));
    assert!(
        !h.f.stream_failed(1),
        "a message of exactly the cap is not refused"
    );
    assert!(
        h.gathering.is_empty(),
        "the completed message left the gathering"
    );
}

/// The tail states exactly the operations this door serves.
#[test]
fn the_tail_states_the_ops_the_door_serves() {
    use busbar_contract::abi::transport::{FACT_ACCEPTS, FACT_DIALS};
    assert_eq!(TAIL.facts, FACT_ACCEPTS | FACT_DIALS);
}
