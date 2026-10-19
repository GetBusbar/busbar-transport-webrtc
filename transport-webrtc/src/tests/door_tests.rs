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

// ── the binding's auth on a `begin` (ruling 23) ─────────────────────────────────────────────────

use std::cell::RefCell;

use busbar_contract::abi::auth::POINT_FRAME;
use busbar_contract::abi::host::service::FLOW_STOP;
use busbar_contract::abi::mechanism::call::Outcome as Answered;

/// The op's ticket.
const TICKET: Ticket = Ticket {
    slot: 7,
    generation: 1,
};

/// The ref the kernel minted for this framer's binding, at the running generation.
const MINTED: AuthRef = AuthRef {
    id: 41,
    mac: 0x5eed,
};

/// A host's auth handle as the kernel serves it: it verifies the ref FIRST (owner, generation,
/// MAC: here, the one ref it minted) and refuses any other, then answers the binding's auth's
/// flow, or PENDING while that is not ready. Every call is recorded.
struct Kernel {
    flow: Poll<u32>,
    calls: RefCell<Vec<(CompletionHandle, AuthRef)>>,
}

impl Kernel {
    fn answering(flow: Poll<u32>) -> Self {
        Self {
            flow,
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl PeerAuth for Kernel {
    fn peer(&self, handle: CompletionHandle, auth: AuthRef) -> Poll<Result<u32, ServiceError>> {
        self.calls.borrow_mut().push((handle, auth));
        if auth != MINTED {
            return Poll::Ready(Err(ServiceError::Declined(Answered::Refused)));
        }
        self.flow.map(Ok)
    }
}

fn gate(points: u32, auth: AuthRef, host: &Kernel) -> Gate {
    auth_gate(true, points, auth, TICKET, Some(host))
}

/// RED (ruling 23; THE DESIGN §6 item 5): media (ICE, SRTP, SCTP) carries no head, so a binding
/// that declares a head point on this media path is refused, the auth never called and nothing
/// begun. The signalling head is the exchange framer's to sign.
#[test]
fn a_binding_with_head_points_on_the_media_path_is_refused() {
    for points in [
        POINT_HEAD,
        POINT_HEAD_BODY,
        POINT_PEER | POINT_HEAD,
        POINT_PEER | POINT_HEAD_BODY,
    ] {
        let host = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
        assert!(
            matches!(gate(points, MINTED, &host), Gate::Refuse(_)),
            "points {points:#x} refused"
        );
        assert!(host.calls.borrow().is_empty(), "no auth call is made");
    }
}

/// THE PEER POINT (THE DESIGN §6 item 1; `AuthCallIn`'s "THE PEER POINT"): called ONCE per
/// connection, at `begin`, before the association exists, with the binding's own ref on the op's
/// ticket; a continue begins the association.
#[test]
fn the_peer_point_is_called_once_at_begin_with_the_bindings_ref() {
    let host = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
    assert_eq!(gate(POINT_PEER, MINTED, &host), Gate::Go);
    let calls = host.calls.borrow();
    assert_eq!(calls.len(), 1, "once per connection");
    let (handle, auth) = calls[0];
    assert_eq!(auth, MINTED);
    assert_eq!(handle.ticket, TICKET);
    assert_eq!(handle.seq, SEQ_PEER);
}

/// RED: a stale ref (another generation's) or a foreign one (another owner's, or a MAC the kernel
/// did not mint) is refused by the host before any other work, and the dial is refused with it:
/// no association is begun under a ref the kernel does not stand behind.
#[test]
fn a_stale_or_foreign_ref_is_refused() {
    let stale = AuthRef {
        id: MINTED.id,
        mac: MINTED.mac ^ 1,
    };
    let foreign = AuthRef {
        id: 99,
        mac: 0xf0e1,
    };
    for auth in [stale, foreign] {
        let host = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
        assert!(
            matches!(gate(POINT_PEER, auth, &host), Gate::Refuse(_)),
            "{auth:?} refused"
        );
        assert_eq!(host.calls.borrow().len(), 1, "the host judged the ref");
    }
}

/// THE DESIGN §6 item 7: a pending answer parks only its own `begin` (nothing of the association
/// exists yet); the resumed `begin` re-issues the SAME handle and reads the stored answer.
#[test]
fn a_pending_peer_answer_pends_the_begin_and_its_resume_reuses_the_handle() {
    let pending = Kernel::answering(Poll::Pending);
    assert_eq!(gate(POINT_PEER, MINTED, &pending), Gate::Pend);
    let ready = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
    assert_eq!(gate(POINT_PEER, MINTED, &ready), Gate::Go);
    assert_eq!(pending.calls.borrow()[0], ready.calls.borrow()[0]);
}

/// A stop at the peer point refuses the connection: no association, no bytes.
#[test]
fn a_stop_at_the_peer_point_refuses_the_dial() {
    let host = Kernel::answering(Poll::Ready(FLOW_STOP));
    assert!(matches!(gate(POINT_PEER, MINTED, &host), Gate::Refuse(_)));
}

/// A binding with an auth on a host that serves no auth call is refused: an unauthenticated
/// association never begins.
#[test]
fn a_binding_auth_with_no_service_is_refused() {
    assert!(matches!(
        auth_gate(true, POINT_PEER, MINTED, TICKET, None),
        Gate::Refuse(_)
    ));
}

/// A point this framer does not serve (the reserved `Frame`, or an unnamed bit) is refused, the
/// auth never called.
#[test]
fn an_unknown_point_is_refused() {
    for points in [POINT_FRAME, POINT_PEER | POINT_FRAME, 1 << 9] {
        let host = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
        assert!(
            matches!(gate(points, MINTED, &host), Gate::Refuse(_)),
            "points {points:#x} refused"
        );
        assert!(host.calls.borrow().is_empty());
    }
}

/// `BeginIn::auth` is NONE exactly when `points` is `0`, and an accepting side carries neither; a
/// dial with no binding auth begins with no call.
#[test]
fn points_and_ref_agree_or_the_begin_is_refused() {
    let host = Kernel::answering(Poll::Ready(FLOW_CONTINUE));
    assert_eq!(gate(0, AuthRef::NONE, &host), Gate::Go);
    assert!(matches!(gate(0, MINTED, &host), Gate::Refuse(_)));
    assert!(matches!(
        gate(POINT_PEER, AuthRef::NONE, &host),
        Gate::Refuse(_)
    ));
    assert!(matches!(
        auth_gate(false, POINT_PEER, MINTED, TICKET, Some(&host)),
        Gate::Refuse(_)
    ));
    assert_eq!(
        auth_gate(false, 0, AuthRef::NONE, TICKET, Some(&host)),
        Gate::Go
    );
    assert!(
        host.calls.borrow().is_empty(),
        "no call is made for any of them"
    );
}
