// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `webrtc` framer, driven through its own table the way the host drives it: the ops it does
//! not serve refused in the role-stub words, its settings, an unknown lease, an op with no open
//! instance, and the op facts its tail states (sibling alignment D16: the kind's door tests, in the
//! logic crate's `tests/door.rs`). (An integration test, so the crate itself stays
//! `#![forbid(unsafe_code)]`: driving a raw table is the host's side, and needs it.) The framer's
//! datagram behaviour is driven through the one loader by the plugin crate's `tests/door_ops.rs`
//! and `tests/datagram_witness.rs`, and by busbar's suite (`tests/conformance.rs` there).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use busbar_contract::abi::mechanism::call::{Blob, InHead, Op, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ReleaseIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail, WriteIn, FACT_ACCEPTS,
    FACT_ADOPTS, FACT_DETACHES, FACT_DIALS,
};
use busbar_transport_webrtc::door;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn text(t: busbar_contract::abi::mechanism::call::AbiStr) -> String {
    // SAFETY: the framer's string, live for the call.
    String::from_utf8(unsafe { t.bytes() }.to_vec()).unwrap()
}

fn ops() -> &'static Ops {
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d: *const Door = unsafe { door() };
    // SAFETY: the door answers a `'static` door whose table is this kind's `Ops`.
    unsafe { &*(*d).ops().cast::<Ops>() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*ih).ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    // SAFETY: the slot is the door's own, called with the `in` and `out` built above.
    #[allow(unused_unsafe)]
    unsafe {
        (op.expect("every slot is filled"))(
            inst,
            std::ptr::from_ref(i).cast(),
            std::ptr::from_mut(o).cast(),
        )
    }
    .outcome()
}

/// The words an `out` (which leads with an `OutHead`) carries.
fn said<O>(o: &O) -> String {
    // SAFETY: `O` leads with an `OutHead`.
    text(unsafe { &*std::ptr::from_ref(o).cast::<OutHead>() }.error)
}

/// An open instance, with empty settings (a framer lends no host table).
fn open() -> *mut c_void {
    let mut i: OpenIn = z();
    let mut o: OpenOut = z();
    let r = call(
        ops().head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    assert_eq!(r, Outcome::Ready, "{}", text(o.head.error));
    o.instance
}

fn tail() -> &'static TransportTail {
    // SAFETY: the door's Statement is this crate's `'static` one, and its kind tail a `'static`
    // `TransportTail`.
    let statement = unsafe { &*(*door()).statement() };
    unsafe { &*statement.kind_tail().cast::<TransportTail>() }
}

/// Call op `$slot` (`$i` in, `$o` out) on `$inst`; its outcome and words.
macro_rules! op {
    ($inst:expr, $field:ident, $slot:expr, $i:ty, $o:ty) => {{
        let mut i: $i = z();
        let mut o: $o = z();
        let r = call(ops().$field, $inst, &mut i, &mut o, $slot);
        (r, said(&o))
    }};
}

#[test]
fn every_op_the_framer_does_not_serve_is_refused_in_the_role_stub_words() {
    let inst = open();
    let refused = |op: &str| {
        (
            Outcome::Refused,
            format!("{op}: the webrtc framer does not serve this op"),
        )
    };
    assert_eq!(
        op!(inst, listen, slot::LISTEN, ListenIn, ListenOut),
        refused("listen")
    );
    assert_eq!(
        op!(inst, accept, slot::ACCEPT, AcceptIn, AcceptOut),
        refused("accept")
    );
    assert_eq!(
        op!(inst, dial, slot::DIAL, DialIn, ConnOut),
        refused("dial")
    );
    assert_eq!(op!(inst, read, slot::READ, ReadIn, IoOut), refused("read"));
    assert_eq!(
        op!(inst, write, slot::WRITE, WriteIn, IoOut),
        refused("write")
    );
    assert_eq!(
        op!(inst, flush, slot::FLUSH, ConnIn, OutHead),
        refused("flush")
    );
    assert_eq!(
        op!(inst, shut, slot::SHUT, ShutIn, OutHead),
        refused("shut")
    );
    assert_eq!(
        op!(inst, arrival, slot::ARRIVAL, ArrivalIn, ArrivalOut),
        refused("arrival")
    );
    assert_eq!(
        op!(inst, locate, slot::LOCATE, LocateIn, LocateOut),
        refused("locate")
    );
    assert_eq!(
        op!(inst, encode, slot::ENCODE, EncodeIn, FramerOut),
        refused("encode")
    );
    assert_eq!(
        op!(inst, refuse, slot::REFUSE, RefuseIn, FramerOut),
        refused("refuse")
    );
    assert_eq!(
        op!(inst, detach, slot::DETACH, FramingIn, FramerOut),
        refused("detach")
    );
    assert_eq!(
        op!(inst, adopt, slot::ADOPT, AdoptIn, FramerOut),
        refused("adopt")
    );
}

fn validate(settings: &'static [u8]) -> (Outcome, String) {
    let mut err = [0_u8; 256];
    let mut i: ValidateIn = z();
    i.settings = Blob::of(settings);
    i.err_buf = err.as_mut_ptr();
    i.err_cap = err.len();
    let mut o: OutHead = z();
    let r = call(
        ops().head.validate,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::VALIDATE,
    );
    (r, text(o.error))
}

fn refresh(inst: *mut c_void, settings: &'static [u8]) -> (Outcome, String) {
    let mut i: RefreshIn = z();
    i.settings = Blob::of(settings);
    let mut o: OutHead = z();
    let r = call(ops().head.refresh, inst, &mut i, &mut o, life::REFRESH);
    (r, text(o.error))
}

#[test]
fn webrtc_declares_no_settings_so_every_key_is_refused_and_a_non_object_fails() {
    assert_eq!(validate(b"").0, Outcome::Ready);
    assert_eq!(validate(b"{}").0, Outcome::Ready);
    assert_eq!(
        validate(b"{\"ice_lite\":true}"),
        (
            Outcome::Failed,
            "settings: ice_lite is not a setting this transport reads".to_owned()
        )
    );
    assert_eq!(
        validate(b"[1]"),
        (
            Outcome::Failed,
            "settings: must be a JSON object".to_owned()
        )
    );
    let inst = open();
    assert_eq!(refresh(inst, b"{}").0, Outcome::Ready);
    assert_eq!(
        refresh(inst, b"{\"x\":1}"),
        (
            Outcome::Failed,
            "settings: x is not a setting this transport reads".to_owned()
        )
    );
}

#[test]
fn releasing_a_lease_never_handed_out_is_refused() {
    let inst = open();
    let mut i: ReleaseIn = z();
    i.lease = 7;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().head.release, inst, &mut i, &mut o, life::RELEASE),
        Outcome::Refused
    );
    assert_eq!(text(o.error), "release: no such lease");
}

#[test]
fn an_op_with_no_open_instance_fails_naming_the_op() {
    let none = std::ptr::null_mut();
    for (r, op) in [
        (op!(none, begin, slot::BEGIN, BeginIn, FramerOut), "begin"),
        (op!(none, emit, slot::EMIT, EmitIn, FramerOut), "emit"),
        (op!(none, timer, slot::TIMER, FramingIn, FramerOut), "timer"),
        (
            op!(none, finish, slot::FINISH, FinishIn, FramerOut),
            "finish",
        ),
    ] {
        assert_eq!(r.0, Outcome::Failed, "{op}");
        assert_eq!(r.1, format!("{op}: no open instance"), "{op}");
    }
    // `ingest` reads its lane before the instance (this `in` lends none): it fails, naming itself.
    let r = op!(none, ingest, slot::INGEST, IngestIn, FramerOut);
    assert_eq!(r.0, Outcome::Failed);
    assert!(r.1.starts_with("ingest: "), "{}", r.1);
}

/// The tail states exactly the ops the door serves (ruling R1: a framer states its ops): `begin`
/// accepted and dialled; never detach or adopt.
#[test]
fn the_tails_op_facts_are_the_ops_the_door_serves() {
    assert_eq!(tail().facts, FACT_ACCEPTS | FACT_DIALS);
    assert_eq!(tail().facts & (FACT_DETACHES | FACT_ADOPTS), 0);
}
