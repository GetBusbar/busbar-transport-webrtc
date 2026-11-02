// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! WebRTC lifecycle and admission through the real linked and dropped doors.
use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, RefreshIn, TickIn, TickOut};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn, IoOut,
    ListenIn, ListenOut, ReadIn, ShutIn, WriteIn,
};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, Called, Dispatcher, Frame, InFrame,
    LinkedRow, OutFrame, Plugin,
};
use std::sync::atomic::Ordering;
#[path = "support/abi.rs"]
pub mod abi;
#[path = "support/negative.rs"]
mod negative;
fn row() -> LinkedRow {
    LinkedRow::of(busbar_transport_webrtc::linked::door).expect("actual WebRTC statement")
}
fn cdylib() -> std::path::PathBuf {
    abi::cdylib()
}
fn bind(d: &Dispatcher) -> Bind {
    abi::bind(d, "webrtc-lifecycle")
}
fn open(p: &Plugin<Transport>) -> Called {
    let answer = abi::open(p);
    assert_eq!(answer.outcome, Outcome::Ready);
    answer
}
fn counts(p: &Plugin<Transport>) -> (u64, u64) {
    let resumed = p.inner.resumes.load(Ordering::SeqCst);
    (p.inner.crossings.load(Ordering::SeqCst) - resumed, resumed)
}
fn call<I: InFrame, O: OutFrame>(
    p: &Plugin<Transport>,
    slot: u32,
    input: I,
    expected: u64,
) -> (Called, O) {
    let before = counts(p);
    let mut frame = Frame::new(input, abi::output::<O>());
    let answer = p.call(slot, &mut frame);
    let after = counts(p);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (expected, 0),
        "slot {slot}"
    );
    (answer, frame.out)
}
fn lifecycle(p: &Plugin<Transport>, d: &Dispatcher) -> Vec<String> {
    let before = counts(p);
    let facts = p.context::<TransportFacts>().expect("transport tail");
    assert_eq!(facts.role, busbar_contract::abi::transport::ROLE_FRAMER);
    assert_eq!(facts.claims, ["webrtc"]);
    assert!(facts.composes_over.is_empty());
    assert!(facts.datagram);
    assert_eq!(counts(p), before, "reading facts makes no crossings");
    let mut begin: BeginIn = abi::input();
    begin.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    let unopened =
        call::<_, busbar_contract::abi::transport::FramerOut>(p, slot::BEGIN, begin, 0).0;
    assert_eq!(unopened.outcome, Outcome::Refused);
    let before = counts(p);
    let validated = abi::validate(p);
    assert_eq!(validated.outcome, Outcome::Ready);
    assert_eq!(counts(p).0 - before.0, 1);
    let before = counts(p);
    let opened = open(p);
    assert_eq!(counts(p).0 - before.0, 1);
    let before = counts(p);
    assert!(
        !p.has_ready(),
        "the actual WebRTC door declares no ready callback"
    );
    p.ready(d, std::time::Duration::from_secs(30))
        .expect("actual ready");
    assert_eq!(counts(p), before);
    let refused = [
        call::<ListenIn, ListenOut>(p, slot::LISTEN, abi::input(), 1).0,
        call::<AcceptIn, AcceptOut>(p, slot::ACCEPT, abi::input(), 1).0,
        call::<DialIn, ConnOut>(p, slot::DIAL, abi::input(), 1).0,
        call::<ReadIn, IoOut>(p, slot::READ, abi::input(), 1).0,
        call::<WriteIn, IoOut>(p, slot::WRITE, abi::input(), 1).0,
        call::<ConnIn, OutHead>(p, slot::FLUSH, abi::input(), 1).0,
        call::<ShutIn, OutHead>(p, slot::SHUT, abi::input(), 1).0,
        call::<ArrivalIn, ArrivalOut>(p, slot::ARRIVAL, abi::input(), 1).0,
    ];
    assert!(refused.iter().all(|a| a.outcome == Outcome::Refused));
    let mut tick: TickIn = abi::input();
    tick.now_ns = 1;
    let (ticked, out) = call::<_, TickOut>(p, life::TICK, tick, 1);
    let mut refresh: RefreshIn = abi::input();
    refresh.settings = Blob {
        ptr: b"{}".as_ptr(),
        len: 2,
        fmt: BLOB_JSON,
        flags: 0,
    };
    refresh.generation = 2;
    let refreshed = call::<_, OutHead>(p, life::REFRESH, refresh, 1).0;
    assert_eq!(refreshed.outcome, Outcome::Ready);
    let closed = call::<InHead, OutHead>(p, life::CLOSE, abi::input(), 1).0;
    assert_eq!(closed.outcome, Outcome::Ready);
    let mut begin: BeginIn = abi::input();
    begin.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    let after_close =
        call::<_, busbar_contract::abi::transport::FramerOut>(p, slot::BEGIN, begin, 0).0;
    assert_eq!(after_close.outcome, Outcome::Fault);
    let mut transcript = vec![
        format!("{} {facts:?}", p.name()),
        abi::called(&unopened),
        abi::called(&validated),
        abi::called(&opened),
    ];
    transcript.extend(refused.iter().map(abi::called));
    transcript.extend([
        format!("{} next={}", abi::called(&ticked), out.next_tick_ns),
        abi::called(&refreshed),
        abi::called(&closed),
        abi::called(&after_close),
    ]);
    transcript
}
#[test]
fn the_linked_and_the_dropped_in_door_are_one_plugin() {
    let d = Dispatcher::new(Default::default());
    let r = row();
    assert_eq!(
        rendering_of_library(&cdylib())
            .expect("real cdylib rendering")
            .expect("exported door"),
        r.statement
    );
    let (dropped_address, dropped_ops) =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&cdylib())
            .expect("actual image reads")
            .expect("actual door exports");
    let linked_address = (r.door)();
    assert!(!linked_address.is_null());
    // SAFETY: this is the validated real static product door.
    let linked_ops =
        unsafe { busbar_contract::abi::mechanism::door::Door::read_parts(linked_address) }.ops
            as usize;
    assert_ne!(
        dropped_address, linked_address as usize,
        "independent image"
    );
    assert_ne!(dropped_ops, linked_ops, "independent operation table");
    let linked = load_linked::<Transport>(&r, bind(&d)).expect("linked real product");
    let dropped =
        load_dropped::<Transport>(&cdylib(), &r.statement, bind(&d)).expect("dropped real product");
    assert_eq!(lifecycle(&linked, &d), lifecycle(&dropped, &d));
}

#[test]
fn the_tests_run_in_the_requested_profile() {
    if std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some() {
        assert!(!cfg!(debug_assertions), "release tests were requested");
    }
}
#[test]
fn the_transport_inputs_plant_no_credentials_or_foreign_kind_cases() {
    let inputs: serde_json::Value =
        serde_json::from_str(include_str!("conformance.json")).expect("product inputs");
    assert!(inputs.get("credentials").is_none());
    assert!(inputs.get("plane").is_none());
    assert!(inputs.get("auth").is_none());
    assert!(inputs.get("store").is_none());
}

#[path = "support/datagram_witness.rs"]
mod datagram_witness;
