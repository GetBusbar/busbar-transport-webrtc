// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FRAMER, BOTH DOORS, ONE TABLE** — the `webrtc` framer compiled in (`linked::door`, the

use busbar_contract::abi::mechanism::call::{AbiStr, Field};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, DatagramLane, DatagramRoute, EncodeIn, FinishIn, FramePiece,
    FramerOut, FramerSink, IngestIn, ListenIn, ListenOut, LocateIn, LocateOut, LANE_RENDEZVOUS,
    PIECE_END_OF_FRAME, PIECE_TEXT, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL, YIELD_ENDED, YIELD_MORE,
};
use busbar_plugin_loader::dispatch::kinds::transport::{Transport, TransportFacts};
use busbar_plugin_loader::dispatch::{
    load_dropped, Called, Frame, InFrame, LinkedRow, OutFrame, Plugin,
};
#[path = "abi.rs"]
pub mod conf;
use busbar_plugin_loader::dispatch::{
    load_linked, rendering_of_library, DispatchConfig, Dispatcher,
};

/// The host port's address, the one candidate the framer advertises.
const LOCAL: &str = "198.51.100.1:40000";
const CERT: &[u8] = b"the host's public certificate, DER";

/// The host's buffers for one framer op.
struct Host {
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    routes: Vec<DatagramRoute>,
}

impl Host {
    fn new() -> Self {
        let piece = FramePiece {
            stream: 0,
            offset: 0,
            len: 0,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: 0,
            retry_after_secs: 0,
            declared_len: 0,
        };
        Self {
            wire: vec![0; 16 * 1024],
            frame: vec![0; 16 * 1024],
            pieces: vec![piece; 16],
            routes: vec![DatagramRoute::default(); 16],
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: 1,
            now_unix_ns: 1,
            heads: std::ptr::null_mut(),
            heads_cap: 0,
        }
    }

    /// The lane of a call ingesting on `lane` (`0`: nothing), nothing bound or verified yet.
    fn lane(&mut self, lane: u32) -> DatagramLane {
        DatagramLane {
            size: std::mem::size_of::<DatagramLane>() as u32,
            lane,
            path: 0,
            bound: 0,
            path_addr: AbiStr::ABSENT,
            local_addr: AbiStr::of_bytes(LOCAL.as_bytes()),
            verified: 0,
            _reserved: 0,
            keying: std::ptr::null(),
            routes: self.routes.as_mut_ptr(),
            routes_cap: self.routes.len(),
            paths: std::ptr::null(),
            paths_len: 0,
        }
    }

    /// What the last answer yielded, as one deterministic line: the pieces (stream, flags, and for
    fn yielded(
        &self,
        outcome: busbar_contract::abi::mechanism::call::Outcome,
        o: &FramerOut,
    ) -> String {
        busbar_contract::abi::transport::check::check_datagram(
            outcome,
            o,
            &self.routes,
            self.routes.len() as u64,
        )
        .expect("the actual product obeys the datagram lane contract");
        assert_eq!(
            o.datagram.terms.role,
            busbar_contract::abi::transport::HANDSHAKE_NONE
        );
        let n = (o.yielded.pieces_len as usize).min(self.pieces.len());
        let pieces: Vec<String> = self.pieces[..n]
            .iter()
            .map(|p| {
                let at = p.offset as usize;
                let bytes = &self.frame[at..at + p.len as usize];
                let text = String::from_utf8_lossy(bytes);
                let described = p.stream == 0
                    && text.starts_with("v=0")
                    && text.contains("a=fingerprint:sha-256 ")
                    && text.contains("198.51.100.1 40000 typ host")
                    && text.contains("m=application");
                format!(
                    "stream={} flags={} described={described}",
                    p.stream, p.flags
                )
            })
            .collect();
        format!(
            "pieces={pieces:?} routes={} flags={}",
            o.datagram.routes_len,
            o.yielded.flags & (YIELD_ENDED | YIELD_MORE)
        )
    }
}

fn go<I: InFrame, O: OutFrame>(p: &Plugin<Transport>, s: u32, i: I) -> (Called, O) {
    let mut f = Frame::new(i, conf::output::<O>());
    let before = p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed);
    let c = p.call(s, &mut f);
    assert_eq!(
        p.inner.crossings.load(std::sync::atomic::Ordering::Relaxed) - before,
        1,
        "exact crossing count for slot {s}"
    );
    (c, f.out)
}

/// `begin` on `side`, with the host's certificate and (when `lane`) a lane: its line and token.
fn begin(p: &Plugin<Transport>, side: u32, lane: bool) -> (String, u64) {
    let mut host = Host::new();
    let facts = ConnFacts {
        size: std::mem::size_of::<ConnFacts>() as u32,
        _reserved: 0,
        offered_name: AbiStr::ABSENT,
        agreed_protocol: AbiStr::ABSENT,
        peer_subject: AbiStr::ABSENT,
        peer_issuer: AbiStr::ABSENT,
        peer_fingerprint: AbiStr::ABSENT,
        claim: AbiStr::ABSENT,
        local_certificate: AbiStr::of_bytes(CERT),
    };
    let fields = [Field {
        name: AbiStr::of_bytes(b"channel"),
        value: AbiStr::of_bytes(b"events"),
    }];
    let l = host.lane(0);
    let mut i: BeginIn = conf::input();
    i.side = side;

    i.scheme = busbar_contract::abi::host::service::SCHEME_SECURE;
    i.facts = &facts;
    i.sink = host.sink();
    if side == SIDE_DIAL {
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
    }
    if lane {
        i.lane = &l;
    }
    let (called, o): (Called, FramerOut) = go(p, slot::BEGIN, i);
    (
        format!(
            "{} framing={} {}",
            conf::called(&called),
            o.framing != 0,
            host.yielded(called.outcome, &o)
        ),
        o.framing,
    )
}

/// One leg's transcript.
fn fold(p: &Plugin<Transport>) -> Vec<String> {
    let facts = p
        .context::<TransportFacts>()
        .cloned()
        .expect("a transport states its tail");
    let mut t = vec![format!(
        "role={} claims={:?} composes_over={:?}",
        facts.role, facts.claims, facts.composes_over
    )];
    t.push(format!("validate {}", conf::called(&conf::validate(p))));
    t.push(format!("open {}", conf::called(&conf::open(p))));

    t.push(format!(
        "listen {}",
        conf::called(&go::<ListenIn, ListenOut>(&p, slot::LISTEN, conf::input()).0)
    ));
    t.push(format!(
        "locate {}",
        conf::called(&go::<LocateIn, LocateOut>(&p, slot::LOCATE, conf::input()).0)
    ));
    let mut host = Host::new();
    let mut e: EncodeIn = conf::input();
    e.sink = host.sink();
    t.push(format!(
        "encode {}",
        conf::called(&go::<EncodeIn, FramerOut>(&p, slot::ENCODE, e).0)
    ));

    t.push(format!(
        "begin without a lane {}",
        begin(&p, SIDE_DIAL, false).0
    ));

    let (line, token) = begin(&p, SIDE_DIAL, true);
    t.push(format!("begin dial {line}"));

    let mut host = Host::new();
    let junk = b"not a session description";
    for step in ["rendezvous junk", "rendezvous after failure"] {
        let l = host.lane(LANE_RENDEZVOUS);
        let mut i: IngestIn = conf::input();
        (i.framing, i.bytes, i.len, i.sink, i.lane) =
            (token, junk.as_ptr(), junk.len(), host.sink(), &l);
        let (answer, output) = go::<IngestIn, FramerOut>(&p, slot::INGEST, i);
        host.yielded(answer.outcome, &output);
        t.push(format!("{step} {}", conf::called(&answer)));
    }

    let (line, token) = begin(&p, SIDE_ACCEPT, true);
    t.push(format!("begin accept {line}"));
    for step in ["finish", "finish again"] {
        let mut host = Host::new();
        let l = host.lane(0);
        let mut i: FinishIn = conf::input();
        (i.framing, i.sink, i.lane) = (token, host.sink(), &l);
        let (called, o): (Called, FramerOut) = go(&p, slot::FINISH, i);
        t.push(format!(
            "{step} {} {}",
            conf::called(&called),
            host.yielded(called.outcome, &o)
        ));
    }
    let mut host = Host::new();
    let lane = host.lane(LANE_RENDEZVOUS);
    let mut input: IngestIn = conf::input();
    input.framing = u64::MAX;
    input.bytes = junk.as_ptr();
    input.len = junk.len();
    input.sink = host.sink();
    input.lane = &lane;
    let (answer, output) = go::<IngestIn, FramerOut>(p, slot::INGEST, input);
    host.yielded(answer.outcome, &output);
    t.push(format!("ingest on no framing {}", conf::called(&answer)));
    t.push(format!("close {}", conf::called(&conf::close(&p))));
    t
}

/// What the contract requires of each line, by its start.
fn expected() -> Vec<String> {
    let piece = PIECE_END_OF_FRAME | PIECE_TEXT;
    vec![
        format!("role={ROLE_FRAMER} claims=[\"webrtc\"] composes_over=[]"),
        "validate Ready lease=false ".into(),
        "open Ready lease=false ".into(),
        "listen Refused lease=false listen: the webrtc framer does not serve this op".into(),
        "locate Refused lease=false locate: the webrtc framer does not serve this op".into(),
        "encode Refused lease=false encode: the webrtc framer does not serve this op".into(),
        "begin without a lane Failed lease=false begin: a datagram framer reads its lane".into(),
        format!(
            "begin dial Ready lease=false  framing=true pieces=[\"stream=0 flags={piece} described=true\"] routes=0 flags=0"
        ),
        // Every refusal opens with its op (sibling alignment D7).
        "rendezvous junk Failed lease=false ingest: ".into(),
        "rendezvous after failure Failed lease=false ingest: no such framing".into(),
        "begin accept Ready lease=false  framing=true pieces=[] routes=0 flags=0".into(),
        format!("finish Ready lease=false  pieces=[] routes=0 flags={YIELD_ENDED}"),
        "finish again Failed lease=false finish: no such framing".into(),
        "ingest on no framing Failed lease=false ingest: no such framing".into(),
        "close Ready lease=false ".into(),
    ]
}

/// THE WITNESS: the dropped-in library states exactly the linked door's Statement, and the two
#[test]
fn the_linked_and_the_dropped_in_framer_are_one_plugin_on_one_table() {
    let row =
        LinkedRow::of(busbar_transport_webrtc::linked::door).expect("the linked door is admitted");
    let d = Dispatcher::new(DispatchConfig::default());
    let stated = rendering_of_library(&conf::cdylib())
        .expect("renders")
        .expect("real exported door");
    assert_eq!(
        row.statement, stated,
        "the dropped-in library states exactly the linked door's Statement"
    );
    let linked_plugin =
        load_linked::<Transport>(&row, conf::bind(&d, "webrtc-linked")).expect("linked door");
    let dropped_plugin =
        load_dropped::<Transport>(&conf::cdylib(), &stated, conf::bind(&d, "webrtc-dropped"))
            .expect("dropped door");
    let linked = fold(&linked_plugin);
    let dropped = fold(&dropped_plugin);
    assert_eq!(linked, dropped, "the two doors part");
    let want = expected();
    assert_eq!(linked.len(), want.len(), "{linked:#?}");
    for (got, want) in linked.iter().zip(&want) {
        if want.starts_with("begin dial ")
            || want.starts_with("begin accept ")
            || want.starts_with("finish Ready ")
        {
            assert_eq!(got, want, "exact datagram script success answer");
        } else {
            assert!(got.starts_with(want.as_str()), "got:  {got}\nwant: {want}…");
        }
    }
}

/// A dropped-in library stating a different rendering is refused.
#[test]
fn red_arm_a_dropped_in_library_stating_another_statement_is_refused() {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(busbar_transport_webrtc::linked::door).expect("real linked door");
    let own = rendering_of_library(&conf::cdylib())
        .expect("renders")
        .expect("real exported door");
    let mut other = own.clone();
    let last = other.len() - 1;
    other[last] ^= 0x01;
    assert!(
        load_dropped::<Transport>(&conf::cdylib(), &other, conf::bind(&d, "webrtc-other")).is_err(),
        "a library admitted against another Statement must be refused"
    );
    assert!(load_dropped::<Transport>(&conf::cdylib(), &own, conf::bind(&d, "webrtc-own")).is_ok());
    assert!(load_linked::<Transport>(&row, conf::bind(&d, "webrtc-linked")).is_ok());
}
