// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact initialized payloads retained by the real shim and framing, observed immediately before

use core::net::SocketAddr;
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(target_os = "linux")]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::framing::{
    Failed, Framing, Lane, Opening, Piece, Request, Route, Side, Terms, DESCRIPTION,
    PROFILE_AEAD_AES_128_GCM,
};
use crate::shim::Shim;

const MARK: [u8; 8] = *b"ZEROISE!";
const KEY_LEN: usize = 56;
const IDS: usize = 8;

static REGISTERED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static REGISTERED_UPSTREAM: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED_UPSTREAM_TOTAL: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED_UPSTREAM: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static READ_COMPLETE: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static READ_UPSTREAM_COMPLETE: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static MEMORY: OnceLock<File> = OnceLock::new();

struct Payload {
    ptr: usize,
    len: usize,
    id: usize,
    upstream: bool,
}

thread_local! {
    // These synchronous sans-IO scripts allocate and drop their buffers on the test's thread.
    // Metadata owns no payload: registration/reallocation can only free unregistered metadata.
    static PAYLOADS: RefCell<Vec<Payload>> = const { RefCell::new(Vec::new()) };
    #[cfg(target_os = "linux")]
    static READING: Cell<bool> = const { Cell::new(false) };
}

fn marked(w: &[u8]) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK
        && rest.len() >= KEY_LEN - MARK.len()
        && rest[..KEY_LEN - MARK.len()].iter().all(|b| *b == id))
    .then_some(usize::from(id))
    .filter(|id| *id < IDS)
}

fn register(bytes: &[u8], upstream: bool) {
    let Some(id) = bytes.windows(KEY_LEN).find_map(marked) else {
        return;
    };

    #[cfg(target_os = "linux")]
    MEMORY.get_or_init(|| {
        File::open("/proc/self/mem").expect("Linux wipe proof needs /proc/self/mem")
    });
    PAYLOADS.with(|p| {
        let mut payloads = p.borrow_mut();
        let ptr = bytes.as_ptr().addr();
        if let Some(held) = payloads.iter_mut().find(|p| p.ptr == ptr) {
            assert_eq!((held.id, held.upstream), (id, upstream));
            held.len = held.len.max(bytes.len());
            return;
        }
        payloads.push(Payload {
            ptr,
            len: bytes.len(),
            id,
            upstream,
        });
        let registered = if upstream {
            &REGISTERED_UPSTREAM
        } else {
            &REGISTERED
        };
        registered[id].fetch_add(1, Ordering::SeqCst);
    });
}

/// Called after the real Vec's payload is initialized, before it is retained by the product.

pub(crate) fn owned(bytes: &[u8]) {
    register(bytes, false);
}

/// KeyingMaterial::new in the pinned dependency creates a Vec whose entire initialized payload

pub(crate) fn upstream(bytes: &[u8]) {
    register(bytes, true);
}

struct Watch;

#[cfg(target_os = "linux")]
fn observe(payload: &Payload) -> Option<bool> {
    let memory = MEMORY.get()?;
    let mut chunk = [0_u8; 4096 + KEY_LEN - 1];
    let mut offset = 0;
    let mut carried = 0;
    let mut intact = false;
    while offset < payload.len {
        let take = (payload.len - offset).min(4096);
        let address = u64::try_from(payload.ptr.checked_add(offset)?).ok()?;
        memory
            .read_exact_at(&mut chunk[carried..carried + take], address)
            .ok()?;
        let total = carried + take;
        let bytes = &chunk[..total];
        intact |= if payload.upstream {
            bytes
                .windows(KEY_LEN)
                .any(|w| marked(w) == Some(payload.id))
        } else {
            bytes.iter().any(|b| *b != 0)
        };
        carried = total.min(KEY_LEN - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += take;
    }
    Some(intact)
}

// SAFETY: allocation calls forward unchanged. At deallocation only the matching registered base
// and the allocator's bounds are examined in Rust. On Linux the kernel copies physical bytes to
// initialized stack storage before System releases the allocation; no source-memory reference or
// typed/padding read is made. No allocator path asserts, allocates metadata or unwinds.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's allocation contract is forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = PAYLOADS.try_with(|p| {
            let payload = {
                let Ok(mut payloads) = p.try_borrow_mut() else {
                    return;
                };
                let Some(at) = payloads.iter().position(|p| p.ptr == ptr.addr()) else {
                    return;
                };
                payloads.swap_remove(at)
            };
            let (freed, unzeroed) = if payload.upstream {
                (&FREED_UPSTREAM_TOTAL, &FREED_UPSTREAM)
            } else {
                (&FREED, &FREED_UNZEROED)
            };
            freed[payload.id].fetch_add(1, Ordering::SeqCst);

            #[cfg(target_os = "linux")]
            if payload.len <= layout.size() {
                let _ = READING.try_with(|reading| {
                    if reading.replace(true) {
                        return;
                    }
                    let observed = observe(&payload);
                    reading.set(false);
                    if let Some(intact) = observed {
                        let complete = if payload.upstream {
                            &READ_UPSTREAM_COMPLETE
                        } else {
                            &READ_COMPLETE
                        };
                        complete[payload.id].fetch_add(1, Ordering::SeqCst);
                        if intact {
                            unzeroed[payload.id].fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            #[cfg(not(target_os = "linux"))]
            let _ = (layout, unzeroed);
        });
        // SAFETY: the caller's allocation contract is forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static WATCH: Watch = Watch;

fn all_freed(id: u8) {
    let id = usize::from(id);
    let registered = REGISTERED[id].load(Ordering::SeqCst);
    assert!(
        registered > 0,
        "the real product payload must be registered"
    );
    assert_eq!(
        FREED[id].load(Ordering::SeqCst),
        registered,
        "every registered payload must be freed"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        READ_COMPLETE[id].load(Ordering::SeqCst),
        registered,
        "every registered payload needs a complete OS read at its actual free"
    );
}

fn upstream_freed(id: u8) {
    let id = usize::from(id);
    let registered = REGISTERED_UPSTREAM[id].load(Ordering::SeqCst);
    assert!(
        registered > 0,
        "the actual upstream payload must be registered"
    );
    assert_eq!(FREED_UPSTREAM_TOTAL[id].load(Ordering::SeqCst), registered);
    #[cfg(target_os = "linux")]
    assert_eq!(
        READ_UPSTREAM_COMPLETE[id].load(Ordering::SeqCst),
        registered,
        "every upstream payload needs a complete OS read at its actual free"
    );
}

/// The marked key `id`, on the stack (the stack is not the allocator's to watch).
fn key(id: u8) -> [u8; KEY_LEN] {
    let mut k = [id; KEY_LEN];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

/// Unzeroed frees of key `id` made by the plugin's own code.
#[cfg(target_os = "linux")]
fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

/// Unzeroed frees of the exact upstream KeyingMaterial payload for key `id`.
#[cfg(target_os = "linux")]
fn freed_upstream(id: u8) -> usize {
    FREED_UPSTREAM[usize::from(id)].load(Ordering::SeqCst)
}

#[cfg_attr(target_os = "linux", test)]
fn keying_material_held_by_the_shim_is_zeroised_when_it_drops() {
    let material = key(1);
    let shim = Shim::default();
    shim.keyed(&material, PROFILE_AEAD_AES_128_GCM)
        .expect("AEAD-AES-128-GCM is taken");
    assert!(shim.holds_keying(), "the material was held, on the heap");
    drop(shim);
    all_freed(1);
    #[cfg(target_os = "linux")]
    assert_eq!(freed_unzeroed(1), 0, "the held material was freed unzeroed");
}

#[cfg_attr(target_os = "linux", test)]
fn keying_material_a_framing_refuses_is_zeroised() {
    let material = key(2);
    let now = Instant::now();
    let mut f = Framing::begin(
        Side::Accept,
        b"public certificate bytes",
        Some("203.0.113.9:3478".parse().expect("an address")),
        &Opening::default(),
        now,
    )
    .expect("begins");

    assert!(f
        .host(0, false, Some((PROFILE_AEAD_AES_128_GCM, &material)), now)
        .is_err());
    assert!(!f.holds_keying());

    assert!(f.host(0, true, Some((0x0001, &material)), now).is_err());
    assert!(!f.holds_keying());
    assert_eq!(REGISTERED[2].load(Ordering::SeqCst), 0);

    f.host(0, true, Some((PROFILE_AEAD_AES_128_GCM, &material)), now)
        .expect("queued");
    assert!(f.holds_keying());
    assert!(f
        .host(0, true, Some((PROFILE_AEAD_AES_128_GCM, &material)), now)
        .is_err());
    assert!(f.holds_keying());
    drop(f);
    all_freed(2);
    #[cfg(target_os = "linux")]
    assert_eq!(freed_unzeroed(2), 0, "a refused item was freed unzeroed");
}

#[cfg_attr(target_os = "linux", test)]
fn red_arm_a_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let material = key(3);
    let plain: Vec<u8> = material.to_vec();
    owned(&plain);
    drop(std::hint::black_box(plain));
    all_freed(3);
    #[cfg(target_os = "linux")]
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a key freed without zeroising"
    );

    let held = zeroize::Zeroizing::new(key(4).to_vec());
    owned(&held);
    drop(std::hint::black_box(held));
    all_freed(4);
    #[cfg(target_os = "linux")]
    assert_eq!(freed_unzeroed(4), 0);
}

/// A placeholder certificate: the framer states its SHA-256 and nothing else reads it.
const CERT: &[u8] = b"public certificate bytes";

const PROFILE: u32 = PROFILE_AEAD_AES_128_GCM;

/// One end: its framing and its host's view (the unit tests' shape; not every field is read here).
#[allow(dead_code)]
struct End {
    f: Framing,
    addr: SocketAddr,
    paths: HashMap<SocketAddr, u32>,
    by_id: HashMap<u32, SocketAddr>,
    bound: u32,
    verified: bool,
    keyed: bool,
    pieces: Vec<Piece>,
    requests: Vec<Request>,
    sent: Vec<Route>,
}

impl End {
    fn new(side: Side, addr: &str, opening: &Opening, now: Instant) -> Self {
        let addr: SocketAddr = addr.parse().expect("an address");
        End {
            f: Framing::begin(side, CERT, Some(addr), opening, now).expect("begins"),
            addr,
            paths: HashMap::new(),
            by_id: HashMap::new(),
            bound: 0,
            verified: false,
            keyed: false,
            pieces: Vec::new(),
            requests: Vec::new(),
            sent: Vec::new(),
        }
    }

    fn path(&mut self, a: SocketAddr) -> u32 {
        let n = self.paths.len() as u32 + 1;
        let p = *self.paths.entry(a).or_insert(n);
        self.by_id.insert(p, a);
        p
    }

    /// The description this end yielded on stream 0.
    fn description(&mut self) -> Vec<u8> {
        self.collect();
        let at = self
            .pieces
            .iter()
            .position(|p| p.stream == DESCRIPTION)
            .expect("a description");
        self.pieces.remove(at).bytes
    }

    fn collect(&mut self) {
        while let Some(p) = self.f.next_piece() {
            self.pieces.push(p);
        }
        while let Some(r) = self.f.take_request() {
            self.requests.push(r);
        }
    }

    /// Take the terms; a dialling end's host judges and numbers the far end's candidates.
    fn terms(&mut self) -> Terms {
        let t = self.f.take_terms().expect("terms");
        let known: Vec<(u32, SocketAddr)> =
            t.candidates.iter().map(|a| (self.path(*a), *a)).collect();
        self.f.paths(known);
        t
    }

    fn host(&mut self, keying: Option<&[u8]>, now: Instant) -> Result<(), Failed> {
        let r = self
            .f
            .host(self.bound, self.verified, keying.map(|k| (PROFILE, k)), now);
        if keying.is_some() && r.is_ok() {
            self.keyed = true;
        }
        self.collect();
        r
    }

    fn bind_what_was_asked(&mut self, now: Instant) {
        self.collect();
        for r in std::mem::take(&mut self.requests) {
            self.bound = match r {
                Request::Bind(p) | Request::Rebind(_, p) => p,
            };
        }
        let _ = self.host(None, now);
    }
}

/// Carry every route each end owes to the other, until both are quiet.
fn pump(a: &mut End, b: &mut End, now: Instant) {
    for _ in 0..200 {
        let mut moved = false;
        for flip in [false, true] {
            let (from, to) = if flip {
                (&mut *b, &mut *a)
            } else {
                (&mut *a, &mut *b)
            };
            while let Some(r) = from.f.next_route() {
                moved = true;
                from.sent.push(r.clone());
                let path = to.path(from.addr);
                let lane = r.lane;
                if lane == Lane::Secured && !(from.verified && to.verified) {
                    continue;
                }
                to.f.datagram(path, from.addr, lane, &r.bytes, now);
            }
            from.collect();
        }
        if !moved {
            break;
        }
    }
}

/// Run the clock and the pump for `ms`, in 10 ms steps.
fn run(a: &mut End, b: &mut End, start: &mut Instant, ms: u64) {
    for _ in 0..ms / 10 {
        *start += Duration::from_millis(10);
        for e in [&mut *a, &mut *b] {
            if e.f.next_timeout().is_some_and(|t| t <= *start) {
                e.f.timeout(*start);
            }
            e.bind_what_was_asked(*start);
        }
        pump(a, b, *start);
    }
}

fn opening() -> Opening {
    Opening {
        channels: vec!["events".into()],
        audio: true,
    }
}

/// Two ends through the rendezvous, ICE, verification and keying with `material`: a connected

fn connected_with(material: &[u8]) -> (End, End, Instant) {
    let mut now = Instant::now();
    let mut dial = End::new(Side::Dial, "198.51.100.1:40000", &opening(), now);
    let mut accept = End::new(Side::Accept, "203.0.113.9:3478", &Opening::default(), now);
    let offer = dial.description();
    accept
        .f
        .rendezvous(&offer, now)
        .expect("the offer is accepted");
    let answer = accept.description();
    dial.f
        .rendezvous(&answer, now)
        .expect("the answer is accepted");
    let (ta, td) = (accept.terms(), dial.terms());
    assert_ne!(ta.initiates, td.initiates, "one end opens the handshake");
    assert_eq!(ta.remote_user, td.local_user);
    assert_eq!(td.remote_user, ta.local_user);
    run(&mut dial, &mut accept, &mut now, 3000);
    assert_ne!(dial.bound, 0, "the dialling end's nomination was bound");
    assert_ne!(accept.bound, 0, "the accepting end's nomination was bound");
    for e in [&mut dial, &mut accept] {
        e.verified = true;
        e.host(Some(material), now).expect("keyed");
    }
    run(&mut dial, &mut accept, &mut now, 3000);
    (dial, accept, now)
}

/// THE PLUGIN'S OWN COPIES on the accepted path: keying material presented to a verified

#[cfg_attr(target_os = "linux", test)]
fn keying_material_the_plugin_holds_on_the_accepted_path_is_zeroised() {
    let material = key(5);
    let (dial, accept, _) = connected_with(&material);
    assert!(dial.keyed && accept.keyed, "both ends took the material");
    drop((dial, accept));
    all_freed(5);
    upstream_freed(5);
    #[cfg(target_os = "linux")]
    assert_eq!(
        freed_unzeroed(5),
        0,
        "a copy of the keying material the plugin holds was freed unzeroed"
    );
}

/// KNOWN RESIDUAL, ASSERTED AS KNOWN (listed in the README): the published str0m 0.24.1 and

#[cfg_attr(target_os = "linux", test)]
fn known_residual_upstream_copies_of_the_keying_material_are_freed_unzeroed() {
    let material = key(6);
    let (dial, accept, _) = connected_with(&material);
    drop((dial, accept));
    all_freed(6);
    upstream_freed(6);
    #[cfg(target_os = "linux")]
    assert!(
        freed_upstream(6) >= 1,
        "str0m/dimpl no longer free the keying material unzeroed: make this a gate and drop the README note"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(freed_unzeroed(6), 0, "the plugin's own copies are zeroised");
}

/// PLAINTEXT QUEUED FOR SEALING IS ZEROISED TOO (codeaudit W10; the shim's doc: relayed plaintext

#[cfg_attr(target_os = "linux", test)]
fn plaintext_queued_for_sealing_is_zeroised() {
    use str0m::crypto::dtls::{DtlsInstance, DtlsOutput};
    let plain = key(7);
    let mut shim = Shim::default();
    shim.handle_packet(&crate::shim::CONNECTED_FRAME)
        .expect("the relay is taken");
    let mut buf = vec![0_u8; 2048];

    for _ in 0..12 {
        shim.send_application_data(&plain)
            .expect("taken once connected");
    }
    let mut sealed = 0;
    for _ in 0..20 {
        if let DtlsOutput::Packet(p) = shim.poll_output(&mut buf) {
            assert_eq!(&p[1..], &plain[..]);
            sealed += 1;
        }
    }
    assert_eq!(sealed, 12, "every packet handed back to seal");

    shim.send_application_data(&plain).expect("taken");
    buf.fill(0);
    drop(shim);
    all_freed(7);
    #[cfg(target_os = "linux")]
    assert_eq!(
        freed_unzeroed(7) + freed_upstream(7),
        0,
        "plaintext queued for sealing was freed unzeroed"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn shim_and_refused_framing_behavior_only_without_linux_wipe_proof() {
    keying_material_held_by_the_shim_is_zeroised_when_it_drops();
    keying_material_a_framing_refuses_is_zeroised();
    red_arm_a_key_in_a_plain_vec_is_seen_freed_unzeroed();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn accepted_framing_behavior_only_without_linux_wipe_proof() {
    keying_material_the_plugin_holds_on_the_accepted_path_is_zeroised();
    known_residual_upstream_copies_of_the_keying_material_are_freed_unzeroed();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn queued_plaintext_behavior_only_without_linux_wipe_proof() {
    plaintext_queued_for_sealing_is_zeroised();
}
