// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real provider creates and uses AES-128/256-GCM ciphers, then drops their actual Boxes.
//! The test registers each returned Box's data address and dynamic size, without naming ring's
//! private fields or forming a byte slice over its opaque state or padding.
//!
//! On Linux, `/proc/self/mem` copies that physical allocation into initialized stack storage while
//! the Box is alive and again in deallocation, before System releases it. A complete live read
//! must find the full marked session key first; a complete read at the matching actual free must
//! not find it. Plain-Vec and Zeroizing-Vec controls use the same observer and require actual frees.
//! The other platforms retain the cipher behavior and free receipts under behavior-only names;
//! no physical-memory wipe proof is implemented for them here.
//!
//! This is marker-disappearance evidence for the selected ring backend and CPU, not proof that
//! every expanded-key/GHASH byte, stack copy or other upstream secret was erased. ring 0.17.14
//! stores the AES/GHASH state inline inside this Box, but the marker cannot identify every byte of
//! that derived state. In particular, replacing the key in Gcm::drop may leave separate old stack
//! copies. Production destruction is not changed or simulated by this test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm,
};

const MARK: [u8; 8] = *b"SESSKEY!";
const IDS: usize = 8;
const LONGEST: usize = 32;

static REGISTERED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static READ_COMPLETE: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(target_os = "linux")]
static MEMORY: OnceLock<File> = OnceLock::new();

#[derive(Clone, Copy)]
struct Probe {
    ptr: usize,
    size: usize,
    len: usize,
    id: usize,
    key_len: usize,
}

thread_local! {
    // The synchronous cipher script creates and frees its Box on the same test thread. Metadata
    // is fixed-size and owns no payload, so the allocator never allocates its own bookkeeping.
    static PROBE: Cell<Option<Probe>> = const { Cell::new(None) };
    #[cfg(target_os = "linux")]
    static READING: Cell<bool> = const { Cell::new(false) };
}

#[cfg(target_os = "linux")]
fn marked(bytes: &[u8], probe: Probe) -> bool {
    bytes.windows(probe.key_len).any(|key| {
        key.starts_with(&MARK)
            && key[MARK.len()..]
                .iter()
                .all(|b| usize::from(*b) == probe.id)
    })
}

// Only the initialized destination is read by Rust. The source is an address passed to the
// kernel, not a Rust byte reference. Complete reads and a longest-key overlap cover the entire
// registered range, including a marker straddling two chunks. No bytes are written to the source.
#[cfg(target_os = "linux")]
fn observe(probe: Probe) -> Option<bool> {
    let memory = MEMORY.get()?;
    let mut chunk = [0_u8; 4096 + LONGEST - 1];
    let mut offset = 0;
    let mut carried = 0;
    let mut intact = false;
    while offset < probe.len {
        let take = (probe.len - offset).min(4096);
        let address = u64::try_from(probe.ptr.checked_add(offset)?).ok()?;
        memory
            .read_exact_at(&mut chunk[carried..carried + take], address)
            .ok()?;
        let total = carried + take;
        intact |= marked(&chunk[..total], probe);
        carried = total.min(LONGEST - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += take;
    }
    Some(intact)
}

fn register(ptr: usize, size: usize, len: usize, id: u8, key_len: usize) {
    let probe = Probe {
        ptr,
        size,
        len,
        id: usize::from(id),
        key_len,
    };
    assert!(len <= size && len >= key_len && key_len >= MARK.len() && key_len <= LONGEST);
    assert!(probe.id < IDS);
    // Open outside the allocator and before arming the probe; initialization may allocate.
    #[cfg(target_os = "linux")]
    {
        MEMORY.get_or_init(|| {
            File::open("/proc/self/mem").expect("Linux wipe proof needs /proc/self/mem")
        });
        assert_eq!(
            observe(probe),
            Some(true),
            "a complete live read must see the actual full key before this witness can prove its disappearance"
        );
    }
    PROBE.with(|slot| {
        assert!(
            slot.replace(Some(probe)).is_none(),
            "one live probe per script"
        );
    });
    REGISTERED[probe.id].fetch_add(1, Ordering::SeqCst);
}

struct Watch;

// SAFETY: allocation calls forward unchanged. Deallocation compares only the registered address
// and layout in Rust. The Linux kernel reads the physical range before System releases it, into
// initialized stack storage; no reference to opaque/deinitialized source memory is constructed.
// There are no assertions, metadata allocations or unwinding paths inside the allocator.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's allocation contract is forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = PROBE.try_with(|slot| {
            let Some(probe) = slot.get().filter(|probe| probe.ptr == ptr.addr()) else {
                return;
            };
            slot.set(None);
            FREED[probe.id].fetch_add(1, Ordering::SeqCst);
            #[cfg(target_os = "linux")]
            if layout.size() == probe.size && probe.len <= layout.size() {
                let _ = READING.try_with(|reading| {
                    if reading.replace(true) {
                        return;
                    }
                    let observed = observe(probe);
                    reading.set(false);
                    if let Some(intact) = observed {
                        READ_COMPLETE[probe.id].fetch_add(1, Ordering::SeqCst);
                        if intact {
                            FREED_UNZEROED[probe.id].fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            #[cfg(not(target_os = "linux"))]
            let _ = (layout, probe.size, probe.len, probe.key_len);
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
        "the actual owning allocation must be registered"
    );
    assert_eq!(
        FREED[id].load(Ordering::SeqCst),
        registered,
        "every registered allocation must actually be freed"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        READ_COMPLETE[id].load(Ordering::SeqCst),
        registered,
        "every actual free needs a complete OS read with the expected layout"
    );
}

/// The marked session key `id` of `N` bytes, on the stack.
fn key<const N: usize>(id: u8) -> [u8; N] {
    let mut k = [id; N];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

#[cfg(target_os = "linux")]
fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

const IV: [u8; 12] = [7; 12];
const HEADER: [u8; 12] = [0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
const PAYLOAD: [u8; 64] = [0x5a; 64];

#[cfg_attr(target_os = "linux", test)]
fn an_aes_128_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = busbar_transport_webrtc::crypto::provider();
    let gcm = SrtpProvider::aead_aes_128_gcm(p.srtp_provider);
    let mut seal = SupportedAeadAes128Gcm::create_cipher(gcm, key::<16>(1), true);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    AeadAes128GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed)
        .expect("the key seals");
    let size = std::mem::size_of_val(&*seal);
    register(
        std::ptr::from_ref(&*seal).cast::<()>().addr(),
        size,
        size,
        1,
        16,
    );
    drop(std::hint::black_box(seal));
    all_freed(1);
    #[cfg(target_os = "linux")]
    assert_eq!(
        freed_unzeroed(1),
        0,
        "the full AES-128-GCM session-key marker remained in its freed cipher Box"
    );
}

#[cfg_attr(target_os = "linux", test)]
fn an_aes_256_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = busbar_transport_webrtc::crypto::provider();
    let gcm = SrtpProvider::aead_aes_256_gcm(p.srtp_provider);
    let mut open = SupportedAeadAes256Gcm::create_cipher(gcm, key::<32>(2), false);
    // A forged packet: the real cipher is used, and refuses it.
    let mut out = [0_u8; PAYLOAD.len() + 16];
    assert!(AeadAes256GcmCipher::decrypt(
        &mut *open,
        &IV,
        &[&HEADER],
        &[0_u8; PAYLOAD.len() + 16],
        &mut out
    )
    .is_err());
    let size = std::mem::size_of_val(&*open);
    register(
        std::ptr::from_ref(&*open).cast::<()>().addr(),
        size,
        size,
        2,
        32,
    );
    drop(std::hint::black_box(open));
    all_freed(2);
    #[cfg(target_os = "linux")]
    assert_eq!(
        freed_unzeroed(2),
        0,
        "the full AES-256-GCM session-key marker remained in its freed cipher Box"
    );
}

#[cfg_attr(target_os = "linux", test)]
fn red_arm_a_session_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let plain: Vec<u8> = key::<16>(3).to_vec();
    register(plain.as_ptr().addr(), plain.capacity(), plain.len(), 3, 16);
    drop(std::hint::black_box(plain));
    all_freed(3);
    #[cfg(target_os = "linux")]
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a session key freed without zeroising"
    );
    let held = zeroize::Zeroizing::new(key::<16>(4).to_vec());
    register(held.as_ptr().addr(), held.capacity(), held.len(), 4, 16);
    drop(std::hint::black_box(held));
    all_freed(4);
    #[cfg(target_os = "linux")]
    assert_eq!(freed_unzeroed(4), 0);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn aes_128_provider_behavior_only_without_linux_wipe_proof() {
    an_aes_128_gcm_session_key_is_zeroised_when_its_cipher_drops();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn aes_256_provider_behavior_only_without_linux_wipe_proof() {
    an_aes_256_gcm_session_key_is_zeroised_when_its_cipher_drops();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn owning_vec_free_behavior_only_without_linux_wipe_proof() {
    red_arm_a_session_key_in_a_plain_vec_is_seen_freed_unzeroed();
}
