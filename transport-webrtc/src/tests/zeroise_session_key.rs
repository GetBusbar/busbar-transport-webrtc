// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real provider creates and uses AES-128/256-GCM ciphers, then drops their owned state.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "../../tests/support/provider_alloc.rs"]
mod native;

use std::alloc::Layout;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, SrtpProvider, SupportedAeadAes128Gcm,
    SupportedAeadAes256Gcm,
};

const MARK: [u8; 8] = *b"SESSKEY!";
const IDS: usize = 8;
const LONGEST: usize = 32;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const READ_CHUNK_LEN: usize = 4096;

static REGISTERED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
static FREED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static READ_COMPLETE: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];

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
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    static READING: Cell<bool> = const { Cell::new(false) };
}

fn marked(bytes: &[u8], probe: Probe) -> bool {
    bytes.windows(probe.key_len).any(|key| {
        key.starts_with(&MARK)
            && key[MARK.len()..]
                .iter()
                .all(|b| usize::from(*b) == probe.id)
    })
}

// SAFETY: pointer is the actual current System.dealloc parameter, still live. Registration
// records only a Vec's initialized full slice; these controls never mutate its length or
// reallocate before drop. Zeroizing may clear its length after overwriting the same u8 bytes,
// which remain initialized. The caller checks the allocation's actual layout before reading.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe fn observe(pointer: *const u8, probe: Probe) -> bool {
    let mut chunk = zeroize::Zeroizing::new([0_u8; READ_CHUNK_LEN + LONGEST - 1]);
    let mut offset = 0;
    let mut carried = 0;
    let mut intact = false;
    while offset < probe.len {
        let take = (probe.len - offset).min(READ_CHUNK_LEN);
        // SAFETY: source stays within the registered initialized slice of the live
        // allocation. The stack destination is separate and has room for this chunk.
        unsafe {
            pointer
                .add(offset)
                .copy_to_nonoverlapping(chunk[carried..].as_mut_ptr(), take);
        }
        let total = carried + take;
        intact |= marked(&chunk[..total], probe);
        carried = total.min(LONGEST - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += take;
    }
    intact
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
    PROBE.with(|slot| {
        assert!(
            slot.replace(Some(probe)).is_none(),
            "one live probe per script"
        );
    });
    REGISTERED[probe.id].fetch_add(1, Ordering::SeqCst);
}

fn register_payload(bytes: &[u8], capacity: usize, id: u8, key_len: usize) {
    let probe = Probe {
        ptr: bytes.as_ptr().addr(),
        size: capacity,
        len: bytes.len(),
        id: usize::from(id),
        key_len,
    };
    assert!(
        marked(bytes, probe),
        "the initialized live payload must contain the actual full key"
    );
    register(probe.ptr, probe.size, probe.len, id, key_len);
}

// Called by the shared test allocator before the allocation is released.
pub(super) unsafe fn on_dealloc(ptr: *mut u8, layout: Layout) {
    let _ = PROBE.try_with(|slot| {
        let Some(probe) = slot.get().filter(|probe| probe.ptr == ptr.addr()) else {
            return;
        };
        slot.set(None);
        FREED[probe.id].fetch_add(1, Ordering::SeqCst);
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if layout.size() == probe.size && probe.len <= layout.size() {
            let _ = READING.try_with(|reading| {
                if reading.replace(true) {
                    return;
                }
                // SAFETY: this is the actual live deallocation pointer, its layout
                // matches the registered allocation, and len is the initialized slice.
                let intact = unsafe { observe(ptr, probe) };
                reading.set(false);
                READ_COMPLETE[probe.id].fetch_add(1, Ordering::SeqCst);
                if intact {
                    FREED_UNZEROED[probe.id].fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let _ = (layout, probe.size, probe.len, probe.key_len);
    });
}

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
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    assert_eq!(
        READ_COMPLETE[id].load(Ordering::SeqCst),
        registered,
        "every actual free needs a complete initialized-byte read through its current pointer"
    );
}

/// The marked session key `id` of `N` bytes, on the stack.
fn key<const N: usize>(id: u8) -> [u8; N] {
    let mut k = [id; N];
    k[..MARK.len()].copy_from_slice(&MARK);
    k
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}

const IV: [u8; 12] = [7; 12];
const HEADER: [u8; 12] = [0x80, 0x6f, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
const PAYLOAD: [u8; 64] = [0x5a; 64];

#[cfg_attr(all(target_os = "linux", target_env = "gnu"), test)]
fn an_aes_128_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = crate::crypto::provider();
    let gcm = SrtpProvider::aead_aes_128_gcm(p.srtp_provider);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let capture = native::Capture::start(1, 16);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let mut seal = busbar_contract::abi::sdk::aead::test_support::with_owned_state_observer(
        native::register_state,
        || SupportedAeadAes128Gcm::create_cipher(gcm, key::<16>(1), true),
    );
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let mut seal = SupportedAeadAes128Gcm::create_cipher(gcm, key::<16>(1), true);
    let mut sealed = [0_u8; PAYLOAD.len() + 16];
    AeadAes128GcmCipher::encrypt(&mut *seal, &IV, &HEADER, &PAYLOAD, &mut sealed)
        .expect("the key seals");
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let size = std::mem::size_of_val(&*seal);
        register(
            std::ptr::from_ref(&*seal).cast::<()>().addr(),
            size,
            size,
            1,
            16,
        );
    }
    drop(std::hint::black_box(seal));
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    all_freed(1);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    capture.finish_key();
}

#[cfg_attr(all(target_os = "linux", target_env = "gnu"), test)]
fn an_aes_256_gcm_session_key_is_zeroised_when_its_cipher_drops() {
    let p = crate::crypto::provider();
    let gcm = SrtpProvider::aead_aes_256_gcm(p.srtp_provider);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let capture = native::Capture::start(2, 32);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let mut open = busbar_contract::abi::sdk::aead::test_support::with_owned_state_observer(
        native::register_state,
        || SupportedAeadAes256Gcm::create_cipher(gcm, key::<32>(2), false),
    );
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let mut open = SupportedAeadAes256Gcm::create_cipher(gcm, key::<32>(2), false);

    let mut out = [0_u8; PAYLOAD.len() + 16];
    assert!(AeadAes256GcmCipher::decrypt(
        &mut *open,
        &IV,
        &[&HEADER],
        &[0_u8; PAYLOAD.len() + 16],
        &mut out
    )
    .is_err());
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let size = std::mem::size_of_val(&*open);
        register(
            std::ptr::from_ref(&*open).cast::<()>().addr(),
            size,
            size,
            2,
            32,
        );
    }
    drop(std::hint::black_box(open));
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    all_freed(2);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    capture.finish_key();
}

#[cfg_attr(all(target_os = "linux", target_env = "gnu"), test)]
fn red_arm_a_session_key_in_a_plain_vec_is_seen_freed_unzeroed() {
    let plain: Vec<u8> = key::<16>(3).to_vec();
    register_payload(&plain, plain.capacity(), 3, 16);
    drop(std::hint::black_box(plain));
    all_freed(3);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    assert!(
        freed_unzeroed(3) >= 1,
        "the witness must see a session key freed without zeroising"
    );
    let held = zeroize::Zeroizing::new(key::<16>(4).to_vec());
    register_payload(&held, held.capacity(), 4, 16);
    drop(std::hint::black_box(held));
    all_freed(4);
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    assert_eq!(freed_unzeroed(4), 0);
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[test]
fn aes_128_provider_behavior_only_without_gnu_linux_wipe_proof() {
    an_aes_128_gcm_session_key_is_zeroised_when_its_cipher_drops();
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[test]
fn aes_256_provider_behavior_only_without_gnu_linux_wipe_proof() {
    an_aes_256_gcm_session_key_is_zeroised_when_its_cipher_drops();
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[test]
fn owning_vec_free_behavior_only_without_gnu_linux_wipe_proof() {
    red_arm_a_session_key_in_a_plain_vec_is_seen_freed_unzeroed();
}
