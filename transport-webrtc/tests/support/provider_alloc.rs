// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GNU/Linux integration-test executable hooks below the provider's default allocator.
//! No OPENSSL allocator callback or private allocation-header layout is used.
//!
//! During capture, malloc fills its entire requested span with a nonzero sentinel before
//! returning it. This initializes alignment/padding bytes without knowing any native layout.
//! Nothing writes the allocation in the observer or deallocator: the real provider must clear
//! that whole span before its actual downstream free. A key-only wipe control retains the
//! sentinel outside its key, so it cannot masquerade as whole-allocation cleansing.
//!
//! In aws-lc-sys 0.47.0, crypto/fipsmodule/cipher/cipher.c initializes the context with
//! OPENSSL_zalloc and allocates cipher_data with OPENSSL_malloc. The selected AES-GCM path in
//! e_aes.c writes fields, expands the initialized input key, zeroes GCM128_CONTEXT, and copies
//! only initialized IV/tag/input bytes. It never calls EVP_CIPHER_CTX_copy/EVP_CTRL_COPY, which
//! would need a separate initialization argument. The fixed 12-byte IV uses the context's own
//! initialized IV array. Its unused alignment bytes retain the malloc sentinel until cleanup.

use std::cell::Cell;
use std::ffi::{c_int, c_void};

use zeroize::{Zeroize as _, Zeroizing};

use super::{key, LONGEST, MARK, READ_CHUNK_LEN};

const CAPTURED_ALLOCATION_SLOTS: usize = 64;
const PROVIDER_ALLOCATION_COUNT: usize = 2;
const ALLOCATION_SENTINEL: u8 = 0xa5;
const CONTROL_KEY_LEN: usize = 16;
const CONTROL_TAIL_LEN: usize = MARK.len();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Kind {
    #[default]
    Unused,
    Context,
    CipherData,
    Control,
}

#[derive(Clone, Copy, Default)]
struct Allocation {
    // Retain the allocator's actual raw pointer, never reconstruct one from its address.
    base: *mut u8,
    size: usize,
    live: bool,
}

#[derive(Clone, Copy, Default)]
struct Watched {
    allocation: Allocation,
    kind: Kind,
    frees: usize,
    complete: bool,
    all_zero: bool,
    marked: bool,
}

#[derive(Clone, Copy)]
struct Trace {
    active: bool,
    id: u8,
    key_len: usize,
    allocations: [Allocation; CAPTURED_ALLOCATION_SLOTS],
    watched: [Watched; PROVIDER_ALLOCATION_COUNT],
    overflow: bool,
    wrong_size: bool,
    invalid_span: bool,
    free_calls: usize,
    sized_free_calls: usize,
}

impl Trace {
    const EMPTY: Self = Self {
        active: false,
        id: 0,
        key_len: 0,
        allocations: [Allocation {
            base: std::ptr::null_mut(),
            size: 0,
            live: false,
        }; CAPTURED_ALLOCATION_SLOTS],
        watched: [Watched {
            allocation: Allocation {
                base: std::ptr::null_mut(),
                size: 0,
                live: false,
            },
            kind: Kind::Unused,
            frees: 0,
            complete: false,
            all_zero: false,
            marked: false,
        }; PROVIDER_ALLOCATION_COUNT],
        overflow: false,
        wrong_size: false,
        invalid_span: false,
        free_calls: 0,
        sized_free_calls: 0,
    };
}

thread_local! {
    // Constant-initialized, destructor-free TLS: allocator hooks never allocate metadata.
    static TRACE: Cell<Trace> = const { Cell::new(Trace::EMPTY) };
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

unsafe extern "C" {
    fn __libc_malloc(size: usize) -> *mut c_void;
    fn __libc_free(ptr: *mut c_void);
}

fn in_hook(action: impl FnOnce(&mut Trace)) {
    let _ = IN_HOOK.try_with(|guard| {
        if guard.replace(true) {
            return;
        }
        let _ = TRACE.try_with(|slot| {
            let mut trace = slot.get();
            if trace.active {
                action(&mut trace);
                slot.set(trace);
            }
        });
        guard.set(false);
    });
}

// SAFETY: this test executable's GNU libc interposition preserves malloc's ABI and
// delegates allocation to glibc itself. During a capture the returned, uniquely owned raw
// allocation is initialized before its caller can use it; metadata remains bounded.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    // SAFETY: forward malloc's request unchanged to its non-interposed glibc entry.
    let ptr = unsafe { __libc_malloc(size) };
    if !ptr.is_null() {
        in_hook(|trace| {
            if size > isize::MAX as usize {
                trace.invalid_span = true;
                return;
            }
            if let Some(entry) = trace.allocations.iter_mut().find(|entry| !entry.live) {
                // SAFETY: this is the fresh nonnull malloc result, still uniquely owned by
                // this hook. Exactly the requested bytes, including padding later left by
                // the native object, become initialized. No typed object exists here yet.
                unsafe { ptr.cast::<u8>().write_bytes(ALLOCATION_SENTINEL, size) };
                *entry = Allocation {
                    base: ptr.cast(),
                    size,
                    live: true,
                };
            } else {
                trace.overflow = true;
            }
        });
    }
    ptr
}

#[derive(Clone, Copy)]
struct Observation {
    all_zero: bool,
    marked: bool,
    provider_state: bool,
}

// SAFETY: the caller supplies a live allocation pointer and an entirely initialized span
// within its original malloc request. Live registration derives it only from the saved
// allocator pointer; deallocation supplies the current free/sdallocx parameter itself.
unsafe fn observe(trace: &Trace, pointer: *const u8, len: usize) -> Observation {
    let mut chunk = Zeroizing::new([0_u8; READ_CHUNK_LEN + LONGEST - 1]);
    let mut offset = 0;
    let mut carried = 0;
    let mut observation = Observation {
        all_zero: true,
        marked: false,
        provider_state: false,
    };
    while offset < len {
        let take = (len - offset).min(READ_CHUNK_LEN);
        // SAFETY: offset + take stays within the caller's initialized live span; the
        // separate stack destination has take writable bytes after its overlap. Copying
        // through raw pointers forms no reference to the native object's representation.
        unsafe {
            pointer
                .add(offset)
                .copy_to_nonoverlapping(chunk[carried..].as_mut_ptr(), take);
        }
        let total = carried + take;
        observation.all_zero &= chunk[carried..total].iter().all(|byte| *byte == 0);
        observation.provider_state |= chunk[carried..total]
            .iter()
            .any(|byte| *byte != 0 && *byte != ALLOCATION_SENTINEL);
        observation.marked |= chunk[..total].windows(trace.key_len).any(|candidate| {
            candidate.starts_with(&MARK)
                && candidate[MARK.len()..].iter().all(|byte| *byte == trace.id)
        });
        carried = total.min(LONGEST - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += take;
    }
    observation
}

fn before_free(ptr: *mut c_void, size: Option<usize>) {
    if ptr.is_null() {
        return;
    }
    in_hook(|trace| {
        for index in 0..trace.watched.len() {
            let watched = trace.watched[index];
            if watched.kind == Kind::Unused || watched.allocation.base.addr() != ptr.addr() {
                continue;
            }
            if size.is_some_and(|size| size != watched.allocation.size) {
                trace.wrong_size = true;
            }
            let live = trace.allocations.iter().any(|allocation| {
                allocation.live
                    && allocation.base.addr() == ptr.addr()
                    && allocation.size == watched.allocation.size
            });
            // Never read a stale/reused allocation or trust the sized-free hint as bounds.
            // A mismatch is a failed witness, checked after forwarding to glibc.
            let observed = if live && watched.frees == 0 {
                // SAFETY: this is the current deallocation pointer before native free.
                // Matching live capture establishes its requested, initialized span.
                Some(unsafe { observe(trace, ptr.cast(), watched.allocation.size) })
            } else {
                trace.invalid_span = true;
                None
            };
            let target = &mut trace.watched[index];
            target.frees += 1;
            if let Some(observed) = observed {
                target.complete = true;
                target.all_zero = observed.all_zero;
                target.marked = observed.marked;
            }
            if size.is_some() {
                trace.sized_free_calls += 1;
            } else {
                trace.free_calls += 1;
            }
        }
        for entry in &mut trace.allocations {
            if entry.base.addr() == ptr.addr() {
                entry.live = false;
            }
        }
    });
}

// SAFETY: observation is completed before forwarding the exact allocation to glibc.
// No assertions, allocation, byte writes to the source, or unwinding occur here.
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    // SAFETY: GNU libc exposes this thread's errno cell; free must preserve errno.
    let saved_errno = unsafe { *libc::__errno_location() };
    before_free(ptr, None);
    // SAFETY: the caller's free contract is forwarded to the native allocator.
    unsafe {
        __libc_free(ptr);
        *libc::__errno_location() = saved_errno;
    }
}

// SAFETY: AWS-LC calls this optional downstream deallocator only after its own
// OPENSSL_free has cleansed the allocation. The malloc/free implementation is glibc;
// its free accepts that same allocation. The sized hint is checked, never trusted.
#[no_mangle]
pub unsafe extern "C" fn sdallocx(ptr: *mut c_void, size: usize, _flags: c_int) {
    // SAFETY: the same GNU libc errno preservation as the unsized free route.
    let saved_errno = unsafe { *libc::__errno_location() };
    before_free(ptr, Some(size));
    // SAFETY: no allocation ownership changed while its bytes were observed.
    unsafe {
        __libc_free(ptr);
        *libc::__errno_location() = saved_errno;
    }
}

pub struct Capture;

impl Capture {
    pub fn start(id: u8, key_len: usize) -> Self {
        assert!((MARK.len()..=LONGEST).contains(&key_len));
        // SAFETY: these terminated static symbol names are valid for dlsym.
        // Fail outside allocator hooks if another native allocator is interposed.
        unsafe {
            assert_eq!(
                libc::dlsym(libc::RTLD_NEXT, c"malloc".as_ptr()),
                __libc_malloc as *const () as *mut c_void,
                "native wipe witness requires GNU libc malloc with no other allocator interposer"
            );
            assert_eq!(
                libc::dlsym(libc::RTLD_NEXT, c"free".as_ptr()),
                __libc_free as *const () as *mut c_void,
                "native wipe witness requires GNU libc free with no other allocator interposer"
            );
        }
        TRACE.with(|slot| {
            assert!(!slot.get().active, "native allocation captures cannot nest");
            slot.set(Trace {
                active: true,
                id,
                key_len,
                ..Trace::EMPTY
            });
        });
        Self
    }

    pub fn finish_key(self) {
        let trace = TRACE.with(|slot| slot.replace(Trace::EMPTY));
        assert_eq!(
            trace.watched.map(|entry| entry.kind),
            [Kind::Context, Kind::CipherData],
            "observe both real owned provider allocations"
        );
        check_frees(&trace, true, false);
    }

    fn finish_control(self, zero: bool, marked: bool, sized: bool) {
        let trace = TRACE.with(|slot| slot.replace(Trace::EMPTY));
        assert_eq!(trace.watched[0].kind, Kind::Control);
        check_frees(&trace, zero, marked);
        if sized {
            assert_eq!(
                trace.sized_free_calls, 1,
                "the sdallocx route must actually run"
            );
        } else {
            assert_eq!(trace.free_calls, 1, "the free route must actually run");
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        TRACE.with(|slot| slot.set(Trace::EMPTY));
    }
}

fn check_frees(trace: &Trace, zero: bool, marked: bool) {
    assert!(
        !trace.overflow,
        "native allocation capture exhausted its metadata"
    );
    assert!(
        !trace.wrong_size,
        "sdallocx size must match the captured malloc request"
    );
    assert!(
        !trace.invalid_span,
        "every observation requires its live, initialized malloc span"
    );
    for watched in trace
        .watched
        .iter()
        .filter(|entry| entry.kind != Kind::Unused)
    {
        assert_eq!(
            watched.frees, 1,
            "each registered native allocation must actually be freed once"
        );
        assert!(
            watched.complete,
            "every actual free requires a complete read through its current pointer"
        );
        assert_eq!(
            watched.all_zero, zero,
            "inspect the entire captured native allocation"
        );
        assert_eq!(
            watched.marked, marked,
            "observe the expected full-key marker"
        );
    }
}

fn register(pointer: usize, kind: Kind) {
    TRACE.with(|slot| {
        let mut trace = slot.get();
        assert!(trace.active && !trace.overflow && !trace.invalid_span);
        let mut candidates = trace.allocations.iter().filter(|allocation| {
            allocation.live
                && pointer >= allocation.base.addr()
                && allocation
                    .base
                    .addr()
                    .checked_add(allocation.size)
                    .is_some_and(|end| pointer < end)
        });
        let allocation = *candidates.next().expect(
            "the actual SDK-owned pointer must belong to a captured native malloc allocation",
        );
        assert!(
            candidates.next().is_none(),
            "the owning allocation must be unique"
        );
        assert!(!trace
            .watched
            .iter()
            .any(|entry| entry.kind != Kind::Unused && entry.allocation.base == allocation.base));
        // Match the numeric SDK owner address while walking the actual saved allocator
        // pointer. No numeric address is ever converted to a pointer. Inspect from the real
        // owner onward, so allocator metadata cannot satisfy the live-state/key controls.
        let (owner, len) = (0..allocation.size)
            .find_map(|offset| {
                // SAFETY: offset remains strictly inside this live initialized allocation.
                let candidate = unsafe { allocation.base.add(offset) };
                (candidate.addr() == pointer).then_some((candidate, allocation.size - offset))
            })
            .expect("the owner address is inside its captured allocation");
        // SAFETY: owner was derived from the actual live allocator pointer; malloc
        // initialized its complete request before the provider initialized its own state.
        let observed = unsafe { observe(&trace, owner, len) };
        assert!(
            !observed.all_zero && observed.provider_state,
            "baseline must observe real nonzero state beyond the initialization sentinel"
        );
        if kind != Kind::Context {
            assert!(
                observed.marked,
                "baseline must find the full raw key in the actual key-state allocation"
            );
        }
        let entry = trace
            .watched
            .iter_mut()
            .find(|entry| entry.kind == Kind::Unused)
            .expect("one context and one cipher-data allocation");
        *entry = Watched {
            allocation,
            kind,
            ..Watched::default()
        };
        slot.set(trace);
    });
}

pub fn register_state(context: usize, cipher_data: usize) {
    register(context, Kind::Context);
    register(cipher_data, Kind::CipherData);
}

#[test]
fn native_free_controls_detect_plain_key_and_whole_allocation_wiping() {
    for wipe in [false, true] {
        let capture = Capture::start(3, CONTROL_KEY_LEN);
        // SAFETY: the captured raw allocation is initialized by malloc before return.
        // It stays owned through raw pointers, is optionally wiped, and is freed once.
        unsafe {
            let pointer = malloc(CONTROL_KEY_LEN).cast::<u8>();
            assert!(!pointer.is_null());
            pointer.copy_from_nonoverlapping(key::<CONTROL_KEY_LEN>(3).as_ptr(), CONTROL_KEY_LEN);
            register(pointer.addr(), Kind::Control);
            if wipe {
                std::slice::from_raw_parts_mut(pointer, CONTROL_KEY_LEN).zeroize();
            }
            free(pointer.cast());
        }
        capture.finish_control(wipe, !wipe, false);
    }
}

#[test]
fn native_sdallocx_controls_detect_plain_key_and_whole_allocation_wiping() {
    for wipe in [false, true] {
        let capture = Capture::start(4, CONTROL_KEY_LEN);
        // SAFETY: allocate exactly 16 bytes, initialize them all before registration,
        // optionally wipe that initialized buffer, and release it exactly once.
        unsafe {
            let pointer = malloc(CONTROL_KEY_LEN).cast::<u8>();
            assert!(!pointer.is_null());
            pointer.copy_from_nonoverlapping(key::<CONTROL_KEY_LEN>(4).as_ptr(), CONTROL_KEY_LEN);
            register(pointer.addr(), Kind::Control);
            if wipe {
                std::slice::from_raw_parts_mut(pointer, CONTROL_KEY_LEN).zeroize();
            }
            sdallocx(pointer.cast(), CONTROL_KEY_LEN, 0);
        }
        capture.finish_control(wipe, !wipe, true);
    }
}

#[test]
fn native_whole_span_control_rejects_wiping_only_the_key() {
    for sized in [false, true] {
        let capture = Capture::start(5, CONTROL_KEY_LEN);
        let len = CONTROL_KEY_LEN + CONTROL_TAIL_LEN;
        // SAFETY: the malloc hook initializes all len requested bytes before returning.
        // Write a live key, wipe just that key, and free the same allocation exactly once.
        // Its initialized nonzero tail is owned control data, never Vec spare capacity.
        unsafe {
            let pointer = malloc(len).cast::<u8>();
            assert!(!pointer.is_null());
            pointer.copy_from_nonoverlapping(key::<CONTROL_KEY_LEN>(5).as_ptr(), CONTROL_KEY_LEN);
            assert!(
                std::slice::from_raw_parts(pointer.add(CONTROL_KEY_LEN), CONTROL_TAIL_LEN)
                    .iter()
                    .all(|byte| *byte == ALLOCATION_SENTINEL)
            );
            register(pointer.addr(), Kind::Control);
            std::slice::from_raw_parts_mut(pointer, CONTROL_KEY_LEN).zeroize();
            if sized {
                sdallocx(pointer.cast(), len, 0);
            } else {
                free(pointer.cast());
            }
        }
        capture.finish_control(false, false, sized);
    }
}
