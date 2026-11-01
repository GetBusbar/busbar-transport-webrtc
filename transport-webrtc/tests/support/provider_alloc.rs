// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GNU/Linux integration-test executable hooks below the provider's default allocator.
//! No OPENSSL allocator callback or private allocation-header layout is used.

use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::fs::File;
use std::os::fd::AsRawFd;

use zeroize::{Zeroize as _, Zeroizing};

use super::{key, LONGEST, MARK};

#[derive(Clone, Copy, Default)]
struct Allocation {
    base: usize,
    size: usize,
    live: bool,
}

#[derive(Clone, Copy, Default)]
struct Watched {
    allocation: Allocation,
    kind: u8,
    frees: usize,
    complete: bool,
    all_zero: bool,
    marked: bool,
}

#[derive(Clone, Copy)]
struct Trace {
    active: bool,
    fd: c_int,
    id: u8,
    key_len: usize,
    allocations: [Allocation; 64],
    watched: [Watched; 2],
    overflow: bool,
    wrong_size: bool,
    free_calls: usize,
    sized_free_calls: usize,
}

impl Trace {
    const EMPTY: Self = Self {
        active: false,
        fd: -1,
        id: 0,
        key_len: 0,
        allocations: [Allocation {
            base: 0,
            size: 0,
            live: false,
        }; 64],
        watched: [Watched {
            allocation: Allocation {
                base: 0,
                size: 0,
                live: false,
            },
            kind: 0,
            frees: 0,
            complete: false,
            all_zero: false,
            marked: false,
        }; 2],
        overflow: false,
        wrong_size: false,
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
// delegates allocation to glibc itself. Recording touches only bounded metadata.
#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    // SAFETY: forward malloc's request unchanged to its non-interposed glibc entry.
    let ptr = unsafe { __libc_malloc(size) };
    if !ptr.is_null() {
        in_hook(|trace| {
            if let Some(entry) = trace.allocations.iter_mut().find(|entry| !entry.live) {
                *entry = Allocation {
                    base: ptr.addr(),
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
}

fn observe(trace: &Trace, allocation: Allocation) -> Option<Observation> {
    let mut chunk = Zeroizing::new([0_u8; 4096 + LONGEST - 1]);
    let mut offset = 0;
    let mut carried = 0;
    let mut observation = Observation {
        all_zero: true,
        marked: false,
    };
    while offset < allocation.size {
        let take = (allocation.size - offset).min(4096);
        let address = i64::try_from(allocation.base.checked_add(offset)?).ok()?;
        // SAFETY: the initialized destination has at least take writable bytes.
        // The source is only a numeric offset passed to the kernel; Rust never
        // forms a reference over the provider's opaque state or padding.
        let read = unsafe {
            libc::pread64(
                trace.fd,
                chunk[carried..].as_mut_ptr().cast(),
                take,
                address,
            )
        };
        if usize::try_from(read).ok()? != take {
            return None;
        }
        let total = carried + take;
        observation.all_zero &= chunk[carried..total].iter().all(|byte| *byte == 0);
        observation.marked |= chunk[..total].windows(trace.key_len).any(|candidate| {
            candidate.starts_with(&MARK)
                && candidate[MARK.len()..].iter().all(|byte| *byte == trace.id)
        });
        carried = total.min(LONGEST - 1);
        chunk.copy_within(total - carried..total, 0);
        offset += take;
    }
    Some(observation)
}

fn before_free(ptr: *mut c_void, size: Option<usize>) {
    if ptr.is_null() {
        return;
    }
    in_hook(|trace| {
        for index in 0..trace.watched.len() {
            let watched = trace.watched[index];
            if watched.kind == 0 || watched.allocation.base != ptr.addr() {
                continue;
            }
            if size.is_some_and(|size| size != watched.allocation.size) {
                trace.wrong_size = true;
            }
            let observed = observe(trace, watched.allocation);
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
            if entry.base == ptr.addr() {
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

pub struct Capture {
    _memory: File,
}

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
        let memory = File::open("/proc/self/mem")
            .expect("native wipe witness requires complete /proc/self/mem reads");
        TRACE.with(|slot| {
            assert!(!slot.get().active, "native allocation captures cannot nest");
            slot.set(Trace {
                active: true,
                fd: memory.as_raw_fd(),
                id,
                key_len,
                ..Trace::EMPTY
            });
        });
        Self { _memory: memory }
    }

    pub fn finish_key(self) {
        let trace = TRACE.with(|slot| slot.replace(Trace::EMPTY));
        assert_eq!(
            trace.watched.map(|entry| entry.kind),
            [1, 2],
            "observe both real owned provider allocations"
        );
        check_frees(&trace, true);
    }

    fn finish_control(self, zero: bool, sized: bool) {
        let trace = TRACE.with(|slot| slot.replace(Trace::EMPTY));
        assert_eq!(trace.watched[0].kind, 3);
        check_frees(&trace, zero);
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

fn check_frees(trace: &Trace, zero: bool) {
    assert!(
        !trace.overflow,
        "native allocation capture exhausted its metadata"
    );
    assert!(
        !trace.wrong_size,
        "sdallocx size must match the captured malloc request"
    );
    for watched in trace.watched.iter().filter(|entry| entry.kind != 0) {
        assert_eq!(
            watched.frees, 1,
            "each registered native allocation must actually be freed once"
        );
        assert!(
            watched.complete,
            "every actual free requires a complete OS read"
        );
        assert_eq!(
            watched.all_zero, zero,
            "inspect the entire captured native allocation"
        );
        if !zero {
            assert!(
                watched.marked,
                "negative control must retain the full key marker"
            );
        }
    }
}

fn register(pointer: usize, kind: u8) {
    TRACE.with(|slot| {
        let mut trace = slot.get();
        assert!(trace.active && !trace.overflow);
        let mut candidates = trace.allocations.iter().filter(|allocation| {
            allocation.live
                && pointer >= allocation.base
                && allocation
                    .base
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
            .any(|entry| entry.kind != 0 && entry.allocation.base == allocation.base));
        let observed =
            observe(&trace, allocation).expect("complete live OS read of the native allocation");
        assert!(
            !observed.all_zero,
            "baseline must observe live provider state"
        );
        if kind != 1 {
            assert!(
                observed.marked,
                "baseline must find the full raw key in the actual key-state allocation"
            );
        }
        let entry = trace
            .watched
            .iter_mut()
            .find(|entry| entry.kind == 0)
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
    register(context, 1);
    register(cipher_data, 2);
}

#[test]
fn native_free_controls_detect_plain_key_and_whole_allocation_wiping() {
    for wipe in [false, true] {
        let capture = Capture::start(3, 16);
        let mut payload = key::<16>(3).to_vec();
        register(payload.as_ptr().addr(), 3);
        if wipe {
            payload.zeroize();
        }
        drop(std::hint::black_box(payload));
        capture.finish_control(wipe, false);
    }
}

#[test]
fn native_sdallocx_controls_detect_plain_key_and_whole_allocation_wiping() {
    for wipe in [false, true] {
        let capture = Capture::start(4, 16);
        // SAFETY: allocate exactly 16 bytes, initialize them all before registration,
        // optionally wipe that initialized buffer, and release it exactly once.
        unsafe {
            let pointer = malloc(16).cast::<u8>();
            assert!(!pointer.is_null());
            pointer.copy_from_nonoverlapping(key::<16>(4).as_ptr(), 16);
            register(pointer.addr(), 3);
            if wipe {
                std::slice::from_raw_parts_mut(pointer, 16).zeroize();
            }
            sdallocx(pointer.cast(), 16, 0);
        }
        capture.finish_control(wipe, true);
    }
}
