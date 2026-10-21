// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ALLOCATOR of this crate's tests (the unit-test binary has exactly one
//! `#[global_allocator]`). It does two witnesses at once: it counts the allocations made on an armed
//! thread (`allocations`, the hot-path gate), and it reads every block freed for a marked key
//! (`freed_unzeroed`, the zeroise gate). `unsafe` is allowed in this module only.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

std::thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

pub(crate) const MARK: [u8; 8] = *b"ZEROISE!";
/// A key: the marker and 48 bytes of its id (the AEAD-AES-128-GCM material's 56 bytes).
pub(crate) const KEY_LEN: usize = 56;
const IDS: usize = 8;

static FREED_UNZEROED: [AtomicUsize; IDS] = [const { AtomicUsize::new(0) }; IDS];

/// The system allocator, counting what the armed thread asks for and reading every block it frees
/// for a marked key.
struct Witness;

/// The id of the marked key at the start of `w`, if one is there whole.
fn marked(w: &[u8]) -> Option<usize> {
    let (mark, rest) = w.split_at_checked(MARK.len())?;
    let id = *rest.first()?;
    (mark == MARK
        && rest.len() >= KEY_LEN - MARK.len()
        && rest[..KEY_LEN - MARK.len()].iter().all(|b| *b == id))
    .then_some(usize::from(id))
    .filter(|id| *id < IDS)
}

// SAFETY: every call is forwarded to `System` with its own arguments; the count is a plain
// per-thread cell, read and written without allocating, and `dealloc` only reads the block it is
// handed before forwarding.
unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ARMED.try_with(|a| {
            if a.get() {
                let _ = COUNT.try_with(|c| c.set(c.get() + 1));
            }
        });
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= KEY_LEN {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until `System` frees it below,
            // and its owner has given it up: nothing else reads or writes it during `dealloc`. It
            // is read as plain bytes and nothing read is kept.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            for at in 0..=block.len() - KEY_LEN {
                if block[at] == MARK[0] {
                    if let Some(id) = marked(&block[at..]) {
                        FREED_UNZEROED[id].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static WITNESS: Witness = Witness;

/// How many allocations `f` made on this thread.
pub(crate) fn allocations<R>(f: impl FnOnce() -> R) -> (usize, R) {
    COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    let r = f();
    ARMED.with(|a| a.set(false));
    (COUNT.with(Cell::get), r)
}

/// How many blocks marked with `id` were freed still holding the key.
pub(crate) fn freed_unzeroed(id: u8) -> usize {
    FREED_UNZEROED[usize::from(id)].load(Ordering::SeqCst)
}
