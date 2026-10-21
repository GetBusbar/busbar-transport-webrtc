// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIT TESTS' ONE ALLOCATOR: busbar-contract's test-only `alloc-counter` (a dev-dependency
//! feature, ARCHITECT ruling 2026-10-21), which counts the hot-path gate's allocations and reads
//! every freed block for the zeroise gate's marked keys. Declared under `src/tests/`, the test
//! build's own tree, so the framer's shipped source declares no `static`
//! (`tests/no_process_global.rs`); this crate holds no `unsafe`.

#[global_allocator]
static A: busbar_contract::alloc_counter::Counting =
    busbar_contract::alloc_counter::Counting::new();
