// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `alloc-counter` FEATURE IS NEVER ON IN A SHIPPED BUILD OF THIS PLUGIN (ARCHITECT ruling
//! 2026-10-21). busbar-contract's `alloc-counter` is the unit tests' counting allocator and freed-key
//! witness. Cargo features are additive and unify across a build graph, so one non-dev edge naming
//! it would compile the test allocator into the shipped cdylib. busbar's own
//! `crates/busbar-contract/tests/test_seal_is_dev_only.rs` reads busbar's manifests only; this test
//! reads this repo's: every `Cargo.toml` here may name `alloc-counter` only under a
//! `[dev-dependencies]` table (`[dev-dependencies.x]` and `[target.'cfg(..)'.dev-dependencies]`
//! included). `[dependencies]`, `[build-dependencies]`, `[features]` and
//! `[workspace.dependencies]` (whose features every inheriting edge takes, dev or not) are refused.
//!
//! THE RED ARMS, kept: each non-dev form, planted in a manifest text, is refused.

use std::path::{Path, PathBuf};

const FEATURE: &str = "alloc-counter";

/// This repo's root: the workspace this crate is a member of.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives one level under the repo root")
        .to_path_buf()
}

/// Every `Cargo.toml` under `dir`, build output and VCS metadata aside.
fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "vendor" || name == "node_modules" {
                continue;
            }
            manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// The table a manifest line sits under: the last `[header]` above it.
fn section_of(lines: &[&str], idx: usize) -> String {
    lines[..=idx]
        .iter()
        .rev()
        .find_map(|l| {
            let t = l.trim();
            (t.starts_with('[') && t.ends_with(']')).then(|| t.to_string())
        })
        .unwrap_or_else(|| "<no section>".to_string())
}

/// `[dev-dependencies]`, `[dev-dependencies.x]` and `[target.'cfg(..)'.dev-dependencies]`.
fn is_dev_section(section: &str) -> bool {
    let inner = section.trim_start_matches('[').trim_end_matches(']');
    inner
        .split('.')
        .any(|seg| seg.trim_matches(|c| c == '\'' || c == '"') == "dev-dependencies")
}

/// Each line of `text` (the manifest `label`) naming the feature outside a dev-only table, and how
/// many dev edges name it.
fn offenders_in(label: &str, text: &str) -> (Vec<String>, usize) {
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    let lines: Vec<&str> = text.lines().collect();
    for (n, line) in lines.iter().enumerate() {
        let code = line.split('#').next().unwrap_or_default();
        if !code.contains(FEATURE) {
            continue;
        }
        let section = section_of(&lines, n);
        if is_dev_section(&section) {
            dev_edges += 1;
            continue;
        }
        offenders.push(format!(
            "{label}:{} under {section} -> {}",
            n + 1,
            line.trim()
        ));
    }
    (offenders, dev_edges)
}

#[test]
fn alloc_counter_is_named_only_on_dev_dependency_edges() {
    let root = repo_root();
    let mut found = Vec::new();
    manifests(&root, &mut found);
    assert!(
        found.len() >= 3,
        "the manifest walk found {} Cargo.toml files under {}: the workspace root and its two \
         members at least, or the walk is broken",
        found.len(),
        root.display()
    );
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    for manifest in &found {
        let text = std::fs::read_to_string(manifest).expect("a readable manifest");
        let label = manifest
            .strip_prefix(&root)
            .unwrap_or(manifest)
            .display()
            .to_string();
        let (o, d) = offenders_in(&label, &text);
        offenders.extend(o);
        dev_edges += d;
    }
    assert!(
        offenders.is_empty(),
        "`{FEATURE}` is named outside [dev-dependencies]: that compiles busbar-contract's test \
         allocator into the shipped plugin. Move these to [dev-dependencies]:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        dev_edges > 0,
        "no manifest names `{FEATURE}` on a dev edge: the unit tests' allocator is gone (then \
         delete this test) or the scan stopped matching (then fix the scan)"
    );
}

// ── THE RED ARMS ────────────────────────────────────────────────────────────────────────────────

#[test]
fn red_arm_every_non_dev_table_is_refused() {
    for text in [
        "[dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
        "[dependencies.busbar-contract]\nworkspace = true\nfeatures = [\"alloc-counter\"]\n",
        "[build-dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
        "[target.'cfg(unix)'.dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
        "[features]\ndefault = [\"busbar-contract/alloc-counter\"]\n",
        "[workspace.dependencies]\nbusbar-contract = { git = \"x\", features = [\"alloc-counter\"] }\n",
        "[dev-dependencies]\nx = \"1\"\n[dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
    ] {
        let (offenders, _) = offenders_in("Cargo.toml", text);
        assert_eq!(offenders.len(), 1, "{text}");
    }
}

#[test]
fn green_arm_dev_tables_and_comments_are_not_offenders() {
    for text in [
        "[dev-dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
        "[dev-dependencies.busbar-contract]\nworkspace = true\nfeatures = [\"alloc-counter\"]\n",
        "[target.'cfg(unix)'.dev-dependencies]\nbusbar-contract = { workspace = true, features = [\"alloc-counter\"] }\n",
    ] {
        let (offenders, dev_edges) = offenders_in("Cargo.toml", text);
        assert!(offenders.is_empty(), "{text}: {offenders:?}");
        assert_eq!(dev_edges, 1, "{text}");
    }
    let (offenders, dev_edges) = offenders_in(
        "Cargo.toml",
        "[dependencies]\n# never alloc-counter here\nx = \"1\"\n",
    );
    assert!(offenders.is_empty() && dev_edges == 0);
}
