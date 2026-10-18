// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER HOLDS NO PROCESS-GLOBAL STATE (THE DESIGN §2: "A plugin holds no process-global
//! state: what it keeps is per-instance ... The one owner-approved per-thread slot is the door's
//! log-capture slot, macro-expanded into each plugin"). The log-capture slot is the door macro's,
//! expanded in the dropped-in crate; this crate's own source declares no `static`, no
//! `thread_local!` and no lazily-initialised global of any kind.
//!
//! THE RED ARMS, kept: each form, planted in a line of source, is refused; a `'static` lifetime and
//! a comment are not.

use std::path::{Path, PathBuf};

/// The forms a process-global or per-thread slot takes.
const FORMS: [&str; 6] = [
    "thread_local!",
    "OnceLock",
    "LazyLock",
    "OnceCell",
    "lazy_static!",
    "static ",
];

/// The line without its comment.
fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or_default()
}

/// What `text` (the source file `path`) declares that it may not.
fn findings(path: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = code(line);
        for form in FORMS {
            let hit = if form == "static " {
                // A `static` ITEM: the word at the start of the line or after a visibility, never
                // the `'static` lifetime.
                let t = code.trim_start();
                let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
                let t = t.strip_prefix("pub ").unwrap_or(t);
                t.starts_with("static ") || t.starts_with("static mut ")
            } else {
                code.contains(form)
            };
            if hit {
                out.push(format!("{path}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    out
}

/// Every shipped source file under `src` (the crate's own `src/tests/` aside).
fn shipped(dir: &Path) -> Vec<(String, String)> {
    fn walk(d: &Path, rel: &str, out: &mut Vec<(String, String)>) {
        for e in std::fs::read_dir(d).expect("readable") {
            let p = e.expect("an entry").path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let at = format!("{rel}/{name}");
            if p.is_dir() {
                if name != "tests" {
                    walk(&p, &at, out);
                }
            } else if name.ends_with(".rs") {
                out.push((at, std::fs::read_to_string(&p).expect("a source file")));
            }
        }
    }
    let mut out = Vec::new();
    walk(&dir.join("src"), "src", &mut out);
    out
}

fn crate_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

#[test]
fn the_framer_declares_no_static_and_no_per_thread_slot() {
    let files = shipped(&crate_dir());
    assert!(
        files.iter().any(|(p, _)| p == "src/shim.rs"),
        "the source is read"
    );
    let found: Vec<String> = files.iter().flat_map(|(p, t)| findings(p, t)).collect();
    assert!(
        found.is_empty(),
        "process-global or per-thread state in the framer:\n{}",
        found.join("\n")
    );
}

// ── THE RED ARMS ────────────────────────────────────────────────────────────────────────────────

#[test]
fn red_arm_every_form_is_refused() {
    for line in [
        "std::thread_local! { static P: Cell<u8> = const { Cell::new(0) }; }",
        "pub static HOST: Host = Host;",
        "static RING: Ring = Ring;",
        "pub(crate) static mut N: u8 = 0;",
        "static ONCE: OnceLock<u8> = OnceLock::new();",
        "let x: LazyLock<u8> = LazyLock::new(|| 1);",
    ] {
        assert!(!findings("src/x.rs", line).is_empty(), "{line}");
    }
    // A `'static` lifetime and a comment declare nothing.
    assert!(findings("src/x.rs", "fn f(&self) -> &'static dyn Tr { &Ring }").is_empty());
    assert!(findings("src/x.rs", "// no static and no thread_local! here").is_empty());
}
