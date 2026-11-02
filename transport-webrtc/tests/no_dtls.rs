// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DTLS runs outside the framer.

use std::path::{Path, PathBuf};

/// The DTLS engines: no file here may name one.
const ENGINES: [&str; 8] = [
    "dimpl",
    "rustls",
    "openssl",
    "boring",
    "webrtc_dtls",
    "webrtc-dtls",
    "mbedtls",
    "wolfssl",
];

/// The one file allowed to name the media stack's DTLS interface.
const SHIM: &str = "shim.rs";

/// This crate's directory: the framer whose source is scanned.
fn crate_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// The line without its comment (`//` for Rust, `#` for a manifest).
fn code(line: &str, comment: &str) -> String {
    line.split(comment)
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// What `path` (relative to its crate) names that it may not.
fn findings(path: &str, text: &str) -> Vec<String> {
    let manifest = path.ends_with(".toml");
    let comment = if manifest { "#" } else { "//" };
    let file = path.rsplit('/').next().unwrap_or(path);
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = code(line, comment);
        for engine in ENGINES {
            if code.contains(engine) {
                out.push(format!(
                    "{path}:{}: names the DTLS engine `{engine}`",
                    n + 1
                ));
            }
        }
        if !manifest && file != SHIM && code.contains("dtls") {
            out.push(format!(
                "{path}:{}: names DTLS outside the shim: {}",
                n + 1,
                line.trim()
            ));
        }
    }
    out
}

/// Every shipped source file under `dir/src` (the crate's own `src/tests/` aside: tests name

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
    let mut out = vec![(
        "Cargo.toml".to_owned(),
        std::fs::read_to_string(dir.join("Cargo.toml")).expect("the manifest"),
    )];
    walk(&dir.join("src"), "src", &mut out);
    out
}

fn scan(files: &[(String, String)]) -> Vec<String> {
    files.iter().flat_map(|(p, t)| findings(p, t)).collect()
}

#[test]
fn the_framer_source_names_no_dtls_type() {
    let files = shipped(&crate_dir());
    assert!(files.len() > 1, "the source is read");
    let found = scan(&files);
    assert!(found.is_empty(), "{}", found.join("\n"));

    let shim = shipped(&crate_dir())
        .into_iter()
        .find(|(p, _)| p == "src/shim.rs")
        .expect("src/shim.rs");
    assert!(shim.1.contains("impl DtlsInstance for Shim"));
}

#[test]
fn red_arm_an_engine_in_the_shim_or_the_manifest_is_refused() {
    let found = findings("src/shim.rs", "use dimpl::{Config, Dtls};\n");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("`dimpl`"));
    let found = findings(
        "Cargo.toml",
        "[dependencies]\nrustls = { workspace = true } # a second secure layer\n",
    );
    assert_eq!(found.len(), 1, "{found:?}");

    assert!(findings(
        "src/framing.rs",
        "// unlike dimpl, nothing here handshakes\n"
    )
    .is_empty());
}

#[test]
fn red_arm_the_dtls_interface_outside_the_shim_is_refused() {
    for (path, line) in [
        ("src/framing.rs", "use str0m::crypto::dtls::DtlsInstance;"),
        ("src/door.rs", "let cert: DtlsCert = todo!();"),
        ("src/crypto.rs", "impl DtlsProvider for Ring {}"),
    ] {
        let found = findings(path, line);
        assert_eq!(found.len(), 1, "{path}: {found:?}");
        assert!(found[0].contains("outside the shim"));
    }

    assert!(findings("src/shim.rs", "use str0m::crypto::dtls::DtlsInstance;").is_empty());
}
