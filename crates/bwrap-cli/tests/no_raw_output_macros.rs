//! Guard: production code must never use the bare `print!`/`println!`/
//! `eprint!`/`eprintln!` macros.
//!
//! Those macros panic when the write fails (e.g. output redirected to a full
//! disk or a closed pipe), and with `panic = "abort"` the panic becomes
//! `SIGABRT` (exit 134) — diverging from bubblewrap, which ignores the write
//! error and keeps its normal exit code. All diagnostics must go through
//! `bwrap_core::log::emit_err`/`emit_out`, which swallow write errors.
//!
//! This test scans every crate's `src/` tree. Test harnesses (under `tests/`)
//! may still print freely, so they are not scanned — that is exactly the
//! "grep returns only test code" condition from the audit.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/bwrap-cli.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above the crate")
        .to_path_buf()
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Drop line comments (`// …`, including `///` doc comments) so a macro *named*
/// in prose does not count as a use. Good enough for this guard: production
/// source does not embed `//` inside string literals on a macro-call line.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

#[test]
fn no_raw_output_macros_in_production_src() {
    let root = repo_root();
    let crates_dir = root.join("crates");

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates_dir)
        .expect("crates/ exists")
        .flatten()
    {
        let src = entry.path().join("src");
        if src.is_dir() {
            rs_files(&src, &mut files);
        }
    }
    assert!(
        !files.is_empty(),
        "found no production source files to scan"
    );

    // `print!` also matches `eprint!`; `println!` also matches `eprintln!`.
    const FORBIDDEN: [&str; 2] = ["print!", "println!"];

    let mut violations = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source file");
        for (n, raw) in text.lines().enumerate() {
            let code = strip_line_comment(raw);
            if FORBIDDEN.iter().any(|m| code.contains(m)) {
                let rel = file.strip_prefix(&root).unwrap_or(file);
                violations.push(format!("{}:{}: {}", rel.display(), n + 1, raw.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "production code must use bwrap_core::log::emit_err/emit_out instead of \
         raw print/eprint macros (they abort under panic=abort on a failed write):\n{}",
        violations.join("\n"),
    );
}
