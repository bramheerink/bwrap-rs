//! Guardrail: the raw-fd escape hatches must stay quarantined in `bwrap-sys`.
//!
//! The fd-ownership table ([`bwrap_sys::fd::FdTable`]) is the only sanctioned way
//! for the upper, `#![forbid(unsafe_code)]` crates to touch an inherited
//! descriptor. If `borrow_raw`, `close_raw` or a bare `from_raw_fd`/`borrow_raw`
//! reappears in `bwrap-core` or `bwrap-cli`, a borrow could again outlive its fd
//! or a number could be closed twice — so fail the build loudly instead.

use std::path::Path;

/// Tokens that must not appear in the safe crates' sources.
const FORBIDDEN: &[&str] = &["borrow_raw", "close_raw", "from_raw_fd"];

fn scan_dir(dir: &Path, hits: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan_dir(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for (lineno, line) in text.lines().enumerate() {
                for tok in FORBIDDEN {
                    if line.contains(tok) {
                        hits.push(format!(
                            "{}:{}: {}",
                            path.display(),
                            lineno + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn safe_crates_have_no_raw_fd_escape_hatch() {
    // CARGO_MANIFEST_DIR is crates/bwrap-cli; the two safe crates' sources are
    // this crate's src and the sibling bwrap-core's src.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli_src = manifest.join("src");
    let core_src = manifest.join("..").join("bwrap-core").join("src");

    let mut hits = Vec::new();
    scan_dir(&cli_src, &mut hits);
    scan_dir(&core_src, &mut hits);

    assert!(
        hits.is_empty(),
        "raw-fd escape hatch found outside bwrap-sys — route it through \
         bwrap_sys::fd::FdTable instead:\n{}",
        hits.join("\n")
    );
}
