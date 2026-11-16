//! Helpers the SPL parser's corpus tests share.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions; each test file uses some"
)]
// Each test binary compiles this module and uses a different subset of it,
// so an expectation would be unfulfilled in some binaries (crates/AGENTS.md).
#![allow(dead_code)]

use opentide_core::LanguageId;
use opentide_parse::{debug_errors, debug_tree};
use opentide_spl::syntax::{Lang, SyntaxKind, parse};
use std::path::{Path, PathBuf};

pub fn body(path: &Path) -> String {
    let text = std::fs::read_to_string(path).expect("read");
    if path.components().any(|c| c.as_os_str() == "corpus") {
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    } else {
        text
    }
}

pub fn render(source: &str) -> String {
    let (tree, parse) = parse(source);
    assert_eq!(tree.to_string(), source, "lossless");
    let mut out = debug_tree(&tree, |k: SyntaxKind| format!("{k:?}"));
    out.push_str("--\n");
    out.push_str(&debug_errors(&parse.errors, |k| {
        format!("{:?}", <Lang as rowan::Language>::kind_from_raw(k))
    }));
    out
}

pub fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "spl") {
            out.push(path);
        }
    }
}

pub fn old_accepts(source: &str) -> bool {
    let tree = opentide_syntax::parse(LanguageId::Spl, source).expect("parser");
    !opentide_syntax::has_error(&tree)
}
