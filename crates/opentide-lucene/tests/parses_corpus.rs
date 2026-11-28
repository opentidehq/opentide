//! `parses` against the parse `analyze` runs, over the corpus and the
//! external sets and every prefix of each short text: `parses` rejects a
//! text from the grammar's events, without building its tree, and must say
//! what the tree's errors say (#1571, ADR 0014 §4). The engine crate reads
//! no file (`scripts/engine/check-io-free.sh`); this test reads the corpus.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use std::path::Path;

fn texts() -> Vec<String> {
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    let mut out = Vec::new();
    for dir in [
        "corpus/lucene",
        "conformance/external/lucene",
        "conformance/external/lucene-queryparser",
        "corpus/kuery",
    ] {
        let mut dirs = vec![testdata.join(dir)];
        while let Some(dir) = dirs.pop() {
            for path in std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
            {
                if path.is_dir() {
                    dirs.push(path);
                } else if let Ok(text) = std::fs::read_to_string(&path) {
                    out.extend(text.lines().map(str::to_owned).take(400));
                    out.push(text);
                }
            }
        }
    }
    let cut: Vec<String> = out
        .iter()
        .filter(|t| t.len() < 400)
        .flat_map(|t| {
            t.char_indices()
                .map(|(i, _)| t[..i].to_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    out.extend(cut);
    out
}

#[test]
fn parses_is_the_parse_without_errors_over_the_corpus() {
    let (mut accepted, mut rejected) = (0, 0);
    for source in texts() {
        let expected = opentide_lucene::parse_tree(&source) == 0;
        assert_eq!(opentide_lucene::parses(&source), expected, "{source:?}");
        if expected {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(
        accepted > 1_000 && rejected > 1_000,
        "{accepted} accepted, {rejected} rejected"
    );
}
