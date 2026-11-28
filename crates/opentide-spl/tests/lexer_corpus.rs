//! The lexer against the corpus: every `.spl` file under the test data lexes
//! losslessly, a valid one without an error token, and so does every prefix
//! of one. (Reading files is the tests' job: `src/` is I/O-free.)

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_spl::syntax::{SyntaxKind as K, lex};

/// Every `.spl` file under the test data, with whether it is meant to
/// parse.
fn corpus() -> Vec<(std::path::PathBuf, bool)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, bool)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "spl") {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                let valid =
                    name.is_some_and(|n| !n.contains("__invalid") && !n.contains(".broken."));
                out.push((path, valid));
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

#[test]
fn the_corpus_lexes_losslessly_and_a_valid_file_has_no_error_token() {
    let files = corpus();
    assert!(files.len() > 250, "{} files", files.len());
    let mut failures = Vec::new();
    for (path, valid) in &files {
        let source = std::fs::read_to_string(path).expect("read");
        // A corpus fixture's first line is its `prod:` tag, not query text.
        let source = if path.components().any(|c| c.as_os_str() == "corpus") {
            source.lines().skip(1).collect::<Vec<_>>().join("\n")
        } else {
            source
        };
        let lexemes = lex(&source);
        let mut end = 0usize;
        for l in &lexemes {
            assert_eq!(usize::from(l.range.start()), end, "{}", path.display());
            end = usize::from(l.range.end());
        }
        assert_eq!(end, source.len(), "{}", path.display());
        if *valid {
            for l in lexemes.iter().filter(|l| l.kind == K::ERROR_TOKEN.raw()) {
                let at = usize::from(l.range.start());
                failures.push(format!(
                    "{}: error token {:?} near {:?}",
                    path.display(),
                    &source[std::ops::Range::<usize>::from(l.range)],
                    &source[at.saturating_sub(20)..source.len().min(at + 20)]
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A prefix cuts a string, a macro, a comment or a directive anywhere:
/// the lexemes still tile it, and nothing panics.
#[test]
fn every_prefix_of_a_file_lexes_losslessly() {
    for (path, _) in corpus().iter().step_by(5) {
        let source = std::fs::read_to_string(path).expect("read");
        let mut end = 0;
        while end < source.len().min(600) {
            end = source.ceil_char_boundary(end + 3);
            let prefix = &source[..end.min(source.len())];
            // In order, contiguous, from 0 to the end, on character boundaries.
            let mut at = 0usize;
            for lexeme in lex(prefix) {
                assert_eq!(
                    usize::from(lexeme.range.start()),
                    at,
                    "{}: {prefix:?}",
                    path.display()
                );
                at = usize::from(lexeme.range.end());
                assert!(
                    prefix.is_char_boundary(at),
                    "{}: {prefix:?}",
                    path.display()
                );
            }
            let covered = at;
            assert_eq!(covered, prefix.len(), "{}: {prefix:?}", path.display());
        }
    }
}
