//! The lexer against the corpus: every `.spl` file under the test data lexes
//! losslessly, a valid one without an error token, and where tree-sitter put
//! its token boundaries the lexer puts them. (Reading files is the tests'
//! job: `src/` is I/O-free.)

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

/// The byte ranges of the tree-sitter tree's leaves.
fn leaves(node: tree_sitter::Node<'_>, out: &mut Vec<(usize, usize)>) {
    if node.child_count() == 0 {
        if node.end_byte() > node.start_byte() {
            out.push((node.start_byte(), node.end_byte()));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        leaves(child, out);
    }
}

/// Where the old lexer put its token boundaries, the new one puts them,
/// on every file the old parser accepts. The known exceptions are
/// tokens the grammar glues from more than one of ours (the parser
/// does it): see `NOTES.md`.
#[test]
fn tokens_start_and_end_where_tree_sitters_do() {
    let mut mismatches = Vec::new();
    let (mut files, mut tokens) = (0, 0);
    for (path, valid) in corpus() {
        if !valid {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read");
        let source = if path.components().any(|c| c.as_os_str() == "corpus") {
            source.lines().skip(1).collect::<Vec<_>>().join("\n")
        } else {
            source
        };
        let Some(tree) = opentide_syntax::parse(opentide_core::LanguageId::Spl, &source) else {
            continue;
        };
        if opentide_syntax::has_error(&tree) {
            continue;
        }
        files += 1;
        let mut old = Vec::new();
        leaves(tree.root_node(), &mut old);
        let new: Vec<(usize, usize)> = lex(&source)
            .iter()
            .filter(|l| l.kind != K::WHITESPACE.raw())
            .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
            .collect();
        tokens += old.len();
        if old != new {
            let at = old
                .iter()
                .zip(&new)
                .position(|(a, b)| a != b)
                .unwrap_or(old.len().min(new.len()));
            let show = |v: &[(usize, usize)]| {
                v.get(at)
                    .map_or(String::from("-"), |&(a, b)| format!("{:?}", &source[a..b]))
            };
            mismatches.push(format!(
                "{}: token {at}: tree-sitter {}, here {}",
                path.display(),
                show(&old),
                show(&new)
            ));
        }
    }
    assert!(files > 150, "{files} files compared");
    assert!(
        mismatches.is_empty(),
        "{} of {files} files ({tokens} tokens) differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
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
