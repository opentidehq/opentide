//! The parser over every YARA-L file of the corpora: the tree is lossless,
//! the verdict is tree-sitter's (a valid file has no error, a broken one has
//! one) and a valid file's tree conforms to `yaral.ungram`.

use opentide_core::LanguageId;
use opentide_yaral::parse_facts::{conformance, parse_error_count, parse_is_lossless};
use std::path::{Path, PathBuf};

/// Every `.yaral` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaral") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

#[test]
fn every_corpus_file_gets_the_verdict_of_tree_sitter() {
    let files = corpus();
    assert!(files.len() > 200, "{} files", files.len());
    let (mut valid, mut broken) = (0, 0);
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let name = path.display();
        assert!(parse_is_lossless(&source), "{name} is not lossless");
        let old = opentide_syntax::parse(LanguageId::Yaral, &source)
            .is_some_and(|tree| tree.root_node().has_error());
        let errors = parse_error_count(&source);
        assert_eq!(
            old,
            errors > 0,
            "{name}: {errors} errors here, tree-sitter {old}"
        );
        if errors == 0 {
            valid += 1;
            let misfits = conformance(&source);
            assert!(misfits.is_empty(), "{name} does not conform: {misfits:?}");
        } else {
            broken += 1;
        }
    }
    assert!(valid > 150 && broken > 50, "{valid} valid, {broken} broken");
}
