//! `analyze_document` gives, for every file of the YARA corpus, what
//! `analyze` and `editor::symbols` give apart, from one AST (ADR 0014).

#[test]
fn a_document_analysis_is_the_two_calls_from_one_parse() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/corpus/yara");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    assert!(files.len() > 50);
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        #[cfg(debug_assertions)]
        let before = opentide_yara::asts_built();
        let (result, symbols) = opentide_yara::analyze_document(&source);
        #[cfg(debug_assertions)]
        assert_eq!(
            opentide_yara::asts_built() - before,
            1,
            "{}",
            path.display()
        );
        let apart = opentide_yara::analyze(&source);
        assert_eq!(result.diagnostics, apart.diagnostics, "{}", path.display());
        assert_eq!(result.tokens, apart.tokens, "{}", path.display());
        assert_eq!(
            symbols,
            opentide_yara::editor::symbols(&source),
            "{}",
            path.display()
        );
    }
}
