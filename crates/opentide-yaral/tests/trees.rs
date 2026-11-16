//! The parser's trees as snapshots: one tree per file of the small corpus,
//! valid and invalid alike.

use opentide_yaral::debug_parse;

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/yaral", "*.yaral", |path| {
        let source = std::fs::read_to_string(path).expect("a corpus file");
        insta::assert_snapshot!(debug_parse(&source));
    });
}
