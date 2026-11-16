//! The parser's trees as snapshots: a few hand-picked queries and one tree
//! per corpus file, valid and invalid alike.

use opentide_kuery::debug_parse;

#[test]
fn trees() {
    insta::assert_snapshot!(
        "detection",
        debug_parse(
            "event.category:process and not process.name:(\"cmd.exe\" or power shell) and source.port >= 1024"
        )
    );
    insta::assert_snapshot!(
        "nested_and_group",
        debug_parse("(user:{ name:x or id:1 }) or a:1 and b:2 or not c")
    );
    insta::assert_snapshot!("trailing_keyword_is_a_value", debug_parse("f:(a or)"));
    insta::assert_snapshot!("unclosed", debug_parse("a:(b or c"));
    insta::assert_snapshot!("stray_paren", debug_parse("a:1) and b"));
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/kuery", "*.kuery", |path| {
        let source = std::fs::read_to_string(path).expect("a corpus file");
        insta::assert_snapshot!(debug_parse(&source));
    });
}
