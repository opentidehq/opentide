//! The parser's trees as snapshots: a few hand-picked queries and one tree
//! per corpus file, valid and invalid alike.

use opentide_lucene::debug_parse;

#[test]
fn trees() {
    insta::assert_snapshot!(
        "detection",
        debug_parse(
            "event.category:process AND NOT process.name:(\"cmd.exe\" OR power*) AND source.port:[1024 TO *]"
        )
    );
    insta::assert_snapshot!(
        "modifiers_and_suffixes",
        debug_parse("+a -b !c NOT d (e f)^2 g~1^3 \"h i\"~2 /j\\/k/^4")
    );
    insta::assert_snapshot!(
        "operators_after_a_clause_only",
        debug_parse("&& a && b || c &&:d")
    );
    insta::assert_snapshot!(
        "range_bounds",
        debug_parse("a:[ 1 TO 2] b:{\"x y\" TO z}^2 c:[TO TO TO]")
    );
    insta::assert_snapshot!("a_tab_glues_to_the_bound", debug_parse("a:[1\tTO 2]"));
    insta::assert_snapshot!("unclosed", debug_parse("a:(b OR c"));
    insta::assert_snapshot!("stray_closers", debug_parse("a) b] c} AND OR"));
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/lucene", "*.lucene", |path| {
        let text = std::fs::read_to_string(path).expect("a corpus file");
        // The first line tags the fixture.
        let source: Vec<&str> = text.lines().skip(1).collect();
        insta::assert_snapshot!(debug_parse(&source.join("\n")));
    });
}
