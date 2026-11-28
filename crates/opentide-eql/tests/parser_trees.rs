//! The parser's trees as snapshots: hand-picked queries, valid and broken, and one tree per
//! corpus file.

use opentide_eql::parser;

#[test]
fn trees() {
    for (name, source) in [
        (
            "detection",
            "sequence by host.id with maxspan=1m\n  [process where event.type == \"start\" and process.name : \"cmd.exe\"]\n  [network where startsWith~(process.name, \"cmd\")] | head 5",
        ),
        (
            "precedence",
            "any where not a or b and -c * d + e == f in (1, 2)",
        ),
        (
            "flat_chains",
            "any where a or b or c and d and e or f + g - h * i / j % k",
        ),
        (
            "predicates",
            "any where a not in~ (\"x\", y) and b : (\"c*\", null) and ?c.`d e`[0] regex~ \"f\"",
        ),
        (
            "lineage",
            "process where descendant of [process where true] and not child of [file where x]",
        ),
        (
            "sample_join_until",
            "sample by a [x where true] [y where true] | tail 1\n",
        ),
        (
            "join_until",
            "join [x where true] by k [y where true] until [z where true]",
        ),
        (
            "terms_and_options",
            "sequence with maxspan=5 by k ![x where true] with runs=3 [y where true] by j until [z where true]",
        ),
        (
            "comments",
            "/* a */ process // b\n where /* c /* d */ e */ true",
        ),
        ("comparison_is_not_associative", "process where a == b == c"),
        ("unclosed_paren", "process where (a == 1"),
        ("unclosed_subquery", "sequence [a where true] [b where true"),
        ("missing_where", "process a == 1"),
        ("missing_value", "process where a in ()"),
        ("not_after_comparison", "process where a == not b"),
        ("stray_close", "process where a == 1) | head 1"),
        ("empty_pipe", "process where true |"),
    ] {
        insta::assert_snapshot!(name, parser::debug(source));
    }
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/eql", "*.eql", |path| {
        let source = std::fs::read_to_string(path).expect("a corpus file");
        insta::assert_snapshot!(parser::debug(&source));
    });
}
