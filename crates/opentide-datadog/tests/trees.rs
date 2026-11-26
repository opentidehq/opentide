//! The parser's trees as snapshots: a few hand-picked queries, and one tree per corpus file,
//! valid and invalid alike. A corpus file's first line is its `prod:` tag, not part of the query.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_datadog::debug_tree;

#[test]
fn trees() {
    insta::assert_snapshot!("precedence", debug_tree("a OR b c AND d OR -e"));
    insta::assert_snapshot!(
        "fields",
        debug_tree(r#"@evt.outcome:FAILURE source:okta #d:>1 *:hi *:* "q.f":x @u.first\ name:al*"#)
    );
    insta::assert_snapshot!(
        "values",
        debug_tree("@code:(>=400 <500) env:(a OR b c) @x:[1 TO 5} @t:-* @p:\"a b\" @d:>-1.5E3")
    );
    insta::assert_snapshot!(
        "cidr",
        debug_tree("NOT(CIDR(@network.client.ip, 10.0.0.0/8, fc00::/7))")
    );
    insta::assert_snapshot!("unclosed", debug_tree("(a:b AND (c:(d OR e)"));
    insta::assert_snapshot!("stray", debug_tree("a:b) AND : c"));
    insta::assert_snapshot!("modifiers", debug_tree("--a NOT NOT b"));
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/datadog", "*.datadog", |path| {
        let text = std::fs::read_to_string(path).expect("a corpus file");
        let body: Vec<&str> = text.lines().skip(1).collect();
        insta::assert_snapshot!(debug_tree(&body.join("\n")));
    });
}
