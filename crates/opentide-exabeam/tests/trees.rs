//! The parser's trees as snapshots: a few hand-picked queries and one tree
//! per corpus file, valid and invalid alike. A corpus file's first line is its
//! `prod:` tag, not part of the query.

use opentide_exabeam::debug_parse;

#[test]
fn trees() {
    insta::assert_snapshot!(
        "rule",
        debug_parse(
            r#"vendor:"Microsoft" AND event_code:("4625", 4771) NOT user IN "T"."C" OR web* time:[1 TO 5}"#
        )
    );
    insta::assert_snapshot!(
        "search",
        debug_parse(
            "SELECT count(*) AS n, user FROM logs WHERE a:rgx(\"x\") GROUP-BY user ORDER-BY n DESC LIMIT 10 | FOREACH user [a] LIMIT 2"
        )
    );
    insta::assert_snapshot!(
        "context_lexing",
        debug_parse("GROUP-BY a ASx | SELECT a LIMIT5 | a AND or OR SELECT")
    );
    insta::assert_snapshot!("unclosed", debug_parse("(a:b AND (c:(d, e)"));
    insta::assert_snapshot!("stray_paren", debug_parse("a:b) AND c"));
    insta::assert_snapshot!("unclosed_quote", debug_parse("a:\"b AND c:d"));
}

#[test]
fn corpus_trees() {
    insta::glob!("../../testdata/corpus/exabeam", "*.exabeam", |path| {
        let text = std::fs::read_to_string(path).expect("a corpus file");
        let body: Vec<&str> = text.lines().skip(1).collect();
        insta::assert_snapshot!(debug_parse(&body.join("\n")));
    });
}
