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
    insta::assert_snapshot!("unclosed", debug_parse("(a:b AND (c:(d, e)"));
    insta::assert_snapshot!("stray_paren", debug_parse("a:b) AND c"));
    insta::assert_snapshot!("unclosed_quote", debug_parse("a:\"b AND c:d"));
}

#[test]
fn corpus_trees() {
    // The filter rules; the statement rules come with the next PR of #1223.
    let filters = "{and_expression,call,context_term,field_term,free_text,group,list,not_expression,or_expression,range}__*.exabeam";
    insta::glob!("../../testdata/corpus/exabeam", filters, |path| {
        let text = std::fs::read_to_string(path).expect("a corpus file");
        let body: Vec<&str> = text.lines().skip(1).collect();
        insta::assert_snapshot!(debug_parse(&body.join("\n")));
    });
}
