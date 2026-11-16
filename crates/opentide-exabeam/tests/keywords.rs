//! The parser's highlight captures against the `KEYWORDS` table
//! (`opentide_highlight::keywords`): each token of the table is highlighted
//! with its capture, and no keyword, operator, bracket or delimiter is
//! highlighted that the table (the TextMate grammar's input) does not list.

use opentide_core::LanguageId;
use opentide_exabeam::highlight_captures;
use opentide_highlight::keywords;

/// A query in which `token` stands where the grammar reads it.
fn sample(token: &str) -> &'static str {
    match token {
        "AND" | "OR" | "NOT" | "TO" | "IN" | ":" | "(" | ")" | "," | "." | "[" | "}" => {
            r#"a:(b, c) AND NOT d OR e IN "T"."C" f:[1 TO 2}"#
        }
        "==" | "<" | ">" | "<=" | ">=" | "=" | "{" | "]" => "a==b c<1 d>2 e<=3 f>=4 g={1 TO 2]",
        "SELECT" | "DISTINCT" | "FROM" | "WHERE" | "AS" | "GROUP-BY" | "ORDER-BY" | "ASC"
        | "DESC" | "LIMIT" | "FOREACH" | "|" => {
            "SELECT DISTINCT a FROM t WHERE b AS u GROUP-BY a ORDER-BY a ASC, b DESC LIMIT 1 | FOREACH a [b]"
        }
        other => panic!("no sample for the table token `{other}`"),
    }
}

#[test]
fn every_table_token_is_highlighted_with_its_capture() {
    let table = keywords(LanguageId::Exabeam).expect("exabeam has a KEYWORDS table");
    for (token, capture) in table {
        let source = sample(token);
        let spans = highlight_captures(source);
        assert!(
            spans
                .iter()
                .any(|(span, c)| &source[span.start..span.end] == *token && *c == capture.name()),
            "`{token}` in `{source}` is not a `{}` span: {spans:?}",
            capture.name()
        );
    }
}

#[test]
fn only_table_tokens_are_keywords_operators_or_punctuation() {
    let table = keywords(LanguageId::Exabeam).expect("exabeam has a KEYWORDS table");
    for source in [
        r#"(a:b OR c IN "T"."C") AND NOT d:[1 TO 2} e<=3 | SELECT count(*) AS n FROM t GROUP-BY a"#,
        "f:(1, @x) g==h i>j | FOREACH k [l] LIMIT 3",
    ] {
        for (span, capture) in highlight_captures(source) {
            let text = &source[span.start..span.end];
            let listed = ["keyword", "operator", "operator.pipe"].contains(&capture)
                || capture.starts_with("punctuation");
            if listed && text != "*" {
                assert!(
                    table
                        .iter()
                        .any(|(k, c)| k.eq_ignore_ascii_case(text) && c.name() == capture),
                    "`{text}` ({capture}) in `{source}` is not in the table"
                );
            }
        }
    }
}
