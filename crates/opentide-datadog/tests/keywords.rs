//! The engine's highlight captures against the `KEYWORDS` table
//! (`opentide_highlight::keywords`): each token of the table is highlighted with its capture
//! where the grammar reads it, and no keyword, operator, bracket or delimiter is highlighted
//! that the table (the TextMate grammar's input) does not list. `AND`, `OR` and `NOT` are the
//! TextMate grammar's `tm_extras:logical` rule, as Lucene's are.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::LanguageId;
use opentide_highlight::{HighlightSpec, keywords};

const LOGICAL: [&str; 3] = ["AND", "OR", "NOT"];

/// `(text, capture)` of each highlight token of `source`.
fn captures(source: &str) -> Vec<(String, String)> {
    let spec = HighlightSpec::shared().expect("the spec");
    opentide_datadog::highlight(spec, source)
        .into_iter()
        .map(|t| (source[t.span.start..t.span.end].to_owned(), t.capture))
        .collect()
}

/// A query in which `token` stands where the grammar reads it.
fn sample(token: &str) -> &'static str {
    match token {
        "TO" | "[" | "]" | "{" | "}" | ":" => "@a:[1 TO 5] @b:{1 TO 5}",
        "CIDR" | "(" | ")" | "," => "CIDR(@ip, 10.0.0.0/8, fc00::/7)",
        ">" | ">=" | "<" | "<=" => "@a:>1 @b:>=2 @c:<3 @d:<=4",
        "-" | "*" | "?" => "-@a:* b?c",
        other => panic!("no sample for the table token `{other}`"),
    }
}

#[test]
fn every_table_token_is_highlighted_with_its_capture() {
    let table = keywords(LanguageId::Datadog).expect("datadog has a KEYWORDS table");
    for (token, capture) in table {
        let source = sample(token);
        let found = captures(source);
        assert!(
            found
                .iter()
                .any(|(text, c)| text == token && c == capture.name()),
            "`{token}` in `{source}` is not a `{}` token: {found:?}",
            capture.name()
        );
    }
}

#[test]
fn only_table_tokens_are_keywords_operators_or_punctuation() {
    let table = keywords(LanguageId::Datadog).expect("datadog has a KEYWORDS table");
    for source in [
        "(source:okta OR -@a:*) AND NOT @b:[1 TO 5} CIDR(@ip, 10.0.0.0/8) @c:>=1 d?e*",
        "env:(a OR b) @x:(>=400 <500) *:* *:hi #calc:>1 \"p\" a && b || c",
    ] {
        for (text, capture) in captures(source) {
            let listed = ["keyword", "operator", "function.builtin"].contains(&capture.as_str())
                || capture.starts_with("punctuation");
            if !listed {
                continue;
            }
            let in_table = table.iter().any(|(k, c)| *k == text && c.name() == capture);
            let logical = capture == "keyword"
                && (LOGICAL.contains(&text.as_str()) || text == "&&" || text == "||");
            assert!(
                in_table || logical,
                "`{text}` ({capture}) in `{source}` is not in the table"
            );
        }
    }
}
