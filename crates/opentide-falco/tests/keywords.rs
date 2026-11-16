//! The parser's highlight captures against the `KEYWORDS` table
//! (`opentide_highlight::keywords`): each token of the table is highlighted
//! with its capture, and no bracket or delimiter is highlighted that the
//! table (the TextMate grammar's input) does not list.

use opentide_core::LanguageId;
use opentide_falco::highlight_captures;
use opentide_highlight::keywords;

/// A condition in which `token` stands where Falco lexes it.
fn sample(token: &str) -> &'static str {
    match token {
        "and" | "or" | "not" => "a and not b or c",
        "(" | ")" | "," => "proc.name in (a, b)",
        "[" | "]" => "proc.aname[2] = a",
        other => panic!("no sample for the table token `{other}`"),
    }
}

#[test]
fn every_table_token_is_highlighted_with_its_capture() {
    let table = keywords(LanguageId::Falco).expect("falco has a KEYWORDS table");
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
fn only_table_tokens_are_brackets_or_delimiters() {
    let table = keywords(LanguageId::Falco).expect("falco has a KEYWORDS table");
    for source in [
        "(a.b in (c, \"d\") and not (e or f.g[1] = h)) or tolower(i.j) = k",
        "join(\",\", (a.b, 1)) in (x) and l.m = val(n.o)[p]",
    ] {
        for (span, capture) in highlight_captures(source) {
            let text = &source[span.start..span.end];
            if capture.starts_with("punctuation") {
                assert!(
                    table.iter().any(|(k, c)| *k == text && c.name() == capture),
                    "`{text}` ({capture}) in `{source}` is not in the table"
                );
            }
        }
    }
}
