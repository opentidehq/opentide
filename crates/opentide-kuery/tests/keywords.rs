//! The lexer against the `KEYWORDS` table (`opentide_highlight::keywords`):
//! each token of the table is highlighted with its capture, and nothing but
//! the table's tokens (and words, `or`/`and`/`not`, fields and values) is
//! highlighted as an operator, a bracket or a keyword.

use opentide_core::LanguageId;
use opentide_highlight::keywords;

/// A query in which `token` stands where Kibana lexes it.
fn sample(token: &str) -> String {
    match token {
        "(" | ")" => "(a:1)".into(),
        "{" | "}" => "a:{b:1}".into(),
        "<" | "<=" | ">" | ">=" => format!("a{token}1"),
        ":" => "a:1".into(),
        other => panic!("no sample for the table token `{other}`"),
    }
}

#[test]
fn every_table_token_is_highlighted_with_its_capture() {
    let table = keywords(LanguageId::Kuery).expect("kuery has a KEYWORDS table");
    for (token, capture) in table {
        let source = sample(token);
        let tokens = opentide_kuery::analyze(&source, |_| false).tokens;
        assert!(
            tokens.iter().any(|t| &source[t.span.start..t.span.end] == *token
                && t.capture == capture.name()),
            "`{token}` in `{source}` is not a `{}` token: {tokens:?}",
            capture.name()
        );
    }
}

#[test]
fn only_table_tokens_are_operators_or_brackets() {
    let table = keywords(LanguageId::Kuery).expect("kuery has a KEYWORDS table");
    for source in [
        "a:1 and (b >= 2 or not c < 3)",
        "a:{b:1 and c <= 2}",
        "x:\"q\" or y > 4",
        "a: (1 or 2)",
    ] {
        for t in opentide_kuery::analyze(source, |_| false).tokens {
            let text = &source[t.span.start..t.span.end];
            if matches!(t.capture.as_str(), "operator" | "punctuation.bracket") {
                assert!(
                    table
                        .iter()
                        .any(|(k, c)| *k == text && c.name() == t.capture),
                    "`{text}` ({}) in `{source}` is not in the table",
                    t.capture
                );
            }
        }
    }
}
