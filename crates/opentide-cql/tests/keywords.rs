//! The lexer against the `KEYWORDS` table (`opentide_highlight::keywords`): each token of the
//! table is a token of the lexer, and the lexer cuts no other fixed token (an operator, a
//! bracket, a delimiter, a sigil) the table lacks.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_cql::{lexer, syntax};

use opentide_core::LanguageId;
use opentide_highlight::keywords;
use syntax::SyntaxKind as K;

/// A query in which `token` stands where the grammar lexes it.
fn sample(token: &str) -> &'static str {
    match token {
        "$" => "$a()",
        "?" => "x=?a",
        "?{" => "x=?{a=b}",
        "/" => "x=/a/ | y := a / b",
        "case" => "case { a }",
        "match" => "a match { * => b }",
        "like" => "a like b",
        "|" => "a | b",
        "=" => "a=b",
        "!=" => "a!=b",
        "<" => "a<1",
        "<=" => "a<=1",
        ">" => "a>1",
        ">=" => "a>=1",
        "==" => "x := a == b",
        "<=>" => "a <=> b",
        ":=" => "x := 1",
        "=~" => "a =~ f()",
        "=>" => "a match { * => b }",
        "!" => "!f()",
        "+" => "x := a + b",
        "-" => "x := a - b",
        "*" => "x := a * b",
        "%" => "x := a % b",
        "(" | ")" => "(a)",
        "[" | "]" => "[a]",
        "{" | "}" => "{a}",
        "," => "f(a, b)",
        ";" => "case { a; b }",
        ":" => "f(a: b)",
        other => panic!("no sample for the table token `{other}`"),
    }
}

/// The text of every lexeme of `source`, with its kind.
fn lexemes(source: &str) -> Vec<(K, &str)> {
    lexer::lex(source)
        .iter()
        .map(|l| {
            let range = std::ops::Range::<usize>::from(l.range);
            (K::from_raw(l.kind), &source[range])
        })
        .collect()
}

#[test]
fn every_table_token_is_a_token_of_the_lexer() {
    let table = keywords(LanguageId::Cql).expect("cql has a KEYWORDS table");
    for (token, _) in table {
        let source = sample(token);
        assert!(
            lexemes(source).iter().any(|(_, text)| text == token),
            "`{token}` is not a lexeme of `{source}`: {:?}",
            lexemes(source)
        );
    }
}

#[test]
fn the_lexer_cuts_no_fixed_token_the_table_lacks() {
    let table = keywords(LanguageId::Cql).expect("cql has a KEYWORDS table");
    let words = [
        K::WHITESPACE,
        K::LINE_COMMENT,
        K::BLOCK_COMMENT,
        K::WORD,
        K::ASSIGN_FIELD_TOKEN,
        K::PATTERN,
        K::PATTERN_ERROR,
        K::NUMBER_TOKEN,
        K::TAG_TOKEN,
        K::STRING_TOKEN,
        K::FUNCTION_NAME_TOKEN,
        K::SAVED_QUERY_NAME_TOKEN,
        K::PARAMETER_NAME_TOKEN,
        K::REGEX_PATTERN_TOKEN,
        K::REGEX_FLAGS_TOKEN,
        K::ERROR_TOKEN,
    ];
    for token in table.iter().map(|(token, _)| *token) {
        for (kind, text) in lexemes(sample(token)) {
            assert!(
                words.contains(&kind) || table.iter().any(|(t, _)| *t == text),
                "`{text}` ({kind:?}) in `{}` is not in the table",
                sample(token)
            );
        }
    }
}

/// The analysis colours every table token, in its sample, with a capture the table gives
/// it (`/` is the regex's string or the division's operator): the tree's highlight and
/// the TextMate grammars the table generates agree.
#[test]
fn every_table_token_is_highlighted_with_its_capture() {
    let table = keywords(LanguageId::Cql).expect("cql has a KEYWORDS table");
    for (token, _) in table {
        let source = sample(token);
        let captures: Vec<&str> = table
            .iter()
            .filter(|(t, _)| t == token)
            .map(|(_, c)| c.name())
            .collect();
        let highlighted = opentide_cql::analyze(source).tokens;
        let found = highlighted.iter().any(|t| {
            source.get(t.span.start..t.span.end) == Some(*token)
                && captures.contains(&t.capture.as_str())
        });
        assert!(
            found,
            "`{token}` in `{source}` is not highlighted as {captures:?}: {highlighted:?}"
        );
    }
}
