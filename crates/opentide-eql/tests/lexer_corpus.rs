//! The lexer on every EQL file of the corpora, against tree-sitter's tokens, their ranges and
//! kinds (the engine it replaces), and on the hand-written cases of each token's regex: the five
//! string forms, numbers, indexes, quoted names and the nested block comments.

#![expect(dead_code, reason = "the included modules are used in part")]
#![expect(clippy::expect_used, reason = "a test")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "legacy/lexical.rs"]
mod lexical;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_core::LanguageId;
use std::path::{Path, PathBuf};
use syntax::SyntaxKind as K;

/// The kind and text of every lexeme of `source`, whitespace left out.
fn tokens(source: &str) -> Vec<(K, &str)> {
    all(source)
        .into_iter()
        .filter(|(kind, _)| *kind != K::WHITESPACE)
        .collect()
}

/// The kind and text of every lexeme of `source`; they tile it.
fn all(source: &str) -> Vec<(K, &str)> {
    let mut end = 0;
    let out = lexer::lex(source)
        .iter()
        .map(|l| {
            let range = std::ops::Range::<usize>::from(l.range);
            assert_eq!(range.start, end, "the lexemes tile `{source}`");
            end = range.end;
            (K::from_raw(l.kind), &source[range])
        })
        .collect();
    assert_eq!(end, source.len(), "the lexemes tile `{source}`");
    out
}

fn texts(source: &str) -> Vec<&str> {
    tokens(source).into_iter().map(|(_, text)| text).collect()
}

fn kinds(source: &str) -> Vec<K> {
    tokens(source).into_iter().map(|(kind, _)| kind).collect()
}

fn eql_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "eql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

/// The leaves of a tree-sitter tree, with the kind of each.
fn leaves(node: tree_sitter::Node<'_>, out: &mut Vec<(&'static str, usize, usize)>) {
    if node.child_count() == 0 {
        if node.end_byte() > node.start_byte() {
            out.push((node.kind(), node.start_byte(), node.end_byte()));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        leaves(child, out);
    }
}

/// Each token's kind, start and end.
type Cuts = Vec<(K, usize, usize)>;

/// The lexer's kind of a tree-sitter leaf: a keyword, `any`, `null` and the booleans are words
/// (the parser re-kinds them), `in~` and a case-insensitive name a `TILDE_WORD`, the others by
/// their node or their text.
fn lexer_kind(leaf: &str, text: &str) -> K {
    match leaf {
        "identifier" | "any" | "null" | "boolean" => K::WORD,
        "case_insensitive_name" | "in~" | "like~" | "regex~" => K::TILDE_WORD,
        "number" => K::NUMBER_TOKEN,
        "string" => K::STRING_TOKEN,
        "quoted_identifier" => K::QUOTED_IDENT_TOKEN,
        "index" => K::INDEX_TOKEN,
        "comment" if text.starts_with("//") => K::LINE_COMMENT,
        "comment" => K::BLOCK_COMMENT,
        "missing_event_open" => K::BANG_L_BRACK,
        "optional_marker" => K::QUESTION,
        _ if leaf.bytes().all(|b| b.is_ascii_lowercase()) => K::WORD,
        _ => punctuation(leaf),
    }
}

/// The kind of a punctuation leaf, from a table of its own: lexing the leaf's text would compare
/// the lexer with itself.
fn punctuation(leaf: &str) -> K {
    match leaf {
        "|" => K::PIPE,
        "=" => K::EQ,
        "==" => K::EQ_EQ,
        "!=" => K::NOT_EQ,
        "<" => K::LT,
        "<=" => K::LT_EQ,
        ">" => K::GT,
        ">=" => K::GT_EQ,
        "+" => K::PLUS,
        "-" => K::MINUS,
        "*" => K::STAR,
        "/" => K::SLASH,
        "%" => K::PERCENT,
        "(" => K::L_PAREN,
        ")" => K::R_PAREN,
        "[" => K::L_BRACK,
        "]" => K::R_BRACK,
        "![" => K::BANG_L_BRACK,
        "," => K::COMMA,
        "." => K::DOT,
        ":" => K::COLON,
        "?" => K::QUESTION,
        _ => panic!("a tree-sitter leaf the test does not know: {leaf:?}"),
    }
}

/// The tokens of `source` that tree-sitter and the lexer cut, each with its kind, when
/// tree-sitter parses it without an error (a broken query is lexed by what the parser accepts
/// next, which a lexer without a parser cannot follow).
fn both_cut(source: &str) -> Option<(Cuts, Cuts)> {
    let prepared = lexical::prepare(source);
    let tree = opentide_syntax::parse(LanguageId::Eql, &prepared.text).expect("tree");
    if opentide_syntax::has_error(&tree) {
        return None;
    }
    let mut expected = Vec::new();
    leaves(tree.root_node(), &mut expected);
    let mut at = 0;
    let found = tokens(source)
        .iter()
        .map(|(kind, text)| {
            let start = at + source[at..].find(text).expect("in order");
            at = start + text.len();
            (*kind, start, at)
        })
        .collect();
    let expected = expected
        .iter()
        .map(|&(leaf, s, e)| (lexer_kind(leaf, &source[s..e]), s, e))
        .collect();
    Some((found, expected))
}

#[test]
fn the_lexer_cuts_the_tokens_tree_sitter_does_on_every_file() {
    let files = eql_files();
    assert!(files.len() > 150, "{} files", files.len());
    let mut compared = 0;
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read");
        let Some((found, expected)) = both_cut(&source) else {
            continue;
        };
        compared += 1;
        assert_eq!(found, expected, "{}: the tokens differ", path.display());
    }
    assert!(compared > 100, "{compared} files compared");
}

/// How many characters longer the enumerations go: `OPENTIDE_LEX_SCALE=2` is the full run (a
/// few minutes in a debug build), the default keeps CI well under its 300 s test limit.
fn scale() -> usize {
    std::env::var("OPENTIDE_LEX_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Every string over `alphabet` up to `len` characters, as a literal in a valid query: the
/// lexer cuts what tree-sitter cuts wherever tree-sitter accepts the query.
fn every_literal(alphabet: &[&str], len: usize, wrap: impl Fn(&str) -> String) -> usize {
    let mut compared = 0;
    let mut stack = vec![String::new()];
    while let Some(literal) = stack.pop() {
        let source = wrap(&literal);
        if let Some((found, expected)) = both_cut(&source) {
            compared += 1;
            assert_eq!(found, expected, "{source:?}");
        }
        if literal.chars().count() < len {
            for c in alphabet {
                stack.push(format!("{literal}{c}"));
            }
        }
    }
    compared
}

#[test]
fn the_lexer_cuts_every_short_string_as_tree_sitter_does() {
    let alphabet = ["\"", "'", "\\", "?", "a", " ", "\n"];
    let wrap = |s: &str| format!("any where a == {s}");
    assert!(every_literal(&alphabet, 5 + scale(), wrap) > 300);
    let wrap = |s: &str| format!("any where a == {s} or b");
    assert!(every_literal(&alphabet, 4 + scale(), wrap) > 100);
}

#[test]
fn the_lexer_cuts_every_short_name_and_number_as_tree_sitter_does() {
    let alphabet = ["`", "a", "1", ".", "e", "+", "[", "]", " ", "~"];
    let wrap = |s: &str| format!("any where {s} == 1");
    assert!(every_literal(&alphabet, 4 + scale(), wrap) > 100);
    let wrap = |s: &str| format!("any where a == {s}");
    assert!(every_literal(&alphabet, 4 + scale(), wrap) > 100);
    let wrap = |s: &str| format!("any where a{s} == 1");
    assert!(every_literal(&alphabet, 4 + scale(), wrap) > 50);
}

#[test]
fn the_lexer_cuts_every_short_comment_as_tree_sitter_does() {
    let alphabet = ["/", "*", "a", " ", "\n"];
    let wrap = |s: &str| format!("any where a == 1 {s}\n");
    assert!(every_literal(&alphabet, 6 + scale(), wrap) > 200);
    let wrap = |s: &str| format!("any where {s} a == 1");
    assert!(every_literal(&alphabet, 5 + scale(), wrap) > 100);
}

#[test]
fn words_are_one_token_and_a_trailing_tilde_makes_a_tilde_word() {
    assert_eq!(
        kinds("a @b _c d1 stringcontains~ _x~"),
        [
            K::WORD,
            K::WORD,
            K::WORD,
            K::WORD,
            K::TILDE_WORD,
            K::WORD,
            K::ERROR_TOKEN
        ]
    );
    assert_eq!(texts("a in~ (1)"), ["a", "in~", "(", "1", ")"]);
}

#[test]
fn numbers_take_the_longest_of_the_four_forms() {
    for number in [
        "1", "12", "1.", "1.5", "1.5e3", "1.e5", ".5", ".5e-3", "1e5", "1E+5", "007",
    ] {
        assert_eq!(texts(number), [number], "{number}");
        assert_eq!(kinds(number), [K::NUMBER_TOKEN], "{number}");
    }
    // An exponent needs digits: `e` is a word after the number.
    assert_eq!(texts("1e"), ["1", "e"]);
    assert_eq!(texts("1.5e+"), ["1.5", "e", "+"]);
    assert_eq!(texts("1.5.3"), ["1.5", ".3"]);
    assert_eq!(texts("a.b"), ["a", ".", "b"]);
    assert_eq!(texts("1.x"), ["1.", "x"]);
}

#[test]
fn double_quoted_strings() {
    for ok in [
        r#""""#,
        r#""a""#,
        r#""a\"b""#,
        r#""a\u{1F600}b""#,
        r#""\\""#,
        "\"é\"",
    ] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::STRING_TOKEN], "{ok}");
    }
    // A raw line break ends the line; a backslash takes the carriage return, not the line feed.
    assert_eq!(texts("\"a\nb\""), ["\"", "a", "b", "\""]);
    assert_eq!(kinds("\"a\nb\"")[0], K::ERROR_TOKEN);
    assert_eq!(texts("\"a\\\r\nb\""), ["\"", "a", "\\", "b", "\""]);
    assert_eq!(kinds("\"a\\"), [K::ERROR_TOKEN, K::WORD, K::ERROR_TOKEN]);
}

#[test]
fn single_quoted_strings() {
    for ok in ["''", "'a'", r"'a\'b'", r"'\\'", "'\"'"] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::STRING_TOKEN], "{ok}");
    }
    assert_eq!(kinds("'abc"), [K::ERROR_TOKEN, K::WORD]);
}

#[test]
fn triple_quoted_strings_end_at_the_first_run_of_three_quotes() {
    for ok in [
        r#""""a""""#,
        r#""""a"b""c""""#,
        r####""""""""####,
        r#""""a"""""#,
        r#""""a""""""#,
        r#""""" a """"#,
    ] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::STRING_TOKEN], "{ok}");
    }
    // Five quotes are no string: two empty strings and a stray quote.
    assert_eq!(texts(r#"""""""#), ["\"\"", "\"\"", "\""]);
    // Up to two more quotes belong to the string, no more.
    assert_eq!(
        texts("\"\"\"a\"\"\"\"\"\"\""),
        ["\"\"\"a\"\"\"\"\"", "\"\""]
    );
    // A quote at the end of the line is not content: the empty string, then the string `"a"`.
    assert_eq!(texts("\"\"\"a\"\n"), ["\"\"", "\"a\""]);
    assert_eq!(
        texts("\"\"\"a\"\"\nb\"\"\""),
        ["\"\"", "\"a\"", "\"", "b", "\"\"", "\""]
    );
}

#[test]
fn raw_strings_end_at_the_first_quote_a_backslash_does_not_precede() {
    for ok in [r#"?"a""#, r#"?"a\b""#, r"?'a\b'", r#"?"""#, r#"?"a\"b""#] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::STRING_TOKEN], "{ok}");
    }
    // `\"` may close the string, or continue it when a later quote closes it.
    assert_eq!(texts(r#"?"a\" b"#), [r#"?"a\""#, "b"]);
    assert_eq!(texts(r#"?"a\" b" c"#), [r#"?"a\" b""#, "c"]);
    // Not a raw string: the optional marker.
    assert_eq!(kinds("?a"), [K::QUESTION, K::WORD]);
    assert_eq!(kinds("?\"abc"), [K::QUESTION, K::ERROR_TOKEN, K::WORD]);
}

#[test]
fn quoted_names_double_their_backticks() {
    for ok in ["`a`", "`a b`", "``", "`a``b`", "`a\nb`", "`é`"] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::QUOTED_IDENT_TOKEN], "{ok}");
    }
    // An even run is all content when something closes later, else it closes one short.
    assert_eq!(texts("`a```"), ["`a```"]);
    assert_eq!(texts("`a````"), ["`a```", "`"]);
    assert_eq!(texts("`a````b`"), ["`a````b`"]);
    assert_eq!(kinds("`a"), [K::ERROR_TOKEN, K::WORD]);
}

#[test]
fn indexes_are_digits_in_brackets() {
    for ok in ["[0]", "[ 12 ]", "[1 2]", "[\n3\n]"] {
        assert_eq!(texts(ok), [ok], "{ok}");
        assert_eq!(kinds(ok), [K::INDEX_TOKEN], "{ok}");
    }
    assert_eq!(kinds("[]"), [K::L_BRACK, K::R_BRACK]);
    assert_eq!(kinds("[a]"), [K::L_BRACK, K::WORD, K::R_BRACK]);
    assert_eq!(kinds("[1"), [K::L_BRACK, K::NUMBER_TOKEN]);
    assert_eq!(kinds("![any"), [K::BANG_L_BRACK, K::WORD]);
}

#[test]
fn line_comments_end_at_the_line_break() {
    assert_eq!(kinds("a // b\nc"), [K::WORD, K::LINE_COMMENT, K::WORD]);
    assert_eq!(texts("a // b\r\nc"), ["a", "// b", "c"]);
    assert_eq!(texts("a //"), ["a", "//"]);
    assert_eq!(kinds("a / b"), [K::WORD, K::SLASH, K::WORD]);
}

/// Cases checked against the generated `EqlBaseLexer` (ANTLR 4.13), as `lexical`'s are.
#[test]
fn block_comments_end_where_elasticsearch_ends_them() {
    for (source, comment) in [
        ("a /* x */ b", "/* x */"),
        ("a /* x /* y */ z */ b", "/* x /* y */ z */"),
        ("a /* x /* y */ b", "/* x /* y */"),
        ("/* /* */ */ */ c", "/* /* */ */"),
        ("a /* x /* y /* z */ */ b", "/* x /* y /* z */ */"),
        ("a /*/**y/*/*y*/*/", "/*/**y/*/*y*/"),
        ("a /*xx /**//*/", "/*xx /**//*/"),
        ("a /**/ b", "/**/"),
    ] {
        let found: Vec<_> = tokens(source)
            .into_iter()
            .filter(|(kind, _)| *kind == K::BLOCK_COMMENT)
            .map(|(_, text)| text)
            .collect();
        assert_eq!(found, [comment], "{source}");
    }
    // No `*/` at all: `/` and `*` are operators.
    assert_eq!(
        kinds("a /* never closed"),
        [K::WORD, K::SLASH, K::STAR, K::WORD, K::WORD]
    );
    assert_eq!(kinds("/*/"), [K::SLASH, K::STAR, K::SLASH]);
}

#[test]
fn a_comment_ends_where_the_nested_reading_says_over_the_lexical_scan() {
    // `lexical::prepare` is the old engine's reading of the same comments.
    for source in [
        "process where /* a /* b */ c */ true",
        "a /* x /* y */ b */ c /* d */ e",
        "/* /* /* */ */ */ x",
        "q /*/**y/*/*y*/*/ w",
    ] {
        let prepared = lexical::prepare(source);
        let nested: Vec<_> = prepared
            .comments
            .iter()
            .filter_map(|c| match c {
                lexical::CommentFinding::Nested(span) => Some((span.start, span.end)),
                lexical::CommentFinding::NotAComment(_) => None,
            })
            .collect();
        let ours: Vec<_> = {
            let mut at = 0;
            all(source)
                .into_iter()
                .filter_map(|(kind, text)| {
                    let start = at;
                    at += text.len();
                    (kind == K::BLOCK_COMMENT && text.matches("/*").count() > 1)
                        .then_some((start, at))
                })
                .collect()
        };
        for span in &nested {
            assert!(ours.contains(span), "{source}: {nested:?} vs {ours:?}");
        }
    }
}

#[test]
fn an_unknown_character_is_one_error_token() {
    assert_eq!(
        kinds("a ; é ~ ! {"),
        [
            K::WORD,
            K::ERROR_TOKEN,
            K::ERROR_TOKEN,
            K::ERROR_TOKEN,
            K::ERROR_TOKEN,
            K::ERROR_TOKEN
        ]
    );
}
