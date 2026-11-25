//! The lexer on every EQL file of the corpora (the lexemes tile it), and on the hand-written
//! cases of each token's regex: the five string forms, numbers, indexes, quoted names and the
//! nested block comments.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/lexical.rs"]
mod lexical;
#[path = "../src/syntax.rs"]
mod syntax;

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

/// Every `.eql` file under `crates/testdata`.
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

/// The lexemes tile every EQL file of the corpora ([`all`] asserts it).
#[test]
fn the_lexemes_tile_every_corpus_file() {
    let files = eql_files();
    assert!(files.len() > 150, "{} files", files.len());
    for path in &files {
        let source = std::fs::read_to_string(path).expect("read");
        all(&source);
    }
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
    // `lexical::prepare` is the analysis's own scan of the same comments.
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
