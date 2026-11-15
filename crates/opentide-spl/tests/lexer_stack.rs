//! One huge token must not overflow the stack: logos' generated code for a
//! regex with a repeated group recurses per repetition, which aborts the
//! process. Every shape the lexer can see is lexed on a 1 MB stack.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_spl::syntax::lex;

fn lex_on_small_stack(source: String) -> usize {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let lexemes = lex(&source);
            let end = lexemes.last().map_or(0, |l| usize::from(l.range.end()));
            assert_eq!(end, source.len(), "lossless");
            lexemes.len()
        })
        .expect("spawn")
        .join()
        .expect("no panic")
}

const N: usize = 1_000_000;

#[test]
fn a_huge_string_in_a_search() {
    lex_on_small_stack(format!("a=\"{}\"", "x".repeat(N)));
    lex_on_small_stack(format!("a=\"{}\"", "\\\"".repeat(N)));
    lex_on_small_stack(format!("a='{}'", "\\'".repeat(N)));
}

#[test]
fn a_huge_string_in_an_expression() {
    lex_on_small_stack(format!("| eval x=\"{}\"", "\\\\".repeat(N)));
}

#[test]
fn a_huge_dotted_name() {
    lex_on_small_stack(format!("| eval x={}", "a.".repeat(N) + "b"));
}

#[test]
fn a_huge_template_name() {
    lex_on_small_stack(format!("| foreach * [ eval {}x=1 ]", "<<A>>".repeat(N)));
    lex_on_small_stack(format!("| eval {}=1", "a<<A>>".repeat(N)));
}

#[test]
fn a_huge_word_comment_macro_and_directive() {
    lex_on_small_stack("w".repeat(N));
    lex_on_small_stack(format!("```{}```", "a`".repeat(N)));
    lex_on_small_stack(format!("`m({})`", "a".repeat(N)));
    lex_on_small_stack(format!("TERM({})", "\\\"".repeat(N)));
    lex_on_small_stack(format!(
        "| stats count by x| rex x=\"a\"{}",
        "\"b\"".repeat(N)
    ));
}

#[test]
fn a_huge_glued_option_value() {
    lex_on_small_stack(format!(
        "| streamstats reset_after=\"a\"{}",
        "\\\"b".repeat(N)
    ));
}

#[test]
fn unclosed_quotes_stay_linear() {
    // Each of these is an unclosed quote at every position: a scan to the
    // end per quote would take minutes.
    lex_on_small_stack("\"".repeat(N));
    lex_on_small_stack("\\\"".repeat(N));
    lex_on_small_stack("'".repeat(N));
    lex_on_small_stack("| eval x=\"\\".repeat(N / 2));
    lex_on_small_stack("a=\"b ".repeat(N / 4));
}

#[test]
fn other_long_tokens() {
    lex_on_small_stack("1.".repeat(N) + "1");
    lex_on_small_stack(format!("| eval {}", "a:b".repeat(N)));
    lex_on_small_stack(format!("| eval x={}", "$t$".repeat(N)));
    lex_on_small_stack(format!("| eval {}", "{f}".repeat(N)));
    lex_on_small_stack(format!("a {}", "*x".repeat(N)));
}
