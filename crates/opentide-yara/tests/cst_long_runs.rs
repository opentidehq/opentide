//! The CST's editor features (highlight, folding, parenthesis pairs) on the
//! 1 MB stack of the browser module: one very long token of every kind, a
//! long chain, and nesting far past what YARA-X accepts. None may overflow
//! the stack or hang.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_yara::{editor, highlight, paren_pairs};

/// Runs `f` on a thread with a 1 MB stack, as the browser module has.
fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .expect("a thread")
        .join()
        .expect("no stack overflow, no panic");
}

const MILLION: usize = 1_000_000;

fn rule(condition: &str) -> String {
    format!("rule r {{ strings: $a = \"x\" condition: {condition} }}")
}

fn every_feature(source: &str) {
    let _ = highlight(source);
    let _ = editor::folding(source);
    let _ = paren_pairs(source);
}

#[test]
fn one_huge_token_of_every_kind() {
    on_small_stack(|| {
        for source in [
            format!("rule {} {{ condition: true }}", "a".repeat(MILLION)),
            format!(
                "rule r {{ strings: $a = \"{}\" condition: $a }}",
                "\\\"".repeat(MILLION / 2)
            ),
            format!(
                "rule r {{ strings: $a = \"{}\" condition: $a }}",
                "x".repeat(MILLION)
            ),
            format!(
                "rule r {{ strings: $a = /{}/ condition: $a }}",
                "\\/".repeat(MILLION / 2)
            ),
            format!(
                "rule r {{ strings: $a = {{ {} }} condition: $a }}",
                "00 ".repeat(MILLION / 3)
            ),
            format!(
                "rule r {{ meta: a = {} condition: true }}",
                "1".repeat(MILLION)
            ),
            format!("/*{}*/", "x\n".repeat(MILLION / 2)),
            // The block comment's repeated group in yara-x-parser's lexer.
            format!("/*{}*/", "*x".repeat(MILLION / 2)),
            format!("//{}", "x".repeat(MILLION)),
            format!(
                "rule r {{ condition: true }}{}",
                " \t\r\n".repeat(MILLION / 4)
            ),
            rule(&format!("${}", "a".repeat(MILLION))),
            // yara-x-parser's repeated groups: digit separators, `"""` strings.
            rule(&format!("{}1 == 1", "1_".repeat(MILLION / 2))),
            rule(&format!("0x{}1 == 1", "f_".repeat(MILLION / 2))),
            rule(&format!("1.{}2 == 1.0", "2_".repeat(MILLION / 2))),
            format!(
                "rule r {{ meta: a = \"\"\"{}\"\"\" condition: true }}",
                "\\\"".repeat(MILLION / 2)
            ),
            format!(
                "rule r {{ meta: a = \"\"\"{}\"\"\" condition: true }}",
                "x".repeat(MILLION)
            ),
        ] {
            every_feature(&source);
        }
    });
}

#[test]
fn chains_and_nesting_never_overflow() {
    on_small_stack(|| {
        every_feature(&rule(&("$a or ".repeat(20_000) + "$a")));
        every_feature(&rule(&("not ".repeat(100_000) + "$a")));
        every_feature(&rule(&format!(
            "{}$a{}",
            "(".repeat(100_000),
            ")".repeat(100_000)
        )));
        every_feature(&"(".repeat(200_000));
        every_feature(&rule(&"-".repeat(100_000)));
    });
}
