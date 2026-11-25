//! Snapshots (insta) of what the engine reports for a few queries: each
//! diagnostic's severity, code, range and message, and each highlight
//! token's capture. A change in any of them fails here and shows the diff.
//!
//! The expected text is in `tests/snapshots/`, committed and reviewed like
//! code. After an intended change, `cargo insta review` (or
//! `INSTA_UPDATE=always cargo test -p opentide-analysis --test snapshots`)
//! writes the new one; CI sets `INSTA_UPDATE=no`, so it never writes one.

use opentide_analysis::{QueryRequest, analyze_query, highlight};
use opentide_core::{Diagnostic, LanguageId};
use std::fmt::Write as _;

/// One line per diagnostic: `severity code start-end message`, positions as
/// 0-based `line:character` (UTF-16), as the editor protocol counts them.
fn render_diagnostics(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let _ = writeln!(
            out,
            "{} {} {}:{}-{}:{} {}",
            d.severity.as_str(),
            d.code,
            d.range.start.line,
            d.range.start.character,
            d.range.end.line,
            d.range.end.character,
            d.message
        );
    }
    out
}

fn query(language: LanguageId, platform: Option<&str>, text: &str) -> String {
    render_diagnostics(&analyze_query(&QueryRequest {
        language,
        platform: platform.map(str::to_string),
        stack: None,
        text: text.to_string(),
    }))
}

#[test]
fn kql_unknown_operator_and_table() {
    insta::assert_snapshot!(query(
        LanguageId::Kql,
        Some("sentinel"),
        "SecurityEvnt\n| where EventID == 4688\n| frobnicate\n| take 5\n",
    ));
}

#[test]
fn spl_unknown_command() {
    insta::assert_snapshot!(query(
        LanguageId::Spl,
        None,
        "index=main sourcetype=WinEventLog | notacommand x | stats count by host\n",
    ));
}

#[test]
fn eql_sequence_highlight() {
    let text =
        "sequence by host.id [process where process.name == \"cmd.exe\"] [network where true]";
    let result = highlight(LanguageId::Eql, text);
    let mut out = String::new();
    for token in &result.tokens {
        let _ = writeln!(
            out,
            "{:<24} {}",
            token.capture,
            &text[token.span.start..token.span.end]
        );
    }
    insta::assert_snapshot!(out);
}
