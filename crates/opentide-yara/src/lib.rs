//! I/O-free YARA engine (yara-1.0, #165).
//!
//! The contract is YARA as libyara 4.5 compiles it; YARA-X 1.x is a second
//! opinion whose refusals are warnings (`yara_x_incompatible`). The verdict
//! parser is VirusTotal's `yara-x-parser` (lossless, with error recovery), and
//! `.yar` files are formatted with `yara-x-fmt`. The `yara-x` compiler crate is
//! not a dependency: it is an oracle only (`scripts/oracles`).
//!
//! This first cut reports what the parser refuses. The symbol table and the
//! semantic pass for the rest of the spec's code tables, the dialects and the
//! platform profiles build on it.

use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use opentide_highlight::HighlightToken;
use yara_x_parser::Parser;
use yara_x_parser::ast::{AST, Error as ParseError};

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Analyze a YARA signature on its own (a raw `.yar` file).
pub fn analyze(source: &str) -> AnalyzeResult {
    AnalyzeResult {
        diagnostics: parse_diagnostics(source),
        tokens: Vec::new(),
    }
}

/// The parser's errors, one diagnostic each. The parser recovers after an
/// error, so one signature may report several.
pub fn parse_diagnostics(source: &str) -> Vec<Diagnostic> {
    let ast = AST::from(Parser::new(source.as_bytes()));
    ast.errors()
        .iter()
        .map(|error| {
            let (code, message, span) = classify(error);
            let span = ByteSpan {
                start: span.start(),
                end: span.end(),
            };
            Diagnostic::error(code, message, span_to_range(source, span))
        })
        .collect()
}

/// The code a parser error reports under, its message, and its span.
fn classify(error: &ParseError) -> (&'static str, String, &yara_x_parser::Span) {
    match error {
        ParseError::SyntaxError { message, span } => (
            codes::YARA_PARSE_ERROR,
            format!("YARA syntax error: {message}"),
            span,
        ),
        // An integer literal that does not fit libyara's 64-bit integers.
        ParseError::InvalidInteger { message, span } => {
            (codes::YARA_NUMBER_OUT_OF_RANGE, message.clone(), span)
        }
        ParseError::InvalidRegexpModifier { message, span } => {
            (codes::YARA_REGEXP, message.clone(), span)
        }
        ParseError::InvalidFloat { message, span }
        | ParseError::InvalidEscapeSequence { message, span } => {
            (codes::YARA_PARSE_ERROR, message.clone(), span)
        }
        ParseError::InvalidUTF8(span) => (
            codes::YARA_PARSE_ERROR,
            "invalid UTF-8 in the YARA source".to_string(),
            span,
        ),
        ParseError::UnexpectedEscapeSequence(span) => (
            codes::YARA_PARSE_ERROR,
            "escape sequences are not allowed in this string".to_string(),
            span,
        ),
    }
}

/// Format a YARA signature with `yara-x-fmt`'s defaults. `None` when the text
/// does not parse, so an editor never rewrites a broken buffer.
pub fn format(source: &str) -> Option<String> {
    if !parse_diagnostics(source).is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(source.len());
    yara_x_fmt::Formatter::new()
        .format(source.as_bytes(), &mut out)
        .ok()?;
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes_of(source: &str) -> Vec<String> {
        analyze(source)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn spec_example_parses() {
        let source = r#"import "pe"

private rule MZ_Header {
  condition:
    uint16(0) == 0x5A4D
}

rule Loader_Stage1 : loader {
  meta:
    description = "Stage-1 loader with an encrypted config blob"
    context = "file,memory"
  strings:
    $cfg = { 43 46 47 21 [4-16] 00 01 }
    $mutex = "Global\\qx-7731" ascii wide
  condition:
    MZ_Header and pe.number_of_sections > 3 and all of them
}
"#;
        assert!(codes_of(source).is_empty(), "{:?}", codes_of(source));
    }

    #[test]
    fn a_rule_without_strings_is_valid() {
        assert!(codes_of("rule a { condition: filesize < 10KB }").is_empty());
    }

    #[test]
    fn syntax_error_is_placed() {
        let source = "rule a {\n  condition:\n    true and\n}\n";
        let result = analyze(source);
        assert_eq!(result.diagnostics.len(), 1, "{:?}", result.diagnostics);
        let d = &result.diagnostics[0];
        assert_eq!(d.code, codes::YARA_PARSE_ERROR);
        assert_eq!(d.range.start.line, 3);
    }

    #[test]
    fn integer_overflow_is_out_of_range() {
        let codes = codes_of("rule a { condition: filesize == 99999999999999999999 }");
        assert_eq!(codes, [codes::YARA_NUMBER_OUT_OF_RANGE]);
    }

    #[test]
    fn format_rewrites_a_valid_signature() {
        let formatted = format("rule a{condition:true}").expect("formats");
        assert_eq!(formatted, "rule a {\n  condition:\n    true\n}\n");
    }

    #[test]
    fn format_refuses_a_broken_signature() {
        assert_eq!(format("rule a { condition: }"), None);
    }
}
