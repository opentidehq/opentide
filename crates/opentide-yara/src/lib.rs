//! I/O-free YARA engine (yara-1.0, #165).
//!
//! The contract is YARA as libyara 4.5 compiles it; YARA-X 1.x is a second
//! opinion whose refusals are warnings (`yara_x_incompatible`). The verdict
//! parser is VirusTotal's `yara-x-parser` (lossless, with error recovery), and
//! `.yar` files are formatted with `yara-x-fmt`. The `yara-x` compiler crate is
//! not a dependency: it is an oracle only (`scripts/oracles`).
//!
//! A signature goes through:
//!
//! 1. the platform profile's text checks (`bitdefender_yara_ascii`,
//!    `bitdefender_yara_size`);
//! 2. [`syntax::prepare`]: the libyara forms yara-x-parser refuses are
//!    blanked, keeping every offset (`yara_x_incompatible`);
//! 3. `yara-x-parser`: its errors, classified (`yara_parse_error`,
//!    `yara_hex_string`, `yara_number_out_of_range`, ...);
//! 4. [`check::Checker`]: the symbol table, types and every other code of
//!    the spec, on each rule that parsed.
//!
//! `docs/YARA.md` maps each code to the libyara source and the test.

mod atoms;
pub mod catalog;
mod check;
pub mod editor;
pub mod regexp;
mod syntax;

use opentide_core::{ByteSpan, Diagnostic, LanguageId, LineIndex, Range, Severity, codes};
use opentide_highlight::{HighlightSpec, HighlightToken, YARA_HIGHLIGHTS_SCM, tokens_from_spans};
use yara_x_parser::Parser;
use yara_x_parser::ast::AST;

/// Which engine's language the signature is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// libyara 4.5: the contract of every profile today. What only YARA-X
    /// refuses is the warning `yara_x_incompatible`.
    #[default]
    Libyara4,
    /// YARA-X 1.x: its syntax is accepted, and `yara_x_incompatible` is an
    /// error.
    YaraX,
}

/// A platform's YARA profile (yara-1.0 "Platform profiles").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Harfanglab,
    Bitdefender,
}

impl Profile {
    pub fn key(self) -> &'static str {
        match self {
            Profile::Harfanglab => "harfanglab",
            Profile::Bitdefender => "bitdefender",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Profile::Harfanglab => "HarfangLab",
            Profile::Bitdefender => "Bitdefender",
        }
    }

    /// The profile of a Tide platform block, by its key under `configurations`.
    pub fn for_platform(platform: &str) -> Option<Self> {
        match platform {
            "harfanglab" => Some(Profile::Harfanglab),
            "bitdefender" => Some(Profile::Bitdefender),
            _ => None,
        }
    }
}

/// Where the signature runs. A raw `.yar` file has no profile: libyara 4.5,
/// no module set to confirm, no recommended meta.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub dialect: Dialect,
    pub profile: Option<Profile>,
}

impl Context {
    /// The profile's context, with the dialect it names.
    pub fn for_profile(profile: Profile) -> Self {
        let data = &catalog::Catalog::cached().profiles[profile.key()];
        let dialect = if data.dialect == "yara_x" {
            Dialect::YaraX
        } else {
            Dialect::Libyara4
        };
        Self {
            dialect,
            profile: Some(profile),
        }
    }
}

/// A finding in byte offsets, before ranges.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub start: usize,
    pub end: usize,
}

impl Finding {
    pub fn new(
        code: &'static str,
        severity: Severity,
        message: String,
        start: usize,
        end: usize,
    ) -> Self {
        Self {
            code,
            severity,
            message,
            start,
            end,
        }
    }
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Analyze a YARA signature on its own (a raw `.yar` file).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::default())
}

/// Analyze a YARA signature where `ctx` says it runs.
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    AnalyzeResult {
        diagnostics: diagnostics(source, ctx),
        tokens: highlight(source),
    }
}

/// Every diagnostic of a signature, in source order.
pub fn diagnostics(source: &str, ctx: &Context) -> Vec<Diagnostic> {
    let mut findings = profile_findings(source, ctx);
    let prepared = syntax::prepare(source);
    findings.extend(prepared.findings.iter().cloned().map(|mut f| {
        if ctx.dialect == Dialect::YaraX {
            f.severity = Severity::Error;
        }
        f
    }));
    let ast = AST::from(Parser::new(prepared.text.as_bytes()));
    let errors: Vec<(usize, usize)> = ast
        .errors()
        .iter()
        .map(|e| {
            let s = syntax::error_span(e);
            (s.start(), s.end())
        })
        .collect();
    for error in ast.errors() {
        let mut f = syntax::classify(error, &prepared.text);
        if f.code == codes::YARA_X_INCOMPATIBLE && ctx.dialect == Dialect::YaraX {
            f.severity = Severity::Error;
        }
        findings.push(f);
    }
    // A rule runs from its name to the next rule's: a parse error there
    // stops libyara before the semantic checks.
    let starts: Vec<usize> = ast
        .rules()
        .map(|r| {
            use yara_x_parser::ast::WithSpan;
            r.identifier.span().start()
        })
        .collect();
    let broken = |at: (usize, usize)| {
        let i = starts.iter().position(|&s| s == at.0);
        let end = i
            .and_then(|i| starts.get(i + 1))
            .copied()
            .unwrap_or(usize::MAX);
        let begin = i
            .and_then(|i| i.checked_sub(1))
            .and_then(|p| starts.get(p))
            .map_or(0, |&p| p + 1);
        let begin = begin.min(at.0);
        errors.iter().any(|&(s, _)| {
            s >= begin && s < end && (s >= at.0 || !starts.iter().any(|&o| o > s && o < at.0))
        })
    };
    // The checker reads text (alphabets, jump bounds) from the source itself.
    let mut checker = check::Checker::new(source, ctx, &prepared.rule_wildcards);
    checker.signature(&ast, errors.is_empty(), &broken);
    findings.extend(checker.findings);
    findings.sort_by_key(|f| (f.start, f.end));
    findings.dedup();
    let lines = LineIndex::new(source);
    findings
        .into_iter()
        .map(|f| Diagnostic {
            code: f.code.to_string(),
            severity: f.severity,
            message: f.message,
            range: Range::new(lines.position(f.start), lines.position(f.end.max(f.start))),
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        })
        .collect()
}

/// `bitdefender_yara_ascii` and `bitdefender_yara_size` (bitdefender-1.0).
fn profile_findings(source: &str, ctx: &Context) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(profile) = ctx.profile else {
        return out;
    };
    let data = &catalog::Catalog::cached().profiles[profile.key()];
    if data.ascii_only
        && let Some((i, c)) = source.char_indices().find(|(_, c)| !c.is_ascii())
    {
        out.push(Finding::new(
            codes::BITDEFENDER_YARA_ASCII,
            Severity::Error,
            format!(
                "{} takes ASCII only; `{c}` (U+{:04X}) is not",
                profile.display(),
                c as u32
            ),
            i,
            i + c.len_utf8(),
        ));
    }
    if let Some(max) = data.max_characters {
        let count = source.chars().count();
        if count > max {
            let at = source
                .char_indices()
                .nth(max)
                .map_or(source.len(), |(i, _)| i);
            out.push(Finding::new(
                codes::BITDEFENDER_YARA_SIZE,
                Severity::Error,
                format!(
                    "{} takes at most {max} characters; this signature has {count}",
                    profile.display()
                ),
                at,
                source.len(),
            ));
        }
    }
    out
}

/// Semantic tokens from the tree-sitter grammar and `highlights.scm`. The
/// grammar only colours; verdicts are `yara-x-parser`'s.
pub fn highlight(source: &str) -> Vec<HighlightToken> {
    let Ok(spec) = HighlightSpec::load() else {
        return Vec::new();
    };
    let Ok(spans) = opentide_syntax::query_captures(LanguageId::Yara, source, YARA_HIGHLIGHTS_SCM)
    else {
        return Vec::new();
    };
    let spans: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(&spec, source, &spans).unwrap_or_default()
}

/// Format a YARA signature with `yara-x-fmt`'s defaults. `None` when the text
/// does not parse, so an editor never rewrites a broken buffer.
pub fn format(source: &str) -> Option<String> {
    if !AST::from(Parser::new(source.as_bytes()))
        .errors()
        .is_empty()
    {
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
    fn highlight_colours_rules_strings_and_modules() {
        let source = "import \"pe\"\nrule r : t {\n  strings:\n    $a = \"x\" wide\n  condition:\n    $a and pe.is_dll()\n}\n";
        let tokens = analyze(source).tokens;
        let at = |text: &str| {
            let start = source.find(text).unwrap();
            tokens
                .iter()
                .find(|t| t.span.start == start)
                .map(|t| t.capture.clone())
        };
        assert_eq!(at("rule").as_deref(), Some("keyword"));
        assert_eq!(at("r :").as_deref(), Some("type"));
        assert_eq!(at("$a =").as_deref(), Some("variable"));
        assert_eq!(at("wide").as_deref(), Some("keyword"));
        assert_eq!(at("pe.").as_deref(), Some("type"));
        assert_eq!(at("is_dll").as_deref(), Some("function"));
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
