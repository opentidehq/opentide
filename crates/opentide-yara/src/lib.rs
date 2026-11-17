//! I/O-free YARA engine (yara-1.0, #165).
//!
//! The language is YARA-X 1.x (#1225): what it refuses is an error. The
//! verdict parser is VirusTotal's `yara-x-parser` (lossless, with error
//! recovery), and `.yar` files are formatted with `yara-x-fmt`. The `yara-x`
//! compiler crate is not a dependency: it is an oracle only
//! (`scripts/engine/oracles`).
//!
//! A signature goes through:
//!
//! 1. the platform profile's text checks (`bitdefender_yara_ascii`,
//!    `bitdefender_yara_size`);
//! 2. `yara-x-parser`: its errors, classified (`errors.rs`:
//!    `yara_parse_error`, `yara_hex_string`, `yara_number_out_of_range`, ...);
//! 3. `check::Checker`: the symbol table, types and every other code of
//!    the spec, on each rule that parsed, and the profile's portability
//!    check (`yara_x_only_syntax`).
//!
//! `docs/engine/YARA.md` maps each code to its source and its test.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]
#![expect(
    clippy::too_many_lines,
    reason = "engine dispatchers match every node kind in one function"
)]
mod atoms;
pub mod catalog;
mod check;
mod cst;
pub mod editor;
mod errors;
pub mod regexp;

/// The parser's parenthesis pairs of `source`, for the range tests.
#[doc(hidden)]
pub fn paren_pairs(source: &str) -> Vec<(usize, usize)> {
    cst::paren_pairs(source)
}

use opentide_core::{Diagnostic, LineIndex, Range, Severity, codes};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use yara_x_parser::Parser;
use yara_x_parser::ast::AST;

/// Whether the platform takes syntax only YARA-X has (`with`, digit
/// separators, float meta values, `\"\"\"` strings, booleans in `of` tuples, hex or octal
/// jump bounds, `.len()`). While `Refused`, using it is the error
/// `yara_x_only_syntax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YaraXSyntax {
    /// YARA-X's syntax is the language: a raw `.yar` file.
    #[default]
    Allowed,
    /// The platform's engine is not known to take it: the profile's start.
    Refused,
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

/// Where the signature runs. A raw `.yar` file has no profile: YARA-X
/// syntax allowed, no module set to confirm, no recommended meta.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub profile: Option<Profile>,
    pub yara_x_syntax: YaraXSyntax,
}

impl Context {
    /// The profile's context, with its `yara_x_syntax` setting.
    pub fn for_profile(profile: Profile) -> Self {
        let data = &catalog::Catalog::cached().profiles[profile.key()];
        Self {
            profile: Some(profile),
            yara_x_syntax: data.yara_x_syntax,
        }
    }
}

/// The codes the engine only ever reports as warnings, whatever the profile:
/// the rule compiles, so the platform takes it. The checker reports them
/// through its one warning path (`Checker::warn`), which takes no other
/// code, and [`diagnostics`] never returns one as an error; every other code
/// is an error.
pub const WARNING_CODES: [&str; 6] = [
    codes::HARFANGLAB_YARA_CONTEXT,
    codes::YARA_ENTRYPOINT_DEPRECATED,
    codes::YARA_META_MISSING,
    codes::YARA_MODULE_UNCONFIRMED,
    codes::YARA_SLOW_PATTERN,
    codes::YARA_SUSPICIOUS_EXPRESSION,
];

/// Whether the engine only ever reports `code` as a warning
/// ([`WARNING_CODES`]): `opentide validate` does not fail on it.
pub fn always_warning(code: &str) -> bool {
    WARNING_CODES.contains(&code)
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
    let ast = AST::from(Parser::new(source.as_bytes()));
    let errors: Vec<(usize, usize)> = ast
        .errors()
        .iter()
        .map(|e| {
            let s = errors::span(e);
            (s.start(), s.end())
        })
        .collect();
    // An error past the last token (at the end of the text) is reported
    // right after that token, not past the blanks and comments after it.
    let last = if ast.errors().is_empty() {
        0
    } else {
        cst::significant_end(source)
    };
    findings.extend(ast.errors().iter().map(|e| {
        let mut finding = errors::classify(e, source);
        if finding.start > last {
            (finding.start, finding.end) = (last, last);
        }
        finding
    }));
    // A rule runs from its name to the next rule's: a parse error there
    // stops the compiler before the semantic checks.
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
    let mut checker = check::Checker::new(source, ctx);
    checker.signature(&ast, errors.is_empty(), &broken);
    findings.extend(checker.findings);
    findings.sort_by_key(|f| (f.start, f.end));
    findings.dedup();
    debug_assert!(
        findings
            .iter()
            .all(|f| f.severity == Severity::Warning || !always_warning(f.code)),
        "a warning-only code reported as an error: {findings:?}"
    );
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

/// Semantic tokens from `yara-x-parser`'s CST: every token's capture is
/// decided by its kind and the node around it (`cst.rs`).
pub fn highlight(source: &str) -> Vec<HighlightToken> {
    let Ok(spec) = HighlightSpec::load() else {
        return Vec::new();
    };
    tokens_from_spans(&spec, source, &cst::highlight_spans(source)).unwrap_or_default()
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

/// Whether YARA-X rejects `source` (the errors the analysis reports), and the
/// `Debug` names of the kinds of `yara-x-parser`'s CST in preorder: a node by
/// its own name, a token as `PARENT/TOKEN` (the CST's expressions are generic
/// nodes, told apart by their tokens and where they stand). What the corpus
/// gate of `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    use yara_x_parser::cst::{CST, Event, SyntaxKind};
    let rejected = !AST::from(Parser::new(source.as_bytes()))
        .errors()
        .is_empty();
    let mut open = Vec::new();
    let mut kinds = Vec::new();
    for event in CST::from(source).iter() {
        match event {
            Event::Begin { kind, .. } => {
                kinds.push(format!("{kind:?}"));
                open.push(kind);
            }
            Event::End { .. } => {
                open.pop();
            }
            Event::Token { kind, span } => {
                // A negated hex byte (`~5A`) is one HEX_BYTE token.
                let negated = kind == SyntaxKind::HEX_BYTE
                    && source.as_bytes().get(span.start()) == Some(&b'~');
                let name = if negated {
                    "HEX_BYTE_NOT".to_owned()
                } else {
                    format!("{kind:?}")
                };
                match open.last() {
                    Some(parent) => kinds.push(format!("{parent:?}/{name}")),
                    None => kinds.push(name),
                }
            }
            Event::Error { .. } => {}
        }
    }
    (rejected, kinds)
}

/// The `Debug` names of the node kinds of `yara-x-parser`'s CST, the error
/// node left out: the productions the corpus gate of `opentide-analysis` asks
/// a fixture of. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_node_kinds() -> Vec<String> {
    use yara_x_parser::cst::SyntaxKind as K;
    [
        K::SOURCE_FILE,
        K::IMPORT_STMT,
        K::INCLUDE_STMT,
        K::RULE_DECL,
        K::RULE_MODS,
        K::RULE_TAGS,
        K::META_BLK,
        K::META_DEF,
        K::PATTERNS_BLK,
        K::PATTERN_DEF,
        K::PATTERN_MODS,
        K::PATTERN_MOD,
        K::HEX_PATTERN,
        K::HEX_SUB_PATTERN,
        K::HEX_ALTERNATIVE,
        K::HEX_JUMP,
        K::CONDITION_BLK,
        K::BOOLEAN_EXPR,
        K::BOOLEAN_TERM,
        K::EXPR,
        K::TERM,
        K::PRIMARY_EXPR,
        K::FUNC_CALL,
        K::RANGE,
        K::FOR_EXPR,
        K::OF_EXPR,
        K::WITH_EXPR,
        K::WITH_DECLS,
        K::WITH_DECL,
        K::ITERABLE,
        K::QUANTIFIER,
        K::EXPR_TUPLE,
        K::BOOLEAN_EXPR_TUPLE,
        K::PATTERN_IDENT_TUPLE,
    ]
    .iter()
    .map(|k| format!("{k:?}"))
    .collect()
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
