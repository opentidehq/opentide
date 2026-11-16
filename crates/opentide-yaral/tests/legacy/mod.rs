//! The tree-sitter implementation the pure-Rust parser replaces, kept
//! verbatim (tests only) for the differential test, until stage 2 of the
//! decommission (#1231) deletes it. Was: I/O-free YARA-L 2.0 engine (yara-l-1.0, RFC 0019 section 7).
//!
//! YARA-L is the detection and search language of Google Security
//! Operations. Google publishes no grammar and no offline compiler, so the
//! engine is an approximation of the tenant's compiler (`verifyRuleText`): it
//! reports what Google's pages say the compiler refuses, and never claims a
//! compile. A text goes through:
//!
//! 1. the tree-sitter grammar (`grammars/tree-sitter-opentide-yaral`), whose
//!    errors are `yaral_parse_error`;
//! 2. `check::Checker`: sections and their order for the profile, scope
//!    (event variables, placeholders, outcomes), `match` windows, outcome
//!    aggregation, condition shape, options, the UDM and function catalogues,
//!    literals and limits.
//!
//! Two profiles: a rule (`YaraLRule`, or a Tide block's sections assembled
//! into one) and a search (`YaraLSearch`, a hunt). Reference lists, data
//! tables, composite producer names and curated rules live in the tenant and
//! are never reported unknown. `docs/engine/YARAL.md` maps each code to Google's page
//! and the test that proves it.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#[path = "check.rs"]
mod check;
#[path = "editor.rs"]
mod editor;

pub use editor::hover;

use opentide_core::{ByteSpan, Diagnostic, LanguageId, LineIndex, Range, Severity, codes};
use opentide_highlight::{HighlightSpec, HighlightToken, YARAL_HIGHLIGHTS_SCM, tokens_from_spans};
use opentide_yaral::{Context, Profile};

/// A finding in byte offsets, before ranges.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
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

/// The profile of `source`: a rule when it holds a `rule` declaration.
pub fn infer_profile(source: &str) -> Profile {
    let Some(tree) = opentide_syntax::parse(LanguageId::Yaral, source) else {
        return Profile::Rule;
    };
    let root = tree.root_node();
    let mut cursor = root.walk();
    let rule = root
        .named_children(&mut cursor)
        .any(|n| n.kind() == "rule_declaration");
    if rule || source.trim_start().to_ascii_lowercase().starts_with("rule") {
        Profile::Rule
    } else {
        Profile::Search
    }
}

/// Analyze a YARA-L file (`.yaral`, `.yl2`).
pub fn analyze(source: &str) -> AnalyzeResult {
    analyze_with(source, &Context::FILE)
}

/// Analyze YARA-L text where `ctx` says it runs.
pub fn analyze_with(source: &str, ctx: &Context) -> AnalyzeResult {
    AnalyzeResult {
        diagnostics: diagnostics(source, ctx),
        tokens: highlight(source),
    }
}

/// Every diagnostic of a text, in source order.
pub fn diagnostics(source: &str, ctx: &Context) -> Vec<Diagnostic> {
    let profile = ctx.profile.unwrap_or_else(|| infer_profile(source));
    let mut findings = Vec::new();
    match opentide_syntax::parse(LanguageId::Yaral, source) {
        None => findings.push(Finding::new(
            codes::YARAL_PARSE_ERROR,
            Severity::Error,
            "the YARA-L parser could not read this text".into(),
            0,
            source.len().max(1),
        )),
        Some(tree) if tree.root_node().has_error() => {
            findings.push(parse_error(source, &tree));
            // String escapes are lexical: still reported.
            let mut checker = check::Checker::new(source, profile, ctx.meta_required);
            opentide_syntax::walk_with_ancestors(tree.root_node(), |n, _| {
                if n.kind() == "string" && !n.has_error() {
                    checker_escapes(&mut checker, n);
                }
            });
            findings.extend(checker.findings);
        }
        Some(tree) => {
            let mut checker = check::Checker::new(source, profile, ctx.meta_required);
            checker.run(&tree);
            findings.extend(checker.findings);
        }
    }
    findings.sort_by_key(|f| (f.start, f.end));
    findings.dedup();
    let lines = LineIndex::new(source);
    findings
        .into_iter()
        .map(|f| Diagnostic {
            code: f.code.to_string(),
            severity: f.severity,
            message: f.message,
            range: Range::new(
                lines.position(f.start.min(source.len())),
                lines.position(f.end.max(f.start).min(source.len())),
            ),
            field_path: None,
            suggestion: None,
            object_uuid: None,
            object_type: None,
        })
        .collect()
}

fn checker_escapes(checker: &mut check::Checker<'_>, node: tree_sitter::Node<'_>) {
    checker.string_escapes(node);
}

/// The first syntax error. A comma between condition terms is
/// `yaral_condition_shape`: Google refuses commas there.
fn parse_error(source: &str, tree: &tree_sitter::Tree) -> Finding {
    let root = tree.root_node();
    let node = opentide_syntax::first_error(root).unwrap_or(root);
    let span = opentide_syntax::node_span(node);
    let mut in_condition = false;
    let mut cursor = node;
    while let Some(parent) = cursor.parent() {
        if parent.kind() == "condition_section" {
            in_condition = true;
            break;
        }
        cursor = parent;
    }
    let text = source.get(span.start..span.end).unwrap_or("");
    if in_condition && text.contains(',') {
        let comma = span.start + text.find(',').unwrap_or(0);
        return Finding::new(
            codes::YARAL_CONDITION_SHAPE,
            Severity::Error,
            "`condition` terms are joined with `and` or `or`, never a comma".into(),
            comma,
            comma + 1,
        );
    }
    let message = if node.is_missing() {
        format!("YARA-L expects `{}` here", node.kind())
    } else {
        let shown: String = text.chars().take(40).collect();
        let shown = shown.split('\n').next().unwrap_or("").trim();
        if shown.is_empty() {
            "the YARA-L text does not parse here".to_string()
        } else {
            format!("the YARA-L text does not parse at `{shown}`")
        }
    };
    Finding::new(
        codes::YARAL_PARSE_ERROR,
        Severity::Error,
        message,
        span.start,
        span.end,
    )
}

/// Semantic tokens from the grammar and `highlights.scm`.
pub fn highlight(source: &str) -> Vec<HighlightToken> {
    let Ok(spec) = HighlightSpec::load() else {
        return Vec::new();
    };
    let Ok(spans) =
        opentide_syntax::query_captures(LanguageId::Yaral, source, YARAL_HIGHLIGHTS_SCM)
    else {
        return Vec::new();
    };
    let spans: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(&spec, source, &spans).unwrap_or_default()
}
