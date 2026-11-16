//! The YARA-L analysis on the pure-Rust parser (#1227, ADR 0012): the
//! diagnostics, the highlight tokens and what the editor reads from the tree.

pub(crate) mod checker;
mod highlight;
mod nav;
mod nodes;
mod support;

pub(crate) use nav::field_segments;

pub(crate) use highlight::highlight;

use crate::parser::parse;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use crate::{Context, Finding, Profile};
use opentide_core::{Diagnostic, LineIndex, Range, Severity, codes};
use opentide_parse::{ErrorKind, Parse, SyntaxError, describe_expected};
use rowan::NodeOrToken;
use std::collections::HashMap;
use std::sync::OnceLock;

/// The profile of `source`: a rule when it holds a `rule` declaration.
pub(crate) fn infer_profile(source: &str) -> Profile {
    profile_of(source, &SyntaxNode::new_root(parse(source).green))
}

fn profile_of(source: &str, root: &SyntaxNode) -> Profile {
    let rule = root.children().any(|n| n.kind() == K::RULE_DECLARATION);
    if rule || source.trim_start().to_ascii_lowercase().starts_with("rule") {
        Profile::Rule
    } else {
        Profile::Search
    }
}

/// Every diagnostic of a text, in source order.
pub(crate) fn diagnostics(source: &str, ctx: Context) -> Vec<Diagnostic> {
    let parsed = parse(source);
    let root = SyntaxNode::new_root(parsed.green.clone());
    diagnostics_of(source, ctx, &parsed, &root)
}

/// [`diagnostics`] of a text already parsed: `root` is `parsed`'s tree.
pub(crate) fn diagnostics_of(
    source: &str,
    ctx: Context,
    parsed: &Parse,
    root: &SyntaxNode,
) -> Vec<Diagnostic> {
    let profile = ctx.profile.unwrap_or_else(|| profile_of(source, root));
    let mut findings = Vec::new();
    let mut checker = checker::Checker::new(source, profile, ctx.meta_required);
    if let Some(first) = parsed.errors.first() {
        findings.push(parse_error(source, root, first));
        // String escapes are lexical: still reported.
        for element in root.descendants_with_tokens() {
            if let NodeOrToken::Token(t) = element
                && t.kind() == K::STRING
            {
                checker.escapes(&t);
            }
        }
    } else {
        checker.run(root);
    }
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

/// The names an error message gives a kind: its text, or what it stands for.
fn expected_name(kind: rowan::SyntaxKind) -> &'static str {
    static NAMES: OnceLock<HashMap<u16, String>> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        let mut names = HashMap::new();
        for raw in 0..(K::ERROR as u16) {
            let kind = K::from_raw(rowan::SyntaxKind(raw));
            let name = match kind {
                K::META_KW
                | K::SETUP_KW
                | K::EVENTS_KW
                | K::MATCH_KW
                | K::OUTCOME_KW
                | K::CONDITION_KW
                | K::OPTIONS_KW
                | K::EXPORT_KW
                | K::DEDUP_KW
                | K::ORDER_KW
                | K::LIMIT_KW
                | K::SELECT_KW
                | K::UNSELECT_KW => "a section label such as `events:`".to_owned(),
                K::WHITESPACE | K::COMMENT | K::ERROR_TOKEN => String::new(),
                other => other.describe(),
            };
            names.insert(raw, name);
        }
        names
    });
    names.get(&kind.0).map_or("", String::as_str)
}

/// The first significant token at or after `offset`.
fn token_from(root: &SyntaxNode, offset: usize) -> Option<SyntaxToken> {
    root.descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .find(|t| {
            !matches!(t.kind(), K::WHITESPACE | K::COMMENT)
                && usize::from(t.text_range().start()) >= offset
        })
}

/// The finding of the first syntax error: where it is, what was there, what
/// the parser expected. A comma between condition terms is
/// `yaral_condition_shape`: Google refuses commas there.
fn parse_error(source: &str, root: &SyntaxNode, error: &SyntaxError) -> Finding {
    let end = usize::from(error.gap.end());
    let Some(token) = token_from(root, end) else {
        let message = match error.kind {
            ErrorKind::Syntax => match describe_expected(error.expected, expected_name) {
                Some(list) => format!("YARA-L expects {list} here"),
                None => format!("the YARA-L text ends here: {}", error.message),
            },
            _ => error.message.clone(),
        };
        return Finding::new(
            codes::YARAL_PARSE_ERROR,
            Severity::Error,
            message,
            source.len(),
            source.len() + 1,
        );
    };
    // The run of tokens the parser gave up on, when it wrapped them.
    let region = token
        .parent_ancestors()
        .find(|n| n.kind() == K::ERROR)
        .unwrap_or_else(|| token.parent().unwrap_or_else(|| root.clone()));
    let (start, stop) = if region.kind() == K::ERROR {
        let r = region.text_range();
        (usize::from(r.start()), usize::from(r.end()))
    } else {
        let r = token.text_range();
        (usize::from(r.start()), usize::from(r.end()))
    };
    let stop = stop.max(start + 1);
    let text = source.get(start..stop.min(source.len())).unwrap_or("");
    let in_condition = region.ancestors().any(|n| n.kind() == K::CONDITION_SECTION)
        || (region.kind() == K::ERROR
            && region
                .prev_sibling()
                .is_some_and(|p| p.kind() == K::CONDITION_SECTION));
    if in_condition && error.kind == ErrorKind::Syntax && text.contains(',') {
        let comma = start + text.find(',').unwrap_or(0);
        return Finding::new(
            codes::YARAL_CONDITION_SHAPE,
            Severity::Error,
            "`condition` terms are joined with `and` or `or`, never a comma".into(),
            comma,
            comma + 1,
        );
    }
    let message = match error.kind {
        ErrorKind::Syntax => {
            let shown: String = text.chars().take(40).collect();
            let shown = shown.split('\n').next().unwrap_or("").trim();
            let at = if shown.is_empty() {
                "the YARA-L text does not parse here".to_string()
            } else {
                format!("the YARA-L text does not parse at `{shown}`")
            };
            match describe_expected(error.expected, expected_name) {
                Some(list) => format!("{at}: expected {list}"),
                None => format!("{at}: {}", error.message),
            }
        }
        _ => error.message.clone(),
    };
    Finding::new(
        codes::YARAL_PARSE_ERROR,
        Severity::Error,
        message,
        start,
        stop,
    )
}
