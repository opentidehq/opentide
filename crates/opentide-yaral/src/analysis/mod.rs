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
    check(source, ctx, parsed, root, None)
}

/// [`diagnostics_of`] and the semantic tokens, from one walk over every
/// element: the checks' walk gathers the highlight's spans (ADR 0014 §5a).
pub(crate) fn analysis_of(
    source: &str,
    ctx: Context,
    parsed: &Parse,
    root: &SyntaxNode,
) -> (Vec<Diagnostic>, Vec<opentide_highlight::HighlightToken>) {
    let mut spans = Vec::new();
    let diagnostics = check(source, ctx, parsed, root, Some(&mut spans));
    (diagnostics, highlight::tokens(&spans, source))
}

fn check(
    source: &str,
    ctx: Context,
    parsed: &Parse,
    root: &SyntaxNode,
    spans: Option<&mut Vec<(opentide_core::ByteSpan, &'static str)>>,
) -> Vec<Diagnostic> {
    let profile = ctx.profile.unwrap_or_else(|| profile_of(source, root));
    let mut findings = Vec::new();
    let mut checker = checker::Checker::new(source, profile, ctx.meta_required);
    let gather = spans.is_some();
    if gather {
        checker.spans = Some(Vec::new());
    }
    if let Some(first) = parsed.errors.first() {
        findings.push(parse_error(source, root, first));
        // String escapes are lexical: still reported.
        for element in root.descendants_with_tokens() {
            count_visit();
            if let NodeOrToken::Token(t) = element {
                if let Some(spans) = &mut checker.spans {
                    spans.extend(highlight::span(&t));
                }
                if t.kind() == K::STRING {
                    checker.escapes(&t);
                }
            }
        }
    } else {
        checker.run(root);
    }
    if let (Some(out), Some(gathered)) = (spans, checker.spans.take()) {
        *out = gathered;
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

#[cfg(test)]
thread_local! {
    /// The elements the walks over every element visited on this thread: [`visits`].
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one element a walk over every element visited, in tests (ADR 0014 §7).
#[inline]
pub(super) fn count_visit() {
    #[cfg(test)]
    VISITS.set(VISITS.get() + 1);
}

/// How many elements the walks over every element visited on this thread.
#[cfg(test)]
pub(crate) fn visits() -> usize {
    VISITS.get()
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
        // Nothing but trivia after it: right after the last token.
        let at = usize::from(error.anchor(source.len()));
        return Finding::new(codes::YARAL_PARSE_ERROR, Severity::Error, message, at, at);
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

#[cfg(test)]
mod walk_tests {
    use super::*;

    /// Rules and searches like the corpus's and Google's, written here: an
    /// engine crate reads no file, its tests in `src/` included
    /// (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        r#"rule adfs_dkm_key_access {
  meta:
    author = "Google Cloud Security"
    severity = "High"
  events:
    $object.metadata.event_type = "USER_RESOURCE_ACCESS"
    any $object.security_result.detection_fields.value = "properties:{8d3b}"
    $object.principal.labels["SubjectLogonId"] = $subject
    $login.metadata.event_type = "USER_LOGIN"
    $login.target.labels["TargetLogonId"] = $subject
    $login.principal.hostname = $hostname
  match:
    $hostname over 5m
  outcome:
    $risk_score = 85
    // a comment
    $pids = array_distinct($object.principal.process.pid)
    $n = count_distinct($login.metadata.id)
  condition:
    $object AND $login AND #subject > 1 OR NOT $x
  options:
    allow_zero_values = true
}"#,
        r#"rule r {
  meta:
    author = "a"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    strings.to_lower($e.principal.hostname) = "web01"
    re.regex($e.target.url, `login\.php`) nocase
    $e.target.ip IN %allow_list
    $e.principal.hostname = /web[0-9]+/ NOCASE
  condition:
    $e
}"#,
        "metadata.event_type = \"USER_LOGIN\"\nselect:\n  principal.ip, target.user.userid",
        "cross join\noutcome:\n  $n = 1",
        "rule broken {\n  events:\n    $e.metadata.event_type = \"A\\q\"\n  condition:\n    $e and\n",
        "rule r { events: $e.principal.ip = \"1.2.3.4\" match: $e over 1h condition: $e and window_start > 0 }",
    ];

    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        let cut: Vec<String> = SAMPLES
            .iter()
            .flat_map(|t| t.char_indices().step_by(3).map(|(i, _)| t[..i].to_owned()))
            .collect();
        out.extend(cut);
        out
    }

    /// The diagnostics and tokens of one walk are those of the checks' walk
    /// and the highlight's walk apart (ADR 0014 §5a).
    #[test]
    fn one_walk_gives_the_checks_and_the_highlight_of_two() {
        for source in texts() {
            for ctx in [Context::FILE, Context::SECTIONS, Context::SEARCH] {
                let parsed = parse(&source);
                let root = SyntaxNode::new_root(parsed.green.clone());
                let (diagnostics, tokens) = analysis_of(&source, ctx, &parsed, &root);
                assert_eq!(
                    format!("{diagnostics:?}"),
                    format!("{:?}", diagnostics_of(&source, ctx, &parsed, &root)),
                    "{source:?}"
                );
                assert_eq!(
                    format!("{tokens:?}"),
                    format!("{:?}", highlight(&root, &source)),
                    "{source:?}"
                );
            }
        }
    }

    /// An analysis walks every element once, whether the text parses or not
    /// (ADR 0014 §7): the checks' walk and the highlight's walked it twice.
    #[test]
    fn an_analysis_visits_each_element_once() {
        for source in [SAMPLES[0], SAMPLES[4]] {
            let elements = SyntaxNode::new_root(parse(source).green)
                .descendants_with_tokens()
                .count();
            let before = visits();
            crate::analyze(source);
            assert_eq!(visits() - before, elements, "{source:?}");
        }
    }
}
