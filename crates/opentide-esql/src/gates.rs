//! Version checks for ES|QL syntax that only some release lines accept.
//!
//! Names (commands, functions, cast types) carry their release lines in the
//! catalog. Forms that are not names — `RENAME new = old`, `LIKE (…)` lists,
//! `::failures` selectors, `??` parameters, the `m` time unit, subqueries, and
//! the 8.19-only spellings — are listed here, each with the lines whose
//! grammar (or, for `m`, whose time-unit table) accepts it. Evidence is each
//! release branch's `x-pack/plugin/esql/src/main/antlr` grammar and, where
//! noted, its Java builder.

use crate::syntax::SyntaxKind as K;
use crate::tree::Node;
use crate::version::{Availability, StackTarget};
use crate::{SyntaxNode, ast};
use opentide_core::{ByteSpan, Diagnostic, Range, Severity, codes};
use opentide_parse::ast::AstNode;
use rowan::NodeOrToken;

pub(crate) type SyntaxElement = rowan::SyntaxElement<crate::Lang>;

/// One version-gated construct found in the query.
pub(crate) struct Gate {
    /// What the message names: "function `COPY_SIGN()`", "`RENAME new = old`".
    pub subject: String,
    pub available: Availability,
    /// Extra text after the version clause (a lifecycle, a rewrite).
    pub note: Option<String>,
    /// Replacement text for the diagnostic range.
    pub suggestion: Option<String>,
    /// Severity against the supported range when the newest line accepts the
    /// form. Defaults to information; removed forms are always a warning.
    pub floor_severity: Option<Severity>,
    pub span: ByteSpan,
}

impl Gate {
    fn new(subject: impl Into<String>, available: Availability, span: ByteSpan) -> Self {
        Self {
            subject: subject.into(),
            available,
            note: None,
            suggestion: None,
            floor_severity: None,
            span,
        }
    }

    fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    fn suggest(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    fn severity(mut self, severity: Severity) -> Self {
        self.floor_severity = Some(severity);
        self
    }

    /// The diagnostic for this gate, or `None` when the stack accepts it.
    ///
    /// Without a target the query is checked against every supported line
    /// (elastic-1.0: 8.19 and 9.x): information when only older lines lack
    /// the form, a warning when the newest line rejects it (a removed form).
    /// With a declared target, a warning when that line rejects it.
    pub fn diagnostic(
        self,
        target: Option<StackTarget>,
        range: impl Fn(ByteSpan) -> Range,
    ) -> Option<Diagnostic> {
        let available = self.available;
        let (message, severity) = match target {
            None => {
                if available.is_all() {
                    return None;
                }
                let severity = if available.on_newest() {
                    self.floor_severity.unwrap_or(Severity::Information)
                } else {
                    Severity::Warning
                };
                (
                    format!("{}: {}", self.subject, available.describe()),
                    severity,
                )
            }
            Some(target) => {
                if available.on(target) {
                    return None;
                }
                let works = if available.is_empty() {
                    "no release accepts it".to_string()
                } else {
                    format!(
                        "it works on {}",
                        crate::version::join_versions(&available.versions())
                    )
                };
                (
                    format!(
                        "{}: Elasticsearch {target} rejects it ({works})",
                        self.subject
                    ),
                    Severity::Warning,
                )
            }
        };
        let message = match &self.note {
            Some(note) => format!("{message}; {note}"),
            None => message,
        };
        let mut d = Diagnostic::warning(codes::ESQL_UNAVAILABLE, message, range(self.span));
        d.severity = severity;
        if let Some(s) = self.suggestion {
            d = d.with_suggestion(s);
        }
        Some(d)
    }
}

/// Lines with 8.19 plus 9.1 and later: forms 9.0 does not have.
const NOT_9_0: Availability = Availability::with_8_19_since_9(1);

/// A rowan node's span.
pub(crate) fn span_of(node: &SyntaxNode) -> ByteSpan {
    let range = node.text_range();
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// A rowan node's text in `source`.
pub(crate) fn text_of<'s>(node: &SyntaxNode, source: &'s str) -> &'s str {
    let span = span_of(node);
    source.get(span.start..span.end).unwrap_or("")
}

/// A node's children as the checks read them: its nodes and tokens in order,
/// without whitespace and comments, and with `WITH {…}` (`NamedParameters`)
/// read in place, as one part of the command.
pub(crate) fn parts(node: &SyntaxNode) -> Vec<SyntaxElement> {
    let mut out = Vec::new();
    for child in node.children_with_tokens() {
        match &child {
            NodeOrToken::Node(n) if n.kind() == K::NAMED_PARAMETERS => {
                out.extend(n.children_with_tokens().filter(|c| !trivia(c.kind())));
            }
            _ if trivia(child.kind()) => {}
            _ => out.push(child),
        }
    }
    out
}

fn trivia(kind: K) -> bool {
    matches!(kind, K::WHITESPACE | K::COMMENT)
}

/// The position of the first token of `kinds` in `parts`.
pub(crate) fn first_token(parts: &[SyntaxElement], kinds: &[K]) -> Option<usize> {
    parts
        .iter()
        .position(|p| p.as_token().is_some() && kinds.contains(&p.kind()))
}

/// The nodes of `parts` after position `at`.
pub(crate) fn nodes_after(parts: &[SyntaxElement], at: usize) -> impl Iterator<Item = &SyntaxNode> {
    parts.iter().skip(at + 1).filter_map(|p| p.as_node())
}

/// The command nodes: what a subquery's enclosing check stops at.
fn is_command(kind: K) -> bool {
    ast::Command::can_cast(kind) || kind == K::SET_COMMAND
}

/// The kinds [`syntax_gates`] reads: the arena keeps the rowan node of these
/// only, so the rest of the lossless tree is freed as it is built (a test
/// checks that no other kind has a gate).
pub(crate) const GATED: &[K] = &[
    K::RENAME_CLAUSE,
    K::LIKE_EXPRESSION,
    K::INDEX_PATTERN,
    K::PARAMETER,
    K::QUALIFIED_INTERVAL,
    K::SOURCE_SUBQUERY,
    K::IN_TUPLE,
    K::LIMIT_COMMAND,
    K::GROK_COMMAND,
    K::CHANGE_POINT_COMMAND,
    K::JOIN_COMMAND,
    K::MAP_EXPRESSION,
    K::COMPLETION_COMMAND,
    K::METADATA,
];

/// Version gates for one node (not names: those come from the catalog).
pub(crate) fn syntax_gates(node: &SyntaxNode, source: &str) -> Vec<Gate> {
    let mut out = Vec::new();
    let span = span_of(node);
    let parts = parts(node);
    let nodes: Vec<&SyntaxNode> = parts.iter().filter_map(|p| p.as_node()).collect();
    match node.kind() {
        K::RENAME_CLAUSE if first_token(&parts, &[K::EQ]).is_some() => {
            let mut gate = Gate::new("`RENAME new = old`", NOT_9_0, span)
                .note("`RENAME old AS new` works everywhere");
            // `old AS new`, or `new = old`.
            let as_first = first_token(&parts, &[K::AS_KW]).is_some();
            if let (Some(a), Some(b)) = (nodes.first(), nodes.get(1)) {
                let (old, new) = if as_first { (a, b) } else { (b, a) };
                gate = gate.suggest(format!(
                    "{} AS {}",
                    text_of(old, source),
                    text_of(new, source)
                ));
            }
            out.push(gate);
        }
        K::LIKE_EXPRESSION => {
            let op = first_token(&parts, &[K::LIKE_KW, K::RLIKE_KW]);
            let rlike = op.is_some_and(|at| parts[at].kind() == K::RLIKE_KW);
            let word = if rlike { "RLIKE" } else { "LIKE" };
            if first_token(&parts, &[K::L_PAREN]).is_some() {
                let available = if rlike {
                    Availability::since_9(2)
                } else {
                    NOT_9_0
                };
                out.push(
                    Gate::new(format!("a `{word} (…)` pattern list"), available, span).note(
                        format!("`x {word} \"a\" OR x {word} \"b\"` works everywhere"),
                    ),
                );
            }
            // The patterns follow the operator; the parser reads the operand
            // before it (`expressions.rs`, `Infix::Like`).
            let patterns = op.map(|at| nodes_after(&parts, at)).into_iter().flatten();
            for pattern in patterns {
                match pattern.kind() {
                    K::STRING => {}
                    K::PARAMETER => out.push(Gate::new(
                        format!("a parameter as a {word} pattern"),
                        Availability::since_9(3),
                        span_of(pattern),
                    )),
                    _ => out.push(Gate::new(
                        format!("a {word} pattern that is not a string literal"),
                        Availability::since_9(6),
                        span_of(pattern),
                    )),
                }
            }
        }
        K::INDEX_PATTERN => {
            let pattern = ast::IndexPattern::cast(node.clone());
            if let Some(selector) = pattern.as_ref().and_then(ast::IndexPattern::selector) {
                if pattern
                    .as_ref()
                    .and_then(ast::IndexPattern::cluster)
                    .is_some()
                {
                    out.push(Gate::new(
                        "a `cluster:index::selector` pattern",
                        Availability::since_9(4),
                        span,
                    ));
                } else {
                    out.push(Gate::new(
                        format!("the `::{}` selector", text_of(selector.syntax(), source)),
                        NOT_9_0,
                        span_of(selector.syntax()),
                    ));
                }
            }
        }
        K::PARAMETER if text_of(node, source).starts_with("??") => {
            out.push(Gate::new("a `??` identifier parameter", NOT_9_0, span));
        }
        K::QUALIFIED_INTERVAL => {
            if let Some(unit) = nodes.iter().find(|n| n.kind() != K::NUMBER)
                && text_of(unit, source).eq_ignore_ascii_case("m")
            {
                // EsqlDataTypeConverter.INTERVALS gains `M` on 9.3; earlier
                // lines reject `5 m` and `5m` ("Unexpected temporal unit").
                out.push(
                    Gate::new(
                        "the minute unit `m`",
                        Availability::since_9(3),
                        span_of(unit),
                    )
                    .note("`min` or `minute` works everywhere")
                    .suggest("min"),
                );
            }
        }
        K::SOURCE_SUBQUERY => out.extend(subquery_gate(node, &nodes)),
        K::IN_TUPLE => out.push(Gate::new(
            "an `(a, b) IN (subquery)` tuple",
            Availability::since_9(6),
            span,
        )),
        K::LIMIT_COMMAND
            if first_token(&parts, &[K::BY_KW])
                .is_some_and(|by| nodes_after(&parts, by).next().is_some()) =>
        {
            out.push(Gate::new(
                "`LIMIT … BY`",
                Availability::since_9(4),
                crate::keyword_span_of(node),
            ));
        }
        K::GROK_COMMAND if nodes.len() > 2 => {
            out.push(Gate::new(
                "`GROK` with several patterns",
                Availability::since_9(3),
                span,
            ));
        }
        K::CHANGE_POINT_COMMAND
            if first_token(&parts, &[K::BY_KW])
                .is_some_and(|by| nodes_after(&parts, by).next().is_some()) =>
        {
            out.push(Gate::new(
                "`CHANGE_POINT … BY`",
                Availability::since_9(5),
                span,
            ));
        }
        K::JOIN_COMMAND => {
            // The conditions follow `ON`; the parser reads the index before it
            // (`processing.rs`, `join`).
            let conditions: Vec<&SyntaxNode> = first_token(&parts, &[K::ON_KW])
                .map(|on| nodes_after(&parts, on).collect())
                .unwrap_or_default();
            let simple = conditions.len() == 1 && conditions[0].kind() == K::QUALIFIED_NAME;
            if !simple && !conditions.is_empty() {
                // One field only through 9.1 ("JOIN ON clause only supports one
                // field"); fields lists and expressions from 9.2.
                out.push(Gate::new(
                    "a `LOOKUP JOIN` condition with several fields or an expression",
                    Availability::since_9(2),
                    span,
                ));
            }
        }
        // A map recovery made up where `{` is missing (`WITH` at the end) is
        // not one the query wrote: no gate on it.
        K::MAP_EXPRESSION if span.start < span.end => {
            let nested = node.parent().is_some_and(|p| p.kind() == K::MAP_ENTRY);
            let entries: Vec<&&SyntaxNode> =
                nodes.iter().filter(|c| c.kind() == K::MAP_ENTRY).collect();
            // An entry's value is its second node (`key: value`).
            let has_nested = entries.iter().any(|e| {
                e.children()
                    .nth(1)
                    .is_some_and(|v| v.kind() == K::MAP_EXPRESSION)
            });
            if !nested && (entries.is_empty() || has_nested) {
                out.push(Gate::new(
                    "an empty or nested map",
                    Availability::since_9(2),
                    span,
                ));
            }
        }
        K::COMPLETION_COMMAND => {
            // 8.19 and 9.1: `COMPLETION prompt WITH endpoint`; the first node
            // after `WITH` that is not the `{…}` map. A target (`x =`) comes
            // before `WITH` (`processing.rs`, `completion`).
            let endpoint = first_token(&parts, &[K::WITH_KW])
                .and_then(|with| nodes_after(&parts, with).find(|n| n.kind() != K::MAP_EXPRESSION));
            if let Some(endpoint) = endpoint {
                let id = text_of(endpoint, source).trim_matches('`');
                out.push(
                    Gate::new(
                        "`COMPLETION … WITH endpoint`",
                        Availability::from_versions(&["8.19", "9.1"]),
                        span_of(endpoint),
                    )
                    .note(format!(
                        "9.2 and later take `WITH {{\"inference_id\": \"{id}\"}}`"
                    )),
                );
            } else if node
                .children()
                .filter(|c| c.kind() == K::NAMED_PARAMETERS)
                .any(|n| n.children().any(|m| m.kind() == K::MAP_EXPRESSION))
            {
                out.push(Gate::new(
                    "`COMPLETION … WITH {…}`",
                    Availability::since_9(2),
                    span,
                ));
            }
        }
        K::METADATA if first_token(&parts, &[K::L_BRACK]).is_some() => {
            let fields: Vec<&str> = nodes
                .iter()
                .filter(|n| n.kind() == K::METADATA_FIELD)
                .map(|f| text_of(f, source))
                .collect();
            out.push(
                Gate::new("`[METADATA …]` in brackets", Availability::ONLY_8_19, span)
                    .note("drop the brackets")
                    .suggest(format!("METADATA {}", fields.join(", "))),
            );
        }
        _ => {}
    }
    out
}

/// FROM subqueries are 9.4 (snapshot-only on 9.3); a ROW or TS subquery is
/// 9.5. `IN (subquery)` is 9.5 in WHERE and EVAL, and 9.6 inside an
/// aggregate filter, a function, a comparison, or `IS NULL`. `nodes` are the
/// subquery's own: its source command first.
fn subquery_gate(node: &SyntaxNode, nodes: &[&SyntaxNode]) -> Option<Gate> {
    let parent = node.parent()?;
    let span = span_of(node);
    if parent.kind() == K::IN_EXPRESSION {
        if parent
            .children()
            .next()
            .is_some_and(|l| l.kind() == K::IN_TUPLE)
        {
            // The tuple form has its own (later) gate.
            return None;
        }
        let nested = parent
            .ancestors()
            .skip(1)
            .take_while(|n| !is_command(n.kind()))
            .any(|n| {
                matches!(
                    n.kind(),
                    K::AGGREGATE_FIELD | K::FUNCTION_CALL | K::COMPARISON | K::IS_NULL_EXPRESSION
                )
            });
        return Some(if nested {
            Gate::new(
                "an `IN (subquery)` inside an aggregate filter, function, comparison, or `IS NULL`",
                Availability::since_9(6),
                span,
            )
        } else {
            Gate::new("an `IN (subquery)`", Availability::since_9(5), span)
        });
    }
    if matches!(parent.kind(), K::FROM_COMMAND | K::TS_COMMAND) {
        if nodes.first().map(|n| n.kind()) != Some(K::FROM_COMMAND) {
            return Some(Gate::new(
                "a `ROW` or `TS` subquery",
                Availability::since_9(5),
                span,
            ));
        }
        return Some(Gate::new(
            "a subquery in `FROM`",
            Availability::since_9(4),
            span,
        ));
    }
    None
}

/// What Elasticsearch's lexer does with the character right after a command
/// name. Through 9.5 an unknown-command token is any run of characters other
/// than whitespace, `[`, `]`, and `/`, and the longest match wins, so
/// `where(x` beats the keyword `where`. 9.6 also stops the run at `(` and `)`.
pub(crate) enum Spacing {
    /// `(` or `)`: 9.6 and later only.
    Paren,
    /// `|` or `"`: one unknown word on every release.
    Never(char),
}

pub(crate) fn command_spacing(node: Node, source: &str) -> Option<(Spacing, ByteSpan)> {
    if !node.kind().ends_with("_command") || node.kind() == "unknown_command" {
        return None;
    }
    let keyword = node.child(0)?;
    if keyword.is_named() {
        return None;
    }
    let next = source.get(keyword.end_byte()..)?.chars().next()?;
    let span = ByteSpan::new(keyword.start_byte(), keyword.end_byte() + next.len_utf8());
    match next {
        '(' | ')' => Some((Spacing::Paren, span)),
        '|' | '"' => Some((Spacing::Never(next), span)),
        _ => None,
    }
}

pub(crate) fn spacing_gate(
    word: &str,
    spacing: Spacing,
    span: ByteSpan,
    range: Range,
) -> Result<Gate, Box<Diagnostic>> {
    match spacing {
        Spacing::Paren => Ok(Gate::new(
            format!("`{word}(` with no space"),
            Availability::since_9(6),
            span,
        )
        .note(format!(
            "earlier lexers read `{word}(…` as one unknown command, and Kibana 9.4 and 9.5 may then run a non-aggregating rule without it; add a space"
        ))
        .suggest(format!("{word} ("))
        .severity(Severity::Warning)),
        Spacing::Never(c) => Err(Box::new(Diagnostic::error(
            codes::ESQL_PARSE_ERROR,
            format!(
                "Elasticsearch reads `{word}{c}` as one unknown command; put a space after `{word}`"
            ),
            range,
        )
        .with_suggestion(format!("{word} {c}")))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::Lang;

    /// The arena stopped a subquery's ancestors at a node whose name ends in
    /// `_command`; the typed check stops at the same kinds.
    #[test]
    fn the_command_kinds_are_the_command_nodes() {
        for raw in 0..=u16::MAX {
            let kind = <Lang as rowan::Language>::kind_from_raw(rowan::SyntaxKind(raw));
            if kind == K::ERROR && raw != K::ERROR as u16 {
                break;
            }
            let named = format!("{kind:?}").ends_with("_COMMAND");
            assert_eq!(is_command(kind), named, "{kind:?}");
        }
    }
    /// What every gate of `query` says: (subject, the text of its span, its
    /// suggestion). Each node that has a gate is of a [`GATED`] kind.
    fn gates(query: &str) -> Vec<(String, &str, Option<String>)> {
        crate::syntax_tree(query)
            .descendants()
            .flat_map(|n| {
                let gates = syntax_gates(&n, query);
                assert!(
                    gates.is_empty() || GATED.contains(&n.kind()),
                    "{:?} has a gate but is not in GATED",
                    n.kind()
                );
                gates
            })
            .map(|g| (g.subject, &query[g.span.start..g.span.end], g.suggestion))
            .collect()
    }

    /// The children each gate reads, by position where the grammar labels
    /// none: a rename's old and new, a LIKE's patterns beside its operand,
    /// a join's conditions beside its index, a completion's endpoint beside
    /// its target, a map entry's value beside its key.
    #[test]
    fn each_gate_reads_its_own_children() {
        let one = |s: &str, at: &'static str, sug: Option<&str>| {
            vec![(s.to_string(), at, sug.map(ToString::to_string))]
        };
        let rename = "`RENAME new = old`";
        assert_eq!(
            gates("ROW a = 1 | RENAME b = a"),
            one(rename, "b = a", Some("a AS b"))
        );
        assert_eq!(
            gates("FROM i | RENAME a = b AS c"),
            one(rename, "a = b", Some("b AS a"))
        );
        assert_eq!(gates("ROW a = 1 | RENAME c AS d"), []);
        let endpoint = "`COMPLETION … WITH endpoint`";
        assert_eq!(
            gates("FROM i | COMPLETION p WITH ep"),
            one(endpoint, "ep", None)
        );
        assert_eq!(
            gates("FROM i | COMPLETION x = p WITH ep"),
            one(endpoint, "ep", None)
        );
        let map = "an empty or nested map";
        assert_eq!(
            gates("FROM a | FUSE linear WITH {\"a\": {\"b\": 1}}"),
            one(map, "{\"a\": {\"b\": 1}}", None)
        );
        assert_eq!(gates("FROM a | FUSE linear WITH {\"a\": 1}"), []);
        assert_eq!(gates("FROM a | FUSE linear WITH {}"), one(map, "{}", None));
        assert_eq!(gates("ROW a = \"x\" | WHERE a LIKE \"x\""), []);
        assert_eq!(
            gates("ROW a = \"x\" | WHERE a LIKE ?p"),
            one("a parameter as a LIKE pattern", "?p", None)
        );
        assert_eq!(
            gates("ROW a = \"x\" | WHERE a LIKE b"),
            one("a LIKE pattern that is not a string literal", "b", None)
        );
        assert_eq!(gates("FROM a | LOOKUP JOIN t ON x"), []);
        let join = "a `LOOKUP JOIN` condition with several fields or an expression";
        let q = "FROM a | LOOKUP JOIN t ON x, y";
        assert_eq!(gates(q), one(join, &q[9..], None));
        assert_eq!(
            gates("ROW a = 1 | LIMIT 1 BY a"),
            one("`LIMIT … BY`", "LIMIT", None)
        );
        assert_eq!(gates("ROW a = 1 | LIMIT 1"), []);
        assert_eq!(
            gates("FROM logs-* [METADATA _id, _index]"),
            one(
                "`[METADATA …]` in brackets",
                "[METADATA _id, _index]",
                Some("METADATA _id, _index")
            )
        );
    }

    /// Every gate fires on its form, from a node of a [`GATED`] kind.
    #[test]
    fn every_gated_kind_has_a_gate() {
        let mut fired = std::collections::HashSet::new();
        for query in [
            "ROW a = 1 | RENAME b = a",
            "ROW a = \"x\" | WHERE a LIKE (\"x\", \"y\")",
            "FROM c:logs-*::data, logs-*::failures [METADATA _id]",
            "ROW a = 1 | WHERE a == ??b",
            "ROW a = NOW() - 5 m",
            "FROM a, (FROM b) | WHERE (b, e) IN (FROM c | KEEP d, f)",
            "ROW a = 1 | LIMIT 1 BY a | CHANGE_POINT a BY b",
            "ROW a = \"x\" | GROK a \"%{WORD:b}\", \"%{WORD:c}\"",
            "FROM a | LOOKUP JOIN t ON x, y | COMPLETION p WITH ep | FUSE linear WITH {}",
        ] {
            for node in crate::syntax_tree(query).descendants() {
                if !syntax_gates(&node, query).is_empty() {
                    fired.insert(node.kind());
                }
            }
        }
        let silent: Vec<_> = GATED.iter().filter(|k| !fired.contains(k)).collect();
        assert!(silent.is_empty(), "no gate fired on {silent:?}");
    }
}
