//! Version checks for ES|QL syntax that only some release lines accept.
//!
//! Names (commands, functions, cast types) carry their release lines in the
//! catalog. Forms that are not names — `RENAME new = old`, `LIKE (…)` lists,
//! `::failures` selectors, `??` parameters, the `m` time unit, subqueries, and
//! the 8.19-only spellings — are listed here, each with the lines whose
//! grammar (or, for `m`, whose time-unit table) accepts it. Evidence is each
//! release branch's `x-pack/plugin/esql/src/main/antlr` grammar and, where
//! noted, its Java builder.

use crate::text;
use crate::version::{Availability, StackTarget};
use opentide_core::{ByteSpan, Diagnostic, Range, Severity, codes};
use opentide_syntax::node_span;
use tree_sitter::Node;

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

fn has_child(node: Node, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == kind)
}

fn fields<'t>(node: Node<'t>, name: &str) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.children_by_field_name(name, &mut cursor).collect()
}

/// Version gates for one node (not names: those come from the catalog).
pub(crate) fn syntax_gates(node: Node, source: &str) -> Vec<Gate> {
    let mut out = Vec::new();
    let span = node_span(node);
    match node.kind() {
        "rename_clause" if has_child(node, "=") => {
            let mut gate = Gate::new("`RENAME new = old`", NOT_9_0, span)
                .note("`RENAME old AS new` works everywhere");
            if let (Some(old), Some(new)) = (
                node.child_by_field_name("old"),
                node.child_by_field_name("new"),
            ) {
                gate = gate.suggest(format!("{} AS {}", text(old, source), text(new, source)));
            }
            out.push(gate);
        }
        "like_expression" => {
            let rlike = node
                .child_by_field_name("operator")
                .is_some_and(|o| text(o, source).eq_ignore_ascii_case("rlike"));
            let word = if rlike { "RLIKE" } else { "LIKE" };
            let patterns = fields(node, "pattern");
            if has_child(node, "(") {
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
            for pattern in patterns {
                match pattern.kind() {
                    "string" => {}
                    "parameter" => out.push(Gate::new(
                        format!("a parameter as a {word} pattern"),
                        Availability::since_9(3),
                        node_span(pattern),
                    )),
                    _ => out.push(Gate::new(
                        format!("a {word} pattern that is not a string literal"),
                        Availability::since_9(6),
                        node_span(pattern),
                    )),
                }
            }
        }
        "index_pattern" => {
            if let Some(selector) = node.child_by_field_name("selector") {
                if node.child_by_field_name("cluster").is_some() {
                    out.push(Gate::new(
                        "a `cluster:index::selector` pattern",
                        Availability::since_9(4),
                        span,
                    ));
                } else {
                    out.push(Gate::new(
                        format!("the `::{}` selector", text(selector, source)),
                        NOT_9_0,
                        node_span(selector),
                    ));
                }
            }
        }
        "parameter" if text(node, source).starts_with("??") => {
            out.push(Gate::new("a `??` identifier parameter", NOT_9_0, span));
        }
        "qualified_interval" => {
            if let Some(unit) = node.child_by_field_name("unit") {
                if text(unit, source).eq_ignore_ascii_case("m") {
                    // EsqlDataTypeConverter.INTERVALS gains `M` on 9.3; earlier
                    // lines reject `5 m` and `5m` ("Unexpected temporal unit").
                    out.push(
                        Gate::new(
                            "the minute unit `m`",
                            Availability::since_9(3),
                            node_span(unit),
                        )
                        .note("`min` or `minute` works everywhere")
                        .suggest("min"),
                    );
                }
            }
        }
        "source_subquery" => out.extend(subquery_gate(node)),
        "in_tuple" => out.push(Gate::new(
            "an `(a, b) IN (subquery)` tuple",
            Availability::since_9(6),
            span,
        )),
        "limit_command" if !fields(node, "by").is_empty() => {
            out.push(Gate::new(
                "`LIMIT … BY`",
                Availability::since_9(4),
                crate::keyword_span(node),
            ));
        }
        "grok_command" if fields(node, "pattern").len() > 1 => {
            out.push(Gate::new(
                "`GROK` with several patterns",
                Availability::since_9(3),
                span,
            ));
        }
        "change_point_command" if !fields(node, "by").is_empty() => {
            out.push(Gate::new(
                "`CHANGE_POINT … BY`",
                Availability::since_9(5),
                span,
            ));
        }
        "join_command" => {
            let conditions = fields(node, "condition");
            let simple = conditions.len() == 1 && conditions[0].kind() == "qualified_name";
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
        "map_expression" => {
            let nested = node.parent().is_some_and(|p| p.kind() == "map_entry");
            let mut cursor = node.walk();
            let entries: Vec<Node> = node
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "map_entry")
                .collect();
            let has_nested = entries.iter().any(|e| {
                e.child_by_field_name("value")
                    .is_some_and(|v| v.kind() == "map_expression")
            });
            if !nested && (entries.is_empty() || has_nested) {
                out.push(Gate::new(
                    "an empty or nested map",
                    Availability::since_9(2),
                    span,
                ));
            }
        }
        "completion_command" => {
            if let Some(endpoint) = node.child_by_field_name("inference_id") {
                let id = text(endpoint, source).trim_matches('`');
                out.push(
                    Gate::new(
                        "`COMPLETION … WITH endpoint`",
                        Availability::from_versions(&["8.19", "9.1"]),
                        node_span(endpoint),
                    )
                    .note(format!(
                        "9.2 and later take `WITH {{\"inference_id\": \"{id}\"}}`"
                    )),
                );
            } else if node.child_by_field_name("options").is_some() {
                out.push(Gate::new(
                    "`COMPLETION … WITH {…}`",
                    Availability::since_9(2),
                    span,
                ));
            }
        }
        "metadata" if node.child_by_field_name("bracket").is_some() => {
            let fields: Vec<&str> = fields(node, "field")
                .into_iter()
                .map(|f| text(f, source))
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
/// aggregate filter, a function, a comparison, or `IS NULL`.
fn subquery_gate(node: Node) -> Option<Gate> {
    let parent = node.parent()?;
    let span = node_span(node);
    let source_kind = node.child_by_field_name("source").map(|s| s.kind());
    if parent.kind() == "in_expression" {
        if parent
            .child_by_field_name("left")
            .is_some_and(|l| l.kind() == "in_tuple")
        {
            // The tuple form has its own (later) gate.
            return None;
        }
        let mut nested = false;
        let mut cur = parent.parent();
        while let Some(n) = cur {
            if n.kind().ends_with("_command") {
                break;
            }
            if matches!(
                n.kind(),
                "aggregate_field" | "function_call" | "comparison" | "is_null_expression"
            ) {
                nested = true;
                break;
            }
            cur = n.parent();
        }
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
    if matches!(parent.kind(), "from_command" | "ts_command") {
        if source_kind != Some("from_command") {
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
