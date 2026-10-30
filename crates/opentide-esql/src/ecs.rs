//! The indices an ES|QL query reads (`FROM`, `TS`), and the checks that
//! follow from them: ECS field types and near-miss names where every index
//! holds ECS documents (`logs-*` data streams, or indices a log source
//! declares with `ecs = true`), and `elastic_dataset_not_declared` where the
//! workspace declares Elastic indices.
//!
//! Field types are known only for columns the query reads straight from the
//! indices. The pipeline is followed command by command: a name `EVAL`,
//! `RENAME`, `DISSECT`, `GROK`, `ENRICH … WITH`, or `INLINE STATS` defines
//! is the query's own and is not checked. After `STATS`, or a command whose
//! columns the query text does not show (`LOOKUP JOIN`, `FORK`, `ENRICH`
//! without `WITH`, ...), nothing more is checked.
//!
//! What is an error is what the Verifier rejects: `LIKE` and `RLIKE` on a
//! column that is not a string, and a column passed to a function parameter
//! that takes no type of its kind (the catalog's parameter types). ES|QL
//! compares `text` with `==` and casts a string constant compared with an
//! `ip` or a date, so comparisons are never reported.

use crate::columns::{dissect_keys, grok_names, qualified};
use crate::{Catalog, range, string_value, text};
use opentide_core::{ByteSpan, Diagnostic, LanguageId};
use opentide_ecs::ValueType;
use opentide_syntax::{node_span, parse as ts_parse};
use std::collections::HashSet;
use tree_sitter::Node;

fn query_node(root: Node) -> Option<Node> {
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .find(|c| c.kind() == "query")
}

/// Every index name or pattern the source command reads, as written
/// (`remote:logs-*::data`), with its span. `None` when the query does not
/// start with `FROM` or `TS`, or reads a subquery.
fn sources(root: Node, source: &str) -> Option<Vec<(String, ByteSpan)>> {
    let command = query_node(root)?.child_by_field_name("source")?;
    if !matches!(command.kind(), "from_command" | "ts_command") {
        return None;
    }
    let mut out = Vec::new();
    let mut cursor = command.walk();
    for index in command.children_by_field_name("index", &mut cursor) {
        if index.kind() != "index_pattern" {
            return None;
        }
        let raw = text(index, source);
        let span = node_span(index);
        if raw.starts_with('"') {
            // `FROM "logs-*,winlogbeat-*"`: one string, several names.
            let value = string_value(raw)?;
            out.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(|n| (n.to_string(), span)),
            );
        } else {
            out.push((raw.to_string(), span));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The indices an ES|QL query reads from its `FROM` or `TS` command, as
/// written. `None` for `ROW`, `SHOW`, a subquery source, or a query that
/// does not parse.
pub fn source_indices(source: &str) -> Option<Vec<String>> {
    let tree = ts_parse(LanguageId::Esql, source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    sources(root, source).map(|s| s.into_iter().map(|(n, _)| n).collect())
}

/// The dataset and ECS diagnostics `analyze_for` adds.
pub(crate) fn dataset_diagnostics(root: Node, source: &str) -> Vec<Diagnostic> {
    if root.has_error() {
        return Vec::new();
    }
    let Some(indices) = sources(root, source) else {
        return Vec::new();
    };
    let mut out: Vec<Diagnostic> = indices
        .iter()
        .filter_map(|(name, span)| opentide_ecs::index_not_declared(name, range(source, *span)))
        .collect();
    let names: Vec<&str> = indices.iter().map(|(n, _)| n.as_str()).collect();
    if opentide_ecs::indices_are_ecs(&names) {
        if let Some(query) = query_node(root) {
            out.extend(Walker::new(source).run(query));
        }
    }
    out
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query as if every index
/// it reads held ECS documents. `analyze` adds them itself when the `FROM`
/// indices do; this entry point is for callers that know more.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    let Some(tree) = ts_parse(LanguageId::Esql, source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    match query_node(root) {
        Some(query) => Walker::new(source).run(query),
        None => Vec::new(),
    }
}

struct Walker<'s> {
    source: &'s str,
    catalog: &'static Catalog,
    /// Names the query itself defines; they shadow the index's columns.
    defined: HashSet<String>,
    out: Vec<Diagnostic>,
}

impl<'s> Walker<'s> {
    fn new(source: &'s str) -> Self {
        Self {
            source,
            catalog: Catalog::cached(),
            defined: HashSet::new(),
            out: Vec::new(),
        }
    }

    fn run(mut self, query: Node) -> Vec<Diagnostic> {
        let mut cursor = query.walk();
        let commands: Vec<Node> = query
            .children_by_field_name("command", &mut cursor)
            .collect();
        for command in commands {
            if !self.command(command) {
                break;
            }
        }
        self.out
    }

    fn define(&mut self, name: Option<String>) {
        if let Some(name) = name {
            self.defined.insert(name);
        }
    }

    /// Check one command and record what it defines. `false`: the columns
    /// after it are not known, so stop.
    fn command(&mut self, command: Node) -> bool {
        let named = |field: &str| -> Vec<Node> {
            let mut cursor = command.walk();
            command.children_by_field_name(field, &mut cursor).collect()
        };
        match command.kind() {
            "where_command" => {
                for n in named("condition") {
                    self.expression(n);
                }
                true
            }
            "sort_command" => {
                let mut cursor = command.walk();
                let keys: Vec<Node> = command
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() == "order_expression")
                    .filter_map(|c| c.child_by_field_name("key"))
                    .collect();
                for key in keys {
                    self.expression(key);
                }
                true
            }
            "eval_command" => {
                for field in self.fields(command) {
                    if let Some(value) = field.child_by_field_name("value") {
                        self.expression(value);
                    }
                    let name = field
                        .child_by_field_name("name")
                        .and_then(|n| qualified(n, self.source));
                    self.define(name);
                }
                true
            }
            "inline_stats_command" | "stats_command" => {
                for aggregate in named("aggregate") {
                    if let Some(value) = aggregate.child_by_field_name("value") {
                        self.expression(value);
                    }
                    if let Some(filter) = aggregate.child_by_field_name("filter") {
                        self.expression(filter);
                    }
                }
                for by in named("by") {
                    if let Some(value) = by.child_by_field_name("value") {
                        self.expression(value);
                    }
                }
                if command.kind() == "stats_command" {
                    return false;
                }
                for field in named("aggregate").into_iter().chain(named("by")) {
                    let name = field
                        .child_by_field_name("name")
                        .and_then(|n| qualified(n, self.source));
                    self.define(name);
                }
                true
            }
            "mv_expand_command" => {
                for n in named("field") {
                    self.expression(n);
                }
                true
            }
            "keep_command" | "drop_command" => {
                let mut cursor = command.walk();
                let patterns: Vec<Node> = command
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() == "name_pattern")
                    .collect();
                for pattern in patterns {
                    self.name_pattern(pattern);
                }
                true
            }
            "rename_command" => {
                let mut cursor = command.walk();
                let clauses: Vec<Node> = command
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() == "rename_clause")
                    .collect();
                for clause in clauses {
                    let (Some(old), Some(new)) = (
                        clause.child_by_field_name("old"),
                        clause.child_by_field_name("new"),
                    ) else {
                        return false;
                    };
                    let (Some(old_name), Some(new_name)) =
                        (qualified(old, self.source), qualified(new, self.source))
                    else {
                        return false;
                    };
                    if old_name.contains('*') || new_name.contains('*') {
                        return false;
                    }
                    self.name_pattern(old);
                    self.defined.insert(old_name);
                    self.defined.insert(new_name);
                }
                true
            }
            "dissect_command" | "grok_command" => {
                for input in named("input") {
                    self.expression(input);
                }
                for pattern in named("pattern") {
                    let Some(value) = string_value(text(pattern, self.source)) else {
                        return false;
                    };
                    let keys = if command.kind() == "dissect_command" {
                        dissect_keys(&value)
                    } else {
                        grok_names(&value)
                    };
                    let Some(keys) = keys else {
                        return false;
                    };
                    self.defined.extend(keys);
                }
                true
            }
            "enrich_command" => {
                let clauses = named("with");
                if clauses.is_empty() {
                    return false;
                }
                for clause in clauses {
                    let name = clause
                        .child_by_field_name("new")
                        .or_else(|| clause.child_by_field_name("field"))
                        .and_then(|n| qualified(n, self.source));
                    let Some(name) = name.filter(|n| !n.contains('*')) else {
                        return false;
                    };
                    self.defined.insert(name);
                }
                true
            }
            "limit_command" | "sample_command" | "dedup_command" => true,
            _ => false,
        }
    }

    fn fields<'t>(&self, command: Node<'t>) -> Vec<Node<'t>> {
        let mut cursor = command.walk();
        command
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "field_assignment_or_expression")
            .collect()
    }

    /// A column the query reads from its indices: not one it defines, not a
    /// parameter, not a pattern.
    fn source_column(&self, node: Node) -> Option<String> {
        if node.kind() != "qualified_name" {
            return None;
        }
        let name = qualified(node, self.source)?;
        (!self.defined.contains(&name) && !name.contains('*')).then_some(name)
    }

    fn name_pattern(&mut self, node: Node) {
        let Some(name) = qualified(node, self.source) else {
            return;
        };
        if name.contains('*') || self.defined.contains(&name) {
            return;
        }
        if let Some(d) =
            opentide_ecs::unknown_field_diagnostic(&name, || range(self.source, node_span(node)))
        {
            self.out.push(d);
        }
    }

    fn expression(&mut self, node: Node) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            match n.kind() {
                // `IN (FROM …)` reads other indices.
                "source_subquery" | "map_expression" => continue,
                "qualified_name" => {
                    if let Some(name) = self.source_column(n) {
                        if let Some(d) = opentide_ecs::unknown_field_diagnostic(&name, || {
                            range(self.source, node_span(n))
                        }) {
                            self.out.push(d);
                        }
                    }
                    continue;
                }
                "like_expression" => self.like(n),
                "function_call" => self.function(n),
                _ => {}
            }
            let mut cursor = n.walk();
            stack.extend(n.named_children(&mut cursor));
        }
    }

    fn like(&mut self, node: Node) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let Some(name) = self.source_column(left) else {
            return;
        };
        let Some((value_type, type_name)) = opentide_ecs::field_type(&name) else {
            return;
        };
        if value_type != ValueType::String {
            let operator = node
                .child_by_field_name("operator")
                .map(|o| text(o, self.source).to_ascii_uppercase())
                .unwrap_or_else(|| "LIKE".into());
            self.out.push(opentide_ecs::type_mismatch(
                &name,
                type_name,
                &format!("`{operator}`, which takes a string,"),
                range(self.source, node_span(left)),
            ));
        }
    }

    fn function(&mut self, node: Node) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let display = text(name_node, self.source);
        let Some(row) = self.catalog.function(display) else {
            return;
        };
        // The catalog lists required parameters first; where the signature
        // starts with an optional one (`DATE_FORMAT([dateFormat], date)`),
        // positions do not match the list, so the call is not judged.
        let sig = &row.signature;
        let inner = sig
            .find('(')
            .zip(sig.rfind(')'))
            .and_then(|(a, b)| sig.get(a + 1..b))
            .unwrap_or("");
        let written: Vec<String> = inner
            .split(',')
            .map(|p| p.replace(['[', ']'], "").trim().to_string())
            .filter(|p| !p.is_empty() && p != "...")
            .collect();
        let listed: Vec<&str> = row.parameters.iter().map(|p| p.name.as_str()).collect();
        if written != listed {
            return;
        }
        let variadic = sig.contains("...");
        let mut cursor = node.walk();
        let arguments: Vec<Node> = node
            .children_by_field_name("arguments", &mut cursor)
            .collect();
        let params = &row.parameters;
        for (i, argument) in arguments.iter().copied().enumerate() {
            // With an optional parameter before this one and fewer arguments
            // than parameters (`DATE_FORMAT(@timestamp)`), positions do not
            // say which parameter an argument fills.
            if arguments.len() < params.len() && params.iter().take(i + 1).any(|p| !p.required) {
                break;
            }
            let param = match params.get(i) {
                Some(p) => p,
                None if variadic && !params.is_empty() => &params[params.len() - 1],
                None => break,
            };
            let Some(column) = self.source_column(argument) else {
                continue;
            };
            let Some((value_type, type_name)) = opentide_ecs::field_type(&column) else {
                continue;
            };
            let accepted: Vec<ValueType> = param
                .types
                .iter()
                .filter_map(|t| ValueType::of_esql(t))
                .collect();
            // A parameter whose types the classes do not cover is not judged.
            if accepted.is_empty() || accepted.contains(&value_type) {
                continue;
            }
            self.out.push(opentide_ecs::type_mismatch(
                &column,
                type_name,
                &format!(
                    "it as `{}` of `{}` ({})",
                    param.name,
                    display.to_ascii_uppercase(),
                    param.types.join(", ")
                ),
                range(self.source, node_span(argument)),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::{Severity, codes};

    fn codes_of(query: &str) -> Vec<(String, Severity)> {
        crate::analyze(query)
            .diagnostics
            .into_iter()
            .filter(|d| d.code.starts_with("ecs_"))
            .map(|d| (d.code, d.severity))
            .collect()
    }

    fn mismatch(query: &str) -> bool {
        codes_of(query)
            .iter()
            .any(|(c, s)| c == codes::ECS_TYPE_MISMATCH && *s == Severity::Error)
    }

    #[test]
    fn like_on_an_ip_field() {
        let query = "FROM logs-* | WHERE source.ip LIKE \"10.*\"";
        let d: Vec<Diagnostic> = crate::analyze(query)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::ECS_TYPE_MISMATCH)
            .collect();
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].severity, Severity::Error);
        assert!(d[0].message.contains("`ip`"), "{}", d[0].message);
        assert_eq!(d[0].range.start.character, 20);
        assert!(mismatch(
            "FROM logs-* | WHERE process.pid NOT RLIKE \"1.*\""
        ));
        assert!(mismatch("FROM logs-* | WHERE TO_LOWER(source.ip) == \"x\""));
        assert!(mismatch(
            "FROM logs-* | WHERE CIDR_MATCH(source.address, \"10.0.0.0/8\")"
        ));
        assert!(mismatch(
            "FROM logs-* | EVAL d = DATE_TRUNC(1 hour, source.ip)"
        ));
    }

    #[test]
    fn only_on_ecs_indices_and_source_columns() {
        for query in [
            // Not ECS, or not only ECS.
            "FROM winlogbeat-* | WHERE source.ip LIKE \"10.*\"",
            "FROM logs-*, winlogbeat-* | WHERE source.ip LIKE \"10.*\"",
            "FROM logs-*::failures | WHERE source.ip LIKE \"10.*\"",
            // The query's own column.
            "FROM logs-* | EVAL source.ip = TO_STRING(source.ip) | WHERE source.ip LIKE \"10.*\"",
            "FROM logs-* | STATS c = COUNT(*) BY source.ip | WHERE c > 1",
            // Valid: ES|QL compares text with `==`, casts a string to an ip.
            "FROM logs-* | WHERE message == \"x\" AND source.ip == \"10.0.0.1\"",
            "FROM logs-* | WHERE process.command_line.text LIKE \"*x*\"",
            "FROM logs-* | WHERE CIDR_MATCH(source.ip, \"10.0.0.0/8\") AND TO_LOWER(process.name) == \"x\"",
            "FROM logs-* | WHERE TO_STRING(source.ip)::keyword LIKE \"10.*\"",
            // DATE_FORMAT's format is optional and comes first.
            "FROM logs-* | EVAL d = DATE_FORMAT(@timestamp)",
            "FROM logs-* | EVAL d = DATE_FORMAT(\"yyyy-MM-dd\", @timestamp)",
            "FROM logs-* | STATS COUNT_DISTINCT(source.ip), VALUES(process.pid) BY host.name",
            "FROM logs-* | WHERE azure.signinlogs.properties.app LIKE \"x*\"",
        ] {
            assert!(codes_of(query).is_empty(), "{query}: {:?}", codes_of(query));
        }
    }

    #[test]
    fn near_misses_warn() {
        let found = codes_of("FROM logs-* | WHERE process.nmae == \"x\" | KEEP process.nmae");
        assert_eq!(
            found,
            vec![
                (codes::ECS_UNKNOWN_FIELD.to_string(), Severity::Warning),
                (codes::ECS_UNKNOWN_FIELD.to_string(), Severity::Warning)
            ]
        );
        assert!(
            codes_of("FROM logs-* | EVAL process.nmae = 1 | WHERE process.nmae > 0").is_empty()
        );
    }

    #[test]
    fn source_indices_as_written() {
        assert_eq!(
            source_indices("FROM logs-*, remote:logs-x::data METADATA _id | LIMIT 1"),
            Some(vec!["logs-*".into(), "remote:logs-x::data".into()])
        );
        assert_eq!(
            source_indices("FROM \"logs-a,logs-b\""),
            Some(vec!["logs-a".into(), "logs-b".into()])
        );
        assert_eq!(source_indices("ROW a = 1"), None);
    }
}
