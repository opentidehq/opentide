//! The indices an ES|QL query reads (`FROM`, `TS`), and the checks that
//! follow from them: ECS field types and near-miss names where every index
//! holds ECS documents (`logs-*` data streams; the fields `visibility.toml`
//! declares for an index pattern count as mapped there), and
//! `elastic_dataset_not_declared` where the workspace has elastic log sources.
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

use crate::catalog::Catalog;
use crate::columns::{
    Assignment, assignment, child_of, dissect_keys, grok_names, nodes, qualified_of as qualified,
    renamed,
};
use crate::gates::{first_token, nodes_after, parts, span_of, text_of as text};
use crate::syntax::SyntaxKind as K;
use crate::tree::Tree;
use crate::{SyntaxNode, range, string_value};
use opentide_core::{ByteSpan, Diagnostic};
use opentide_ecs::ValueType;
use std::collections::HashSet;

fn query_node(tree: &Tree) -> Option<SyntaxNode> {
    tree.syntax.children().find(|c| c.kind() == K::QUERY)
}

/// A query's commands, its source command first.
fn commands(query: &SyntaxNode) -> Vec<SyntaxNode> {
    parts(query)
        .into_iter()
        .filter_map(|p| p.into_node())
        .collect()
}

/// Every index name or pattern the source command reads, as written
/// (`remote:logs-*::data`), with its span. `None` when the query does not
/// start with `FROM` or `TS`, or reads a subquery.
fn sources(tree: &Tree, source: &str) -> Option<Vec<(String, ByteSpan)>> {
    let command = commands(&query_node(tree)?).into_iter().next()?;
    if !matches!(command.kind(), K::FROM_COMMAND | K::TS_COMMAND) {
        return None;
    }
    let mut out = Vec::new();
    // Every node but the metadata is an index.
    for (_, index) in nodes(&parts(&command)).filter(|(_, n)| n.kind() != K::METADATA) {
        if index.kind() != K::INDEX_PATTERN {
            return None;
        }
        let raw = text(index, source);
        let span = span_of(index);
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
    let tree = crate::tree::parse_tree(source)?;
    if tree.root_node().has_error() {
        return None;
    }
    sources(&tree, source).map(|s| s.into_iter().map(|(n, _)| n).collect())
}

/// The dataset and ECS diagnostics `analyze_for` adds.
pub(crate) fn dataset_diagnostics(tree: &Tree, source: &str) -> Vec<Diagnostic> {
    if tree.root_node().has_error() {
        return Vec::new();
    }
    let Some(indices) = sources(tree, source) else {
        return Vec::new();
    };
    let mut out: Vec<Diagnostic> = indices
        .iter()
        .filter_map(|(name, span)| opentide_ecs::index_not_declared(name, range(source, *span)))
        .collect();
    let names: Vec<&str> = indices.iter().map(|(n, _)| n.as_str()).collect();
    if opentide_ecs::indices_are_ecs(&names)
        && let Some(query) = query_node(tree)
    {
        let ecs = opentide_ecs::with_declared_fields(&names, || Walker::new(source).run(&query));
        out.extend(ecs);
    }
    out
}

/// `ecs_type_mismatch` and `ecs_unknown_field` for a query as if every index
/// it reads held ECS documents. `analyze` adds them itself when the `FROM`
/// indices do; this entry point is for callers that know more.
pub fn ecs_diagnostics(source: &str) -> Vec<Diagnostic> {
    crate::with_lines(source, || field_diagnostics(source))
}

fn field_diagnostics(source: &str) -> Vec<Diagnostic> {
    let Some(tree) = crate::tree::parse_tree(source) else {
        return Vec::new();
    };
    if tree.root_node().has_error() {
        return Vec::new();
    }
    match query_node(&tree) {
        Some(query) => Walker::new(source).run(&query),
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

    fn run(mut self, query: &SyntaxNode) -> Vec<Diagnostic> {
        for command in commands(query).iter().skip(1) {
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
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per command, as the pipeline reads them"
    )]
    fn command(&mut self, command: &SyntaxNode) -> bool {
        let own = parts(command);
        let all = || nodes(&own).map(|(_, n)| n.clone()).collect::<Vec<_>>();
        // The aggregates before `BY`, the groups after it.
        let by = first_token(&own, &[K::BY_KW]);
        let aggregates = || -> Vec<SyntaxNode> {
            nodes(&own)
                .filter(|(i, _)| by.is_none_or(|b| *i < b))
                .map(|(_, n)| n.clone())
                .collect()
        };
        let groups = || -> Vec<SyntaxNode> {
            by.map(|b| nodes_after(&own, b).cloned().collect())
                .unwrap_or_default()
        };
        match command.kind() {
            K::WHERE_COMMAND | K::MV_EXPAND_COMMAND => {
                for n in all() {
                    self.expression(&n);
                }
                true
            }
            K::SORT_COMMAND => {
                // An order's key: its first node.
                let keys: Vec<SyntaxNode> = child_of(&own, K::ORDER_EXPRESSION)
                    .into_iter()
                    .filter_map(|c| nodes(&parts(c)).map(|(_, n)| n.clone()).next())
                    .collect();
                for key in keys {
                    self.expression(&key);
                }
                true
            }
            K::EVAL_COMMAND => {
                for field in child_of(&own, K::FIELD_ASSIGNMENT_OR_EXPRESSION) {
                    let Assignment { name, value, .. } = assignment(field);
                    if let Some(value) = value {
                        self.expression(&value);
                    }
                    let name = name.and_then(|n| qualified(&n, self.source));
                    self.define(name);
                }
                true
            }
            K::INLINE_STATS_COMMAND | K::STATS_COMMAND => {
                for aggregate in aggregates() {
                    let Assignment { value, filter, .. } = assignment(&aggregate);
                    if let Some(value) = value {
                        self.expression(&value);
                    }
                    if let Some(filter) = filter {
                        self.expression(&filter);
                    }
                }
                for group in groups() {
                    if let Some(value) = assignment(&group).value {
                        self.expression(&value);
                    }
                }
                if command.kind() == K::STATS_COMMAND {
                    return false;
                }
                for field in aggregates().into_iter().chain(groups()) {
                    let name = assignment(&field)
                        .name
                        .and_then(|n| qualified(&n, self.source));
                    self.define(name);
                }
                true
            }
            K::KEEP_COMMAND | K::DROP_COMMAND => {
                for pattern in child_of(&own, K::NAME_PATTERN) {
                    self.name_pattern(pattern);
                }
                true
            }
            K::RENAME_COMMAND => {
                for clause in child_of(&own, K::RENAME_CLAUSE) {
                    let (Some(old), Some(new)) = renamed(clause) else {
                        return false;
                    };
                    let (Some(old_name), Some(new_name)) =
                        (qualified(&old, self.source), qualified(&new, self.source))
                    else {
                        return false;
                    };
                    if old_name.contains('*') || new_name.contains('*') {
                        return false;
                    }
                    self.name_pattern(&old);
                    self.defined.insert(old_name);
                    self.defined.insert(new_name);
                }
                true
            }
            K::DISSECT_COMMAND | K::GROK_COMMAND => {
                // The input, then the patterns (and a dissect's options).
                let mut kids = all().into_iter();
                if let Some(input) = kids.next() {
                    self.expression(&input);
                }
                for pattern in kids.filter(|n| n.kind() != K::COMMAND_OPTION) {
                    let Some(value) = string_value(text(&pattern, self.source)) else {
                        return false;
                    };
                    let keys = if command.kind() == K::DISSECT_COMMAND {
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
            K::ENRICH_COMMAND => {
                // The clauses follow `WITH`; the parser reads the policy
                // before it (`processing.rs`, `enrich`).
                let clauses: Vec<SyntaxNode> = first_token(&own, &[K::WITH_KW])
                    .map(|with| nodes_after(&own, with).cloned().collect())
                    .unwrap_or_default();
                if clauses.is_empty() {
                    return false;
                }
                for clause in clauses {
                    // `new = field`, or `field`: the first name either way.
                    let name = (clause.kind() == K::ENRICH_WITH_CLAUSE)
                        .then(|| nodes(&parts(&clause)).map(|(_, n)| n.clone()).next())
                        .flatten()
                        .and_then(|n| qualified(&n, self.source));
                    let Some(name) = name.filter(|n| !n.contains('*')) else {
                        return false;
                    };
                    self.defined.insert(name);
                }
                true
            }
            K::LIMIT_COMMAND | K::SAMPLE_COMMAND | K::DEDUP_COMMAND => true,
            _ => false,
        }
    }

    /// A column the query reads from its indices: not one it defines, not a
    /// parameter, not a pattern.
    fn source_column(&self, node: &SyntaxNode) -> Option<String> {
        if node.kind() != K::QUALIFIED_NAME {
            return None;
        }
        let name = qualified(node, self.source)?;
        (!self.defined.contains(&name) && !name.contains('*')).then_some(name)
    }

    fn name_pattern(&mut self, node: &SyntaxNode) {
        let Some(name) = qualified(node, self.source) else {
            return;
        };
        if name.contains('*') || self.defined.contains(&name) {
            return;
        }
        if let Some(d) =
            opentide_ecs::unknown_field_diagnostic(&name, || range(self.source, span_of(node)))
        {
            self.out.push(d);
        }
    }

    fn expression(&mut self, node: &SyntaxNode) {
        let mut stack = vec![node.clone()];
        while let Some(n) = stack.pop() {
            match n.kind() {
                // `IN (FROM …)` reads other indices.
                K::SOURCE_SUBQUERY | K::MAP_EXPRESSION => continue,
                K::QUALIFIED_NAME => {
                    if let Some(name) = self.source_column(&n)
                        && let Some(d) = opentide_ecs::unknown_field_diagnostic(&name, || {
                            range(self.source, span_of(&n))
                        })
                    {
                        self.out.push(d);
                    }
                    continue;
                }
                K::LIKE_EXPRESSION => self.like(&n),
                K::FUNCTION_CALL => self.function(&n),
                _ => {}
            }
            stack.extend(n.children());
        }
    }

    fn like(&mut self, node: &SyntaxNode) {
        let own = parts(node);
        let Some((_, left)) = nodes(&own).next() else {
            return;
        };
        let Some(name) = self.source_column(left) else {
            return;
        };
        let Some((value_type, type_name)) = opentide_ecs::field_type(&name) else {
            return;
        };
        if value_type != ValueType::String {
            let operator = first_token(&own, &[K::LIKE_KW, K::RLIKE_KW])
                .and_then(|at| own[at].as_token().map(|t| t.text().to_ascii_uppercase()))
                .unwrap_or_else(|| "LIKE".into());
            self.out.push(opentide_ecs::type_mismatch(
                &name,
                type_name,
                &format!("`{operator}`, which takes a string,"),
                range(self.source, span_of(left)),
            ));
        }
    }

    fn function(&mut self, node: &SyntaxNode) {
        let own = parts(node);
        // The name, then the arguments (and an options map).
        let mut kids = nodes(&own).map(|(_, n)| n);
        let Some(name_node) = kids.next() else {
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
        let arguments: Vec<&SyntaxNode> = kids.filter(|n| n.kind() != K::MAP_EXPRESSION).collect();
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
                range(self.source, span_of(argument)),
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

    /// Each command's checks read its own parts: a STATS filter and group,
    /// a DISSECT input, a rename's old name, the names ENRICH defines, both
    /// sides of `AND` (the right one first, as the walk pops them), and the
    /// operator a type mismatch names.
    #[test]
    fn each_command_reads_its_own_parts() {
        let at = |query: &str| -> Vec<u32> {
            ecs_diagnostics(query)
                .iter()
                .inspect(|d| assert_eq!(d.code, codes::ECS_UNKNOWN_FIELD, "{query}"))
                .map(|d| d.range.start.character)
                .collect()
        };
        assert_eq!(
            at("FROM logs-* | STATS c = COUNT(*) WHERE process.nmae == \"a\""),
            [39]
        );
        assert_eq!(at("FROM logs-* | STATS COUNT(*) BY process.nmae"), [32]);
        assert_eq!(
            at("FROM logs-* | INLINE STATS c = MAX(a) BY g = process.nmae"),
            [45]
        );
        assert_eq!(at("FROM logs-* | DISSECT process.nmae \"%{a}\""), [22]);
        assert_eq!(at("FROM logs-* | RENAME process.nmae AS h"), [21]);
        assert_eq!(
            at("FROM logs-* | ENRICH p WITH process.nmae = city | WHERE process.nmae == \"a\""),
            [0; 0]
        );
        assert_eq!(
            at("FROM logs-* | WHERE process.nmae == \"a\" AND user.nmae == \"b\""),
            [44, 20]
        );
        // SORT's keys and MV_EXPAND's field are read.
        assert_eq!(at("FROM logs-* | SORT process.nmae DESC"), [19]);
        assert_eq!(at("FROM logs-* | MV_EXPAND process.nmae"), [24]);
        // A DISSECT option is no pattern: the walk goes on.
        assert_eq!(
            at(
                "FROM logs-* | DISSECT process.nmae \"%{a}\" append_separator = \",\" | WHERE user.nmae == \"y\""
            ),
            [22, 73]
        );
        // ENRICH defines its clauses' names, not its policy or match field.
        assert_eq!(
            at("FROM logs-* | ENRICH p ON host.nmae WITH c = x | WHERE process.nmae == \"a\""),
            [55]
        );
        // INLINE STATS defines its groups' names.
        assert_eq!(
            at(
                "FROM logs-* | INLINE STATS c = COUNT(*) BY host.nmae = host.name | WHERE host.nmae == \"a\""
            ),
            [0; 0]
        );
        let d = ecs_diagnostics("FROM logs-* | WHERE source.ip RLIKE \"a\"");
        assert!(d[0].message.contains("`RLIKE`"), "{}", d[0].message);
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
