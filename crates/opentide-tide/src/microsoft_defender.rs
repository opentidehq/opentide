//! A Microsoft Defender block against what its query returns (#1885).
//!
//! Every column the block names is a column of the query's output: the
//! `entities` fields, the action columns, the `alert.custom_details` values
//! and the `{{Column}}` placeholders of `alert.title` and
//! `alert.description`. The KQL engine infers the output offline
//! ([`opentide_kql::output`]); when it cannot, nothing is reported.
//!
//! - `microsoft_defender_column_not_in_output` (error), on the field: a
//!   column the output does not have, with the output column it most likely
//!   means. When the output is a table's documented columns (no `project`),
//!   which the table may outgrow, only a near miss of one is reported, as
//!   `kql_unknown_column` reports one.
//! - `microsoft_defender_required_columns` (error), on the query's last
//!   operator: a complete output lacks a column a custom detection needs for
//!   the Defender XDR tables the query names (the table `validate query
//!   --live` checks a run's columns against, opentide-schema's
//!   `required_columns`). Offline, only when the query names one of those
//!   tables: without one the table family, and so the columns, are unknown.
//! - `microsoft_defender_column_type` (warning), on the field: an entity
//!   field or action column mapped from an output column whose type the
//!   engine knows is `dynamic`, `datetime`, `bool` or `timespan`, none of
//!   which holds an identifier, a name or an address.
//! - `microsoft_defender_unprojected_output` (note), on the query's last
//!   operator: the output has columns nothing in the block uses, from which
//!   Defender derives entity mappings of its own. Its suggestion is the
//!   `| project` to append after that operator (none after a `render`, or in
//!   a single-quoted YAML scalar it would need escaping in).
//!
//! Column names compare as KQL's do: case-sensitively.
//!
//! The findings go with the block's query ([`crate::attach_to_queries`]):
//! `opentide validate`'s and `lint`'s `queries` check and the editor report
//! them, and a placeholder query carries none.

use std::sync::Arc;

use opentide_core::node::{Node, Value};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, codes, suggest};
use opentide_kql::Profile;
use opentide_kql::output::Output;
use opentide_schema::objects::platform::microsoft_defender::required_columns::{
    defender_xdr_tables_in_query, missing_required_column_groups, required_column_groups,
};
use opentide_schema::objects::platform::microsoft_defender::{
    DEVICE_GROUPS, ISOLATION_TYPE, action, entity_kind,
};

use crate::InjectedQuery;
use crate::yaml_scalar::{mapping_keys, scalar_at};

/// The block's key.
pub(crate) const PLATFORM: &str = "microsoft_defender";

/// The block's query.
pub(crate) const QUERY: [&str; 3] = ["configurations", PLATFORM, "query"];

/// How many unused columns a message names before "and N more".
const NAMED: usize = 5;

/// The types `microsoft_defender_column_type` reports: none holds an
/// identifier, a name or an address. A number may (`ApplicationId`).
const NOT_AN_ENTITY: [&str; 5] = ["dynamic", "datetime", "bool", "boolean", "timespan"];

/// A column the block names.
#[derive(Debug)]
struct Named {
    /// The column, as written (trimmed).
    column: String,
    /// Where its name is in the source.
    span: ByteSpan,
    /// The field that names it, list items by index.
    field_path: Vec<String>,
    /// The field, as a message names it (`entities.hosts[0].device_id`).
    label: String,
    /// Whether the source text at `span` is the column's name as written,
    /// so a suggestion can replace it (no escape or line break inside).
    replaceable: bool,
    /// An entity field or an action column, which holds text: a custom
    /// detail or a placeholder shows any type.
    textual: bool,
}

/// The findings of the Defender block of `configurations` against its query.
pub(crate) fn output_findings(
    source: &str,
    configurations: &Arc<Node>,
    query: &InjectedQuery,
) -> Vec<Diagnostic> {
    let Some(block) = configurations.get(PLATFORM) else {
        return Vec::new();
    };
    let Some(output) = opentide_kql::output::output(&query.inner, Profile::Defender) else {
        return Vec::new();
    };
    let lines = LineIndex::new(source);
    let named = named_columns(source, block);
    let mut out = Vec::new();
    // Each column the output lacks, with the one it most likely means.
    let mut missing: Vec<(&str, Option<&str>)> = Vec::new();
    for name in &named {
        if let Some(column) = output.column(&name.column) {
            if let Some(type_name) = column
                .type_name
                .as_deref()
                .filter(|t| NOT_AN_ENTITY.contains(t))
                && name.textual
            {
                out.push(
                    Diagnostic::warning(
                        codes::MICROSOFT_DEFENDER_COLUMN_TYPE,
                        format!(
                            "{} maps '{}', a {type_name} column, which holds no identifier, \
                             name or address: map the column that does, or extract it as text \
                             in the query (tostring(...))",
                            name.label, name.column
                        ),
                        lines.range(name.span),
                    )
                    .with_field_path(name.field_path.clone()),
                );
            }
            continue;
        }
        let candidates = output.columns.iter().map(|c| c.name.as_str());
        let meant = suggest::closest(&name.column, candidates).filter(|m| *m != name.column);
        // A table's documented columns: only a near miss is certainly wrong.
        if !output.complete && meant.is_none() {
            continue;
        }
        missing.push((&name.column, meant));
        let mut message = format!(
            "{} names the unknown column '{}': the query's output has no such column",
            name.label, name.column
        );
        if let Some(meant) = meant {
            message.push_str(&format!("; did you mean '{meant}'?"));
        }
        let mut diagnostic = Diagnostic::error(
            codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT,
            message,
            lines.range(name.span),
        )
        .with_field_path(name.field_path.clone());
        if let Some(meant) = meant.filter(|_| name.replaceable) {
            diagnostic = diagnostic.with_suggestion(meant);
        }
        out.push(diagnostic);
    }
    let at = lines.range(crate::remap_span(query, output.last_operator));
    let returned: Vec<&str> = output.columns.iter().map(|c| c.name.as_str()).collect();
    // The family of the tables the query reads, which the required columns
    // follow; unknown (no Defender XDR table named), nothing is required
    // offline. `validate query --live` checks what the tenant returns.
    let family_known = !defender_xdr_tables_in_query(&query.inner).is_empty();
    let required = missing_required_column_groups(&query.inner, &returned);
    if family_known && output.complete && !required.is_empty() {
        out.push(
            Diagnostic::error(
                codes::MICROSOFT_DEFENDER_REQUIRED_COLUMNS,
                format!(
                    "the query's output lacks a column a custom detection needs: {}",
                    required.join("; ")
                ),
                at,
            )
            .with_field_path(QUERY.iter().map(ToString::to_string).collect()),
        );
    }
    let quoted = source
        .get(..query.host_span.start)
        .is_some_and(|before| before.ends_with('\''));
    let found = Found {
        named: &named,
        missing: &missing,
        family_known,
        single_quoted: quoted,
    };
    if let Some(diagnostic) = unprojected(query, &output, &found, at) {
        out.push(diagnostic);
    }
    out
}

/// What the block's columns came to, for the `| project` suggestion.
struct Found<'f> {
    named: &'f [Named],
    /// Each column the output lacks, with the one it most likely means.
    missing: &'f [(&'f str, Option<&'f str>)],
    /// Whether the query names a Defender XDR table, so its required
    /// columns are known.
    family_known: bool,
    /// The query is a single-quoted YAML scalar, where a `'` the suggestion
    /// writes would need doubling.
    single_quoted: bool,
}

/// `microsoft_defender_unprojected_output` when the output has columns no
/// field of the block and no required column uses, with the `| project` of
/// the ones that are.
fn unprojected(
    query: &InjectedQuery,
    output: &Output,
    found: &Found<'_>,
    at: opentide_core::Range,
) -> Option<Diagnostic> {
    let named = found.named;
    let groups = required_column_groups(&query.inner);
    let used = |column: &str| {
        named.iter().any(|n| n.column == column)
            || found
                .missing
                .iter()
                .any(|(_, meant)| *meant == Some(column))
            || groups.iter().any(|group| group.contains(&column))
    };
    let unused: Vec<&str> = output
        .columns
        .iter()
        .map(|c| c.name.as_str())
        .filter(|c| !used(c))
        .collect();
    if unused.is_empty() {
        return None;
    }
    let mut shown = unused
        .iter()
        .take(NAMED)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if unused.len() > NAMED {
        shown.push_str(&format!(" and {} more", unused.len() - NAMED));
    }
    let lead = if output.complete {
        format!(
            "the query returns {} column{} nothing in the block uses ({shown})",
            unused.len(),
            if unused.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "the query ends without a project, so it returns every column of its tables, \
             {} of which nothing in the block uses ({shown})",
            unused.len()
        )
    };
    let mut diagnostic = Diagnostic::information(
        codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT,
        format!(
            "{lead}: Defender derives entity mappings from result columns, beyond the ones the \
             block declares; project the columns the rule uses"
        ),
        at,
    )
    .with_field_path(QUERY.iter().map(ToString::to_string).collect());
    // After a `render`, a project would change what is drawn, not what the
    // rule returns: no edit is offered there.
    let ends_in_render = query
        .inner
        .get(output.last_operator.start..output.last_operator.end)
        .is_some_and(|op| op.trim_start().starts_with("render"));
    if !ends_in_render
        && let Some(project) = project_clause(output, found, &groups)
        && !(found.single_quoted && project.contains('\''))
    {
        diagnostic = diagnostic.with_suggestion(project);
    }
    Some(diagnostic)
}

/// `| project` of the required columns (of each group, the first the
/// output has; when the output is a table's documented columns and has none
/// of a one-column group, that column, which the table has undocumented),
/// then the columns the block names, a misspelt one as the column it most
/// likely means, each once; `None` when there is none, or a name cannot be
/// written as a KQL column name.
fn project_clause(
    output: &Output,
    found: &Found<'_>,
    groups: &[Vec<&'static str>],
) -> Option<String> {
    let mut columns: Vec<&str> = Vec::new();
    for group in groups {
        match group.iter().find(|c| output.column(c).is_some()) {
            Some(column) => columns.push(column),
            None if found.family_known && !output.complete && group.len() == 1 => {
                columns.extend(group.first().copied());
            }
            None => {}
        }
    }
    for name in found.named {
        match found
            .missing
            .iter()
            .find(|(column, _)| *column == name.column)
        {
            // The column it most likely means, which the output has.
            Some((_, Some(meant))) => columns.push(meant),
            // A column the output lacks would be an unknown column of the
            // project.
            Some((_, None)) => {}
            None if output.lacks(&name.column) => {}
            None => columns.push(&name.column),
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut written = Vec::new();
    for column in columns {
        if seen.insert(column) {
            written.push(kql_name(column)?);
        }
    }
    (!written.is_empty()).then(|| format!("| project {}", written.join(", ")))
}

/// `name` as a KQL column name: bare when it is an identifier, else
/// `['name']`; `None` when it holds a quote, a backslash or a control
/// character, which a bracketed name would need escaped.
fn kql_name(name: &str) -> Option<String> {
    let identifier = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if identifier {
        return Some(name.to_owned());
    }
    if name.is_empty()
        || name
            .chars()
            .any(|c| matches!(c, '\'' | '\\') || c.is_control())
    {
        return None;
    }
    Some(format!("['{name}']"))
}

/// Every column the block names, in source order.
fn named_columns(source: &str, block: &Node) -> Vec<Named> {
    let mut out = Vec::new();
    for key in mapping_keys(source) {
        let Some(at) = key.scalar else {
            continue;
        };
        let path: Vec<&str> = key.path.iter().map(String::as_str).collect();
        let ["configurations", PLATFORM, rest @ ..] = path.as_slice() else {
            continue;
        };
        let Some(value) = node_at(block, rest) else {
            continue;
        };
        let Value::Str(text) = &value.value else {
            continue;
        };
        let Some(scalar) = scalar_at(source, at, key.column) else {
            continue;
        };
        if scalar.text != **text {
            continue;
        }
        let field_path = key.path.clone();
        match rest {
            ["entities", kind, index, field]
                if is_index(index)
                    && entity_kind(kind).is_some_and(|k| k.graph_field(field).is_some()) =>
            {
                let label = format!("entities.{kind}[{index}].{field}");
                out.extend(whole(&scalar, field_path, label, true));
            }
            ["actions", name, index, field]
                if is_index(index)
                    && !matches!(*field, ISOLATION_TYPE | DEVICE_GROUPS)
                    && action(name).is_some_and(|a| a.graph_field(field).is_some()) =>
            {
                let label = format!("actions.{name}[{index}].{field}");
                out.extend(whole(&scalar, field_path, label, true));
            }
            ["alert", "custom_details", detail] => {
                let label = format!("custom detail '{detail}'");
                out.extend(whole(&scalar, field_path, label, false));
            }
            ["alert", field @ ("title" | "description")] => {
                out.extend(placeholders(&scalar, &field_path, field));
            }
            _ => {}
        }
    }
    out
}

/// The node at `path` under `block`, list items by index.
fn node_at<'n>(block: &'n Node, path: &[&str]) -> Option<&'n Node> {
    let mut node = block;
    for step in path {
        node = match &node.value {
            Value::Seq(items) => items.get(step.parse::<usize>().ok()?)?,
            _ => node.get(step)?,
        };
    }
    Some(node)
}

fn is_index(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The column a whole scalar names: its text, trimmed; none when blank
/// (`microsoft_defender_column`, the block's own check).
fn whole(
    scalar: &crate::yaml_scalar::Scalar,
    field_path: Vec<String>,
    label: String,
    textual: bool,
) -> Option<Named> {
    let text = &scalar.text;
    let start = text.len() - text.trim_start().len();
    let end = text.trim_end().len();
    if start >= end {
        return None;
    }
    named(scalar, start, end, field_path, label, textual)
}

/// The `{{Column}}` placeholders of an alert's `field`.
fn placeholders(
    scalar: &crate::yaml_scalar::Scalar,
    field_path: &[String],
    field: &str,
) -> Vec<Named> {
    let text = &scalar.text;
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(open) = text.get(from..).and_then(|rest| rest.find("{{")) {
        let inner_start = from + open + 2;
        let Some(close) = text.get(inner_start..).and_then(|rest| rest.find("}}")) else {
            break;
        };
        let inner_end = inner_start + close;
        from = inner_end + 2;
        let inner = &text[inner_start..inner_end];
        let start = inner_start + (inner.len() - inner.trim_start().len());
        let end = inner_start + inner.trim_end().len();
        if start >= end || text[start..end].contains(['{', '}']) {
            continue;
        }
        let label = format!("alert.{field}'s placeholder {{{{{}}}}}", &text[start..end]);
        out.extend(named(scalar, start, end, field_path.to_vec(), label, false));
    }
    out
}

/// The column `scalar.text[start..end]` names, placed through the scalar's
/// map onto the source.
fn named(
    scalar: &crate::yaml_scalar::Scalar,
    start: usize,
    end: usize,
    field_path: Vec<String>,
    label: String,
    textual: bool,
) -> Option<Named> {
    let first = *scalar.map.get(start)?;
    let last = *scalar.map.get(end.checked_sub(1)?)?;
    let span = ByteSpan::new(first, last + 1);
    // Each byte of the name is the source byte after the one before.
    let replaceable = scalar
        .map
        .get(start..end)?
        .windows(2)
        .all(|pair| pair[1] == pair[0] + 1);
    Some(Named {
        column: scalar.text.get(start..end)?.to_owned(),
        span,
        field_path,
        label,
        replaceable,
        textual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(yaml: &str) -> Vec<Diagnostic> {
        crate::analyze_queries(yaml, &[])
            .into_iter()
            .flat_map(|q| q.diagnostics)
            .filter(|d| d.code.starts_with("microsoft_defender_"))
            .collect()
    }

    fn rule(query: &str, block: &str) -> String {
        let query: String = query.lines().flat_map(|l| ["      ", l, "\n"]).collect();
        format!("name: Rule\nconfigurations:\n  microsoft_defender:\n    query: |\n{query}{block}")
    }

    fn codes_of(found: &[Diagnostic]) -> Vec<&str> {
        found.iter().map(|d| d.code.as_str()).collect()
    }

    fn covered<'s>(yaml: &'s str, d: &Diagnostic) -> &'s str {
        let lines = LineIndex::new(yaml);
        &yaml[lines.offset(d.range.start)..lines.offset(d.range.end)]
    }

    const PROJECTED: &str = "DeviceEvents\n| where ActionType == 'x'\n\
         | project Timestamp, ReportId, DeviceId, InitiatingProcessAccountUpn";

    #[test]
    fn the_issue_s_clean_case_is_clean() {
        let yaml = rule(
            PROJECTED,
            "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n",
        );
        assert_eq!(findings(&yaml), []);
    }

    #[test]
    fn an_entity_column_the_final_project_drops_is_not_in_the_output() {
        let yaml = rule(
            PROJECTED,
            "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n      \
             files:\n        - name: FileName\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT]
        );
        let d = &found[0];
        assert_eq!(covered(&yaml, d), "FileName");
        assert_eq!(
            d.field_path.as_deref().unwrap(),
            [
                "configurations",
                "microsoft_defender",
                "entities",
                "files",
                "0",
                "name"
            ]
        );
        assert!(
            d.message.contains("entities.files[0].name"),
            "{}",
            d.message
        );
    }

    #[test]
    fn a_misspelt_column_is_reported_with_its_suggestion() {
        let yaml = rule(
            PROJECTED,
            "    entities:\n      hosts:\n        - device_id: DevicId\n      \
             accounts:\n        - upn: InitiatingProcessAccountUpn\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT]
        );
        assert_eq!(found[0].suggestion.as_deref(), Some("DeviceId"));
        assert_eq!(covered(&yaml, &found[0]), "DevicId");
    }

    #[test]
    fn without_a_project_only_a_near_miss_of_a_documented_column_is_reported() {
        let yaml = rule(
            "DeviceEvents | where ActionType == 'x'",
            "    entities:\n      hosts:\n        - device_id: DevicId\n        \
             - name: SomeColumnTheReferenceDoesNotList\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [
                codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT,
                codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT
            ]
        );
        assert_eq!(found[0].suggestion.as_deref(), Some("DeviceId"));
    }

    #[test]
    fn a_custom_detail_naming_a_missing_column() {
        let yaml = rule(
            PROJECTED,
            "    alert:\n      custom_details:\n        Who: \"InitiatingProcessAccountUpn\"\n        \
             Where: FolderPath\n    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT]
        );
        assert_eq!(covered(&yaml, &found[0]), "FolderPath");
        assert!(found[0].message.contains("custom detail 'Where'"));
    }

    #[test]
    fn an_alert_placeholder_naming_a_missing_column() {
        let yaml = rule(
            PROJECTED,
            "    alert:\n      title: \"Odd event on {{ DeviceId }} by {{AccountUpn}}\"\n      \
             description: |\n        Seen {{Timestamp}}.\n    entities:\n      accounts:\n        \
             - upn: InitiatingProcessAccountUpn\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT]
        );
        assert_eq!(covered(&yaml, &found[0]), "AccountUpn");
        assert_eq!(
            found[0]
                .field_path
                .as_deref()
                .unwrap()
                .last()
                .map(String::as_str),
            Some("title")
        );
    }

    #[test]
    fn an_action_column_missing_from_the_output() {
        let yaml = rule(
            PROJECTED,
            "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n    \
             actions:\n      isolate_devices:\n        - device_id: DeviceId\n          \
             isolation_type: full\n      block_files:\n        - sha1: SHA1\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_COLUMN_NOT_IN_OUTPUT]
        );
        assert_eq!(covered(&yaml, &found[0]), "SHA1");
    }

    #[test]
    fn column_names_compare_with_their_case() {
        let yaml = rule(
            PROJECTED,
            "    entities:\n      hosts:\n        - device_id: deviceid\n      \
             accounts:\n        - upn: InitiatingProcessAccountUpn\n",
        );
        let found = findings(&yaml);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("DeviceId"));
    }

    #[test]
    fn an_output_without_the_required_columns() {
        let yaml = rule(
            "DeviceEvents | project Timestamp, InitiatingProcessAccountUpn",
            "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_REQUIRED_COLUMNS]
        );
        assert!(
            found[0].message.contains("DeviceId; ReportId"),
            "{}",
            found[0].message
        );
        assert_eq!(
            covered(&yaml, &found[0]),
            "project Timestamp, InitiatingProcessAccountUpn"
        );
    }

    #[test]
    fn a_query_without_a_project_warns_and_suggests_one() {
        let yaml = rule(
            "DeviceEvents\n| where ActionType == 'x' // keep",
            "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n    \
             alert:\n      custom_details:\n        File: FileName\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT]
        );
        let d = &found[0];
        assert_eq!(d.severity, opentide_core::Severity::Information);
        assert_eq!(covered(&yaml, d), "where ActionType == 'x'");
        assert_eq!(
            d.suggestion.as_deref(),
            Some("| project Timestamp, DeviceId, ReportId, InitiatingProcessAccountUpn, FileName")
        );
        assert!(d.message.contains("without a project"), "{}", d.message);
    }

    #[test]
    fn a_project_with_an_unused_column_warns() {
        let yaml = rule(
            "DeviceEvents | project Timestamp, ReportId, DeviceId, FolderPath",
            "    entities:\n      hosts:\n        - device_id: DeviceId\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT]
        );
        assert!(
            found[0].message.contains("1 column nothing"),
            "{}",
            found[0].message
        );
        assert!(found[0].message.contains("FolderPath"));
    }

    #[test]
    fn nothing_when_the_output_cannot_be_inferred() {
        for query in [
            "MyTable_CL | project A, B",
            "DeviceEvents | evaluate bag_unpack(AdditionalFields)",
            "MyFunction() | where x == 1",
            "DeviceEvents | project tolower(DeviceName)",
            "union DeviceEvents, Unknown_CL",
            "DeviceEvents | project",
        ] {
            let yaml = rule(
                query,
                "    entities:\n      hosts:\n        - device_id: Nope\n    alert:\n      \
                 title: \"{{Nada}}\"\n",
            );
            assert_eq!(findings(&yaml), [], "{query}");
        }
    }

    #[test]
    fn a_placeholder_query_carries_nothing() {
        let yaml = "name: Rule\nconfigurations:\n  microsoft_defender:\n    \
                    # opentide:placeholder\n    query: ...\n    entities:\n      hosts:\n        \
                    - device_id: Nope\n";
        assert_eq!(findings(yaml), []);
    }

    #[test]
    fn an_entity_mapped_from_a_column_that_is_not_text_warns() {
        let yaml = rule(
            "DeviceEvents | extend Seen = Timestamp \
             | project Timestamp, ReportId, DeviceId, Seen, AdditionalFields",
            "    entities:\n      hosts:\n        - device_id: DeviceId\n          name: Seen\n    \
             alert:\n      title: \"{{Seen}}\"\n      custom_details:\n        Extra: AdditionalFields\n",
        );
        let found = findings(&yaml);
        assert_eq!(codes_of(&found), [codes::MICROSOFT_DEFENDER_COLUMN_TYPE]);
        assert_eq!(found[0].severity, opentide_core::Severity::Warning);
        assert_eq!(covered(&yaml, &found[0]), "Seen");
        assert!(
            found[0].message.contains("datetime"),
            "{}",
            found[0].message
        );
    }

    /// `yaml` with the unprojected finding's suggestion appended after the
    /// query's last operator, as the editor's quick fix does.
    fn with_project(yaml: &str) -> String {
        let found = findings(yaml);
        let d = found
            .iter()
            .find(|d| d.code == codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT)
            .unwrap_or_else(|| panic!("{found:?}"));
        let suggestion = d.suggestion.clone().unwrap_or_else(|| panic!("{d:?}"));
        let at = LineIndex::new(yaml).offset(d.range.end);
        format!("{} {suggestion}{}", &yaml[..at], &yaml[at..])
    }

    #[test]
    fn applying_the_project_leaves_the_rule_clean() {
        // #1885 review: the suggestion skipped a required column the
        // documented columns lacked, and turned a passing rule red.
        for (query, block) in [
            (
                "EmailAttachmentInfo | where FileType == \"html\"",
                "    entities:\n      mailboxes:\n        - primary_address: RecipientEmailAddress\n",
            ),
            (
                "DeviceEvents\n| where ActionType == 'x' // keep",
                "    entities:\n      accounts:\n        - upn: InitiatingProcessAccountUpn\n    \
                 alert:\n      title: \"On {{DeviceName}}\"\n",
            ),
            (
                "DeviceNetworkInfo | where NetworkAdapterStatus == \"Up\"",
                "    entities:\n      hosts:\n        - device_id: DeviceId\n",
            ),
        ] {
            let fixed = with_project(&rule(query, block));
            assert_eq!(findings(&fixed), [], "{fixed}");
        }
    }

    #[test]
    fn the_project_names_a_misspelt_column_as_the_one_it_means() {
        let yaml = rule(
            "DeviceEvents | where ActionType == 'x'",
            "    entities:\n      hosts:\n        - device_id: DevicId\n",
        );
        let found = findings(&yaml);
        let project = found
            .iter()
            .find_map(|d| d.suggestion.as_deref().filter(|s| s.starts_with('|')))
            .unwrap_or_else(|| panic!("{found:?}"));
        assert_eq!(project, "| project Timestamp, DeviceId, ReportId");
    }

    #[test]
    fn no_project_is_offered_after_a_render_or_where_quoting_would_need_escapes() {
        let yaml = rule(
            "DeviceEvents | where ActionType == 'x' | render table",
            "    entities:\n      hosts:\n        - device_id: DeviceId\n",
        );
        let found = findings(&yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT]
        );
        assert_eq!(found[0].suggestion, None);
        // A bracketed name in a single-quoted YAML scalar.
        let yaml = "name: Rule\nconfigurations:\n  microsoft_defender:\n    \
                    query: 'DeviceEvents | where ActionType == \"x\"'\n    entities:\n      \
                    hosts:\n        - name: Analyst Tag\n";
        let found = findings(yaml);
        assert_eq!(
            codes_of(&found),
            [codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT]
        );
        assert_eq!(found[0].suggestion, None, "{found:?}");
    }

    #[test]
    fn no_required_columns_without_a_defender_xdr_table() {
        let yaml = rule(
            "datatable(Account: string) ['a'] | project Account",
            "    entities:\n      accounts:\n        - name: Account\n",
        );
        assert_eq!(findings(&yaml), []);
    }

    #[test]
    fn a_numeric_id_is_an_entity_column() {
        let yaml = rule(
            "CloudAppEvents | project Timestamp, ReportId, ApplicationId, AccountObjectId",
            "    entities:\n      cloud_applications:\n        - app_id: ApplicationId\n      \
             accounts:\n        - aad_user_id: AccountObjectId\n",
        );
        assert_eq!(findings(&yaml), []);
    }

    #[test]
    fn a_project_keep_of_the_issue_s_columns_is_clean() {
        // #1885 review: project-keep only removed columns, so a kept one the
        // reference lacks was reported missing.
        let yaml = rule(
            "DeviceNetworkInfo | where NetworkAdapterStatus == \"Up\" \
             | project-keep Timestamp, ReportId, DeviceId, IPAddresses",
            "    entities:\n      hosts:\n        - device_id: DeviceId\n    \
             alert:\n      custom_details:\n        Addresses: IPAddresses\n",
        );
        assert_eq!(findings(&yaml), []);
    }

    #[test]
    fn applying_the_project_to_a_table_outside_the_families_leaves_it_clean() {
        // BehaviorEntities is not among the Defender XDR tables the
        // required columns know: nothing is required offline, and the
        // project names no Log Analytics column.
        let yaml = rule(
            "BehaviorEntities | where EntityType == \"User\"",
            "    entities:\n      accounts:\n        - upn: AccountUpn\n",
        );
        let found = findings(&yaml);
        let project = found
            .iter()
            .find_map(|d| d.suggestion.as_deref())
            .unwrap_or_else(|| panic!("{found:?}"));
        assert!(!project.contains("TimeGenerated"), "{project}");
        let fixed = with_project(&yaml);
        assert_eq!(findings(&fixed), [], "{fixed}");
    }

    #[test]
    fn an_arg_max_star_by_a_key_is_only_as_sure_as_its_table() {
        // Whether `*` repeats the `by` key (`DeviceId1`) is not something
        // to fail a rule on: from a table, the output is its documented
        // columns, so nothing beyond a near miss is reported.
        let yaml = rule(
            "DeviceProcessEvents | summarize arg_max(Timestamp, *) by DeviceId",
            "    entities:\n      hosts:\n        - device_id: DeviceId1\n      \
             accounts:\n        - upn: AccountUpn\n",
        );
        let found = findings(&yaml);
        assert!(
            !found
                .iter()
                .any(|d| matches!(d.code.as_str(), codes::MICROSOFT_DEFENDER_REQUIRED_COLUMNS)),
            "{found:?}"
        );
    }

    #[test]
    fn no_message_names_a_log_analytics_column() {
        for query in [
            "DeviceNetworkInfo | where NetworkAdapterStatus == \"Up\"",
            "EmailAttachmentInfo | where FileType == \"html\"",
            "IdentityLogonEvents | where ActionType == \"LogonFailed\"",
        ] {
            let yaml = rule(
                query,
                "    entities:\n      accounts:\n        - upn: AccountUpn\n",
            );
            for d in findings(&yaml) {
                let text = format!("{} {:?}", d.message, d.suggestion);
                for column in [
                    "TimeGenerated",
                    "TenantId",
                    "SourceSystem",
                    "_BilledSize",
                    "_IsBillable",
                ] {
                    assert!(!text.contains(column), "{query}: {text}");
                }
            }
        }
    }

    #[test]
    fn a_name_that_is_not_an_identifier_is_bracketed_or_left_out() {
        assert_eq!(kql_name("DeviceId").as_deref(), Some("DeviceId"));
        assert_eq!(kql_name("a b").as_deref(), Some("['a b']"));
        assert_eq!(kql_name("it's"), None);
        assert_eq!(kql_name(""), None);
    }
}
