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
//!   the tables the query reads (the table `validate query --live` checks a
//!   run's columns against, opentide-schema's `required_columns`).
//! - `microsoft_defender_column_type` (warning), on the field: an entity
//!   field or action column mapped from an output column whose type the
//!   engine knows and is neither `string` nor `guid` (Graph's entity
//!   columns hold identifiers, names and addresses as text).
//! - `microsoft_defender_unprojected_output` (warning), on the query's last
//!   operator: the output has columns nothing in the block uses, from which
//!   Defender derives entity mappings of its own. Its suggestion is the
//!   `| project` to append after that operator.
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
    missing_required_column_groups, required_column_groups,
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
    let mut missing: Vec<&str> = Vec::new();
    for name in &named {
        if let Some(column) = output.column(&name.column) {
            if let Some(type_name) = column
                .type_name
                .as_deref()
                .filter(|t| !matches!(*t, "string" | "guid"))
                && name.textual
            {
                out.push(
                    Diagnostic::warning(
                        codes::MICROSOFT_DEFENDER_COLUMN_TYPE,
                        format!(
                            "{} maps '{}', a {type_name} column: Defender reads an entity's or \
                             action's column as text; convert it with tostring() in the query",
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
        missing.push(&name.column);
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
    let required = missing_required_column_groups(&query.inner, &returned);
    if output.complete && !required.is_empty() {
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
    if let Some(diagnostic) = unprojected(query, &output, &named, &missing, at) {
        out.push(diagnostic);
    }
    out
}

/// `microsoft_defender_unprojected_output` when the output has columns no
/// field of the block and no required column uses, with the `| project` of
/// the ones that are.
fn unprojected(
    query: &InjectedQuery,
    output: &Output,
    named: &[Named],
    missing: &[&str],
    at: opentide_core::Range,
) -> Option<Diagnostic> {
    let groups = required_column_groups(&query.inner);
    let used = |column: &str| {
        named.iter().any(|n| n.column == column)
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
    let mut diagnostic = Diagnostic::warning(
        codes::MICROSOFT_DEFENDER_UNPROJECTED_OUTPUT,
        format!(
            "{lead}: Defender derives entity mappings from result columns, beyond the ones the \
             block declares; project the columns the rule uses"
        ),
        at,
    )
    .with_field_path(QUERY.iter().map(ToString::to_string).collect());
    if let Some(project) = project_clause(output, named, missing, &groups) {
        diagnostic = diagnostic.with_suggestion(project);
    }
    Some(diagnostic)
}

/// `| project` of the required columns the output has (the first of each
/// group), then the columns the block names, each once; `None` when there is
/// none, or a name cannot be written as a KQL column name.
fn project_clause(
    output: &Output,
    named: &[Named],
    missing: &[&str],
    groups: &[Vec<&'static str>],
) -> Option<String> {
    let mut columns: Vec<&str> = Vec::new();
    for group in groups {
        if let Some(column) = group.iter().find(|c| output.column(c).is_some()) {
            columns.push(column);
        }
    }
    for name in named {
        // A column the output lacks would be an unknown column of the project.
        if missing.contains(&name.column.as_str()) || output.lacks(&name.column) {
            continue;
        }
        columns.push(&name.column);
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
        assert_eq!(d.severity, opentide_core::Severity::Warning);
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

    #[test]
    fn a_name_that_is_not_an_identifier_is_bracketed_or_left_out() {
        assert_eq!(kql_name("DeviceId").as_deref(), Some("DeviceId"));
        assert_eq!(kql_name("a b").as_deref(), Some("['a b']"));
        assert_eq!(kql_name("it's"), None);
        assert_eq!(kql_name(""), None);
    }
}
