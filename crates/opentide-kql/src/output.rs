//! What a KQL query returns: the columns of its result, inferred offline
//! (#1885).
//!
//! The column pass ([`crate::schema`]) follows the columns through every
//! operator of the query; its schema after the last operator of the query's
//! one tabular statement is the query's output. Run here without the comma
//! quirk the diagnostics keep for now (#1386): `| project A, B, C` returns
//! exactly `A`, `B` and `C`.
//!
//! The inference says "unknown" ([`output`] is `None`) rather than guess:
//!
//! - the query does not parse, or has no tabular statement, or several;
//! - the pass loses track of the columns ([`Known::Open`]): a source the
//!   catalog does not know (a custom table, a workspace function, an
//!   undocumented table), an `evaluate` plugin, `bag_unpack`, an item whose
//!   generated name the pass does not model (`project tolower(A)`, an
//!   aggregate without a name it models), a `union` with such a leg,
//!   `make-series`, `mv-apply`, an operator the pass does not read.
//!
//! Otherwise the output is either *complete* (the query names its columns:
//! `project`, `summarize`, `distinct`, `count`, a `datatable`) or the
//! documented columns of a catalog table, to which a table may add columns
//! the reference does not list yet: [`Output::complete`] is `false`, and a
//! name that is not among them may still be a column.

use crate::schema::{self, Known};
use crate::syntax::SyntaxNode;
use crate::{Catalog, Profile, parser::parse_once};
use opentide_core::{ByteSpan, LineIndex};

/// One column of a query's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputColumn {
    /// Its name, as Kusto spells it (case-sensitive).
    pub name: String,
    /// Its Kusto scalar type (`string`, `long`, `datetime`), when known.
    pub type_name: Option<String>,
}

/// What a query returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The columns, in order.
    pub columns: Vec<OutputColumn>,
    /// `true`: the columns are exactly these. `false`: these are the
    /// documented columns of a table (no `project` or `summarize` narrowed
    /// them), and the table may have others.
    pub complete: bool,
    /// The query's last operator, without its `|` (or its source, when it
    /// has none): where a finding about the output is reported, and after
    /// which a `| project` goes.
    pub last_operator: ByteSpan,
}

impl Output {
    /// The column named `name`, compared as Kusto compares column names:
    /// case-sensitively.
    pub fn column(&self, name: &str) -> Option<&OutputColumn> {
        self.columns.iter().find(|c| c.name == name)
    }

    /// Whether the output certainly has no column named `name`: it is
    /// complete and does not hold it.
    pub fn lacks(&self, name: &str) -> bool {
        self.complete && self.column(name).is_none()
    }
}

/// What `source` returns under `profile`'s catalog, or `None` when it cannot
/// be inferred (see the module's documentation).
pub fn output(source: &str, profile: Profile) -> Option<Output> {
    let catalog = Catalog::for_workspace(profile, source);
    let parsed = parse_once(source);
    if !parsed.errors.is_empty() {
        return None;
    }
    let root = SyntaxNode::new_root(parsed.green);
    let lines = LineIndex::new(source);
    let (schema, last_operator) = schema::new_tree::output(&root, source, &lines, &catalog)?;
    let complete = match schema.known {
        Known::Open => return None,
        Known::Typos => false,
        Known::Closed => true,
    };
    Some(Output {
        columns: schema
            .columns
            .iter()
            .map(|c| OutputColumn {
                name: c.name.clone(),
                type_name: c.type_name.clone(),
            })
            .collect(),
        complete,
        last_operator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(query: &str) -> Option<(Vec<String>, bool)> {
        output(query, Profile::Defender)
            .map(|o| (o.columns.into_iter().map(|c| c.name).collect(), o.complete))
    }

    fn exactly(query: &str) -> Vec<String> {
        match names(query) {
            Some((columns, true)) => columns,
            other => panic!("{query}: not a complete output: {other:?}"),
        }
    }

    #[test]
    fn a_project_of_several_columns_returns_exactly_them() {
        assert_eq!(
            exactly(
                "DeviceEvents | where ActionType == 'x' \
                 | project Timestamp, ReportId, DeviceId, InitiatingProcessAccountUpn"
            ),
            [
                "Timestamp",
                "ReportId",
                "DeviceId",
                "InitiatingProcessAccountUpn"
            ]
        );
    }

    #[test]
    fn a_project_types_its_columns_from_the_table() {
        let out = output(
            "DeviceEvents | project Timestamp, DeviceId",
            Profile::Defender,
        )
        .unwrap();
        assert_eq!(out.columns[0].type_name.as_deref(), Some("datetime"));
        assert_eq!(out.columns[1].type_name.as_deref(), Some("string"));
    }

    #[test]
    fn a_table_without_a_project_returns_its_documented_columns_and_maybe_more() {
        let (columns, complete) = names("DeviceEvents | where ActionType == 'x'").unwrap();
        assert!(!complete);
        assert!(columns.iter().any(|c| c == "DeviceId"));
        assert!(columns.iter().any(|c| c == "InitiatingProcessAccountUpn"));
        let out = output("DeviceEvents", Profile::Defender).unwrap();
        assert!(!out.lacks("SomeNewColumn"), "the table may have it");
    }

    #[test]
    fn project_away_rename_and_extend_follow_the_columns() {
        assert_eq!(
            exactly(
                "DeviceEvents | project Timestamp, DeviceId, ReportId, FileName \
                 | project-away FileName | project-rename Device = DeviceId \
                 | extend Kind = 'x', Seen = Timestamp"
            ),
            ["Timestamp", "ReportId", "Device", "Kind", "Seen"]
        );
    }

    #[test]
    fn project_keep_and_reorder() {
        assert_eq!(
            exactly(
                "DeviceEvents | project Timestamp, DeviceId, ReportId \
                 | project-keep DeviceId, Timestamp"
            ),
            ["Timestamp", "DeviceId"]
        );
    }

    #[test]
    fn summarize_by_returns_the_aggregates_then_the_keys() {
        let columns = exactly(
            "DeviceEvents | summarize Count = count(), arg_max(Timestamp, ReportId) by DeviceId",
        );
        assert!(columns.contains(&"Count".to_string()), "{columns:?}");
        assert!(columns.contains(&"DeviceId".to_string()), "{columns:?}");
        assert!(columns.contains(&"ReportId".to_string()), "{columns:?}");
        assert!(!columns.contains(&"FileName".to_string()), "{columns:?}");
    }

    #[test]
    fn a_let_bound_pipeline_carries_its_columns() {
        assert_eq!(
            exactly(
                "let events = DeviceEvents | project Timestamp, DeviceId, ReportId;\n\
                 events | where DeviceId != ''"
            ),
            ["Timestamp", "DeviceId", "ReportId"]
        );
    }

    #[test]
    fn an_inner_join_renames_the_right_side_s_repeated_columns() {
        let columns = exactly(
            "DeviceEvents | project Timestamp, DeviceId \
             | join kind=inner (DeviceInfo | project DeviceId, OSPlatform) on DeviceId",
        );
        assert_eq!(
            columns,
            ["Timestamp", "DeviceId", "DeviceId1", "OSPlatform"]
        );
        let semi = exactly(
            "DeviceEvents | project Timestamp, DeviceId \
             | join kind=leftsemi (DeviceInfo | project DeviceId, OSPlatform) on DeviceId",
        );
        assert_eq!(semi, ["Timestamp", "DeviceId"]);
    }

    #[test]
    fn project_keep_returns_the_names_it_keeps_even_undocumented_ones() {
        // #1885 review: project-keep only removed, so a kept name the
        // catalog lacks was missing from a "complete" output.
        let columns = exactly(
            "DeviceNetworkInfo | where NetworkAdapterStatus == 'Up' \
             | project-keep Timestamp, ReportId, DeviceId, IPAddresses, NotInTheReference",
        );
        for name in [
            "Timestamp",
            "ReportId",
            "DeviceId",
            "IPAddresses",
            "NotInTheReference",
        ] {
            assert!(columns.iter().any(|c| c == name), "{name}: {columns:?}");
        }
        assert_eq!(columns.len(), 5, "{columns:?}");
    }

    #[test]
    fn arg_max_star_leaves_out_the_by_keys_and_is_as_sure_as_its_input() {
        // Kusto's arg_max example: `arg_max(Version, *) by Fruit` returns
        // Fruit, Version, Color, with no Fruit1.
        assert_eq!(
            exactly(
                "datatable(Fruit: string, Color: string, Version: int) ['a', 'b', 1] \
                 | summarize arg_max(Version, *) by Fruit"
            ),
            ["Fruit", "Version", "Color"]
        );
        // From a table, the copied columns are its documented ones: not
        // a complete output.
        let (columns, complete) =
            names("DeviceProcessEvents | summarize arg_max(Timestamp, *) by DeviceId").unwrap();
        assert!(!complete);
        assert!(!columns.iter().any(|c| c == "DeviceId1"), "{columns:?}");
        assert_eq!(columns.first().map(String::as_str), Some("DeviceId"));
    }

    #[test]
    fn a_defender_table_has_no_log_analytics_columns() {
        let out = output("DeviceNetworkInfo", Profile::Defender).unwrap();
        for name in [
            "TimeGenerated",
            "TenantId",
            "Type",
            "SourceSystem",
            "_BilledSize",
        ] {
            assert!(out.column(name).is_none(), "{name}");
        }
        assert!(out.column("Timestamp").is_some());
        assert!(out.column("ReportId").is_some());
    }

    #[test]
    fn every_defender_table_has_timestamp_and_no_log_analytics_column() {
        // #1885 review: the reference describes the Log Analytics copies of
        // the advanced hunting tables.
        let catalog = Catalog::cached(Profile::Defender);
        let tables: Vec<&str> = catalog
            .tables
            .iter()
            .filter(|t| t.profile.as_deref() == Some("defender"))
            .map(|t| t.name.as_str())
            .collect();
        assert!(tables.len() > 30, "{tables:?}");
        for table in tables {
            let Some(out) = output(table, Profile::Defender) else {
                continue;
            };
            assert!(out.column("Timestamp").is_some(), "{table}");
            for (name, _) in crate::tables::STANDARD_COLUMNS {
                assert!(out.column(name).is_none(), "{table}: {name}");
            }
        }
    }

    #[test]
    fn the_last_operator_is_where_a_project_goes() {
        let query = "DeviceEvents\n| where ActionType == 'x' // note\n";
        let out = output(query, Profile::Defender).unwrap();
        assert_eq!(
            &query[out.last_operator.start..out.last_operator.end],
            "where ActionType == 'x'"
        );
        let bare = output("DeviceEvents", Profile::Defender).unwrap();
        assert_eq!(bare.last_operator, ByteSpan::new(0, 12));
    }

    #[test]
    fn column_names_are_compared_with_their_case() {
        let out = output("DeviceEvents | project DeviceId", Profile::Defender).unwrap();
        assert!(out.column("DeviceId").is_some());
        assert!(out.lacks("deviceid"));
    }

    #[test]
    fn what_the_pass_cannot_follow_is_unknown() {
        for query in [
            // A table the catalog does not know.
            "MyCustomTable_CL | project A, B",
            // An `evaluate` plugin, and `bag_unpack`.
            "DeviceEvents | evaluate bag_unpack(AdditionalFields)",
            "DeviceEvents | project DeviceId | evaluate pivot(DeviceId)",
            // A function no `let` binds.
            "MyFunction() | where x == 1",
            // A column whose generated name the pass does not model.
            "DeviceEvents | project tolower(DeviceName)",
            "DeviceEvents | extend tolower(DeviceName)",
            // A union with an unknown leg.
            "union DeviceEvents, Unknown_CL | project-away DeviceId",
            // make-series.
            "DeviceEvents | make-series count() on Timestamp step 1h by DeviceId",
            // A query that does not parse.
            "DeviceEvents | project",
            // Two tabular statements.
            "DeviceEvents | take 1; DeviceInfo | take 1",
            // No tabular statement.
            "let x = 1;",
        ] {
            assert_eq!(names(query), None, "{query}");
        }
    }

    #[test]
    fn the_diagnostics_keep_the_comma_quirk() {
        // #1386: the diagnostics still leave the schema open after a list
        // of two items, while the output is exact.
        let query = "DeviceEvents | project DeviceId, ReportId | where Nope == 1";
        let diagnostics = crate::analyze(query, Profile::Defender).diagnostics;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == opentide_core::codes::KQL_UNKNOWN_COLUMN),
            "{diagnostics:?}"
        );
        assert_eq!(exactly(query), ["DeviceId", "ReportId"]);
    }
}
