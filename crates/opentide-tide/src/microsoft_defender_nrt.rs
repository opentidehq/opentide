//! A Microsoft Defender block that runs continuously (`schedule.frequency:
//! NRT`) against what Microsoft documents an NRT query may be (#1890).
//!
//! Microsoft's custom detection docs
//! (<https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules>,
//! "Queries you can run continuously", read 2026-11-26) say:
//!
//! > You can run a query continuously as long as:
//! > - The query references one table only.
//! > - The query uses an operator from the list of Supported KQL features.
//! >   [...]
//! > - The query doesn't use joins, unions, or the externaldata operator.
//! > - The query doesn't include any comments line or information.
//!
//! and list the tables near real-time detections support ([`NRT_TABLES`]),
//! "EmailEvents (except LatestDeliveryLocation and LatestDeliveryAction
//! columns)" ([`EMAIL_EVENTS_EXCLUDED`]).
//!
//! Each broken condition is one `microsoft_defender_nrt_query` warning at
//! the query text that breaks it: a second table, a table off the list, each
//! `join`, `union` and `externaldata`, the first comment, each excluded
//! `EmailEvents` column. What Graph does with such a rule is not documented,
//! so it is a warning, which `opentide lint` and the editor report. The check
//! is conservative: a query with a syntax error, a table read through a
//! function or another database, and the supported operator list (a page of
//! its own) are not judged.

use opentide_core::node::Node;
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};

use crate::{InjectedQuery, remap_span};

/// The block's query.
pub(crate) const QUERY: [&str; 3] = ["configurations", "microsoft_defender", "query"];

/// The tables Microsoft documents for near real-time detections, Defender
/// XDR's then Microsoft Sentinel's, as the docs list them (read
/// 2026-11-26).
pub(crate) const NRT_TABLES: [&str; 38] = [
    // Microsoft Defender XDR
    "AlertEvidence",
    "CloudAppEvents",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "IdentityDirectoryEvents",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "UrlClickEvents",
    // Microsoft Sentinel
    "ABAPAuditLog_C",
    "ABAPChangeDocsLog_CL",
    "AuditLogs",
    "AWSCloudTrail",
    "AWSGuardDuty",
    "AzureActivity",
    "CommonSecurityLog",
    "GCPAuditLogs",
    "MicrosoftGraphActivityLogs",
    "OfficeActivity",
    "Okta_CL",
    "OktaV2_CL",
    "ProofpointPOD",
    "ProofPointTAPClicksPermitted_CL",
    "ProofPointTAPMessagesDelivered_CL",
    "SecurityAlert",
    "SecurityEvent",
    "SigninLogs",
];

/// The `EmailEvents` columns the docs leave out of NRT.
pub(crate) const EMAIL_EVENTS_EXCLUDED: [&str; 2] =
    ["LatestDeliveryLocation", "LatestDeliveryAction"];

/// Whether the Defender block `block` runs continuously.
fn runs_continuously(block: &Node) -> bool {
    block
        .get("schedule")
        .and_then(|schedule| schedule.get("frequency"))
        .and_then(|frequency| frequency.value.as_str())
        == Some("NRT")
}

/// The `microsoft_defender_nrt_query` findings of the Defender block `block`
/// on its query `query`, in the file `source`; none when the block does not
/// run continuously or the query does not parse.
pub(crate) fn nrt_findings(source: &str, block: &Node, query: &InjectedQuery) -> Vec<Diagnostic> {
    if !runs_continuously(block) {
        return Vec::new();
    }
    let Some(shape) = opentide_kql::shape::shape(&query.inner) else {
        return Vec::new();
    };
    let mut found: Vec<(ByteSpan, String)> = Vec::new();
    // The distinct tables in order, and a set of them, so a query naming
    // many tables is read in linear time.
    let mut distinct: Vec<&str> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (table, span) in &shape.tables {
        if !seen.insert(table.as_str()) {
            continue;
        }
        distinct.push(table);
        if distinct.len() == 2 {
            found.push((
                *span,
                format!(
                    "a continuous (NRT) rule's query reads one table only; this one also reads \
                     '{table}' after '{}': run the rule on a schedule (1H, 3H, 12H, 24H), or \
                     split it",
                    distinct[0]
                ),
            ));
        }
        if !NRT_TABLES.contains(&table.as_str()) {
            found.push((
                *span,
                format!(
                    "'{table}' is not a table Defender documents for continuous (NRT) \
                     detections: run the rule on a schedule (1H, 3H, 12H, 24H)"
                ),
            ));
        }
    }
    let operators = [
        (&shape.joins, "join"),
        (&shape.unions, "union"),
        (&shape.externaldata, "externaldata"),
    ];
    for (spans, operator) in operators {
        for span in spans {
            found.push((
                *span,
                format!(
                    "a continuous (NRT) rule's query uses no {operator}: rewrite it without, or \
                     run the rule on a schedule (1H, 3H, 12H, 24H)"
                ),
            ));
        }
    }
    if let Some(first) = shape.comments.first() {
        let count = shape.comments.len();
        found.push((
            *first,
            format!(
                "a continuous (NRT) rule's query holds no comment, and this one has {count}: \
                 move {} to the rule's description",
                if count == 1 { "it" } else { "them" }
            ),
        ));
    }
    if distinct == ["EmailEvents"] {
        for (name, span) in &shape.names {
            if EMAIL_EVENTS_EXCLUDED.contains(&name.as_str()) {
                found.push((
                    *span,
                    format!(
                        "EmailEvents' {name} is not available to a continuous (NRT) rule: drop \
                         it, or run the rule on a schedule (1H, 3H, 12H, 24H)"
                    ),
                ));
            }
        }
    }
    found.sort_by_key(|(span, _)| (span.start, span.end));
    found
        .into_iter()
        .map(|(span, message)| {
            Diagnostic::warning(
                codes::MICROSOFT_DEFENDER_NRT_QUERY,
                message,
                span_to_range(source, remap_span(query, span)),
            )
            .with_field_path(query.field_path.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::analyze_queries;

    /// The `microsoft_defender_nrt_query` findings of a Defender rule with
    /// `frequency` and `query` (a block scalar), as `(line, text)`: the
    /// 0-based line and the text each is on.
    fn nrt(frequency: &str, query: &str) -> Vec<(u32, String)> {
        let body = query
            .lines()
            .map(|line| format!("      {line}\n"))
            .collect::<Vec<_>>()
            .concat();
        let source = format!(
            "name: R\nconfigurations:\n  microsoft_defender:\n    status: STAGING\n    \
             schedule:\n      frequency: {frequency}\n    query: |\n{body}"
        );
        analyze_queries(&source, &[])
            .into_iter()
            .flat_map(|q| q.diagnostics)
            .filter(|d| d.code == "microsoft_defender_nrt_query")
            .map(|d| {
                let line = source.lines().nth(d.range.start.line as usize).unwrap();
                let start = d.range.start.character as usize;
                let end = d.range.end.character as usize;
                (d.range.start.line, line[start..end].to_owned())
            })
            .collect()
    }

    #[test]
    fn a_query_defender_can_run_continuously_earns_nothing() {
        let query = "DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n\
                     | project Timestamp, DeviceId, ReportId, DeviceName";
        assert_eq!(nrt("NRT", query), []);
        let bound = "let names = dynamic([\"a.exe\"]);\nDeviceProcessEvents\n\
                     | where FileName in (names)";
        assert_eq!(nrt("NRT", bound), []);
        assert_eq!(
            nrt("NRT", "EmailEvents | where DeliveryAction == \"Delivered\""),
            []
        );
    }

    #[test]
    fn a_scheduled_rule_or_a_broken_query_earns_nothing() {
        let joined = "// two tables\nDeviceEvents | join (DeviceInfo) on DeviceId";
        assert_eq!(nrt("1H", joined), []);
        assert_eq!(nrt("NRT", "DeviceEvents | join (DeviceInfo"), []);
    }

    #[test]
    fn each_documented_nrt_restriction_is_reported_where_it_is_broken() {
        // A join of a second table: the join and the table.
        assert_eq!(
            nrt("NRT", "DeviceEvents\n| join (DeviceInfo) on DeviceId"),
            [(8, "join".to_owned()), (8, "DeviceInfo".to_owned())]
        );
        // A union, and a table off the list.
        assert_eq!(
            nrt("NRT", "union DeviceEvents, DeviceEvents"),
            [(7, "union".to_owned())]
        );
        assert_eq!(
            nrt("NRT", "IdentityInfo | take 1"),
            [(7, "IdentityInfo".to_owned())]
        );
        // externaldata.
        let external = "DeviceEvents\n| where FileName in ((externaldata (n: string) \
                        [\"https://example.org/n.csv\"] | project n))";
        assert_eq!(nrt("NRT", external), [(8, "externaldata".to_owned())]);
        // Comments: one finding, at the first.
        assert_eq!(
            nrt("NRT", "// recent\nDeviceEvents // all of them\n| take 1"),
            [(7, "// recent".to_owned())]
        );
        // EmailEvents' excluded columns.
        assert_eq!(
            nrt(
                "NRT",
                "EmailEvents | where LatestDeliveryAction == \"Blocked\""
            ),
            [(7, "LatestDeliveryAction".to_owned())]
        );
    }

    #[test]
    fn every_nrt_table_is_listed_once() {
        let mut seen = std::collections::BTreeSet::new();
        for table in super::NRT_TABLES {
            assert!(seen.insert(table), "{table} twice");
        }
    }
}
