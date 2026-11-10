//! The "did you mean" each engine gives for typical misspellings (#790):
//! every engine crate picks its suggestion with the one shared rule,
//! `opentide_core::suggest`, so the CLI, the editor and every query language
//! suggest alike.
//!
//! One line per diagnostic: `severity code text-under-range => suggestion`.
//! A change of a suggestion shows here as a snapshot diff; a change of a code,
//! a severity or a range shows too, and is not a suggestion change (plan §3,
//! invariant 3). After an intended change,
//! `INSTA_UPDATE=always cargo test -p opentide-analysis --test suggestions`
//! writes the new snapshot; read its diff before committing.

use opentide_analysis::{AnalyzeRequest, MemoryWorkspace, QueryRequest, analyze, analyze_query};
use opentide_core::{Diagnostic, LanguageId};
use std::fmt::Write as _;

/// The text `d` covers in `source` (its first line, when it spans more).
fn covered(source: &str, d: &Diagnostic) -> String {
    let line = source
        .lines()
        .nth(d.range.start.line as usize)
        .unwrap_or("");
    let units: Vec<u16> = line.encode_utf16().collect();
    let start = (d.range.start.character as usize).min(units.len());
    let end = if d.range.end.line == d.range.start.line {
        (d.range.end.character as usize).clamp(start, units.len())
    } else {
        units.len()
    };
    String::from_utf16_lossy(&units[start..end])
}

/// The diagnostics with a suggestion, or with one of `codes`, one per line.
fn render(source: &str, diagnostics: &[Diagnostic], codes: &[&str]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        if d.suggestion.is_none() && !codes.contains(&d.code.as_str()) {
            continue;
        }
        let _ = writeln!(
            out,
            "  {} {} `{}` => {}",
            d.severity.as_str(),
            d.code,
            covered(source, d),
            d.suggestion.as_deref().unwrap_or("(none)"),
        );
    }
    out
}

/// Each query of `cases`, analysed on its own, and what it suggests.
fn queries(language: LanguageId, platform: Option<&str>, codes: &[&str], cases: &[&str]) -> String {
    let mut out = String::new();
    for text in cases {
        let found = analyze_query(&QueryRequest {
            language,
            platform: platform.map(str::to_string),
            stack: None,
            text: (*text).to_string(),
        });
        let _ = writeln!(out, "{text}");
        out.push_str(&render(text, &found, codes));
    }
    out
}

/// A rule whose `configurations` block is `block`, analysed as a Tide file.
fn tide(block: &str, codes: &[&str]) -> String {
    let text = format!(
        "name: Suggestions\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000005a9\n  schema: rule::1.0\nconfigurations:\n{block}"
    );
    let uri = "objects/rules/suggestions.yaml";
    let host = MemoryWorkspace {
        files: vec![(uri.into(), text.clone())],
    };
    let found = analyze(
        &host,
        AnalyzeRequest {
            uri: uri.into(),
            language: LanguageId::TideYaml,
            text: text.clone(),
        },
    )
    .diagnostics;
    format!("{}\n{}", block.trim_end(), render(&text, &found, codes))
}

#[test]
fn kql() {
    let mut out = queries(
        LanguageId::Kql,
        Some("sentinel"),
        &["kql_unknown_operator", "kql_unknown_function"],
        &[
            "SecurityEvent | wher EventID == 4688",
            "SecurityEvent | summarzie count() by Account",
            "SecurityEvent | extend a = tolowr(Account)",
            "SecurityEvent | extend a = strlenn(Account)",
            "SecurityEvent | evaluate bag_unpak(x)",
            "SecurityEvent | prjct Account",
            "SecurityEvent | extend a = to_lower(Account)",
            "SecurityEvnt | take 1",
            "Securityevent | take 1",
            // Two letters cut from a long name, or changed side by side:
            // bound by the whole name, so still found.
            "SecurityEve | take 1",
            "SecurityEvent | summari count() by Account",
            // The scalar-function gate (#790, invariant 3): within two edits
            // a diagnostic, three edits none.
            "SecurityEvent | extend a = tolwr(Account)",
            "SecurityEvent | extend a = tlwr(Account)",
            // A deprecated function is never the suggestion (`argmax`, one
            // edit, is deprecated for `arg_max`).
            "SecurityEvent | extend a = argmaxx(Account)",
            "SecurityEvent | extend a = totimee(Account)",
        ],
    );
    out.push_str(&queries(
        LanguageId::Kql,
        Some("defender_for_endpoint"),
        &["kql_unknown_column", "kql_unknown_table"],
        &[
            "DeviceProcesEvents | take 1",
            "DeviceProcessEvents | where FileNme == \"cmd.exe\"",
            "DeviceProcessEvents | where filename == \"cmd.exe\"",
            "DeviceProcessEvents | where ProcesCommandLine has \"x\"",
            "DeviceProcessEven | take 1",
            // The column gate (invariant 3): within two edits, ignoring case,
            // and less than half the name.
            "DeviceProcessEvents | where FilNme == \"cmd.exe\"",
            "DeviceProcessEvents | where SHA1xy == \"x\"",
            "DeviceProcessEvents | where SH1x == \"x\"",
            "DeviceProcessEvents | where filenme == \"cmd.exe\"",
        ],
    ));
    insta::assert_snapshot!(out);
}

#[test]
fn spl() {
    insta::assert_snapshot!(queries(
        LanguageId::Spl,
        None,
        &[
            "spl_unknown_command",
            "spl_unknown_datamodel",
            "spl_unknown_datamodel_field"
        ],
        &[
            "index=main | stast count by host",
            "index=main | statz count by host",
            "index=main | tabel host",
            "index=main | evall x=1",
            "index=main | rexx field=_raw \"(?<a>.)\"",
            "index=main | sats count",
            "index=main | stas count",
            "index=main | tsast count",
            "index=main | stattz count",
            "| tstats count from datamodel=Endpointz.Processes by Processes.process_name",
            "| tstats count from datamodel=Endpoint.Procesess by Processes.process_name",
            "| tstats count from datamodel=Endpoint.Processes by Processes.process_nam",
            "| tstats count from datamodel=Endpoint.Processes by Processes.proces_path",
        ],
    ));
}

#[test]
fn esql() {
    insta::assert_snapshot!(queries(
        LanguageId::Esql,
        None,
        &[
            "esql_unknown_command",
            "esql_unknown_function",
            "esql_unknown_type",
            "ecs_unknown_field"
        ],
        &[
            "FROM logs-* | WEHRE process.pid > 1",
            "FROM logs-* | STAST count = COUNT(*)",
            "FROM logs-* | WHR process.pid > 1",
            "FROM logs-* | EVAL a = DATEDIFF(\"day\", @timestamp, @timestamp)",
            "FROM logs-* | EVAL a = TO_LOWR(process.name)",
            "FROM logs-* | EVAL a = TOLOWER(process.name)",
            "FROM logs-* | EVAL a = process.pid::lng",
            "FROM logs-* | EVAL a = process.pid::keywrd",
            "FROM logs-* | WHERE process.nmae == \"cmd.exe\"",
            "FROM logs-* | WHERE process.parent.nmea == \"cmd.exe\"",
            // Alias and snapshot-only commands and functions are never the
            // suggestion (`INLINESTATS` is an alias of `INLINE STATS`;
            // `FILLNULL`, `TSTEP` and `V_MAGNITUDE` are snapshot-only).
            "FROM logs-* | INLINESTAT x = COUNT(*)",
            "FROM logs-* | FILLNUL",
            "FROM logs-* | EVAL a = TSTE(@timestamp)",
            "FROM logs-* | EVAL a = V_MAGNITUD(x)",
        ],
    ));
}

#[test]
fn eql() {
    insta::assert_snapshot!(queries(
        LanguageId::Eql,
        None,
        &["eql_unknown_function"],
        &[
            "process where startswith~(process.name, \"cmd\")",
            "process where startwith(process.name, \"cmd\")",
            "process where lenght(process.name) > 1",
            "process where str(process.pid) == \"1\"",
            "process where stringContains(process.name, \"cmd\")",
            "process where cidrmatch(source.ip, \"10.0.0.0/8\")",
        ],
    ));
}

#[test]
fn cql() {
    insta::assert_snapshot!(queries(
        LanguageId::Cql,
        None,
        &[
            "cql_unknown_function",
            "cql_unknown_parameter",
            "cql_unknown_event"
        ],
        &[
            "groupBi([ComputerName])",
            "groupby([ComputerName], functin=count())",
            "#event_simpleName=ProcessRollup3",
            "#event_simpleName=processrollup2",
            "#event_simpleName=ProcesRollup2",
            "selct([ComputerName])",
            // Two edits apart: not within the one edit events allow.
            "#event_simpleName=PrucessRollup3",
            // An unavailable or removed function is never the suggestion
            // (`holtwinters` and `rdns` are removed,
            // `math:spherical2cartesian` unavailable).
            "holtwinter(x)",
            "rdnz(x)",
            "math:spherical2cartesia(x)",
        ],
    ));
}

#[test]
fn falco() {
    insta::assert_snapshot!(queries(
        LanguageId::Falco,
        None,
        &[
            "falco_unknown_field",
            "falco_unknown_event",
            "falco_unknown_macro"
        ],
        &[
            "evt.typ = execve",
            "evt.type = execvee",
            "proc.nmae = bash",
            "proc.Name = bash",
            "spawned_proces and proc.name = bash",
            "container.imge.repository = nginx",
        ],
    ));
}

#[test]
fn carbon_black_lucene() {
    insta::assert_snapshot!(tide(
        "  carbon_black_cloud:\n    query: process_nmae:cmd.exe OR parent_nme:x OR Process_Name:y OR proces_cmdline:z OR proces_nme:a OR PROCES_NAME:b OR prcs_nme:c\n",
        &["cbc_unknown_field"],
    ));
}

#[test]
fn sysdig_append_to_rule() {
    insta::assert_snapshot!(tide(
        "  sysdig:\n    append_to_rule: Terminal shell in containr\n    condition: proc.name = bash\n",
        &["falco_unknown_rule"],
    ));
}
