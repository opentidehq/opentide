//! The column pass (#112) and the column and type checks on documented
//! sources (#113).

use opentide_core::{Position, Severity, codes};
use opentide_kql::schema::Known;
use opentide_kql::{Profile, analyze, columns, completions, hover, signature_help};

fn errors(src: &str, profile: Profile) -> Vec<(String, String, Option<String>)> {
    analyze(src, profile)
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| (d.code, d.message, d.suggestion))
        .collect()
}

fn column_errors(src: &str) -> Vec<(String, Option<String>)> {
    errors(src, Profile::Sentinel)
        .into_iter()
        .filter(|(code, _, _)| code == codes::KQL_UNKNOWN_COLUMN)
        .map(|(_, message, suggestion)| (message, suggestion))
        .collect()
}

fn type_errors(src: &str) -> Vec<String> {
    errors(src, Profile::Sentinel)
        .into_iter()
        .filter(|(code, _, _)| code == codes::KQL_TYPE_MISMATCH)
        .map(|(_, message, _)| message)
        .collect()
}

/// The columns of the query's last pipeline after its last operator.
fn output(src: &str) -> Vec<String> {
    let analysis = columns(src, Profile::Sentinel);
    let pipeline = analysis
        .pipelines
        .iter()
        .max_by_key(|p| (p.span.end, std::cmp::Reverse(p.span.start)))
        .expect("pipeline");
    let schema = pipeline
        .stages
        .last()
        .map(|s| &s.output)
        .unwrap_or(&pipeline.source);
    schema.columns.iter().map(|c| c.name.clone()).collect()
}

fn hover_at(src: &str, needle: &str, nth: usize) -> String {
    let offset = src.match_indices(needle).nth(nth).expect("needle").0 + 1;
    let before = &src[..offset];
    let line = before.matches('\n').count() as u32;
    let col = before.rsplit('\n').next().unwrap().chars().count() as u32;
    hover(src, Position::new(line, col), Profile::Sentinel).expect("hover")
}

#[test]
fn asim_parser_typo_is_an_error_with_the_column_it_misspells() {
    let found = column_errors("_Im_NetworkSession | where DstPortNumbr == 22");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].1.as_deref(), Some("DstPortNumber"));
    assert!(found[0].0.contains("ASIM NetworkSession"), "{}", found[0].0);
    // Named filtering parameters parse.
    assert!(
        column_errors(
            "_Im_NetworkSession(starttime=ago(1d), dstportnumber=22) | where DstPortNumber == 22"
        )
        .is_empty()
    );
    assert!(
        errors(
            "_Im_NetworkSession(starttime=ago(1d), dstportnumber=22) | take 1",
            Profile::Sentinel
        )
        .is_empty()
    );
}

#[test]
fn asim_parsers_and_ingest_time_tables_have_columns() {
    for source in [
        "ASimNetworkSessionLogs",
        "imAuthentication",
        "_ASim_Dns",
        "ASimDns",
        "_Im_ProcessCreate",
    ] {
        let analysis = columns(&format!("{source} | take 1"), Profile::Sentinel);
        let pipeline = &analysis.pipelines[0];
        assert!(pipeline.source.columns.len() > 50, "{source}");
        assert_eq!(pipeline.source.known, Known::Typos, "{source}");
        assert!(
            analyze(&format!("{source} | take 1"), Profile::Sentinel)
                .diagnostics
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn defender_xdr_tables_are_clean_under_sentinel() {
    assert!(
        analyze("DeviceProcessEvents | take 1", Profile::Sentinel)
            .diagnostics
            .is_empty()
    );
    assert!(column_errors("DeviceProcessEvents | where Timestamp > ago(1d) and TimeGenerated > ago(1d) | project FileName, ProcessCommandLine").is_empty());
    let found = errors(
        "DeviceProcessEvents | where FileNam == 'x'",
        Profile::Defender,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].2.as_deref(), Some("FileName"));
}

#[test]
fn a_documented_table_reports_near_misses_only() {
    let found = column_errors("SigninLogs | where UserPrincipalNam == 'x'");
    assert_eq!(
        found,
        vec![(
            "'UserPrincipalNam' is not a column of SigninLogs".into(),
            Some("UserPrincipalName".into())
        )]
    );
    // Tables gain columns before the reference lists them.
    assert!(column_errors("SigninLogs | where SomeNewColumn == 1").is_empty());
    // Standard and custom (`_CF`) columns exist on every Log Analytics table.
    assert!(column_errors("SigninLogs | where TenantId == 'x' and _ResourceId != '' and MyField_CF == 1 and _ItemId != ''").is_empty());
}

#[test]
fn columns_after_an_operator_that_reshapes_are_exact() {
    let found = column_errors(
        "SigninLogs | summarize count() by UserPrincipalName | where TimeGenerated > ago(1d)",
    );
    assert_eq!(
        found,
        vec![(
            "'TimeGenerated' is not a column after `summarize`".into(),
            None
        )]
    );
    let found = column_errors("SigninLogs | project User = UserPrincipalName | where Bogus == 1");
    assert_eq!(found.len(), 1, "{found:?}");
    let found = column_errors(
        "SigninLogs | project-rename User = UserPrincipalName | where UserPrincipalName == 'x'",
    );
    assert_eq!(
        found,
        vec![(
            "'UserPrincipalName' is not a column after `project-rename`".into(),
            None
        )]
    );
    let found = column_errors(
        "SigninLogs | distinct UserPrincipalName, AppDisplayName | where IPAddress == '1'",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    let found = column_errors("SigninLogs | count | where Count > 1 and Bogus == 1");
    assert_eq!(found.len(), 1, "{found:?}");
    let found = column_errors("datatable(A:string, B:long)['x', 1] | where C == 1");
    assert_eq!(
        found,
        vec![("'C' is not a column of the datatable".into(), None)]
    );
}

#[test]
fn an_unknown_source_never_yields_a_column_diagnostic() {
    for src in [
        "MyCustomLog_CL | where Bogus == 1",
        "MyCustomLog_CL | project A | where B == 1",
        "MyCustomLog_CL | summarize count() by A | where B == 1",
        "SigninLogs | evaluate bag_unpack(DeviceDetail) | where Bogus == 1",
        "SigninLogs | evaluate autocluster() | where Bogus == 1",
        "_GetWatchlist('x') | where Bogus == 1",
        "SigninLogs | extend tolower(UserPrincipalName) | where Bogus == 1",
        "SigninLogs | parse-kv Status as (a:string) with (pair_delimiter=',') | where Bogus == 1",
        "search 'x' | where Bogus == 1",
        "SigninLogs | invoke f() | where Bogus == 1",
    ] {
        assert!(
            column_errors(src).is_empty(),
            "{src}: {:?}",
            column_errors(src)
        );
    }
}

#[test]
fn a_query_that_does_not_parse_gets_no_column_diagnostic() {
    let r = analyze("SigninLogs | where Bogus == | project", Profile::Sentinel);
    assert!(
        r.diagnostics
            .iter()
            .any(|d| d.code == codes::KQL_PARSE_ERROR)
    );
    assert!(
        !r.diagnostics
            .iter()
            .any(|d| d.code == codes::KQL_UNKNOWN_COLUMN)
    );
}

#[test]
fn summarize_names_its_columns_as_kusto_does() {
    // Verified against the KQL oracle (scripts/oracles).
    assert_eq!(
        output(
            "SecurityEvent | summarize count(), dcount(Account), make_set(Account), make_list(Account), sum(EventID), countif(EventID == 1), take_any(Activity), make_set(Account, 10) by Computer"
        ),
        [
            "Computer",
            "count_",
            "dcount_Account",
            "set_Account",
            "list_Account",
            "sum_EventID",
            "countif_",
            "Activity",
            "set_Account1"
        ]
    );
    assert_eq!(
        output(
            "SecurityEvent | summarize count() by bin(TimeGenerated, 1h), bin(TimeGenerated, 1d), Computer"
        ),
        ["TimeGenerated", "TimeGenerated1", "Computer", "count_"]
    );
    assert_eq!(
        output("SecurityEvent | summarize arg_min(TimeGenerated, Account, EventID) by Computer"),
        ["Computer", "TimeGenerated", "Account", "EventID"]
    );
    let star = output("SecurityEvent | summarize arg_max(TimeGenerated, *) by Computer");
    assert!(star.len() > 100 && star.iter().filter(|c| *c == "Computer").count() == 1);
    let named = output("SecurityEvent | summarize Last = arg_max(TimeGenerated, *) by Computer");
    assert!(
        named.contains(&"Last".into())
            && named.contains(&"Account".into())
            && !named.contains(&"TimeGenerated".into())
    );
    assert!(column_errors("ThreatIntelligenceIndicator | summarize Latest = arg_max(TimeGenerated, *) by IndicatorId | where Active == true and ExpirationDateTime > now()").is_empty());
    // The deprecated argmax names its columns max_T_Col; the pass does not guess.
    assert!(column_errors("ThreatIntelligenceIndicator | summarize T = argmax(TimeGenerated, *) by IndicatorId | extend D = max_TimeGenerated_Description").is_empty());
}

#[test]
fn join_lookup_and_union_combine_columns() {
    assert_eq!(
        output(
            "SecurityEvent | project Account, TimeGenerated | join (SecurityEvent | project Account, TimeGenerated) on Account"
        ),
        ["Account", "TimeGenerated", "Account1", "TimeGenerated1"]
    );
    assert_eq!(
        output(
            "SecurityEvent | project Account | join kind=leftsemi (SigninLogs | project UserPrincipalName) on $left.Account == $right.UserPrincipalName"
        ),
        ["Account"]
    );
    assert_eq!(
        output(
            "SecurityEvent | project Account | join kind=rightanti (SigninLogs | project UserPrincipalName) on $left.Account == $right.UserPrincipalName"
        ),
        ["UserPrincipalName"]
    );
    assert_eq!(
        output(
            "SecurityEvent | project Account, Computer | lookup (SigninLogs | project Account = UserPrincipalName, Computer = AppDisplayName) on Account"
        ),
        ["Account", "Computer", "Computer1"]
    );
    assert_eq!(
        output("union withsource=Src (datatable(A:string)['x']), (datatable(B:long)[1])"),
        ["A", "B", "Src"]
    );
    assert_eq!(
        output("union (datatable(A:string)['x']), (datatable(A:long)[1])"),
        ["A_string", "A_long"]
    );
    let found = column_errors(
        "SecurityEvent | join kind=inner (SigninLogs) on $left.Account == $right.UserPrincipalNam",
    );
    assert_eq!(found[0].1.as_deref(), Some("UserPrincipalName"));
    assert_eq!(column_errors("SecurityEvent | project Account | join (SigninLogs | project UserPrincipalName) on Account").len(), 1);
}

#[test]
fn extend_mv_expand_parse_and_lets_track_columns() {
    assert!(output("SigninLogs | project UserPrincipalName | extend Domain = tostring(split(UserPrincipalName, '@')[1]), (A, B) = f(1)").ends_with(&["Domain".into(), "A".into(), "B".into()]));
    assert_eq!(
        output(
            "SigninLogs | project ConditionalAccessPolicies | mv-expand with_itemindex=Idx P = ConditionalAccessPolicies to typeof(string)"
        ),
        ["ConditionalAccessPolicies", "Idx", "P"]
    );
    assert_eq!(
        output(
            "Syslog | project SyslogMessage | parse SyslogMessage with * 'user=' User:string ' port=' Port:long"
        ),
        ["SyslogMessage", "User", "Port"]
    );
    assert_eq!(output("print a = 1, 'x'"), ["a", "print_1"]);
    // A tabular let, a tabular function and materialize carry their columns.
    assert_eq!(
        column_errors("let base = SigninLogs | project U = UserPrincipalName; base | where V == 1")
            .len(),
        1
    );
    assert_eq!(column_errors("let f = (n:long) { SigninLogs | project U = UserPrincipalName | where strlen(U) > n }; f(5) | where V == 1").len(), 1);
    assert_eq!(column_errors("let m = materialize(SigninLogs | summarize c = count() by UserPrincipalName); m | where V == 1").len(), 1);
    // Scalar lets and parameters are not columns.
    assert!(column_errors("let threshold = 5; let names = dynamic(['a']); SigninLogs | summarize c = count() by UserPrincipalName | where c > threshold and UserPrincipalName in (names)").is_empty());
    // A subquery has its own source.
    assert!(column_errors("SigninLogs | where UserPrincipalName in ((AuditLogs | project Identity)) | where toscalar(AuditLogs | count) > 0").is_empty());
    assert_eq!(column_errors("SigninLogs | where UserPrincipalName in ((AuditLogs | project Identity | where Bogus == 1))").len(), 1);
}

#[test]
fn hover_on_a_renamed_column_shows_its_new_name_and_type() {
    let src = "SigninLogs | project-rename User = UserPrincipalName | where User == 'x'";
    let md = hover_at(src, "User ==", 0);
    assert!(md.starts_with("**User** column (`string`)"), "{md}");
    assert!(
        md.contains("Renamed from `UserPrincipalName` by `project-rename`"),
        "{md}"
    );
    let src = "SigninLogs | summarize Logins = count() by UserPrincipalName | where Logins > 5";
    let md = hover_at(src, "Logins >", 0);
    assert!(
        md.starts_with("**Logins** column (`long`)") && md.contains("Made by `summarize`"),
        "{md}"
    );
    let md = hover_at("_Im_NetworkSession | take 1", "_Im_NetworkSession", 0);
    assert!(
        md.contains("unifying ASIM parser") && md.contains("dstportnumber: int"),
        "{md}"
    );
}

#[test]
fn hover_on_a_reference_column_shows_its_description() {
    let src = "SigninLogs | where isnotempty(AppliedEventListeners)";
    let md = hover_at(src, "AppliedEventListeners", 0);
    assert!(
        md.starts_with("**AppliedEventListeners** column (`dynamic`)"),
        "{md}"
    );
    assert!(
        md.contains(
            "On `SigninLogs`. Detailed information about the listeners, such as Azure Logic Apps \
             and Azure Functions, that were triggered by the corresponding events in the sign-in event."
        ),
        "{md}"
    );
    assert!(
        md.contains(
            "(https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs)"
        ),
        "{md}"
    );
    // The column is described from the table it comes from, not from the
    // first table the query names.
    let src = "SigninLogs | take 1 | union (AADNonInteractiveUserSignInLogs | where isnotempty(AppliedEventListeners))";
    let md = hover_at(src, "AppliedEventListeners", 0);
    assert!(
        md.contains("On `AADNonInteractiveUserSignInLogs`. Detailed information about the applied event listeners"),
        "{md}"
    );
}

#[test]
fn hover_on_an_asim_column_shows_its_schema_and_class() {
    let md = hover_at(
        "_Im_NetworkSession | where SrcIpAddr == '10.0.0.1'",
        "SrcIpAddr",
        0,
    );
    assert!(md.starts_with("**SrcIpAddr** column (`string`)"), "{md}");
    assert!(
        md.contains("Recommended field of the ASIM `NetworkSession` schema."),
        "{md}"
    );
    assert!(
        md.contains("(https://aka.ms/ASimNetworkSessionDoc)"),
        "{md}"
    );
}

#[test]
fn column_completion_documents_reference_columns() {
    let src = "SigninLogs | where ";
    let items = completions(src, src.len(), Profile::Sentinel);
    let item = items
        .iter()
        .find(|i| i.label == "AppliedEventListeners")
        .expect("column item");
    assert_eq!(item.detail.as_deref(), Some("SigninLogs (dynamic)"));
    assert!(
        item.documentation
            .as_deref()
            .is_some_and(|d| d.starts_with("Detailed information about the listeners")),
        "{item:?}"
    );
    // With no table named, only the hand-written columns are offered, not
    // every documented column of the reference.
    let src = "print x = 1 | where ";
    let items = completions(src, src.len(), Profile::Sentinel);
    assert!(items.iter().any(|i| i.label == "UserPrincipalName"));
    assert!(!items.iter().any(|i| i.label == "AppliedEventListeners"));
}

#[test]
fn asim_parameters_get_signature_help() {
    let src = "_Im_NetworkSession(starttime=ago(1d), dstportnumber=";
    let help = signature_help(src, src.len(), Profile::Sentinel).expect("help");
    let sig = &help.signatures[0];
    assert!(
        sig.label
            .starts_with("_Im_NetworkSession(starttime: datetime"),
        "{}",
        sig.label
    );
    assert!(
        sig.parameters[help.active_parameter as usize]
            .label
            .starts_with("dstportnumber")
    );
}

#[test]
fn the_pass_says_which_operator_made_the_columns_a_predicate_reads() {
    let src = "SigninLogs | extend Domain = tostring(split(UserPrincipalName, '@')[1]) | where Domain == 'example.com' and AppId != ''";
    let analysis = columns(src, Profile::Sentinel);
    let filter = src.find("where").unwrap();
    let span = opentide_core::ByteSpan::new(filter, src.len());
    let reads: Vec<_> = analysis
        .reads(span)
        .map(|r| {
            (
                r.name.clone(),
                r.column
                    .as_ref()
                    .and_then(|c| c.made_by)
                    .map(|m| m.keyword()),
            )
        })
        .collect();
    assert_eq!(
        reads,
        vec![("Domain".into(), Some("extend")), ("AppId".into(), None)]
    );
}

#[test]
fn operators_kusto_does_not_define_for_a_type_are_errors() {
    // Each verified against the KQL oracle (scripts/oracles): KS106 or KS107.
    for src in [
        "SecurityEvent | where EventID has '46'",
        "SecurityEvent | where EventID contains '46'",
        "SecurityEvent | where EventID matches regex '4.*'",
        "SecurityEvent | where EventID =~ '4688'",
        "SecurityEvent | where EventID has_any ('46')",
        "SecurityEvent | where TimeGenerated startswith '2024'",
        "SigninLogs | where IsInteractive has 'true'",
        "SecurityEvent | where TimeGenerated > '2024-01-01'",
        "SecurityEvent | where '2024' < TimeGenerated",
        "SecurityEvent | where TimeGenerated > 5",
        "SecurityEvent | where EventID > '5'",
        "SecurityEvent | where Account > 5",
        "SecurityEvent | where Account between ('a' .. 'b')",
    ] {
        assert_eq!(type_errors(src).len(), 1, "{src}");
    }
    for src in [
        "SecurityEvent | where EventID == '4688'",
        "SecurityEvent | where Account == 5",
        "SecurityEvent | where TimeGenerated == '2024-01-01'",
        "SecurityEvent | where EventID in ('4688', '4624')",
        "SecurityEvent | where EventID between (1 .. 5)",
        "SecurityEvent | where TimeGenerated > ago(1d)",
        "SigninLogs | where Id has 'x'",
        "SigninLogs | where LocationDetails has 'x'",
        "SigninLogs | where IsInteractive > 1",
        "MyCustomLog_CL | where EventID has 'x'",
        "SecurityEvent | extend EventID = tostring(EventID) | where EventID has '46'",
    ] {
        assert!(type_errors(src).is_empty(), "{src}: {:?}", type_errors(src));
    }
    assert_eq!(
        type_errors("SecurityEvent | where EventID has '46'"),
        vec!["`has` is not defined for `EventID`, an int column; Kusto rejects the query"]
    );
}
