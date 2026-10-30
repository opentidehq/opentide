//! Valid KQL the grammar rejected (opentidehq/language-server#109, A3):
//! doubled quotes in verbatim strings, `.[...]` access, quoted identifiers,
//! `parse-where`, and `distinct` with named expressions. Each form is also
//! followed by the column pass.

use opentide_core::{Diagnostic, Severity, codes};
use opentide_kql::{Profile, analyze, columns};

fn diagnostics(source: &str) -> Vec<Diagnostic> {
    analyze(source, Profile::Sentinel).diagnostics
}

fn assert_clean(source: &str) {
    let errors: Vec<(String, String)> = diagnostics(source)
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| (d.code, d.message))
        .collect();
    assert!(errors.is_empty(), "{source}\n{errors:?}");
}

fn assert_parse_error(source: &str) {
    assert!(
        diagnostics(source)
            .iter()
            .any(|d| d.code == codes::KQL_PARSE_ERROR),
        "{source} should not parse"
    );
}

fn column_errors(source: &str) -> Vec<String> {
    diagnostics(source)
        .into_iter()
        .filter(|d| d.code == codes::KQL_UNKNOWN_COLUMN)
        .map(|d| d.message)
        .collect()
}

/// The columns of the query's last pipeline after its last operator.
fn output(source: &str) -> Vec<String> {
    let analysis = columns(source, Profile::Sentinel);
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

#[test]
fn verbatim_strings_double_a_quote_to_hold_one() {
    for source in [
        r#"print s = @"{""a"":""b""}""#,
        r#"print x = "a[1]" | extend y = replace_regex(x, @"\[|\]|""", "")"#,
        r#"print s = @'it''s'"#,
        // A doubled quote is not two strings, and an empty verbatim string still ends.
        r#"print s = @"", t = @"a" == "b""#,
        r#"print s = @"""""#,
    ] {
        assert_clean(source);
    }
    // A verbatim string still ends at a single quote.
    assert_parse_error(r#"print s = @"a"b""#);
    assert_parse_error(r#"print s = @"a"""#);
}

#[test]
fn dot_bracket_access_reads_a_key_or_an_element() {
    for source in [
        r#"print d = parse_json("{}") | extend v = tostring(d.["a.b"])"#,
        r#"print d = parse_json("{}") | extend v = tostring(d.[0].n)"#,
        r#"print d = dynamic({"a": {"b.c": 1}}) | extend v = d.a.["b.c"]"#,
        r#"print d = dynamic([1]) | extend e = d[0], f = d["k"]"#,
    ] {
        assert_clean(source);
    }
    assert_parse_error("print d = dynamic([1]) | extend v = d.[0");
    // The object is still a column reference.
    assert_eq!(
        column_errors("SigninLogs | project DeviceDetail | extend v = DeviceDetaill.[\"a\"]"),
        ["'DeviceDetaill' is not a column after `project`"]
    );
}

#[test]
fn quoted_identifiers_are_column_names() {
    for source in [
        "print c = 1 | where ['c'] > 0",
        "print n = 2 | project [\"Display Name\"] = tostring(n)",
        "print n = 2 | extend ['a b'] = n, [\"c\"] = 1 | where ['a b'] > 1",
        "print a = 1 | project-rename ['b c'] = a | project-away ['b c']",
        "print a = 1, b = 2 | project-keep ['a'] | project-reorder ['a'] desc",
        "print a = 1 | summarize count() by ['a']",
    ] {
        assert_clean(source);
    }
    assert_parse_error("print c = 1 | where ['c' > 0");
    assert_parse_error("print c = 1 | where [c] > 0");
    // A quoted name defines and reads the same column as the plain name.
    assert_eq!(
        output("print n = 2 | project [\"Display Name\"] = tostring(n), ['x'] = n"),
        ["Display Name", "x"]
    );
    assert_eq!(
        output("SigninLogs | project-rename ['User'] = UserPrincipalName | project User"),
        ["User"]
    );
    assert!(
        column_errors("SigninLogs | project ['UserPrincipalName'] | where UserPrincipalName != ''")
            .is_empty()
    );
    assert_eq!(
        column_errors("SigninLogs | project UserPrincipalName | where ['AppId'] == 'x'"),
        ["'AppId' is not a column after `project`"]
    );
    // A near miss of a documented column through a quoted name.
    assert_eq!(
        column_errors("SigninLogs | where ['UserPrincipalNam'] == 'x'").len(),
        1
    );
}

#[test]
fn parse_where_parses_like_parse_and_makes_its_columns() {
    for source in [
        "print P = \"a\" | parse-where P with * \"a\" T",
        r#"print P = "a Identity\",\"Value\":\"bob\" z" | parse-where P with * 'Identity","Value":"' Target '"' *"#,
        "print P = \"a=1\" | parse-where kind=regex P with \"a=\" N:long",
    ] {
        assert_clean(source);
    }
    assert_parse_error("print P = \"a\" | parse-where P * \"a\" T");
    assert_eq!(
        output(
            "Syslog | project SyslogMessage | parse-where SyslogMessage with * 'user=' User:string ' port=' Port:long"
        ),
        ["SyslogMessage", "User", "Port"]
    );
    // The column it parses is checked, and its outputs are known after it.
    assert_eq!(
        column_errors("Syslog | project SyslogMessage | parse-where SyslogMesage with * 'u=' U"),
        ["'SyslogMesage' is not a column after `project`"]
    );
    assert!(column_errors("Syslog | project SyslogMessage | parse-where SyslogMessage with * 'u=' U | where U != ''").is_empty());
}

#[test]
fn distinct_takes_named_expressions_and_star() {
    for source in [
        "print a = \"X\" | distinct b = tolower(a)",
        "print a = \"X\", b = 1 | distinct a, b",
        "print a = \"X\" | distinct *",
        "print a = \"X\" | distinct c = a, ['d'] = strlen(a)",
    ] {
        assert_clean(source);
    }
    assert_parse_error("print a = 1 | distinct b =");
    // A named expression is an output column; the columns it reads are not.
    assert_eq!(
        output("SigninLogs | distinct CallerApp = AppId, IdentityName = UserPrincipalName"),
        ["CallerApp", "IdentityName"]
    );
    assert_eq!(
        column_errors(
            "SigninLogs | distinct CallerApp = AppId, UserPrincipalName | where AppId == 'x'"
        ),
        ["'AppId' is not a column after `distinct`"]
    );
    assert!(
        column_errors("SigninLogs | distinct CallerApp = AppId | where CallerApp == 'x'")
            .is_empty()
    );
    // The expression reads the input's columns.
    assert_eq!(
        column_errors("SigninLogs | distinct A = tolower(AppIdd)").len(),
        1
    );
    // `distinct *` keeps every column.
    assert!(
        column_errors("SigninLogs | project AppId | distinct * | where AppId == 'x'").is_empty()
    );
    // An unnamed computed column gets a generated name: nothing is reported after it.
    assert!(
        column_errors("SigninLogs | distinct tolower(AppId) | where Column1 == 'x'").is_empty()
    );
}

#[test]
fn a_named_argument_to_a_builtin_parses() {
    // #109's open shape: the parser takes `name = value` as any call's
    // argument; whether `tostring` has a parameter `Key` is not syntax.
    assert_clean("print Name = \"a\" | summarize by tostring(Key=Name)");
}
