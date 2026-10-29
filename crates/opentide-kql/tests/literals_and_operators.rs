//! Typed scalar literals, legacy `contains` spellings, `externaldata`, tabular
//! function parameters, function calls as `union` legs, and the tabular
//! operators with their own syntax (opentidehq/language-server#125).

use opentide_core::{Diagnostic, Severity, codes};
use opentide_kql::{Hir, Profile, analyze, lower};

fn diagnostics(source: &str) -> Vec<Diagnostic> {
    analyze(source, Profile::Sentinel).diagnostics
}

fn errors(source: &str) -> Vec<(String, String)> {
    diagnostics(source)
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| (d.code, d.message))
        .collect()
}

fn assert_clean(source: &str) {
    let errors = errors(source);
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

#[test]
fn typed_scalar_literals_are_literals_not_calls() {
    for source in [
        "print x = datetime(2024-01-01)",
        "print x = datetime(2024-01-01 10:00:00)",
        "print x = datetime(2024-01-01T10:00:00Z)",
        "print x = date(2024-01-01)",
        "print x = timespan(1d), y = time(0s), z = timespan(0.12:34:56.7)",
        "print x = bool(true), y = int(1), z = long(-1), w = int64(2), v = int32(3)",
        "print x = real(1.5), y = double(0), z = decimal(1.5)",
        "print x = guid(00000000-0000-0000-0000-000000000000)",
        "print d = 1h | where d between (time(0s) .. 2h)",
        "print x = 1 | extend p = double(0), q = double(0)",
    ] {
        assert_clean(source);
        assert!(
            !diagnostics(source)
                .iter()
                .any(|d| d.code == codes::KQL_UNKNOWN_FUNCTION),
            "{source}"
        );
    }
}

#[test]
fn typed_null_literals_parse() {
    for ty in [
        "bool", "datetime", "decimal", "guid", "int", "long", "real", "double", "timespan",
    ] {
        assert_clean(&format!("print x = {ty}(null)"));
    }
}

#[test]
fn typed_literal_needs_its_closing_paren_on_the_line() {
    assert_parse_error("print x = datetime(2024-01-01");
    // Kusto.Language scans a literal's value to the end of the line, and needs
    // the `(` right after the type name.
    assert_parse_error("print x = datetime(2024-01-01\n)");
    assert_parse_error("print x = datetime (2024-01-01)");
}

#[test]
fn names_that_start_like_a_type_stay_calls_and_columns() {
    assert_clean(
        "print x = 1 | extend t = todatetime(\"2024-01-01\"), d = datetime_diff(\"day\", now(), now()), i = toint(\"1\")",
    );
    assert_clean("print timeout = 1, dates = 2, interval = 3 | where timeout > 0 and dates > 0");
    // `range` is also an operator keyword; the function still parses.
    assert_clean("let r = range(1, 5, 1);\nprint r");
}

#[test]
fn string_is_not_a_typed_literal() {
    // Kusto.Language lexes `type(...)` as a literal only for bool, date, datetime,
    // decimal, double, guid, int, int32, int64, long, real, time and timespan;
    // the string type has no null (docs/kql/types.md).
    let tree = lower("print x = string(null)");
    assert!(matches!(tree, Hir::Query { .. }));
    assert!(
        diagnostics("print x = string(null)")
            .iter()
            .any(|d| d.code == codes::KQL_UNKNOWN_FUNCTION)
    );
}

#[test]
fn legacy_contains_spellings_parse_and_suggest_the_current_name() {
    for (source, legacy, current) in [
        (
            "print h = \"Mozilla\" | where h containscs \"M\"",
            "containscs",
            "contains_cs",
        ),
        (
            "print h = \"Mozilla\" | where h notcontainscs \"x\"",
            "notcontainscs",
            "!contains_cs",
        ),
        (
            "print h = \"Mozilla\" | where h notcontains \"x\"",
            "notcontains",
            "!contains",
        ),
    ] {
        assert_clean(source);
        let found = diagnostics(source)
            .into_iter()
            .find(|d| d.code == codes::KQL_DEPRECATED_OPERATOR)
            .unwrap_or_else(|| panic!("{source}: no {}", codes::KQL_DEPRECATED_OPERATOR));
        assert_eq!(found.severity, Severity::Warning);
        assert_eq!(found.suggestion.as_deref(), Some(current));
        assert!(found.message.contains(legacy), "{}", found.message);
    }
    assert!(
        !diagnostics("print h = \"M\" | where h contains_cs \"M\"")
            .iter()
            .any(|d| d.code == codes::KQL_DEPRECATED_OPERATOR)
    );
}

#[test]
fn bang_containscs_is_not_an_operator() {
    // Kusto.Language has `!contains_cs` and `notcontainscs`, not `!containscs`.
    assert_parse_error("print h = \"Mozilla\" | where h !containscs \"M\"");
}

#[test]
fn externaldata_is_a_tabular_expression() {
    for source in [
        "let a = externaldata(c:string, v:dynamic) [\"https://example.com/x.json\"] with(format=\"multijson\");\na",
        "externaldata(c:string) [@\"https://example.com/x.csv\"] with (format=\"csv\") | take 1",
        "externaldata(c:string) [\"https://example.com/a.csv\", \"https://example.com/b.csv\",] | take 1",
        "print x = \"a\" | where x !in ((externaldata(c:string) [@\"https://e/x.csv\"] with (format=\"csv\")))",
        "print x = \"a\" | where x in (externaldata(c:string) [@\"https://e/x.csv\"] with (format=\"csv\") | project c)",
        "let k = (externaldata(id:string, name:string)[@\"https://e/x.csv\"] with (format=\"csv\", ignoreFirstRecord=true)\n| project id);\nk",
    ] {
        assert_clean(source);
    }
}

#[test]
fn externaldata_needs_a_uri_list() {
    assert_parse_error("externaldata(c:string) with (format=\"csv\") | take 1");
    assert_parse_error("externaldata(c:string) | take 1");
}

#[test]
fn tabular_parameter_is_a_table_inside_the_body() {
    assert_clean("let f = (T:(x:string)) { T | where x == \"a\" };\nf(SigninLogs)");
    assert_clean("let f = (T:(*), n:long) { T | where n > 0 };\nf(SigninLogs, 1)");
    // Only inside its own body.
    assert!(
        errors("let f = (T:(x:string)) { T | where x == \"a\" };\nT | take 1")
            .iter()
            .any(|(code, message)| code == codes::KQL_UNKNOWN_TABLE && message.contains("'T'"))
    );
    // A scalar parameter is not a table.
    assert!(
        errors("let f = (T:string) { T | take 1 };\nf(\"a\")")
            .iter()
            .any(|(code, _)| code == codes::KQL_UNKNOWN_TABLE)
    );
}

#[test]
fn union_legs_may_be_function_calls() {
    assert_clean("let g = (t:string) { print t };\nunion isfuzzy=true g(\"a\"), g(\"b\")");
    assert_clean(
        "let g = (T:(*)) { T | take 1 };\nunion g(SigninLogs), (SigninLogs | take 1), AuditLogs",
    );
}

#[test]
fn operators_with_their_own_syntax_parse() {
    for source in [
        "range x from 1 to 3 step 1",
        "range Day from ago(7d) to now() step 1d | take 1",
        "print x = 1, y = 2 | project-reorder y asc, x",
        "print x = 1, y = 2 | project-reorder y desc, x granny-asc",
        "SigninLogs | top-nested 3 of UserPrincipalName by count()",
        "SigninLogs | top-nested 3 of UserPrincipalName with others = \"other\" by c = count() desc, top-nested of AppDisplayName by count()",
        "SigninLogs | fork (take 1) (take 2)",
        "SigninLogs | fork a = (where ResultType == 0 | take 5) b = (count)",
        "SigninLogs | facet by UserPrincipalName",
        "SigninLogs | facet by UserPrincipalName, AppDisplayName with (where ResultType == 0 | take 5)",
        "SigninLogs | facet by UserPrincipalName with take 5",
        "SigninLogs | sample-distinct 1 of UserPrincipalName",
        "range x from 1 to 3 step 1 | scan with (step s: x == 1;)",
        "range x from 1 to 5 step 1 | scan declare (c: long = 0) with (step s1 output=last: true => c = x + s1.c; step s2 optional: x > 2;)",
        "range x from 1 to 5 step 1 | scan with_match_id=m order by x partition by x with (step s: x == 1;)",
        "SigninLogs | partition by UserPrincipalName (take 1)",
        "SigninLogs | partition hint.strategy=native by UserPrincipalName (top 1 by TimeGenerated desc)",
    ] {
        assert_clean(source);
    }
}

#[test]
fn operator_hir_names_match_the_keywords() {
    let Hir::Query { operators, .. } = lower(
        "SigninLogs | top-nested 3 of UserPrincipalName by count() | sample-distinct 1 of UserPrincipalName | fork (take 1)",
    ) else {
        panic!("no query");
    };
    let names: Vec<&str> = operators.iter().map(|op| op.name.as_str()).collect();
    for name in ["top-nested", "sample-distinct", "fork", "take"] {
        assert!(names.contains(&name), "{names:?}");
    }
}

#[test]
fn malformed_operators_still_fail() {
    for source in [
        "range x from 1 to 3",
        "SigninLogs | fork",
        "SigninLogs | facet UserPrincipalName",
        "SigninLogs | sample-distinct 1",
        "SigninLogs | scan with (step s: true)",
        "SigninLogs | partition by UserPrincipalName",
        "SigninLogs | top-nested 3 by count()",
    ] {
        assert_parse_error(source);
    }
}
