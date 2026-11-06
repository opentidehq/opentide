//! One test per diagnostic: the finding on the faulty query, and silence on
//! the same query written correctly.

use super::*;

fn codes_of(source: &str) -> Vec<String> {
    analyze(source)
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect()
}

fn codes_in_rule(source: &str) -> Vec<String> {
    analyze_with(source, &Context::CORRELATION_RULE)
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect()
}

#[track_caller]
fn clean(source: &str) {
    let d = analyze(source).diagnostics;
    assert!(d.is_empty(), "{source:?}: {d:#?}");
}

#[track_caller]
fn only(source: &str, code: &str) {
    assert_eq!(codes_of(source), vec![code.to_string()], "{source:?}");
}

#[test]
fn real_detections_are_clean() {
    clean(
        "#event_simpleName=ProcessRollup2 event_platform=Win\n\
         | ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i\n\
         | CommandLine=/-enc(odedcommand)?\\s/i\n\
         | groupBy([aid, ComputerName], function=[count(), collect([CommandLine])], limit=max)",
    );
    clean("#event_simpleName=DnsRequest\n| DomainName=*.onion\n| top(DomainName, limit=10)");
    clean("in(field=\"#event_simpleName\", values=[ProcessRollup2, SyntheticProcessRollup2])");
    clean("ratio := bytes / packets | sort(ratio, order=desc, limit=200)");
    clean("status =~ in(values=[\"500\", \"502\"])");
    clean("case { a=1 | x := \"one\"; a=2 | x := \"two\"; * }");
    clean("kind match { \"a\" => x := 1; /b+/ => x := 2; * => * }");
    clean("ts := formatTime(\"%Y-%m-%d\", field=@timestamp)");
    clean("$falcon/helper:enrich(field=UserIsAdmin)");
    clean("regex(\"(?<user>\\w+)@(?<domain>\\S+)\", field=email)");
    clean("groupby(aid) | selectlast([ComputerName])");
}

#[test]
fn parse_error() {
    only("groupBy(aid", codes::CQL_PARSE_ERROR);
    only("https://", codes::CQL_PARSE_ERROR);
}

#[test]
fn parse_error_names_a_non_breaking_space() {
    let d = analyze("#event_simpleName=ProcessRollup2\u{a0}| count()").diagnostics;
    assert_eq!(d[0].code, codes::CQL_PARSE_ERROR);
    assert!(d[0].message.contains("U+00A0"), "{}", d[0].message);
}

#[test]
fn unknown_function_with_suggestion() {
    let d = analyze("groupBi(aid)").diagnostics;
    assert_eq!(d.len(), 1, "{d:#?}");
    assert_eq!(d[0].code, codes::CQL_UNKNOWN_FUNCTION);
    assert_eq!(d[0].suggestion.as_deref(), Some("groupBy"));
    // Function names are matched without regard to case.
    clean("GroupBy(aid)");
}

#[test]
fn removed_and_deprecated_functions() {
    let d = analyze("rdns(ip)").diagnostics;
    assert_eq!(d[0].code, codes::CQL_REMOVED_FUNCTION);
    assert_eq!(d[0].suggestion.as_deref(), Some("reverseDns"));
    assert!(codes_of("lowercase(field)").contains(&codes::CQL_DEPRECATED_FUNCTION.to_string()));
}

#[test]
fn unknown_parameter() {
    let d = analyze("groupBy(aid, fuction=count())").diagnostics;
    assert_eq!(d.len(), 1, "{d:#?}");
    assert_eq!(d[0].code, codes::CQL_UNKNOWN_PARAMETER);
    assert_eq!(d[0].suggestion.as_deref(), Some("function"));
    // A documented alias: `table` for `file`.
    clean("match(table=\"t\", field=aid)");
}

#[test]
fn unnamed_arguments() {
    only("groupBy(aid, ComputerName)", codes::CQL_UNNAMED_ARGUMENT);
    // `count` has an omittable parameter; `now` has none to take one.
    clean("count(aid)");
    only("eventSize(@rawstring)", codes::CQL_UNNAMED_ARGUMENT);
}

#[test]
fn duplicate_parameter() {
    only("groupBy(aid, field=cid)", codes::CQL_DUPLICATE_PARAMETER);
    only("sort(field=a, field=b)", codes::CQL_DUPLICATE_PARAMETER);
}

#[test]
fn missing_parameter() {
    only("in(values=[a])", codes::CQL_MISSING_PARAMETER);
    // Required in the reference, but with a default: `field=@timestamp`.
    clean("time:dayOfWeek()");
    // The position supplies it: `x =~ f()` gives `field`, `x := f()` gives `as`.
    clean("x =~ in(values=[a])");
    clean("t := formatTime(\"%H\")");
}

#[test]
fn parameter_value() {
    only("sort(x, order=down)", codes::CQL_PARAMETER_VALUE);
    only("head(300000)", codes::CQL_PARAMETER_VALUE);
    clean("head(10)");
    clean("sort(x, order=DESC)");
    clean("groupBy(aid, limit=max)");
}

#[test]
fn assignment_with_as() {
    only("x := count(as=y)", codes::CQL_ASSIGNMENT_AS);
    clean("count(as=y)");
}

#[test]
fn regex_flag() {
    only("CommandLine=/whoami/x", codes::CQL_REGEX_FLAG);
    clean("CommandLine=/whoami/iF");
}

#[test]
fn string_escape() {
    only("x := \"a\\qb\"", codes::CQL_STRING_ESCAPE);
    clean("x := \"a\\\"b\\\\c\\n\\t\"");
}

#[test]
fn free_text_after_aggregate() {
    only("groupBy(aid) | error", codes::CQL_FREE_TEXT_AFTER_AGGREGATE);
    clean("error | groupBy(aid)");
    clean("groupBy(aid) | _count > 5");
}

#[test]
fn link_outside_correlate() {
    only("a <=> b.c", codes::CQL_LINK_OUTSIDE_CORRELATE);
}

#[test]
fn unknown_event() {
    let d = analyze("#event_simpleName=ProcessRollup").diagnostics;
    assert_eq!(d.len(), 1, "{d:#?}");
    assert_eq!(d[0].code, codes::CQL_UNKNOWN_EVENT);
    assert_eq!(d[0].severity, opentide_core::Severity::Warning);
    assert_eq!(d[0].suggestion.as_deref(), Some("ProcessRollup2"));
    // Wildcards and regexes are never judged.
    clean("#event_simpleName=*ProcessRollup*");
    clean("#event_simpleName=/Rollup/");
}

#[test]
fn correlation_rule_correlate_with_aggregate() {
    let query = "correlate(A: { #event_simpleName=UserLogon }, B: { #event_simpleName=ProcessRollup2 | aid <=> A.aid }, within=10m) | groupBy(aid)";
    assert!(
        codes_in_rule(query).contains(&codes::CQL_CORRELATE_AGGREGATE.to_string()),
        "{:?}",
        codes_in_rule(query)
    );
    // Several named subqueries, with attributes, all bind `query`.
    clean("correlate(A: { a=1 } include: [aid], B: { b=1 | aid <=> A.aid }, within=5m)");
    // Plain LogScale allows it; only the correlation rule refuses it.
    assert!(!codes_of(query).contains(&codes::CQL_CORRELATE_AGGREGATE.to_string()));
}

#[test]
fn tokens_mark_builtin_functions() {
    let r = analyze("groupBy(aid) | myFunc(x)");
    let at = |s: &str| {
        let text = "groupBy(aid) | myFunc(x)";
        let i = text.find(s).unwrap();
        r.tokens
            .iter()
            .find(|t| t.span.start == i)
            .map(|t| t.capture.clone())
    };
    assert_eq!(at("groupBy").as_deref(), Some("function.builtin"));
    assert_eq!(at("myFunc").as_deref(), Some("function"));
}

#[test]
fn hover_function_parameter_field_event() {
    let q = "#event_simpleName=ProcessRollup2 | groupBy(aid, limit=max)";
    let h = hover(q, q.find("groupBy").unwrap() + 2).expect("function hover");
    assert!(
        h.contains("groupBy(") && h.contains("library.humio.com"),
        "{h}"
    );
    let h = hover(q, q.find("limit").unwrap() + 1).expect("parameter hover");
    assert!(h.contains("`limit` of `groupBy()`"), "{h}");
    let h = hover(q, 3).expect("tag hover");
    assert!(h.contains("#event_simpleName"), "{h}");
    let h = hover(q, q.find("ProcessRollup2").unwrap() + 2).expect("event hover");
    assert!(h.contains("Falcon sensor event"), "{h}");
}

#[test]
fn completion_contexts() {
    let labels = |q: &str| -> Vec<String> {
        completions(q, q.len())
            .into_iter()
            .map(|i| i.label)
            .collect()
    };
    assert!(labels("#event_simpleName=").contains(&"ProcessRollup2".to_string()));
    let params = labels("groupBy(aid, ");
    assert!(params.contains(&"function".to_string()) && params.contains(&"limit".to_string()));
    assert!(
        !params.contains(&"field".to_string()),
        "field is given: {params:?}"
    );
    assert_eq!(labels("sort(x, order="), vec!["asc", "desc"]);
    assert!(labels("| grou").contains(&"groupBy".to_string()));
}

#[test]
fn signature_help_tracks_the_parameter() {
    let q = "groupBy(aid, limit=";
    let s = signature_help(q, q.len()).expect("signature");
    let active = &s.signatures[0].parameters[s.active_parameter as usize];
    assert_eq!(active.label, "limit");
    let q = "groupBy(";
    let s = signature_help(q, q.len()).expect("signature");
    assert_eq!(
        s.signatures[0].parameters[s.active_parameter as usize].label,
        "field"
    );
    assert!(signature_help("x := 1", 6).is_none());
}

/// A range counts lines from the start of the text, so it is computed only
/// for a finding: 3000 nested calls stay linear.
#[test]
fn deep_nesting_stays_fast() {
    let q = format!(
        "{}count(){}",
        "groupBy(a, function=".repeat(3000),
        ")".repeat(3000)
    );
    let t = std::time::Instant::now();
    let r = analyze(&q);
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    // Debug builds are slow; the quadratic version took seconds even in release.
    assert!(
        t.elapsed() < std::time::Duration::from_secs(2),
        "{:?}",
        t.elapsed()
    );
}
