//! Every engine code of yara-l-1.0 "Diagnostics", with the shortest text that
//! raises it and its clean neighbour. The YAML-only codes of a Google SecOps
//! block (`yaral_section_header`, `yaral_section_empty`,
//! `yaral_section_alias`, `yaral_match_shape`) are in
//! `crates/opentide-tide/tests/google_secops.rs`. `docs/YARAL.md` maps each
//! code to Google's page and to its test here.

use opentide_core::{Severity, codes};
use opentide_yaral::{Context, analyze, analyze_with};

fn codes_of(text: &str) -> Vec<String> {
    analyze(text)
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect()
}

fn search_codes(text: &str) -> Vec<String> {
    analyze_with(text, &Context::SEARCH)
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect()
}

/// A rule with `events`, then `rest` (sections after events), the meta
/// given. Clean when `events` is.
fn rule(events: &str, rest: &str) -> String {
    format!("rule r {{\n  meta:\n    author = \"a\"\n  events:\n{events}\n{rest}}}\n")
}

const EVENTS: &str = "    $e.metadata.event_type = \"USER_LOGIN\"\n    $u = $e.target.user.userid";
const CONDITION: &str = "  condition:\n    $e\n";
const MATCHED: &str = "  match:\n    $u over 10m\n";

fn has(found: &[String], code: &str) -> bool {
    found.iter().any(|c| c == code)
}

fn assert_code(text: &str, code: &str) {
    let found = codes_of(text);
    assert!(
        has(&found, code),
        "expected {code} in {found:?} for\n{text}"
    );
}

fn assert_clean(text: &str) {
    let found = analyze(text).diagnostics;
    assert!(
        found.iter().all(|d| d.severity != Severity::Error),
        "{:?}\n{text}",
        found
            .iter()
            .map(|d| (&d.code, &d.message))
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_base_rule_is_clean() {
    assert_clean(&rule(EVENTS, CONDITION));
    assert!(codes_of(&rule(EVENTS, CONDITION)).is_empty());
}

#[test]
fn parse_error() {
    assert_code(
        &rule("    $e.metadata.event_type = ", CONDITION),
        codes::YARAL_PARSE_ERROR,
    );
    let two = format!("{}{}", rule(EVENTS, CONDITION), rule(EVENTS, CONDITION));
    assert_code(&two, codes::YARAL_PARSE_ERROR);
}

#[test]
fn section_missing() {
    assert_code(
        "rule r {\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}\n",
        codes::YARAL_SECTION_MISSING,
    );
    assert_code(&rule(EVENTS, ""), codes::YARAL_SECTION_MISSING);
    // The block form has no meta: deploy writes it.
    let found = analyze_with(
        "rule r {\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}\n",
        &Context::SECTIONS,
    )
    .diagnostics;
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn section_order() {
    let text = "rule r {\n  meta:\n    author = \"a\"\n  condition:\n    $e\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n}\n";
    assert_code(text, codes::YARAL_SECTION_ORDER);
    // `export` is the last section.
    let text = rule(
        EVENTS,
        "  outcome:\n    $user = $u\n  condition:\n    $e\n  export:\n    %t.write_row(user: $user)\n  options:\n    allow_zero_values = true\n",
    );
    assert_code(&text, codes::YARAL_SECTION_ORDER);
    assert_code(
        &rule(EVENTS, "  condition:\n    $e\n  condition:\n    $e\n"),
        codes::YARAL_SECTION_ORDER,
    );
}

#[test]
fn section_unavailable() {
    assert_code(
        &rule(EVENTS, &format!("{CONDITION}  limit:\n    10\n")),
        codes::YARAL_SECTION_UNAVAILABLE,
    );
    let search = "metadata.event_type = \"USER_LOGIN\"\noptions:\n  allow_zero_values = true\n";
    assert!(has(&search_codes(search), codes::YARAL_SECTION_UNAVAILABLE));
    assert!(search_codes("metadata.event_type = \"USER_LOGIN\"\nlimit:\n  10\n").is_empty());
}

#[test]
fn meta_duplicate() {
    let twice = "rule r {\n  meta:\n    author = \"a\"\n    author = \"b\"\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}\n";
    assert_code(twice, codes::YARAL_META_DUPLICATE);
    let number = "rule r {\n  meta:\n    version = 3\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}\n";
    assert_code(number, codes::YARAL_META_DUPLICATE);
}

#[test]
fn reserved_identifier() {
    assert_code(
        &rule(
            "    $e.metadata.event_type = \"USER_LOGIN\"\n    $window_start = $e.metadata.id",
            CONDITION,
        ),
        codes::YARAL_RESERVED_IDENTIFIER,
    );
    assert_code(
        &rule(
            "    $e.metadata.event_type = \"USER_LOGIN\"\n    $match = $e.metadata.id",
            CONDITION,
        ),
        codes::YARAL_RESERVED_IDENTIFIER,
    );
}

#[test]
fn undefined_variable() {
    assert_code(
        &rule(
            EVENTS,
            "  outcome:\n    $x = $nowhere\n  condition:\n    $e\n",
        ),
        codes::YARAL_UNDEFINED_VARIABLE,
    );
    assert_code(
        &rule(EVENTS, "  condition:\n    $e and $nowhere\n"),
        codes::YARAL_UNDEFINED_VARIABLE,
    );
    // An event variable of `events` must appear in `condition`, or a
    // placeholder assigned from it must.
    let two = "    $e.metadata.event_type = \"USER_LOGIN\"\n    $f.metadata.event_type = \"USER_LOGOUT\"\n    $e.target.user.userid = $u\n    $f.target.user.userid = $u";
    assert_code(
        &rule(two, &format!("{MATCHED}  condition:\n    $e\n")),
        codes::YARAL_UNDEFINED_VARIABLE,
    );
    assert_clean(&rule(
        EVENTS,
        &format!("{MATCHED}  condition:\n    #u > 2\n"),
    ));
}

#[test]
fn multi_event_match() {
    let two = "    $e.metadata.event_type = \"USER_LOGIN\"\n    $f.metadata.event_type = \"USER_LOGOUT\"\n    $e.target.user.userid = $u\n    $f.target.user.userid = $u";
    assert_code(
        &rule(two, "  condition:\n    $e and $f\n"),
        codes::YARAL_MULTI_EVENT_MATCH,
    );
    assert_clean(&rule(
        two,
        &format!("{MATCHED}  condition:\n    $e and $f\n"),
    ));
}

#[test]
fn match_variable() {
    assert_code(
        &rule(EVENTS, "  match:\n    $e over 10m\n  condition:\n    $e\n"),
        codes::YARAL_MATCH_VARIABLE,
    );
    assert_code(
        &rule(
            EVENTS,
            "  match:\n    $nobody over 10m\n  condition:\n    $e\n",
        ),
        codes::YARAL_MATCH_VARIABLE,
    );
}

#[test]
fn match_window() {
    for window in ["$u over 15d", "$u by 4d", "$u over 10s", "$u over 0m"] {
        assert_code(
            &rule(EVENTS, &format!("  match:\n    {window}\n{CONDITION}")),
            codes::YARAL_MATCH_WINDOW,
        );
    }
    for window in [
        "$u over 14d",
        "$u by 72h",
        "$u over 1m",
        "$u over 5m after $e",
    ] {
        assert_clean(&rule(
            EVENTS,
            &format!("  match:\n    {window}\n{CONDITION}"),
        ));
    }
    // A search's hop window is at most 48 hours.
    let search =
        "metadata.event_type = \"USER_LOGIN\"\n$u = target.user.userid\nmatch:\n  $u over 3d\n";
    assert!(has(&search_codes(search), codes::YARAL_MATCH_WINDOW));
    let search =
        "metadata.event_type = \"USER_LOGIN\"\n$u = target.user.userid\nmatch:\n  $u over 2d\n";
    assert!(!has(&search_codes(search), codes::YARAL_MATCH_WINDOW));
}

#[test]
fn condition_shape() {
    assert_code(
        &rule(EVENTS, &format!("{MATCHED}  condition:\n    not $e\n")),
        codes::YARAL_CONDITION_SHAPE,
    );
    assert_code(
        &rule(EVENTS, "  condition:\n    $e, $e\n"),
        codes::YARAL_CONDITION_SHAPE,
    );
    let three = "    $a.metadata.event_type = \"USER_LOGIN\"\n    $b.metadata.event_type = \"USER_LOGOUT\"\n    $c.metadata.event_type = \"PROCESS_LAUNCH\"\n    $a.principal.hostname = $h\n    $b.principal.hostname = $h\n    $c.principal.hostname = $h";
    assert_code(
        &rule(
            three,
            "  match:\n    $h over 10m\n  condition:\n    $a or $b or $c\n",
        ),
        codes::YARAL_CONDITION_SHAPE,
    );
    let two = "    $e.metadata.event_type = \"USER_LOGIN\"\n    $f.metadata.event_type = \"USER_LOGOUT\"\n    $e.target.user.userid = $u\n    $f.target.user.userid = $u";
    // Non-existence needs a window and a bounded event.
    assert_code(
        &rule(two, &format!("{MATCHED}  condition:\n    !$e and !$f\n")),
        codes::YARAL_CONDITION_SHAPE,
    );
    assert_clean(&rule(
        two,
        &format!("{MATCHED}  condition:\n    $e and !$f\n"),
    ));
    // `or` refused with an unbounded term.
    assert_code(
        &rule(two, &format!("{MATCHED}  condition:\n    $e or !$f\n")),
        codes::YARAL_CONDITION_SHAPE,
    );
    // An `or` group among event terms needs its parentheses.
    let outcome = "  outcome:\n    $n = count($e.metadata.id)\n";
    assert_code(
        &rule(
            two,
            &format!("{MATCHED}{outcome}  condition:\n    $e or $f and $n > 2\n"),
        ),
        codes::YARAL_CONDITION_SHAPE,
    );
    assert_clean(&rule(
        two,
        &format!("{MATCHED}{outcome}  condition:\n    ($e or $f) and $n > 2\n"),
    ));
}

#[test]
fn nocase_on_enum() {
    assert_code(
        &rule(
            "    $e.metadata.event_type = \"USER_LOGIN\" nocase",
            CONDITION,
        ),
        codes::YARAL_NOCASE_ON_ENUM,
    );
}

#[test]
fn nesting_depth() {
    let mut call = "$e.principal.hostname".to_string();
    for _ in 0..21 {
        call = format!("strings.to_lower({call})");
    }
    assert_code(
        &rule(&format!("{EVENTS}\n    {call} = \"x\""), CONDITION),
        codes::YARAL_NESTING_DEPTH,
    );
}

#[test]
fn outcome_limit() {
    let outcome: String = (0..21).map(|i| format!("    $o{i} = {i}\n")).collect();
    assert_code(
        &rule(EVENTS, &format!("  outcome:\n{outcome}{CONDITION}")),
        codes::YARAL_OUTCOME_LIMIT,
    );
    let outcome: String = (0..20).map(|i| format!("    $o{i} = {i}\n")).collect();
    assert_clean(&rule(EVENTS, &format!("  outcome:\n{outcome}{CONDITION}")));
}

#[test]
fn outcome_aggregation() {
    assert_code(
        &rule(
            EVENTS,
            &format!("{MATCHED}  outcome:\n    $host = $e.principal.hostname\n{CONDITION}"),
        ),
        codes::YARAL_OUTCOME_AGGREGATION,
    );
    assert_code(
        &rule(
            EVENTS,
            &format!(
                "{MATCHED}  outcome:\n    $n = count($e.metadata.id)\n    $m = max($n)\n{CONDITION}"
            ),
        ),
        codes::YARAL_OUTCOME_AGGREGATION,
    );
    assert_clean(&rule(
        EVENTS,
        &format!(
            "{MATCHED}  outcome:\n    $hosts = array_distinct($e.principal.hostname)\n    $u2 = $u\n{CONDITION}"
        ),
    ));
    // Without `match`, a single-event rule reads fields as they are.
    assert_clean(&rule(
        EVENTS,
        &format!("  outcome:\n    $host = $e.principal.hostname\n{CONDITION}"),
    ));
}

#[test]
fn unknown_function() {
    assert_code(
        &rule(
            &format!("{EVENTS}\n    strings.lowercase($e.principal.hostname) = \"x\""),
            CONDITION,
        ),
        codes::YARAL_UNKNOWN_FUNCTION,
    );
    assert_code(
        &rule(
            &format!("{EVENTS}\n    strings.to_lower($e.principal.hostname, 1) = \"x\""),
            CONDITION,
        ),
        codes::YARAL_UNKNOWN_FUNCTION,
    );
    assert_code(
        &rule(&format!("{EVENTS}\n    nonsense.f(1) = \"x\""), CONDITION),
        codes::YARAL_UNKNOWN_FUNCTION,
    );
}

#[test]
fn function_unavailable() {
    // math.round and group are search functions.
    assert_code(
        &rule(
            &format!("{EVENTS}\n    math.round($e.network.sent_bytes, 2) > 1"),
            CONDITION,
        ),
        codes::YARAL_FUNCTION_UNAVAILABLE,
    );
    // avg is a search aggregation; a rule writes window.avg.
    assert_code(
        &rule(
            EVENTS,
            &format!("{MATCHED}  outcome:\n    $a = avg($e.network.sent_bytes)\n{CONDITION}"),
        ),
        codes::YARAL_FUNCTION_UNAVAILABLE,
    );
    assert_clean(&rule(
        EVENTS,
        &format!("{MATCHED}  outcome:\n    $a = window.avg($e.network.sent_bytes)\n{CONDITION}"),
    ));
    // window.avg is a rule function.
    let search = "metadata.event_type = \"USER_LOGIN\"\n$u = target.user.userid\nmatch:\n  $u\noutcome:\n  $a = window.avg(network.sent_bytes)\n";
    assert!(has(
        &search_codes(search),
        codes::YARAL_FUNCTION_UNAVAILABLE
    ));
}

#[test]
fn unknown_udm_field() {
    assert_code(
        &rule(
            &format!("{EVENTS}\n    $e.principal.hostnam = \"x\""),
            CONDITION,
        ),
        codes::YARAL_UNKNOWN_UDM_FIELD,
    );
    // Under a map key, keys are free; data tables and lists are the tenant's.
    assert_clean(&rule(
        &format!(
            "{EVENTS}\n    $e.additional.fields[\"anything\"] = \"x\"\n    $e.principal.hostname in %hosts.name\n    $e.principal.ip in cidr %ranges"
        ),
        CONDITION,
    ));
    // The entity graph and detections.
    assert_clean(&rule(
        "    $g.graph.metadata.entity_type = \"ASSET\"\n    $g.graph.entity.hostname = \"x\"",
        "  condition:\n    $g\n",
    ));
    assert_clean(&rule(
        "    $d.detection.detection.rule_name = \"Producer\"\n    $d.detection.detection.variables[\"user\"].string_val = \"x\"",
        "  condition:\n    $d\n",
    ));
}

#[test]
fn enum_value() {
    assert_code(
        &rule("    $e.metadata.event_type = \"PROCESS_LAUCH\"", CONDITION),
        codes::YARAL_ENUM_VALUE,
    );
    assert_clean(&rule(
        "    $e.metadata.event_type = \"PROCESS_LAUNCH\"",
        CONDITION,
    ));
}

#[test]
fn type_mismatch() {
    assert_code(
        &rule(EVENTS, &format!("{MATCHED}  condition:\n    #e > \"5\"\n")),
        codes::YARAL_TYPE,
    );
    assert_code(
        &rule(
            &format!("{EVENTS}\n    any $e.metadata.ingestion_labels[\"k\"] = \"x\""),
            CONDITION,
        ),
        codes::YARAL_TYPE,
    );
    assert_code(
        &rule(
            &format!("{EVENTS}\n    $e.target.port = 22 nocase"),
            CONDITION,
        ),
        codes::YARAL_TYPE,
    );
}

#[test]
fn regex() {
    assert_code(
        &rule(
            &format!("{EVENTS}\n    $e.principal.hostname = /web(/"),
            CONDITION,
        ),
        codes::YARAL_REGEX,
    );
    assert_code(
        &rule(
            &format!("{EVENTS}\n    re.regex($e.principal.hostname, `(?=x)`)"),
            CONDITION,
        ),
        codes::YARAL_REGEX,
    );
    assert_clean(&rule(
        &format!("{EVENTS}\n    $e.principal.hostname = /^web\\d{{2}}$/ nocase"),
        CONDITION,
    ));
}

#[test]
fn string_escape() {
    assert_code(
        &rule(
            &format!("{EVENTS}\n    $e.principal.hostname = \"web\\d\""),
            CONDITION,
        ),
        codes::YARAL_STRING_ESCAPE,
    );
    assert_clean(&rule(
        &format!("{EVENTS}\n    $e.principal.hostname = \"a\\\\b\\\"c\\n\""),
        CONDITION,
    ));
}

#[test]
fn reference_list_limit() {
    let lists: String = (0..11)
        .map(|i| format!("\n    $e.principal.hostname in %t{i}.c"))
        .collect();
    assert_code(
        &rule(&format!("{EVENTS}{lists}"), CONDITION),
        codes::YARAL_REFERENCE_LIST_LIMIT,
    );
    let lists: String = (0..6)
        .map(|i| format!("\n    $e.principal.ip in cidr %t{i}"))
        .collect();
    assert_code(
        &rule(&format!("{EVENTS}{lists}"), CONDITION),
        codes::YARAL_REFERENCE_LIST_LIMIT,
    );
    // A search allows 2 cidr lists.
    let search = "metadata.event_type = \"USER_LOGIN\"\nprincipal.ip in cidr %a\nprincipal.ip in cidr %b\nprincipal.ip in cidr %c\n";
    assert!(has(
        &search_codes(search),
        codes::YARAL_REFERENCE_LIST_LIMIT
    ));
}

#[test]
fn option() {
    assert_code(
        &rule(
            EVENTS,
            &format!("{CONDITION}  options:\n    allow_nulls = true\n"),
        ),
        codes::YARAL_OPTION,
    );
    assert_code(
        &rule(
            EVENTS,
            &format!("{CONDITION}  options:\n    allow_zero_values = 1\n"),
        ),
        codes::YARAL_OPTION,
    );
    assert_code(
        &rule(
            EVENTS,
            &format!("{MATCHED}{CONDITION}  options:\n    suppression_window = 5m\n"),
        ),
        codes::YARAL_OPTION,
    );
    assert_clean(&rule(
        EVENTS,
        &format!(
            "{MATCHED}{CONDITION}  options:\n    allow_zero_values = true\n    suppression_window = 1h\n"
        ),
    ));
}

fn warnings(text: &str) -> Vec<String> {
    analyze(text)
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.code)
        .collect()
}

#[test]
fn deprecated_field() {
    let text = rule(
        &format!("{EVENTS}\n    $e.principal.resource.type = \"x\""),
        CONDITION,
    );
    assert!(warnings(&text).contains(&codes::YARAL_DEPRECATED_FIELD.to_string()));
    assert_clean(&text);
}

#[test]
fn unfiltered_event() {
    let text = rule("    $e.principal.hostname = \"web01\"", CONDITION);
    assert!(warnings(&text).contains(&codes::YARAL_UNFILTERED_EVENT.to_string()));
    assert!(warnings(&rule(EVENTS, CONDITION)).is_empty());
}

#[test]
fn leading_wildcard_regex() {
    let text = rule(
        &format!("{EVENTS}\n    $e.principal.hostname = /.*web/"),
        CONDITION,
    );
    assert!(warnings(&text).contains(&codes::YARAL_LEADING_WILDCARD_REGEX.to_string()));
}

#[test]
fn reference_list_deprecated() {
    let text = rule(
        &format!("{EVENTS}\n    $e.principal.hostname in %hosts"),
        CONDITION,
    );
    assert!(warnings(&text).contains(&codes::YARAL_REFERENCE_LIST_DEPRECATED.to_string()));
    let table = rule(
        &format!("{EVENTS}\n    $e.principal.hostname in %hosts.name"),
        CONDITION,
    );
    assert!(!warnings(&table).contains(&codes::YARAL_REFERENCE_LIST_DEPRECATED.to_string()));
}

#[test]
fn search_profile_basics() {
    let hunt = "metadata.event_type = \"USER_LOGIN\"\nsecurity_result.action = \"BLOCK\"\n$user = target.user.userid\n$ip = principal.ip\nmatch:\n  $user, $ip\noutcome:\n  $attempts = count(metadata.id)\norder:\n  $attempts desc\nlimit:\n  50\n";
    assert!(search_codes(hunt).is_empty(), "{:?}", search_codes(hunt));
    let stages = "stage daily {\n  metadata.event_type = \"NETWORK_CONNECTION\"\n  $host = principal.hostname\n  match:\n    $host by 1h\n  outcome:\n    $bytes = sum(network.sent_bytes)\n}\n$host = $daily.host\nmatch:\n  $host\noutcome:\n  $m = max($daily.bytes)\n";
    assert!(
        search_codes(stages).is_empty(),
        "{:?}",
        search_codes(stages)
    );
}

#[test]
fn every_spec_code_is_registered() {
    let spec = [
        "yaral_parse_error",
        "yaral_section_header",
        "yaral_section_empty",
        "yaral_section_alias",
        "yaral_section_missing",
        "yaral_section_order",
        "yaral_section_unavailable",
        "yaral_meta_duplicate",
        "yaral_reserved_identifier",
        "yaral_undefined_variable",
        "yaral_multi_event_match",
        "yaral_match_shape",
        "yaral_match_variable",
        "yaral_match_window",
        "yaral_condition_shape",
        "yaral_nocase_on_enum",
        "yaral_nesting_depth",
        "yaral_outcome_limit",
        "yaral_outcome_aggregation",
        "yaral_unknown_function",
        "yaral_function_unavailable",
        "yaral_unknown_udm_field",
        "yaral_enum_value",
        "yaral_type",
        "yaral_regex",
        "yaral_string_escape",
        "yaral_reference_list_limit",
        "yaral_option",
        "yaral_deprecated_field",
        "yaral_unfiltered_event",
        "yaral_leading_wildcard_regex",
        "yaral_reference_list_deprecated",
    ];
    assert_eq!(spec.len(), 32);
    for code in spec {
        assert!(codes::ALL.contains(&code), "{code}");
        assert!(codes::describe(code).is_some(), "{code}");
    }
}

#[test]
fn the_spec_goldens_are_clean() {
    for stem in [
        "rule-google-secops-process-1.0",
        "rule-google-secops-spray-1.0",
    ] {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/conformance/specifications-google-secops")
            .join(format!("{stem}.yaral"));
        let text = std::fs::read_to_string(path).unwrap();
        let found = analyze(&text).diagnostics;
        assert!(found.is_empty(), "{stem}: {found:?}");
    }
}
