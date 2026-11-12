//! Google SecOps blocks in Tide objects (google-secops-1.0, yara-l-1.0): the
//! section keys checked as the one rule deploy assembles, the block's
//! constraint codes at their field paths, hunts under the `search` profile,
//! and the spec's fixtures (`testdata/conformance/specifications-google-secops/`).

use opentide_core::{Diagnostic, Severity};
use opentide_tide::{AnalyzeInput, analyze, extract_injections};
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/specifications-google-secops")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn analyse(source: &str) -> Vec<Diagnostic> {
    analyze(AnalyzeInput {
        path: "objects/rules/secops.yaml",
        source,
        workspace: &[],
        elastic_tenants: &[],
    })
    .diagnostics
}

/// The Google SecOps and YARA-L findings: `(code, field path, source text at
/// the range)`.
fn findings(source: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<_> = analyse(source)
        .into_iter()
        .filter(|d| d.code.starts_with("yaral_") || d.code.starts_with("google_secops_"))
        .map(|d| {
            let line = source
                .lines()
                .nth(d.range.start.line as usize)
                .unwrap_or("");
            let start = (d.range.start.character as usize).min(line.len());
            let end = if d.range.end.line == d.range.start.line {
                (d.range.end.character as usize).min(line.len())
            } else {
                line.len()
            };
            let at = line.get(start..end.max(start)).unwrap_or("").to_string();
            (d.code, d.field_path.unwrap_or_default().join("."), at)
        })
        .collect();
    out.sort();
    out
}

fn errors(source: &str) -> Vec<Diagnostic> {
    analyse(source)
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .collect()
}

#[test]
fn valid_fixtures_have_no_error() {
    for name in [
        "google-secops.yaml",
        "rule-google-secops-process-1.0.yaml",
        "rule-google-secops-spray-1.0.yaml",
    ] {
        let source = fixture(name);
        let found: Vec<_> = findings(&source);
        assert!(
            errors(&source)
                .iter()
                .all(|d| !(d.code.starts_with("yaral_") || d.code.starts_with("google_secops_"))),
            "{name}: {found:?}"
        );
    }
}

#[test]
fn invalid_fixtures_report_their_code() {
    for (name, code, path) in [
        (
            "rule-google-secops-section-header.yaml",
            "yaral_section_header",
            "configurations.google_secops.events",
        ),
        (
            "rule-google-secops-condition-comment.yaml",
            "yaral_section_empty",
            "configurations.google_secops.condition",
        ),
        (
            "rule-google-secops-sliding-no-pivot.yaml",
            "yaral_match_shape",
            "configurations.google_secops.match",
        ),
        (
            "rule-google-secops-missing-condition.yaml",
            "yaral_section_missing",
            "configurations.google_secops.condition",
        ),
        (
            "rule-google-secops-hourly.yaml",
            "google_secops_run_frequency",
            "configurations.google_secops.run_frequency",
        ),
        (
            "rule-google-secops-hourly.yaml",
            "google_secops_schedule",
            "configurations.google_secops.schedule",
        ),
        (
            "rule-google-secops-meta-reserved.yaml",
            "google_secops_meta_key",
            "configurations.google_secops.meta.severity",
        ),
    ] {
        let source = fixture(name);
        let found = findings(&source);
        assert!(
            found.iter().any(|(c, p, _)| c == code && p == path),
            "{name}: expected {code} at {path}, got {found:?}"
        );
        // The header comment names the code too.
        assert!(source.contains(code), "{name} does not name {code}");
    }
}

#[test]
fn the_assembled_rule_matches_the_golden_text_line_for_line() {
    // google-secops-1.0 "Assembled rule": line n of a section is line L + n
    // of the rule, four columns to the right.
    for stem in [
        "rule-google-secops-process-1.0",
        "rule-google-secops-spray-1.0",
    ] {
        let source = fixture(&format!("{stem}.yaml"));
        let golden = fixture(&format!("{stem}.yaral"));
        let inj = extract_injections(&source)
            .into_iter()
            .find(|q| q.field_path == ["configurations", "google_secops"])
            .expect("the block is an injection");
        let assembled: Vec<&str> = inj.inner.lines().collect();
        let golden: Vec<&str> = golden.lines().collect();
        let body = |lines: &[&str]| -> Vec<String> {
            let from = lines.iter().position(|l| l.trim() == "events:").unwrap();
            lines[from..].iter().map(|l| l.to_string()).collect()
        };
        assert_eq!(body(&assembled), body(&golden), "{stem}");
        assert_eq!(golden[0], assembled[0], "{stem}: the rule header");
    }
}

#[test]
fn a_finding_in_a_section_lands_on_its_yaml_line_and_column() {
    let source = "name: Login\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  google_secops:\n    enabled: true\n    schema: platform::google_secops::1.0\n    status: STAGING\n    events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n      $e.principal.hostnam = \"web01\"\n    outcome: |\n      $risk_score = 10\n    condition: |\n      $e\n";
    let found = findings(source);
    assert!(
        found.contains(&(
            "yaral_unknown_udm_field".into(),
            "configurations.google_secops.events".into(),
            "hostnam".into()
        )),
        "{found:?}"
    );
}

#[test]
fn match_names_land_on_their_yaml_items() {
    let source = "name: Login\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  google_secops:\n    status: STAGING\n    events: |\n      $a.metadata.event_type = \"USER_LOGIN\"\n      $b.metadata.event_type = \"USER_LOGOUT\"\n      $a.target.user.userid = $user\n      $b.target.user.userid = $user\n    match:\n      group_by: [$user, $host]\n      window: 10m\n    outcome: |\n      $risk_score = max(10)\n    condition: |\n      $a and $b\n";
    let found = findings(source);
    assert!(
        found.contains(&(
            "yaral_match_variable".into(),
            "configurations.google_secops.match.group_by.1".into(),
            "$host".into()
        )),
        "{found:?}"
    );
}

#[test]
fn two_event_variables_without_match_are_reported_on_events() {
    let source = "name: Login\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  google_secops:\n    status: STAGING\n    events: |\n      $a.metadata.event_type = \"USER_LOGIN\"\n      $b.metadata.event_type = \"USER_LOGOUT\"\n    outcome: |\n      $risk_score = 10\n    condition: |\n      $a and $b\n";
    let found = findings(source);
    assert!(
        found.contains(&(
            "yaral_multi_event_match".into(),
            "configurations.google_secops.events".into(),
            "events".into()
        )),
        "{found:?}"
    );
}

#[test]
fn block_codes_follow_the_reference() {
    let base = "name: Login\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  google_secops:\n    status: STAGING\n    events: |\n      $e.metadata.event_type = \"USER_LOGIN\"\n      $u = $e.target.user.userid\n    outcome: |\n      $risk_score = max(10)\n    condition: |\n      #e > 5\n";
    let codes = |extra: &str| -> Vec<String> {
        findings(&format!("{base}{extra}"))
            .into_iter()
            .filter(|(c, ..)| {
                !c.starts_with("yaral_unfiltered") && c != "google_secops_risk_score_missing"
            })
            .map(|(c, ..)| c)
            .collect()
    };
    let window = "    match:\n      group_by: [$u]\n      window: 10m\n";
    assert_eq!(codes(window), Vec::<String>::new());
    assert_eq!(
        codes(&format!("{window}    name: bad-name\n")),
        ["google_secops_rule_name"]
    );
    assert_eq!(
        codes(&format!("{window}    name: match\n")),
        ["google_secops_rule_name"]
    );
    assert_eq!(
        codes(&format!("{window}    severity: Informational\n")),
        ["google_secops_severity"]
    );
    assert_eq!(
        codes(&format!("{window}    priority: urgent\n")),
        ["google_secops_severity"]
    );
    assert_eq!(
        codes(&format!("{window}    run_frequency: HOURLY\n")),
        ["google_secops_run_frequency"]
    );
    assert_eq!(
        codes(&format!(
            "{window}    run_frequency: LIVE\n    schedule:\n      ensure_enrichment_completeness: true\n"
        )),
        ["google_secops_schedule"]
    );
    assert_eq!(
        codes(&format!(
            "{window}    run_frequency: HOURLY_CUSTOMIZABLE\n    schedule:\n      late_arriving_data_adjustment: soon\n"
        )),
        ["google_secops_schedule"]
    );
    for key in ["technique", "opentide_uuid", "not-an-identifier", "or"] {
        assert_eq!(
            codes(&format!("{window}    meta:\n      \"{key}\": x\n")),
            ["google_secops_meta_key"],
            "{key}"
        );
    }
    // google-secops-1.0 1.1: tactic is not derived, so a block may set one.
    assert!(codes(&format!("{window}    meta:\n      tactic: TA0006\n")).is_empty());
    assert_eq!(
        codes("    match:\n      group_by: [$u]\n      window: 15d\n"),
        ["yaral_match_window"]
    );
    assert_eq!(
        codes("    match:\n      group_by: [$u]\n      window: 3d\n"),
        Vec::<String>::new()
    );
    assert_eq!(
        codes("    match:\n      group_by: [$u]\n      window: 4d\n      type: tumbling\n"),
        ["yaral_match_window"]
    );
    assert_eq!(
        codes("    match:\n      group_by: [$u]\n      window: 10s\n"),
        ["yaral_match_window"]
    );
    assert!(
        codes("    match:\n      group_by: []\n      window: 10m\n")
            .contains(&"yaral_match_shape".to_string())
    );
    assert!(
        codes("    match:\n      group_by: [u]\n      window: 10m\n")
            .contains(&"yaral_match_shape".to_string())
    );
    assert!(
        codes("    match:\n      group_by: [$u]\n      window: 10m\n      pivot: $e\n")
            .contains(&"yaral_match_shape".to_string())
    );
    assert_eq!(
        codes(
            "    match:\n      group_by: [$u]\n      window: 10m\n      type: sliding\n      pivot: $e\n      direction: after\n"
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        codes(&format!(
            "{window}    options:\n      allow_zero_values: \"yes\"\n"
        )),
        ["yaral_option"]
    );
    assert_eq!(
        codes(&format!("{window}    options:\n      allow_nulls: true\n")),
        ["yaral_option"]
    );
    assert_eq!(
        codes(&format!(
            "{window}    options:\n      suppression_window: 1 hour\n"
        )),
        ["yaral_option"]
    );
    assert_eq!(
        codes(&format!(
            "{window}    options:\n      suppression_window: 5m\n"
        )),
        ["yaral_option"]
    );
    assert_eq!(
        codes(&format!(
            "{window}    options:\n      suppression_window: 1h\n"
        )),
        Vec::<String>::new()
    );
}

#[test]
fn an_aliased_section_is_reported() {
    let source = "name: Login\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nx-anchor: &events |\n  $e.metadata.event_type = \"USER_LOGIN\"\nconfigurations:\n  google_secops:\n    status: STAGING\n    events: *events\n    condition: |\n      $e\n";
    assert!(
        findings(source)
            .iter()
            .any(|(c, p, _)| c == "yaral_section_alias"
                && p == "configurations.google_secops.events"),
        "{:?}",
        findings(source)
    );
}

#[test]
fn advisories_are_warnings() {
    let source = "name: Composite\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  google_secops:\n    status: STAGING\n    run_frequency: LIVE\n    events: |\n      $d.detection.detection.rule_id = \"ru_e0d3f371-6832-4d20-b0ad-1f4e234acb2b\"\n      $e.metadata.event_type = \"USER_LOGIN\"\n      $d.detection.detection.variables[\"user\"].string_val = $u\n      $e.target.user.userid = $u\n    match:\n      group_by: [$u]\n      window: 1h\n    condition: |\n      $d and $e\n";
    let found = analyse(source);
    for code in [
        "google_secops_risk_score_missing",
        "google_secops_rule_id_literal",
        "google_secops_live_frequency_unavailable",
    ] {
        let d = found
            .iter()
            .find(|d| d.code == code)
            .unwrap_or_else(|| panic!("{code}: {found:?}"));
        assert_eq!(d.severity, Severity::Warning, "{code}");
    }
    assert!(
        !found.iter().any(|d| d.severity == Severity::Error
            && (d.code.starts_with("yaral_") || d.code.starts_with("google_secops_"))),
        "{found:?}"
    );
}

#[test]
fn a_hunt_is_a_search() {
    let source = fixture("rule-google-secops-spray-1.0.yaml");
    let hunt = extract_injections(&source)
        .into_iter()
        .find(|q| q.field_path.first().map(String::as_str) == Some("response"))
        .expect("the hunt is an injection");
    assert_eq!(hunt.platform, "google_secops");
    // A rule section in a hunt is not part of a search.
    let broken = source.replace(
        "          order:\n",
        "          options:\n            allow_zero_values = true\n          order:\n",
    );
    assert!(
        findings(&broken)
            .iter()
            .any(|(c, p, _)| c == "yaral_section_unavailable"
                && p == "response.procedure.searches.0.query"),
        "{:?}",
        findings(&broken)
    );
}

#[test]
fn the_block_is_highlighted_as_yaral_and_yaml() {
    let source = fixture("rule-google-secops-spray-1.0.yaml");
    let tokens = analyze(AnalyzeInput {
        path: "objects/rules/secops.yaml",
        source: &source,
        workspace: &[],
        elastic_tenants: &[],
    })
    .tokens;
    let capture = |text: &str| {
        let start = source.find(text).unwrap();
        tokens
            .iter()
            .find(|t| t.span.start == start)
            .map(|t| t.capture.clone())
    };
    assert_eq!(capture("$fail.metadata").as_deref(), Some("variable"));
    assert_eq!(
        capture("count_distinct").as_deref(),
        Some("function.builtin")
    );
    assert_eq!(
        capture("\"USER_LOGIN\"\n      $fail.security").as_deref(),
        Some("string")
    );
}
