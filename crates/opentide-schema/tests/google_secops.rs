//! The Google SecOps block (platform-google-secops rev 1.2) on the
//! repository's fixtures, from 0.28.0's `tests/fixtures/google_secops`: every
//! valid block converts, each invalid one reports the codes its header names
//! at their paths, and the assembled text of each rule equals its `.yaral`
//! fixture byte for byte (the text is the rule Google stores).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test]: a fixture that cannot be read fails the test"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use opentide_schema::FromNode;
use opentide_schema::from_node::Context;
use opentide_schema::node::{self, Node, Value};
use opentide_schema::objects::platform::google_secops::assemble::{RuleFacts, assemble};
use opentide_schema::objects::platform::google_secops::{
    GoogleSecopsConfig, RunFrequency, Severity, block_codes,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/google_secops")
}

fn yaml_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    files.sort();
    files
}

fn load_rule(path: &Path) -> (String, Node) {
    let text = std::fs::read_to_string(path).unwrap();
    let document = node::load(&text).unwrap();
    let root = (**document.root().unwrap()).clone();
    (text, root)
}

fn block(root: &Node) -> &Node {
    root.get("configurations")
        .and_then(|configurations| configurations.get("google_secops"))
        .unwrap()
}

fn text(node: Option<&std::sync::Arc<Node>>) -> Option<String> {
    node.and_then(|node| match &node.value {
        Value::Str(text) => Some(text.clone()),
        Value::Int(integer) => Some(integer.to_string()),
        _ => None,
    })
}

/// The facts a compiler reads off a rule, without an index to inherit
/// techniques from.
fn facts(root: &Node) -> RuleFacts {
    let metadata = root.get("metadata").unwrap();
    let mut techniques: Vec<String> = match root.get("techniques").map(|node| &node.value) {
        Some(Value::Seq(items)) => items.iter().filter_map(|item| text(Some(item))).collect(),
        _ => Vec::new(),
    };
    techniques.sort();
    techniques.dedup();
    RuleFacts {
        title: text(root.get("name")).unwrap_or_default(),
        uuid: text(metadata.get("uuid")).unwrap_or_default(),
        version: text(metadata.get("version")),
        author: text(metadata.get("author")),
        description: text(root.get("description")).unwrap_or_default(),
        alert_severity: root
            .get("response")
            .and_then(|response| text(response.get("alert_severity"))),
        techniques,
    }
}

fn convert(block: &Node) -> (Option<GoogleSecopsConfig>, Vec<(String, String)>) {
    let mut cx = Context::new();
    let value = GoogleSecopsConfig::from_node(block, &mut cx);
    let errors = cx
        .into_errors()
        .into_iter()
        .map(|error| {
            let path: Vec<String> = error.path.iter().map(ToString::to_string).collect();
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                path.join("."),
            )
        })
        .collect();
    (value, errors)
}

#[test]
fn every_valid_block_converts() {
    let files = yaml_files(&fixtures());
    assert_eq!(files.len(), 3, "{files:?}");
    for path in files {
        let (_, root) = load_rule(&path);
        let (value, errors) = convert(block(&root));
        assert!(errors.is_empty(), "{}: {errors:?}", path.display());
        assert!(value.is_some(), "{}", path.display());
        assert!(block_codes(block(&root)).is_empty());
    }
}

#[test]
fn the_spray_block_reads_every_field() {
    let (_, root) = load_rule(&fixtures().join("rule-google-secops-spray-1.0.yaml"));
    let (Some(block), _) = convert(block(&root)) else {
        panic!("the block did not convert");
    };
    assert_eq!(block.name, "password_spray_then_success");
    assert_eq!(block.severity, Some(Severity::High));
    assert_eq!(block.run_frequency, Some(RunFrequency::LiveCustomizable));
    let schedule = block.schedule.unwrap();
    assert_eq!(schedule.ensure_enrichment_completeness, Some(true));
    assert_eq!(
        schedule.late_arriving_data_adjustment.as_deref(),
        Some("30m")
    );
    let window = block.r#match.unwrap();
    assert_eq!(window.group_by, ["$user", "$ip"]);
    assert_eq!(window.window, "30m");
    assert_eq!(
        block.options.unwrap().suppression_window.as_deref(),
        Some("1h")
    );
}

#[test]
fn each_invalid_fixture_reports_the_codes_its_header_names() {
    let files = yaml_files(&fixtures().join("invalid"));
    assert_eq!(files.len(), 6);
    for path in files {
        let (text, root) = load_rule(&path);
        let expected: BTreeSet<String> = text
            .lines()
            .take_while(|line| line.starts_with('#'))
            .filter_map(|line| {
                line.split_once("Expected code")
                    .map(|(_, codes)| codes.trim_start_matches('s').trim_start_matches(':'))
            })
            .flat_map(|codes| codes.trim().trim_end_matches('.').split(", "))
            .map(str::to_owned)
            .collect();
        assert!(!expected.is_empty(), "{}", path.display());
        let found: BTreeSet<String> = block_codes(block(&root))
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(found, expected, "{}", path.display());
        let (value, errors) = convert(block(&root));
        assert!(value.is_none());
        let typed: BTreeSet<String> = errors.iter().map(|(kind, _)| kind.clone()).collect();
        assert_eq!(typed, expected, "{}: {errors:?}", path.display());
    }
}

#[test]
fn findings_are_placed_at_their_paths() {
    let (_, root) = load_rule(&fixtures().join("invalid/rule-google-secops-hourly.yaml"));
    let (_, errors) = convert(block(&root));
    assert_eq!(
        errors,
        [
            (
                "google_secops_run_frequency".to_owned(),
                "run_frequency".to_owned()
            ),
            ("google_secops_schedule".to_owned(), "schedule".to_owned()),
        ]
    );
    let (_, root) = load_rule(&fixtures().join("invalid/rule-google-secops-meta-reserved.yaml"));
    let (_, errors) = convert(block(&root));
    assert_eq!(errors[0].0, "google_secops_meta_key");
    assert!(errors[0].1.starts_with("meta."), "{errors:?}");
}

#[test]
fn a_block_without_status_is_left_to_its_fields() {
    let document = node::load("events: |\n  events:\ncondition: x\n").unwrap();
    let (value, errors) = convert(document.root().unwrap());
    assert!(value.is_none());
    assert_eq!(errors, [("missing".to_owned(), "status".to_owned())]);
}

#[test]
fn query_is_refused_as_an_extra_key() {
    let document =
        node::load("status: S\nquery: x\nevents: |\n  $e\ncondition: |\n  $e\n").unwrap();
    let (_, errors) = convert(document.root().unwrap());
    assert_eq!(errors, [("extra_forbidden".to_owned(), "query".to_owned())]);
}

#[test]
fn a_dumped_block_with_every_field_is_judged_without_its_nulls() {
    let document = node::load(
        "enabled: true\nname: ''\nschema: null\nstatus: S\nflags: null\ntenants: null\n\
         contributors: null\nsetup: null\nevents: |\n  $e\nmatch: null\noutcome: null\n\
         condition: |\n  $e\noptions: null\nexport: null\nseverity: null\npriority: null\n\
         alerting: null\nrun_frequency: null\nschedule: null\nmeta: null\n",
    )
    .unwrap();
    assert!(block_codes(document.root().unwrap()).contains("yaral_section_empty"));
    let (value, errors) = convert(document.root().unwrap());
    assert!(errors.is_empty(), "{errors:?}");
    assert!(value.is_some());
}

#[test]
fn the_assembled_text_equals_each_yaral_fixture() {
    for stem in ["process", "spray"] {
        let path = fixtures().join(format!("rule-google-secops-{stem}-1.0.yaml"));
        let (_, root) = load_rule(&path);
        let assembled = assemble(&facts(&root), block(&root)).unwrap();
        let expected = std::fs::read_to_string(path.with_extension("yaral")).unwrap();
        assert_eq!(assembled.text, expected, "{stem}");
        // Each label line names its section.
        let lines: Vec<&str> = assembled.text.lines().collect();
        for place in &assembled.sections {
            assert_eq!(lines[place.label_line - 1], format!("  {}:", place.key));
        }
    }
}

#[test]
fn locate_puts_a_position_back_on_its_section_line() {
    let (_, root) = load_rule(&fixtures().join("rule-google-secops-spray-1.0.yaml"));
    let assembled = assemble(&facts(&root), block(&root)).unwrap();
    let events = assembled.label_line("events").unwrap();
    // The ninth line of events is `$success.target.user.userid = $user`.
    let at = assembled.locate(Some(events + 9), Some(15));
    assert_eq!(at.key, Some("events"));
    assert_eq!(at.line, Some(9));
    assert_eq!(at.column, Some(11));
    let match_line = assembled.label_line("match").unwrap();
    assert_eq!(assembled.locate(Some(match_line + 1), Some(5)).line, None);
    assert_eq!(assembled.locate(Some(2), Some(1)).key, None);
}

#[test]
fn a_block_without_condition_is_not_assembled() {
    let document = node::load("status: S\nevents: |\n  $e\ncondition: '  '\n").unwrap();
    let facts = RuleFacts {
        title: "T".to_owned(),
        ..RuleFacts::default()
    };
    let error = assemble(&facts, document.root().unwrap()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "rule \"T\": configurations.google_secops has no condition"
    );
}

/// 0.28.0's `validation/errors.py` reports a google-secops-1.0 constraint by
/// its own code (`google_secops.checks.CONSTRAINT_CODES`), not
/// `schema_validation`; the stray `query` key is not one of them.
#[test]
fn constraints_are_reported_by_their_own_code() {
    use opentide_schema::error::Surface;

    let document = node::load(
        "status: S\nquery: x\nrun_frequency: HOURLY\nevents: |\n  $e\ncondition: |\n  $e\n",
    )
    .unwrap();
    let mut cx = Context::new();
    let _ = GoogleSecopsConfig::from_node(document.root().unwrap(), &mut cx);
    let mut codes: Vec<(String, &str)> = cx
        .into_errors()
        .iter()
        .map(|error| (error.field_path().join("."), error.code(Surface::Object)))
        .collect();
    codes.sort();
    assert_eq!(
        codes,
        [
            ("query".to_owned(), "schema_validation"),
            ("run_frequency".to_owned(), "google_secops_run_frequency"),
        ]
    );
}
