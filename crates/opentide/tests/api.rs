//! The facade's API on a workspace: open, validate, lint, info, the
//! catalogue, coverage and the deploy plan.

#![cfg(feature = "compile")]
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a fixture that does not lay out is a failure"
)]

mod common;

use opentide::lint::{LintCheck, LintStatus};
use opentide::validate::{Check, PlatformConfigurations, PlatformFinding, QueriesMode};
use opentide::{
    DeployPlanOptions, Error, LintOptions, Options, Strategy, ValidateOptions, Workspace,
};

fn corpus() -> (tempfile::TempDir, Workspace) {
    let dir = common::tide_corpus();
    let ws = Workspace::open(dir.path(), &Options::default()).unwrap();
    (dir, ws)
}

#[test]
fn a_workspace_opens_and_counts_its_objects() {
    let (dir, ws) = corpus();
    assert_eq!(
        ws.root().canonicalize().unwrap(),
        dir.path().canonicalize().unwrap()
    );
    let info = ws.info();
    assert_eq!(
        (
            info.counts.threats,
            info.counts.objectives,
            info.counts.rules
        ),
        (1, 1, 10)
    );
    assert_eq!(info.load_errors, 0);
    assert_eq!(info.platforms.len(), 11);
    assert!(
        info.platforms
            .iter()
            .any(|p| p.name == "sentinel" && p.enabled)
    );
    // Serialised as `info --json` names its keys.
    let json = serde_json::to_value(&info).unwrap();
    assert_eq!(json["counts"]["rules"], 10);
}

#[test]
fn a_relative_path_opens_from_the_working_directory_and_options_place_paths() {
    let dir = common::tide_corpus();
    let ws = Workspace::open(
        dir.path(),
        &Options::default().cwd(dir.path().join("objects")),
    )
    .unwrap();
    assert_eq!(ws.info().counts.rules, 10);
}

#[test]
fn validate_runs_every_default_check() {
    let (_dir, ws) = corpus();
    let validation = ws.validate(&ValidateOptions::default().queries(QueriesMode::Off));
    assert_eq!(validation.summary.objects, 12);
    let names: Vec<&str> = validation.checks.iter().map(|(c, _)| c.name()).collect();
    assert_eq!(
        names,
        ["id-uniqueness", "uuid-format", "schema", "configuration"]
    );
    assert!(
        validation.report.issues.is_empty(),
        "{:?}",
        validation.report.issues
    );
    assert!(!validation.failed);
}

/// A platform plugin's own check of its blocks, as the Python package
/// passes it (UC-4.5b).
struct AcmeBlocks;

impl PlatformConfigurations for AcmeBlocks {
    fn platforms(&self) -> Vec<String> {
        vec!["acme".to_owned()]
    }

    fn check(&self, platform: &str, block: &serde_json::Value) -> Vec<PlatformFinding> {
        assert_eq!(platform, "acme");
        if block["severity"].is_u64() {
            return Vec::new();
        }
        vec![PlatformFinding {
            field_path: vec!["severity".to_owned()],
            message: "Input should be a valid integer".to_owned(),
            warning: false,
        }]
    }
}

#[test]
fn validate_compiles_what_a_deploy_would_compile() {
    // UC-2.2 (#817): a Sentinel rule without `grouping.alert` passes the
    // schema and fails the Sentinel compiler, so validate fails it, as
    // `deploy --dry-run` would.
    let (dir, _) = corpus();
    let rule = dir.path().join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    let cut = "\n      alert:\n        enabled: false\n";
    assert_eq!(text.matches(cut).count(), 1);
    std::fs::write(&rule, text.replace(cut, "\n")).unwrap();
    let ws = Workspace::open(dir.path(), &Options::default()).unwrap();
    // The queries check is the engines' (the `queries` feature), not this test's.
    let validation = ws.validate(&ValidateOptions::default().queries(QueriesMode::Off));
    let found: Vec<(&str, &[String])> = validation
        .report
        .issues
        .iter()
        .map(|d| (d.code.as_str(), d.field_path.as_slice()))
        .collect();
    assert_eq!(
        found,
        [(
            "compile_missing_field",
            &["configurations", "sentinel", "grouping", "alert"].map(String::from)[..]
        )]
    );
    assert!(validation.failed);
    assert_eq!(validation.exit_code(), 1);
}

#[test]
fn validate_with_platforms_checks_a_plugins_block_with_the_plugin() {
    let (dir, _) = corpus();
    let rule = dir.path().join("objects/rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    std::fs::write(
        &rule,
        text.replacen(
            "configurations:\n",
            "configurations:\n  acme:\n    severity: high\n",
            1,
        ),
    )
    .unwrap();
    let ws = Workspace::open(dir.path(), &Options::default()).unwrap();
    let options = ValidateOptions::default()
        .check(Check::Schema)
        .file("rule-0001-sentinel-kql.yaml");
    let at = |validation: &opentide::Validation| -> Vec<Vec<String>> {
        validation
            .report
            .issues
            .iter()
            .filter(|d| d.field_path.get(1).is_some_and(|key| key == "acme"))
            .map(|d| d.field_path.clone())
            .collect()
    };
    // Without the plugin, the block is an extra key; with it, the plugin's
    // finding sits inside the block.
    assert_eq!(at(&ws.validate(&options)), [["configurations", "acme"]]);
    let checked = ws.validate_with_platforms(&options, &AcmeBlocks);
    assert_eq!(at(&checked), [["configurations", "acme", "severity"]]);
    assert!(checked.failed);
}

#[test]
fn validate_narrows_to_a_check_a_file_a_uuid_and_a_type() {
    let (dir, ws) = corpus();
    let uuid = common::uuid_of(dir.path(), "rule-0001-sentinel-kql.yaml");
    let one = ws.validate(
        &ValidateOptions::default()
            .check(Check::Schema)
            .uuid(&uuid)
            .object_type("rule")
            .strict(true),
    );
    assert_eq!(one.summary.objects, 1);
    assert_eq!(one.checks, [(Check::Schema, "passed")]);
    let by_file = ws.validate(
        &ValidateOptions::default()
            .check(Check::UuidFormat)
            .file("rule-0003-splunk-spl.yaml"),
    );
    assert_eq!(by_file.summary.objects, 1);
    let none = ws.validate(
        &ValidateOptions::default()
            .check(Check::Schema)
            .file("no-such-rule.yaml"),
    );
    assert!(none.failed);
    assert!(
        none.report
            .issues
            .iter()
            .any(|d| d.code == "scope_no_match")
    );
}

#[cfg(not(feature = "queries"))]
#[test]
fn without_the_engines_the_queries_check_reports_engine_unavailable() {
    let (_dir, ws) = corpus();
    for mode in [QueriesMode::Error, QueriesMode::Warn] {
        let validation = ws.validate(&ValidateOptions::default().queries(mode));
        assert!(validation.failed, "{mode:?}");
        let unavailable: Vec<_> = validation
            .report
            .issues
            .iter()
            .filter(|d| d.code == opentide::queries::ENGINE_UNAVAILABLE)
            .collect();
        assert_eq!(unavailable.len(), 1, "{mode:?}");
        assert_eq!(unavailable[0].severity, opentide::Severity::Error);
        assert_eq!(
            unavailable[0].suggestion.as_deref(),
            Some(opentide::queries::ENGINE_UNAVAILABLE_ADVICE)
        );
    }
    let lint = ws.lint(&LintOptions::default().check(LintCheck::Queries));
    assert_eq!(lint.status, LintStatus::Failed);
    assert_eq!(lint.failure_code, Some("engine_unavailable"));
    assert!(
        lint.message.contains("no query engines"),
        "{}",
        lint.message
    );
}

#[cfg(feature = "queries")]
#[test]
fn with_the_engines_the_queries_check_runs() {
    let (_dir, ws) = corpus();
    let validation = ws.validate(&ValidateOptions::default());
    assert!(
        validation
            .report
            .issues
            .iter()
            .all(|d| d.code != opentide::queries::ENGINE_UNAVAILABLE)
    );
    assert!(
        validation
            .summary
            .queries
            .is_some_and(|queries| queries > 0)
    );
    let lint = ws.lint(&LintOptions::default().check(LintCheck::Queries));
    assert_ne!(lint.failure_code, Some("engine_unavailable"));
}

#[test]
fn lint_runs_the_checks_it_is_given() {
    let (_dir, ws) = corpus();
    let lint = ws.lint(
        &LintOptions::default()
            .check(LintCheck::Filenames)
            .check(LintCheck::Placeholders)
            .file("rule-0001-sentinel-kql.yaml"),
    );
    assert_eq!(lint.checks, [LintCheck::Filenames, LintCheck::Placeholders]);
    assert_ne!(lint.status, LintStatus::Failed, "{}", lint.message);
    assert_eq!(lint.summary.map(|s| s.files), Some(1));
    let strict = ws.lint(
        &LintOptions::default()
            .check(LintCheck::Metadata)
            .strict(true),
    );
    assert_eq!(strict.checks, [LintCheck::Metadata]);
}

#[test]
fn the_catalogue_lists_every_object_and_coverage_finds_the_rules() {
    let (_dir, ws) = corpus();
    let catalogue = ws.catalog();
    assert_eq!(catalogue.objects.len(), 12);
    assert_eq!(catalogue.summary.rules, 10);
    let json = serde_json::to_value(&catalogue).unwrap();
    for key in ["objects", "edges", "signals", "attack"] {
        assert!(json.get(key).is_some(), "{key}");
    }
    let coverage = ws.coverage("T1059");
    assert!(coverage.count > 0, "{coverage:?}");
    assert_eq!(coverage.count, coverage.rules.len());
    assert_eq!(ws.coverage("T9999").count, 0);
}

#[test]
fn rules_objectives_and_threats_are_the_catalogues_rows_of_each_family() {
    let (_dir, ws) = corpus();
    let (rules, objectives, threats) = (ws.rules(), ws.objectives(), ws.threats());
    assert_eq!((rules.len(), objectives.len(), threats.len()), (10, 1, 1));
    assert!(rules.iter().all(|row| row.family == "rule"));
    assert_eq!(objectives[0].family, "objective");
    assert_eq!(threats[0].family, "threat");
    // In the catalogue's order.
    let catalogue: Vec<String> = ws
        .catalog()
        .objects
        .iter()
        .filter(|row| row.loaded_family() == Some("rule"))
        .map(|row| serde_json::to_value(row).unwrap()["uuid"].to_string())
        .collect();
    let listed: Vec<String> = rules
        .iter()
        .map(|row| serde_json::to_value(&row.uuid).unwrap().to_string())
        .collect();
    assert_eq!(listed, catalogue);
}

#[test]
fn a_deploy_plan_compiles_every_rule_and_sends_nothing() {
    let (dir, ws) = corpus();
    let plan = ws
        .deploy_plan(&DeployPlanOptions::new(Strategy::Preview))
        .unwrap();
    let document = plan.document().value();
    assert_eq!(document["dry_run"], true, "{}", plan.document());
    assert_eq!(document["strategies"], serde_json::json!(["PREVIEW"]));
    // The text keeps the command line's key order (a `serde_json::Value`
    // would sort `advice` first).
    let text = plan.document().as_str();
    let at = |key: &str| text.find(&format!("\"{key}\":")).unwrap();
    assert!(
        at("status") < at("deployed") && at("deployed") < at("advice"),
        "{text}"
    );
    // Seven enabled platforms have no tenant: the plan warns that a real run
    // would stop there.
    assert!(plan.ok());
    assert_eq!(
        document["missing_tenants"].as_object().map(|m| m.len()),
        Some(7)
    );
    assert!(plan.summary().is_some());
    let uuid = common::uuid_of(dir.path(), "rule-0001-sentinel-kql.yaml");
    let selected = ws
        .deploy_plan(
            &DeployPlanOptions::new(Strategy::Preview)
                .strategy(Strategy::Release)
                .uuid(&uuid)
                .platform("sentinel"),
        )
        .unwrap();
    assert_eq!(selected.document().value()["scope"], "selected");
    let unmatched = ws
        .deploy_plan(&DeployPlanOptions::new(Strategy::Release).file("missing.yaml"))
        .unwrap();
    assert!(!unmatched.ok());
    assert_eq!(
        unmatched.document().value()["unmatched"],
        serde_json::json!(["missing.yaml"])
    );
}

#[test]
fn a_deploy_plan_without_a_strategy_is_a_usage_error() {
    let (_dir, ws) = corpus();
    let error = ws.deploy_plan(&DeployPlanOptions::default()).unwrap_err();
    assert_eq!(error.code(), "usage_missing_option");
    assert!(error.to_string().starts_with("Pass --strategy"), "{error}");
    assert_eq!(Strategy::Release.to_string(), "RELEASE");
}

#[test]
fn a_configuration_that_does_not_resolve_is_an_error_with_its_code() {
    let dir = common::tide_corpus();
    std::fs::write(
        dir.path().join(".opentide/configurations/paths.toml"),
        "this is = = not toml",
    )
    .unwrap();
    let error = Workspace::open(dir.path(), &Options::default()).unwrap_err();
    assert!(matches!(error, Error::Configuration { .. }), "{error:?}");
    assert_eq!(error.code(), "config_parse");
}

#[test]
fn an_in_memory_workspace_reads_nothing_from_the_disk() {
    let ws = Workspace::from_files(
        "/ws",
        [
            (
                "objects/rules/a.yaml",
                "name: A\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n",
            ),
            (
                "objects/rules/b.yaml",
                "name: B\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n",
            ),
        ],
    )
    .unwrap();
    let validation = ws.validate(
        &ValidateOptions::default()
            .check(Check::IdUniqueness)
            .queries(QueriesMode::Off),
    );
    let duplicate = validation
        .report
        .issues
        .iter()
        .find(|d| d.code == "duplicate_id")
        .unwrap();
    assert_eq!(duplicate.path.as_deref(), Some("objects/rules/b.yaml"));
    assert_eq!((duplicate.line, duplicate.column), (Some(3), Some(9)));
}
