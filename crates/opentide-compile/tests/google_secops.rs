//! The Google SecOps compiler on 0.28.0's fixtures
//! (`tests/fixtures/google_secops`): the assembled text equals each `.yaral`
//! file, and the requests a deploy sends (verify, create, the run state,
//! disable and archive) equal each `.api.json` file as data.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace and fixture here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::google_secops::{
    self, RunState, archived_request, create_request, deployment_request, run_state,
    tenant_instance, verify_request,
};
use opentide_compile::{Json, Owned, Rule, preview};
use opentide_schema::objects::platform::GoogleSecopsConfig;
use opentide_schema::platforms::PlatformKey;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/google_secops")
}

fn read_json(path: &Path) -> Json {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn workspace(rule: &str) -> Workspace {
    workspace_with(rule, None)
}

/// A workspace holding `rule`, and `platform` as its Google SecOps
/// configuration when given.
fn workspace_with(rule: &str, platform: Option<&str>) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", rule.to_owned());
    if let Some(platform) = platform {
        fs.write(
            "/ws/.opentide/configurations/platforms/google_secops.toml",
            platform.to_owned(),
        );
    }
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

/// The tenant of `tests/fixtures/google_secops/tenant.toml`.
fn tenant() -> Json {
    serde_json::from_str(
        r#"{"name": "secops-eu", "setup": {"ssl": true, "project": "acme-secops",
            "location": "eu", "instance": "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6",
            "credentials": "$GOOGLE_SECOPS_CREDENTIALS", "deletion": "archive"}}"#,
    )
    .unwrap()
}

/// The rule id the fixtures' paths carry.
const RULE_ID: &str = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1";

struct Compiled {
    text: String,
    offline: Json,
    deployment: Json,
    sections: Vec<&'static str>,
    block: Json,
    status: String,
    writes_create: Vec<Json>,
    writes_bound: Vec<Json>,
}

fn compile(stem: &str) -> Compiled {
    let path = fixtures().join(format!("rule-google-secops-{stem}-1.0.yaml"));
    compile_text(&std::fs::read_to_string(&path).unwrap())
}

fn compile_text(text: &str) -> Compiled {
    let uuid = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned();
    let workspace = workspace(text);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", &uuid).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let block = rule.block("google_secops").unwrap().clone();
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();
    let assembled = google_secops::assemble(&cx, &rule).unwrap();
    let writes = |known| {
        google_secops::compile(&cx, &rule, &tenant(), known)
            .unwrap()
            .iter()
            .map(opentide_compile::deploy::Write::to_json)
            .collect()
    };
    Compiled {
        text: assembled.text,
        offline: google_secops::compile_offline(&cx, &rule).unwrap(),
        deployment: google_secops::compile_deployment(&cx, &rule).unwrap(),
        sections: assembled.sections.iter().map(|place| place.key).collect(),
        block,
        status,
        writes_create: writes(None),
        writes_bound: writes(Some(RULE_ID)),
    }
}

/// The run settings of a block, read by its model.
fn settings(block: &Json) -> google_secops::RunSettings {
    let config: GoogleSecopsConfig = serde_json::from_str(&block.to_compact()).unwrap();
    google_secops::RunSettings::from(&config)
}

fn strategy(status: &str) -> opentide_compile::strategy::StatusStrategy {
    use opentide_compile::strategy::StatusStrategy;
    match status {
        "STAGING" => StatusStrategy::Preview,
        _ => StatusStrategy::Release,
    }
}

/// #1142: the plan payload carries, beside the text, what the deploy reads:
/// the name, the sections, and the run state of the block's status (a
/// STAGING rule deploys without alerting) with its run frequency.
#[test]
fn the_deployment_payload_carries_the_run_state_of_the_blocks_status() {
    for stem in ["process", "spray"] {
        let compiled = compile(stem);
        let payload = &compiled.deployment;
        assert_eq!(payload.get("text"), compiled.offline.get("text"));
        let state =
            google_secops::run_state(&settings(&compiled.block), strategy(&compiled.status));
        let run = payload.get("run_state").unwrap();
        assert_eq!(
            run.get("mask").and_then(Json::as_str),
            Some(state.mask.as_str())
        );
        assert_eq!(run.get("body"), Some(&Json::Object(state.body)));
        assert_eq!(
            payload.get("run_frequency"),
            compiled.block.get("run_frequency")
        );
        let Some(Json::Array(sections)) = payload.get("sections") else {
            panic!("{payload:?}")
        };
        let keys: Vec<&str> = sections
            .iter()
            .filter_map(|section| section.get("key").and_then(Json::as_str))
            .collect();
        assert_eq!(keys, compiled.sections, "{stem}");
    }
    // STAGING is PREVIEW: no alerting.
    let staging = compile("process");
    assert_eq!(staging.status, "STAGING");
    let body = staging
        .deployment
        .get("run_state")
        .unwrap()
        .get("body")
        .unwrap();
    assert_eq!(body.get("alerting"), Some(&Json::Bool(false)));
}

/// The block is read by the model `opentide validate` checks it with
/// (`GoogleSecopsConfig`, #1951): a block whose shape the model refuses fails
/// the deploy's compile and the dry run's writes with `compile_failed` at the
/// field, in the model's words, with a hint to run `validate`.
#[test]
fn a_block_the_model_refuses_fails_at_its_field() {
    let fixture =
        std::fs::read_to_string(fixtures().join("rule-google-secops-process-1.0.yaml")).unwrap();
    for (written, field, reason) in [
        (
            "    run_frequency: LIVE\n    alerting: 'yes'\n",
            "alerting",
            "Input should be a valid boolean",
        ),
        (
            "    run_frequency: HOURLY\n",
            "run_frequency",
            "Input should be",
        ),
        (
            "    run_frequency: LIVE\n    schedule:\n      ensure_enrichment_completeness: é\n",
            "schedule.ensure_enrichment_completeness",
            "Input should be a valid boolean",
        ),
        (
            "    run_frequency: LIVE\n    surprisé: 😀\n",
            "surprisé",
            "Extra inputs are not permitted",
        ),
    ] {
        let text = fixture.replace("    run_frequency: LIVE\n", written);
        let uuid = "00000000-0000-4000-8003-000000000061";
        let workspace = workspace(&text);
        let owned = Owned::new(
            &Vocabularies::bundled(),
            &workspace.configuration().resolved,
        );
        let index = workspace.index().clone();
        let cx = owned.context(&index);
        let object = index.get("rule", uuid).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let at: Vec<&str> = ["configurations", "google_secops"]
            .into_iter()
            .chain(field.split('.'))
            .collect();
        for error in [
            google_secops::compile_deployment(&cx, &rule).unwrap_err(),
            google_secops::compile(&cx, &rule, &tenant(), None).unwrap_err(),
        ] {
            assert_eq!(error.code, "compile_failed", "{field}: {error}");
            assert_eq!(error.field, at, "{field}: {error}");
            assert!(
                error
                    .reason
                    .contains(&format!("configurations.google_secops.{field}: {reason}")),
                "{field}: {error}"
            );
            assert!(
                error
                    .hint
                    .as_deref()
                    .is_some_and(|hint| hint.contains("opentide validate")),
                "{field}: {error}"
            );
        }
    }
}

/// A rule without `metadata.version` deploys without `opentide_version` in
/// its meta, never the string `"None"`.
#[test]
fn a_rule_without_a_version_sends_no_opentide_version() {
    let text = std::fs::read_to_string(fixtures().join("rule-google-secops-process-1.0.yaml"))
        .unwrap()
        .replace("  version: 3\n", "");
    let compiled = compile_text(&text);
    assert!(
        !compiled.text.contains("opentide_version"),
        "{}",
        compiled.text
    );
    assert!(!compiled.text.contains("\"None\""), "{}", compiled.text);
    assert!(
        compiled.text.contains("opentide_uuid = "),
        "{}",
        compiled.text
    );
}

#[test]
fn every_request_equals_its_fixture() {
    let instance = tenant_instance(&tenant());
    for stem in ["process", "spray"] {
        let compiled = compile(stem);
        let fixture = |kind: &str| {
            read_json(&fixtures().join(format!("rule-google-secops-{stem}-1.0.{kind}.api.json")))
        };
        assert_eq!(
            compiled.text,
            std::fs::read_to_string(
                fixtures().join(format!("rule-google-secops-{stem}-1.0.yaral"))
            )
            .unwrap(),
            "{stem}"
        );
        assert_eq!(
            verify_request(&instance, &compiled.text).to_json(),
            fixture("verify"),
            "{stem}"
        );
        assert_eq!(
            create_request(&instance, &compiled.text, None).to_json(),
            fixture("create"),
            "{stem}"
        );
        assert_eq!(
            compiled.offline,
            fixture("create").get("body").unwrap().clone()
        );
        let state = run_state(&settings(&compiled.block), strategy(&compiled.status));
        assert_eq!(
            deployment_request(&instance, RULE_ID, &state).to_json(),
            fixture("deployment"),
            "{stem}"
        );
        assert_eq!(
            deployment_request(&instance, RULE_ID, &RunState::disabled()).to_json(),
            fixture("disable"),
            "{stem}"
        );
        assert_eq!(
            Json::Array(vec![
                deployment_request(&instance, RULE_ID, &RunState::disabled()).to_json(),
                archived_request(&instance, RULE_ID, true).to_json(),
            ]),
            fixture("archive"),
            "{stem}"
        );
        // The dry run of a new rule: verify, create, then the run state.
        assert_eq!(compiled.writes_create.len(), 3, "{stem}");
        assert_eq!(
            compiled.writes_create[0].get("url").and_then(Json::as_str),
            Some(
                "https://eu-chronicle.googleapis.com/v1/projects/acme-secops/locations/eu/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6:verifyRuleText"
            )
        );
        assert_eq!(
            compiled.writes_create[1].get("body"),
            fixture("create").get("body")
        );
        // A bound rule: verify, the text update, then the run state.
        assert_eq!(compiled.writes_bound.len(), 3, "{stem}");
        assert_eq!(
            compiled.writes_bound[2].get("body"),
            fixture("deployment").get("body")
        );
    }
}

/// Three tenants: `eu`, whose modifier runs its rules daily; `lab`, with
/// none; and `é😀`, whose modifier blanks the rule's `condition`.
const MODIFIED_TENANTS: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"eu\"\n\
     strategies = [\"PREVIEW\"]\n[tenants.setup]\nproject = \"p\"\nlocation = \"eu\"\ninstance \
     = \"i\"\n\n[[tenants]]\nname = \"lab\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nproject \
     = \"p\"\nlocation = \"us\"\ninstance = \"i\"\n\n[[tenants]]\nname = \"é😀\"\nstrategies = \
     [\"PREVIEW\"]\n[tenants.setup]\nproject = \"p\"\nlocation = \"us\"\ninstance = \"i\"\n\n\
     [[modifiers]]\nname = \"eu daily\"\n[modifiers.conditions]\ntenants = [\"eu\"]\n\
     [modifiers.modifications]\nrun_frequency = \"DAILY\"\n\n[[modifiers]]\nname = \"no \
     condition\"\n[modifiers.conditions]\ntenants = [\"é😀\"]\n[modifiers.modifications]\n\
     condition = \" \"\n";

/// #1952: the dry run compiles the rule for each tenant the run reaches,
/// with that tenant's `[[modifiers]]`, as the deploy does: the body shown
/// is the first tenant's, the entry names it, and a later tenant whose
/// modifiers break the rule fails the dry run, naming that tenant.
#[test]
fn the_dry_run_compiles_for_each_tenant_with_its_modifiers() {
    let text =
        std::fs::read_to_string(fixtures().join("rule-google-secops-process-1.0.yaml")).unwrap();
    let ws = workspace_with(&text, Some(MODIFIED_TENANTS));
    let owned = Owned::new(&Vocabularies::bundled(), &ws.configuration().resolved);
    let index = ws.index().clone();
    let cx = owned.context(&index);
    let object = index
        .get("rule", "00000000-0000-4000-8003-000000000061")
        .unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let platform = PlatformKey::new("google_secops");
    let dry_run = |tenants: &[&str]| {
        let tenants: Vec<String> = tenants.iter().map(|&name| name.to_owned()).collect();
        preview::preview_on(&cx, &platform, &rule, &tenants)
    };
    let frequency = |entry: &Json| {
        entry
            .get("api_request")
            .and_then(|request| request.get("run_frequency"))
            .and_then(Json::as_str)
            .map(str::to_owned)
    };
    // `eu` first: its modifier is in the body shown.
    let entry = dry_run(&["eu", "lab"]);
    assert_eq!(entry.get("tenant").and_then(Json::as_str), Some("eu"));
    assert_eq!(frequency(&entry).as_deref(), Some("DAILY"), "{entry:?}");
    // `lab` first: `eu`'s modifier does not leak into it.
    let entry = dry_run(&["lab", "eu"]);
    assert_eq!(entry.get("tenant").and_then(Json::as_str), Some("lab"));
    assert_eq!(frequency(&entry).as_deref(), Some("LIVE"), "{entry:?}");
    // A later tenant whose modifier blanks `condition` fails the dry run,
    // and the error names that tenant.
    let entry = dry_run(&["eu", "é😀"]);
    assert_eq!(
        entry.get("status").and_then(Json::as_str),
        Some("failed"),
        "{entry:?}"
    );
    let error = entry.get("error").and_then(Json::as_str).unwrap();
    assert!(error.contains("condition"), "{error}");
    assert!(error.ends_with("(tenant 'é😀')"), "{error}");
    assert_eq!(entry.get("api_request"), Some(&Json::Null));
}
