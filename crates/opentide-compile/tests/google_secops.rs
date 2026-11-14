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
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/google_secops")
}

fn read_json(path: &Path) -> Json {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn workspace(rule: &str) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", rule.to_owned());
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
        block,
        status,
        writes_create: writes(None),
        writes_bound: writes(Some(RULE_ID)),
    }
}

fn strategy(status: &str) -> opentide_compile::strategy::StatusStrategy {
    use opentide_compile::strategy::StatusStrategy;
    match status {
        "STAGING" => StatusStrategy::Preview,
        _ => StatusStrategy::Release,
    }
}

/// A rule without `metadata.version` deploys without `opentide_version` in
/// its meta: Python's `str(None)` sent the string `"None"` to the tenant.
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
        let state = run_state(&compiled.block, strategy(&compiled.status));
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
