//! The `deploy` output schema `opentide --json commands` publishes accepts the
//! dry-run documents the command prints (#1728, E2E-4): `RulePayload.api_request`
//! was `object | null`, and refused the list of `{method, url, body}` requests
//! six platforms put there (docs/cli/deploy.md, "Payloads").
//!
//! The documents are the dry runs of the `tide-corpus` fixture, the one the
//! snapshot cases `deploy dry-run` and `deploy platform` run, one run per
//! platform of the registry. The fixture has rules for nine platforms; the
//! other five (Bitdefender, Graylog, Exabeam, Google SecOps, Datadog) get a rule from
//! `opentide new rule` in the test's copy, so every platform's `payloads` hold
//! a rule.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a test: a fixture, a run or a schema that fails is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The platforms whose `api_request` is a list of requests.
const LISTS: [&str; 6] = [
    "microsoft_defender",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "splunk",
    "carbon_black_cloud",
];

/// The platforms the fixture has no rule for: `new rule` writes one, and its
/// status is moved to `STAGING`, a `PREVIEW` status.
const SCAFFOLDED: [&str; 5] = [
    "bitdefender",
    "graylog",
    "exabeam",
    "google_secops",
    "datadog",
];

/// `opentide --json <args>` in `cwd`, its document, whatever the exit code.
fn document(cwd: &Path, args: &[&str]) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_opentide-cli"));
    command.arg("--json").args(args).current_dir(cwd);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENTIDE_") {
            command.env_remove(name);
        }
    }
    for name in ["CI", "GITHUB_ACTIONS", "TF_BUILD", "DEPLOYMENT_PLAN"] {
        command.env_remove(name);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!(
            "{args:?}: {error}: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// A rule for each of [`SCAFFOLDED`] in `ws`, its platform enabled.
fn scaffold_the_missing_platforms(ws: &Path) {
    for id in SCAFFOLDED {
        let platforms = ws.join(".opentide/configurations/platforms");
        std::fs::write(
            platforms.join(format!("{id}.toml")),
            "[platform]\nenabled = true\n",
        )
        .unwrap();
        let name = format!("Rule {id}");
        let created = document(ws, &["new", "rule", "--name", &name, "--platform", id]);
        assert_eq!(created["ok"], true, "{id}: {created}");
        let file = ws.join(created["path"].as_str().expect("a created file"));
        let text = std::fs::read_to_string(&file).unwrap();
        let moved: Vec<String> = text
            .lines()
            .map(|line| {
                if line.starts_with("    status: ") {
                    "    status: STAGING".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect();
        std::fs::write(&file, moved.join("\n") + "\n").unwrap();
    }
}

/// The `deploy` command's `output_schema` as `opentide --json commands`
/// publishes it, with the document's `$defs` beside it.
fn published_schema(cwd: &Path) -> Value {
    let commands = document(cwd, &["commands"]);
    let mut schema = commands["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|command| command["path"] == "deploy")
        .expect("a deploy command")["output_schema"]
        .clone();
    schema["$defs"] = commands["$defs"].clone();
    schema
}

#[test]
fn the_published_deploy_schema_accepts_every_dry_run_document() {
    let root = replay::case_root();
    let ws = root.path();
    replay::fixture("tide-corpus", ws);
    scaffold_the_missing_platforms(ws);
    let validator = jsonschema::validator_for(&published_schema(ws)).expect("a valid schema");

    let mut lists = Vec::new();
    for platform in opentide_schema::platforms::PLATFORMS {
        let id = platform.id;
        let doc = document(
            ws,
            &[
                "deploy",
                "--platform",
                id,
                "--strategy",
                "PREVIEW",
                "--all",
                "--dry-run",
            ],
        );
        assert_eq!(doc["dry_run"], true, "{id}: {doc}");
        let errors: Vec<String> = validator
            .iter_errors(&doc)
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{id}: {errors:#?}");
        // Every platform has a rule in the run, compiled: a document with no
        // payload would pass the schema without testing it.
        let payloads = doc["payloads"][id].as_array().unwrap_or_else(|| {
            panic!("{id}: no payloads: {doc}");
        });
        assert!(!payloads.is_empty(), "{id}: {doc}");
        assert!(
            payloads
                .iter()
                .all(|payload| !payload["api_request"].is_null()),
            "{id}: a rule that did not compile: {doc}"
        );
        if payloads[0]["api_request"].is_array() {
            lists.push(id);
        }
    }
    // The run is not vacuous: each list platform has a rule in the fixture.
    lists.sort_unstable();
    let mut expected = LISTS.to_vec();
    expected.sort_unstable();
    assert_eq!(lists, expected);
}
