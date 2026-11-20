//! The `deploy` output schema `opentide --json commands` publishes accepts the
//! dry-run documents the command prints (#1728, E2E-4): `RulePayload.api_request`
//! was `object | null`, and refused the list of `{method, url, body}` requests
//! six platforms put there (docs/cli/deploy.md, "Payloads").
//!
//! The documents are the dry runs of the `tide-corpus` fixture, the one the
//! snapshot cases `deploy dry-run` and `deploy platform` run, one run per
//! platform of the registry.

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
    "defender_for_endpoint",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "splunk",
    "carbon_black_cloud",
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
        if doc["payloads"][id][0]["api_request"].is_array() {
            lists.push(id);
        }
    }
    // The run is not vacuous: each list platform has a rule in the fixture.
    lists.sort_unstable();
    let mut expected = LISTS.to_vec();
    expected.sort_unstable();
    assert_eq!(lists, expected);
}
