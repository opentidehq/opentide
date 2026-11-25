//! A rule whose file is gone (#1713): `opentide deploy` warns about it, and
//! with `--prune` on a `RELEASE` run retires it from the tenants that hold
//! it. The evidence is the run's diff (a deleted rule file, read as the
//! diff's base held it) or deployment state (an `--all` run's shards whose
//! rule no file holds). Each platform's deployer is scripted here and
//! records what it was sent; the connectors' own delete requests are their
//! tests'.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::commands::deploy_send::{Args, Context, Lines, Sent, run};
use opentide_cli::env::Env;
use opentide_cli::json::Json;
use opentide_cli::render::outcome::Console;
use opentide_cli::render::text::Colour;
use opentide_connectors::Registry;
use opentide_connectors::connector::{
    BoxFuture, DeployError, DeployFailure, DeployOutcome, DeployRequest, Deployer, Operation,
    Platform, TenantContext,
};

const GONE: &str = "00000000-0000-4000-8113-000000000001";
const KEPT: &str = "00000000-0000-4000-8113-000000000002";

/// A rule file of one platform block.
fn rule(name: &str, uuid: &str, block: &str) -> String {
    format!(
        "name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.0\n  version: 1\n  created: \
         2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: {name} detects it.\n\
         response:\n  alert_severity: High\nconfigurations:\n{block}"
    )
}

const SENTINEL_SETUP: &str = "ssl = true\nresource_group = \"soc-rg\"\nworkspace_name = \
     \"soc\"\nworkspace_id = \"11111111-2222-4333-8444-555555555555\"\nazure_tenant_id = \
     \"contoso-tenant-id\"\nazure_subscription_id = \"sub-0001\"\nazure_client_id = \
     \"opentide-app-id\"\nazure_client_secret = \"$AZURE_CLIENT_SECRET\"\n";

fn sentinel_block(status: &str) -> String {
    format!(
        "  sentinel:\n    status: {status}\n    query: SecurityEvent\n    scheduling:\n      \
         frequency: PT1H\n      lookback: PT1H\n    grouping:\n      event: SingleAlert\n      \
         alert:\n        enabled: false\n"
    )
}

const SPLUNK_SETUP: &str = "url = \"splunk.invalid\"\ntoken = \"$SPLUNK_TOKEN\"\n";
const ELASTIC_SETUP: &str = "url = \"https://elastic.invalid\"\napi_key = \"$ELASTIC_API_KEY\"\n";
const S1_SETUP: &str = "ssl = true\nurl = \"https://s1.invalid\"\naccount_id = 1001\napi_token = \
     \"$S1_API_TOKEN\"\n";
const DEFENDER_SETUP: &str = "tenant_id = \"contoso-tenant-id\"\nclient_id = \
     \"opentide-app-id\"\nclient_secret = \"$DEFENDER_CLIENT_SECRET\"\n";
const CBC_SETUP: &str = "ssl = true\nurl = \"https://cbc.invalid\"\norg_key = \"ORGKEY01\"\ntoken \
     = \"$CBC_TOKEN\"\nwatchlist = \"opentide\"\n";

/// The variables every tenant above reads.
fn env() -> Env {
    Env::from_pairs(
        [
            "AZURE_CLIENT_SECRET",
            "SPLUNK_TOKEN",
            "ELASTIC_API_KEY",
            "S1_API_TOKEN",
            "DEFENDER_CLIENT_SECRET",
            "CBC_TOKEN",
        ]
        .map(|name| (name.to_owned(), "secret".to_owned())),
    )
}

/// A workspace whose `platform` has the tenant `lab`, taking PREVIEW and
/// RELEASE runs, and the rules `rules` (file name, text).
fn workspace(platform: &str, setup: &str, rules: &[(&str, String)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let platforms = dir.path().join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join(format!("{platform}.toml")),
        format!(
            "[platform]\nenabled = true\nname = \"Stand-in\"\n\n[[tenants]]\nname = \
             \"lab\"\nstrategies = [\"PREVIEW\", \"RELEASE\"]\n[tenants.setup]\n{setup}"
        ),
    )
    .unwrap();
    let rules_dir = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    for (file, text) in rules {
        std::fs::write(rules_dir.join(file), text).unwrap();
    }
    dir
}

/// Records `uuid` as deployed to `platform`'s tenant `lab` with `id`.
fn record(ws: &Path, platform: &str, uuid: &str, id: &str) {
    let states = ws.join(".opentide/states/deployment");
    std::fs::create_dir_all(&states).unwrap();
    std::fs::write(
        states.join(format!("{uuid}.json")),
        format!(
            "{{\"object_uuid\": \"{uuid}\", \"platforms\": {{\"{platform}\": {{\"lab\": \
             \"{id}\"}}}}, \"schema\": \"deployment.state::1.0\"}}\n"
        ),
    )
    .unwrap();
}

/// Runs git in `ws`, with no user configuration.
fn git(ws: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(ws)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .envs([
            ("GIT_AUTHOR_NAME", "t"),
            ("GIT_AUTHOR_EMAIL", "t@opentide.invalid"),
            ("GIT_COMMITTER_NAME", "t"),
            ("GIT_COMMITTER_EMAIL", "t@opentide.invalid"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

/// `ws` as a repository whose last commit deleted `file` (under the rules
/// folder).
fn deleted_in_last_commit(ws: &Path, file: &str) {
    git(ws, &["init", "-q"]);
    git(ws, &["add", "-A"]);
    git(ws, &["commit", "-q", "-m", "base"]);
    git(ws, &["rm", "-q", &format!("objects/rules/{file}")]);
    git(ws, &["commit", "-q", "-m", "delete"]);
}

/// What the run wrote on stderr.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A RELEASE run's arguments on `platform`: the changed rules, `--prune`
/// as given.
fn release(platform: &str, prune: bool) -> Args {
    Args {
        strategies: vec!["RELEASE".into()],
        platform: Some(platform.to_owned()),
        prune,
        ..Args::default()
    }
}

/// Runs `deploy` with `args` in `ws`.
fn deploy(ws: &Path, args: &Args, registry: &Registry) -> (Sent, String) {
    let buffer = Buffer::default();
    let lines = Lines {
        sink: Arc::new(Mutex::new(buffer.clone())),
        console: Console {
            colour: Colour::None,
            width: None,
        },
        silent: false,
        quiet: false,
        progress: false,
        terminal: false,
        live: None,
    };
    let never = || false;
    let env = env();
    let sent = run(
        args,
        &Context {
            repo: Some(ws.to_str().unwrap()),
            env: &env,
            cwd: ws,
            proxy: None,
            interrupted: &never,
            now: jiff::Timestamp::from_second(0).unwrap(),
            registry,
            lines,
            json: false,
            debug: false,
        },
    );
    let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    (sent, text)
}

/// The result's value at `key`.
fn value<'a>(sent: &'a Sent, key: &str) -> &'a Json {
    sent.result
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("no {key} in {:?}", sent.result))
}

fn get<'a>(sent: &'a Sent, key: &str) -> Option<&'a Json> {
    sent.result
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// The run's warnings, as text.
fn warnings(sent: &Sent) -> Vec<String> {
    match get(sent, "warnings") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Each result row: `(id, status, action, retired)`.
fn rows(sent: &Sent) -> Vec<(String, String, Option<String>, bool)> {
    let Some(Json::Array(results)) = get(sent, "results") else {
        return Vec::new();
    };
    results
        .iter()
        .map(|row| {
            (
                row.get("id").and_then(Json::as_str).unwrap().to_owned(),
                row.get("status").and_then(Json::as_str).unwrap().to_owned(),
                row.get("action").and_then(Json::as_str).map(str::to_owned),
                row.get("retired") == Some(&Json::Bool(true)),
            )
        })
        .collect()
}

/// One request a deployer saw.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    rule_id: String,
    operation: Operation,
    body: String,
}

/// A deployer that records each request and answers it with the next of
/// `answers` (else done).
struct Recorder {
    id: &'static str,
    answers: Mutex<Vec<Result<(), DeployError>>>,
    seen: Mutex<Vec<Seen>>,
}

impl Deployer for Recorder {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        self.seen.lock().unwrap().push(Seen {
            rule_id: request.rule_id.clone(),
            operation: request.operation,
            body: String::from_utf8_lossy(&request.body).into_owned(),
        });
        let mut answers = self.answers.lock().unwrap();
        let next = if answers.is_empty() {
            Ok(())
        } else {
            answers.remove(0)
        };
        let remote = (request.operation != Operation::Delete).then(|| "77".to_owned());
        let operation = request.operation;
        Box::pin(async move { next.map(|()| DeployOutcome::new(remote, operation)) })
    }
}

struct Forward(&'static Recorder);

impl Platform for Forward {
    fn id(&self) -> &'static str {
        self.0.id
    }

    fn deployer(&self) -> Option<&dyn Deployer> {
        Some(self.0)
    }
}

/// A recording `platform` deployer, registered.
fn recorder(
    platform: &'static str,
    answers: Vec<Result<(), DeployError>>,
) -> (Registry, &'static Recorder) {
    let recorder: &'static Recorder = Box::leak(Box::new(Recorder {
        id: platform,
        answers: Mutex::new(answers),
        seen: Mutex::new(Vec::new()),
    }));
    let mut registry = Registry::new();
    registry.register(Box::new(Forward(recorder))).unwrap();
    (registry, recorder)
}

/// A Sentinel workspace of two production rules, `gone.yaml` deleted by
/// the last commit.
fn sentinel_push() -> tempfile::TempDir {
    let ws = workspace(
        "sentinel",
        SENTINEL_SETUP,
        &[
            (
                "gone.yaml",
                rule("Gone rule", GONE, &sentinel_block("PRODUCTION")),
            ),
            (
                "kept.yaml",
                rule("Kept rule", KEPT, &sentinel_block("PRODUCTION")),
            ),
        ],
    );
    deleted_in_last_commit(ws.path(), "gone.yaml");
    ws
}

#[test]
fn a_deleted_sentinel_rule_is_retired_by_its_uuid_with_prune() {
    let ws = sentinel_push();
    let (registry, recorder) = recorder("sentinel", Vec::new());
    let (sent, stderr) = deploy(ws.path(), &release("sentinel", true), &registry);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: GONE.into(),
            operation: Operation::Delete,
            body: String::new(),
        }]
    );
    assert_eq!(
        rows(&sent),
        [(
            GONE.to_owned(),
            "deployed".to_owned(),
            Some("delete".to_owned()),
            true
        )]
    );
    assert_eq!(value(&sent, "status"), &Json::str("completed"));
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
    let Json::Object(summary) = value(&sent, "_summary") else {
        panic!("a summary")
    };
    assert_eq!(summary.get("delete"), Some(&Json::Int(1)));
    let Json::Array(changes) = value(&sent, "changes") else {
        panic!("changes")
    };
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].get("action"), Some(&Json::str("delete")));
    assert_eq!(changes[0].get("retired"), Some(&Json::Bool(true)));
    assert_eq!(changes[0].get("status"), Some(&Json::str("PRODUCTION")));
    assert!(stderr.contains("✓ deleted   Gone rule"), "{stderr}");
}

#[test]
fn without_prune_a_deleted_rule_is_only_warned_about() {
    let ws = sentinel_push();
    let (registry, recorder) = recorder("sentinel", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("sentinel", false), &registry);
    assert!(recorder.seen.lock().unwrap().is_empty());
    assert_eq!(value(&sent, "status"), &Json::str("skipped"));
    // A CI script sees the drift without --prune: nothing was sent.
    assert_eq!(
        value(&sent, "retirable"),
        &Json::Array(vec![Json::object([
            ("platform", Json::str("sentinel")),
            ("tenant", Json::str("lab")),
            ("uuid", Json::str(GONE)),
            ("name", Json::str("Gone rule")),
            ("status", Json::str("PRODUCTION")),
            ("action", Json::str("delete")),
        ])])
    );
    assert!(get(&sent, "results").is_none());
    let warnings = warnings(&sent);
    assert!(
        warnings.iter().any(|warning| warning
            == &format!(
                "1 rule deployed earlier has no rule file any more and is not retired from 1 \
                 tenant: Gone rule ({GONE}); a --strategy RELEASE run with --prune retires it"
            )),
        "{warnings:?}"
    );
}

#[test]
fn prune_needs_a_release_run_and_no_selection() {
    let ws = sentinel_push();
    let (registry, recorder) = recorder("sentinel", Vec::new());
    let mut args = release("sentinel", true);
    args.strategies = vec!["PREVIEW".into()];
    let (sent, _) = deploy(ws.path(), &args, &registry);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(2));
    assert_eq!(
        value(&sent, "message"),
        &Json::str("--prune retires rules, which only a --strategy RELEASE run does")
    );
    let mut args = release("sentinel", true);
    args.uuids = vec![KEPT.into()];
    let (sent, _) = deploy(ws.path(), &args, &registry);
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(2));
    assert!(recorder.seen.lock().unwrap().is_empty());
}

#[test]
fn a_moved_rule_file_is_not_retired() {
    let ws = workspace(
        "sentinel",
        SENTINEL_SETUP,
        &[(
            "old.yaml",
            rule("Moved rule", GONE, &sentinel_block("PRODUCTION")),
        )],
    );
    git(ws.path(), &["init", "-q"]);
    git(ws.path(), &["add", "-A"]);
    git(ws.path(), &["commit", "-q", "-m", "base"]);
    git(
        ws.path(),
        &["mv", "objects/rules/old.yaml", "objects/rules/new.yaml"],
    );
    git(ws.path(), &["commit", "-q", "-m", "rename"]);
    let (registry, recorder) = recorder("sentinel", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("sentinel", true), &registry);
    // The rule is deployed under its new file name, never deleted.
    let seen = recorder.seen.lock().unwrap().clone();
    assert_eq!(
        seen.iter()
            .map(|seen| (seen.rule_id.as_str(), seen.operation))
            .collect::<Vec<_>>(),
        [(GONE, Operation::Update)]
    );
    assert!(rows(&sent).iter().all(|row| !row.3), "{:?}", rows(&sent));
}

#[test]
fn a_rule_already_retired_or_never_deployed_is_left_alone() {
    for status in ["REMOVED", "DRAFT"] {
        let ws = workspace(
            "sentinel",
            SENTINEL_SETUP,
            &[(
                "gone.yaml",
                rule("Gone rule", GONE, &sentinel_block(status)),
            )],
        );
        deleted_in_last_commit(ws.path(), "gone.yaml");
        let (registry, recorder) = recorder("sentinel", Vec::new());
        let (sent, _) = deploy(ws.path(), &release("sentinel", true), &registry);
        assert!(recorder.seen.lock().unwrap().is_empty(), "{status}");
        assert!(rows(&sent).is_empty(), "{status}");
    }
}

#[test]
fn an_unreadable_rule_file_stops_every_retirement() {
    let ws = sentinel_push();
    // Another rule file that does not load: its rule would look deleted.
    std::fs::write(ws.path().join("objects/rules/broken.yaml"), "name: [\n").unwrap();
    let (registry, recorder) = recorder("sentinel", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("sentinel", true), &registry);
    assert!(recorder.seen.lock().unwrap().is_empty());
    assert!(
        warnings(&sent).iter().any(|warning| warning.starts_with(
            "1 rule deployed earlier has no rule file, but 1 object file could not be read"
        )),
        "{:?}",
        warnings(&sent)
    );
}

#[test]
fn a_deleted_splunk_rule_is_retired_by_its_name_and_marked_uuid() {
    let block = "  splunk:\n    status: PRODUCTION\n    query: index=main\n";
    let ws = workspace(
        "splunk",
        SPLUNK_SETUP,
        &[("gone.yaml", rule("Gone search", GONE, block))],
    );
    deleted_in_last_commit(ws.path(), "gone.yaml");
    let (registry, recorder) = recorder("splunk", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("splunk", true), &registry);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: "Gone search".into(),
            operation: Operation::Delete,
            body: format!(
                "{{\"description\":\"Gone search detects it.\\n\\nopentide rule {GONE}\"}}"
            ),
        }]
    );
    assert_eq!(rows(&sent)[0].1, "deployed");
    assert!(rows(&sent)[0].3);
}

#[test]
fn a_deleted_elastic_rule_is_retired_by_its_uuid() {
    let block = "  elastic:\n    status: PRODUCTION\n    query: process.name:cmd.exe\n";
    let ws = workspace(
        "elastic",
        ELASTIC_SETUP,
        &[("gone.yaml", rule("Gone elastic", GONE, block))],
    );
    deleted_in_last_commit(ws.path(), "gone.yaml");
    let (registry, recorder) = recorder("elastic", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("elastic", true), &registry);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: GONE.into(),
            operation: Operation::Delete,
            body: String::new(),
        }]
    );
    assert_eq!(rows(&sent)[0].2.as_deref(), Some("delete"));
}

/// Microsoft Defender keeps no deployment state: a deleted rule is retired
/// by its uuid, which is the Defender rule id
/// (`platform::microsoft_defender::1.0`).
#[test]
fn a_deleted_microsoft_defender_rule_is_retired_by_its_uuid() {
    let block = "  microsoft_defender:\n    status: PRODUCTION\n    query: DeviceEvents\n    \
                 schedule:\n      frequency: 1H\n";
    let ws = workspace(
        "microsoft_defender",
        DEFENDER_SETUP,
        &[("gone.yaml", rule("Gone defender", GONE, block))],
    );
    deleted_in_last_commit(ws.path(), "gone.yaml");
    let (registry, recorder) = recorder("microsoft_defender", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("microsoft_defender", true), &registry);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: GONE.into(),
            operation: Operation::Delete,
            body: String::new(),
        }]
    );
    assert_eq!(rows(&sent)[0].2.as_deref(), Some("delete"));
}

#[test]
fn carbon_black_says_it_cannot_retire_a_deleted_rule() {
    let block = "  carbon_black_cloud:\n    status: PRODUCTION\n    query: process_name:cmd.exe\n";
    let ws = workspace(
        "carbon_black_cloud",
        CBC_SETUP,
        &[("gone.yaml", rule("Gone report", GONE, block))],
    );
    deleted_in_last_commit(ws.path(), "gone.yaml");
    let (registry, recorder) = recorder("carbon_black_cloud", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("carbon_black_cloud", true), &registry);
    assert!(recorder.seen.lock().unwrap().is_empty());
    let Some(Json::Array(results)) = get(&sent, "results") else {
        panic!("results")
    };
    assert_eq!(results[0].get("status"), Some(&Json::str("skipped")));
    assert_eq!(
        results[0].get("reason"),
        Some(&Json::str(
            opentide_cli::commands::deploy_retire::CARBON_BLACK_UNSUPPORTED
        ))
    );
}

/// A SentinelOne workspace that holds `KEPT` and records both rules on
/// SentinelOne. `KEPT`'s file now has a block for another platform only, so
/// the run sends SentinelOne nothing of its own: what it sends is retirement.
fn s1_state() -> tempfile::TempDir {
    let block = "  sentinel:\n    status: DRAFT\n";
    let ws = workspace(
        "sentinel_one",
        S1_SETUP,
        &[("kept.yaml", rule("Kept rule", KEPT, block))],
    );
    record(ws.path(), "sentinel_one", GONE, "42");
    record(ws.path(), "sentinel_one", KEPT, "43");
    ws
}

#[test]
fn an_all_run_retires_what_deployment_state_records_and_forgets_it() {
    let ws = s1_state();
    let (registry, recorder) = recorder("sentinel_one", Vec::new());
    let mut args = release("sentinel_one", true);
    args.all = true;
    let (sent, _) = deploy(ws.path(), &args, &registry);
    // The orphan is deleted by its recorded id; the kept rule, whose file
    // is there, is never retired.
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: "42".into(),
            operation: Operation::Delete,
            body: String::new(),
        }]
    );
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{GONE}.json"))
            .exists()
    );
    assert!(
        ws.path()
            .join(format!(".opentide/states/deployment/{KEPT}.json"))
            .exists()
    );
    let retired: Vec<_> = rows(&sent).into_iter().filter(|row| row.3).collect();
    assert_eq!(
        retired,
        [(
            GONE.to_owned(),
            "deployed".to_owned(),
            Some("delete".to_owned()),
            true
        )]
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
}

#[test]
fn a_retirement_the_tenant_no_longer_has_is_skipped_and_forgotten() {
    let ws = s1_state();
    std::fs::remove_file(
        ws.path()
            .join(format!(".opentide/states/deployment/{KEPT}.json")),
    )
    .unwrap();
    let gone =
        DeployError::rule(DeployFailure::new("tenant_refused", "no such rule").with_status(404));
    let (registry, _) = recorder("sentinel_one", vec![Err(gone)]);
    let mut args = release("sentinel_one", true);
    args.all = true;
    let (sent, _) = deploy(ws.path(), &args, &registry);
    let Some(Json::Array(results)) = get(&sent, "results") else {
        panic!("results")
    };
    assert_eq!(results[0].get("status"), Some(&Json::str("skipped")));
    assert_eq!(
        results[0].get("reason"),
        Some(&Json::str("already gone from the tenant"))
    );
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{GONE}.json"))
            .exists()
    );
    assert_eq!(value(&sent, "_exit_code"), &Json::Int(0));
}

#[test]
fn an_all_run_of_a_workspace_with_no_rule_retires_nothing() {
    let ws = s1_state();
    std::fs::remove_file(ws.path().join("objects/rules/kept.yaml")).unwrap();
    let (registry, recorder) = recorder("sentinel_one", Vec::new());
    let mut args = release("sentinel_one", true);
    args.all = true;
    let (sent, _) = deploy(ws.path(), &args, &registry);
    assert!(recorder.seen.lock().unwrap().is_empty());
    assert!(
        warnings(&sent).iter().any(|warning| warning
            .starts_with("the workspace holds no rule, so the 2 deployment state shards")),
        "{:?}",
        warnings(&sent)
    );
    assert!(
        ws.path()
            .join(format!(".opentide/states/deployment/{GONE}.json"))
            .exists()
    );
}

#[test]
fn a_change_detection_run_retires_a_deleted_rule_by_its_recorded_id() {
    let ws = s1_state();
    std::fs::write(
        ws.path().join("objects/rules/gone.yaml"),
        rule(
            "Gone rule",
            GONE,
            "  sentinel_one:\n    status: PRODUCTION\n",
        ),
    )
    .unwrap();
    deleted_in_last_commit(ws.path(), "gone.yaml");
    let (registry, recorder) = recorder("sentinel_one", Vec::new());
    let (sent, _) = deploy(ws.path(), &release("sentinel_one", true), &registry);
    assert_eq!(
        *recorder.seen.lock().unwrap(),
        [Seen {
            rule_id: "42".into(),
            operation: Operation::Delete,
            body: String::new(),
        }]
    );
    assert_eq!(rows(&sent)[0].0, GONE);
    assert!(
        !ws.path()
            .join(format!(".opentide/states/deployment/{GONE}.json"))
            .exists()
    );
}
