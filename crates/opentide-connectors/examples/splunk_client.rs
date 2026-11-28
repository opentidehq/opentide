//! The Rust client of the `splunk/deploy` cassette scenario
//! (`tests/cassettes/scenarios.toml`), and the writer of the deploy inputs
//! of `tests/fixtures/splunk.json`, since opentide stopped sending what the
//! frozen Python client sent (#1657).
//!
//! - `fixture <path>`: compiles the tide corpus's Splunk rule
//!   (`rule-0003-splunk-spl.yaml`) as `opentide deploy` compiles it for a
//!   tenant of the `search` app, at each step's status, and writes each
//!   step's request (`name`, `status`, the `body` deploy sends) under the
//!   fixture's `deploy`, keeping its `query` and `validate` inputs, which
//!   `tests/cassettes/splunk/client.py fixture` wrote.
//! - `deploy`: sends the fixture's steps through the Splunk `Deployer`, as
//!   `opentide deploy` does, to `splunk.invalid:8089` with the token in
//!   `SPLUNK_TOKEN`: created, deployed again, retired, retired again. Run
//!   behind `opentide-cassette`'s recording proxy (its `HTTPS_PROXY` and CA
//!   bundle) against `tests/cassettes/splunk/tenant.py`, it records the
//!   scenario. Each step's outcome is printed, one JSON line each.
//!
//! Run from the repository root:
//! `cargo run -p opentide-connectors --example splunk_client -- <command>`.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use opentide_compile::json::{Json, Object};
use opentide_compile::{Owned, Rule, splunk as compile};
use opentide_connectors::connector::{DeployRequest, Deployer as _, Operation, TenantContext};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::runtime::block_on;
use opentide_connectors::splunk::{self, Splunk};
use opentide_connectors::{Environment, HttpClient, Tenant};
use opentide_schema::platforms::PlatformKey;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};
use tokio_util::sync::CancellationToken;

type Failed = Box<dyn Error>;

/// The tide corpus's Splunk rule.
const RULE: &str =
    "tests/fixtures/tide_corpus/current/Objects/Detection Rules/rule-0003-splunk-spl.yaml";
const UUID: &str = "00000000-0000-4000-8003-000000000003";
/// The fixture this writes and reads.
const FIXTURE: &str = "crates/opentide-connectors/tests/fixtures/splunk.json";
/// The scenario's tenant: `client.py`'s.
const SETUP: &str = "ssl = true\nurl = \"splunk.invalid\"\nport = 8089\napp = \"search\"\n\
                     token = \"$SPLUNK_TOKEN\"\nenterprise_security = false\n";
/// The statuses of the steps: created, deployed again, retired, retired again.
const STEPS: [&str; 4] = ["STAGING", "STAGING", "REMOVED", "REMOVED"];

fn main() -> Result<(), Failed> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["fixture", path] => fixture(Path::new(path)),
        ["fixture"] => fixture(Path::new(FIXTURE)),
        ["deploy"] => deploy(),
        _ => Err("usage: splunk_client fixture [PATH] | deploy".into()),
    }
}

/// The rule file at *status*.
fn rule_text(status: &str) -> Result<String, Failed> {
    let text = std::fs::read_to_string(RULE)?;
    Ok(text.replace("    status: STAGING\n", &format!("    status: {status}\n")))
}

/// The request `opentide deploy` sends for the corpus rule at *status*
/// (`splunk_request`): the saved search's name and settings (the compiled
/// updates, merged), or, for a status that retires it, the description that
/// names the rule.
fn request(status: &str) -> Result<(String, Operation, Object), Failed> {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.write(
        "/ws/.opentide/configurations/platforms/splunk.toml",
        format!(
            "[platform]\nenabled = true\n\n[[tenants]]\nname = \"splunk\"\n[tenants.setup]\n{SETUP}"
        ),
    );
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/rule.yaml", rule_text(status)?);
    let workspace = Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )?;
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index
        .get("rule", UUID)
        .ok_or("the corpus rule is not indexed")?;
    let root = object.root().ok_or("the corpus rule did not parse")?;
    let rule = Rule::new(root, None);
    let tenant = opentide_compile::deploy::tenants(&cx, &PlatformKey::new(compile::PLATFORM))
        .first()
        .copied()
        .ok_or("no Splunk tenant")?;
    // The rule's schedule is its own cron: no time is drawn.
    let clock = compile::Clock {
        random: (0, 0),
        now: (0, 0),
    };
    let name = rule.name.trim().to_owned();
    if cx.statuses.strategy(status)? == opentide_compile::strategy::StatusStrategy::Deletion {
        let mut named = Object::new();
        named.insert(
            "description".into(),
            Json::Str(compile::retired_description(&rule)),
        );
        return Ok((name, Operation::Delete, named));
    }
    let writes = compile::compile(&cx, &rule, tenant, Some(clock))?;
    let compiled = writes
        .first()
        .and_then(|create| create.body.get("name"))
        .and_then(Json::as_str)
        .ok_or("the compiled create names no saved search")?;
    if compiled != name {
        return Err(format!("the corpus rule is a correlation search: {compiled}").into());
    }
    let mut settings = Object::new();
    for write in writes.iter().skip(1) {
        if let Json::Object(members) = &write.body {
            for (key, value) in members {
                settings.insert(key.clone(), value.clone());
            }
        }
    }
    Ok((name, Operation::Update, settings))
}

fn fixture(path: &Path) -> Result<(), Failed> {
    let Json::Object(mut document) = serde_json::from_str::<Json>(&std::fs::read_to_string(path)?)?
    else {
        return Err("the fixture is not a JSON object".into());
    };
    let mut steps = Vec::new();
    for status in STEPS {
        let (name, _, body) = request(status)?;
        let mut step = Object::new();
        step.insert("name".into(), Json::Str(name));
        step.insert("status".into(), Json::Str(status.to_owned()));
        step.insert("body".into(), Json::Object(body));
        steps.push(Json::Object(step));
    }
    document.insert("deploy".into(), Json::Array(steps));
    let mut text = serde_json::to_string_pretty(&Json::Object(document))?;
    text.push('\n');
    std::fs::write(path, text)?;
    Ok(())
}

fn deploy() -> Result<(), Failed> {
    let fixture = serde_json::from_str::<Json>(&std::fs::read_to_string(FIXTURE)?)?;
    let Some(Json::Array(steps)) = fixture.get("deploy") else {
        return Err("the fixture has no deploy steps".into());
    };
    let env = Environment::process();
    let setup: opentide_core::json::Object = toml::from_str(SETUP)?;
    let tenant = Tenant::from_setup(
        splunk::PLATFORM,
        "splunk",
        &setup,
        &env,
        Resolve::Required,
        &splunk::http_settings(Duration::from_secs(120)),
    )?;
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None)?;
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let connector = Splunk::new();
    for step in steps {
        let name = step.get("name").and_then(Json::as_str).unwrap_or_default();
        let retired = step.get("status").and_then(Json::as_str) == Some("REMOVED");
        let body = step.get("body").cloned().unwrap_or_default();
        let request = DeployRequest::new(
            name,
            if retired {
                Operation::Delete
            } else {
                Operation::Update
            },
            body.to_compact().into_bytes(),
        );
        let outcome = block_on(async { connector.deploy(cx, &request).await })?
            .map_err(|failed| failed.failure.message)?;
        let warnings: Vec<Json> = outcome
            .warnings
            .iter()
            .map(|warning| Json::Str(format!("{}: {}", warning.code, warning.message)))
            .collect();
        let mut printed = Object::new();
        printed.insert(
            "status".into(),
            Json::Str(
                step.get("status")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            ),
        );
        printed.insert("written".into(), Json::Bool(outcome.remote_id.is_some()));
        printed.insert("warnings".into(), Json::Array(warnings));
        println!("{}", Json::Object(printed).to_compact());
    }
    Ok(())
}
