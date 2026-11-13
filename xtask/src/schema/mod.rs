//! `cargo xtask schema diff --against python` (UC-1.3, #809): the object
//! models of `opentide_schema::objects` against the oracle (the frozen
//! Python CLI), two ways.
//!
//! - **schemas** ([`mod@normalise`]): each model's schemars output against
//!   Pydantic's `model_json_schema(by_alias=True)`, structurally equal after
//!   normalisation (byte equality is UC-1.8's, #814), and the registry's
//!   schema identifiers against `objects::checks::REGISTERED`. The platform
//!   blocks (UC-1.4, #810) are compared whole, in the rules and on their own.
//! - **objects**: every object file of every corpus (the fixtures of
//!   `tests/golden/cases.toml` and the heavy workspace, seed 20261107) read
//!   by the object models and validated by the oracle (`validate --json`):
//!   the same findings, code, field path, message and position, the platform
//!   blocks' included. A difference must be one of the fault runner's
//!   approved differences (`corpus::structural::APPROVED`), which name their
//!   reason and CHANGELOG entry.

pub mod normalise;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail, ensure};
use opentide_schema::objects;
use opentide_schema::objects::platform;
use serde_json::{Value, json};

use crate::corpus::structural;
use normalise::{Side, differences, normalise};

const PROBE: &str = include_str!("probe.py");

/// The usage.
pub const USAGE: &str = "\
usage: cargo xtask schema <command> [options]

commands:
  diff --against python [--only schemas|objects] [--fixture NAME ...]
       [--python PATH] [--report FILE]
                 compare the object models (opentide-schema, UC-1.3) with the
                 oracle's Pydantic models: each model's JSON Schema, structurally
                 after normalisation (schemas), and the findings on every object
                 file of the corpora: the fixtures of tests/golden/cases.toml and
                 the heavy workspace (objects). --python is the oracle's
                 interpreter, else it is installed from tests/golden/ORACLE
  help           print this message

exit status: 0 passed, 1 a check failed, 2 usage error or the check could not run
";

/// The fixtures `objects` reads, and the heavy workspace.
pub const FIXTURES: [&str; 5] = crate::vocab::diff::FIXTURES;

/// The seed of the heavy workspace CI checks (`corpus generate`).
pub const HEAVY_SEED: u64 = 20_261_107;

/// Runs `cargo xtask schema ARGS`.
pub fn main(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "diff" => parse(rest).and_then(|options| run(&options)),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprint!("xtask schema: unknown command `{other}`\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// What `diff` compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Only {
    /// The JSON Schemas.
    Schemas,
    /// The findings on the corpora.
    Objects,
}

/// The options of `diff`.
#[derive(Debug, Default)]
pub struct Options {
    /// The oracle's Python; installed from `tests/golden/ORACLE` when `None`.
    pub python: Option<PathBuf>,
    /// One comparison, or both.
    pub only: Option<Only>,
    /// The fixtures; [`FIXTURES`] and the heavy workspace when empty.
    pub fixtures: Vec<String>,
    /// Where to write the JSON report.
    pub report: Option<PathBuf>,
}

/// Parses `diff`'s arguments.
pub fn parse(args: &[String]) -> Result<Options> {
    let mut options = Options::default();
    let mut against = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--against" => {
                let engine = value()?;
                ensure!(engine == "python", "--against: only `python` (the oracle)");
                against = true;
            }
            "--python" => options.python = Some(PathBuf::from(value()?)),
            "--report" => options.report = Some(PathBuf::from(value()?)),
            "--fixture" => options.fixtures.push(value()?),
            "--only" => {
                options.only = Some(match value()?.as_str() {
                    "schemas" => Only::Schemas,
                    "objects" => Only::Objects,
                    other => bail!("--only: `{other}` is neither schemas nor objects"),
                });
            }
            other => bail!("unknown option `{other}`"),
        }
    }
    ensure!(against, "--against python is required");
    Ok(options)
}

/// Each object model's schemars output, under its Pydantic class name.
pub fn rust_schemas() -> Vec<(&'static str, Value)> {
    fn of<T: schemars::JsonSchema>() -> Value {
        schemars::schema_for!(T).to_value()
    }
    vec![
        ("Organisation", of::<objects::Organisation>()),
        ("ObjectMetadata", of::<objects::ObjectMetadata>()),
        ("RuleMetadata", of::<objects::RuleMetadata>()),
        ("ObjectReferences", of::<objects::ObjectReferences>()),
        ("ResponseSearch", of::<objects::ResponseSearch>()),
        ("ResponseProcedure", of::<objects::ResponseProcedure>()),
        ("RuleResponse", of::<objects::RuleResponse>()),
        ("ThreatActor", of::<objects::ThreatActor>()),
        ("ThreatBody", of::<objects::ThreatBody>()),
        ("ThreatVector", of::<objects::ThreatVectorV1_0>()),
        ("SignalData", of::<objects::SignalData>()),
        ("ExternalDetector", of::<objects::ExternalDetector>()),
        ("DetectionExample", of::<objects::DetectionExample>()),
        ("DetectionSignal", of::<objects::DetectionSignal>()),
        (
            "ObjectiveComposition",
            of::<objects::ObjectiveComposition>(),
        ),
        ("ObjectiveBody", of::<objects::ObjectiveBody>()),
        ("DetectionObjective", of::<objects::ObjectiveV1_0>()),
        ("RuleConfigurations", of::<objects::RuleConfigurations>()),
        ("DetectionRule", of::<objects::RuleV1_0>()),
        ("DetectionRule_v1_1", of::<objects::RuleV1_1>()),
        ("SentinelConfig", of::<platform::SentinelConfig>()),
        ("DefenderConfig", of::<platform::DefenderConfig>()),
        ("SplunkConfig", of::<platform::SplunkConfig>()),
        ("SentinelOneConfig", of::<platform::SentinelOneConfig>()),
        ("CrowdstrikeConfig", of::<platform::CrowdstrikeConfig>()),
        ("HarfangLabConfig", of::<platform::HarfangLabConfig>()),
        ("CarbonBlackConfig", of::<platform::CarbonBlackConfig>()),
        ("ElasticConfig", of::<platform::ElasticConfig>()),
        ("SysdigConfig", of::<platform::SysdigConfig>()),
        ("GoogleSecopsConfig", of::<platform::GoogleSecopsConfig>()),
    ]
}

/// The model-name prefixes of the platforms the recorded oracle lacks
/// (`opentide_schema::platforms::SINCE_ORACLE`): each such platform's config
/// class without its `Config` suffix (`ExabeamConfig` -> `Exabeam`), which its
/// nested models also share. A platform with no row yet contributes none.
fn since_oracle_model_prefixes() -> Vec<String> {
    platform::PLATFORM_CONFIG_MODELS
        .iter()
        .filter(|entry| opentide_schema::platforms::after_oracle(entry.key))
        .map(|entry| {
            entry
                .model
                .strip_suffix("Config")
                .unwrap_or(entry.model)
                .to_owned()
        })
        .collect()
}

/// Compares the oracle's schemas (`probe.py schemas`) with the models'. The
/// differences by model; an empty list passes.
pub fn compare_schemas(oracle: &Value) -> Result<Vec<(String, Vec<String>)>> {
    let mut out = Vec::new();
    let registered: Vec<&str> = oracle["registered"]
        .as_array()
        .context("the probe wrote no registered identifiers")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if registered != objects::checks::REGISTERED {
        out.push((
            "(registry)".to_owned(),
            vec![format!(
                "the oracle registers {registered:?}, objects::checks::REGISTERED holds {:?}",
                objects::checks::REGISTERED
            )],
        ));
    }
    let after_oracle = since_oracle_model_prefixes();
    for (name, rust) in rust_schemas() {
        // The recorded probe (0.23.0) lacks the models of the platforms the
        // train ports onto it; skip those, keyed by their config class's
        // prefix. On this oracle no such prefix exists, so this is a no-op.
        if after_oracle
            .iter()
            .any(|prefix| name.starts_with(prefix.as_str()))
        {
            continue;
        }
        let pydantic = oracle["schemas"]
            .get(name)
            .with_context(|| format!("the probe wrote no schema for {name}"))?;
        let a = normalise(pydantic, Side::Pydantic, &[]);
        let mut rust = rust;
        drop_since_oracle_properties(&mut rust);
        let b = normalise(&rust, Side::Schemars, &[]);
        out.push((name.to_owned(), differences(&a, &b)));
    }
    Ok(out)
}

/// Removes, at any depth, each `properties` member named after a platform
/// the recorded oracle lacks (`SINCE_ORACLE`): `RuleConfigurations` and the
/// rule models carry their blocks, which the 0.23.0 probe's schemas cannot.
fn drop_since_oracle_properties(schema: &mut Value) {
    match schema {
        Value::Object(members) => {
            if let Some(Value::Object(properties)) = members.get_mut("properties") {
                properties.retain(|key, _| !opentide_schema::platforms::after_oracle(key));
            }
            members.values_mut().for_each(drop_since_oracle_properties);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_since_oracle_properties),
        _ => {}
    }
}

fn python(options: &Options, repo: &Path, target: &Path) -> Result<PathBuf> {
    if let Some(python) = &options.python {
        return Ok(python.clone());
    }
    let golden = repo.join("tests/golden");
    let oracle = crate::golden::oracle::Oracle::parse(&fs::read_to_string(golden.join("ORACLE"))?)?;
    let engine = oracle.provision(&golden, &crate::golden::oracle::cache_dir(target))?;
    Ok(engine.install_dir.join("bin").join("python"))
}

fn probe(python: &Path, scratch: &Path, args: &[&Path]) -> Result<Value> {
    let script = scratch.join("probe.py");
    if !script.exists() {
        fs::write(&script, PROBE)?;
    }
    let home = scratch.join("home");
    fs::create_dir_all(&home)?;
    let result = scratch.join(format!(
        "result-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let status = Command::new(python)
        .arg("-I")
        .arg(&script)
        .args(args)
        .arg(&result)
        .env_clear()
        .env(
            "PATH",
            python.parent().map(Path::as_os_str).unwrap_or_default(),
        )
        .env("HOME", &home)
        .env("NO_COLOR", "1")
        .env("OPENTIDE_NO_UPDATE_CHECK", "1")
        .status()
        .with_context(|| format!("run {}", python.display()))?;
    ensure!(status.success(), "the oracle's probe failed ({status})");
    let text = fs::read_to_string(&result).context("the probe wrote no result")?;
    serde_json::from_str(&text).context("read the probe's result")
}

/// What `objects` found on one corpus.
#[derive(Debug, Default, serde::Serialize)]
pub struct Corpus {
    /// The fixture, or `heavy`.
    pub name: String,
    /// Object files compared.
    pub files: usize,
    /// The oracle's findings compared.
    pub findings: usize,
    /// Files whose findings differ by an approved difference.
    pub approved: usize,
    /// Files the oracle's loader or workspace refused before any model ran.
    pub loader: usize,
    /// Files whose findings differ otherwise: path, oracle, Rust.
    pub mismatches: Vec<(String, Value, Value)>,
}

/// Whether the oracle refused `path` before validating it: `missing_uuid`
/// or `schema_missing`.
fn loader_refused(report: &Value, path: &str) -> bool {
    report["report"]["issues"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|item| {
            item["path"].as_str() == Some(path)
                && matches!(
                    item["code"].as_str(),
                    Some("missing_uuid" | "schema_missing")
                )
        })
}

/// Compares the findings on one workspace (`probe.py objects`'s result).
pub fn compare_objects(name: &str, ws: &Path, result: &Value) -> Result<Corpus> {
    let mut corpus = Corpus {
        name: name.to_owned(),
        ..Corpus::default()
    };
    let report = &result["report"];
    let files = result["objects"]
        .as_array()
        .context("the probe listed no object files")?;
    for file in files {
        let path = file["path"].as_str().context("an object without a path")?;
        let family = file["family"]
            .as_str()
            .context("an object without a family")?;
        let bytes = fs::read(ws.join(path)).with_context(|| format!("read {path}"))?;
        corpus.files += 1;
        // The loader's and the workspace's decisions, before any model runs
        // (UC-2.x): a file without metadata.uuid or metadata.schema, and an
        // empty document.
        let empty = opentide_schema::node::load_bytes(&bytes)
            .is_ok_and(|document| document.root().is_none());
        if empty || loader_refused(report, path) {
            corpus.loader += 1;
            continue;
        }
        // The CLI sorts a report's findings; the model's own order is
        // compared with Pydantic's by opentide-schema's `objects::table` test.
        let mut rust = structural::comparable(&structural::check_object_as(family, &bytes));
        let mut oracle = structural::oracle_findings(report, path);
        rust.sort_by_key(ToString::to_string);
        oracle.sort_by_key(ToString::to_string);
        corpus.findings += oracle.len();
        if rust == oracle {
            continue;
        }
        if structural::APPROVED
            .iter()
            .any(|entry| entry.applies(&oracle, &rust))
        {
            corpus.approved += 1;
        } else {
            corpus
                .mismatches
                .push((path.to_owned(), Value::from(oracle), Value::from(rust)));
        }
    }
    ensure!(corpus.files > 0, "{name}: the probe found no object file");
    Ok(corpus)
}

/// Runs `diff`. Whether it passed.
pub fn run(options: &Options) -> Result<bool> {
    let (repo, target) = crate::vocab::diff::workspace()?;
    let python = python(options, &repo, &target)?;
    let scratch = tempfile::tempdir()?;
    let mut passed = true;
    let mut report = json!({});
    if options.only != Some(Only::Objects) {
        let oracle = probe(&python, scratch.path(), &[Path::new("schemas")])?;
        let compared = compare_schemas(&oracle)?;
        for (name, found) in &compared {
            if found.is_empty() {
                println!("ok   schema {name}");
            } else {
                passed = false;
                println!("FAIL schema {name}: {} difference(s)", found.len());
                for line in found {
                    println!("       {line}");
                }
            }
        }
        report["schemas"] = json!(compared);
    }
    if options.only != Some(Only::Schemas) {
        let spec = crate::golden::case::Spec::parse(&fs::read_to_string(
            repo.join("tests/golden/cases.toml"),
        )?)?;
        let mut names: Vec<String> = options.fixtures.clone();
        if names.is_empty() {
            names.extend(FIXTURES.iter().map(|f| (*f).to_owned()));
            names.push("heavy".to_owned());
        }
        let mut corpora = Vec::new();
        for name in &names {
            let ws = scratch.path().join("ws").join(name);
            fs::create_dir_all(&ws)?;
            if name == "heavy" {
                let workspace = crate::corpus::generate::generate(
                    &crate::corpus::generate::Options::new(HEAVY_SEED),
                );
                fs::remove_dir(&ws)?;
                crate::corpus::cli::write_workspace(&workspace, &ws)?;
            } else {
                spec.fixtures
                    .get(name)
                    .with_context(|| format!("cases.toml has no fixture `{name}`"))?
                    .materialise(&repo, &ws)
                    .with_context(|| format!("materialise {name}"))?;
            }
            let result = probe(&python, scratch.path(), &[Path::new("objects"), &ws])?;
            let corpus = compare_objects(name, &ws, &result)?;
            if corpus.mismatches.is_empty() {
                println!(
                    "ok   objects {name}: {} files, {} findings the same, {} approved \
                     difference(s), {} refused by the loader",
                    corpus.files, corpus.findings, corpus.approved, corpus.loader
                );
            } else {
                passed = false;
                println!(
                    "FAIL objects {name}: {} of {} files differ",
                    corpus.mismatches.len(),
                    corpus.files
                );
                for (path, oracle, rust) in &corpus.mismatches {
                    println!("       {path}\n         oracle: {oracle}\n         rust:   {rust}");
                }
            }
            corpora.push(corpus);
        }
        report["objects"] = json!(corpora);
    }
    if let Some(path) = &options.report {
        fs::write(path, serde_json::to_string_pretty(&report)? + "\n")?;
    }
    println!(
        "schema diff: {}",
        if passed {
            "the same, but for the approved differences"
        } else {
            "FAILED"
        }
    );
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["--against", "rust"])).is_err());
        let options = parse(&args(&["--against", "python", "--only", "schemas"])).unwrap();
        assert_eq!(options.only, Some(Only::Schemas));
        assert!(parse(&args(&["--against", "python", "--only", "x"])).is_err());
    }

    #[test]
    fn properties_of_platforms_the_oracle_lacks_are_dropped() {
        let mut schema = serde_json::json!({"properties": {
            "configurations": {"properties": {"google_secops": {}, "sentinel": {}}},
            "google_secops": {"type": "object"}
        }});
        drop_since_oracle_properties(&mut schema);
        assert_eq!(
            schema,
            serde_json::json!({"properties": {"configurations": {"properties": {"sentinel": {}}}}})
        );
    }

    #[test]
    fn every_model_and_every_platform_block_has_a_schema() {
        let schemas = rust_schemas();
        assert_eq!(schemas.len(), 30);
        for entry in platform::PLATFORM_CONFIG_MODELS {
            assert!(
                schemas.iter().any(|(name, _)| *name == entry.model),
                "{}",
                entry.model
            );
        }
    }
}
