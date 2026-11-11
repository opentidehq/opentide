//! `cargo xtask cassettes`: record and check the recorded-HTTP cassettes
//! (UC-4.1, #831; plan §5.4 "HTTP").
//!
//! `tests/cassettes/scenarios.toml` lists the scenarios. `record <name>…`
//! runs each one's client (the frozen Python implementation, the oracle of
//! `tests/golden/ORACLE`) behind the recording proxy of `opentide-cassette`
//! and writes `tests/cassettes/<name>.json`. `check` reads every cassette and
//! fails on a digest that does not match (a hand edit), on a request or
//! answer that redaction would still change (a secret, a transport header),
//! on a value of a scenario's secret, and on a scenario without its cassette
//! or a cassette without its scenario.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use opentide_cassette::{Cassette, Mode, Proxy, Redaction, cassette};
use serde::Deserialize;

use crate::golden::Layout;
use crate::golden::oracle::{self, Oracle};

const USAGE: &str = "\
Usage: cargo xtask cassettes <command>

Commands:
  check            check every cassette under tests/cassettes
  record <name>…   record the scenarios named (all with --all) from the oracle
  list             list the scenarios

Exit status: 0 success, 1 a check failed, 2 usage error or the run could not start
";

/// `tests/cassettes/scenarios.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenarios {
    /// The scenarios.
    pub scenario: Vec<Scenario>,
}

/// One scenario.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Its name, the cassette's path under `tests/cassettes` without `.json`.
    pub name: String,
    /// What it records.
    pub description: String,
    /// The client's command line.
    pub client: Vec<String>,
    /// A stand-in tenant to start first.
    #[serde(default)]
    pub tenant: Vec<String>,
    /// Hosts sent to the stand-in tenant.
    #[serde(default)]
    pub routes: Vec<String>,
    /// Variables given a fresh random value and redacted.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// `repo` or `tmp`.
    pub cwd: String,
}

impl Scenarios {
    /// Parses the scenarios, checking their names are unique and safe.
    pub fn parse(text: &str) -> Result<Self> {
        let scenarios: Self = toml::from_str(text).context("parse scenarios.toml")?;
        let mut seen = std::collections::BTreeSet::new();
        for scenario in &scenarios.scenario {
            let safe = scenario.name.split('/').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });
            if !safe {
                bail!(
                    "scenario name {:?} is not a relative path of plain words",
                    scenario.name
                );
            }
            if !seen.insert(scenario.name.clone()) {
                bail!("scenario {} is listed twice", scenario.name);
            }
            if !matches!(scenario.cwd.as_str(), "repo" | "tmp") {
                bail!("scenario {}: cwd is repo or tmp", scenario.name);
            }
            if scenario.client.is_empty() {
                bail!("scenario {}: client is empty", scenario.name);
            }
        }
        Ok(scenarios)
    }
}

/// Runs `cargo xtask cassettes <args>`.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((verb, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    let layout = Layout::find()?;
    let dir = layout.repo.join("tests/cassettes");
    let scenarios = Scenarios::parse(
        &std::fs::read_to_string(dir.join("scenarios.toml")).context("read scenarios.toml")?,
    )?;
    match verb.as_str() {
        "check" => {
            let problems = check(&dir, &scenarios)?;
            for problem in &problems {
                eprintln!("cassettes check: {problem}");
            }
            if problems.is_empty() {
                println!(
                    "cassettes check: {} cassettes, each recorded and redacted",
                    scenarios.scenario.len()
                );
                Ok(0)
            } else {
                Ok(1)
            }
        }
        "list" => {
            for scenario in &scenarios.scenario {
                println!("{}  {}", scenario.name, scenario.description);
            }
            Ok(0)
        }
        "record" => {
            let all = rest.iter().any(|arg| arg == "--all");
            let names: Vec<&String> = rest.iter().filter(|arg| !arg.starts_with("--")).collect();
            let chosen: Vec<&Scenario> = scenarios
                .scenario
                .iter()
                .filter(|scenario| all || names.contains(&&scenario.name))
                .collect();
            if chosen.is_empty() || (!all && chosen.len() != names.len()) {
                eprint!("cassettes record: name scenarios of scenarios.toml, or --all\n\n{USAGE}");
                return Ok(2);
            }
            let oracle = Oracle::parse(
                &std::fs::read_to_string(layout.golden.join("ORACLE")).context("read ORACLE")?,
            )?;
            let engine = oracle.provision(&layout.golden, &oracle::cache_dir(&layout.target))?;
            for scenario in chosen {
                let cassette = record(scenario, &layout.repo, &engine.bin_dir)?;
                let path = dir.join(format!("{}.json", scenario.name));
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, cassette.to_text())
                    .with_context(|| format!("write {}", path.display()))?;
                println!(
                    "cassettes record: {} ({} interactions)",
                    path.display(),
                    cassette.interactions.len()
                );
            }
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => {
            eprint!("cassettes: unknown command `{other}`\n\n{USAGE}");
            Ok(2)
        }
    }
}

/// A random value for a scenario's secret.
fn random_secret() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut value = String::from("rec-");
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |time| time.as_nanos()),
        );
        value.push_str(&format!("{:016x}", hasher.finish()));
    }
    value
}

/// One argument of a scenario's command line, its placeholders filled.
fn expand(arg: &str, bin: &Path) -> String {
    arg.replace("{python}", &bin.join("python").to_string_lossy())
        .replace("{oracle}", &bin.to_string_lossy())
}

/// A running stand-in tenant; killed when dropped.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Records *scenario* with the oracle in *bin*.
pub fn record(scenario: &Scenario, repo: &Path, bin: &Path) -> Result<Cassette> {
    let secrets: BTreeMap<String, String> = scenario
        .secrets
        .iter()
        .map(|name| (name.clone(), random_secret()))
        .collect();
    let scratch = tempfile::tempdir().context("make a scratch directory")?;
    let home = scratch.path().join("home");
    let work = scratch.path().join("work");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&work)?;
    let base_env = |command: &mut Command| {
        command
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", &home)
            .env("LANG", "C.UTF-8")
            .env("TZ", "UTC")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .envs(&secrets);
    };
    let mut routes = BTreeMap::new();
    let _tenant = if scenario.tenant.is_empty() {
        None
    } else {
        let mut command = Command::new(expand(&scenario.tenant[0], bin));
        command
            .args(scenario.tenant[1..].iter().map(|arg| expand(arg, bin)))
            .current_dir(repo)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        base_env(&mut command);
        let mut child = Child(command.spawn().context("start the stand-in tenant")?);
        let stdout = child.0.stdout.take().context("the tenant's stdout")?;
        let mut line = String::new();
        BufReader::new(stdout)
            .read_line(&mut line)
            .context("read the tenant's port")?;
        let port: u16 = line.trim().parse().context("the tenant printed no port")?;
        for host in &scenario.routes {
            routes.insert(host.clone(), format!("http://127.0.0.1:{port}"));
        }
        Some(child)
    };
    let proxy = Proxy::start(
        Mode::Record { routes },
        Redaction::new(secrets.values().cloned()),
    )
    .map_err(|error| anyhow::anyhow!("start the recording proxy: {error}"))?;
    let ca = scratch.path().join("ca.pem");
    std::fs::write(&ca, proxy.ca_pem())?;
    let argv: Vec<String> = scenario.client.iter().map(|arg| expand(arg, bin)).collect();
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(if scenario.cwd == "repo" { repo } else { &work });
    base_env(&mut command);
    command.envs(proxy.client_env(&ca.to_string_lossy()));
    let output = command
        .output()
        .with_context(|| format!("run {}", argv[0]))?;
    if !output.status.success() {
        bail!(
            "scenario {}: the client exited with {}\nstdout: {}\nstderr: {}",
            scenario.name,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let interactions = proxy.interactions();
    if interactions.is_empty() {
        bail!(
            "scenario {}: the client sent nothing through the proxy",
            scenario.name
        );
    }
    let recorded_from: Vec<String> = scenario.client.clone();
    let cassette = Cassette::new(&scenario.name, recorded_from, interactions);
    let text = cassette.to_text();
    for (name, value) in &secrets {
        if text.contains(value.as_str()) {
            bail!(
                "scenario {}: {name}'s value survived redaction",
                scenario.name
            );
        }
    }
    Ok(cassette)
}

/// Every problem with the cassettes in *dir*.
pub fn check(dir: &Path, scenarios: &Scenarios) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let mut found: Vec<PathBuf> = Vec::new();
    collect(dir, &mut found)?;
    let expected: BTreeMap<PathBuf, &Scenario> = scenarios
        .scenario
        .iter()
        .map(|scenario| (dir.join(format!("{}.json", scenario.name)), scenario))
        .collect();
    for path in &found {
        if !expected.contains_key(path) {
            problems.push(format!(
                "{} has no scenario in scenarios.toml",
                path.display()
            ));
        }
    }
    for (path, scenario) in &expected {
        let Ok(text) = std::fs::read_to_string(path) else {
            problems.push(format!(
                "{} has no cassette: cargo xtask cassettes record {}",
                scenario.name, scenario.name
            ));
            continue;
        };
        problems.extend(
            check_text(&text, &scenario.name)
                .into_iter()
                .map(|problem| format!("{}: {problem}", path.display())),
        );
    }
    Ok(problems)
}

/// Every problem with one cassette's text.
pub fn check_text(text: &str, scenario: &str) -> Vec<String> {
    let cassette = match Cassette::parse(text) {
        Ok(cassette) => cassette,
        Err(error) => return vec![error],
    };
    let mut problems = Vec::new();
    if cassette.scenario != scenario {
        problems.push(format!(
            "records scenario {}, not {scenario}",
            cassette.scenario
        ));
    }
    if cassette.to_text() != text {
        problems.push("is not laid out as the recorder writes it".to_owned());
    }
    let redaction = Redaction::default();
    for (index, interaction) in cassette.interactions.iter().enumerate() {
        let place = index + 1;
        let request = &interaction.request;
        if redaction.url(&request.url) != request.url {
            problems.push(format!("request {place}: its URL holds a credential"));
        }
        let headers = redaction.request_headers(
            request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        if headers != request.headers {
            problems.push(format!(
                "request {place}: a header is a secret or a transport header, or they are not sorted"
            ));
        }
        if redaction.body(&request.body.bytes()) != request.body.bytes() {
            problems.push(format!("request {place}: its body holds a secret"));
        }
        let response: &cassette::Response = &interaction.response;
        let kept = redaction.response_headers(
            response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        if kept != response.headers {
            problems.push(format!(
                "answer {place}: a header is a secret or a transport header"
            ));
        }
        if redaction.body(&response.body.bytes()) != response.body.bytes() {
            problems.push(format!("answer {place}: its body holds a secret"));
        }
    }
    problems
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_cassette::{Body, Interaction};

    fn interaction(header: (&str, &str), body: &str) -> Interaction {
        Interaction {
            request: cassette::Request {
                method: "POST".into(),
                url: "https://tenant.invalid/api".into(),
                headers: vec![(header.0.into(), header.1.into())],
                body: Body::Text(body.into()),
            },
            response: cassette::Response {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: Body::Text("{}".into()),
            },
        }
    }

    #[test]
    fn a_recorded_redacted_cassette_passes() {
        let cassette = Cassette::new(
            "s",
            vec!["client".into()],
            vec![interaction(
                ("authorization", "Bearer REDACTED"),
                "{\"a\": 1}",
            )],
        );
        assert_eq!(check_text(&cassette.to_text(), "s"), Vec::<String>::new());
    }

    #[test]
    fn a_hand_edit_a_secret_or_a_transport_header_fails() {
        let cassette = Cassette::new(
            "s",
            vec!["client".into()],
            vec![interaction(
                ("authorization", "Bearer REDACTED"),
                "{\"a\": 1}",
            )],
        );
        let edited = cassette
            .to_text()
            .replace("{\\\"a\\\": 1}", "{\\\"a\\\": 2}");
        assert_ne!(edited, cassette.to_text());
        assert!(check_text(&edited, "s")[0].contains("never edited"));
        for (header, body) in [
            (("authorization", "Bearer abc123"), "{}"),
            (("user-agent", "python-requests/2.32"), "{}"),
            (("accept", "*/*"), "{\"client_secret\": \"hunter22\"}"),
        ] {
            let leaky = Cassette::new("s", vec![], vec![interaction(header, body)]);
            assert_eq!(
                check_text(&leaky.to_text(), "s").len(),
                1,
                "{header:?} {body}"
            );
        }
        assert!(check_text(&cassette.to_text(), "other")[0].contains("not other"));
    }

    #[test]
    fn the_scenarios_parse() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/cassettes/scenarios.toml"),
        )
        .unwrap();
        let scenarios = Scenarios::parse(&text).unwrap();
        assert!(
            scenarios
                .scenario
                .iter()
                .any(|s| s.name == "mock-platform/deploy")
        );
        assert!(Scenarios::parse("[[scenario]]\nname = \"../x\"\ndescription = \"\"\nclient = [\"a\"]\ncwd = \"tmp\"\n").is_err());
    }
}
