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
  record <name>… [--oracle FILE]
                   record the scenarios named (all with --all) from the oracle
                   of tests/golden/ORACLE, or of FILE (tests/golden/ORACLE.next)
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
    /// The exit code the client ends with (0 unless set): a command line
    /// whose run fails by design (`validate query --live` with a query the
    /// tenant refuses) is recorded only when it exits with this code.
    #[serde(default)]
    pub exit: i32,
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
            let mut all = false;
            let mut oracle_file = layout.golden.join("ORACLE");
            let mut names: Vec<&String> = Vec::new();
            let mut args = rest.iter();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--all" => all = true,
                    "--oracle" => {
                        let Some(file) = args.next() else {
                            eprint!("cassettes record: --oracle needs a file\n\n{USAGE}");
                            return Ok(2);
                        };
                        oracle_file = PathBuf::from(file);
                    }
                    other if other.starts_with("--") => {
                        eprint!("cassettes record: unknown option `{other}`\n\n{USAGE}");
                        return Ok(2);
                    }
                    _ => names.push(arg),
                }
            }
            let chosen: Vec<&Scenario> = scenarios
                .scenario
                .iter()
                .filter(|scenario| all || names.contains(&&scenario.name))
                .collect();
            if chosen.is_empty() || (!all && chosen.len() != names.len()) {
                eprint!("cassettes record: name scenarios of scenarios.toml, or --all\n\n{USAGE}");
                return Ok(2);
            }
            let (oracle, oracle_dir) = Oracle::read_file(&oracle_file)?;
            let engine = oracle.provision(&oracle_dir, &oracle::cache_dir(&layout.target))?;
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
    if output.status.code() != Some(scenario.exit) {
        bail!(
            "scenario {}: the client exited with {}, not {}\nstdout: {}\nstderr: {}",
            scenario.name,
            output.status,
            scenario.exit,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // What the client printed (the outcomes a scenario's Rust test expects).
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        eprintln!("cassettes record: {}: {line}", scenario.name);
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
            (
                ("accept", "application/json"),
                "{\"client_secret\": \"hunter22\"}",
            ),
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

    fn scenario_toml(name: &str, client: &str, cwd: &str) -> String {
        format!(
            "[[scenario]]\nname = \"{name}\"\ndescription = \"d\"\nclient = {client}\ncwd = \"{cwd}\"\n"
        )
    }

    fn parse_error(text: &str) -> String {
        format!("{:#}", Scenarios::parse(text).unwrap_err())
    }

    #[test]
    fn a_scenario_list_breaking_a_rule_is_refused_with_the_rule() {
        let good = scenario_toml("a/b_c-1", "[\"x\"]", "repo");
        assert_eq!(Scenarios::parse(&good).unwrap().scenario[0].name, "a/b_c-1");

        for name in ["a//b", "/a", "a/", "a b", "a/../b", "a.b"] {
            assert!(
                parse_error(&scenario_toml(name, "[\"x\"]", "tmp"))
                    .contains("is not a relative path of plain words"),
                "{name}"
            );
        }
        let twice = format!("{good}{good}");
        assert!(parse_error(&twice).contains("scenario a/b_c-1 is listed twice"));
        assert!(parse_error(&scenario_toml("a", "[\"x\"]", "home")).contains("cwd is repo or tmp"));
        assert!(parse_error(&scenario_toml("a", "[]", "tmp")).contains("client is empty"));
        assert!(
            parse_error(&format!("{good}colour = \"red\"\n")).contains("parse scenarios.toml"),
            "an unknown key is refused"
        );
        assert!(parse_error("[[scenario]]\nname = \"a\"\n").contains("parse scenarios.toml"));
    }

    #[test]
    fn placeholders_name_the_oracles_interpreter_and_bin_directory() {
        let bin = Path::new("/opt/oracle/bin");
        assert_eq!(
            expand("{python}", bin),
            bin.join("python").to_string_lossy()
        );
        assert_eq!(
            expand("{oracle}/opentide", bin),
            format!("{}/opentide", bin.display())
        );
        assert_eq!(expand("--json", bin), "--json");
    }

    #[test]
    fn each_secret_is_a_fresh_marked_value() {
        let first = random_secret();
        let second = random_secret();
        assert_ne!(first, second);
        for value in [&first, &second] {
            let hex = value.strip_prefix("rec-").expect("marked rec-");
            assert_eq!(hex.len(), 32, "{value}");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{value}");
        }
    }

    fn write_cassette(dir: &Path, name: &str, scenario: &str) {
        let path = dir.join(format!("{name}.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let cassette = Cassette::new(
            scenario,
            vec!["client".into()],
            vec![interaction(("accept", "application/json"), "{}")],
        );
        std::fs::write(path, cassette.to_text()).unwrap();
    }

    #[test]
    fn the_check_pairs_each_scenario_with_its_cassette() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let scenarios = Scenarios::parse(&format!(
            "{}{}{}",
            scenario_toml("good", "[\"x\"]", "tmp"),
            scenario_toml("nested/good", "[\"x\"]", "tmp"),
            scenario_toml("missing", "[\"x\"]", "tmp"),
        ))
        .unwrap();
        // A clean cassette at the top and in a folder, and nothing for
        // `missing`: only `missing` is reported.
        write_cassette(dir, "good", "good");
        write_cassette(dir, "nested/good", "nested/good");
        std::fs::write(dir.join("scenarios.toml"), "not a cassette").unwrap();
        std::fs::write(dir.join("nested/README.md"), "notes").unwrap();
        assert_eq!(
            check(dir, &scenarios).unwrap(),
            ["missing has no cassette: cargo xtask cassettes record missing"]
        );

        // A cassette no scenario names, and one recording another scenario.
        write_cassette(dir, "missing", "missing");
        write_cassette(dir, "nested/stray", "stray");
        write_cassette(dir, "good", "other");
        let problems = check(dir, &scenarios).unwrap();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert_eq!(
            problems[0],
            format!(
                "{} has no scenario in scenarios.toml",
                dir.join("nested").join("stray.json").display()
            )
        );
        assert_eq!(
            problems[1],
            format!(
                "{}: records scenario other, not good",
                dir.join("good.json").display()
            )
        );

        // A folder that is not there cannot be checked.
        let error = check(&dir.join("absent"), &scenarios).unwrap_err();
        assert!(format!("{error:#}").contains("read "), "{error:#}");
    }

    fn words(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn the_command_line_exit_statuses() {
        assert_eq!(run(&[]).unwrap(), 2, "no command");
        assert_eq!(run(&words(&["frobnicate"])).unwrap(), 2);
        assert_eq!(run(&words(&["help"])).unwrap(), 0);
        assert_eq!(run(&words(&["list"])).unwrap(), 0);
        // The repository's cassettes are recorded and redacted (a Windows
        // checkout may convert their line endings, which the check refuses).
        if !cfg!(windows) {
            assert_eq!(run(&words(&["check"])).unwrap(), 0);
        }
        // `record` names scenarios of scenarios.toml, every one known, before
        // it provisions the oracle.
        assert_eq!(run(&words(&["record"])).unwrap(), 2);
        assert_eq!(run(&words(&["record", "no-such-scenario"])).unwrap(), 2);
        assert_eq!(
            run(&words(&["record", "skills/manifest", "no-such-scenario"])).unwrap(),
            2
        );
    }

    #[cfg(unix)]
    fn scenario(client: &[&str], tenant: &[&str], cwd: &str) -> Scenario {
        Scenario {
            name: "s".into(),
            description: String::new(),
            client: words(client),
            tenant: words(tenant),
            routes: vec!["tenant.invalid".into()],
            secrets: vec!["SCENARIO_TOKEN".into()],
            cwd: cwd.into(),
            exit: 0,
        }
    }

    #[cfg(unix)]
    fn record_error(scenario: &Scenario, repo: &Path) -> String {
        format!(
            "{:#}",
            record(scenario, repo, Path::new("/nonexistent/bin")).unwrap_err()
        )
    }

    #[cfg(unix)]
    #[test]
    fn a_client_that_fails_is_reported_with_what_it_printed() {
        let repo = tempfile::tempdir().unwrap();
        // The client runs in a clean environment: its own HOME, the secret
        // set to a fresh value, the proxy variables, nothing inherited.
        let error = record_error(
            &scenario(
                &[
                    "/bin/sh",
                    "-c",
                    "pwd; echo \"token=$SCENARIO_TOKEN home=$HOME proxy=${HTTPS_PROXY:+set} \
                     cargo=${CARGO:-unset}\"; echo oops >&2; exit 3",
                ],
                &[],
                "repo",
            ),
            repo.path(),
        );
        assert!(
            error.starts_with("scenario s: the client exited with"),
            "{error}"
        );
        assert!(error.contains("stderr: oops"), "{error}");
        let canonical = repo.path().canonicalize().unwrap();
        assert!(
            error.contains(&format!("stdout: {}\n", canonical.display()))
                || error.contains(&format!("stdout: {}\n", repo.path().display())),
            "cwd repo runs in the repository: {error}"
        );
        assert!(error.contains("token=rec-"), "{error}");
        assert!(error.contains("proxy=set"), "{error}");
        assert!(error.contains("cargo=unset"), "{error}");
        assert!(
            error.contains("/home proxy=set"),
            "HOME is the scratch home: {error}"
        );

        // `tmp` runs in an empty scratch folder, not the repository.
        let error = record_error(
            &scenario(&["/bin/sh", "-c", "pwd; ls -A; exit 1"], &[], "tmp"),
            repo.path(),
        );
        assert!(error.contains("/work\n"), "{error}");
        assert!(
            !error.contains(&repo.path().display().to_string()),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_client_must_exit_with_the_scenarios_code() {
        let repo = tempfile::tempdir().unwrap();
        let mut failing = scenario(&["/bin/sh", "-c", "exit 1"], &[], "tmp");
        let error = record_error(&failing, repo.path());
        assert!(error.contains("the client exited with"), "{error}");
        assert!(error.contains(", not 0"), "{error}");
        // Expected to fail: the run goes on to the proxy, which saw nothing.
        failing.exit = 1;
        assert_eq!(
            record_error(&failing, repo.path()),
            "scenario s: the client sent nothing through the proxy"
        );
        let parsed = Scenarios::parse(
            "[[scenario]]\nname = \"a/b\"\ndescription = \"\"\nclient = [\"x\"]\ncwd = \"tmp\"\nexit = 1\n",
        )
        .unwrap();
        assert_eq!(parsed.scenario[0].exit, 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_client_that_sends_nothing_records_nothing() {
        let repo = tempfile::tempdir().unwrap();
        let error = record_error(
            &scenario(&["/bin/sh", "-c", "echo done"], &[], "tmp"),
            repo.path(),
        );
        assert_eq!(
            error,
            "scenario s: the client sent nothing through the proxy"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_tenant_must_start_and_print_its_port() {
        let repo = tempfile::tempdir().unwrap();
        let client = ["/bin/sh", "-c", "exit 0"];
        let error = record_error(
            &scenario(&client, &["/bin/sh", "-c", "echo listening"], "tmp"),
            repo.path(),
        );
        assert!(error.starts_with("the tenant printed no port"), "{error}");
        let error = record_error(
            &scenario(&client, &["/nonexistent/tenant"], "tmp"),
            repo.path(),
        );
        assert!(error.starts_with("start the stand-in tenant"), "{error}");
        // A tenant that prints its port is started and its hosts routed; the
        // client then sending nothing is the failure.
        let error = record_error(
            &scenario(
                &client,
                &["/bin/sh", "-c", "echo 40000; exec sleep 30"],
                "tmp",
            ),
            repo.path(),
        );
        assert_eq!(
            error,
            "scenario s: the client sent nothing through the proxy"
        );
    }
}
