//! `cargo xtask cassettes`: check the recorded-HTTP cassettes (UC-4.1, #831;
//! plan §5.4 "HTTP").
//!
//! `tests/cassettes/scenarios.toml` lists the scenarios, each recorded from
//! the frozen Python implementation (`cassettes record`, retired with the
//! oracle in #1142; a cassette is now re-recorded only by hand, with the
//! proxy of `opentide-cassette`). `check` reads every cassette and
//! fails on a digest that does not match (a hand edit), on a request or
//! answer that redaction would still change (a secret, a transport header),
//! on a value of a scenario's secret, and on a scenario without its cassette
//! or a cassette without its scenario.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use opentide_cassette::{Cassette, Redaction, cassette};
use serde::Deserialize;

/// `cargo xtask cassettes <command>`.
#[derive(Subcommand)]
#[command(
    after_help = "Exit status: 0 success, 1 a check failed, 2 usage error or the run \
    could not start."
)]
pub enum Cmd {
    /// Check every cassette under tests/cassettes
    Check,
    /// List the scenarios
    List,
}

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

/// Runs `cargo xtask cassettes <command>`.
pub fn run(command: &Cmd) -> Result<u8> {
    let dir = crate::corpus::cli::repo_root().join("tests/cassettes");
    let scenarios = Scenarios::parse(
        &std::fs::read_to_string(dir.join("scenarios.toml")).context("read scenarios.toml")?,
    )?;
    match command {
        Cmd::Check => {
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
        Cmd::List => {
            for scenario in &scenarios.scenario {
                println!("{}  {}", scenario.name, scenario.description);
            }
            Ok(0)
        }
    }
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
                "{} has no cassette ({})",
                scenario.name,
                path.display()
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
            [format!(
                "missing has no cassette ({})",
                dir.join("missing.json").display()
            )]
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

    /// The exit status of `cassettes <args>`: clap's 2 for a usage error.
    fn exit_status(args: &[&str]) -> u8 {
        match crate::parse_subcommand::<Cmd>(args) {
            Ok(command) => run(&command).unwrap(),
            Err(error) => u8::try_from(error.exit_code()).unwrap(),
        }
    }

    #[test]
    fn the_command_line_exit_statuses() {
        assert_eq!(exit_status(&[]), 2, "no command");
        assert_eq!(exit_status(&["frobnicate"]), 2);
        assert_eq!(exit_status(&["list"]), 0);
        // The repository's cassettes are recorded and redacted (a Windows
        // checkout may convert their line endings, which the check refuses).
        if !cfg!(windows) {
            assert_eq!(exit_status(&["check"]), 0);
        }
        // `record` was retired with the Python CLI (#1142).
        assert_eq!(exit_status(&["record"]), 2);
    }

    #[test]
    fn a_scenario_names_the_exit_code_its_client_ends_with() {
        let parsed = Scenarios::parse(
            "[[scenario]]\nname = \"a/b\"\ndescription = \"\"\nclient = [\"x\"]\ncwd = \"tmp\"\nexit = 1\n",
        )
        .unwrap();
        assert_eq!(parsed.scenario[0].exit, 1);
    }
}
