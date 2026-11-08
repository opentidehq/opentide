//! The case model: the reviewed specification (`tests/golden/cases.toml`)
//! and the cases it expands to, one per command, variant, mode and fixture.
//!
//! A [`Case`] is everything needed to run one invocation again: argv, the
//! full environment, standard input, the fixture and the mode. Its
//! `case.toml` is written next to the recording, so a reviewer sees exactly
//! what ran, and the comparator (UC-0.7) runs the same [`Case`] through
//! another engine.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The program name every argv starts with.
pub const PROGRAM: &str = "opentide";

/// Placeholder for the engine's directory of executables in `PATH`.
pub const ENGINE_BIN: &str = "<ENGINE_BIN>";
/// Placeholder for the case's workspace (the fixture copy, the working directory).
pub const WS: &str = "<WS>";
/// Placeholder for the case's home directory.
pub const HOME: &str = "<HOME>";
/// Placeholder for the case's private root, which holds `ws/`, `home/` and `tmp/`.
pub const TMP: &str = "<TMP>";

/// An output mode the goldens record. `mcp` belongs to UC-3.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A pseudo-terminal of 100 columns on stdin, stdout and stderr.
    Human,
    /// Pipes; the mode a non-terminal resolves to.
    Plain,
    /// Pipes and `--json` right after the program name.
    Json,
    /// Pipes and an agent detected (`AI_AGENT`).
    Agent,
}

impl Mode {
    /// Every mode, in report order.
    pub const ALL: [Mode; 4] = [Mode::Human, Mode::Plain, Mode::Json, Mode::Agent];

    /// The name used in paths, `cases.toml` and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Human => "human",
            Mode::Plain => "plain",
            Mode::Json => "json",
            Mode::Agent => "agent",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the program reads on standard input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StdinKind {
    /// `/dev/null`: not a terminal, end of file at once.
    Null,
    /// A pipe that carries `input`, then end of file.
    Pipe,
    /// A pseudo-terminal that carries `input`, then the end-of-file character (human mode).
    Tty,
}

/// Standard input of a case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stdin {
    /// The kind of file standard input is.
    pub kind: StdinKind,
    /// The bytes written to it before end of file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub input: String,
}

/// An extra normalisation rule a case opts into (`normalise` in `cases.toml`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rule {
    /// UUIDs that the fixture does not contain become `<UUID-1>`, `<UUID-2>`, …
    /// in order of first appearance: for commands that mint identifiers.
    FreshUuids,
}

/// One recorded invocation: the contents of its `case.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Case {
    /// `<command>/<mode>/<fixture>/<variant>`: the recording's directory under `cases/`.
    pub id: String,
    /// The command path as `opentide --json commands` names it; empty for the root.
    pub command: String,
    /// The name of this argument set among the command's cases.
    pub variant: String,
    /// The output mode.
    pub mode: Mode,
    /// The fixture workspace's name (`[fixtures]` in `cases.toml`).
    pub fixture: String,
    /// The full argv; `argv[0]` is `opentide`, found on `PATH`.
    pub argv: Vec<String>,
    /// The working directory, relative to the workspace.
    pub cwd: String,
    /// The complete environment: nothing else is inherited. Values may hold
    /// the placeholders `<ENGINE_BIN>`, `<WS>`, `<HOME>` and `<TMP>`.
    pub env: BTreeMap<String, String>,
    /// Standard input.
    pub stdin: Stdin,
    /// Seconds before the case is killed and fails.
    pub timeout_secs: u64,
    /// Extra normalisation rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normalise: Vec<Rule>,
}

impl Case {
    /// The directory name of a command path: words joined by `.`, `_root` for the root.
    pub fn command_dir(command: &str) -> String {
        if command.is_empty() {
            "_root".to_owned()
        } else {
            command.split(' ').collect::<Vec<_>>().join(".")
        }
    }

    /// Parses a `case.toml`.
    pub fn parse(text: &str) -> Result<Case> {
        toml::from_str(text).context("parse case.toml")
    }

    /// Renders the `case.toml`, with a header that says it is generated.
    pub fn render(&self) -> Result<String> {
        let body = toml::to_string(self).context("serialise case.toml")?;
        Ok(format!(
            "# Generated by `cargo xtask golden record` from tests/golden/cases.toml: never edit.\n{body}"
        ))
    }
}

/// `tests/golden/cases.toml`: the reviewed source of every case.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    /// Values a `[[case]]` takes unless it sets its own.
    pub defaults: Defaults,
    /// The fixture workspaces by name.
    pub fixtures: BTreeMap<String, crate::golden::fixture::FixtureSpec>,
    /// The cases.
    #[serde(rename = "case")]
    pub cases: Vec<CaseSpec>,
}

/// `[defaults]` in `cases.toml`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Modes a case runs in.
    pub modes: Vec<Mode>,
    /// Fixtures a case runs against.
    pub fixtures: Vec<String>,
    /// Seconds before a case is killed.
    pub timeout_secs: u64,
}

/// One `[[case]]`: an argument set, expanded over modes and fixtures.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    /// The command path the case covers (`""` for the root).
    pub command: String,
    /// A name unique among the command's cases.
    pub variant: String,
    /// The arguments after `opentide`. `{name}` is replaced by the fixture's
    /// variable `name`; a fixture without it is left out of this case.
    pub args: Vec<String>,
    /// Modes, instead of the defaults.
    #[serde(default)]
    pub modes: Option<Vec<Mode>>,
    /// Fixtures, instead of the defaults.
    #[serde(default)]
    pub fixtures: Option<Vec<String>>,
    /// Environment variables added to (or replacing) the base environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Bytes written to standard input before end of file.
    #[serde(default)]
    pub input: String,
    /// The working directory, relative to the workspace.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Seconds before the case is killed, instead of the default.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Extra normalisation rules.
    #[serde(default)]
    pub normalise: Vec<Rule>,
}

impl Spec {
    /// Parses and checks `cases.toml`.
    pub fn parse(text: &str) -> Result<Spec> {
        let spec: Spec = toml::from_str(text).context("parse tests/golden/cases.toml")?;
        spec.check()?;
        Ok(spec)
    }

    fn check(&self) -> Result<()> {
        for name in &self.defaults.fixtures {
            ensure!(
                self.fixtures.contains_key(name),
                "[defaults] names fixture `{name}`, which [fixtures] does not define"
            );
        }
        let mut seen = BTreeSet::new();
        for case in &self.cases {
            let key = (case.command.clone(), case.variant.clone());
            ensure!(
                seen.insert(key),
                "two cases of `{}` are named `{}`",
                case.command,
                case.variant
            );
            ensure!(
                !case.variant.is_empty()
                    && case
                        .variant
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "case `{}` variant `{}`: use letters, digits, `-` and `_`",
                case.command,
                case.variant
            );
            for name in case.fixtures.iter().flatten() {
                ensure!(
                    self.fixtures.contains_key(name),
                    "case `{} {}` names fixture `{name}`, which [fixtures] does not define",
                    case.command,
                    case.variant
                );
            }
        }
        Ok(())
    }

    /// Every case, in a stable order (command, variant, mode, fixture as listed).
    pub fn expand(&self) -> Result<Vec<Case>> {
        let mut out = Vec::new();
        for spec in &self.cases {
            let before = out.len();
            let modes = spec.modes.as_ref().unwrap_or(&self.defaults.modes);
            let fixtures = spec.fixtures.as_ref().unwrap_or(&self.defaults.fixtures);
            for &mode in modes {
                for fixture in fixtures {
                    let vars = &self.fixtures[fixture].vars;
                    let Some(args) = substitute(&spec.args, vars) else {
                        continue;
                    };
                    out.push(build(spec, mode, fixture, args, self.defaults.timeout_secs));
                }
            }
            if out.len() == before {
                bail!(
                    "case `{} {}` expands to no fixture: every listed fixture lacks a variable it uses",
                    spec.command,
                    spec.variant
                );
            }
        }
        Ok(out)
    }
}

/// Replaces `{name}` in each argument; `None` when a variable is missing.
fn substitute(args: &[String], vars: &BTreeMap<String, String>) -> Option<Vec<String>> {
    args.iter()
        .map(|arg| {
            let mut result = String::new();
            let mut rest = arg.as_str();
            while let Some(start) = rest.find('{') {
                let end = rest[start..].find('}')? + start;
                result.push_str(&rest[..start]);
                result.push_str(vars.get(&rest[start + 1..end])?);
                rest = &rest[end + 1..];
            }
            result.push_str(rest);
            Some(result)
        })
        .collect()
}

fn build(spec: &CaseSpec, mode: Mode, fixture: &str, arguments: Vec<String>, timeout: u64) -> Case {
    let mut argv = vec![PROGRAM.to_owned()];
    if mode == Mode::Json && !arguments.iter().any(|arg| arg == "--json") {
        argv.push("--json".to_owned());
    }
    argv.extend(arguments);
    let mut env = base_env(mode);
    env.extend(spec.env.clone());
    let stdin = match (mode, spec.input.is_empty()) {
        (Mode::Human, _) => Stdin {
            kind: StdinKind::Tty,
            input: spec.input.clone(),
        },
        (_, true) => Stdin {
            kind: StdinKind::Null,
            input: String::new(),
        },
        (_, false) => Stdin {
            kind: StdinKind::Pipe,
            input: spec.input.clone(),
        },
    };
    let mut normalise = spec.normalise.clone();
    normalise.sort();
    normalise.dedup();
    Case {
        id: format!(
            "{}/{}/{}/{}",
            Case::command_dir(&spec.command),
            mode,
            fixture,
            spec.variant
        ),
        command: spec.command.clone(),
        variant: spec.variant.clone(),
        mode,
        fixture: fixture.to_owned(),
        argv,
        cwd: spec.cwd.clone().unwrap_or_else(|| ".".to_owned()),
        env,
        stdin,
        timeout_secs: spec.timeout_secs.unwrap_or(timeout),
        normalise,
    }
}

/// The environment every case starts from; nothing is inherited.
///
/// Network access goes to a proxy on the discard port of the loopback
/// interface, which refuses every connection: a tenant-contacting path is
/// recorded as its failure, the same on every machine. Git finds no
/// repository above the case's root and no user configuration.
pub fn base_env(mode: Mode) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = [
        ("PATH", format!("{ENGINE_BIN}:/usr/local/bin:/usr/bin:/bin")),
        ("HOME", HOME.to_owned()),
        ("TMPDIR", format!("{TMP}/tmp")),
        ("USER", "golden".to_owned()),
        ("LOGNAME", "golden".to_owned()),
        ("LANG", "C.UTF-8".to_owned()),
        ("LC_ALL", "C.UTF-8".to_owned()),
        ("TZ", "UTC".to_owned()),
        ("TERM", "xterm-256color".to_owned()),
        ("PYTHONHASHSEED", "0".to_owned()),
        ("PYTHONDONTWRITEBYTECODE", "1".to_owned()),
        ("HTTP_PROXY", "http://127.0.0.1:9".to_owned()),
        ("HTTPS_PROXY", "http://127.0.0.1:9".to_owned()),
        ("ALL_PROXY", "http://127.0.0.1:9".to_owned()),
        ("http_proxy", "http://127.0.0.1:9".to_owned()),
        ("https_proxy", "http://127.0.0.1:9".to_owned()),
        ("all_proxy", "http://127.0.0.1:9".to_owned()),
        ("GIT_CEILING_DIRECTORIES", TMP.to_owned()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
        ("GIT_AUTHOR_NAME", "golden".to_owned()),
        ("GIT_AUTHOR_EMAIL", "golden@example.invalid".to_owned()),
        ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z".to_owned()),
        ("GIT_COMMITTER_NAME", "golden".to_owned()),
        ("GIT_COMMITTER_EMAIL", "golden@example.invalid".to_owned()),
        ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    if mode == Mode::Agent {
        env.insert("AI_AGENT".to_owned(), "golden".to_owned());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
[defaults]
modes = ["human", "plain", "json", "agent"]
fixtures = ["corpus", "none"]
timeout_secs = 60

[fixtures.corpus]
kind = "copy"
source = "tests/fixtures/x"
vars = { threat = "00000000-0000-4000-8001-000000000001" }

[fixtures.none]
kind = "skeleton"

[[case]]
command = "validate"
variant = "default"
args = ["validate"]

[[case]]
command = "new objective"
variant = "example"
args = ["new", "objective", "--threat", "{threat}"]
modes = ["json"]
normalise = ["fresh-uuids"]

[[case]]
command = "validate"
variant = "json-after"
args = ["validate", "--json"]
modes = ["json"]
fixtures = ["none"]
env = { DEBUG = "*" }
"#;

    #[test]
    fn expands_modes_by_fixtures_and_skips_fixtures_without_a_variable() {
        let cases = Spec::parse(SPEC).unwrap().expand().unwrap();
        let ids: Vec<&str> = cases.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "validate/human/corpus/default",
                "validate/human/none/default",
                "validate/plain/corpus/default",
                "validate/plain/none/default",
                "validate/json/corpus/default",
                "validate/json/none/default",
                "validate/agent/corpus/default",
                "validate/agent/none/default",
                "new.objective/json/corpus/example",
                "validate/json/none/json-after",
            ]
        );
        let objective = &cases[8];
        assert_eq!(
            objective.argv,
            [
                "opentide",
                "--json",
                "new",
                "objective",
                "--threat",
                "00000000-0000-4000-8001-000000000001"
            ]
        );
        assert_eq!(objective.normalise, [Rule::FreshUuids]);
    }

    #[test]
    fn json_mode_adds_the_flag_once_and_modes_set_their_environment() {
        let cases = Spec::parse(SPEC).unwrap().expand().unwrap();
        let after = cases.last().unwrap();
        assert_eq!(after.argv, ["opentide", "validate", "--json"]);
        assert_eq!(after.env["DEBUG"], "*");
        let human = &cases[0];
        assert_eq!(human.stdin.kind, StdinKind::Tty);
        assert!(!human.env.contains_key("AI_AGENT"));
        let agent = &cases[6];
        assert_eq!(agent.env["AI_AGENT"], "golden");
        assert_eq!(agent.stdin.kind, StdinKind::Null);
        for case in &cases {
            assert!(!case.env.contains_key("CI"), "{}", case.id);
            assert!(!case.env.contains_key("OPENTIDE_OUTPUT"), "{}", case.id);
        }
    }

    #[test]
    fn case_toml_round_trips() {
        let cases = Spec::parse(SPEC).unwrap().expand().unwrap();
        for case in cases {
            let text = case.render().unwrap();
            assert!(text.starts_with("# Generated"));
            assert_eq!(Case::parse(&text).unwrap(), case);
        }
    }

    #[test]
    fn rejects_duplicates_unknown_fixtures_and_cases_that_expand_to_nothing() {
        let dup =
            format!("{SPEC}\n[[case]]\ncommand = \"validate\"\nvariant = \"default\"\nargs = []\n");
        assert!(
            Spec::parse(&dup)
                .unwrap_err()
                .to_string()
                .contains("two cases")
        );
        let unknown = format!(
            "{SPEC}\n[[case]]\ncommand = \"lint\"\nvariant = \"a\"\nargs = []\nfixtures = [\"nope\"]\n"
        );
        assert!(
            Spec::parse(&unknown)
                .unwrap_err()
                .to_string()
                .contains("nope")
        );
        let empty = format!(
            "{SPEC}\n[[case]]\ncommand = \"lint\"\nvariant = \"a\"\nargs = [\"{{rule}}\"]\n"
        );
        let error = Spec::parse(&empty)
            .unwrap()
            .expand()
            .unwrap_err()
            .to_string();
        assert!(error.contains("expands to no fixture"), "{error}");
    }

    #[test]
    fn command_dirs() {
        assert_eq!(Case::command_dir(""), "_root");
        assert_eq!(
            Case::command_dir("generate docs rules"),
            "generate.docs.rules"
        );
        assert_eq!(
            Case::command_dir("deploy migrate-state"),
            "deploy.migrate-state"
        );
    }
}
