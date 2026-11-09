//! Who is reading: a person, a pipe, an agent, a JSON parser or a protocol host.
//!
//! Resolved once per run (`docs/cli/json-output.md`, "Output modes"); the
//! first rule that matches wins:
//!
//! 1. `mcp start`, `lsp start` or `serve`: `mcp`, stdout belongs to JSON-RPC;
//! 2. `--json`: `json`;
//! 3. `OPENTIDE_OUTPUT` is `json`, `agent`, `plain` or `human`: that mode;
//! 4. a coding agent is detected: `agent`;
//! 5. stdout is not a terminal, `NO_COLOR` or `--no-color`, `TERM=dumb`, or CI: `plain`;
//! 6. otherwise `human`.

use crate::env::Env;

/// The five output modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Colour, live progress, brand marks: a person at a terminal.
    Human,
    /// Human output without colour or animation: a pipe, a file, CI.
    Plain,
    /// Plain, plus no prompts and a `--json` tip on failure: a coding agent.
    Agent,
    /// One JSON document on stdout.
    Json,
    /// Nothing but JSON-RPC on stdout.
    Mcp,
}

impl Mode {
    /// The name `OPENTIDE_OUTPUT` and the crash log use.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Human => "human",
            Mode::Plain => "plain",
            Mode::Agent => "agent",
            Mode::Json => "json",
            Mode::Mcp => "mcp",
        }
    }

    /// Whether stdout belongs to a parser (`json`) or to JSON-RPC (`mcp`).
    pub fn is_machine(self) -> bool {
        matches!(self, Mode::Json | Mode::Mcp)
    }
}

/// Command paths whose stdout carries a JSON-RPC protocol.
pub const PROTOCOL_COMMANDS: &[&[&str]] = &[&["mcp", "start"], &["lsp", "start"], &["serve"]];

/// `OPENTIDE_OUTPUT` values, in the order the catalogue lists them.
pub const OUTPUT_ENV_VALUES: &[&str] = &["agent", "human", "json", "plain"];

/// Variables a coding agent sets, read in this order. `AI_AGENT` is the
/// proposed cross-tool standard and names the agent.
pub const AGENT_VARIABLES: &[&str] = &[
    "AI_AGENT",
    "CLAUDECODE",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CODEX_CI",
    "COPILOT_AGENT",
    "COPILOT_CLI",
    "OPENCODE",
    "AMP_CURRENT_THREAD_ID",
    "AUGMENT_AGENT",
    "CLINE_ACTIVE",
];

/// CI providers by the variable each one sets.
pub const CI_PROVIDERS: &[(&str, &str)] = &[
    ("GITHUB_ACTIONS", "github"),
    ("GITLAB_CI", "gitlab"),
    ("TF_BUILD", "azure"),
];

const FALSE_VALUES: &[&str] = &["", "0", "false", "no", "off"];

fn is_set(env: &Env, name: &str) -> bool {
    env.get(name)
        .is_some_and(|value| !FALSE_VALUES.contains(&value.trim().to_lowercase().as_str()))
}

/// The coding agent running this process, if one is detected. A hint for
/// presentation only: it never relaxes a confirmation.
pub fn detect_agent(env: &Env) -> Option<String> {
    AGENT_VARIABLES
        .iter()
        .find(|name| is_set(env, name))
        .map(|name| {
            if *name == "AI_AGENT" {
                env.get(name).unwrap_or_default().trim().to_owned()
            } else {
                name.to_lowercase()
            }
        })
}

/// The CI provider, `ci` for another one, or none.
pub fn detect_ci(env: &Env) -> Option<&'static str> {
    CI_PROVIDERS
        .iter()
        .find(|(name, _)| is_set(env, name))
        .map(|(_, provider)| *provider)
        .or_else(|| is_set(env, "CI").then_some("ci"))
}

/// What the mode is resolved from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inputs<'a> {
    /// `--json` was given.
    pub json_flag: bool,
    /// `--no-color` was given.
    pub no_color: bool,
    /// The leading command words.
    pub command: &'a [String],
    /// Whether stdout is a terminal.
    pub stdout_tty: bool,
}

/// The mode, by the rules at the top of this module.
pub fn resolve(inputs: Inputs<'_>, env: &Env) -> Mode {
    let lead: Vec<&str> = inputs.command.iter().take(2).map(String::as_str).collect();
    if PROTOCOL_COMMANDS.iter().any(|path| lead == *path) {
        return Mode::Mcp;
    }
    if inputs.json_flag {
        return Mode::Json;
    }
    let requested = env
        .get("OPENTIDE_OUTPUT")
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    match requested.as_str() {
        "json" => return Mode::Json,
        "agent" => return Mode::Agent,
        "plain" => return Mode::Plain,
        "human" => return Mode::Human,
        _ => {}
    }
    if detect_agent(env).is_some() {
        return Mode::Agent;
    }
    if inputs.no_color
        || !inputs.stdout_tty
        || env.get("NO_COLOR").is_some_and(|value| !value.is_empty())
        || env
            .get("TERM")
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("dumb")
        || detect_ci(env).is_some()
    {
        return Mode::Plain;
    }
    Mode::Human
}

/// Whether a JSON document is indented: on a terminal, unless
/// `OPENTIDE_JSON_INDENT` is `0` (one line) or `2` (indented). Any other value
/// is ignored.
pub fn json_indent(env: &Env, stdout_tty: bool) -> bool {
    match env.get("OPENTIDE_JSON_INDENT").map(str::trim) {
        Some("0") => false,
        Some("2") => true,
        _ => stdout_tty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().copied())
    }

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    fn mode(json: bool, command: &str, tty: bool, pairs: &[(&str, &str)]) -> Mode {
        let command = words(command);
        resolve(
            Inputs {
                json_flag: json,
                no_color: false,
                command: &command,
                stdout_tty: tty,
            },
            &env(pairs),
        )
    }

    #[test]
    fn framework_mode_protocol_commands_win_over_everything() {
        assert_eq!(mode(true, "mcp start", true, &[]), Mode::Mcp);
        assert_eq!(mode(true, "lsp start", true, &[]), Mode::Mcp);
        assert_eq!(
            mode(false, "serve", false, &[("OPENTIDE_OUTPUT", "json")]),
            Mode::Mcp
        );
        assert_eq!(mode(false, "mcp", true, &[]), Mode::Human);
        assert_eq!(mode(false, "server", true, &[]), Mode::Human);
        assert_eq!(mode(false, "serve now", true, &[]), Mode::Human);
        assert_eq!(mode(false, "mcp start now", true, &[]), Mode::Mcp);
    }

    #[test]
    fn framework_mode_json_flag_then_opentide_output() {
        assert_eq!(
            mode(true, "validate", true, &[("OPENTIDE_OUTPUT", "plain")]),
            Mode::Json
        );
        for (value, expected) in [
            ("json", Mode::Json),
            (" Agent ", Mode::Agent),
            ("plain", Mode::Plain),
            ("human", Mode::Human),
        ] {
            assert_eq!(
                mode(
                    false,
                    "x",
                    false,
                    &[("OPENTIDE_OUTPUT", value), ("AI_AGENT", "a")]
                ),
                expected
            );
        }
        // An unknown value is ignored.
        assert_eq!(
            mode(false, "x", true, &[("OPENTIDE_OUTPUT", "mcp")]),
            Mode::Human
        );
    }

    #[test]
    fn framework_mode_agents_are_detected_in_order() {
        assert_eq!(mode(false, "x", true, &[("CLAUDECODE", "1")]), Mode::Agent);
        assert_eq!(mode(false, "x", true, &[("CLAUDECODE", "0")]), Mode::Human);
        assert_eq!(
            detect_agent(&env(&[("AI_AGENT", " codex "), ("CLAUDECODE", "1")])).as_deref(),
            Some("codex")
        );
        assert_eq!(
            detect_agent(&env(&[("CLINE_ACTIVE", "true")])).as_deref(),
            Some("cline_active")
        );
        assert_eq!(detect_agent(&env(&[("CURSOR_AGENT", "off")])), None);
    }

    #[test]
    fn framework_mode_plain_without_a_terminal_colour_or_in_ci() {
        assert_eq!(mode(false, "x", false, &[]), Mode::Plain);
        assert_eq!(mode(false, "x", true, &[("NO_COLOR", "1")]), Mode::Plain);
        assert_eq!(mode(false, "x", true, &[("NO_COLOR", "")]), Mode::Human);
        assert_eq!(mode(false, "x", true, &[("TERM", "dumb")]), Mode::Plain);
        assert_eq!(mode(false, "x", true, &[("CI", "true")]), Mode::Plain);
        assert_eq!(
            mode(false, "x", true, &[("GITHUB_ACTIONS", "true")]),
            Mode::Plain
        );
        let none: Vec<String> = Vec::new();
        let no_color = Inputs {
            json_flag: false,
            no_color: true,
            command: &none,
            stdout_tty: true,
        };
        assert_eq!(resolve(no_color, &env(&[])), Mode::Plain);
    }

    #[test]
    fn framework_mode_ci_providers() {
        assert_eq!(detect_ci(&env(&[("GITLAB_CI", "true")])), Some("gitlab"));
        assert_eq!(detect_ci(&env(&[("TF_BUILD", "True")])), Some("azure"));
        assert_eq!(detect_ci(&env(&[("CI", "1")])), Some("ci"));
        assert_eq!(detect_ci(&env(&[("CI", "false")])), None);
    }

    #[test]
    fn framework_json_indent_follows_the_terminal_unless_told() {
        assert!(json_indent(&env(&[]), true));
        assert!(!json_indent(&env(&[]), false));
        assert!(!json_indent(&env(&[("OPENTIDE_JSON_INDENT", "0")]), true));
        assert!(json_indent(&env(&[("OPENTIDE_JSON_INDENT", " 2 ")]), false));
        assert!(json_indent(&env(&[("OPENTIDE_JSON_INDENT", "4")]), true));
    }

    #[test]
    fn framework_mode_names() {
        for (mode, name) in [
            (Mode::Human, "human"),
            (Mode::Plain, "plain"),
            (Mode::Agent, "agent"),
            (Mode::Json, "json"),
            (Mode::Mcp, "mcp"),
        ] {
            assert_eq!(mode.as_str(), name);
            assert_eq!(mode.is_machine(), matches!(mode, Mode::Json | Mode::Mcp));
        }
    }
}
