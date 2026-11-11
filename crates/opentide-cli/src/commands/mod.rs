//! The commands that run on this crate (UC-2.4: `info`, `rules unreviewed`).
//!
//! A command reads its arguments and the workspace and returns a
//! [`Report`]: the JSON envelope's parts, and what the text modes print
//! before the outcome line. `app::Run::emit_report` writes it in the run's
//! mode.

pub mod doctor;
pub mod generate;
pub mod info;
pub mod migrate;
pub mod rules;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_workspace::{OsFs, RootOptions, Workspace, root};

use crate::env::Env;
use crate::envelope::{Failure, NextAction, Outcome, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::render::outcome::OutcomeKind;
use crate::render::text::Text;

/// `failure.code` of a command that stopped on an error of its own.
pub const COMMAND_FAILED: &str = "command_failed";
/// `failure.code` of a run that found problems and was asked to fail on them.
pub const ISSUES_FOUND: &str = "issues_found";

/// What a command prints.
#[derive(Clone, Debug)]
pub struct Report {
    /// The envelope's parts.
    pub outcome: Outcome,
    /// `warning:` lines, and the document's `warnings`.
    pub warnings: Vec<String>,
    /// The outcome line, when it is not the message.
    pub outcome_line: Option<String>,
    /// The outcome line's kind, when the status does not say it.
    pub outcome_kind: Option<OutcomeKind>,
    /// What the text modes print on stdout before the outcome line.
    pub body: Vec<Block>,
    /// The checklist's steps, printed on stderr before anything else.
    pub steps: Vec<crate::render::progress::Step>,
}

/// One part of a body.
#[derive(Clone, Debug)]
pub enum Block {
    /// Lines, wrapped at the stream's width when wider.
    Lines(Vec<Text>),
    /// A table, laid out at the stream's width.
    Table(crate::render::table::Table),
    /// Lines wrapped at words on a terminal, each with the indent its
    /// continued rows take (`doctor`'s checklist).
    Hanging(Vec<(Text, usize)>),
}

impl Report {
    /// A successful report.
    pub fn completed(command: &str, data: Vec<(String, Json)>) -> Report {
        Report {
            outcome: Outcome {
                command: command.to_owned(),
                status: "completed".into(),
                message: "Completed successfully".into(),
                data,
                exit_code: 0,
                summary: Vec::new(),
                next_actions: Vec::new(),
                failure: None,
            },
            warnings: Vec::new(),
            outcome_line: None,
            outcome_kind: None,
            body: Vec::new(),
            steps: Vec::new(),
        }
    }

    /// A failure, with `failure.code` `code`.
    pub fn failed(command: &str, exit_code: i32, failure: Failure) -> Report {
        Report {
            outcome: Outcome::failed(command, exit_code, failure),
            warnings: Vec::new(),
            outcome_line: None,
            outcome_kind: None,
            body: Vec::new(),
            steps: Vec::new(),
        }
    }

    /// A usage error the command found itself: exit 2, with `argument` and
    /// the choice closest to `value` (`opentide_core::suggest`).
    pub fn usage(
        command: &str,
        message: impl Into<String>,
        failure_code: &str,
        argument: &str,
        value: Option<&str>,
        choices: &[&str],
    ) -> Report {
        let mut failure = Failure::new(failure_code, message);
        failure.argument = Some(argument.to_owned());
        failure.suggestion = value
            .and_then(|value| {
                opentide_core::suggest::closest(value, choices.iter().copied())
                    .filter(|choice| *choice != value)
            })
            .map(str::to_owned);
        Report::failed(command, USAGE_EXIT_CODE, failure)
    }

    /// An error the command stopped on: exit 1, `command_failed`.
    pub fn error(command: &str, message: impl Into<String>) -> Report {
        Report::failed(command, 1, Failure::new(COMMAND_FAILED, message))
    }

    /// Adds a next step.
    pub fn next(&mut self, command: &str, reason: &str) {
        self.outcome
            .next_actions
            .push(NextAction::new(command, reason));
    }
}

/// `code`'s re-exports the commands use.
pub use code::{USAGE_INVALID_CHOICE, USAGE_INVALID_VALUE, USAGE_MISSING_OPTION};

/// `value` serialised and read back as an order-keeping [`Json`].
pub fn json<T: serde::Serialize>(value: &T) -> Json {
    serde_json::to_string(value)
        .ok()
        .and_then(|text| Json::parse(&text).ok())
        .unwrap_or(Json::Null)
}

/// Where a run's workspace is, as the oracle's context places it: the
/// repository (`--repo`, else `OPENTIDE_REPO_ROOT`, else the nearest
/// workspace root) as it prints it, and the options that open it, with
/// `OPENTIDE_REPO_ROOT` and `OPENTIDE_TIDE_WORKSPACE` set as
/// `apply_environment` sets them.
pub fn placement(repo: Option<&str>, env: &Env, cwd: &Path) -> (String, RootOptions) {
    let from_env = |name: &str| env.get(name).filter(|value| !value.is_empty());
    let given = repo.or_else(|| from_env("OPENTIDE_REPO_ROOT"));
    let shown = match given {
        Some(text) => text.to_owned(),
        None => root::find_workspace_root(&OsFs, cwd)
            .to_string_lossy()
            .into_owned(),
    };
    let repo_path = PathBuf::from(&shown);
    let tide_workspace = if repo.is_some() || from_env("OPENTIDE_TIDE_WORKSPACE").is_none() {
        Some(repo_path.clone())
    } else {
        from_env("OPENTIDE_TIDE_WORKSPACE").map(PathBuf::from)
    };
    let options = RootOptions {
        repo: Some(repo_path.clone()),
        repo_root_env: Some(repo_path),
        tide_workspace_env: tide_workspace,
        cwd: cwd.to_path_buf(),
    };
    (shown, options)
}

/// Opens the workspace `options` place, on disk.
///
/// # Errors
///
/// The configuration does not resolve: the message.
pub fn open(options: RootOptions) -> Result<Workspace, String> {
    Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options { roots: options },
    )
    .map_err(|error| error.to_string())
}

/// `count noun`, with an `s` unless the count is one.
pub fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        assert_eq!(counted(1, "rule"), "1 rule");
        assert_eq!(counted(0, "rule"), "0 rules");
    }

    #[test]
    fn usage_errors_suggest_the_closest_choice() {
        let report = Report::usage(
            "info",
            "bad",
            USAGE_INVALID_CHOICE,
            "section",
            Some("rulez"),
            &["rules", "threats"],
        );
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.suggestion.as_deref(), Some("rules"));
        assert_eq!(failure.argument.as_deref(), Some("section"));
        assert_eq!(report.outcome.exit_code, 2);
        let none = Report::usage(
            "info",
            "bad",
            USAGE_INVALID_CHOICE,
            "section",
            Some("zzzzzz"),
            &["rules"],
        );
        assert_eq!(none.outcome.failure.unwrap().suggestion, None);
    }
}
