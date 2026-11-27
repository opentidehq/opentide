//! A service's result, typed (#1949): what a command found, and the parts the
//! envelope takes from it, as fields rather than `_`-prefixed keys among
//! the command's own.
//!
//! [`CommandResult::report`] is the one place a result becomes a [`Report`].
//! The live check and `deploy` still build their result as keys in order,
//! with `_exit_code`, `_failure_code` and the other `_`-keys among them:
//! [`CommandResult::from_fields`] reads those, until each command builds a
//! [`CommandResult`] itself.

use super::Report;
use crate::envelope::{
    CRASH_EXIT_CODE, Failure, INTERRUPTED_EXIT_CODE, NextAction, Outcome, USAGE_EXIT_CODE,
};
use crate::json::Json;

/// The envelope's `status` (`docs/cli/json-output.md`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Status {
    /// The run did what it was asked.
    #[default]
    Completed,
    /// A check ran and found nothing wrong.
    Passed,
    /// The run found problems.
    Issues,
    /// Nothing ran.
    Skipped,
    /// The run failed.
    Failed,
}

impl Status {
    /// The status as the document writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Completed => "completed",
            Status::Passed => "passed",
            Status::Issues => "issues",
            Status::Skipped => "skipped",
            Status::Failed => "failed",
        }
    }

    /// The status `text` names, if it names one.
    pub fn parse(text: &str) -> Option<Status> {
        Some(match text {
            "completed" => Status::Completed,
            "passed" => Status::Passed,
            "issues" => Status::Issues,
            "skipped" => Status::Skipped,
            "failed" => Status::Failed,
            _ => return None,
        })
    }

    /// `failure.code` when the result names none (`default_failure_code`).
    fn default_failure_code(self) -> &'static str {
        match self {
            Status::Issues => super::ISSUES_FOUND,
            Status::Skipped => "not_run",
            _ => super::COMMAND_FAILED,
        }
    }
}

/// The process exit code of a result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExitCode {
    /// 0.
    #[default]
    Success,
    /// 1: the run failed, or found what it was asked to fail on.
    Failure,
    /// 2: a usage error ([`USAGE_EXIT_CODE`]).
    Usage,
    /// 130: stopped by Ctrl-C ([`INTERRUPTED_EXIT_CODE`]).
    Interrupted,
}

impl ExitCode {
    /// The code the process exits with.
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Success => 0,
            ExitCode::Failure => CRASH_EXIT_CODE,
            ExitCode::Usage => USAGE_EXIT_CODE,
            ExitCode::Interrupted => INTERRUPTED_EXIT_CODE,
        }
    }

    /// The exit code `code` is, if it is one a result exits with.
    pub fn from_code(code: i64) -> Option<ExitCode> {
        match code {
            0 => Some(ExitCode::Success),
            1 => Some(ExitCode::Failure),
            2 => Some(ExitCode::Usage),
            130 => Some(ExitCode::Interrupted),
            _ => None,
        }
    }
}

/// What the envelope's `failure` says beyond its message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailureDetail {
    /// `failure.code`; `None` takes the status's default.
    pub code: Option<String>,
    /// `failure.argument`: the input at fault.
    pub argument: Option<String>,
    /// `failure.suggestion`: the closest valid value.
    pub suggestion: Option<String>,
}

/// A command's result, before it becomes a [`Report`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CommandResult {
    /// `status`.
    pub status: Status,
    /// `message`; `None` is `Completed successfully`.
    pub message: Option<String>,
    /// The exit code.
    pub exit: ExitCode,
    /// The `failure` a failed or non-zero run carries, beyond its message
    /// (`error` among the data, else the message).
    pub failure: FailureDetail,
    /// `warnings`.
    pub warnings: Vec<String>,
    /// `summary`.
    pub summary: Vec<(String, Json)>,
    /// `next_actions`.
    pub next_actions: Vec<NextAction>,
    /// The command's own keys, in order.
    pub data: Vec<(String, Json)>,
}

impl CommandResult {
    /// A failed result: `status` failed with `message`, exiting `exit`.
    pub fn failed(message: impl Into<String>, exit: ExitCode) -> CommandResult {
        CommandResult {
            status: Status::Failed,
            message: Some(message.into()),
            exit,
            ..CommandResult::default()
        }
    }

    /// A result built as keys in order (`CommandResult.from_payload`):
    /// `message`, `status` and `warnings` leave the data, as do
    /// `_exit_code`, `_summary`, `_next_actions`, `_failure_code`,
    /// `_failure_argument`, `_failure_suggestion` and every other `_`-key.
    pub fn from_fields(result: &[(String, Json)]) -> CommandResult {
        let take = |key: &str| result.iter().find(|(name, _)| name == key).map(|(_, v)| v);
        let text = |key: &str| match take(key) {
            Some(Json::Str(text)) => Some(text.clone()),
            _ => None,
        };
        let exit = match take("_exit_code") {
            Some(Json::Int(code)) => ExitCode::from_code(*code).unwrap_or(ExitCode::Failure),
            _ => ExitCode::Success,
        };
        let warnings = match take("warnings") {
            Some(Json::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Json::Str(text) => text.clone(),
                    other => crate::json::document_text(other, false),
                })
                .collect(),
            _ => Vec::new(),
        };
        let summary = match take("_summary") {
            Some(Json::Object(members)) => members.clone().into_iter().collect(),
            _ => Vec::new(),
        };
        let next_actions = match take("_next_actions") {
            Some(Json::Array(items)) => items
                .iter()
                .map(|item| {
                    let field =
                        |key: &str| item.get(key).and_then(Json::as_str).unwrap_or_default();
                    NextAction::new(field("command"), field("reason"))
                })
                .collect(),
            _ => Vec::new(),
        };
        let data = result
            .iter()
            .filter(|(key, _)| {
                !key.starts_with('_') && !matches!(key.as_str(), "message" | "status" | "warnings")
            })
            .cloned()
            .collect();
        CommandResult {
            status: text("status")
                .as_deref()
                .and_then(Status::parse)
                .unwrap_or_default(),
            message: text("message"),
            exit,
            failure: FailureDetail {
                code: text("_failure_code"),
                argument: text("_failure_argument"),
                suggestion: text("_failure_suggestion"),
            },
            warnings,
            summary,
            next_actions,
            data,
        }
    }

    /// The report of `command`'s result: a run that failed or exits
    /// non-zero has a failure, with `error` (else the message) as its
    /// message.
    pub fn report(self, command: &str) -> Report {
        let message = self
            .message
            .unwrap_or_else(|| "Completed successfully".to_owned());
        let failed = self.status == Status::Failed || self.exit != ExitCode::Success;
        let failure = failed.then(|| {
            let error = match self.data.iter().find(|(key, _)| key == "error") {
                Some((_, Json::Str(text))) => Some(text.clone()),
                _ => None,
            };
            let code = self
                .failure
                .code
                .unwrap_or_else(|| self.status.default_failure_code().to_owned());
            let mut failure = Failure::new(&code, error.unwrap_or_else(|| message.clone()));
            failure.argument = self.failure.argument;
            failure.suggestion = self.failure.suggestion;
            failure
        });
        let mut report = Report::completed(command, self.data);
        report.outcome = Outcome {
            command: command.to_owned(),
            status: self.status.as_str().to_owned(),
            message,
            data: report.outcome.data,
            exit_code: self.exit.code(),
            summary: self.summary,
            next_actions: self.next_actions,
            failure,
        };
        report.warnings = self.warnings;
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::code;

    #[test]
    fn every_status_reads_back_as_itself() {
        for status in [
            Status::Completed,
            Status::Passed,
            Status::Issues,
            Status::Skipped,
            Status::Failed,
        ] {
            assert_eq!(Status::parse(status.as_str()), Some(status));
        }
        assert_eq!(Status::parse("unknown"), None);
    }

    #[test]
    fn every_exit_code_reads_back_as_itself() {
        for exit in [
            ExitCode::Success,
            ExitCode::Failure,
            ExitCode::Usage,
            ExitCode::Interrupted,
        ] {
            assert_eq!(ExitCode::from_code(i64::from(exit.code())), Some(exit));
        }
        assert_eq!(ExitCode::from_code(3), None);
    }

    #[test]
    fn a_typed_result_prints_the_document_its_fields_printed() {
        // The `_`-keys and the typed fields make the same document, key for
        // key, and the same exit code (#1949).
        let fields = vec![
            ("platform".to_owned(), Json::str("é😀")),
            ("status".to_owned(), Json::str("failed")),
            ("message".to_owned(), Json::str("refusé 😀")),
            ("_exit_code".to_owned(), Json::Int(2)),
            (
                "_failure_code".to_owned(),
                Json::str(code::USAGE_MISSING_OPTION),
            ),
            ("_failure_argument".to_owned(), Json::str("--platform")),
            ("_failure_suggestion".to_owned(), Json::str("--tenant")),
            (
                "_summary".to_owned(),
                Json::object([("checked", Json::Int(3))]),
            ),
            (
                "_next_actions".to_owned(),
                Json::Array(vec![Json::object([
                    ("command", Json::str("opentide info")),
                    ("reason", Json::str("why")),
                ])]),
            ),
            ("warnings".to_owned(), Json::Array(vec![Json::str("w")])),
        ];
        let typed = CommandResult {
            status: Status::Failed,
            message: Some("refusé 😀".to_owned()),
            exit: ExitCode::Usage,
            failure: FailureDetail {
                code: Some(code::USAGE_MISSING_OPTION.to_owned()),
                argument: Some("--platform".to_owned()),
                suggestion: Some("--tenant".to_owned()),
            },
            warnings: vec!["w".to_owned()],
            summary: vec![("checked".to_owned(), Json::Int(3))],
            next_actions: vec![NextAction::new("opentide info", "why")],
            data: vec![("platform".to_owned(), Json::str("é😀"))],
        };
        assert_eq!(CommandResult::from_fields(&fields), typed);
        let report = typed.report("validate query");
        assert_eq!(report.outcome.exit_code, 2);
        assert_eq!(report.warnings, ["w"]);
        assert_eq!(
            crate::json::document_text(&report.outcome.document(0), false),
            "{\"platform\":\"é😀\",\"ok\":false,\"status\":\"failed\",\
             \"message\":\"refusé 😀\",\"error\":\"refusé 😀\",\"schema_version\":1,\
             \"command\":\"validate query\",\"duration_ms\":0,\"exit_code\":2,\
             \"summary\":{\"checked\":3},\"next_actions\":[{\"command\":\
             \"opentide --json info\",\"reason\":\"why\"}],\"failure\":{\"code\":\
             \"usage_missing_option\",\"message\":\"refusé 😀\",\"argument\":\
             \"--platform\",\"suggestion\":\"--tenant\",\"crash_log\":null}}\n"
        );
    }

    #[test]
    fn a_failure_takes_its_message_from_error_and_its_code_from_the_status() {
        let mut result = CommandResult::failed("the message", ExitCode::Failure);
        result.data = vec![("error".to_owned(), Json::str("the error"))];
        let failure = result.report("deploy").outcome.failure;
        assert_eq!(
            failure,
            Some(Failure::new(super::super::COMMAND_FAILED, "the error"))
        );
        let mut issues = CommandResult {
            status: Status::Issues,
            exit: ExitCode::Failure,
            ..CommandResult::default()
        }
        .report("validate query");
        assert_eq!(
            issues.outcome.failure.take().map(|failure| failure.code),
            Some(super::super::ISSUES_FOUND.to_owned())
        );
        assert_eq!(issues.outcome.message, "Completed successfully");
        let passed = CommandResult {
            status: Status::Passed,
            ..CommandResult::default()
        }
        .report("validate query");
        assert_eq!(passed.outcome.failure, None);
        assert_eq!(passed.outcome.exit_code, 0);
    }
}
