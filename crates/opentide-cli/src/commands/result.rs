//! A service's result, typed (#1949): what a command found, and the parts the
//! envelope takes from it, as fields rather than `_`-prefixed keys among
//! the command's own.
//!
//! [`CommandResult::report`] is the one place a result becomes a [`Report`].
//! Every command builds its [`CommandResult`] itself; no result is read
//! back from `_`-keys.

use super::Report;
use crate::envelope::{
    CRASH_EXIT_CODE, Failure, INTERRUPTED_EXIT_CODE, NextAction, Outcome, PARTIAL_EXIT_CODE,
    USAGE_EXIT_CODE,
};
use crate::json::{Json, Object};

/// The envelope's `status` (`docs/cli/json-output.md`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
    /// A status a command copied from its data (`generate extract` writes
    /// the importer's `success`), printed as it came. It is not a failure:
    /// [`Status::is_failed`] is false for it, and so is [`Outcome::ok`].
    Other(String),
}

impl Status {
    /// The status as the document writes it.
    pub fn as_str(&self) -> &str {
        match self {
            Status::Completed => "completed",
            Status::Passed => "passed",
            Status::Issues => "issues",
            Status::Skipped => "skipped",
            Status::Failed => "failed",
            Status::Other(text) => text,
        }
    }

    /// Whether the run failed: the one test `ok`, the exit code's default
    /// and the outcome's kind all share.
    pub fn is_failed(&self) -> bool {
        matches!(self, Status::Failed)
    }

    /// The status `text` is: a known one, else [`Status::Other`] with the
    /// text kept as it is.
    pub fn from_text(text: &str) -> Status {
        Status::parse(text).unwrap_or_else(|| Status::Other(text.to_owned()))
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
    fn default_failure_code(&self) -> &'static str {
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
    /// 2 ([`USAGE_EXIT_CODE`]): the command could not do what was asked:
    /// usage, a decision only a person can make, authentication or
    /// connectivity.
    Usage,
    /// 3: the run did part of its work (`share`'s partial push).
    Partial,
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
            ExitCode::Partial => PARTIAL_EXIT_CODE,
            ExitCode::Interrupted => INTERRUPTED_EXIT_CODE,
        }
    }

    /// The exit code of a process or service outside this crate: one this
    /// enum names, else [`ExitCode::Failure`] so a non-zero code stays
    /// non-zero. An unnamed code is a bug in that producer, so a debug
    /// build stops on it.
    pub fn of_service(code: i32) -> ExitCode {
        let named = ExitCode::from_code(i64::from(code));
        debug_assert!(
            named.is_some(),
            "a service's exit code is unexpected: {code}"
        );
        named.unwrap_or(ExitCode::Failure)
    }

    /// The exit code `code` is, if it is one a result exits with.
    pub fn from_code(code: i64) -> Option<ExitCode> {
        match code {
            0 => Some(ExitCode::Success),
            1 => Some(ExitCode::Failure),
            2 => Some(ExitCode::Usage),
            3 => Some(ExitCode::Partial),
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
    pub summary: Object,
    /// `next_actions`.
    pub next_actions: Vec<NextAction>,
    /// The command's own keys, in order.
    pub data: Object,
    /// The outcome line the text modes print, when it is not the message.
    pub outcome_line: Option<String>,
    /// The run ends with its exit code alone: no document, no outcome line
    /// (`deploy`'s invalid promotion target).
    pub bare_exit: bool,
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

    /// The result with `failure.code` set to `code`.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> CommandResult {
        self.failure.code = Some(code.into());
        self
    }

    /// The value of the command's own key `key`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.data.get(key)
    }

    /// `value` set at the command's own key `key`, in place when the key is
    /// there, else last.
    pub fn set(&mut self, key: &str, value: Json) {
        self.data.insert(key.to_owned(), value);
    }

    /// The result as one JSON object: the command's own keys, then
    /// `status`, the message and the warnings when there are any (the CI
    /// job summary reads it). The envelope's other fields are not in it.
    pub fn to_json(&self) -> Json {
        let mut members = self.data.clone();
        members.insert("status".to_owned(), Json::str(self.status.as_str()));
        if let Some(message) = &self.message {
            members.insert("message".to_owned(), Json::str(message));
        }
        if !self.warnings.is_empty() {
            members.insert(
                "warnings".to_owned(),
                Json::Array(self.warnings.iter().map(Json::str).collect()),
            );
        }
        Json::Object(members)
    }

    /// The report of `command`'s result: a run that failed or exits
    /// non-zero has a failure, with `error` (else the message) as its
    /// message.
    pub fn report(self, command: &str) -> Report {
        let message = self
            .message
            .unwrap_or_else(|| "Completed successfully".to_owned());
        let failed = self.status.is_failed() || self.exit != ExitCode::Success;
        let failure = failed.then(|| {
            let error = match self.data.get("error") {
                Some(Json::Str(text)) => Some(text.clone()),
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
            status: self.status,
            message,
            data: report.outcome.data,
            exit_code: self.exit,
            summary: self.summary,
            next_actions: self.next_actions,
            failure,
        };
        report.warnings = self.warnings;
        report.outcome_line = self.outcome_line;
        report.bare_exit = self.bare_exit;
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
        // An unknown status is a failure, never a success.
        // A status no variant names is kept as it is, and is not a failure.
        assert_eq!(Status::from_text("passed"), Status::Passed);
        for text in ["success", "échoué 😀", ""] {
            let status = Status::from_text(text);
            assert_eq!(status, Status::Other(text.to_owned()));
            assert_eq!(status.as_str(), text);
            assert!(!status.is_failed());
        }
        assert!(Status::from_text("failed").is_failed());
    }

    #[test]
    fn every_exit_code_reads_back_as_itself() {
        for exit in [
            ExitCode::Success,
            ExitCode::Failure,
            ExitCode::Usage,
            ExitCode::Partial,
            ExitCode::Interrupted,
        ] {
            assert_eq!(ExitCode::from_code(i64::from(exit.code())), Some(exit));
        }
        assert_eq!(ExitCode::from_code(4), None);
        assert_eq!(ExitCode::from_code(3), Some(ExitCode::Partial));
    }

    #[test]
    fn a_status_no_producer_names_is_not_a_known_status() {
        // A typo in a producer's status read as `completed`, `ok: true` and
        // exit 0 (#1949); a typed status cannot be misspelt, and a text that
        // is none of the known ones does not parse as one.
        assert_eq!(Status::parse("faild"), None);
        let result = CommandResult::failed("é", ExitCode::Failure);
        assert_eq!(result.status, Status::Failed);
        let report = result.report("deploy");
        assert_eq!(report.outcome.exit_code, ExitCode::Failure);
        assert!(report.outcome.failure.is_some());
    }

    #[test]
    fn an_exit_code_outside_the_set_is_not_an_exit_code() {
        // The reader of `_exit_code` fell back to 1 for a code outside the
        // set; a typed `ExitCode` cannot hold one.
        assert_eq!(ExitCode::from_code(4), None);
        assert_eq!(ExitCode::from_code(-1), None);
        assert_eq!(ExitCode::from_code(130), Some(ExitCode::Interrupted));
    }

    #[test]
    fn a_result_without_a_status_completes() {
        let mut result = CommandResult::default();
        result.data.insert("platform".to_owned(), Json::str("é"));
        assert_eq!(result.status, Status::Completed);
        assert_eq!(result.exit, ExitCode::Success);
        let report = result.report("deploy");
        assert_eq!(report.outcome.status, Status::Completed);
        assert_eq!(report.outcome.exit_code, ExitCode::Success);
        assert_eq!(report.outcome.failure, None);
        assert_eq!(report.outcome.message, "Completed successfully");
    }

    #[test]
    fn setting_a_key_keeps_its_place_and_a_new_key_goes_last() {
        let mut result = CommandResult::default();
        result.set("a", Json::Int(1));
        result.set("b", Json::Int(2));
        result.set("a", Json::Int(3));
        let keys: Vec<&str> = result.data.keys().map(String::as_str).collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(result.get("a"), Some(&Json::Int(3)));
        assert_eq!(result.get("c"), None);
    }

    #[test]
    fn a_typed_result_prints_the_document_its_fields_printed() {
        // The typed fields make this document, key for key, and this exit
        // code (#1949).
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
            summary: Object::from([("checked".to_owned(), Json::Int(3))]),
            next_actions: vec![NextAction::new("opentide info", "why")],
            data: Object::from([("platform".to_owned(), Json::str("é😀"))]),
            ..CommandResult::default()
        };
        let report = typed.report("validate query");
        assert_eq!(report.outcome.exit_code, ExitCode::Usage);
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
        result.data = Object::from([("error".to_owned(), Json::str("the error"))]);
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
        assert_eq!(passed.outcome.exit_code, ExitCode::Success);
    }
}
