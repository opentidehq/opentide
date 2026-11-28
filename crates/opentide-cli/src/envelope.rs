//! The JSON envelope every `--json` document carries (`docs/cli/json-output.md`).
//!
//! Key order is fixed, as part of the `--json` contract: the command's own
//! keys, then `ok`, `status`, `message`, `warnings` when there are any, then
//! `schema_version`, `command`, `duration_ms`, `exit_code`, `summary`,
//! `next_actions` and `failure`. A non-zero exit always carries `error`: where the command put it,
//! else after `message`.

use crate::commands::result::{ExitCode, Status};
use crate::json::{Json, Object};

/// Puts a run's `warnings` in a document's members, after `message`. A
/// command that wrote `warnings` among its own keys keeps them: the run's
/// come first, then the command's that are not already there; a `warnings`
/// that is not an array is kept as one entry.
///
/// With no run warnings the members are untouched, so the command's own
/// `warnings` stay where it put them. With some, the key moves to just after
/// `message` (the end when there is no `message`).
pub fn put_warnings(members: &mut Object, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    let mut all: Vec<Json> = warnings.iter().map(Json::str).collect();
    let own = match members.shift_remove("warnings") {
        Some(Json::Array(own)) => own,
        Some(other) => vec![other],
        None => Vec::new(),
    };
    for item in own {
        if !all.contains(&item) {
            all.push(item);
        }
    }
    let at = members
        .get_index_of("message")
        .map_or(members.len(), |at| at + 1);
    members.shift_insert(at, "warnings".into(), Json::Array(all));
}

/// Bumped only when an existing key changes meaning, which the contract forbids.
pub const SCHEMA_VERSION: i64 = 1;

/// Exit code of every usage error.
pub const USAGE_EXIT_CODE: i32 = 2;
/// Exit code of an unexpected error (`internal`).
pub const CRASH_EXIT_CODE: i32 = 1;
/// Exit code of a run stopped by Ctrl-C: 128 + SIGINT.
pub const INTERRUPTED_EXIT_CODE: i32 = 130;
/// The exit code of a run that did part of its work (`share`'s partial push).
pub const PARTIAL_EXIT_CODE: i32 = 3;

/// `failure.code` values the framework produces.
pub mod code {
    /// No such command.
    pub const USAGE_UNKNOWN_COMMAND: &str = "usage_unknown_command";
    /// No such option for that command.
    pub const USAGE_UNKNOWN_OPTION: &str = "usage_unknown_option";
    /// A value outside the accepted ones.
    pub const USAGE_INVALID_CHOICE: &str = "usage_invalid_choice";
    /// A value that cannot be used.
    pub const USAGE_INVALID_VALUE: &str = "usage_invalid_value";
    /// A required option or argument is missing.
    pub const USAGE_MISSING_OPTION: &str = "usage_missing_option";
    /// Another usage error.
    pub const USAGE_ERROR: &str = "usage_error";
    /// An unexpected error: a bug in opentide.
    pub const INTERNAL: &str = "internal";
}

/// Why a command did not exit 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Failure {
    /// Stable snake_case code.
    pub code: String,
    /// The error message.
    pub message: String,
    /// The input at fault (`--type`, the mistyped command).
    pub argument: Option<String>,
    /// The closest valid value.
    pub suggestion: Option<String>,
    /// With `internal`: the crash log's path.
    pub crash_log: Option<String>,
}

impl Failure {
    /// A failure with `code` and `message` and nothing else.
    pub fn new(code: &str, message: impl Into<String>) -> Failure {
        Failure {
            code: code.to_owned(),
            message: message.into(),
            ..Failure::default()
        }
    }

    /// The `failure` object.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("code", Json::str(&self.code)),
            ("message", Json::str(&self.message)),
            ("argument", Json::opt_str(self.argument.clone())),
            ("suggestion", Json::opt_str(self.suggestion.clone())),
            ("crash_log", Json::opt_str(self.crash_log.clone())),
        ])
    }
}

/// A command worth running next, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextAction {
    /// The command line, `opentide ...`.
    pub command: String,
    /// Why.
    pub reason: String,
}

impl NextAction {
    /// A next action.
    pub fn new(command: impl Into<String>, reason: impl Into<String>) -> NextAction {
        NextAction {
            command: command.into(),
            reason: reason.into(),
        }
    }
}

/// `opentide x` as a JSON reader runs it: `opentide --json x`.
pub fn json_command(command: &str) -> String {
    let words: Vec<&str> = command.split_whitespace().collect();
    if words.first() != Some(&"opentide") || words.contains(&"--json") {
        return command.to_owned();
    }
    // After the prefix, not re-joined by words: a quoted path may hold
    // runs of spaces.
    match command.strip_prefix("opentide ") {
        Some(rest) => format!("opentide --json {rest}"),
        None => "opentide --json".to_owned(),
    }
}

/// A command's result, before it is printed.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    /// The command path (`validate query`); empty when none was recognised.
    pub command: String,
    /// `completed`, `passed`, `issues`, `skipped` or `failed`.
    pub status: Status,
    /// The outcome in one sentence.
    pub message: String,
    /// The command's own keys, in order.
    pub data: Vec<(String, Json)>,
    /// The process exit code.
    pub exit_code: ExitCode,
    /// Counts behind the outcome.
    pub summary: Vec<(String, Json)>,
    /// What to run next.
    pub next_actions: Vec<NextAction>,
    /// Why it failed; `None` exactly when the exit code is 0.
    pub failure: Option<Failure>,
}

impl Outcome {
    /// A failed run: `error` and `message` are the failure's message.
    pub fn failed(command: &str, exit_code: ExitCode, failure: Failure) -> Outcome {
        Outcome {
            command: command.to_owned(),
            status: Status::Failed,
            message: failure.message.clone(),
            data: vec![("error".into(), Json::str(&failure.message))],
            exit_code,
            summary: Vec::new(),
            next_actions: Vec::new(),
            failure: Some(failure),
        }
    }

    /// Whether the run succeeded: its status is not [`Status::Failed`].
    pub fn ok(&self) -> bool {
        !self.status.is_failed()
    }

    /// The document, with `duration_ms` as given.
    pub fn document(&self, duration_ms: i64) -> Json {
        let mut members: Vec<(String, Json)> = self.data.clone();
        members.push(("ok".into(), Json::Bool(self.ok())));
        members.push(("status".into(), Json::str(self.status.as_str())));
        members.push(("message".into(), Json::str(&self.message)));
        // `error`, unless the command put it among its own keys, goes after
        // those keys and the message.
        if self.exit_code != ExitCode::Success && !members.iter().any(|(k, _)| k == "error") {
            let message = if self.message.is_empty() {
                self.failure
                    .as_ref()
                    .map(|f| f.message.clone())
                    .unwrap_or_default()
            } else {
                self.message.clone()
            };
            members.push(("error".into(), Json::Str(message)));
        }
        members.push(("schema_version".into(), Json::Int(SCHEMA_VERSION)));
        members.push(("command".into(), Json::str(&self.command)));
        members.push(("duration_ms".into(), Json::Int(duration_ms)));
        members.push((
            "exit_code".into(),
            Json::Int(i64::from(self.exit_code.code())),
        ));
        members.push(("summary".into(), Json::object(self.summary.clone())));
        members.push((
            "next_actions".into(),
            Json::Array(
                self.next_actions
                    .iter()
                    .map(|action| {
                        Json::object([
                            ("command", Json::Str(json_command(&action.command))),
                            ("reason", Json::str(&action.reason)),
                        ])
                    })
                    .collect(),
            ),
        ));
        members.push((
            "failure".into(),
            self.failure.as_ref().map_or(Json::Null, Failure::to_json),
        ));
        Json::object(members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::document_text;

    /// `ok`, the outcome's kind and the document's `ok` and `status` read one
    /// status: they cannot disagree (#1949).
    #[test]
    fn ok_and_the_kind_agree_with_the_status_for_every_status() {
        for status in [
            Status::Completed,
            Status::Passed,
            Status::Issues,
            Status::Skipped,
            Status::Failed,
            Status::Other("success".to_owned()),
            Status::Other("réussi 😀".to_owned()),
        ] {
            let mut outcome = Outcome::failed("x", ExitCode::Failure, Failure::new("c", "m"));
            outcome.status = status.clone();
            let failed = status == Status::Failed;
            assert_eq!(outcome.ok(), !failed, "{status:?}");
            assert_eq!(status.is_failed(), failed, "{status:?}");
            assert_eq!(
                crate::render::outcome::OutcomeKind::of(outcome.status.as_str(), outcome.ok())
                    == crate::render::outcome::OutcomeKind::Failed,
                failed,
                "{status:?}"
            );
            let doc = outcome.document(0);
            assert_eq!(doc.get("ok"), Some(&Json::Bool(!failed)), "{status:?}");
            assert_eq!(doc.get("status"), Some(&Json::str(status.as_str())));
        }
    }

    #[test]
    fn every_exit_code_prints_its_number() {
        let mut outcome = Outcome::failed("x", ExitCode::Failure, Failure::new("c", "m"));
        for (exit, code) in [
            (ExitCode::Success, 0),
            (ExitCode::Failure, 1),
            (ExitCode::Usage, 2),
            (ExitCode::Partial, 3),
            (ExitCode::Interrupted, 130),
        ] {
            outcome.exit_code = exit;
            assert_eq!(outcome.document(0).get("exit_code"), Some(&Json::Int(code)));
        }
    }

    #[test]
    fn framework_envelope_a_usage_error_document_keeps_its_key_order() {
        let mut failure = Failure::new(code::USAGE_UNKNOWN_COMMAND, "No such command 'valdiate'.");
        failure.argument = Some("valdiate".into());
        failure.suggestion = Some("validate".into());
        let outcome = Outcome::failed("", ExitCode::Usage, failure);
        assert_eq!(
            document_text(&outcome.document(0), false),
            "{\"error\":\"No such command 'valdiate'.\",\"ok\":false,\"status\":\"failed\",\
             \"message\":\"No such command 'valdiate'.\",\"schema_version\":1,\"command\":\"\",\
             \"duration_ms\":0,\"exit_code\":2,\"summary\":{},\"next_actions\":[],\
             \"failure\":{\"code\":\"usage_unknown_command\",\"message\":\"No such command 'valdiate'.\",\
             \"argument\":\"valdiate\",\"suggestion\":\"validate\",\"crash_log\":null}}\n"
        );
    }

    #[test]
    fn framework_envelope_error_follows_the_message_when_the_command_set_none() {
        let mut outcome = Outcome::failed(
            "generate exports",
            ExitCode::Failure,
            Failure::new("command_failed", "exports: broken"),
        );
        outcome.data = vec![("phase".into(), Json::str("exports"))];
        let text = document_text(&outcome.document(0), false);
        assert!(
            text.starts_with(
                "{\"phase\":\"exports\",\"ok\":false,\"status\":\"failed\",\
                 \"message\":\"exports: broken\",\"error\":\"exports: broken\",\"schema_version\":1,"
            ),
            "{text}"
        );
    }

    #[test]
    fn framework_envelope_a_success_has_no_error_and_a_null_failure() {
        let outcome = Outcome {
            command: "commands".into(),
            status: Status::Completed,
            message: "58 commands".into(),
            data: vec![("program".into(), Json::str("opentide"))],
            exit_code: ExitCode::Success,
            summary: vec![("commands".into(), Json::Int(58))],
            next_actions: vec![NextAction::new("opentide validate", "check")],
            failure: None,
        };
        let text = document_text(&outcome.document(3), false);
        assert_eq!(
            text,
            "{\"program\":\"opentide\",\"ok\":true,\"status\":\"completed\",\"message\":\"58 commands\",\
             \"schema_version\":1,\"command\":\"commands\",\"duration_ms\":3,\"exit_code\":0,\
             \"summary\":{\"commands\":58},\"next_actions\":[{\"command\":\"opentide --json validate\",\
             \"reason\":\"check\"}],\"failure\":null}\n"
        );
    }

    #[test]
    fn framework_envelope_a_non_zero_exit_always_carries_error() {
        let outcome = Outcome {
            command: "x".into(),
            status: Status::Issues,
            message: String::new(),
            data: Vec::new(),
            exit_code: ExitCode::Failure,
            summary: Vec::new(),
            next_actions: Vec::new(),
            failure: Some(Failure::new("issues_found", "found")),
        };
        let doc = outcome.document(0);
        assert_eq!(doc.get("error"), Some(&Json::str("found")));
        assert_eq!(doc.get("ok"), Some(&Json::Bool(true)));
    }

    #[test]
    fn framework_envelope_next_actions_read_as_a_json_reader_runs_them() {
        assert_eq!(
            json_command("opentide lint --fix"),
            "opentide --json lint --fix"
        );
        assert_eq!(json_command("opentide --json lint"), "opentide --json lint");
        assert_eq!(json_command("git status"), "git status");
        // A quoted path keeps its spaces.
        assert_eq!(
            json_command("opentide validate --file 'a  b.yaml'"),
            "opentide --json validate --file 'a  b.yaml'"
        );
        assert_eq!(json_command("opentide"), "opentide --json");
    }

    #[test]
    fn a_runs_warnings_join_the_commands_own() {
        let mut members = Object::new();
        members.insert("own".into(), Json::Int(1));
        members.insert(
            "warnings".into(),
            Json::Array(vec![Json::str("b"), Json::str("a")]),
        );
        members.insert("message".into(), Json::str("m"));
        members.insert("exit_code".into(), Json::Int(0));
        put_warnings(&mut members, &[]);
        assert_eq!(
            members.keys().collect::<Vec<_>>(),
            ["own", "warnings", "message", "exit_code"]
        );
        put_warnings(&mut members, &["a".to_owned(), "c".to_owned()]);
        assert_eq!(
            document_text(&Json::Object(members), false),
            "{\"own\":1,\"message\":\"m\",\"warnings\":[\"a\",\"c\",\"b\"],\"exit_code\":0}\n"
        );
        let mut plain = Object::new();
        plain.insert("message".into(), Json::str("m"));
        plain.insert("next".into(), Json::Null);
        put_warnings(&mut plain, &["w".to_owned()]);
        assert_eq!(
            plain.keys().collect::<Vec<_>>(),
            ["message", "warnings", "next"]
        );
        let mut odd = Object::new();
        odd.insert("warnings".into(), Json::str("own"));
        odd.insert("message".into(), Json::str("m"));
        put_warnings(&mut odd, &["w".to_owned()]);
        assert_eq!(
            document_text(&Json::Object(odd), false),
            "{\"message\":\"m\",\"warnings\":[\"w\",\"own\"]}\n"
        );
    }
}
