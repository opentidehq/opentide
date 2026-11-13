//! `verifyRuleText` answers, read and put back on the block, ported from
//! 0.28.0's `platforms/google_secops/diagnostics.py`.
//!
//! `verifyRuleText` compiles a rule without creating it. It answers
//! `success: true` for a rule that compiles; a refused rule answers HTTP 200
//! with `compilationDiagnostics` and no `success`. Each diagnostic has a
//! `message`, a `severity` (`ERROR` or `WARNING`), an optional `uri`, and an
//! optional `position` (1-based lines and columns) in the assembled text,
//! which [`AssembledRule::locate`] maps back into the section key it falls
//! in.

use opentide_compile::Json;
use opentide_schema::objects::platform::google_secops::assemble::AssembledRule;

/// One compilation diagnostic, as Google sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// `message`, or `no message`.
    pub message: String,
    /// `severity`, upper case; `ERROR` when it names none.
    pub severity: String,
    /// `uri`, Google's documentation link.
    pub uri: Option<String>,
    /// `position.startLine`.
    pub line: Option<usize>,
    /// `position.startColumn`.
    pub column: Option<usize>,
}

/// What `verifyRuleText` said of one rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// `success` is `true`.
    pub success: bool,
    /// Diagnostics that are not warnings.
    pub errors: Vec<Diagnostic>,
    /// `WARNING` diagnostics.
    pub warnings: Vec<Diagnostic>,
    /// `allowedRunFrequencies`.
    pub allowed: Vec<String>,
}

impl VerifyOutcome {
    /// The rule compiles.
    pub fn ok(&self) -> bool {
        self.success && self.errors.is_empty()
    }
}

/// An integer, or a string of digits (protobuf JSON writes `int64` as a
/// string); never a boolean.
fn int(value: Option<&Json>) -> Option<usize> {
    match value? {
        Json::Int(integer) => usize::try_from(*integer).ok(),
        Json::Str(text) if !text.is_empty() && text.chars().all(|ch| ch.is_ascii_digit()) => {
            text.parse().ok()
        }
        _ => None,
    }
}

fn diagnostic(raw: &Json) -> Diagnostic {
    let position = raw
        .get("position")
        .filter(|value| value.as_object().is_some());
    let text = |key: &str| {
        raw.get(key)
            .filter(|value| value.truthy())
            .map(opentide_compile::deploy::text)
    };
    Diagnostic {
        message: text("message").unwrap_or_else(|| "no message".to_owned()),
        severity: text("severity")
            .unwrap_or_else(|| "ERROR".to_owned())
            .to_uppercase(),
        uri: text("uri"),
        line: int(position.and_then(|position| position.get("startLine"))),
        column: int(position.and_then(|position| position.get("startColumn"))),
    }
}

/// A `VerifyRuleTextResponse` as a [`VerifyOutcome`].
pub fn read_verify_answer(answer: &Json) -> VerifyOutcome {
    let diagnostics: Vec<Diagnostic> = match answer.get("compilationDiagnostics") {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|item| item.as_object().is_some())
            .map(diagnostic)
            .collect(),
        _ => Vec::new(),
    };
    let allowed = match answer.get("allowedRunFrequencies") {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let (warnings, errors) = diagnostics
        .into_iter()
        .partition(|item| item.severity == "WARNING");
    VerifyOutcome {
        success: answer.get("success") == Some(&Json::Bool(true)),
        errors,
        warnings,
        allowed,
    }
}

/// One line: where in the block, Google's message, and its documentation
/// link.
pub fn describe_diagnostic(diagnostic: &Diagnostic, assembled: &AssembledRule) -> String {
    let place = assembled.locate(diagnostic.line, diagnostic.column);
    let text = format!("{}: {}", place.describe(), diagnostic.message);
    match &diagnostic.uri {
        Some(uri) => format!("{text} ({uri})"),
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use opentide_schema::objects::platform::google_secops::assemble::SectionPlace;

    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn answers_are_read_and_placed_on_their_sections() {
        let outcome = read_verify_answer(&json(
            r#"{"compilationDiagnostics": [
                {"message": "bad field", "severity": "error", "uri": "https://docs",
                 "position": {"startLine": "12", "startColumn": 9}},
                {"severity": "WARNING", "position": {"startLine": true}},
                "not a diagnostic"],
              "allowedRunFrequencies": ["LIVE", 3, "DAILY"]}"#,
        ));
        assert!(!outcome.success && !outcome.ok());
        assert_eq!(outcome.allowed, ["LIVE", "DAILY"]);
        assert_eq!(outcome.warnings[0].message, "no message");
        assert_eq!(outcome.warnings[0].line, None);
        let assembled = AssembledRule {
            name: "r".to_owned(),
            text: String::new(),
            sections: vec![SectionPlace {
                key: "events",
                label_line: 10,
                lines: 4,
                dropped: 0,
            }],
        };
        assert_eq!(
            describe_diagnostic(&outcome.errors[0], &assembled),
            "configurations.google_secops.events line 2, column 5: bad field (https://docs)"
        );
        assert_eq!(
            describe_diagnostic(&outcome.warnings[0], &assembled),
            "configurations.google_secops: no message"
        );
        assert!(read_verify_answer(&json(r#"{"success": true}"#)).ok());
        assert!(!read_verify_answer(&json(r#"{"success": "true"}"#)).ok());
    }
}
