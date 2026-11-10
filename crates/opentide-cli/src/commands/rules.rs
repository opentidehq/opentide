//! `opentide rules unreviewed` (`cli/rules_app.py`, `cli/services/rules.py`).

use std::path::Path;

use jiff::Timestamp;
use opentide_workspace::OsFs;
use opentide_workspace::review::{Window, unreviewed, window_text};

use super::{Block, Report, USAGE_INVALID_VALUE, counted, json, placement};
use crate::env::Env;
use crate::json::Json;
use crate::render::outcome::OutcomeKind;
use crate::render::text::Text;

const COMMAND: &str = "rules unreviewed";

/// `evaluated_at`: UTC, microseconds when there are any, `Z`.
fn evaluated_at(now: Timestamp) -> String {
    let utc = now.to_zoned(jiff::tz::TimeZone::UTC);
    let micros = utc.subsec_nanosecond() / 1000;
    let base = utc.strftime("%Y-%m-%dT%H:%M:%S").to_string();
    if micros == 0 {
        format!("{base}Z")
    } else {
        format!("{base}.{micros:06}Z")
    }
}

/// Runs `opentide rules unreviewed --older-than <older_than>` at `now`.
pub fn run(
    older_than: &str,
    repo: Option<&str>,
    env: &Env,
    cwd: &Path,
    now: Timestamp,
    text: bool,
) -> Report {
    let window = match Window::parse(older_than) {
        Ok(window) => window,
        Err(message) => {
            return Report::usage(
                COMMAND,
                message,
                USAGE_INVALID_VALUE,
                "--older-than",
                None,
                &[],
            );
        }
    };
    let Some(duration) = window.duration() else {
        return Report::error(COMMAND, "window is too long to subtract from now");
    };
    let (shown, _) = placement(repo, env, cwd);
    let root = cwd.join(&shown);
    let findings = match unreviewed(&OsFs, &root, duration, now) {
        Ok(findings) => findings,
        Err(message) => return Report::error(COMMAND, message),
    };
    let count = findings.rules.len();
    let span = window_text(older_than);
    let mut data: Vec<(String, Json)> = vec![
        ("evaluated_at".into(), Json::str(evaluated_at(now))),
        ("window".into(), Json::str(older_than.trim())),
        (
            "count".into(),
            Json::Int(i64::try_from(count).unwrap_or(i64::MAX)),
        ),
        ("rules".into(), json(&findings.rules)),
    ];
    let mut warnings = Vec::new();
    if !findings.unreadable.is_empty() {
        data.push((
            "unreadable".into(),
            Json::Object(
                findings
                    .unreadable
                    .iter()
                    .map(|(path, reason)| (path.clone(), Json::str(reason)))
                    .collect(),
            ),
        ));
        warnings = findings
            .unreadable
            .iter()
            .map(|(path, reason)| {
                format!("Could not read {path}, so its review was not checked: {reason}")
            })
            .collect();
    }
    let mut report = Report::completed(COMMAND, data);
    report.outcome.summary = vec![(
        "unreviewed".into(),
        Json::Int(i64::try_from(count).unwrap_or(i64::MAX)),
    )];
    report.warnings = warnings;
    if count > 0 {
        let noun = counted(count, "rule");
        report.outcome.message = format!("{noun} unreviewed for {span}");
        report.outcome_kind = Some(OutcomeKind::Warning);
    } else if !findings.any_rule_files {
        report.outcome.message = "No rules yet".into();
        report.outcome.status = "skipped".into();
        report.next("opentide new rule", "scaffold your first rule");
    } else {
        report.outcome.message = format!("Every rule reviewed in the last {span}");
    }
    if text {
        report.body = vec![Block::Lines(
            findings
                .rules
                .iter()
                .map(|rule| {
                    Text::plain(&format!(
                        "{}  {}  {}  {}",
                        rule.path,
                        rule.reason,
                        rule.schema,
                        rule.reviewed.as_deref().unwrap_or("-")
                    ))
                })
                .collect(),
        )];
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_print_as_python_isoformat_does() {
        let at: Timestamp = "2026-01-02T03:04:05Z".parse().unwrap();
        assert_eq!(evaluated_at(at), "2026-01-02T03:04:05Z");
        let at: Timestamp = "2026-01-02T03:04:05.000120500Z".parse().unwrap();
        assert_eq!(evaluated_at(at), "2026-01-02T03:04:05.000120Z");
    }

    #[test]
    fn a_bad_window_is_a_usage_error() {
        let env = Env::default();
        let report = run(
            "90x",
            None,
            &env,
            Path::new("/"),
            Timestamp::UNIX_EPOCH,
            false,
        );
        assert_eq!(report.outcome.exit_code, 2);
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.message, "window must look like 90d, 12h, or 30m");
        assert_eq!(failure.argument.as_deref(), Some("--older-than"));
    }

    /// A fresh workspace folder for one test, removed again by the caller.
    fn workspace(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("opentide-cli-rules-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".opentide")).unwrap();
        root
    }

    fn now() -> Timestamp {
        "2026-03-01T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn a_workspace_without_rules_is_skipped() {
        let root = workspace("none");
        // A rules folder with no rule file in it is no rules either.
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/README.md"), "# rules\n").unwrap();
        let env = Env::default();
        let report = run("90d", root.to_str(), &env, &root, now(), false);
        std::fs::remove_dir_all(&root).unwrap();
        let outcome = &report.outcome;
        assert_eq!(outcome.status, "skipped");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.message, "No rules yet");
        let next: Vec<(&str, &str)> = outcome
            .next_actions
            .iter()
            .map(|n| (n.command.as_str(), n.reason.as_str()))
            .collect();
        assert_eq!(next, [("opentide new rule", "scaffold your first rule")]);
        assert_eq!(report.outcome_kind, None);
    }

    #[test]
    fn every_rule_reviewed_completes() {
        let root = workspace("reviewed");
        let rules = root.join("objects/rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("r.yaml"),
            "name: r\nmetadata:\n  uuid: 0b4d0e4e-1c33-4f53-8a6b-4c5b6e7f8a9b\n  schema: rule::1.1\n  reviewed: 2026-02-20\n",
        )
        .unwrap();
        let env = Env::default();
        let report = run("90d", root.to_str(), &env, &root, now(), false);
        let stale = run("3d", root.to_str(), &env, &root, now(), true);
        std::fs::remove_dir_all(&root).unwrap();
        let outcome = &report.outcome;
        assert_eq!(outcome.status, "completed");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.message, "Every rule reviewed in the last 90 days");
        assert!(outcome.next_actions.is_empty());
        assert_eq!(report.outcome_kind, None);
        // The same rule, past a shorter window, is reported.
        assert_eq!(stale.outcome.status, "completed");
        assert_eq!(stale.outcome.message, "1 rule unreviewed for 3 days");
        assert_eq!(stale.outcome_kind, Some(OutcomeKind::Warning));
    }
}
