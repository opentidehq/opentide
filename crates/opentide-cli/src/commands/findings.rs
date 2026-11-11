//! Where findings go besides the terminal (`cli/findings.py`): the
//! `--format` report, written to `--output` or as the whole of stdout, and
//! the CI sinks (annotations and the job summary). `validate`, `validate
//! query` and `lint` share them.

use std::path::{Path, PathBuf};

use opentide_workspace::diagnostic as ws;

use crate::env::Env;
use crate::mode::Mode;
use crate::render::diagnostic::{Diagnostic, Fix, Severity, TextEdit};
use crate::render::report::{ReportFormat, report_text};
use crate::render::{ci, summary};

/// A workspace finding as the renderers read it.
pub fn diagnostic(item: &ws::Diagnostic) -> Diagnostic {
    Diagnostic {
        code: item.code.clone(),
        severity: match item.severity {
            ws::Severity::Error => Severity::Error,
            ws::Severity::Warning => Severity::Warning,
            _ => Severity::Note,
        },
        message: item.frame_message().to_owned(),
        path: item.path.clone(),
        file_path: item.file_path.clone(),
        line: item.line,
        column: item.column,
        end_column: item.end_column,
        end_line: item.end_line,
        field_path: item.field_path.clone(),
        help: item.help.clone(),
        fix: item.fix.as_ref().map(|fix| Fix {
            safe: fix.safe,
            edits: fix
                .edits
                .iter()
                .map(|edit| TextEdit {
                    line: edit.line,
                    column: edit.column,
                    end_column: edit.end_column,
                    replacement: edit.replacement.clone(),
                    end_line: Some(edit.end_line),
                })
                .collect(),
        }),
        label: item.label.clone(),
        notes: item.notes.clone(),
        object_uuid: Some(item.object_uuid.clone()).filter(|uuid| !uuid.is_empty()),
    }
}

/// The report's text for `format`, its paths relative to the CI checkout
/// when there is one; `None` for `text`.
pub fn report(
    format: ReportFormat,
    diagnostics: &[Diagnostic],
    command: &str,
    version: &str,
    env: &Env,
) -> Option<String> {
    let root = ci::checkout_root(ci::ci_provider(env), env);
    let path_for = |item: &Diagnostic| ci::repository_path(item, root.as_deref());
    report_text(
        format,
        diagnostics,
        command,
        version,
        &crate::explain::rule_catalogue(),
        &path_for,
    )
}

/// Writes `text` to `output` (relative to `cwd`), creating its folder.
///
/// # Errors
///
/// The folder or the file cannot be written.
pub fn write_report(output: &Path, cwd: &Path, text: &str) -> std::io::Result<PathBuf> {
    let path = if output.is_absolute() {
        output.to_path_buf()
    } else {
        cwd.join(output)
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Annotations and the job summary for this run's CI, when there is one:
/// the annotation lines (and Azure's summary attachment) for stdout.
pub fn publish(
    diagnostics: &[Diagnostic],
    command: &str,
    outcome: &str,
    kind: &str,
    mode: Mode,
    env: &Env,
    cwd: &Path,
) -> String {
    let Some(provider) = ci::active_provider(mode, env) else {
        return String::new();
    };
    let root = ci::checkout_root(Some(provider), env);
    let mut out = String::new();
    for line in ci::annotation_lines(diagnostics, Some(provider), root.as_deref()) {
        out.push_str(&line);
        out.push('\n');
    }
    let path_for = |item: &Diagnostic| ci::repository_path(item, root.as_deref());
    let markdown = summary::diagnostics_summary(
        &format!("opentide {command}"),
        outcome,
        diagnostics,
        kind,
        Some(&path_for),
    );
    let written = ci::append_summary(
        &summary::fit(&markdown, summary::MAX_SUMMARY_BYTES),
        command,
        mode,
        env,
        cwd,
    );
    for line in written.stdout {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// `outcome_kind`: the glyph's name a status and verdict give.
pub fn kind_name(status: &str, ok: bool) -> &'static str {
    if !ok || status == "failed" {
        "failed"
    } else if status == "issues" {
        "warning"
    } else if status == "skipped" {
        "skipped"
    } else {
        "ok"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workspace_finding_keeps_its_place_fix_and_notes() {
        let mut item = ws::Diagnostic::warning("vocab_unknown", "bad");
        item.object_uuid = String::new();
        item.line = Some(3);
        item.column = Some(5);
        item.end_column = Some(9);
        item.notes.push(("note".into(), "text".into()));
        item.fix = Some(ws::Fix {
            safe: true,
            edits: vec![ws::TextEdit {
                line: 3,
                column: 5,
                end_line: 3,
                end_column: 9,
                replacement: "High".into(),
            }],
        });
        let shown = diagnostic(&item);
        assert_eq!(shown.severity, Severity::Warning);
        assert_eq!(shown.object_uuid, None);
        assert_eq!(
            (shown.line, shown.column, shown.end_column),
            (Some(3), Some(5), Some(9))
        );
        let fix = shown.fix.unwrap();
        assert!(fix.safe);
        assert_eq!(fix.edits[0].replacement, "High");
        assert_eq!(shown.notes, [("note".to_owned(), "text".to_owned())]);
        let mut info = ws::Diagnostic::warning("x", "y");
        info.severity = ws::Severity::Info;
        assert_eq!(diagnostic(&info).severity, Severity::Note);
    }

    #[test]
    fn kinds() {
        assert_eq!(kind_name("passed", true), "ok");
        assert_eq!(kind_name("passed", false), "failed");
        assert_eq!(kind_name("issues", true), "warning");
        assert_eq!(kind_name("skipped", true), "skipped");
    }
}
