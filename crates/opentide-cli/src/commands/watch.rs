//! `opentide validate --watch` (`cli/commands/validate.py` `_watch`,
//! `cli/ui/watch.py`'s views): `opentide-workspace`'s watcher, shown as a
//! live view redrawn in place and cropped to the terminal (`human`), or as
//! each pass's frames and one outcome line (`plain`). `validate::refuse`
//! has already refused the other modes. Ctrl-C stops it with exit 0.

use std::io::Write;
use std::path::{Path, PathBuf};

use opentide_workspace::OsFs;
use opentide_workspace::validate::{STRICT_EXEMPT_WARNINGS, Summary};
use opentide_workspace::watch::{WatchRun, Watcher, WorkspaceValidate};

use super::findings::diagnostic;
use super::placement;
use super::validate::{Args, Context, outcome_line};
use crate::mode::Mode;
use crate::queries::EngineQueries;
use crate::render::diagnostic::{Diagnostic, SourceFiles};
use crate::render::outcome::{OutcomeKind, outcome_text};
use crate::render::text::{Style, Text};

/// The folder that holds every watched one, relative to `cwd`.
pub fn shown(roots: &[PathBuf], cwd: &Path) -> String {
    let Some(first) = roots.first() else {
        return "nothing: no object folder exists".to_owned();
    };
    let mut common: PathBuf = first.clone();
    for root in &roots[1..] {
        while !root.starts_with(&common) {
            if !common.pop() {
                break;
            }
        }
    }
    let posix = |path: &Path| {
        path.components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    match common.strip_prefix(cwd) {
        Ok(rest) if rest.as_os_str().is_empty() => ".".to_owned(),
        Ok(rest) => posix(rest),
        Err(_) => common.to_string_lossy().replace('\\', "/"),
    }
}

/// A pass's outcome line, without the queries count a pass does not keep.
pub fn describe(run: &WatchRun) -> String {
    let summary = Summary {
        objects: run.objects,
        errors: run.errors,
        warnings: run.warnings,
        files: run.files,
        warning_files: 0,
        queries: None,
        fixable: run.fixable,
    };
    outcome_line(&summary, run.failed, run.elapsed.as_secs_f64(), None)
}

fn kind(run: &WatchRun) -> OutcomeKind {
    if run.failed {
        OutcomeKind::Failed
    } else {
        OutcomeKind::Ok
    }
}

/// `watching objects · changed rule.yaml · 12:42:23 · Ctrl-C to stop`.
pub fn footer(watching: &str, run: &WatchRun, clock: &str) -> String {
    let mut parts = vec![format!("watching {watching}")];
    if let Some(first) = run.changed.first() {
        let mut what = first
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if run.changed.len() > 1 {
            what.push_str(&format!(" and {} more", run.changed.len() - 1));
        }
        parts.push(format!(
            "{} {what}",
            if run.scoped { "re-checked" } else { "changed" }
        ));
    }
    parts.push(clock.to_owned());
    parts.push("Ctrl-C to stop".to_owned());
    parts.join(" · ")
}

/// The live view's lines: the frames that fit above the outcome line and the
/// footer in `height` rows (`… N more lines` when they do not), then both.
pub fn live_lines(
    frames: &[Text],
    outcome: Text,
    footer: Text,
    width: usize,
    height: usize,
) -> Vec<Text> {
    let rows = |line: &Text| line.cell_len().div_ceil(width.max(1)).max(1);
    let room = height.saturating_sub(rows(&outcome) + rows(&footer));
    let heights: Vec<usize> = frames.iter().map(rows).collect();
    let mut out: Vec<Text> = Vec::new();
    if heights.iter().sum::<usize>() > room {
        let (mut kept, mut used) = (0, 1);
        while kept < frames.len() && used + heights[kept] <= room {
            used += heights[kept];
            kept += 1;
        }
        out.extend(frames[..kept].iter().cloned());
        out.push(Text::styled(
            &format!("… {} more lines", frames.len() - kept),
            &Style::new("dim"),
        ));
    } else {
        out.extend(frames.iter().cloned());
    }
    out.push(outcome);
    out.push(footer);
    out
}

/// Runs the watch until `stop` says so; the exit code.
///
/// # Errors
///
/// stdout cannot be written.
pub fn run(
    args: &Args,
    cx: &Context<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    stop: &dyn Fn() -> bool,
) -> std::io::Result<i32> {
    let terminal = cx.terminal;
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = match super::open(options) {
        Ok(workspace) => workspace,
        Err(message) => {
            err.write_all(
                terminal
                    .stderr
                    .error(&message, &[], terminal.mode, false)
                    .as_bytes(),
            )?;
            return Ok(1);
        }
    };
    let mut validate = WorkspaceValidate::new(workspace, args.selection.clone());
    validate.check = args.check;
    validate.strict = args.strict;
    validate.queries = args.queries.unwrap_or_default();
    validate.query_check = Some(&EngineQueries);
    validate.platform_configurations = crate::plugins::configurations();
    validate.compile_check = Some(&opentide_compile::validate::Compilers);
    let roots: Vec<PathBuf> = validate
        .roots()
        .into_iter()
        .filter(|root| root.is_dir())
        .collect();
    let watching = shown(&roots, cx.cwd);
    let mut watcher = Watcher::new(
        &OsFs,
        roots,
        validate,
        args.strict,
        args.selection.is_empty(),
        &STRICT_EXEMPT_WARNINGS,
    );
    let frames = terminal.frames(cx.cwd, cx.env);
    let human = terminal.mode == Mode::Human;
    let mut drawn = 0usize;
    let failure: std::cell::RefCell<Option<std::io::Error>> = std::cell::RefCell::new(None);
    if human {
        out.write_all(b"\x1b[?25l")?;
    }
    let result = watcher.run(
        |pass| {
            if failure.borrow().is_some() {
                return;
            }
            let shown: Vec<Diagnostic> = if human {
                &pass.diagnostics
            } else {
                &pass.found
            }
            .iter()
            .map(diagnostic)
            .filter(|item| {
                !terminal.quiet || item.severity == crate::render::diagnostic::Severity::Error
            })
            .collect();
            let outcome = outcome_text(kind(pass), &describe(pass));
            let text = if human {
                let mut sources = SourceFiles::default();
                let mut lines = Vec::new();
                for item in crate::render::diagnostic::sort_diagnostics(&shown) {
                    lines.extend(frames.diagnostic_lines(item, &mut sources, None));
                    lines.push(Text::default());
                }
                let (width, height) = terminal_size::terminal_size()
                    .map_or((terminal.width.unwrap_or(80), 24), |(w, h)| {
                        (usize::from(w.0), usize::from(h.0))
                    });
                let clock = jiff::Zoned::now().strftime("%H:%M:%S").to_string();
                let footer = Text::styled(&footer(&watching, pass, &clock), &Style::new("dim"));
                let lines = live_lines(&lines, outcome, footer, width, height);
                let mut text = String::new();
                if drawn > 0 {
                    text.push_str(&format!("\x1b[{drawn}A\r\x1b[J"));
                }
                drawn = 0;
                for mut line in lines {
                    line.expand_tabs();
                    drawn += line.cell_len().div_ceil(width.max(1)).max(1);
                    text.push_str(&line.render(terminal.stdout.colour, frames.links));
                    text.push('\n');
                }
                text
            } else {
                let mut text = frames.render(&shown, &mut SourceFiles::default(), false);
                text.push_str(&terminal.stdout.line(&outcome));
                text
            };
            if let Err(error) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
                *failure.borrow_mut() = Some(error);
            }
        },
        || stop() || failure.borrow().is_some(),
    );
    if human {
        out.write_all(b"\x1b[?25h")?;
    }
    out.flush()?;
    if let Some(error) = failure.into_inner() {
        return Err(error);
    }
    if let Err(error) = result {
        err.write_all(
            terminal
                .stderr
                .error(
                    &format!("cannot watch the object folders: {error}"),
                    &[],
                    terminal.mode,
                    false,
                )
                .as_bytes(),
        )?;
        return Ok(1);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pass(changed: Vec<PathBuf>, scoped: bool) -> WatchRun {
        WatchRun {
            number: 1,
            diagnostics: Vec::new(),
            found: Vec::new(),
            objects: 3,
            errors: 1,
            warnings: 0,
            files: 1,
            failed: true,
            fixable: 0,
            scoped,
            changed,
            elapsed: Duration::from_millis(120),
        }
    }

    #[test]
    fn the_footer_names_the_change_and_how_to_stop() {
        let run = pass(vec!["/w/a.yaml".into(), "/w/b.yaml".into()], true);
        assert_eq!(
            footer("objects", &run, "12:00:00"),
            "watching objects · re-checked a.yaml and 1 more · 12:00:00 · Ctrl-C to stop"
        );
        assert_eq!(
            footer("objects", &pass(Vec::new(), false), "12:00:00"),
            "watching objects · 12:00:00 · Ctrl-C to stop"
        );
        assert_eq!(
            describe(&run),
            "1 error in 1 file · 3 objects checked · 0.1s"
        );
    }

    #[test]
    fn the_live_view_crops_frames_to_keep_the_outcome_on_screen() {
        let frames: Vec<Text> = (0..10).map(|n| Text::plain(&format!("line {n}"))).collect();
        let lines = live_lines(
            &frames,
            Text::plain("outcome"),
            Text::plain("footer"),
            80,
            6,
        );
        let plain: Vec<String> = lines.iter().map(Text::as_plain).collect();
        assert_eq!(
            plain,
            [
                "line 0",
                "line 1",
                "line 2",
                "… 7 more lines",
                "outcome",
                "footer"
            ]
        );
        let lines = live_lines(&frames[..2], Text::plain("o"), Text::plain("f"), 80, 6);
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn the_watched_folder_is_their_common_parent() {
        let cwd = Path::new("/w");
        let roots = vec![
            PathBuf::from("/w/objects/rules"),
            PathBuf::from("/w/objects/threats"),
        ];
        assert_eq!(shown(&roots, cwd), "objects");
        assert_eq!(shown(&[], cwd), "nothing: no object folder exists");
        assert_eq!(shown(&[PathBuf::from("/x/r")], cwd), "/x/r");
    }
}
