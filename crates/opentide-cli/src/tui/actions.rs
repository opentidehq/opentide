//! The commands `opentide tui` runs (`cli/services/tui.py`'s actions): each
//! is the command line itself, run in this process as a person at a terminal
//! runs it, so what the Results tab shows is what the command prints. Its
//! output comes from the CLI's renderers (code frames, a dry run's plan, the
//! outcome line, warnings, next steps), captured as SGR runs and read back
//! into ratatui's text.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ratatui::text::Text;

use super::Launch;
use super::model::{Finding, findings_from};

/// A command the UI runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    /// Its key in the UI.
    pub name: &'static str,
    /// What a person would type for the same result.
    pub command: &'static str,
    /// What it does, in the command palette.
    pub help: &'static str,
}

impl Action {
    /// Whether it is a validate run, whose findings the detail pane shows.
    pub fn validates(&self) -> bool {
        self.name == "validate"
    }

    /// The command line's words after `opentide`.
    fn words(&self) -> Vec<String> {
        self.command
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect()
    }
}

/// Every action, in the palette's order.
pub const ACTIONS: [Action; 4] = [
    Action {
        name: "validate",
        command: "opentide validate",
        help: "Validate every object: schema, UUIDs, uniqueness, and each query with the analysis engine",
    },
    Action {
        name: "generate",
        command: "opentide generate",
        help: "Run the full generation pipeline: docs, exports, vocabularies, templates, schemas, snippets",
    },
    Action {
        name: "deploy-preview",
        command: "opentide deploy --dry-run --strategy PREVIEW --all",
        help: "Show what a PREVIEW deploy of every rule file would send, without calling a platform",
    },
    Action {
        name: "deploy-release",
        command: "opentide deploy --dry-run --strategy RELEASE --all",
        help: "Show what a RELEASE deploy of every rule file would send, without calling a platform",
    },
];

/// The action named `name`.
pub fn action(name: &str) -> Option<Action> {
    ACTIONS.iter().copied().find(|action| action.name == name)
}

/// What one action printed and returned.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The command line that ran.
    pub command: String,
    /// Whether it ran a validate.
    pub validates: bool,
    /// Its exit code.
    pub exit_code: i32,
    /// What it printed, stdout and stderr in the order written, as at a
    /// terminal, SGR runs included.
    pub output: String,
    /// The findings of a validate run.
    pub findings: Vec<Finding>,
    /// The first line of its outcome, for the status line.
    pub said: String,
}

impl Outcome {
    /// Whether it succeeded.
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }

    /// `$ command`, then the output as the CLI prints it.
    pub fn text(&self) -> Text<'static> {
        use ansi_to_tui::IntoText as _;
        let shown = format!("\x1b[1m$ {}\x1b[0m\n{}", self.command, clean(&self.output));
        shown
            .as_bytes()
            .into_text()
            .unwrap_or_else(|_| Text::raw(strip_sgr(&shown)))
    }
}

/// Where both streams of a captured run go, in the order they are written.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wide enough that no renderer wraps a line: the Results tab wraps the
/// text to its own width.
const UNWRAPPED: usize = 10_000;

/// Runs `action` as its command line would, in human mode at a terminal,
/// and never panics: a run that does is reported as the CLI reports an
/// internal error.
pub fn run(launch: &Launch, action: Action) -> Outcome {
    run_words(launch, action.command, &action.words(), action.validates())
}

/// [`run`] for a command line's words.
pub fn run_words(launch: &Launch, command: &str, words: &[String], validates: bool) -> Outcome {
    let mut argv: Vec<String> = Vec::new();
    if let Some(repo) = &launch.repo {
        argv.push("--repo".into());
        argv.push(repo.clone());
    }
    argv.extend(words.iter().cloned());
    // The UI owns the terminal: the run renders for a person at one, at a
    // width that never wraps, with no progress events of its own.
    let env = crate::env::Env::from_pairs(
        launch
            .env
            .iter()
            .filter(|(name, _)| {
                !matches!(*name, "OPENTIDE_OUTPUT" | "COLUMNS" | "OPENTIDE_PROGRESS")
            })
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .chain(std::iter::once((
                "OPENTIDE_OUTPUT".to_owned(),
                "human".to_owned(),
            ))),
    );
    let captured = Captured::default();
    let sink: crate::logging::Sink = Arc::new(Mutex::new(captured.clone()));
    let host = crate::Host {
        version: launch.version.clone(),
        stdout_tty: true,
        stderr_tty: true,
        log_sink: sink,
        cwd: Some(launch.cwd.clone()),
        width: Some(UNWRAPPED),
        interrupt: crate::app::Interrupt::default(),
    };
    let (exit_code, document) = crate::app::run_keeping_document(
        &argv,
        &env,
        &host,
        &mut captured.clone(),
        &mut captured.clone(),
    );
    let output = String::from_utf8_lossy(
        &captured
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    let document = document.and_then(|document| serde_json::to_value(&document).ok());
    let findings = match (&document, validates) {
        (Some(document), true) => findings_from(document),
        _ => Vec::new(),
    };
    let said = said(&output, document.as_ref());
    Outcome {
        command: command.to_owned(),
        validates,
        exit_code,
        output,
        findings,
        said,
    }
}

/// What the status line says of a run: the counted outcome line the
/// command printed (`✓ 3 objects valid · 1.2s`), else its message.
fn said(output: &str, document: Option<&serde_json::Value>) -> String {
    let plain = strip_sgr(&clean(output));
    let marks = ["✓ ", "✗ ", "! ", "error: ", "error[", "warning: "];
    let outcome = plain
        .lines()
        .map(str::trim)
        .filter(|line| marks.iter().any(|mark| line.starts_with(mark)))
        .find(|line| {
            line.starts_with("✓ ") || line.starts_with("✗ ") || line.starts_with("error: ")
        });
    if let Some(line) = outcome {
        return line.to_owned();
    }
    document
        .and_then(|document| document.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            plain
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// `text` without what only a terminal reads: OSC 8 links (their text
/// stays), the status line a run draws and clears, cursor switches.
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    // `validate`'s status line: drawn with the cursor hidden, cleared before
    // the result.
    if let Some(after) = rest.strip_prefix("\x1b[?25l")
        && let Some(end) = after.find("\x1b[?25h")
    {
        rest = &after[end + "\x1b[?25h".len()..];
    }
    while let Some(start) = rest.find("\x1b]8;") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        // `ESC ] 8 ; params ; uri ST`, ST being `ESC \` or BEL.
        let end = after
            .find("\x1b\\")
            .map(|at| at + 2)
            .or_else(|| after.find('\x07').map(|at| at + 1))
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out.replace("\x1b[?25l", "")
        .replace("\x1b[?25h", "")
        .replace("\r\x1b[2K", "")
}

/// `text` without SGR runs.
pub fn strip_sgr(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_lists_the_actions_by_their_command_line() {
        let commands: Vec<&str> = ACTIONS.iter().map(|action| action.command).collect();
        assert_eq!(
            commands,
            [
                "opentide validate",
                "opentide generate",
                "opentide deploy --dry-run --strategy PREVIEW --all",
                "opentide deploy --dry-run --strategy RELEASE --all",
            ]
        );
        // Deploy runs only as a dry run.
        for action in ACTIONS
            .iter()
            .filter(|action| action.name.starts_with("deploy"))
        {
            assert!(action.words().contains(&"--dry-run".to_owned()));
        }
        assert!(action("validate").is_some_and(|action| action.validates()));
        assert!(action("generate").is_some_and(|action| !action.validates()));
    }

    #[test]
    fn links_and_the_status_line_are_left_out_and_their_text_kept() {
        let text = "\x1b[?25l\x1b[1;36m⠋\x1b[0m Validating objects\r\x1b[2K\x1b[?25h\
                    \x1b]8;;file:///x.yaml\x1b\\x.yaml\x1b]8;;\x1b\\:8\n";
        assert_eq!(clean(text), "x.yaml:8\n");
        assert_eq!(strip_sgr("\x1b[1;31merror\x1b[0m: x"), "error: x");
    }

    #[test]
    fn the_status_line_says_the_counted_outcome() {
        let output = "\x1b[1;32m✓\x1b[0m 3 objects valid · 3 queries · 0.1s\n";
        assert_eq!(said(output, None), "✓ 3 objects valid · 3 queries · 0.1s");
        let document = serde_json::json!({"message": "Deployment completed"});
        assert_eq!(said("plan\n", Some(&document)), "Deployment completed");
    }
}
