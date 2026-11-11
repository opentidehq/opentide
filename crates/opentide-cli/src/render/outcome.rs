//! Outcome, warning, error and next-step lines for the `human`, `plain` and `agent` modes.
//!
//! The grammar of `docs/internal/cli-experience.md`, "Human output grammar":
//! one outcome line per run, `✓` done, `!` done with issues, `✗` failed
//! (with the findings framed above it), `Skipped:` and no glyph for a plan's
//! tally (`Plan: 1 to create, …`); `warning:` lines before it; indented
//! `note:` and `help:` under it; at most three `→ command · reason` next steps
//! after it; the `--json` tip last in `agent` mode. On a pipe each line is
//! whole; at a terminal narrower than a line it is broken between words, never
//! inside one, and continued under its text.

use super::codeframe::quoted;
use super::glyphs;
use super::text::{Colour, Style, Text, cell_len, char_width};
use crate::envelope::NextAction;
use crate::mode::Mode;

/// At most this many next steps follow an outcome line.
pub const MAX_NEXT_ACTIONS: usize = 3;

/// The `agent` mode's last line.
pub const AGENT_TIP: &str = "add --json for machine-readable output";

/// `failure.code`s whose findings are the error report: the outcome line counts them (`✗`).
pub const FRAMED_FAILURES: [&str; 3] = ["issues_found", "config_parse", "yaml_parse"];

/// The glyph an outcome line carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    /// `✓`
    Ok,
    /// `!`
    Warning,
    /// `Skipped:`
    Skipped,
    /// `✗`
    Failed,
    /// A dry run's tally: nothing happened, so no glyph.
    Plan,
}

impl OutcomeKind {
    /// A result's status (`completed`, `issues`, `skipped`, `failed`) as its line's kind.
    pub fn of(status: &str, ok: bool) -> OutcomeKind {
        if !ok || status == "failed" {
            OutcomeKind::Failed
        } else if status == "issues" {
            OutcomeKind::Warning
        } else if status == "skipped" {
            OutcomeKind::Skipped
        } else {
            OutcomeKind::Ok
        }
    }

    fn style(self) -> Style {
        Style::new(match self {
            OutcomeKind::Ok => "bold green",
            OutcomeKind::Warning => "bold yellow",
            OutcomeKind::Failed => "bold red",
            OutcomeKind::Skipped | OutcomeKind::Plan => "bold",
        })
    }
}

/// A stream the lines go to: its styles, and its width when it is a terminal.
#[derive(Clone, Copy, Debug)]
pub struct Console {
    /// The styles it gets.
    pub colour: Colour,
    /// The terminal's width; `None` on a pipe, a file or a CI log.
    pub width: Option<usize>,
}

impl Console {
    /// `text` as one written line, tabs expanded.
    pub fn line(self, text: &Text) -> String {
        let mut text = text.clone();
        text.expand_tabs();
        let mut out = text.render(self.colour, false);
        out.push('\n');
        out
    }

    /// `line`, wrapped at words `hang` cells in when the terminal is narrower
    /// than it. A line break inside it continues on a row `hang` cells in as
    /// well, so no printed line starts with the text of a message.
    pub fn print_line(self, line: &Text, hang: usize) -> String {
        let width = self.width.unwrap_or(0);
        let mut out = String::new();
        for (index, part) in line.split_lines().into_iter().enumerate() {
            let part = if index == 0 {
                part
            } else {
                let mut led = Text::plain(&" ".repeat(hang.max(1)));
                led.append_text(&part);
                led
            };
            if width == 0 || part.cell_len() <= width || hang >= width / 2 {
                out.push_str(&self.line(&part));
            } else {
                for row in word_wrap(&part, width, hang) {
                    out.push_str(&self.line(&row));
                }
            }
        }
        out
    }

    /// `label: message`, continued under the message when it wraps.
    pub fn labelled(self, label: &str, message: &str, indent: usize) -> String {
        self.print_line(
            &labelled_text(label, message, indent),
            indent + cell_len(label) + 2,
        )
    }

    /// The one outcome line a command ends with.
    pub fn outcome(self, kind: OutcomeKind, message: &str) -> String {
        let line = outcome_text(kind, message);
        let lead = line
            .as_plain()
            .chars()
            .position(|ch| ch == ' ')
            .map_or(0, |at| at + 1);
        self.print_line(&line, if (1..=10).contains(&lead) { lead } else { 2 })
    }

    /// One `warning:` line each, printed before the outcome line.
    pub fn warnings(self, warnings: &[String]) -> String {
        warnings
            .iter()
            .map(|warning| self.labelled("warning", warning, 0))
            .collect()
    }

    /// Indented `note:` and `help:` lines under an outcome or an error.
    pub fn notes(self, notes: &[(String, String)]) -> String {
        notes
            .iter()
            .map(|(label, text)| self.labelled(label, text, 2))
            .collect()
    }

    /// `error: message` and its notes, then the `--json` tip in `agent` mode when `tip`.
    pub fn error(self, message: &str, notes: &[(String, String)], mode: Mode, tip: bool) -> String {
        let mut out = self.labelled("error", message, 0);
        out.push_str(&self.notes(notes));
        if tip {
            out.push_str(&self.agent_tip(mode));
        }
        out
    }

    /// `tip: add --json for machine-readable output`, in `agent` mode only.
    pub fn agent_tip(self, mode: Mode) -> String {
        if mode == Mode::Agent {
            self.labelled("tip", AGENT_TIP, 0)
        } else {
            String::new()
        }
    }

    /// At most [`MAX_NEXT_ACTIONS`] `→` lines, printed after the outcome line.
    /// At most three next steps, numbered, under a `Next steps` header
    /// (the brand's mark beside it in `human` mode), after a blank line.
    pub fn numbered_next_actions(self, actions: &[NextAction], mode: Mode) -> String {
        let shown: Vec<&NextAction> = actions.iter().take(MAX_NEXT_ACTIONS).collect();
        if shown.is_empty() {
            return String::new();
        }
        let mut out = String::from("\n");
        let bold = Style::new("bold");
        let mut header = Text::default();
        if mode == Mode::Human {
            let mark = if self.colour == Colour::Full {
                Style::new("bold color(231) on_color(18)")
            } else {
                Style::new("bold reverse")
            };
            header.append(" \u{224b} ", &mark);
            header.push_str(" ");
        }
        header.append("Next steps", &bold);
        out.push_str(&self.line(&header));
        let dim = Style::new("dim");
        for (number, action) in shown.iter().enumerate() {
            let mut line = Text::styled(&format!("  {}  ", number + 1), &dim);
            // The row is dim, the command bold on top of it (Rich's nesting).
            line.append(&action.command, &Style::new("bold dim"));
            if !action.reason.is_empty() {
                line.append(&format!(" {} ", glyphs::SEPARATOR), &dim);
                line.append(&action.reason, &dim);
            }
            out.push_str(&self.print_line(&line, 5));
        }
        out
    }

    /// At most three `→` next steps.
    pub fn next_actions(self, actions: &[NextAction]) -> String {
        actions
            .iter()
            .take(MAX_NEXT_ACTIONS)
            .map(|action| self.print_line(&next_action_text(action), 2))
            .collect()
    }
}

/// `✓ message`, `! message`, `✗ message`, `Skipped: message` or `Plan: …`.
pub fn outcome_text(kind: OutcomeKind, message: &str) -> Text {
    let style = kind.style();
    let mut line = Text::default();
    match kind {
        OutcomeKind::Plan => {
            match message.split_once(':') {
                Some((label, rest)) if !label.contains(' ') => {
                    line.append(&format!("{label}:"), &style);
                    line.push_str(rest);
                }
                _ => {
                    line.push_str(message);
                }
            }
            return line;
        }
        OutcomeKind::Skipped => {
            line.append("Skipped:", &style);
        }
        OutcomeKind::Ok => {
            line.append(glyphs::OK, &style);
        }
        OutcomeKind::Warning => {
            line.append(glyphs::WARNING, &style);
        }
        OutcomeKind::Failed => {
            line.append(glyphs::FAILED, &style);
        }
    }
    line.push_str(" ");
    line.push_str(message);
    line
}

/// The style of a line's label.
fn label_style(label: &str) -> Style {
    Style::new(match label {
        "error" => "bold red",
        "warning" => "bold yellow",
        "note" => "bold blue",
        "help" | "tip" => "bold cyan",
        _ => "bold",
    })
}

/// `error: message`, `  help: message` and so on.
pub fn labelled_text(label: &str, message: &str, indent: usize) -> Text {
    let mut line = Text::plain(&" ".repeat(indent));
    line.append(&format!("{label}:"), &label_style(label));
    line.push_str(" ");
    line.push_str(message);
    line
}

/// `→ opentide lint --fix · rename 2 files to match their names`.
pub fn next_action_text(action: &NextAction) -> Text {
    let mut line = Text::default();
    line.append(glyphs::NEXT, &Style::new("bold cyan"));
    line.push_str(" ");
    line.append(&action.command, &Style::new("bold"));
    if !action.reason.is_empty() {
        let dim = Style::new("dim");
        line.append(&format!(" {} ", glyphs::SEPARATOR), &dim);
        line.append(&action.reason, &dim);
    }
    line
}

/// One word of a line being wrapped: characters `start..end`, the spaces up
/// to the next word after it, measured in terminal cells.
#[derive(Debug)]
struct Word {
    start: usize,
    end: usize,
    cells: usize,
    space: usize,
}

impl textwrap::core::Fragment for Word {
    #[expect(clippy::cast_precision_loss, reason = "a line's cells, far below 2^52")]
    fn width(&self) -> f64 {
        self.cells as f64
    }

    #[expect(clippy::cast_precision_loss, reason = "a line's cells, far below 2^52")]
    fn whitespace_width(&self) -> f64 {
        self.space as f64
    }

    fn penalty_width(&self) -> f64 {
        0.0
    }
}

/// `line` broken at spaces into rows of `width` cells, rows after the first
/// `hang` in, by textwrap's first-fit algorithm.
///
/// A word is never split, so a path or URL wider than a row stays whole (the
/// terminal wraps it and it can still be selected); the first row keeps the
/// label and the first word of the message together, its indent with them.
pub fn word_wrap(line: &Text, width: usize, hang: usize) -> Vec<Text> {
    let plain: Vec<char> = line.as_plain().chars().collect();
    let cells = |a: usize, b: usize| -> usize { plain[a..b].iter().copied().map(char_width).sum() };
    // The words, as runs of characters between whitespace.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut index = 0;
    while index < plain.len() {
        if plain[index].is_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        while index < plain.len() && !plain[index].is_whitespace() {
            index += 1;
        }
        spans.push((start, index));
    }
    if spans.is_empty() {
        return vec![line.clone()];
    }
    // The first row starts with the line's indent, and its first two words
    // (the label and the first word of the message) are one fragment.
    let glued = spans.len().min(2);
    let mut fragments = vec![(0, spans[glued - 1].1)];
    fragments.extend_from_slice(&spans[glued..]);
    let words: Vec<Word> = fragments
        .iter()
        .enumerate()
        .map(|(at, &(start, end))| {
            let next = fragments.get(at + 1).map_or(plain.len(), |next| next.0);
            Word {
                start,
                end,
                cells: cells(start, end),
                space: cells(end, next),
            }
        })
        .collect();
    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    let widths = [width as f64, width.saturating_sub(hang) as f64];
    let rows = textwrap::wrap_algorithms::wrap_first_fit(&words, &widths);
    let count = rows.len();
    rows.into_iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let (first, last) = (row.first()?, row.last()?);
            let start = if index == 0 { 0 } else { first.start };
            let end = if index + 1 == count {
                plain.len()
            } else {
                last.end
            };
            Some(if index == 0 {
                line.slice(start, end)
            } else {
                let mut led = Text::plain(&" ".repeat(hang));
                led.append_text(&line.slice(start, end));
                led
            })
        })
        .collect()
}

/// What a command's result says, as the text modes print it.
#[derive(Clone, Debug, Default)]
pub struct ResultView {
    /// The result's message.
    pub message: String,
    /// The outcome line, when it is not the message.
    pub outcome: Option<String>,
    /// `completed`, `issues`, `skipped` or `failed`.
    pub status: String,
    /// Whether the command succeeded.
    pub ok: bool,
    /// The outcome line's kind when the status alone does not say (a plan).
    pub outcome_kind: Option<OutcomeKind>,
    /// `failure.code` and `failure.suggestion`, when it failed.
    pub failure: Option<(String, Option<String>)>,
    /// `detail` (a `note:`) and `advice` (a `help:`).
    pub detail: Option<String>,
    /// See `detail`.
    pub advice: Option<String>,
    /// `warning:` lines.
    pub warnings: Vec<String>,
    /// Next steps.
    pub next_actions: Vec<NextAction>,
    /// The next steps as a numbered list under a `Next steps` header.
    pub numbered_next: bool,
}

/// A result's text: `(stdout, stderr)`.
///
/// Warnings first, then exactly one outcome line: an `error:` line for a
/// failure, a `✗` line on stderr when it failed with findings it printed
/// (`issues_found`), otherwise the outcome on stdout; then its notes and at
/// most three next steps; in `agent` mode the `--json` tip last when it failed.
pub fn render_result(
    result: &ResultView,
    stdout: Console,
    stderr: Console,
    mode: Mode,
    quiet: bool,
) -> (String, String) {
    let (mut out, mut err) = (String::new(), String::new());
    let mut notes: Vec<(String, String)> = Vec::new();
    for (label, value) in [("note", &result.detail), ("help", &result.advice)] {
        if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
            notes.push((label.to_owned(), value.clone()));
        }
    }
    if !quiet {
        err.push_str(&stderr.warnings(&result.warnings));
    }
    let mut kind = OutcomeKind::of(&result.status, result.ok);
    if let Some(own) = result.outcome_kind
        && (kind != OutcomeKind::Failed || own == OutcomeKind::Plan)
    {
        kind = own;
    }
    let line = result
        .outcome
        .clone()
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| result.message.clone());
    let framed = result
        .failure
        .as_ref()
        .is_some_and(|(code, _)| FRAMED_FAILURES.contains(&code.as_str()));
    if kind == OutcomeKind::Failed && framed {
        err.push_str(&stderr.outcome(OutcomeKind::Failed, &line));
        err.push_str(&stderr.notes(&notes));
        if !quiet {
            err.push_str(&stderr.next_actions(&result.next_actions));
        }
        err.push_str(&stderr.agent_tip(mode));
    } else if kind == OutcomeKind::Failed {
        if let Some((_, Some(suggestion))) = &result.failure
            && !suggestion.is_empty()
            && !result.message.contains(&quoted(suggestion))
        {
            notes.push((
                "help".to_owned(),
                format!("did you mean {}?", quoted(suggestion)),
            ));
        }
        err.push_str(&stderr.error(&result.message, &notes, mode, false));
        if !quiet {
            err.push_str(&stderr.next_actions(&result.next_actions));
        }
        err.push_str(&stderr.agent_tip(mode));
    } else {
        out.push_str(&stdout.outcome(kind, &line));
        if !quiet {
            out.push_str(&stdout.notes(&notes));
            if result.numbered_next {
                out.push_str(&stdout.numbered_next_actions(&result.next_actions, mode));
            } else {
                out.push_str(&stdout.next_actions(&result.next_actions));
            }
        }
        if !result.ok && mode == Mode::Agent {
            err.push_str(&stderr.labelled("tip", AGENT_TIP, 0));
        }
    }
    (out, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIPE: Console = Console {
        colour: Colour::None,
        width: None,
    };

    fn rows(line: &str, width: usize, hang: usize) -> Vec<String> {
        word_wrap(&Text::plain(line), width, hang)
            .iter()
            .map(Text::as_plain)
            .collect()
    }

    #[test]
    fn word_wrap_keeps_words_and_the_label_whole() {
        // The label and the first word stay together, even wider than the row.
        assert_eq!(
            rows("error: averyveryverylongword next", 10, 7),
            ["error: averyveryverylongword", "       next"]
        );
        // A word wider than a row has the row to itself, unsplit.
        assert_eq!(
            rows("✓ a b /a/very/long/path/to/a/file.yaml c", 12, 2),
            ["✓ a b", "  /a/very/long/path/to/a/file.yaml", "  c"]
        );
        // The indent stays with the first row; the last row keeps its tail.
        assert_eq!(
            rows("  help: one two three ", 16, 8),
            ["  help: one two", "        three "]
        );
        // Rows are measured in cells: two wide characters are four.
        assert_eq!(rows("! 名前 名前 名前", 11, 2), ["! 名前 名前", "  名前"]);
        assert_eq!(
            rows("! 名前 名前 名前", 9, 2),
            ["! 名前", "  名前", "  名前"]
        );
        assert_eq!(rows("x", 1, 0), ["x"]);
        assert_eq!(rows("   ", 1, 0), ["   "]);
    }

    #[test]
    fn a_line_break_in_a_message_continues_under_its_text() {
        assert_eq!(
            PIPE.labelled("warning", "a\n::error::x", 0),
            "warning: a\n         ::error::x\n"
        );
        let console = Console {
            colour: Colour::None,
            width: Some(20),
        };
        assert_eq!(
            console.outcome(OutcomeKind::Failed, "two\n::error::x and more words"),
            "✗ two\n  ::error::x and\n  more words\n"
        );
        assert_eq!(console.labelled("error", "\u{1b}[2J", 0), "error: ␛[2J\n");
    }

    #[test]
    fn kinds() {
        assert_eq!(OutcomeKind::of("completed", true), OutcomeKind::Ok);
        assert_eq!(OutcomeKind::of("issues", true), OutcomeKind::Warning);
        assert_eq!(OutcomeKind::of("skipped", true), OutcomeKind::Skipped);
        assert_eq!(OutcomeKind::of("completed", false), OutcomeKind::Failed);
        assert_eq!(OutcomeKind::of("failed", true), OutcomeKind::Failed);
    }

    #[test]
    fn results_go_to_their_stream() {
        let mut result = ResultView {
            message: "Validation passed".into(),
            status: "completed".into(),
            ok: true,
            advice: Some("look".into()),
            warnings: vec!["w".into()],
            next_actions: vec![NextAction::new("opentide x", "why")],
            ..ResultView::default()
        };
        assert_eq!(
            render_result(&result, PIPE, PIPE, Mode::Plain, false),
            (
                "✓ Validation passed\n  help: look\n→ opentide x · why\n".to_owned(),
                "warning: w\n".to_owned()
            )
        );
        result.ok = false;
        result.status = "failed".into();
        result.failure = Some(("issues_found".into(), None));
        result.outcome = Some("3 errors".into());
        assert_eq!(
            render_result(&result, PIPE, PIPE, Mode::Agent, true),
            (
                String::new(),
                "✗ 3 errors\n  help: look\ntip: add --json for machine-readable output\n"
                    .to_owned()
            )
        );
        result.failure = Some(("usage_invalid_choice".into(), Some("rule".into())));
        result.message = "No such type".into();
        let (_, err) = render_result(&result, PIPE, PIPE, Mode::Plain, false);
        assert_eq!(
            err,
            "warning: w\nerror: No such type\n  help: look\n  help: did you mean 'rule'?\n→ opentide x · why\n"
        );
        let numbered = ResultView {
            message: "Created X here".into(),
            status: "completed".into(),
            ok: true,
            next_actions: vec![
                NextAction::new("opentide generate", "schemas"),
                NextAction::new("opentide validate", ""),
            ],
            numbered_next: true,
            ..ResultView::default()
        };
        assert_eq!(
            render_result(&numbered, PIPE, PIPE, Mode::Plain, false).0,
            "✓ Created X here\n\nNext steps\n  1  opentide generate · schemas\n  2  opentide validate\n"
        );
        let full = Console {
            colour: Colour::Full,
            width: None,
        };
        assert!(
            render_result(&numbered, full, PIPE, Mode::Human, false)
                .0
                .contains(
                    "\n\u{1b}[1;38;5;231;48;5;18m \u{224b} \u{1b}[0m \u{1b}[1mNext steps\u{1b}[0m\n"
                )
        );
        let plan = ResultView {
            message: "Plan: 1 to create".into(),
            status: "failed".into(),
            ok: false,
            outcome_kind: Some(OutcomeKind::Plan),
            ..ResultView::default()
        };
        assert_eq!(
            render_result(&plan, PIPE, PIPE, Mode::Agent, false),
            (
                "Plan: 1 to create\n".to_owned(),
                "tip: add --json for machine-readable output\n".to_owned()
            )
        );
    }
}
