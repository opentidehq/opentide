//! The labelled lines every mode but `json` prints, with their styles.
//!
//! `error: message`, then indented `help:` and `usage:` notes, `→ command ·
//! reason` next actions and, in `agent` mode, the `--json` tip
//! (`docs/internal/cli-experience.md`). Colour is one SGR sequence per span
//! (`ESC[1;31m`), as the oracle writes it, in `human` mode only.

use crate::envelope::NextAction;
use crate::mode::Mode;

/// The agent tip, the last line of a failure in `agent` mode.
pub const AGENT_TIP: &str = "add --json for machine-readable output";

/// Styles, or none. `human` mode writes bold, dim and colour; `plain` mode
/// on a terminal (`--no-color`, `NO_COLOR`) keeps bold and dim and drops the
/// colour, as the oracle does; a pipe, `agent` and `json` get plain text.
#[derive(Clone, Copy, Debug)]
pub struct Painter {
    ansi: bool,
    colour: bool,
    width: Option<usize>,
}

impl Painter {
    /// The painter of `mode` on a terminal.
    pub fn new(mode: Mode) -> Painter {
        Painter {
            ansi: mode == Mode::Human,
            colour: mode == Mode::Human,
            width: None,
        }
    }

    /// The painter of `mode` on a stream, a terminal or not, `TERM=dumb` or not.
    pub fn for_stream(mode: Mode, tty: bool, dumb: bool) -> Painter {
        let ansi = tty && !dumb && matches!(mode, Mode::Human | Mode::Plain);
        Painter {
            ansi,
            colour: ansi && mode == Mode::Human,
            width: None,
        }
    }

    /// This painter, wrapping lines at `width` columns: on a terminal, a line
    /// wraps at word boundaries under its label; a pipe gets each line whole
    /// (soft wrap), for the reader's terminal to wrap.
    #[must_use]
    pub fn wrapping(mut self, width: Option<usize>) -> Painter {
        self.width = width.filter(|_| self.ansi);
        self
    }

    /// `text` in `style`.
    pub fn paint(self, style: Style, text: &str) -> String {
        if !self.ansi || text.is_empty() {
            return text.to_owned();
        }
        let codes = if self.colour {
            style.0.to_owned()
        } else {
            style
                .0
                .split(';')
                .filter(|code| matches!(*code, "1" | "2" | "3" | "4"))
                .collect::<Vec<_>>()
                .join(";")
        };
        if codes.is_empty() {
            text.to_owned()
        } else {
            format!("\u{1b}[{codes}m{text}\u{1b}[0m")
        }
    }
}

/// An SGR style: the parameters between `ESC[` and `m`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style(pub &'static str);

/// Bold.
pub fn bold() -> Style {
    Style("1")
}

/// Dim.
pub fn dim() -> Style {
    Style("2")
}

/// The style of a label.
pub fn label_style(label: &str) -> Style {
    match label {
        "error" => Style("1;31"),
        "help" | "→" => Style("1;36"),
        "warning" => Style("1;33"),
        "✓" => Style("1;32"),
        _ => bold(),
    }
}

/// `label: text`, the label styled.
pub fn labelled(painter: Painter, label: &str, text: &str) -> String {
    labelled_at(painter, 0, label, text)
}

/// `label: text` after `indent` spaces, wrapped under the text when the
/// painter wraps.
fn labelled_at(painter: Painter, indent: usize, label: &str, text: &str) -> String {
    let head = format!("{}{label}: ", " ".repeat(indent));
    let styled = format!(
        "{}{} ",
        " ".repeat(indent),
        painter.paint(label_style(label), &format!("{label}:"))
    );
    let Some(width) = painter.width else {
        return format!("{styled}{text}");
    };
    let hang = " ".repeat(head.chars().count());
    let options = textwrap::Options::new(width)
        .initial_indent(&head)
        .subsequent_indent(&hang)
        .word_splitter(textwrap::WordSplitter::NoHyphenation);
    let wrapped = textwrap::fill(text, options);
    wrapped.replacen(&head, &styled, 1)
}

/// A failure's lines: `error:`, its notes indented by two, then the next
/// actions, then the agent tip in `agent` mode.
pub fn error_lines(
    mode: Mode,
    painter: Painter,
    message: &str,
    notes: &[(String, String)],
    next: &[NextAction],
) -> String {
    let mut out = labelled(painter, "error", message);
    out.push('\n');
    for (label, text) in notes {
        out.push_str(&labelled_at(painter, 2, label, text));
        out.push('\n');
    }
    for action in next {
        out.push_str(&next_action_line(painter, action));
        out.push('\n');
    }
    if mode == Mode::Agent {
        out.push_str(&labelled(painter, "tip", AGENT_TIP));
        out.push('\n');
    }
    out
}

/// `→ command · reason`.
pub fn next_action_line(painter: Painter, action: &NextAction) -> String {
    let mut line = format!(
        "{} {}",
        painter.paint(label_style("→"), "→"),
        painter.paint(bold(), &action.command)
    );
    if !action.reason.is_empty() {
        line.push_str(&painter.paint(dim(), " · "));
        line.push_str(&painter.paint(dim(), &action.reason));
    }
    line
}

/// `✓ message`: a successful outcome line.
pub fn success_line(painter: Painter, message: &str) -> String {
    format!("{} {message}\n", painter.paint(label_style("✓"), "✓"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_style_human_colours_and_plain_does_not() {
        let notes = vec![("help".to_owned(), "did you mean 'validate'?".to_owned())];
        assert_eq!(
            error_lines(
                Mode::Human,
                Painter::new(Mode::Human),
                "No such command 'x'.",
                &notes,
                &[]
            ),
            "\u{1b}[1;31merror:\u{1b}[0m No such command 'x'.\n  \u{1b}[1;36mhelp:\u{1b}[0m did you mean 'validate'?\n"
        );
        let next = [NextAction::new("opentide --help", "why")];
        assert_eq!(
            error_lines(Mode::Agent, Painter::new(Mode::Agent), "m", &[], &next),
            "error: m\n→ opentide --help · why\ntip: add --json for machine-readable output\n"
        );
        assert_eq!(
            success_line(Painter::new(Mode::Plain), "58 commands"),
            "✓ 58 commands\n"
        );
        let no_colour = Painter::for_stream(Mode::Plain, true, false);
        assert_eq!(success_line(no_colour, "x"), "\u{1b}[1m✓\u{1b}[0m x\n");
        assert_eq!(no_colour.paint(Style("31"), "r"), "r");
        assert_eq!(
            Painter::for_stream(Mode::Human, true, true).paint(bold(), "b"),
            "b"
        );
        assert_eq!(
            Painter::for_stream(Mode::Agent, true, false).paint(bold(), "b"),
            "b"
        );
        let narrow = Painter::for_stream(Mode::Plain, true, false).wrapping(Some(22));
        assert_eq!(
            labelled_at(narrow, 2, "help", "did you mean the-long-word here?"),
            "  \u{1b}[1mhelp:\u{1b}[0m did you mean\n        the-long-word\n        here?"
        );
        let pipe = Painter::for_stream(Mode::Plain, false, false).wrapping(Some(20));
        assert_eq!(
            labelled(pipe, "error", "a b c d e f g h i j k l m"),
            "error: a b c d e f g h i j k l m"
        );
        assert_eq!(
            next_action_line(
                Painter::new(Mode::Plain),
                &NextAction::new("opentide x", "")
            ),
            "→ opentide x"
        );
    }
}
