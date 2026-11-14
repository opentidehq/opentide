//! The opentide marks for the terminal (`brand.py`): pixel grids drawn with
//! upper half-blocks, two pixel rows to a line, and the one-line pill.
//!
//! Reflex Blue (`#001489`) is a fill, drawn as the terminal's 256-colour
//! `18`, white as `231`. Without colour the shapes stay: the blue pixels are
//! drawn in the terminal's own foreground and the rest left blank.

use super::text::{Colour, Text};
use anstyle::{Ansi256Color, Style};

/// Said wherever the product describes itself.
pub const TAGLINE: &str = "Spec-driven development for agentic detection engineering";

/// Reflex Blue as the terminal's 256 colours give it.
const BLUE: Ansi256Color = Ansi256Color(18);
/// White as the terminal's 256 colours give it.
const WHITE: Ansi256Color = Ansi256Color(231);

/// A pixel's colour; `.` is the terminal's own background.
fn pixel(cell: char) -> Option<Ansi256Color> {
    match cell {
        'B' => Some(BLUE),
        'W' => Some(WHITE),
        _ => None,
    }
}

/// The ` ≋ ` mark's style: white on Reflex Blue, in reverse video without colour.
pub fn mark_style(colour: Colour) -> Style {
    if colour == Colour::Full {
        WHITE.on(BLUE).bold()
    } else {
        Style::new().bold().invert()
    }
}

/// `rows` (pixels: `B` blue, `W` white, `.` none) as lines, two pixel rows to
/// a line (`brand.render`): in colour each cell takes the top pixel as its
/// foreground and the bottom one as its background.
pub fn grid(rows: &[&str], colour: Colour) -> Vec<Text> {
    rows.chunks(2)
        .map(|pair| {
            let top = pair[0];
            let bottom = pair.get(1).copied().unwrap_or("");
            let mut line = Text::default();
            for (index, upper) in top.chars().enumerate() {
                let lower = bottom.chars().nth(index).unwrap_or('.');
                if colour != Colour::Full {
                    let cell = match (upper == 'B', lower == 'B') {
                        (true, true) => "█",
                        (true, false) => "▀",
                        (false, true) => "▄",
                        (false, false) => " ",
                    };
                    line.push_str(cell);
                    continue;
                }
                match (pixel(upper), pixel(lower)) {
                    (None, None) => {
                        line.push_str(" ");
                    }
                    (None, Some(lower)) => {
                        line.append("▄", &lower.on_default());
                    }
                    (Some(upper), None) => {
                        line.append("▀", &upper.on_default());
                    }
                    (Some(upper), Some(lower)) if upper == lower => {
                        line.append("█", &upper.on_default());
                    }
                    (Some(upper), Some(lower)) => {
                        line.append("▀", &upper.on(lower));
                    }
                }
            }
            line
        })
        .collect()
}

/// `▐ ≋ opentide ▌`, the one-line mark (`brand.pill`): white on a Reflex
/// Blue pill, in reverse video without colour.
pub fn pill(colour: Colour) -> Text {
    let edge = if colour == Colour::Full {
        BLUE.on_default()
    } else {
        Style::new()
    };
    let mut text = Text::styled("▐", &edge);
    text.append(" ≋ opentide ", &mark_style(colour));
    text.append("▌", &edge);
    text
}

/// A section header (`brand.header`): ` ≋ ` on a blue square, then `label`
/// in bold.
pub fn header(label: &str, colour: Colour) -> Text {
    let mut text = Text::styled(" ≋ ", &mark_style(colour));
    text.push_str(" ");
    text.append(label, &Style::new().bold());
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grid_is_two_pixel_rows_a_line() {
        let lines = grid(&[".B", "BW"], Colour::Full);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].render(Colour::Full, false),
            "\u{1b}[38;5;18m▄\u{1b}[0m\u{1b}[38;5;18m\u{1b}[48;5;231m▀\u{1b}[0m"
        );
        assert_eq!(grid(&["BB.", "B.."], Colour::None)[0].as_plain(), "█▀ ");
        // An odd row out is drawn over nothing.
        assert_eq!(grid(&["B"], Colour::None)[0].as_plain(), "▀");
    }

    #[test]
    fn the_header_is_a_mark_and_a_bold_label() {
        assert_eq!(
            header("Next", Colour::Full).render(Colour::Full, false),
            "\u{1b}[1m\u{1b}[38;5;231m\u{1b}[48;5;18m ≋ \u{1b}[0m \u{1b}[1mNext\u{1b}[0m"
        );
        assert_eq!(header("Next", Colour::None).as_plain(), " ≋  Next");
    }
}
