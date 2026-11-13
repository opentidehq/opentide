//! The opentide marks for the terminal (`brand.py`): pixel grids drawn with
//! upper half-blocks, two pixel rows to a line, and the one-line pill.
//!
//! Reflex Blue (`#001489`) is a fill, drawn as the terminal's 256-colour
//! `18`, white as `231`. Without colour the shapes stay: the blue pixels are
//! drawn in the terminal's own foreground and the rest left blank.

use super::text::{Colour, Style, Text};

/// Said wherever the product describes itself.
pub const TAGLINE: &str = "Spec-driven development for agentic detection engineering";

/// A pixel's 256-colour code: Reflex Blue as the terminal's 256 colours give
/// it, and white; `.` is the terminal's own background.
fn pixel(cell: char) -> Option<u8> {
    match cell {
        'B' => Some(18),
        'W' => Some(231),
        _ => None,
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
                        line.append("▄", &Style::new(&format!("color({lower})")));
                    }
                    (Some(upper), None) => {
                        line.append("▀", &Style::new(&format!("color({upper})")));
                    }
                    (Some(upper), Some(lower)) if upper == lower => {
                        line.append("█", &Style::new(&format!("color({upper})")));
                    }
                    (Some(upper), Some(lower)) => {
                        line.append(
                            "▀",
                            &Style::new(&format!("color({upper}) on_color({lower})")),
                        );
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
    let mut text = Text::default();
    if colour == Colour::Full {
        text.append("▐", &Style::new("color(18)"));
        text.append(" ≋ opentide ", &Style::new("bold color(231) on_color(18)"));
        text.append("▌", &Style::new("color(18)"));
    } else {
        text.push_str("▐");
        text.append(" ≋ opentide ", &Style::new("bold reverse"));
        text.push_str("▌");
    }
    text
}

/// A section header (`brand.header`): ` ≋ ` on a blue square, then `label`
/// in bold.
pub fn header(label: &str, colour: Colour) -> Text {
    let mark = if colour == Colour::Full {
        Style::new("bold color(231) on_color(18)")
    } else {
        Style::new("bold reverse")
    };
    let mut text = Text::styled(" ≋ ", &mark);
    text.push_str(" ");
    text.append(label, &Style::new("bold"));
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
            "\u{1b}[38;5;18m▄\u{1b}[0m\u{1b}[38;5;18;48;5;231m▀\u{1b}[0m"
        );
        assert_eq!(grid(&["BB.", "B.."], Colour::None)[0].as_plain(), "█▀ ");
        // An odd row out is drawn over nothing.
        assert_eq!(grid(&["B"], Colour::None)[0].as_plain(), "▀");
    }

    #[test]
    fn the_header_is_a_mark_and_a_bold_label() {
        assert_eq!(
            header("Next", Colour::Full).render(Colour::Full, false),
            "\u{1b}[1;38;5;231;48;5;18m ≋ \u{1b}[0m \u{1b}[1mNext\u{1b}[0m"
        );
        assert_eq!(header("Next", Colour::None).as_plain(), " ≋  Next");
    }
}
