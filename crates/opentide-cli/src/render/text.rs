//! Styled text: a string and the styled spans over it, written as the terminal reads it.
//!
//! The renderers build each line as a [`Text`] and write it with
//! [`Text::render`]: each run of text written the same in its [`anstyle`]
//! style, an OSC 8 hyperlink around a linked run, and the bare text where no
//! style applies. Widths are terminal cells ([`cell_len`], the
//! `unicode-width` crate); offsets are characters, as in the code frames'
//! columns.

use anstyle::Style;
use unicode_width::UnicodeWidthChar;

/// The cells `text` takes in a terminal: a wide character two, a combining one none.
pub fn cell_len(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// The cells one character takes as a [`Text`] shows it: a control character
/// it drops none, one it shows as a picture ([`shown`]) one.
pub fn char_width(ch: char) -> usize {
    shown(ch).map_or(0, |ch| ch.width().unwrap_or(0))
}

/// How a [`Text`] holds `ch`: `None` for the controls a terminal would act on
/// mid-line and the oracle dropped (bell, backspace, vertical tab, form feed,
/// carriage return); the Unicode control picture (`␛`, `␀`, `␡`) for the other
/// C0 controls but tab and newline and for DEL, and `�` for a C1 control, so
/// text from a file never reaches the terminal as an escape sequence; else `ch`.
pub fn shown(ch: char) -> Option<char> {
    match ch {
        '\u{7}' | '\u{8}' | '\u{b}' | '\u{c}' | '\r' => None,
        '\t' | '\n' => Some(ch),
        '\u{0}'..='\u{1f}' => char::from_u32(0x2400 + u32::from(ch)),
        '\u{7f}' => Some('\u{2421}'),
        '\u{80}'..='\u{9f}' => Some(char::REPLACEMENT_CHARACTER),
        _ => Some(ch),
    }
}

/// How much of a style a stream gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Colour {
    /// No escape sequences at all: a pipe, a file, a CI log.
    None,
    /// Bold, dim, italic and underline, no colour: `--no-color` or `NO_COLOR` on a terminal.
    Mono,
    /// Everything: `human` mode on a terminal.
    Full,
}

/// `base` with `top` drawn over it: their effects add up, `top`'s colours win.
pub fn layer(base: Style, top: Style) -> Style {
    base.effects(base.get_effects() | top.get_effects())
        .fg_color(top.get_fg_color().or(base.get_fg_color()))
        .bg_color(top.get_bg_color().or(base.get_bg_color()))
}

/// A styled span: characters `start..end` of a [`Text`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Span {
    start: usize,
    end: usize,
    style: Style,
    link: Option<String>,
}

/// A line of text with styled spans; later spans are drawn over earlier ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Text {
    chars: Vec<char>,
    spans: Vec<Span>,
}

/// `text` as a [`Text`] holds it: each character [`shown`].
fn strip_control(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().filter_map(shown)
}

impl Text {
    /// Unstyled `text`.
    pub fn plain(text: &str) -> Text {
        Text {
            chars: strip_control(text).collect(),
            spans: Vec::new(),
        }
    }

    /// `text` in `style`.
    pub fn styled(text: &str, style: &Style) -> Text {
        let mut out = Text::default();
        out.append(text, style);
        out
    }

    /// The text without its styles.
    pub fn as_plain(&self) -> String {
        self.chars.iter().collect()
    }

    /// Its length in characters.
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Whether it holds no character.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// The cells it takes in a terminal.
    pub fn cell_len(&self) -> usize {
        self.chars.iter().copied().map(char_width).sum()
    }

    /// Adds `text` in `style` (none when `style` is plain) at the end.
    pub fn append(&mut self, text: &str, style: &Style) -> &mut Text {
        let start = self.chars.len();
        self.chars.extend(strip_control(text));
        let end = self.chars.len();
        if end > start && !style.is_plain() {
            self.spans.push(Span {
                start,
                end,
                style: *style,
                link: None,
            });
        }
        self
    }

    /// Adds `text` at the end, linked to `url` (an OSC 8 hyperlink where links are written).
    pub fn append_link(&mut self, text: &str, url: String) -> &mut Text {
        let start = self.chars.len();
        self.chars.extend(strip_control(text));
        let end = self.chars.len();
        self.spans.push(Span {
            start,
            end,
            style: Style::new(),
            link: Some(url),
        });
        self
    }

    /// Adds unstyled `text` at the end.
    pub fn push_str(&mut self, text: &str) -> &mut Text {
        self.append(text, &Style::new())
    }

    /// Adds `other`, its spans with it, at the end.
    pub fn append_text(&mut self, other: &Text) -> &mut Text {
        let offset = self.chars.len();
        self.chars.extend_from_slice(&other.chars);
        self.spans.extend(other.spans.iter().map(|span| Span {
            start: span.start + offset,
            end: span.end + offset,
            ..span.clone()
        }));
        self
    }

    /// Styles characters `start..end` (clipped to the text) in `style`, over the others.
    pub fn stylize(&mut self, style: &Style, start: usize, end: usize) {
        let end = end.min(self.chars.len());
        if start >= end || style.is_plain() {
            return;
        }
        self.spans.push(Span {
            start,
            end,
            style: *style,
            link: None,
        });
    }

    /// Characters `start..end`, with the parts of the spans over them.
    pub fn slice(&self, start: usize, end: usize) -> Text {
        let end = end.min(self.chars.len());
        let start = start.min(end);
        Text {
            chars: self.chars[start..end].to_vec(),
            spans: self
                .spans
                .iter()
                .filter(|span| span.start < end && span.end > start)
                .map(|span| Span {
                    start: span.start.max(start) - start,
                    end: span.end.min(end) - start,
                    ..span.clone()
                })
                .collect(),
        }
    }

    /// The text split at each newline, the spans with each part.
    pub fn split_lines(&self) -> Vec<Text> {
        let mut parts = Vec::new();
        let mut start = 0;
        for (index, ch) in self.chars.iter().enumerate() {
            if *ch == '\n' {
                parts.push(self.slice(start, index));
                start = index + 1;
            }
        }
        parts.push(self.slice(start, self.chars.len()));
        parts
    }

    /// Removes trailing whitespace, and the parts of spans over it.
    pub fn rstrip(&mut self) {
        let keep = self
            .chars
            .iter()
            .rposition(|ch| !ch.is_whitespace())
            .map_or(0, |index| index + 1);
        *self = self.slice(0, keep);
    }

    /// At most `width` cells: a longer text is cut to `width - 1` cells (a space
    /// where a wide character no longer fits) and ends in `…`, which keeps the
    /// styles over its position.
    pub fn truncate_ellipsis(&mut self, width: usize) {
        if self.cell_len() <= width || width == 0 {
            return;
        }
        let room = width - 1;
        let mut cells = 0;
        let mut kept = Vec::new();
        for ch in &self.chars {
            let next = cells + char_width(*ch);
            if next > room {
                break;
            }
            cells = next;
            kept.push(*ch);
        }
        kept.extend(std::iter::repeat_n(' ', room - cells));
        kept.push('…');
        let length = kept.len();
        self.chars = kept;
        self.spans.retain(|span| span.start < length);
        for span in &mut self.spans {
            span.end = span.end.min(length);
        }
    }

    /// Tabs as spaces to the next stop of 8 cells, as a terminal shows them: a tab
    /// becomes a space, then as many more as reach the stop, styled as the tab was.
    pub fn expand_tabs(&mut self) {
        if !self.chars.contains(&'\t') {
            return;
        }
        // The parts after each tab, styles split at the part boundaries.
        let mut bounds = vec![0];
        bounds.extend(
            self.chars
                .iter()
                .enumerate()
                .filter(|(_, ch)| **ch == '\t')
                .map(|(index, _)| index + 1),
        );
        if bounds.last() != Some(&self.chars.len()) {
            bounds.push(self.chars.len());
        }
        let mut out = Text::default();
        let mut cells = 0;
        for window in bounds.windows(2) {
            let mut part = self.slice(window[0], window[1]);
            if part.chars.last() == Some(&'\t') {
                let last = part.chars.len() - 1;
                part.chars[last] = ' ';
                cells += part.cell_len();
                let remainder = cells % 8;
                if remainder != 0 {
                    let spaces = 8 - remainder;
                    let end = part.chars.len();
                    for span in &mut part.spans {
                        if span.end >= end {
                            span.end += spaces;
                        }
                    }
                    part.chars.extend(std::iter::repeat_n(' ', spaces));
                    cells += spaces;
                }
            } else {
                cells += part.cell_len();
            }
            out.append_text(&part);
        }
        *self = out;
    }

    /// The text as written to a stream at `colour`: each run of characters
    /// written the same in its style and a reset, a linked run inside an OSC 8
    /// hyperlink (`links`), the rest bare. [`Colour::Mono`] keeps the effects
    /// and drops the colours.
    pub fn render(&self, colour: Colour, links: bool) -> String {
        if colour == Colour::None && !links || self.spans.is_empty() {
            return self.as_plain();
        }
        let mut bounds: Vec<usize> = vec![0, self.chars.len()];
        bounds.extend(self.spans.iter().flat_map(|span| [span.start, span.end]));
        bounds.sort_unstable();
        bounds.dedup();
        // (style, link, text): neighbours written the same are one run.
        let mut runs: Vec<(Style, Option<&str>, String)> = Vec::new();
        for window in bounds.windows(2) {
            let (start, end) = (window[0], window[1]);
            let over = || {
                self.spans
                    .iter()
                    .filter(|span| span.start <= start && span.end >= end)
            };
            let style = over().fold(Style::new(), |style, span| layer(style, span.style));
            let style = match colour {
                Colour::None => Style::new(),
                Colour::Mono => style.fg_color(None).bg_color(None),
                Colour::Full => style,
            };
            let link = over()
                .filter_map(|span| span.link.as_deref())
                .next_back()
                .filter(|_| links);
            let chars = self.chars[start..end].iter();
            match runs.last_mut() {
                Some((last_style, last_link, text))
                    if *last_style == style && *last_link == link =>
                {
                    text.extend(chars);
                }
                _ => runs.push((style, link, chars.collect())),
            }
        }
        let mut out = String::new();
        for (style, link, text) in runs {
            match link {
                Some(url) => out.push_str(&format!(
                    "\u{1b}]8;;{url}\u{1b}\\{style}{text}{style:#}\u{1b}]8;;\u{1b}\\"
                )),
                None => out.push_str(&format!("{style}{text}{style:#}")),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anstyle::{Ansi256Color, AnsiColor};

    const RED: Style = AnsiColor::Red.on_default();
    const BLUE: Style = AnsiColor::Blue.on_default();

    #[test]
    fn layers_add_effects_and_the_top_colour_wins() {
        let combined = layer(RED.bold(), BLUE.underline());
        assert_eq!(combined, BLUE.bold().underline());
        let background = Ansi256Color(231).on(Ansi256Color(18));
        assert_eq!(layer(background, Style::new().bold()), background.bold());
    }

    #[test]
    fn render_one_style_per_run_written_the_same() {
        let mut text = Text::default();
        text.append("ab", &BLUE);
        text.append("c", &BLUE);
        text.push_str(" d");
        assert_eq!(text.render(Colour::Full, false), "\u{1b}[34mabc\u{1b}[0m d");
        // Blue and red differ in colour, not without it.
        let mut two = Text::styled("a", &BLUE.bold());
        two.append("b", &RED.bold());
        assert_eq!(
            two.render(Colour::Full, false),
            "\u{1b}[1m\u{1b}[34ma\u{1b}[0m\u{1b}[1m\u{1b}[31mb\u{1b}[0m"
        );
        assert_eq!(two.render(Colour::Mono, false), "\u{1b}[1mab\u{1b}[0m");
        assert_eq!(text.render(Colour::Mono, false), "abc d");
        assert_eq!(text.render(Colour::None, false), "abc d");
        let brand = Text::styled("x", &Ansi256Color(231).on(Ansi256Color(18)).bold());
        assert_eq!(
            brand.render(Colour::Full, false),
            "\u{1b}[1m\u{1b}[38;5;231m\u{1b}[48;5;18mx\u{1b}[0m"
        );
        assert_eq!(brand.render(Colour::Mono, false), "\u{1b}[1mx\u{1b}[0m");
    }

    #[test]
    fn render_links_and_overlapping_styles() {
        let mut text = Text::default();
        text.append_link("abc", "file:///a".to_owned());
        text.stylize(&Style::new().bold(), 1, 2);
        let (open, close) = ("\u{1b}]8;;file:///a\u{1b}\\", "\u{1b}]8;;\u{1b}\\");
        assert_eq!(
            text.render(Colour::Full, true),
            format!("{open}a{close}{open}\u{1b}[1mb\u{1b}[0m{close}{open}c{close}")
        );
        assert_eq!(text.render(Colour::Full, false), "a\u{1b}[1mb\u{1b}[0mc");
        assert_eq!(text.render(Colour::None, true), format!("{open}abc{close}"));
        assert_eq!(text.render(Colour::None, false), "abc");
    }

    #[test]
    fn control_characters_are_dropped_and_tabs_expand() {
        assert_eq!(Text::plain("a\r\nb\u{7}").as_plain(), "a\nb");
        // Escape sequences and other controls are shown, never written raw.
        let hostile = Text::styled("\u{1b}[2J\u{1b}]8;;x\u{7}\0\u{7f}\u{9b}", &RED);
        assert_eq!(hostile.as_plain(), "␛[2J␛]8;;x␀␡\u{fffd}");
        assert!(!hostile.render(Colour::None, false).contains('\u{1b}'));
        assert_eq!(
            hostile.render(Colour::Full, false),
            "\u{1b}[31m␛[2J␛]8;;x␀␡\u{fffd}\u{1b}[0m"
        );
        assert_eq!(char_width('\u{1b}'), 1);
        assert_eq!(char_width('\u{7}'), 0);
        assert_eq!(cell_len("\u{1b}[1m"), 4);
        let parts = Text::styled("a\nb", &RED).split_lines();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].render(Colour::Full, false), "\u{1b}[31mb\u{1b}[0m");
        let mut text = Text::styled("ab", &BLUE);
        text.push_str("\tc\t");
        text.expand_tabs();
        assert_eq!(text.as_plain(), "ab      c       ");
        let mut wide = Text::plain("名\tx");
        wide.expand_tabs();
        assert_eq!(wide.as_plain(), "名      x");
        let mut stop = Text::plain("1234567\tx");
        stop.expand_tabs();
        assert_eq!(stop.as_plain(), "1234567 x");
    }

    #[test]
    fn the_last_colour_drawn_wins_and_attributes_add_up() {
        let mut text = Text::styled("abc", &RED.bold());
        text.stylize(&BLUE, 1, 2);
        text.stylize(&Style::new().underline(), 2, 3);
        assert_eq!(
            text.render(Colour::Full, false),
            "\u{1b}[1m\u{1b}[31ma\u{1b}[0m\u{1b}[1m\u{1b}[34mb\u{1b}[0m\u{1b}[1m\u{1b}[4m\u{1b}[31mc\u{1b}[0m"
        );
        assert_eq!(
            text.render(Colour::Mono, false),
            "\u{1b}[1mab\u{1b}[0m\u{1b}[1m\u{1b}[4mc\u{1b}[0m"
        );
    }

    #[test]
    fn truncate_pads_where_a_wide_character_no_longer_fits() {
        let mut wide = Text::styled("名前名", &RED);
        wide.truncate_ellipsis(4);
        assert_eq!(wide.as_plain(), "名 …");
        assert_eq!(wide.cell_len(), 4);
        let mut fits = Text::plain("名前");
        fits.truncate_ellipsis(4);
        assert_eq!(fits.as_plain(), "名前");
        let mut ascii = Text::plain("abcdef");
        ascii.truncate_ellipsis(4);
        assert_eq!(ascii.as_plain(), "abc…");
    }

    #[test]
    fn slice_rstrip_and_cells() {
        let mut text = Text::styled("ab  ", &RED);
        text.rstrip();
        assert_eq!(text.render(Colour::Full, false), "\u{1b}[31mab\u{1b}[0m");
        assert_eq!(cell_len("名前x"), 5);
        assert_eq!(Text::plain("abc").slice(1, 9).as_plain(), "bc");
        assert!(Text::default().is_empty());
        assert_eq!(Text::plain("ab").len(), 2);
    }
}
