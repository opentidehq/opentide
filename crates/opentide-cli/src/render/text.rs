//! Styled text: a string and the styled spans over it, written as the terminal reads it.
//!
//! The renderers build each line as a [`Text`] and write it with
//! [`Text::render`]: one SGR sequence per run of text between two span
//! boundaries (`ESC[1;31m…ESC[0m`), an OSC 8 hyperlink around a linked run,
//! and the bare text where no style applies. That is the byte layout the
//! oracle's terminal library writes, so a frame or an outcome line is the
//! same byte for byte (`docs/internal/cli-experience.md`, "Human output
//! grammar"). Widths are terminal cells ([`cell_len`], the `unicode-width`
//! crate); offsets are characters, as in the code frames' columns.

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

/// A text attribute or colour; [`Style::new`] parses the names the renderers use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the four SGR attributes the renderers use, each on or off"
)]
pub struct Style {
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    /// The SGR foreground code: `31` red, `96` bright cyan.
    fg: Option<u8>,
    /// Reverse video (`7`): the brand mark without colour.
    reverse: bool,
    /// A 256-colour foreground (`38;5;n`), `color(n)`.
    fg256: Option<u8>,
    /// A 256-colour background (`48;5;n`), `on_color(n)`.
    bg256: Option<u8>,
    link: Option<String>,
}

impl Style {
    /// A style from space-separated words: `bold`, `dim`, `italic`, `underline` and
    /// the colour names (`red`, `bright_cyan`). An unknown word is ignored.
    pub fn new(words: &str) -> Style {
        let mut style = Style::default();
        for word in words.split_whitespace() {
            match word {
                "bold" => style.bold = true,
                "dim" => style.dim = true,
                "italic" => style.italic = true,
                "underline" => style.underline = true,
                "reverse" => style.reverse = true,
                other if other.starts_with("color(") || other.starts_with("on_color(") => {
                    let number = other
                        .trim_end_matches(')')
                        .rsplit('(')
                        .next()
                        .and_then(|number| number.parse::<u8>().ok());
                    if other.starts_with("on_") {
                        style.bg256 = number;
                    } else {
                        style.fg256 = number;
                    }
                }
                other => {
                    if let Some(code) = colour_code(other) {
                        style.fg = Some(code);
                    }
                }
            }
        }
        style
    }

    /// A hyperlink to `url`, with no other style.
    pub fn link(url: impl Into<String>) -> Style {
        Style {
            link: Some(url.into()),
            ..Style::default()
        }
    }

    /// Whether the style changes nothing.
    pub fn is_plain(&self) -> bool {
        *self == Style::default()
    }

    /// `self`, then `other` on top: attributes add up, `other`'s colour and link win.
    pub fn combine(&self, other: &Style) -> Style {
        Style {
            bold: self.bold || other.bold,
            dim: self.dim || other.dim,
            italic: self.italic || other.italic,
            underline: self.underline || other.underline,
            fg: other.fg.or(self.fg),
            reverse: self.reverse || other.reverse,
            fg256: other.fg256.or(self.fg256),
            bg256: other.bg256.or(self.bg256),
            link: other.link.clone().or_else(|| self.link.clone()),
        }
    }

    /// The SGR parameters at `colour`: attributes in the order 1, 2, 3, 4, then the colour.
    fn sgr(&self, colour: Colour) -> String {
        let mut codes: Vec<String> = Vec::new();
        for (on, code) in [
            (self.bold, "1"),
            (self.dim, "2"),
            (self.italic, "3"),
            (self.underline, "4"),
        ] {
            if on {
                codes.push(code.to_owned());
            }
        }
        if self.reverse {
            codes.push("7".to_owned());
        }
        if colour == Colour::Full {
            if let Some(fg) = self.fg {
                codes.push(fg.to_string());
            }
            if let Some(fg) = self.fg256 {
                codes.push(format!("38;5;{fg}"));
            }
            if let Some(bg) = self.bg256 {
                codes.push(format!("48;5;{bg}"));
            }
        }
        codes.join(";")
    }
}

/// The SGR foreground code of a colour name.
fn colour_code(name: &str) -> Option<u8> {
    const BASE: [&str; 8] = [
        "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
    ];
    if let Some(index) = BASE.iter().position(|base| *base == name) {
        return u8::try_from(index).ok().map(|index| 30 + index);
    }
    let bright = name.strip_prefix("bright_")?;
    let index = BASE.iter().position(|base| *base == bright)?;
    u8::try_from(index).ok().map(|index| 90 + index)
}

/// A styled span: characters `start..end` of a [`Text`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Span {
    start: usize,
    end: usize,
    style: Style,
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
                style: style.clone(),
            });
        }
        self
    }

    /// Adds unstyled `text` at the end.
    pub fn push_str(&mut self, text: &str) -> &mut Text {
        self.append(text, &Style::default())
    }

    /// Adds `other`, its spans with it, at the end.
    pub fn append_text(&mut self, other: &Text) -> &mut Text {
        let offset = self.chars.len();
        self.chars.extend_from_slice(&other.chars);
        self.spans.extend(other.spans.iter().map(|span| Span {
            start: span.start + offset,
            end: span.end + offset,
            style: span.style.clone(),
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
            style: style.clone(),
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
                    style: span.style.clone(),
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

    /// The text as written to a stream at `colour`: a run between two span
    /// boundaries in one SGR sequence, a linked run inside an OSC 8 hyperlink
    /// (`links`), the rest bare. `link_id` names each hyperlink.
    pub fn render(&self, colour: Colour, links: bool) -> String {
        if colour == Colour::None && !links || self.spans.is_empty() {
            return self.as_plain();
        }
        let mut bounds: Vec<usize> = vec![0, self.chars.len()];
        for span in &self.spans {
            bounds.push(span.start);
            bounds.push(span.end);
        }
        bounds.sort_unstable();
        bounds.dedup();
        let mut out = String::new();
        for window in bounds.windows(2) {
            let (start, end) = (window[0], window[1]);
            let run: String = self.chars[start..end].iter().collect();
            let style = self
                .spans
                .iter()
                .filter(|span| span.start <= start && span.end >= end)
                .fold(Style::default(), |style, span| style.combine(&span.style));
            let codes = if colour == Colour::None {
                String::new()
            } else {
                style.sgr(colour)
            };
            let mut piece = if codes.is_empty() {
                run
            } else {
                format!("\u{1b}[{codes}m{run}\u{1b}[0m")
            };
            if links && let Some(url) = &style.link {
                piece = format!(
                    "\u{1b}]8;id={};{url}\u{1b}\\{piece}\u{1b}]8;;\u{1b}\\",
                    link_id(url)
                );
            }
            out.push_str(&piece);
        }
        out
    }
}

/// A hyperlink's id: a terminal groups the cells of one link by it. Derived
/// from the URL, so a run is reproducible (the oracle's are random).
fn link_id(url: &str) -> String {
    // FNV-1a: a stable, dependency-free hash; the id only has to be the same
    // for the same link within one run.
    let mut hash: u32 = 0x811c_9dc5;
    for byte in url.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_one_sgr_run_per_span_boundary() {
        let mut text = Text::default();
        text.append("ab", &Style::new("blue"));
        text.append("c", &Style::new("blue"));
        text.push_str(" d");
        assert_eq!(
            text.render(Colour::Full, false),
            "\u{1b}[34mab\u{1b}[0m\u{1b}[34mc\u{1b}[0m d"
        );
        assert_eq!(text.render(Colour::Mono, false), "abc d");
        assert_eq!(text.render(Colour::None, false), "abc d");
        let bold = Text::styled("x", &Style::new("bold red"));
        assert_eq!(bold.render(Colour::Mono, false), "\u{1b}[1mx\u{1b}[0m");
        assert_eq!(
            Text::styled("y", &Style::new("bright_cyan")).render(Colour::Full, false),
            "\u{1b}[96my\u{1b}[0m"
        );
    }

    #[test]
    fn render_links_and_overlapping_styles() {
        let mut text = Text::styled("abc", &Style::link("file:///a"));
        text.stylize(&Style::new("bold"), 1, 2);
        let rendered = text.render(Colour::Full, true);
        let id = link_id("file:///a");
        assert_eq!(
            rendered,
            format!(
                "\u{1b}]8;id={id};file:///a\u{1b}\\a\u{1b}]8;;\u{1b}\\\u{1b}]8;id={id};file:///a\u{1b}\\\u{1b}[1mb\u{1b}[0m\u{1b}]8;;\u{1b}\\\u{1b}]8;id={id};file:///a\u{1b}\\c\u{1b}]8;;\u{1b}\\"
            )
        );
        assert_eq!(text.render(Colour::Full, false), "a\u{1b}[1mb\u{1b}[0mc");
    }

    #[test]
    fn control_characters_are_dropped_and_tabs_expand() {
        assert_eq!(Text::plain("a\r\nb\u{7}").as_plain(), "a\nb");
        // Escape sequences and other controls are shown, never written raw.
        let hostile = Text::styled(
            "\u{1b}[2J\u{1b}]8;;x\u{7}\0\u{7f}\u{9b}",
            &Style::new("red"),
        );
        assert_eq!(hostile.as_plain(), "␛[2J␛]8;;x␀␡\u{fffd}");
        assert!(!hostile.render(Colour::None, false).contains('\u{1b}'));
        assert_eq!(
            hostile.render(Colour::Full, false),
            "\u{1b}[31m␛[2J␛]8;;x␀␡\u{fffd}\u{1b}[0m"
        );
        assert_eq!(char_width('\u{1b}'), 1);
        assert_eq!(char_width('\u{7}'), 0);
        assert_eq!(cell_len("\u{1b}[1m"), 4);
        let parts = Text::styled("a\nb", &Style::new("red")).split_lines();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].render(Colour::Full, false), "\u{1b}[31mb\u{1b}[0m");
        let mut text = Text::styled("ab", &Style::new("blue"));
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
        let mut text = Text::styled("abc", &Style::new("bold red"));
        text.stylize(&Style::new("blue"), 1, 2);
        text.stylize(&Style::new("underline"), 2, 3);
        assert_eq!(
            text.render(Colour::Full, false),
            "\u{1b}[1;31ma\u{1b}[0m\u{1b}[1;34mb\u{1b}[0m\u{1b}[1;4;31mc\u{1b}[0m"
        );
        assert_eq!(
            text.render(Colour::Mono, false),
            "\u{1b}[1ma\u{1b}[0m\u{1b}[1mb\u{1b}[0m\u{1b}[1;4mc\u{1b}[0m"
        );
    }

    #[test]
    fn truncate_pads_where_a_wide_character_no_longer_fits() {
        let mut wide = Text::styled("名前名", &Style::new("red"));
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
        let mut text = Text::styled("ab  ", &Style::new("red"));
        text.rstrip();
        assert_eq!(text.render(Colour::Full, false), "\u{1b}[31mab\u{1b}[0m");
        assert_eq!(cell_len("名前x"), 5);
        assert_eq!(Text::plain("abc").slice(1, 9).as_plain(), "bc");
        assert!(Text::default().is_empty());
        assert_eq!(Text::plain("ab").len(), 2);
    }
}
