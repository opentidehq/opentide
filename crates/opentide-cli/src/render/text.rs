//! Styled text: a string and the styled spans over it, written as the terminal reads it.
//!
//! The renderers build each line as a [`Text`] and write it with
//! [`Text::render`]: each run of text written the same in its [`anstyle`]
//! style, an OSC 8 hyperlink around a linked run, and the bare text where no
//! style applies. Widths are terminal cells ([`cell_len`], the
//! `unicode-width` crate); offsets are characters, as in the code frames'
//! columns.

use anstyle::Style;
use textwrap::core::Fragment;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// The cells `text` takes in a terminal, as unicode-width measures a string
/// (an emoji sequence joined by ZWJ, or with VS16, as one glyph), each
/// character [`shown`] as a [`Text`] holds it; tabs and line breaks take none.
pub fn cell_len(text: &str) -> usize {
    let shown: String = text
        .chars()
        .filter_map(shown)
        .filter(|ch| !matches!(ch, '\t' | '\n'))
        .collect();
    shown.width()
}

/// How a [`Text`] holds `ch`: `None` for the controls a terminal would act on
/// mid-line, which are dropped (bell, backspace, vertical tab, form feed,
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

/// A piece of a line for [`Text::wrap`]: characters `start..end`, the spaces
/// after them up to the next piece, measured in terminal cells. A width is
/// that of the whole string ([`cell_len`]), never a sum over characters, so an
/// emoji sequence is as wide as the terminal draws it.
#[derive(Debug)]
struct Piece {
    start: usize,
    end: usize,
    cells: usize,
    space: usize,
}

impl Fragment for Piece {
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

/// The cells the characters `chars` take, as [`cell_len`] measures their string.
fn cells_of(chars: &[char]) -> usize {
    cell_len(&chars.iter().collect::<String>())
}

/// The pieces of `chars` for [`Text::wrap`]: each run up to a space (the spaces
/// its whitespace), cut again after a `/`, so a long path breaks between
/// folders. A run wider than a row is cut at grapheme boundaries, never inside
/// one: the text's first run into `width` cells for its first piece, every
/// other piece into `rest` cells (a grapheme wider than that takes a piece of
/// its own).
fn pieces(chars: &[char], width: usize, rest: usize) -> Vec<Piece> {
    let mut cuts = vec![0];
    for (at, ch) in chars.iter().enumerate() {
        if matches!(ch, ' ' | '/') && chars.get(at + 1).is_some_and(|after| *after != ' ') {
            cuts.push(at + 1);
        }
    }
    cuts.push(chars.len());
    let mut found: Vec<Piece> = Vec::new();
    for bounds in cuts.windows(2) {
        let (start, next) = (bounds[0], bounds[1]);
        let end = chars[start..next]
            .iter()
            .rposition(|ch| *ch != ' ')
            .map_or(start, |last| start + last + 1);
        let space = cells_of(&chars[end..next]);
        let mut limit = if found.is_empty() { width } else { rest };
        let cells = cells_of(&chars[start..end]);
        if cells <= limit {
            found.push(Piece {
                start,
                end,
                cells,
                space,
            });
            continue;
        }
        let text: String = chars[start..end].iter().collect();
        let (mut from, mut taken, mut count) = (start, 0, 0);
        for grapheme in text.graphemes(true) {
            let size = cell_len(grapheme);
            if count > 0 && taken + size > limit {
                found.push(Piece {
                    start: from,
                    end: from + count,
                    cells: taken,
                    space: 0,
                });
                (from, taken, count, limit) = (from + count, 0, 0, rest);
            }
            taken += size;
            count += grapheme.chars().count();
        }
        found.push(Piece {
            start: from,
            end,
            cells: taken,
            space,
        });
    }
    found
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
        cell_len(&self.as_plain())
    }

    /// The text in rows of at most `width` cells (textwrap's first fit), each
    /// row after the first led by `indent`: broken at a space, or after a `/`
    /// (a path), and a word wider than a row cut into pieces at grapheme
    /// boundaries; styles carry over. A row is never wider than `width` unless
    /// one grapheme is.
    pub fn wrap(&self, width: usize, indent: &Text) -> Vec<Text> {
        if width == 0 || self.cell_len() <= width {
            return vec![self.clone()];
        }
        let rest = width.saturating_sub(indent.cell_len()).max(1);
        let pieces = pieces(&self.chars, width, rest);
        #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
        let widths = [width as f64, rest as f64];
        textwrap::wrap_algorithms::wrap_first_fit(&pieces, &widths)
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                let (first, last) = (row.first()?, row.last()?);
                let mut line = if index == 0 {
                    Text::default()
                } else {
                    indent.clone()
                };
                line.append_text(&self.slice(first.start, last.end));
                Some(line)
            })
            .collect()
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
        let mut kept = 0;
        for grapheme in self.as_plain().graphemes(true) {
            let next = cells + cell_len(grapheme);
            if next > room {
                break;
            }
            cells = next;
            kept += grapheme.chars().count();
        }
        let mut kept: Vec<char> = self.chars[..kept].to_vec();
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
                Colour::Mono => style.fg_color(None).bg_color(None).underline_color(None),
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
        // OSC 8 without an `id=`: no run here splits a link, so a terminal's
        // grouping by URI is enough.
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
        assert_eq!(cell_len("\u{1b}"), 1);
        assert_eq!(cell_len("\u{7}"), 0);
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
        // A ZWJ sequence and a VS16 emoji are one glyph each, two cells wide.
        assert_eq!(cell_len("\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}"), 2);
        assert_eq!(cell_len("\u{2764}\u{fe0f}"), 2);
        assert_eq!(Text::plain("a\u{1f468}\u{200d}\u{1f469}").cell_len(), 3);
        assert_eq!(Text::plain("abc").slice(1, 9).as_plain(), "bc");
        assert!(Text::default().is_empty());
        assert_eq!(Text::plain("ab").len(), 2);
    }

    /// Every row of `text` wrapped at `width`, as plain strings.
    fn wrapped(text: &str, width: usize, indent: &str) -> Vec<String> {
        Text::plain(text)
            .wrap(width, &Text::plain(indent))
            .iter()
            .map(Text::as_plain)
            .collect()
    }

    #[test]
    fn wrap_measures_and_cuts_by_grapheme() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        let heart = "\u{2764}\u{fe0f}";
        let samples = [
            format!("{family}{family}{family}{family}"),
            format!("ab {family}{family} cd {heart}{heart}{heart}{heart}"),
            heart.repeat(7),
            format!("x{}", heart.repeat(5)),
            "名前名前名前名前名前 x 名前/名前".to_owned(),
            format!("{family} {heart} 名 {family}{heart}名/{heart}"),
        ];
        for text in &samples {
            for width in 4..=11 {
                // The widest grapheme is two cells: a row holds one at least.
                for indent in ["", " ", "  "] {
                    let rows = wrapped(text, width, indent);
                    for row in &rows {
                        assert!(
                            cell_len(row) <= width,
                            "{row:?} is wider than {width} (indent {indent:?}) in {rows:?}"
                        );
                    }
                    // No grapheme is cut, and no character is lost.
                    let kept: String = rows
                        .iter()
                        .enumerate()
                        .map(|(at, row)| {
                            if at == 0 {
                                row.as_str()
                            } else {
                                &row[indent.len()..]
                            }
                        })
                        .collect();
                    assert_eq!(
                        kept.replace(' ', ""),
                        text.replace(' ', ""),
                        "{rows:?} at {width}"
                    );
                    for row in &rows {
                        assert!(!row.ends_with('\u{200d}'), "{row:?} ends inside a sequence");
                        assert!(!row.starts_with('\u{fe0f}'), "{row:?} starts at a selector");
                    }
                }
            }
        }
        // A family is one glyph two cells wide: three fit a row of six.
        assert_eq!(
            wrapped(&format!("{family}{family}{family}{family}"), 6, ""),
            [family.repeat(3), family.to_owned()]
        );
        // A VS16 emoji is two cells: three fit in six, not four.
        assert_eq!(
            wrapped(&heart.repeat(4), 6, ""),
            [heart.repeat(3), heart.to_owned()]
        );
        // A grapheme wider than the row still moves on, one to a row.
        assert_eq!(wrapped("名名", 1, ""), ["名", "名"]);
    }

    #[test]
    fn wrap_breaks_the_first_row_at_the_full_width() {
        assert_eq!(wrapped("abcdefghij", 4, " "), ["abcd", " efg", " hij"]);
        assert_eq!(
            wrapped("aaa bbb/ccc/ddd", 6, "  "),
            ["aaa", "  bbb/", "  ccc/", "  ddd"]
        );
    }

    #[test]
    fn truncate_ellipsis_keeps_graphemes_whole() {
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        let mut text = Text::plain(&format!("a{family}{family}"));
        text.truncate_ellipsis(4);
        assert_eq!(text.as_plain(), format!("a{family}…"));
        assert!(text.cell_len() <= 4);
    }
}
