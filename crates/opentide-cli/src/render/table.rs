//! Tables and aligned columns, as `info` prints them.
//!
//! A [`Table`] is the oracle's: a centred title, a heavy-headed box
//! (`┏━┳┓`, `┃`, `┡━╇┩`, then `│` and `└─┴┘`), a bold header row, cells
//! padded one space each side, an optional centred caption. Each column is as
//! wide as its widest cell; when the table is wider than the stream, the
//! widest columns that may wrap give up width first, then every column
//! evenly. A cell wraps at words by textwrap's first-fit algorithm, and a word
//! wider than its column is cut into column-wide pieces (`fold`) or ends in
//! `…`. [`columns`] lays rows out as label and value columns without a box.

use crate::render::text::{Style, Text, cell_len, char_width};

/// How a column aligns its cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Justify {
    /// Against the left edge.
    Left,
    /// Against the right edge.
    Right,
}

/// One column.
#[derive(Clone, Debug)]
pub struct Column {
    /// The header.
    pub header: String,
    /// The alignment.
    pub justify: Justify,
    /// Whether the column keeps its width: it never wraps.
    pub no_wrap: bool,
    /// The narrowest the column's text may be.
    pub min_width: Option<usize>,
    /// Whether a word wider than the column is cut into pieces (else it
    /// ends in `…`).
    pub fold: bool,
}

impl Column {
    /// A column that wraps, left-aligned, a long word ending in `…`.
    pub fn new(header: &str) -> Column {
        Column {
            header: header.to_owned(),
            justify: Justify::Left,
            no_wrap: false,
            min_width: None,
            fold: false,
        }
    }

    /// Right-aligned.
    pub fn right(mut self) -> Column {
        self.justify = Justify::Right;
        self
    }

    /// Never wrapped.
    pub fn no_wrap(mut self) -> Column {
        self.no_wrap = true;
        self
    }

    /// At least `width` cells of text.
    pub fn min_width(mut self, width: usize) -> Column {
        self.min_width = Some(width);
        self
    }

    /// A long word is cut, not shortened.
    pub fn fold(mut self) -> Column {
        self.fold = true;
        self
    }
}

/// A table.
#[derive(Clone, Debug, Default)]
pub struct Table {
    /// The title, above.
    pub title: Option<String>,
    /// The caption, below.
    pub caption: Option<String>,
    /// The columns.
    pub columns: Vec<Column>,
    /// The rows, one string per column.
    pub rows: Vec<Vec<String>>,
}

/// Cell padding: one space each side.
const PADDING: usize = 2;

/// The smallest and largest width a text takes: its longest word and its
/// longest line.
fn measure(text: &str) -> (usize, usize) {
    let widest = text.lines().map(cell_len).max().unwrap_or(0);
    let word = text
        .split_whitespace()
        .map(cell_len)
        .max()
        .unwrap_or(widest);
    (word.min(widest), widest)
}

/// `(minimum, maximum)` of a column at most `limit` wide, padding included.
fn measure_column(
    column: &Column,
    rows: &[Vec<String>],
    index: usize,
    limit: usize,
) -> (usize, usize) {
    if limit < 1 {
        return (0, 0);
    }
    let cell = |text: &str| -> (usize, usize) {
        if limit < 1 + PADDING {
            return (limit, limit);
        }
        let inner = limit - PADDING;
        let (low, high) = measure(text);
        let (low, high) = (low.min(inner), high.min(inner));
        if high < 1 {
            return (PADDING, PADDING);
        }
        ((low + PADDING).min(limit), (high + PADDING).min(limit))
    };
    let mut low = 0;
    let mut high = 0;
    for text in std::iter::once(column.header.as_str()).chain(
        rows.iter()
            .map(|row| row.get(index).map_or("", String::as_str)),
    ) {
        let (a, b) = cell(text);
        low = low.max(a);
        high = high.max(b);
    }
    let (mut low, mut high) = (low.min(limit), high.min(limit));
    if let Some(min) = column.min_width {
        let min = min + PADDING;
        low = low.max(min);
        high = high.max(min);
    }
    (low, high)
}

/// Takes `total` from `values`, in proportion to `ratios`, at most each
/// `maximums`, rounding halves to even.
fn ratio_reduce(
    total: usize,
    ratios: &[usize],
    maximums: &[usize],
    values: &[usize],
) -> Vec<usize> {
    let ratios: Vec<usize> = ratios
        .iter()
        .zip(maximums)
        .map(|(ratio, max)| if *max > 0 { *ratio } else { 0 })
        .collect();
    let mut total_ratio: usize = ratios.iter().sum();
    if total_ratio == 0 {
        return values.to_vec();
    }
    let mut remaining = total;
    let mut out = Vec::with_capacity(values.len());
    for ((ratio, maximum), value) in ratios.iter().zip(maximums).zip(values) {
        if *ratio > 0 && total_ratio > 0 {
            let distributed = (*maximum).min(round_half_even(ratio * remaining, total_ratio));
            out.push(value.saturating_sub(distributed));
            remaining = remaining.saturating_sub(distributed);
            total_ratio -= ratio;
        } else {
            out.push(*value);
        }
    }
    out
}

/// `numerator / denominator` rounded to the nearest whole number, a half to
/// the even one.
fn round_half_even(numerator: usize, denominator: usize) -> usize {
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    match (remainder * 2).cmp(&denominator) {
        std::cmp::Ordering::Less => quotient,
        std::cmp::Ordering::Greater => quotient + 1,
        std::cmp::Ordering::Equal => quotient + quotient % 2,
    }
}

/// The widths that fit `limit`: the widest wrapping columns shrink first.
fn collapse(widths: &[usize], wrapable: &[bool], limit: usize) -> Vec<usize> {
    let mut widths = widths.to_vec();
    let mut total: usize = widths.iter().sum();
    if !wrapable.iter().any(|w| *w) {
        return widths;
    }
    while total > 0 && total > limit {
        let excess = total - limit;
        let widest = widths
            .iter()
            .zip(wrapable)
            .filter(|(_, w)| **w)
            .map(|(width, _)| *width)
            .max()
            .unwrap_or(0);
        let second = widths
            .iter()
            .zip(wrapable)
            .map(|(width, w)| if *w && *width != widest { *width } else { 0 })
            .max()
            .unwrap_or(0);
        let difference = widest - second;
        let ratios: Vec<usize> = widths
            .iter()
            .zip(wrapable)
            .map(|(width, w)| usize::from(*width == widest && *w))
            .collect();
        if ratios.iter().all(|r| *r == 0) || difference == 0 {
            break;
        }
        let maximums = vec![excess.min(difference); widths.len()];
        widths = ratio_reduce(excess, &ratios, &maximums, &widths);
        total = widths.iter().sum();
    }
    widths
}

impl Table {
    fn widths(&self, limit: usize) -> Vec<usize> {
        let measured: Vec<(usize, usize)> = self
            .columns
            .iter()
            .enumerate()
            .map(|(index, column)| measure_column(column, &self.rows, index, limit))
            .collect();
        let mut widths: Vec<usize> = measured.iter().map(|(_, high)| (*high).max(1)).collect();
        let total: usize = widths.iter().sum();
        if total > limit {
            let wrapable: Vec<bool> = self.columns.iter().map(|c| !c.no_wrap).collect();
            widths = collapse(&widths, &wrapable, limit);
            let total: usize = widths.iter().sum();
            if total > limit {
                let ones = vec![1; widths.len()];
                widths = ratio_reduce(total - limit, &ones, &widths.clone(), &widths);
            }
            widths = self
                .columns
                .iter()
                .enumerate()
                .zip(&widths)
                .map(|((index, column), width)| measure_column(column, &self.rows, index, *width).1)
                .collect();
        }
        widths
    }

    /// The table's lines at `width` cells.
    pub fn render(&self, width: usize) -> Vec<Text> {
        let count = self.columns.len();
        if count == 0 {
            return vec![Text::default()];
        }
        let extra = 2 + count - 1;
        let widths = self.widths(width.saturating_sub(extra));
        let table_width: usize = widths.iter().sum::<usize>() + extra;
        let mut out = Vec::new();
        if let Some(title) = &self.title {
            out.extend(centred(title, table_width, &Style::new("italic")));
        }
        let rule = |left: &str, fill: &str, cross: &str, right: &str| -> Text {
            let parts: Vec<String> = widths.iter().map(|w| fill.repeat(*w)).collect();
            Text::plain(&format!("{left}{}{right}", parts.join(cross)))
        };
        out.push(rule("┏", "━", "┳", "┓"));
        let bold = Style::new("bold");
        let header: Vec<String> = self.columns.iter().map(|c| c.header.clone()).collect();
        out.extend(self.row(&header, &widths, &bold, "┃", true));
        out.push(rule("┡", "━", "╇", "┩"));
        for row in &self.rows {
            out.extend(self.row(row, &widths, &Style::default(), "│", false));
        }
        out.push(rule("└", "─", "┴", "┘"));
        if let Some(caption) = &self.caption {
            out.extend(centred(caption, table_width, &Style::new("italic dim")));
        }
        out
    }

    fn row(
        &self,
        cells: &[String],
        widths: &[usize],
        style: &Style,
        edge: &str,
        header: bool,
    ) -> Vec<Text> {
        let rendered: Vec<Vec<String>> = self
            .columns
            .iter()
            .zip(widths)
            .enumerate()
            .map(|(index, (column, width))| {
                let text = cells.get(index).map_or("", String::as_str);
                cell_lines(text, width.saturating_sub(PADDING), column)
            })
            .collect();
        let height = rendered.iter().map(Vec::len).max().unwrap_or(1).max(1);
        (0..height)
            .map(|line| {
                let mut text = Text::plain(edge);
                for (index, (lines, width)) in rendered.iter().zip(widths).enumerate() {
                    if index > 0 {
                        text.push_str(edge);
                    }
                    // A header aligns to the bottom, a cell to the top.
                    let offset = if header { height - lines.len() } else { 0 };
                    match line.checked_sub(offset).and_then(|at| lines.get(at)) {
                        Some(content) if *width >= PADDING => {
                            text.append(" ", style);
                            text.append(content, style);
                            text.append(" ", style);
                        }
                        Some(content) => {
                            text.append(&crop(content, *width), style);
                        }
                        None => {
                            text.append(&" ".repeat(*width), style);
                        }
                    }
                }
                text.push_str(edge);
                text
            })
            .collect()
    }
}

/// `text` centred in `width` cells, every line in `style`.
fn centred(text: &str, width: usize, style: &Style) -> Vec<Text> {
    wrap(text, width, true)
        .into_iter()
        .map(|line| {
            let excess = width.saturating_sub(cell_len(&line));
            let left = excess / 2;
            let padded = format!("{}{line}{}", " ".repeat(left), " ".repeat(excess - left));
            Text::styled(&padded, style)
        })
        .collect()
}

/// The first `width` cells of `text`.
fn crop(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut cells = 0;
    for ch in text.chars() {
        let w = char_width(ch);
        if cells + w > width {
            break;
        }
        cells += w;
        out.push(ch);
    }
    out
}

/// `text` in `width` cells, ending in `…` when it is wider.
fn ellipsis(text: &str, width: usize) -> String {
    if cell_len(text) <= width {
        return text.to_owned();
    }
    let mut out = crop(text, width.saturating_sub(1));
    out.push('…');
    out
}

/// A cell's lines, each exactly `width` cells.
fn cell_lines(text: &str, width: usize, column: &Column) -> Vec<String> {
    let lines = if column.no_wrap {
        text.lines().map(str::to_owned).collect()
    } else {
        wrap(text, width, column.fold)
    };
    let lines = if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    };
    lines
        .into_iter()
        .map(|line| {
            let line = if column.fold {
                crop(&line, width)
            } else {
                ellipsis(&line, width)
            };
            let pad = " ".repeat(width.saturating_sub(cell_len(&line)));
            match column.justify {
                Justify::Left => format!("{line}{pad}"),
                Justify::Right => format!("{pad}{line}"),
            }
        })
        .collect()
}

/// A word of a line: its text, its cells and the whitespace after it.
#[derive(Debug)]
struct Word {
    text: String,
    cells: usize,
    space: usize,
}

impl textwrap::core::Fragment for Word {
    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    fn width(&self) -> f64 {
        self.cells as f64
    }

    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    fn whitespace_width(&self) -> f64 {
        self.space as f64
    }

    fn penalty_width(&self) -> f64 {
        0.0
    }
}

/// `text` wrapped at words in `width` cells by textwrap's first-fit
/// algorithm, each line without trailing whitespace. A word wider than
/// `width` starts a line; with `fold` it is cut into `width`-cell pieces,
/// otherwise it is left whole (and later shortened with `…`).
pub fn wrap(text: &str, width: usize, fold: bool) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let mut words: Vec<Word> = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut index = 0;
        // Leading whitespace stays with the first word.
        let lead: String = chars.iter().take_while(|c| c.is_whitespace()).collect();
        index += lead.chars().count();
        let mut first = true;
        while index < chars.len() {
            let start = index;
            while index < chars.len() && !chars[index].is_whitespace() {
                index += 1;
            }
            let mut word: String = chars[start..index].iter().collect();
            let space_start = index;
            while index < chars.len() && chars[index].is_whitespace() {
                index += 1;
            }
            let space = chars[space_start..index]
                .iter()
                .copied()
                .map(char_width)
                .sum();
            if first {
                word = format!("{lead}{word}");
                first = false;
            }
            let cells = cell_len(&word);
            if fold && width > 0 && cells > width {
                let pieces = chop(&word, width);
                let last = pieces.len() - 1;
                for (at, piece) in pieces.into_iter().enumerate() {
                    let cells = cell_len(&piece);
                    words.push(Word {
                        text: piece,
                        cells,
                        space: if at == last { space } else { 0 },
                    });
                }
            } else {
                words.push(Word {
                    text: word,
                    cells,
                    space,
                });
            }
        }
        if words.is_empty() {
            out.push(lead);
            continue;
        }
        #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
        let widths = [width.max(1) as f64];
        for row in textwrap::wrap_algorithms::wrap_first_fit(&words, &widths) {
            let joined: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(at, word)| {
                    if at + 1 == row.len() {
                        word.text.clone()
                    } else {
                        format!("{}{}", word.text, " ".repeat(word.space))
                    }
                })
                .collect();
            out.push(joined.concat());
        }
    }
    out
}

/// A positioned word of a styled line: characters `start..end`, and the
/// whitespace after it.
#[derive(Debug)]
struct Span {
    start: usize,
    end: usize,
    cells: usize,
    space: usize,
}

impl textwrap::core::Fragment for Span {
    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    fn width(&self) -> f64 {
        self.cells as f64
    }

    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    fn whitespace_width(&self) -> f64 {
        self.space as f64
    }

    fn penalty_width(&self) -> f64 {
        0.0
    }
}

/// A styled line as a stream `width` cells wide shows it: whole when it
/// fits, else wrapped at words (first fit), a word wider than the stream cut
/// into pieces; styles kept.
pub fn wrap_text(line: &Text, width: usize) -> Vec<Text> {
    if width == 0 || line.cell_len() <= width {
        return vec![line.clone()];
    }
    let chars: Vec<char> = line.as_plain().chars().collect();
    let mut spans: Vec<Span> = Vec::new();
    // Leading whitespace stays with the first word.
    let mut index = chars.iter().take_while(|c| c.is_whitespace()).count();
    while index < chars.len() {
        let start = if spans.is_empty() { 0 } else { index };
        while index < chars.len() && !chars[index].is_whitespace() {
            index += 1;
        }
        let end = index;
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        let space: usize = chars[end..index].iter().copied().map(char_width).sum();
        // Cut a word wider than the stream into stream-wide pieces.
        let mut piece_start = start;
        let mut cells = 0;
        for (at, ch) in chars.iter().enumerate().take(end).skip(start) {
            let w = char_width(*ch);
            if cells + w > width && at > piece_start {
                spans.push(Span {
                    start: piece_start,
                    end: at,
                    cells,
                    space: 0,
                });
                piece_start = at;
                cells = 0;
            }
            cells += w;
        }
        spans.push(Span {
            start: piece_start,
            end,
            cells,
            space,
        });
    }
    if spans.is_empty() {
        return vec![line.clone()];
    }
    #[expect(clippy::cast_precision_loss, reason = "a terminal's columns")]
    let widths = [width as f64];
    textwrap::wrap_algorithms::wrap_first_fit(&spans, &widths)
        .into_iter()
        .filter_map(|row| Some(line.slice(row.first()?.start, row.last()?.end)))
        .collect()
}

/// `word` in pieces of at most `width` cells.
fn chop(word: &str, width: usize) -> Vec<String> {
    let mut pieces = vec![String::new()];
    let mut cells = 0;
    for ch in word.chars() {
        let w = char_width(ch);
        if cells + w > width && !pieces.last().is_some_and(String::is_empty) {
            pieces.push(String::new());
            cells = 0;
        }
        cells += w;
        if let Some(last) = pieces.last_mut() {
            last.push(ch);
        }
    }
    pieces
}

/// Rows as aligned columns, `gap` cells apart, each line without trailing
/// blanks; the columns in `right` are right-aligned. A column empty on every
/// row takes no room, nor its gap.
pub fn columns(rows: &[Vec<Text>], gap: usize, right: &[usize]) -> Vec<Text> {
    let count = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..count)
        .map(|i| {
            rows.iter()
                .filter_map(|row| row.get(i))
                .map(Text::cell_len)
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|row| {
            let mut line = Text::default();
            let mut pending = String::new();
            for (index, cell) in row.iter().enumerate() {
                let width = widths[index];
                if width == 0 {
                    continue;
                }
                line.push_str(&pending);
                let pad = " ".repeat(width - cell.cell_len());
                if right.contains(&index) {
                    line.push_str(&pad);
                    line.append_text(cell);
                    pending = " ".repeat(gap);
                } else {
                    line.append_text(cell);
                    pending = format!("{pad}{}", " ".repeat(gap));
                }
            }
            line.rstrip();
            line
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::text::Colour;

    fn plain(lines: &[Text]) -> Vec<String> {
        lines.iter().map(Text::as_plain).collect()
    }

    /// The oracle's `info rules` at 80 columns: the UUID column keeps its
    /// width, the others share what is left, and a long word is folded.
    #[test]
    fn a_narrow_table_wraps_and_folds() {
        let table = Table {
            title: Some("Rules (2)".into()),
            caption: None,
            columns: vec![
                Column::new("UUID").no_wrap().min_width(36),
                Column::new("Name").fold(),
                Column::new("Platforms").fold(),
            ],
            rows: vec![
                vec![
                    "00000000-0000-4000-8003-000000000002".into(),
                    "Defender KQL Rule".into(),
                    "defender_for_endpoint".into(),
                ],
                vec![
                    "3619eda3-a6ca-43c3-b079-972f387190c8".into(),
                    "Covert Beacon Rule 0185".into(),
                    "carbon_black_cloud, defender_for_endpoint, elastic".into(),
                ],
            ],
        };
        let lines = plain(&table.render(80));
        // The title is centred over the table: 35 cells before it, 36 after.
        assert_eq!(
            lines[0],
            format!("{}Rules (2){}", " ".repeat(35), " ".repeat(36))
        );
        assert_eq!(
            lines[1..].join("\n"),
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ UUID                                 ┃ Name              ┃ Platforms         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ 00000000-0000-4000-8003-000000000002 │ Defender KQL Rule │ defender_for_endp │
│                                      │                   │ oint              │
│ 3619eda3-a6ca-43c3-b079-972f387190c8 │ Covert Beacon     │ carbon_black_clou │
│                                      │ Rule 0185         │ d,                │
│                                      │                   │ defender_for_endp │
│                                      │                   │ oint, elastic     │
└──────────────────────────────────────┴───────────────────┴───────────────────┘"
        );
        // Wide enough, every column takes its widest cell.
        let wide = table.render(120);
        assert_eq!(wide[1].cell_len(), 38 + 25 + 52 + 4);
    }

    #[test]
    fn header_and_title_are_styled_cell_by_cell() {
        let table = Table {
            title: Some("T".into()),
            caption: Some("none".into()),
            columns: vec![Column::new("A"), Column::new("Count").right()],
            rows: Vec::new(),
        };
        let lines = table.render(80);
        assert_eq!(
            lines
                .iter()
                .map(|l| l.render(Colour::Full, false))
                .collect::<Vec<_>>(),
            [
                "\u{1b}[3m      T      \u{1b}[0m",
                "┏━━━┳━━━━━━━┓",
                "┃\u{1b}[1m \u{1b}[0m\u{1b}[1mA\u{1b}[0m\u{1b}[1m \u{1b}[0m┃\u{1b}[1m \u{1b}[0m\u{1b}[1mCount\u{1b}[0m\u{1b}[1m \u{1b}[0m┃",
                "┡━━━╇━━━━━━━┩",
                "└───┴───────┘",
                "\u{1b}[2;3m    none     \u{1b}[0m",
            ]
        );
    }

    #[test]
    fn ratio_reduce_rounds_halves_to_even() {
        assert_eq!(round_half_even(5, 2), 2);
        assert_eq!(round_half_even(7, 2), 4);
        assert_eq!(round_half_even(7, 3), 2);
        assert_eq!(ratio_reduce(3, &[1, 1], &[5, 5], &[10, 10]), [8, 9]);
        assert_eq!(
            collapse(&[38, 26, 23], &[false, true, true], 74),
            [38, 18, 18]
        );
    }

    #[test]
    fn words_wrap_first_fit() {
        assert_eq!(
            wrap("SentinelOne S1QL Rule", 17, true),
            ["SentinelOne S1QL", "Rule"]
        );
        assert_eq!(wrap("abcdefghij", 4, true), ["abcd", "efgh", "ij"]);
        assert_eq!(wrap("abcdefghij x", 4, false), ["abcdefghij", "x"]);
        assert_eq!(ellipsis("abcdefghij", 4), "abc…");
        assert_eq!(wrap("", 4, true), [""]);
    }

    #[test]
    fn columns_align_and_trim() {
        let rows = vec![
            vec![Text::plain("version"), Text::plain("1"), Text::plain("")],
            vec![
                Text::plain("platforms"),
                Text::plain("Sentinel"),
                Text::plain("on"),
            ],
        ];
        assert_eq!(
            plain(&columns(&rows, 2, &[0])),
            ["  version  1", "platforms  Sentinel  on"]
        );
    }
}
