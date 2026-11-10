//! Tables and aligned columns, as `info` prints them.
//!
//! A [`Table`] is drawn by comfy-table: a box of UTF-8 lines (heavy above
//! the header row, which is bold, light around the rows, the look `info` has
//! always had), each column as wide as its widest cell, and the table no
//! wider than the stream: comfy-table wraps the cells of the columns that
//! may wrap to fit. A centred title goes above it and an
//! optional centred caption below. [`columns`] lays rows out as label and
//! value columns without a box.

use comfy_table::{CellAlignment, ColumnConstraint, ContentArrangement, Width};

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
    pub min_width: Option<u16>,
}

impl Column {
    /// A column that wraps, left-aligned.
    pub fn new(header: &str) -> Column {
        Column {
            header: header.to_owned(),
            justify: Justify::Left,
            no_wrap: false,
            min_width: None,
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
    pub fn min_width(mut self, width: u16) -> Column {
        self.min_width = Some(width);
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

/// comfy-table's preset: the characters of each part of the box, in its
/// order (borders, the header's rule, cell lines, the rules between rows,
/// which are blank, then the intersections and corners).
const PRESET: &str = "││━─┡━╇┩│    ┳┴┏┓└┘";
/// The rule under the header row.
const HEADER_RULE: char = '┡';
/// The vertical line around and between cells.
const VERTICAL: char = '│';

/// The top border's corners and the mark where two columns meet.
const TOP: [char; 3] = ['┏', '┳', '┓'];

/// A cell's text wrapped to `width` cells by textwrap: at spaces, first
/// fit, a word wider than the column on a line of its own and cut there.
fn wrapped(text: &str, width: usize) -> String {
    let options = textwrap::Options::new(width.max(1))
        .break_words(true)
        .word_splitter(textwrap::WordSplitter::NoHyphenation)
        .wrap_algorithm(textwrap::WrapAlgorithm::FirstFit);
    textwrap::wrap(text, options).join("\n")
}

/// The width of each column of a drawn table, padding included, read from
/// its top border.
fn column_widths(top: &str) -> Vec<usize> {
    top.trim_start_matches(TOP[0])
        .trim_end_matches(TOP[2])
        .split(TOP[1])
        .map(|part| part.chars().count())
        .collect()
}

impl Table {
    /// The comfy-table that draws this table at most `width` cells wide;
    /// with `fixed`, each column exactly that wide and the cells of the
    /// columns that wrap wrapped to it first.
    fn drawn(&self, width: usize, fixed: Option<&[usize]>) -> comfy_table::Table {
        let cell = |at: usize, text: &str| -> String {
            match fixed.and_then(|widths| widths.get(at)) {
                Some(width) if !self.columns[at].no_wrap => wrapped(text, width.saturating_sub(2)),
                _ => text.to_owned(),
            }
        };
        let mut table = comfy_table::Table::new();
        table
            .load_preset(PRESET)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_width(u16::try_from(width).unwrap_or(u16::MAX))
            .set_header(
                self.columns
                    .iter()
                    .enumerate()
                    .map(|(at, column)| cell(at, &column.header)),
            );
        for row in &self.rows {
            table.add_row(
                (0..self.columns.len()).map(|at| cell(at, row.get(at).map_or("", String::as_str))),
            );
        }
        for (at, column) in self.columns.iter().enumerate() {
            let Some(drawn) = table.column_mut(at) else {
                continue;
            };
            if column.justify == Justify::Right {
                drawn.set_cell_alignment(CellAlignment::Right);
            }
            if let Some(width) = fixed.and_then(|widths| widths.get(at)) {
                let width = u16::try_from(*width).unwrap_or(u16::MAX);
                drawn.set_constraint(ColumnConstraint::Absolute(Width::Fixed(width)));
            } else if column.no_wrap {
                drawn.set_constraint(ColumnConstraint::ContentWidth);
            } else if let Some(min) = column.min_width {
                // The bound counts the cell's padding, one space each side.
                drawn.set_constraint(ColumnConstraint::LowerBoundary(Width::Fixed(
                    min.saturating_add(2),
                )));
            }
        }
        table
    }

    /// The table's lines at `width` cells.
    ///
    /// comfy-table chooses the column widths. Where a column is narrower
    /// than its text, the table is drawn again with each cell wrapped at
    /// words by textwrap to that width, so a long word is cut only when it
    /// is wider than the column, never because the line is full.
    pub fn render(&self, width: usize) -> Vec<Text> {
        if self.columns.is_empty() {
            return vec![Text::default()];
        }
        let first = self.drawn(width, None);
        let widths = first
            .lines()
            .next()
            .map(|top| column_widths(&top))
            .unwrap_or_default();
        let narrow = self
            .columns
            .iter()
            .zip(&widths)
            .enumerate()
            .any(|(at, (column, width))| {
                !column.no_wrap
                    && std::iter::once(column.header.as_str())
                        .chain(
                            self.rows
                                .iter()
                                .map(|row| row.get(at).map_or("", String::as_str)),
                        )
                        .flat_map(str::lines)
                        .any(|line| cell_len(line) > width.saturating_sub(2))
            });
        let lines: Vec<String> = if narrow && widths.len() == self.columns.len() {
            self.drawn(width, Some(&widths)).lines().collect()
        } else {
            first.lines().collect()
        };
        let table_width = lines.iter().map(|line| cell_len(line)).max().unwrap_or(0);
        let header_end = lines
            .iter()
            .position(|line| line.starts_with(HEADER_RULE))
            .unwrap_or(0);
        let mut out = Vec::new();
        if let Some(title) = &self.title {
            out.push(centred(title, table_width, &Style::new("italic")));
        }
        let bold = Style::new("bold");
        for (at, line) in lines.iter().enumerate() {
            if at > 0 && at < header_end {
                out.push(header_line(line, &bold));
            } else {
                out.push(Text::plain(line));
            }
        }
        if let Some(caption) = &self.caption {
            out.push(centred(caption, table_width, &Style::new("italic dim")));
        }
        out
    }
}

/// A header line: its cells in `style`, its lines plain.
fn header_line(line: &str, style: &Style) -> Text {
    let mut text = Text::default();
    let mut cell = String::new();
    for ch in line.chars() {
        if ch == VERTICAL {
            if !cell.is_empty() {
                text.append(&cell, style);
                cell.clear();
            }
            text.push_str(ch.encode_utf8(&mut [0; 4]));
        } else {
            cell.push(ch);
        }
    }
    if !cell.is_empty() {
        text.append(&cell, style);
    }
    text
}

/// `text` centred in `width` cells (whole when it is wider), in `style`.
fn centred(text: &str, width: usize, style: &Style) -> Text {
    let excess = width.saturating_sub(cell_len(text));
    let left = excess / 2;
    let padded = format!("{}{text}{}", " ".repeat(left), " ".repeat(excess - left));
    Text::styled(&padded, style)
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

    #[test]
    fn a_narrow_table_wraps_to_the_stream() {
        let table = Table {
            title: Some("Rules (2)".into()),
            caption: None,
            columns: vec![
                Column::new("UUID").no_wrap(),
                Column::new("Name"),
                Column::new("Platforms"),
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
        // At 80 cells the UUID keeps its width; the others wrap at words, a
        // word wider than its column on a line of its own and cut there.
        assert_eq!(
            plain(&table.render(80)).join("\n"),
            format!("{}Rules (2){}\n", " ".repeat(35), " ".repeat(36))
                + "\
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
│ UUID                                 │ Name              │ Platforms         │
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ 00000000-0000-4000-8003-000000000002 │ Defender KQL Rule │ defender_for_endp │
│                                      │                   │ oint              │
│ 3619eda3-a6ca-43c3-b079-972f387190c8 │ Covert Beacon     │ carbon_black_clou │
│                                      │ Rule 0185         │ d,                │
│                                      │                   │ defender_for_endp │
│                                      │                   │ oint, elastic     │
└──────────────────────────────────────┴───────────────────┴───────────────────┘"
        );
        // Wide enough, every column takes its widest cell and nothing wraps.
        let wide = plain(&table.render(200));
        assert_eq!(wide.len(), 7);
        assert_eq!(cell_len(&wide[1]), 38 + 25 + 52 + 4);
        // No stream width at all: the UUID still keeps its width.
        assert!(
            plain(&table.render(10))
                .iter()
                .any(|line| line.contains("00000000-0000-4000-8003-000000000002"))
        );
    }

    #[test]
    fn cells_wrap_at_words_and_widths_come_from_the_border() {
        assert_eq!(wrapped("a b-c defghijk", 4), "a\nb-c\ndefg\nhijk");
        assert_eq!(
            wrapped("SentinelOne S1QL Rule", 17),
            "SentinelOne S1QL\nRule"
        );
        assert_eq!(wrapped("", 4), "");
        assert_eq!(column_widths("┏━━━┳━┳━━━━━┓"), [3, 1, 5]);
    }

    #[test]
    fn header_and_title_are_styled() {
        let table = Table {
            title: Some("T".into()),
            caption: Some("none".into()),
            columns: vec![Column::new("A"), Column::new("Count").right().min_width(8)],
            rows: vec![vec!["x".into(), "3".into()]],
        };
        let lines: Vec<String> = table
            .render(80)
            .iter()
            .map(|line| line.render(Colour::Full, false))
            .collect();
        // The title and caption centred over the table, the header's cells
        // bold and its lines plain, a right-aligned column at its least width.
        assert_eq!(
            lines,
            [
                "\u{1b}[3m       T        \u{1b}[0m",
                "┏━━━┳━━━━━━━━━━┓",
                "│\u{1b}[1m A \u{1b}[0m│\u{1b}[1m    Count \u{1b}[0m│",
                "┡━━━╇━━━━━━━━━━┩",
                "│ x │        3 │",
                "└───┴──────────┘",
                "\u{1b}[2;3m      none      \u{1b}[0m",
            ]
        );
        assert_eq!(Table::default().render(80).len(), 1);
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
