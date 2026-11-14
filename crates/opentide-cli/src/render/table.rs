//! Tables and aligned columns, as `info` prints them.
//!
//! A [`Table`] is a [`comfy_table::Table`] laid out by [`grid`] (no borders,
//! the columns two spaces apart, a `-` rule under the header, a cell longer
//! than [`CELL_WIDTH`] cut with `…` unless its column is kept [`whole`]) with
//! an optional bold title and dim caption; the header is bold. On a terminal
//! comfy-table fits the columns to its width; in a pipe the lines are whole.
//! [`columns`] lays styled rows out as label and value columns without a
//! header.

use crate::render::text::{Text, char_width};
use anstyle::Style;
use comfy_table::{CellAlignment, ColumnConstraint, ContentArrangement, TableComponent, Width};

/// The cells a table cell shows before it is cut with `…`.
pub const CELL_WIDTH: u16 = 60;

/// A grid with a title above and a caption below.
#[derive(Clone, Debug, Default)]
pub struct Table {
    /// The title, above.
    pub title: Option<String>,
    /// The caption, below.
    pub caption: Option<String>,
    /// The header and rows.
    pub grid: comfy_table::Table,
}

/// A grid with `headers`, as every table here is drawn: no borders, a `-`
/// rule under the header, two spaces between columns, cells cut at [`CELL_WIDTH`].
pub fn grid(headers: &[&str]) -> comfy_table::Table {
    let mut header = comfy_table::Row::from(headers.to_vec());
    header.max_height(1);
    let mut grid = comfy_table::Table::new();
    grid.load_preset(comfy_table::presets::NOTHING)
        .set_style(TableComponent::HeaderLines, '-')
        .set_style(TableComponent::MiddleHeaderIntersections, ' ')
        .set_style(TableComponent::VerticalLines, ' ')
        .set_truncation_indicator("…")
        .set_header(header);
    for column in grid.column_iter_mut() {
        column
            .set_padding((0, 1))
            .set_constraint(ColumnConstraint::UpperBoundary(Width::Fixed(CELL_WIDTH)));
    }
    grid
}

/// Keeps the cells of the columns at `indexes` whole, past [`CELL_WIDTH`].
pub fn whole(grid: &mut comfy_table::Table, indexes: &[usize]) {
    for column in grid
        .column_iter_mut()
        .filter(|c| indexes.contains(&c.index))
    {
        column.set_constraint(ColumnConstraint::ContentWidth);
    }
}

/// Aligns the columns at `indexes` against their right edge.
pub fn right(grid: &mut comfy_table::Table, indexes: &[usize]) {
    for column in grid
        .column_iter_mut()
        .filter(|c| indexes.contains(&c.index))
    {
        column.set_cell_alignment(CellAlignment::Right);
    }
}

impl Table {
    /// The table's lines; on a terminal `width` cells wide (`Some`), the
    /// columns fitted to it, each row on one line.
    pub fn render(&self, width: Option<usize>) -> Vec<Text> {
        let mut grid = self.grid.clone();
        for row in grid.row_iter_mut() {
            row.max_height(1);
        }
        if let Some(width) = width {
            grid.set_content_arrangement(ContentArrangement::Dynamic)
                .set_width(u16::try_from(width).unwrap_or(u16::MAX));
        }
        let bold = Style::new().bold();
        let mut out: Vec<Text> = self.title.iter().map(|t| Text::styled(t, &bold)).collect();
        let header = grid.header().is_some();
        for (index, line) in grid.lines().enumerate().filter(|_| header) {
            let style = if index == 0 { bold } else { Style::new() };
            let mut line = Text::styled(&line, &style);
            line.rstrip();
            out.push(line);
        }
        let dim = Style::new().dimmed();
        out.extend(
            self.caption
                .iter()
                .map(|caption| Text::styled(caption, &dim)),
        );
        if let Some(width) = width {
            for line in &mut out {
                line.truncate_ellipsis(width);
            }
        }
        out
    }
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

    fn rules() -> Table {
        let mut grid = grid(&["UUID", "Name", "Platforms"]);
        whole(&mut grid, &[0]);
        grid.add_rows([
            [
                "00000000-0000-4000-8003-000000000002",
                "Defender KQL Rule",
                "defender_for_endpoint",
            ],
            [
                "3619eda3-a6ca-43c3-b079-972f387190c8",
                "Covert Beacon Rule 0185",
                "carbon_black_cloud, defender_for_endpoint, elastic",
            ],
        ]);
        Table {
            title: Some("Rules (2)".into()),
            caption: None,
            grid,
        }
    }

    #[test]
    fn columns_sit_two_spaces_apart_under_a_rule() {
        assert_eq!(
            plain(&rules().render(None)),
            [
                "Rules (2)",
                "UUID                                  Name                     Platforms",
                "------------------------------------- ------------------------ ---------------------------------------------------",
                "00000000-0000-4000-8003-000000000002  Defender KQL Rule        defender_for_endpoint",
                "3619eda3-a6ca-43c3-b079-972f387190c8  Covert Beacon Rule 0185  carbon_black_cloud, defender_for_endpoint, elastic",
            ]
        );
    }

    #[test]
    fn a_terminal_fits_the_columns_and_a_pipe_keeps_them_whole() {
        let narrow = plain(&rules().render(Some(60)));
        assert_eq!(narrow[0], "Rules (2)");
        assert!(narrow[3].starts_with("00000000-0000-4000-8003-000000000002  "));
        assert_eq!(narrow.len(), 5, "one line a row: {narrow:?}");
        assert!(narrow.iter().all(|line| Text::plain(line).cell_len() <= 60));
        // Every cell is still there in a pipe, however long the line.
        let whole = plain(&rules().render(None));
        assert!(whole[4].ends_with("defender_for_endpoint, elastic"));
    }

    #[test]
    fn a_cell_wider_than_the_cap_is_cut_unless_its_column_is_whole() {
        let long = "x".repeat(usize::from(CELL_WIDTH) + 10);
        let mut table = Table {
            grid: grid(&["Kept", "Cut"]),
            ..Table::default()
        };
        whole(&mut table.grid, &[0]);
        table.grid.add_row([long.clone(), long.clone()]);
        let lines = plain(&table.render(None));
        let (kept, cut) = lines[2].split_once("  ").expect("two columns");
        assert_eq!(kept, long);
        assert!(cut.ends_with('…') && cut.chars().count() <= usize::from(CELL_WIDTH));
    }

    #[test]
    fn header_title_and_caption_are_styled_and_numbers_align_right() {
        let mut grid = grid(&["A", "Count"]);
        right(&mut grid, &[1]);
        grid.add_row(["x", "3"]);
        let table = Table {
            title: Some("T".into()),
            caption: Some("none".into()),
            grid,
        };
        let lines: Vec<String> = table
            .render(Some(80))
            .iter()
            .map(|line| line.render(Colour::Full, false))
            .collect();
        assert_eq!(
            lines,
            [
                "\u{1b}[1mT\u{1b}[0m",
                "\u{1b}[1mA  Count\u{1b}[0m",
                "-- ------",
                "x      3",
                "\u{1b}[2mnone\u{1b}[0m",
            ]
        );
        assert!(Table::default().render(None).is_empty());
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
