//! Tables and aligned columns, as `info` prints them.
//!
//! A [`Table`] is plain text: an optional bold title, then the columns two
//! spaces apart, the header in bold over a `-` rule, each column as wide as
//! its widest cell up to [`CELL_WIDTH`] (a longer cell is cut with `…`), and
//! an optional dim caption. On a terminal, a line wider than it is cut at its
//! edge with `…`; in a pipe it is whole. [`columns`] lays rows out as label
//! and value columns without a header.

use crate::render::text::Text;
use anstyle::Style;

/// The cells a table cell shows before it is cut with `…`.
pub const CELL_WIDTH: usize = 60;

/// The blanks between two columns.
const GAP: &str = "  ";

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
    /// The column's text in the header row.
    pub header: String,
    /// The alignment.
    pub justify: Justify,
    /// Whether the column keeps its widest cell whole, past [`CELL_WIDTH`].
    pub no_wrap: bool,
    /// The narrowest the column may be.
    pub min_width: Option<u16>,
}

impl Column {
    /// A left-aligned column, cut at [`CELL_WIDTH`].
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

    /// Never cut: as wide as its widest cell.
    pub fn no_wrap(mut self) -> Column {
        self.no_wrap = true;
        self
    }

    /// At least `width` cells wide.
    pub fn min_width(mut self, width: u16) -> Column {
        self.min_width = Some(width);
        self
    }
}

/// A table: an optional title above, columns with their headers, rows, and an
/// optional caption below.
#[derive(Clone, Debug, Default)]
pub struct Table {
    /// The title, above.
    pub title: Option<String>,
    /// The caption, below.
    pub caption: Option<String>,
    /// The columns, left to right.
    pub columns: Vec<Column>,
    /// The rows, one string per column.
    pub rows: Vec<Vec<String>>,
}

impl Table {
    /// The width of each column: its widest cell, header included, at least
    /// its `min_width`, at most [`CELL_WIDTH`] unless it is `no_wrap`.
    fn widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(at, column)| {
                let widest = self
                    .rows
                    .iter()
                    .map(|row| row.get(at).map_or(0, |cell| Text::plain(cell).cell_len()))
                    .fold(Text::plain(&column.header).cell_len(), usize::max);
                let capped = if column.no_wrap {
                    widest
                } else {
                    widest.min(CELL_WIDTH)
                };
                capped.max(column.min_width.map_or(0, usize::from))
            })
            .collect()
    }

    /// The table's lines; on a terminal `width` cells wide (`Some`), each
    /// line cut at its edge.
    pub fn render(&self, width: Option<usize>) -> Vec<Text> {
        let widths = self.widths();
        let line = |cells: &[&str], style: &Style| -> Text {
            let mut line = Text::default();
            for (at, (column, column_width)) in self.columns.iter().zip(&widths).enumerate() {
                if at > 0 {
                    line.push_str(GAP);
                }
                let mut cell = Text::styled(cells.get(at).copied().unwrap_or(""), style);
                cell.truncate_ellipsis(*column_width);
                let pad = " ".repeat(column_width.saturating_sub(cell.cell_len()));
                if column.justify == Justify::Right {
                    line.push_str(&pad);
                    line.append_text(&cell);
                } else {
                    line.append_text(&cell);
                    line.push_str(&pad);
                }
            }
            line.rstrip();
            line
        };
        let mut out = Vec::new();
        if let Some(title) = &self.title {
            out.push(Text::styled(title, &Style::new().bold()));
        }
        if !self.columns.is_empty() {
            let headers: Vec<&str> = self.columns.iter().map(|c| c.header.as_str()).collect();
            out.push(line(&headers, &Style::new().bold()));
            let rule: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
            let rule: Vec<&str> = rule.iter().map(String::as_str).collect();
            out.push(line(&rule, &Style::default()));
            for row in &self.rows {
                let cells: Vec<&str> = row.iter().map(String::as_str).collect();
                out.push(line(&cells, &Style::default()));
            }
        }
        if let Some(caption) = &self.caption {
            out.push(Text::styled(caption, &Style::new().dimmed()));
        }
        if let Some(width) = width {
            for line in &mut out {
                line.truncate_ellipsis(width);
            }
        }
        out
    }
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
        Table {
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
                    "microsoft_defender".into(),
                ],
                vec![
                    "3619eda3-a6ca-43c3-b079-972f387190c8".into(),
                    "Covert Beacon Rule 0185".into(),
                    "carbon_black_cloud, microsoft_defender, elastic".into(),
                ],
            ],
        }
    }

    #[test]
    fn columns_sit_two_spaces_apart_under_a_rule() {
        assert_eq!(
            plain(&rules().render(None)),
            [
                "Rules (2)",
                "UUID                                  Name                     Platforms",
                "------------------------------------  -----------------------  -----------------------------------------------",
                "00000000-0000-4000-8003-000000000002  Defender KQL Rule        microsoft_defender",
                "3619eda3-a6ca-43c3-b079-972f387190c8  Covert Beacon Rule 0185  carbon_black_cloud, microsoft_defender, elastic",
            ]
        );
    }

    #[test]
    fn a_terminal_cuts_lines_at_its_edge_and_a_pipe_keeps_them() {
        let narrow = plain(&rules().render(Some(50)));
        assert_eq!(narrow[0], "Rules (2)");
        assert_eq!(
            narrow[3],
            "00000000-0000-4000-8003-000000000002  Defender KQ…"
        );
        assert!(narrow.iter().all(|line| Text::plain(line).cell_len() <= 50));
        // Every cell is still there in a pipe, however long the line.
        let whole = plain(&rules().render(None));
        assert!(whole[4].ends_with("microsoft_defender, elastic"));
    }

    #[test]
    fn a_cell_wider_than_the_cap_is_cut_unless_its_column_never_is() {
        let long = "x".repeat(CELL_WIDTH + 10);
        let table = Table {
            columns: vec![Column::new("Kept").no_wrap(), Column::new("Cut")],
            rows: vec![vec![long.clone(), long.clone()]],
            ..Table::default()
        };
        let lines = plain(&table.render(None));
        let cut = format!("{}…", "x".repeat(CELL_WIDTH - 1));
        assert_eq!(lines[2], format!("{long}  {cut}"));
    }

    #[test]
    fn header_title_and_caption_are_styled_and_numbers_align_right() {
        let table = Table {
            title: Some("T".into()),
            caption: Some("none".into()),
            columns: vec![Column::new("A"), Column::new("Count").right().min_width(8)],
            rows: vec![vec!["x".into(), "3".into()]],
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
                "\u{1b}[1mA\u{1b}[0m     \u{1b}[1mCount\u{1b}[0m",
                "-  --------",
                "x         3",
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
