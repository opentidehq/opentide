//! Positions as the `opentide` CLI writes them: lines and columns 1-based,
//! columns in Unicode code points, `end_column` exclusive. The engine reports
//! LSP positions (0-based, UTF-16 code units); a host converts each against
//! the text it points into (the Python binding, `opentide-cli`'s queries
//! check).

use crate::Range;

/// Byte offsets where each line starts. Lines end at `\n`, as the engine counts
/// them (a `\r` before it belongs to the line).
#[derive(Debug, Clone)]
pub struct LineStarts(Vec<usize>);

impl LineStarts {
    /// The line starts of `text`.
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(at, _)| at + 1));
        Self(starts)
    }

    /// An LSP range as 1-based `(line, column, end_line, end_column)` in code
    /// points. A position past the end of its line or the text is clamped;
    /// an empty or reversed range still marks one character.
    pub fn convert(&self, text: &str, range: Range) -> (usize, usize, usize, usize) {
        let (line, column) = self.position(text, range.start.line, range.start.character);
        let (end_line, mut end_column) = self.position(text, range.end.line, range.end.character);
        if (end_line, end_column) <= (line, column) {
            end_column = column + 1;
            return (line, column, line, end_column);
        }
        (line, column, end_line, end_column)
    }

    /// The byte offset of 1-based `line` and code-point `column`, clamped to
    /// the line's end and to the text.
    pub fn offset(&self, text: &str, line: usize, column: usize) -> usize {
        let index = line.saturating_sub(1).min(self.0.len() - 1);
        let start = self.0[index];
        let end = self.0.get(index + 1).map_or(text.len(), |next| next - 1);
        text[start..end]
            .char_indices()
            .nth(column.saturating_sub(1))
            .map_or(end, |(at, _)| start + at)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "a char is one or two UTF-16 units"
    )]
    fn position(&self, text: &str, line: u32, utf16: u32) -> (usize, usize) {
        let index = (line as usize).min(self.0.len() - 1);
        let start = self.0[index];
        let end = self.0.get(index + 1).map_or(text.len(), |next| next - 1);
        let content = &text[start..end];
        let mut units = 0u32;
        let mut points = 0usize;
        for ch in content.chars() {
            if units >= utf16 {
                break;
            }
            units += ch.len_utf16() as u32;
            points += 1;
        }
        (index + 1, points + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Position;

    fn range(line: u32, start: u32, end_line: u32, end: u32) -> Range {
        Range::new(Position::new(line, start), Position::new(end_line, end))
    }

    #[test]
    fn utf16_columns_become_one_based_code_points() {
        // "🔥" is two UTF-16 units and one code point; "é" is one of each.
        let text = "a: 🔥é x\nnext\n";
        let lines = LineStarts::new(text);
        // `x` starts at UTF-16 unit 7 (a, :, space, 🔥 = 2, é, space).
        assert_eq!(lines.convert(text, range(0, 7, 0, 8)), (1, 7, 1, 8));
        assert_eq!(lines.convert(text, range(1, 0, 1, 4)), (2, 1, 2, 5));
    }

    #[test]
    fn one_based_code_point_positions_become_byte_offsets() {
        let text = "a: 🔥é x\nnext\n";
        let lines = LineStarts::new(text);
        assert_eq!(&text[lines.offset(text, 1, 7)..], "x\nnext\n");
        assert_eq!(&text[lines.offset(text, 2, 2)..], "ext\n");
        // Past the line: its end; past the text: the last line.
        assert_eq!(lines.offset(text, 1, 99), text.find('\n').unwrap());
        assert_eq!(lines.offset(text, 99, 1), text.len());
        assert_eq!(lines.offset(text, 0, 0), 0);
    }

    #[test]
    fn positions_past_the_text_are_clamped_and_empty_ranges_mark_one_character() {
        let text = "only\r\n";
        let lines = LineStarts::new(text);
        assert_eq!(lines.convert(text, range(0, 2, 0, 2)), (1, 3, 1, 4));
        // The \r belongs to the line, as the engine counts it.
        assert_eq!(lines.convert(text, range(0, 0, 0, 99)), (1, 1, 1, 6));
        assert_eq!(lines.convert(text, range(9, 0, 9, 1)), (2, 1, 2, 2));
    }
}
