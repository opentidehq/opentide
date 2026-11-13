//! A configuration file read into the node tree ([`crate::node`]).
//!
//! The text is parsed by the `toml_edit` crate (TOML 1.0, the version
//! Python's `tomllib` reads), whose items keep their byte spans; this module
//! only turns its tables into [`Value::Map`], its arrays into [`Value::Seq`]
//! and its scalars into the matching [`Value`] (a date or time into
//! [`Value::Datetime`]), each node at its position.

use std::sync::Arc;

use toml_edit::{ImDocument, Item, Table};

use crate::node::{Entry, MAX_DEPTH, Mark, Node, Value};

/// Why a text is not a configuration document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What is wrong, as `toml_edit` says it (one line).
    pub message: String,
    /// Where, when the parser says so: line and column from 1, columns in
    /// code points.
    pub line: Option<usize>,
    /// The column.
    pub column: Option<usize>,
    /// The tables nest deeper than [`MAX_DEPTH`] (the oracle's
    /// `RecursionError`): `config_parse`, "The document is nested too deeply."
    pub too_deep: bool,
}

/// Line starts of a text, to turn byte offsets into [`Mark`]s: each line's
/// first byte and the number of characters before it, so that a mark counts
/// only the characters of its own line.
struct Positions<'t> {
    text: &'t str,
    line_starts: Vec<usize>,
    line_chars: Vec<usize>,
    /// How many bytes [`Self::mark`] has counted characters over.
    #[cfg(test)]
    scanned: std::cell::Cell<usize>,
}

impl<'t> Positions<'t> {
    fn new(text: &'t str) -> Self {
        let mut line_starts = vec![0];
        let mut line_chars = vec![0];
        let mut chars = 0;
        let mut previous = 0;
        for (at, _) in text.match_indices('\n') {
            chars += text[previous..=at].chars().count();
            previous = at + 1;
            line_starts.push(previous);
            line_chars.push(chars);
        }
        Self {
            text,
            line_starts,
            line_chars,
            #[cfg(test)]
            scanned: std::cell::Cell::new(text.len()),
        }
    }

    fn mark(&self, byte: usize) -> Mark {
        let mut byte = byte.min(self.text.len());
        while !self.text.is_char_boundary(byte) {
            byte -= 1;
        }
        let line = self.line_starts.partition_point(|start| *start <= byte);
        let start = self.line_starts[line.saturating_sub(1)];
        let before = self.text[start..byte].chars().count();
        #[cfg(test)]
        self.scanned.set(self.scanned.get() + (byte - start));
        Mark {
            index: self.line_chars[line.saturating_sub(1)] + before,
            line,
            column: before + 1,
        }
    }
}

/// Parses `text` into a [`Value::Map`] node.
///
/// # Errors
///
/// A [`ParseError`] when `toml_edit` refuses the text, or when it nests
/// deeper than [`MAX_DEPTH`].
pub fn parse(text: &str) -> Result<Node, ParseError> {
    let document = ImDocument::parse(text).map_err(|error| {
        let positions = Positions::new(text);
        let mark = error.span().map(|span| positions.mark(span.start));
        ParseError {
            message: error
                .message()
                .trim()
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
            line: mark.map(|mark| mark.line),
            column: mark.map(|mark| mark.column),
            too_deep: false,
        }
    })?;
    let positions = Positions::new(text);
    let start = positions.mark(0);
    let end = positions.mark(text.len());
    let entries = table_entries(document.as_table(), &positions, start, 0)?;
    Ok(Node {
        value: Value::Map(entries),
        start,
        end,
        text: None,
    })
}

fn too_deep() -> ParseError {
    ParseError {
        message: "The document is nested too deeply.".to_owned(),
        line: None,
        column: None,
        too_deep: true,
    }
}

fn span_marks(
    span: Option<std::ops::Range<usize>>,
    positions: &Positions<'_>,
    fallback: Mark,
) -> (Mark, Mark) {
    span.map_or((fallback, fallback), |span| {
        (positions.mark(span.start), positions.mark(span.end))
    })
}

fn table_entries(
    table: &Table,
    positions: &Positions<'_>,
    at: Mark,
    depth: usize,
) -> Result<Vec<Entry>, ParseError> {
    let mut entries = Vec::with_capacity(table.len());
    for (key, item) in table {
        let key_span = table.key(key).and_then(toml_edit::Key::span);
        let (key_start, key_end) = span_marks(key_span, positions, at);
        let value = item_node(item, positions, key_start, depth + 1)?;
        entries.push(Entry {
            key: Arc::new(Node {
                value: Value::Str(key.to_owned()),
                start: key_start,
                end: key_end,
                text: None,
            }),
            value: Arc::new(value),
        });
    }
    Ok(entries)
}

fn item_node(
    item: &Item,
    positions: &Positions<'_>,
    at: Mark,
    depth: usize,
) -> Result<Node, ParseError> {
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    let (start, end) = span_marks(item.span(), positions, at);
    let value = match item {
        Item::None => Value::Null,
        Item::Value(value) => return value_node(value, positions, at, depth),
        Item::Table(table) => Value::Map(table_entries(table, positions, start, depth)?),
        Item::ArrayOfTables(tables) => {
            let mut items = Vec::with_capacity(tables.len());
            for table in tables {
                let (table_start, table_end) = span_marks(table.span(), positions, start);
                items.push(Arc::new(Node {
                    value: Value::Map(table_entries(table, positions, table_start, depth + 1)?),
                    start: table_start,
                    end: table_end,
                    text: None,
                }));
            }
            Value::Seq(items)
        }
    };
    Ok(Node {
        value,
        start,
        end,
        text: None,
    })
}

fn value_node(
    value: &toml_edit::Value,
    positions: &Positions<'_>,
    at: Mark,
    depth: usize,
) -> Result<Node, ParseError> {
    if depth > MAX_DEPTH {
        return Err(too_deep());
    }
    let (start, end) = span_marks(value.span(), positions, at);
    let converted = match value {
        toml_edit::Value::String(text) => Value::Str(text.value().clone()),
        toml_edit::Value::Integer(integer) => Value::Int(*integer.value()),
        toml_edit::Value::Float(float) => Value::Float(*float.value()),
        toml_edit::Value::Boolean(flag) => Value::Bool(*flag.value()),
        toml_edit::Value::Datetime(datetime) => Value::Datetime(datetime.value().to_string()),
        toml_edit::Value::Array(array) => {
            let mut items = Vec::with_capacity(array.len());
            for item in array {
                items.push(Arc::new(value_node(item, positions, start, depth + 1)?));
            }
            Value::Seq(items)
        }
        toml_edit::Value::InlineTable(table) => {
            let mut entries = Vec::with_capacity(table.len());
            for (key, item) in table {
                let key_span = table.key(key).and_then(toml_edit::Key::span);
                let (key_start, key_end) = span_marks(key_span, positions, start);
                entries.push(Entry {
                    key: Arc::new(Node {
                        value: Value::Str(key.to_owned()),
                        start: key_start,
                        end: key_end,
                        text: None,
                    }),
                    value: Arc::new(value_node(item, positions, key_start, depth + 1)?),
                });
            }
            Value::Map(entries)
        }
    };
    Ok(Node {
        value: converted,
        start,
        end,
        text: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_arrays_and_scalars_keep_their_type_and_position() {
        let node =
            parse("a = 1\n[b]\nc = \"x\"\nd = 1979-05-27\n[[e]]\nf = [true, 1.5]\n").unwrap();
        let b = node.get("b").unwrap();
        let c = b.get("c").unwrap();
        assert_eq!(c.value, Value::Str("x".into()));
        assert_eq!((c.start.line, c.start.column), (3, 5));
        assert_eq!(
            b.get("d").unwrap().value,
            Value::Datetime("1979-05-27".into())
        );
        let Value::Seq(e) = &node.get("e").unwrap().value else {
            panic!("e");
        };
        let f = e[0].get("f").unwrap();
        let Value::Seq(items) = &f.value else {
            panic!("f");
        };
        assert_eq!(items[0].value, Value::Bool(true));
        assert_eq!(items[1].value, Value::Float(1.5));
        assert_eq!(node.get("a").unwrap().value, Value::Int(1));
    }

    #[test]
    fn a_syntax_error_has_a_message_and_a_position() {
        let error = parse("x = = 1\n").unwrap_err();
        assert!(!error.message.is_empty());
        assert_eq!(error.line, Some(1));
        assert!(!error.too_deep);
    }

    #[test]
    fn nesting_past_the_parsers_limit_is_refused() {
        // toml_edit refuses more than 80 nested keys or values itself, far
        // below MAX_DEPTH, which stays the bound of this module's walk.
        let header = vec!["a"; 100].join(".");
        let error = parse(&format!("[{header}]\nx = 1\n")).unwrap_err();
        assert!(!error.too_deep, "{error:?}");
        let value = format!("x = {}1{}\n", "[".repeat(100), "]".repeat(100));
        assert!(parse(&value).is_err());
        let header = vec!["a"; 60].join(".");
        assert!(parse(&format!("[{header}]\nx = 1\n")).is_ok());
    }

    #[test]
    fn an_error_after_a_multibyte_character_counts_code_points() {
        // `x` is the 9th code point after two two-byte characters (byte 11),
        // and the 8th after one four-byte character (byte 11).
        let accent = parse("a = \"éé\" x\n").unwrap_err();
        assert_eq!((accent.line, accent.column), (Some(1), Some(10)));
        let astral = parse("a = \"😀\" x\n").unwrap_err();
        assert_eq!((astral.line, astral.column), (Some(1), Some(9)));
        let second_line = parse("\"é\" = 1\na = \"😀é\" x\n").unwrap_err();
        assert_eq!((second_line.line, second_line.column), (Some(2), Some(10)));
    }

    #[test]
    fn a_mark_counts_only_the_characters_of_its_line() {
        // Every mark used to count the characters from the start of the
        // text, so parsing was quadratic in its length.
        let mut text = String::new();
        for n in 0..2_000 {
            text.push_str(&format!("k{n} = \"é\"\n"));
        }
        let positions = Positions::new(&text);
        let mut marks = Vec::new();
        for (at, _) in text.match_indices('=') {
            marks.push(positions.mark(at));
        }
        assert!(
            positions.scanned.get() <= 2 * text.len(),
            "{} bytes scanned for a text of {}",
            positions.scanned.get(),
            text.len()
        );
        let last = marks.last().unwrap();
        assert_eq!((last.line, last.column), (2_000, 7));
        let expected = text[..text.rfind('=').unwrap()].chars().count();
        assert_eq!(last.index, expected);
        let node = parse(&text).unwrap();
        let value = node.get("k1999").unwrap();
        assert_eq!((value.start.line, value.start.column), (2_000, 9));
        assert_eq!(value.start.index, expected + 2);
    }

    #[test]
    fn a_position_after_a_multibyte_character_counts_code_points() {
        let node = parse("a = \"é\"\nb = 1\n").unwrap();
        let b = node.get("b").unwrap();
        assert_eq!((b.start.line, b.start.column, b.start.index), (2, 5, 12));
    }
}
