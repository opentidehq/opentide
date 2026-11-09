//! Where a finding points, from the parser's node positions: the CLI's
//! contract is one-line spans, lines and columns from 1, columns in Unicode
//! code points, `end_column` exclusive.
//!
//! - A scalar written on one line (`null` and `~` included): the scalar,
//!   without its quotes.
//! - A block value (a mapping, a sequence, a scalar over several lines) or a
//!   value left empty: its key. A sequence item that is a collection: the
//!   collection when it is written on one line, else its first character; an
//!   empty item: its `-`.
//! - A path that stops at a missing key: the deepest key that exists
//!   (`found` is `false`); a missing top-level key: the document's first key.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use super::{Document, Entry, Mark, Node, Value};

/// A span as the CLI prints it: 1-based `line` and `column` in code points,
/// `end_column` exclusive on `end_line`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Span {
    /// The line, from 1.
    pub line: usize,
    /// The first column, from 1.
    pub column: usize,
    /// The line `end_column` is on (spans are one line).
    pub end_line: usize,
    /// The column just after the span.
    pub end_column: usize,
    /// The text inside the span.
    pub text: String,
    /// `false` when the path stopped short of a missing key: the span is the
    /// deepest key that exists.
    pub found: bool,
}

/// One step down a field path: the child, and the node its key is (the item
/// itself, in a sequence).
struct Step<'a> {
    child: &'a Arc<Node>,
    key: &'a Node,
    in_mapping: bool,
}

/// The index of each string key in the mappings a locator has walked, so
/// many errors in one large mapping are placed in linear time.
#[derive(Debug, Default)]
struct KeyIndex {
    maps: HashMap<usize, HashMap<String, usize>>,
}

impl KeyIndex {
    fn position(&mut self, node: &Node, entries: &[Entry], part: &str) -> Option<usize> {
        if entries.len() < 16 {
            return entries
                .iter()
                .position(|entry| key_text(&entry.key) == part);
        }
        let map = self
            .maps
            .entry(std::ptr::from_ref(node) as usize)
            .or_insert_with(|| {
                entries
                    .iter()
                    .enumerate()
                    .fold(HashMap::new(), |mut map, (index, entry)| {
                        // The first entry wins, as in the scan of a small
                        // mapping: `1` and `"1"` both display as `1`.
                        map.entry(key_text(&entry.key)).or_insert(index);
                        map
                    })
            });
        map.get(part).copied()
    }
}

/// A key as a field path writes it ([`Value`]'s `Display`).
fn key_text(key: &Node) -> String {
    key.value.to_string()
}

fn step<'a>(index: &mut KeyIndex, node: &'a Node, part: &str) -> Option<Step<'a>> {
    match &node.value {
        Value::Map(entries) => {
            let entry = &entries[index.position(node, entries, part)?];
            Some(Step {
                child: &entry.value,
                key: &entry.key,
                in_mapping: true,
            })
        }
        Value::Seq(items) => {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let item = items.get(part.parse::<usize>().ok()?)?;
            Some(Step {
                child: item,
                key: item,
                in_mapping: false,
            })
        }
        _ => None,
    }
}

fn is_scalar(node: &Node) -> bool {
    !matches!(node.value, Value::Seq(_) | Value::Map(_))
}

/// Places field paths in a document, many at a time: [`Document::locator`].
#[derive(Debug)]
pub struct Locator<'d> {
    document: &'d Document,
    index: RefCell<KeyIndex>,
}

impl Locator<'_> {
    /// [`Document::span`].
    pub fn span(&self, field_path: &[String], at_key: bool) -> Option<Span> {
        self.document
            .span_with(&mut self.index.borrow_mut(), field_path, at_key)
    }

    /// [`Document::yaml_line`].
    pub fn yaml_line(&self, field_path: &[String]) -> Option<usize> {
        self.document
            .yaml_line_with(&mut self.index.borrow_mut(), field_path)
    }
}

impl Document {
    /// A locator for many field paths of this document.
    pub fn locator(&self) -> Locator<'_> {
        Locator {
            document: self,
            index: RefCell::new(KeyIndex::default()),
        }
    }

    /// Line `number` (from 1), as characters, made once per line.
    fn line_chars(&self, number: usize) -> Option<&[char]> {
        let index = number.checked_sub(1)?;
        let &(start, end) = self.lines.get(index)?;
        let chars = self
            .line_chars
            .get(index)?
            .get_or_init(|| self.source[start..end].chars().collect());
        Some(chars)
    }

    /// The span from `start` to `end` when both are on one line and it is not
    /// empty; quotes around a scalar are left out.
    fn one_line(&self, start: Mark, end: Mark, unquote: bool, found: bool) -> Option<Span> {
        if start.line != end.line || end.column <= start.column {
            return None;
        }
        let text = self.line_chars(start.line)?;
        let (mut first, mut last) = (start.column - 1, (end.column - 1).min(text.len()));
        // saphyr ends a flow collection that is a block sequence's item, and
        // a quoted scalar, after the blanks that follow it (`- {k: v}   `).
        // Only YAML's blanks: a plain scalar may end in a space YAML does not
        // treat as white space (U+00A0, U+3000), which is the scalar's own.
        while last > first && matches!(text[last - 1], ' ' | '\t') {
            last -= 1;
        }
        if unquote
            && let Some(&quote) = text.get(first).filter(|c| matches!(c, '"' | '\''))
            && let Some(close) = closing_quote(&text[first + 1..last], quote)
        {
            last = first + 1 + close;
            first += 1;
        }
        if last <= first {
            return None;
        }
        Some(Span {
            line: start.line,
            column: first + 1,
            end_line: start.line,
            end_column: last + 1,
            text: text[first..last].iter().collect(),
            found,
        })
    }

    /// The key of a step: the key scalar in a mapping; in a sequence, the
    /// item on its line, else its first character, or its `-` when it is
    /// empty.
    fn key_span(&self, step: &Step<'_>, found: bool) -> Option<Span> {
        let item = step.key;
        if step.in_mapping {
            return self.one_line(item.start, item.end, true, found);
        }
        if let Some(span) = self.one_line(item.start, item.end, true, found) {
            return Some(span);
        }
        let mut start = item.start;
        if item.end.index <= item.start.index {
            // An empty item: the parser marks where its value would be.
            let text = self.line_chars(start.line)?;
            let dash = text[..(start.column - 1).min(text.len())]
                .iter()
                .rposition(|&c| c == '-')?;
            start.column = dash + 1;
        }
        let end = Mark {
            index: start.index + 1,
            line: start.line,
            column: start.column + 1,
        };
        self.one_line(start, end, false, found)
    }

    /// Where a finding about `field_path` points: the value when it is a
    /// scalar on one line, else its key; for a path that stops at a missing
    /// key, the deepest key that exists (`found` is `false`), and for a
    /// missing top-level key the document's first key. `at_key` points at the
    /// key even for a scalar (an unknown key). `None` where there is no place
    /// (an empty document, an empty path).
    pub fn span(&self, field_path: &[String], at_key: bool) -> Option<Span> {
        self.span_with(&mut KeyIndex::default(), field_path, at_key)
    }

    fn span_with(&self, index: &mut KeyIndex, field_path: &[String], at_key: bool) -> Option<Span> {
        let root = self.root.as_ref()?;
        if field_path.is_empty() {
            return None;
        }
        let mut node: &Arc<Node> = root;
        let mut last: Option<Step<'_>> = None;
        let mut found = true;
        for part in field_path {
            match step(index, node, part) {
                Some(next) => {
                    node = next.child;
                    last = Some(next);
                }
                None => {
                    found = false;
                    break;
                }
            }
        }
        let Some(last) = last else {
            // A top-level field is missing: the mapping's first key.
            let Value::Map(entries) = &root.value else {
                return None;
            };
            let first = entries.first()?;
            return self.one_line(first.key.start, first.key.end, true, false);
        };
        if found
            && !at_key
            && is_scalar(node)
            && let Some(span) = self.one_line(node.start, node.end, true, true)
        {
            return Some(span);
        }
        self.key_span(&last, found)
    }

    /// The finding's `yaml_line`, from 0 as the CLI's JSON writes it: for a
    /// scalar in a mapping, its key's line (a block scalar's text starts on
    /// the next one); otherwise the line the value starts on. `None` when a
    /// step of the path is missing.
    pub fn yaml_line(&self, field_path: &[String]) -> Option<usize> {
        self.yaml_line_with(&mut KeyIndex::default(), field_path)
    }

    fn yaml_line_with(&self, index: &mut KeyIndex, field_path: &[String]) -> Option<usize> {
        let mut node: &Arc<Node> = self.root.as_ref()?;
        let mut key: Option<&Node> = None;
        for part in field_path {
            let next = step(index, node, part)?;
            key = next.in_mapping.then_some(next.key);
            node = next.child;
        }
        let line = match key {
            Some(key) if is_scalar(node) => key.start.line,
            _ => node.start.line,
        };
        line.checked_sub(1)
    }
}

/// The index of the quote that closes a scalar opened with `quote`, in the
/// text after the opening quote: `''` is a quote inside single quotes, `\`
/// escapes the next character inside double quotes.
fn closing_quote(text: &[char], quote: char) -> Option<usize> {
    let mut at = 0;
    while at < text.len() {
        match text[at] {
            '\\' if quote == '"' => at += 2,
            c if c == quote => {
                if quote == '\'' && text.get(at + 1) == Some(&'\'') {
                    at += 2;
                } else {
                    return Some(at);
                }
            }
            _ => at += 1,
        }
    }
    None
}

/// Byte ranges of the lines of `source`: split on `\r\n`, `\r` and `\n`, as
/// YAML breaks lines, without a last empty line.
pub(super) fn split_lines(source: &str) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = source.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\r' => {
                lines.push((start, at));
                at += if bytes.get(at + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = at;
            }
            b'\n' => {
                lines.push((start, at));
                at += 1;
                start = at;
            }
            _ => at += 1,
        }
    }
    if start < bytes.len() {
        lines.push((start, bytes.len()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::load;

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn lines_split_as_yaml_breaks_them() {
        let text = "a\r\nb\rc\n\nd";
        let lines: Vec<&str> = split_lines(text)
            .iter()
            .map(|&(s, e)| &text[s..e])
            .collect();
        assert_eq!(lines, ["a", "b", "c", "", "d"]);
        assert_eq!(split_lines("a\n").len(), 1);
        assert!(split_lines("").is_empty());
    }

    #[test]
    fn a_scalar_points_at_itself_without_quotes() {
        let document = load("name: 'x y'  # c\nn: 12\nq: [\"a\\\"b\" , 'it''s']\n").unwrap();
        let span = document.span(&path(&["name"]), false).unwrap();
        assert_eq!((span.line, span.column, span.end_column), (1, 8, 11));
        assert_eq!(span.text, "x y");
        let span = document.span(&path(&["n"]), false).unwrap();
        assert_eq!((span.line, span.column, span.end_column), (2, 4, 6));
        let span = document.span(&path(&["n"]), true).unwrap();
        assert_eq!(
            (span.column, span.end_column, span.text.as_str()),
            (1, 2, "n")
        );
        let span = document.span(&path(&["q", "0"]), false).unwrap();
        assert_eq!(
            (span.column, span.end_column, span.text.as_str()),
            (6, 10, "a\\\"b")
        );
        let span = document.span(&path(&["q", "1"]), false).unwrap();
        assert_eq!(
            (span.column, span.end_column, span.text.as_str()),
            (15, 20, "it''s")
        );
    }

    #[test]
    fn a_span_ends_at_the_values_last_character() {
        // Blanks after a flow collection item or a quoted scalar.
        let document = load("a:\n  - {k: v}   \n  - [x]\t \nb: 'x'   \nc: z   \n").unwrap();
        for (parts, text) in [
            (&["a", "0"][..], "{k: v}"),
            (&["a", "1"][..], "[x]"),
            (&["b"][..], "x"),
            (&["c"][..], "z"),
        ] {
            let span = document.span(&path(parts), false).unwrap();
            assert_eq!(span.text, text, "{parts:?}");
            assert_eq!(span.end_column, span.column + text.chars().count());
        }
        // A space YAML does not treat as white space is the scalar's own.
        for text in ["a: x\u{a0}\n", "a: x  \u{3000}\n"] {
            let document = load(text).unwrap();
            let value = document.root().unwrap().get("a").unwrap().value.clone();
            let span = document.span(&path(&["a"]), false).unwrap();
            assert_eq!(Some(span.text.as_str()), value.as_str(), "{text:?}");
        }
    }

    #[test]
    fn colliding_display_keys_take_the_first_entry_at_any_size() {
        // `1` and `"1"` are two keys; a field path writes both as `1`.
        let small = load("1: a\n\"1\": b\n").unwrap();
        let mut large_text = String::from("1: a\n\"1\": b\n");
        for key in 0..20 {
            large_text.push_str(&format!("f{key}: x\n"));
        }
        let large = load(&large_text).unwrap();
        for document in [&small, &large] {
            let locator = document.locator();
            let span = locator.span(&path(&["1"]), false).unwrap();
            assert_eq!((span.line, span.text.as_str()), (1, "a"));
            assert_eq!(locator.yaml_line(&path(&["1"])), Some(0));
        }
    }

    #[test]
    fn many_errors_on_one_long_line_are_placed_in_linear_time() {
        let count = 40_000;
        let mut text = String::from("a: {");
        for key in 0..count {
            text.push_str(&format!("k{key}: v{key}, "));
        }
        text.push_str("}\n");
        let document = load(&text).unwrap();
        let locator = document.locator();
        let started = std::time::Instant::now();
        for key in 0..count {
            let span = locator
                .span(&path(&["a", &format!("k{key}")]), false)
                .unwrap();
            assert_eq!(span.text, format!("v{key}"));
        }
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs() < 30, "{elapsed:?}");
    }

    #[test]
    fn a_block_value_points_at_its_key() {
        let document = load("top:\n  inner: [a]\ntext: |\n  x\n  y\n").unwrap();
        let span = document.span(&path(&["top"]), false).unwrap();
        assert_eq!((span.line, span.column, span.end_column), (1, 1, 4));
        let span = document.span(&path(&["text"]), false).unwrap();
        assert_eq!((span.line, span.text.as_str()), (3, "text"));
        let span = document.span(&path(&["top", "inner", "0"]), false).unwrap();
        assert_eq!((span.line, span.column, span.end_column), (2, 11, 12));
    }

    #[test]
    fn a_missing_key_points_at_its_parent_or_the_first_key() {
        let document = load("a: 1\nb:\n  c: 2\n").unwrap();
        let span = document.span(&path(&["b", "d"]), false).unwrap();
        assert_eq!((span.line, span.text.as_str(), span.found), (2, "b", false));
        let span = document.span(&path(&["z"]), false).unwrap();
        assert_eq!((span.line, span.text.as_str(), span.found), (1, "a", false));
    }

    #[test]
    fn yaml_line_is_the_values_line_from_zero() {
        let document = load("a: 1\nb:\n  - x\nc:\nd: |\n  t\n").unwrap();
        assert_eq!(document.yaml_line(&path(&["a"])), Some(0));
        assert_eq!(document.yaml_line(&path(&["b"])), Some(2));
        assert_eq!(document.yaml_line(&path(&["b", "0"])), Some(2));
        assert_eq!(document.yaml_line(&path(&["c"])), Some(3));
        assert_eq!(document.yaml_line(&path(&["d"])), Some(4));
        assert_eq!(document.yaml_line(&path(&["e"])), None);
    }

    #[test]
    fn sequence_items_point_at_themselves_or_their_dash() {
        let document = load("a:\n  -\n  - [x, y]\n  - k: v\n    j: w\n  - ~\n").unwrap();
        let span = document.span(&path(&["a", "0"]), false).unwrap();
        assert_eq!((span.line, span.column, span.text.as_str()), (2, 3, "-"));
        let span = document.span(&path(&["a", "1"]), false).unwrap();
        assert_eq!((span.line, span.column, span.end_column), (3, 5, 11));
        let span = document.span(&path(&["a", "2"]), false).unwrap();
        assert_eq!((span.line, span.column, span.text.as_str()), (4, 5, "k"));
        let span = document.span(&path(&["a", "3"]), false).unwrap();
        assert_eq!((span.line, span.column, span.text.as_str()), (6, 5, "~"));
    }
}
