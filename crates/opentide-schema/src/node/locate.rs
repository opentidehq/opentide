//! Where the CLI points for a field path: a port of
//! `opentide.cli.ui.diagnostics.SourceFiles.span` (the span of a finding) and
//! `opentide.validation.errors._find_line` (its `yaml_line`), at the oracle
//! (opentide 0.23.0), quirks included. Both walk the document by the field
//! path's text: a key is found when the mapping has a `str` key equal to the
//! part, an index when the part is digits within the list.

use std::sync::Arc;

use super::{Document, Node, Value};

/// A span as the CLI prints it: 1-based `line` and `column` in code points,
/// `end_column` exclusive on `end_line`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Span {
    /// The line, from 1.
    pub line: usize,
    /// The first column, from 1.
    pub column: usize,
    /// The line `end_column` is on (the CLI's spans are one line).
    pub end_line: usize,
    /// The column just after the span.
    pub end_column: usize,
    /// The text inside the span, unquoted.
    pub text: String,
    /// `false` when the path stopped short of a missing key: the span is the
    /// deepest key that exists (the CLI then labels it "add … under this key").
    pub found: bool,
}

/// One step: the child at `part`, and where its key and value start.
struct Step<'a> {
    child: &'a Arc<Node>,
    /// `(line, column)` of the key (of the item, in a list), 0-based; `None`
    /// for an entry a merge key brought in (ruamel has no marker for it).
    key: Option<(usize, usize)>,
    value: Option<(usize, usize)>,
    in_mapping: bool,
}

fn step<'a>(node: &'a Node, part: &str) -> Option<Step<'a>> {
    match &node.value {
        Value::Map(entries) => {
            let entry = entries
                .iter()
                .find(|entry| entry.key.value.as_str() == Some(part))?;
            let positioned = !entry.merged;
            Some(Step {
                child: &entry.value,
                key: positioned.then_some((entry.key.start.line, entry.key.start.column)),
                value: positioned.then_some((entry.value.start.line, entry.value.start.column)),
                in_mapping: true,
            })
        }
        Value::Seq(items) => {
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let index: usize = part.parse().ok()?;
            let item = items.get(index)?;
            let at = Some((item.start.line, item.start.column));
            Some(Step {
                child: item,
                key: at,
                value: at,
                in_mapping: false,
            })
        }
        _ => None,
    }
}

fn is_container(node: &Node) -> bool {
    matches!(node.value, Value::Seq(_) | Value::Map(_))
}

impl Document {
    /// The source split as `split_yaml_lines` splits it: on `\r\n`, `\r` and
    /// `\n`, without a last empty line.
    fn line_text(&self, number: usize) -> Option<Vec<char>> {
        if number == 0 {
            return None;
        }
        let mut lines = Vec::new();
        let mut rest = self.source.as_str();
        loop {
            match rest.find(['\r', '\n']) {
                Some(at) => {
                    lines.push(&rest[..at]);
                    let skip = if rest[at..].starts_with("\r\n") { 2 } else { 1 };
                    rest = &rest[at + skip..];
                    if lines.len() >= number {
                        break;
                    }
                }
                None => {
                    if !rest.is_empty() {
                        lines.push(rest);
                    }
                    break;
                }
            }
        }
        lines.get(number - 1).map(|line| line.chars().collect())
    }

    /// Where the CLI's frame points for `field_path`: the value when it is a
    /// scalar written on its line, else its key; for a path that stops at a
    /// missing key, the deepest key that exists (`found` is `false`), and for
    /// a missing top-level key the document's first key. `at_key` points at
    /// the key even for a scalar (the CLI does so for "Extra inputs are not
    /// permitted"). `None` where the CLI prints no position.
    pub fn span(&self, field_path: &[String], at_key: bool) -> Option<Span> {
        let root = self.root.as_ref()?;
        if field_path.is_empty() {
            return None;
        }
        let mut node: &Arc<Node> = root;
        let mut last: Option<(Step<'_>, &str)> = None;
        let mut found = true;
        for part in field_path {
            match step(node, part) {
                Some(next) => {
                    node = next.child;
                    last = Some((next, part.as_str()));
                }
                None => {
                    found = false;
                    break;
                }
            }
        }
        if last.is_none()
            && !found
            && let Value::Map(entries) = &root.value
            && let Some(first) = entries.first()
        {
            // A top-level field is missing: point at the mapping's first key.
            let key = first.key.value.python_str();
            let next = step(root, &key)?;
            return self.key_span(&next, &key, false);
        }
        let (last_step, key) = last?;
        if found
            && !at_key
            && !is_container(node)
            && let Some((line, column)) = last_step.value
            && let Some(span) = self.token(line, column)
        {
            return Some(span);
        }
        self.key_span(&last_step, key, found)
    }

    fn key_span(&self, last: &Step<'_>, key: &str, found: bool) -> Option<Span> {
        let (line, mut column) = last.key?;
        let text = self.line_text(line + 1)?;
        let length = if last.in_mapping {
            key.chars().count()
        } else {
            1
        };
        if last.in_mapping {
            let needle: Vec<char> = key.chars().collect();
            if let Some(located) = find_from(&text, &needle, column) {
                column = located;
            }
        }
        let slice: String = text.iter().skip(column).take(length).collect();
        Some(Span {
            line: line + 1,
            column: column + 1,
            end_line: line + 1,
            end_column: column + 1 + length,
            text: slice,
            found,
        })
    }

    /// `SourceFiles._token`: the scalar written at `(line, column)`.
    fn token(&self, line: usize, column: usize) -> Option<Span> {
        let text = self.line_text(line + 1)?;
        if column >= text.len() {
            return None;
        }
        let (start, end) = token_bounds(&text, column);
        if end <= start {
            return None;
        }
        Some(Span {
            line: line + 1,
            column: start + 1,
            end_line: line + 1,
            end_column: end + 1,
            text: text[start..end].iter().collect(),
            found: true,
        })
    }

    /// The finding's `yaml_line` (0-based), as `_find_line` computes it: a
    /// container's own line, else the line its parent marks for the value;
    /// `None` when a step is missing or its value is `null`.
    pub fn yaml_line(&self, field_path: &[String]) -> Option<usize> {
        let mut node: &Arc<Node> = self.root.as_ref()?;
        if field_path.is_empty() {
            return is_container(node).then_some(node.start.line);
        }
        for (index, part) in field_path.iter().enumerate() {
            let next = step(node, part)?;
            if matches!(next.child.value, Value::Null) {
                return None;
            }
            if index + 1 == field_path.len() {
                if is_container(next.child) {
                    return Some(next.child.start.line);
                }
                return next.value.map(|(line, _)| line);
            }
            node = next.child;
        }
        None
    }
}

/// Python's `str.find(needle, start)` on code points.
fn find_from(text: &[char], needle: &[char], start: usize) -> Option<usize> {
    if needle.is_empty() {
        return (start <= text.len()).then_some(start);
    }
    if needle.len() > text.len() {
        return None;
    }
    (start..=text.len() - needle.len()).find(|&at| text[at..at + needle.len()] == *needle)
}

/// `_token_bounds`: `[start, end)` of the scalar written at `start`, without
/// its quotes.
fn token_bounds(text: &[char], start: usize) -> (usize, usize) {
    let first = text[start];
    if first == '"' || first == '\'' {
        let mut end = start + 1;
        while end < text.len() {
            if text[end] == '\\' && first == '"' {
                end += 2;
                continue;
            }
            if text[end] == first {
                if first == '\'' && text.get(end + 1) == Some(&'\'') {
                    end += 2;
                    continue;
                }
                return (start + 1, end);
            }
            end += 1;
        }
        return (start + 1, text.len());
    }
    if first == '|' || first == '>' {
        return (start, start + 1);
    }
    let in_flow = {
        let prefix = &text[..start];
        let count = |c: char| prefix.iter().filter(|&&x| x == c).count();
        count('[') > count(']') || count('{') > count('}')
    };
    let mut end = start;
    while end < text.len() {
        let character = text[end];
        let stop = character == '#' || (in_flow && matches!(character, ',' | ']' | '}'));
        // `text[end - 1]` at `end == 0` is Python's `text[-1]`, the last character.
        let before = if end == 0 {
            text[text.len() - 1]
        } else {
            text[end - 1]
        };
        if stop && (character != '#' || before == ' ' || before == '\t') {
            break;
        }
        end += 1;
    }
    // `len(text[:end].rstrip())`: Python's `str.rstrip()` strips Unicode
    // whitespace.
    let mut trimmed = end;
    while trimmed > 0 && text[trimmed - 1].is_whitespace() {
        trimmed -= 1;
    }
    (start, trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    #[test]
    fn token_bounds_are_the_clis() {
        let text = chars("a: \"x\\\"y\" # c");
        assert_eq!(token_bounds(&text, 3), (4, 8));
        let text = chars("a: 'it''s'");
        assert_eq!(token_bounds(&text, 3), (4, 9));
        let text = chars("a: plain value # comment");
        assert_eq!(token_bounds(&text, 3), (3, 14));
        let text = chars("a: x#y");
        assert_eq!(token_bounds(&text, 3), (3, 6));
        let text = chars("a: [x, y]");
        assert_eq!(token_bounds(&text, 4), (4, 5));
        let text = chars("a: |");
        assert_eq!(token_bounds(&text, 3), (3, 4));
        let text = chars("a: \"unclosed");
        assert_eq!(token_bounds(&text, 3), (4, 12));
    }

    #[test]
    fn find_is_pythons() {
        assert_eq!(find_from(&chars("abcabc"), &chars("bc"), 2), Some(4));
        assert_eq!(find_from(&chars("abc"), &chars("x"), 0), None);
        assert_eq!(find_from(&chars("abc"), &chars(""), 1), Some(1));
    }
}
