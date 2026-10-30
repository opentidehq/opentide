//! Block-style YAML read the way a YAML parser reads it: every mapping key
//! with its full path, list items by index, and the value of a scalar with a
//! map from each byte of the value back to the source.
//!
//! Tide objects are block-style YAML: nested mappings, block sequences, and
//! scalars. Flow collections (`[a, b]`, `{a: 1}`) are skipped whole, never
//! read as keys. Scalars decode as YAML 1.2 does:
//!
//! - block scalars of either style (`|` literal, `>` folded), with a
//!   chomping indicator (`-`, `+`) and an indentation indicator (`|2`) in
//!   either order;
//! - plain scalars, continued on more-indented lines;
//! - single- and double-quoted scalars, on one line or several, with their
//!   escapes.
//!
//! Line breaks a scalar folds into a space, and escapes, map to the source
//! byte they come from, so a position inside the value lands on the source
//! character that produced it.

use crate::yaml_path::mapping_key;

/// A mapping key, its path from the document root, and where its scalar
/// value starts.
#[derive(Debug, Clone)]
pub(crate) struct YamlKey {
    /// Key names from the document root. A list item is its index:
    /// `["response", "procedure", "searches", "0", "query"]`.
    pub path: Vec<String>,
    /// Byte offset of the key token (its opening quote, when quoted).
    pub key_start: usize,
    /// Column of the key: the indentation of the mapping that holds it.
    pub column: usize,
    /// Byte offset of the value's first character, after any tag or anchor,
    /// when the value is a scalar. `None` for a collection, an alias, or no
    /// value.
    pub scalar: Option<usize>,
}

impl YamlKey {
    pub(crate) fn path_is(&self, expected: &[&str]) -> bool {
        self.path.len() == expected.len() && self.path.iter().zip(expected).all(|(a, b)| a == b)
    }
}

/// A scalar's value, and for each byte of it the source byte it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Scalar {
    pub text: String,
    /// `map[i]` is the source byte of `text`'s byte `i`.
    pub map: Vec<usize>,
    /// Where the scalar ends in the source: after the line break of a block
    /// scalar's last line, else after its last character.
    pub end: usize,
}

impl Scalar {
    fn new() -> Self {
        Scalar {
            text: String::new(),
            map: Vec::new(),
            end: 0,
        }
    }

    fn push(&mut self, c: char, at: usize) {
        self.text.push(c);
        for k in 0..c.len_utf8() {
            self.map.push(at + k);
        }
    }

    fn push_str(&mut self, s: &str, at: usize) {
        self.text.push_str(s);
        self.map.extend(at..at + s.len());
    }
}

/// One source line: where it starts, its text without the line break, and
/// where the next line starts.
#[derive(Debug, Clone, Copy)]
struct Line<'a> {
    start: usize,
    text: &'a str,
    next: usize,
}

impl Line<'_> {
    fn indent(&self) -> usize {
        self.text.bytes().take_while(|b| *b == b' ').count()
    }

    /// The text after the indentation.
    fn body(&self) -> &str {
        &self.text[self.indent()..]
    }

    /// Offset of the line break (or of the end of the source).
    fn break_at(&self) -> usize {
        self.start + self.text.len()
    }

    fn is_blank(&self) -> bool {
        self.text.trim_matches([' ', '\t']).is_empty()
    }
}

fn lines_from(source: &str, from: usize) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut start = from;
    for raw in source[from..].split_inclusive('\n') {
        out.push(Line {
            start,
            text: raw.trim_end_matches('\n').trim_end_matches('\r'),
            next: start + raw.len(),
        });
        start += raw.len();
    }
    out
}

/// Every mapping key in a block-style YAML document, in source order.
pub(crate) fn mapping_keys(source: &str) -> Vec<YamlKey> {
    struct Frame {
        column: usize,
        name: String,
        /// Items of the list this key holds that have started.
        items: Option<usize>,
    }
    let lines = lines_from(source, 0);
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    // Lines indented more than this belong to the value before them.
    let mut owned_by: Option<usize> = None;
    for (index, line) in lines.iter().enumerate() {
        let indent = line.indent();
        let body = line.body();
        if line.is_blank() {
            continue;
        }
        if let Some(owner) = owned_by {
            if indent > owner {
                continue;
            }
            owned_by = None;
        }
        if body.starts_with('#') {
            continue;
        }
        if indent == 0 && is_document_marker(body) {
            stack.clear();
            continue;
        }
        // `- key: value` puts the key after the dash; each dash starts an item
        // of the list held by the nearest key left of it.
        let mut column = indent;
        let mut content = body;
        let mut dash = None;
        while let Some(rest) = content.strip_prefix('-') {
            if !(rest.is_empty() || rest.starts_with([' ', '\t'])) {
                break;
            }
            while stack.last().is_some_and(|frame| frame.column > column) {
                stack.pop();
            }
            if let Some(frame) = stack.last_mut() {
                frame.items = Some(frame.items.map_or(0, |n| n + 1));
            }
            dash = Some(column);
            let trimmed = rest.trim_start_matches([' ', '\t']);
            column += content.len() - trimmed.len();
            content = trimmed;
        }
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let Some((name, _, _, after)) = mapping_key(content) else {
            // A scalar list item (`- Host::Account`), maybe continued below.
            if let Some(dash) = dash {
                owned_by = Some(dash);
            }
            continue;
        };
        while stack.last().is_some_and(|frame| frame.column >= column) {
            stack.pop();
        }
        let mut path = Vec::with_capacity(stack.len() * 2 + 1);
        for frame in &stack {
            path.push(frame.name.clone());
            if let Some(item) = frame.items {
                path.push(item.to_string());
            }
        }
        path.push(name.clone());
        let key_start = line.start + column;
        let value = skip_properties(after.trim_start_matches([' ', '\t']));
        let value_at = line.start + line.text.len() - value.len();
        let scalar = match value.chars().next() {
            None | Some('#') => {
                // The value is on the lines below: a collection, or a scalar.
                match next_significant(&lines[index + 1..]) {
                    Some(next) if next.indent() > column && !opens_collection(next.body()) => {
                        owned_by = Some(column);
                        Some(next.start + next.indent())
                    }
                    _ => None,
                }
            }
            Some('[' | '{' | '*') => {
                owned_by = Some(column);
                None
            }
            Some(_) => {
                owned_by = Some(column);
                Some(value_at)
            }
        };
        if scalar.is_none() && owned_by.is_none() {
            stack.push(Frame {
                column,
                name: name.clone(),
                items: None,
            });
        }
        out.push(YamlKey {
            path,
            key_start,
            column,
            scalar,
        });
    }
    out
}

fn is_document_marker(body: &str) -> bool {
    ["---", "..."]
        .iter()
        .any(|marker| body == *marker || body.starts_with(&format!("{marker} ")))
}

/// `value` without a leading tag (`!!str`) or anchor (`&a`).
fn skip_properties(mut value: &str) -> &str {
    while value.starts_with(['!', '&']) {
        let end = value.find([' ', '\t']).unwrap_or(value.len());
        value = value[end..].trim_start_matches([' ', '\t']);
    }
    value
}

fn next_significant<'a>(lines: &[Line<'a>]) -> Option<Line<'a>> {
    lines
        .iter()
        .find(|line| !line.is_blank() && !line.body().starts_with('#'))
        .copied()
}

/// Whether a line opens a block collection: a list item or a mapping key.
fn opens_collection(body: &str) -> bool {
    body == "-" || body.starts_with("- ") || body.starts_with("-\t") || mapping_key(body).is_some()
}

/// The scalar starting at byte `at`, the value of a key in a mapping indented
/// `indent` columns. `None` when it is not a scalar or is not valid YAML.
pub(crate) fn scalar_at(source: &str, at: usize, indent: usize) -> Option<Scalar> {
    match source.get(at..)?.chars().next()? {
        '|' | '>' => block_scalar(source, at, indent),
        quote @ ('"' | '\'') => quoted_scalar(source, at, quote),
        '[' | '{' | '*' | '#' => None,
        _ => plain_scalar(source, at, indent),
    }
}

/// The value of `key` as a string, for a scalar key.
pub(crate) fn scalar_text(source: &str, key: &YamlKey) -> Option<String> {
    let scalar = scalar_at(source, key.scalar?, key.column)?;
    Some(scalar.text)
}

fn block_scalar(source: &str, at: usize, indent: usize) -> Option<Scalar> {
    let header_end = source[at..].find('\n').map_or(source.len(), |i| at + i);
    let header = source[at..header_end].trim_end_matches('\r');
    let folded = header.starts_with('>');
    // The indentation indicator and the chomping indicator, in either order.
    // Chomping only decides the value's trailing line breaks, which are left
    // out here: a scalar ends at its last line of text.
    let mut explicit = None;
    let mut chomping = false;
    let mut rest = &header[1..];
    for _ in 0..2 {
        match rest.chars().next() {
            Some(d @ '1'..='9') if explicit.is_none() => explicit = d.to_digit(10),
            Some('-' | '+') if !chomping => chomping = true,
            _ => break,
        }
        rest = &rest[1..];
    }
    // Then nothing, or a comment after a blank.
    let comment = rest.trim_start_matches([' ', '\t']);
    if !(comment.is_empty() || (comment.starts_with('#') && comment.len() < rest.len())) {
        return None;
    }
    let body_start = (header_end + 1).min(source.len());
    let mut content_indent = explicit.map(|d| indent + d as usize);
    // Lines of the scalar: `None` for an empty line.
    let mut rows: Vec<(Line<'_>, Option<&str>)> = Vec::new();
    let mut end = body_start;
    if header_end < source.len() {
        for line in lines_from(source, body_start) {
            let line_indent = line.indent();
            let only_spaces = line.text.bytes().all(|b| b == b' ');
            match content_indent {
                None if only_spaces => {
                    rows.push((line, None));
                    continue;
                }
                None => {
                    if line_indent <= indent {
                        break;
                    }
                    content_indent = Some(line_indent);
                }
                Some(_) => {}
            }
            let m = content_indent.unwrap_or(0);
            if only_spaces && line.text.len() <= m {
                rows.push((line, None));
                continue;
            }
            if line_indent < m {
                break;
            }
            rows.push((line, Some(&line.text[m..])));
        }
    }
    while rows.last().is_some_and(|(_, text)| text.is_none()) {
        rows.pop();
    }
    let mut scalar = Scalar::new();
    // The line break before the next content line, and the empty lines since.
    let mut pending: Option<usize> = None;
    let mut empties: Vec<usize> = Vec::new();
    let mut previous_spaced = true;
    for (line, text) in &rows {
        let Some(text) = text else {
            empties.push(line.break_at());
            continue;
        };
        let spaced = text.starts_with([' ', '\t']);
        match pending {
            None => {
                for at in &empties {
                    scalar.push('\n', *at);
                }
            }
            Some(at) if folded && !previous_spaced && !spaced => {
                if empties.is_empty() {
                    scalar.push(' ', at);
                } else {
                    for at in &empties {
                        scalar.push('\n', *at);
                    }
                }
            }
            Some(at) => {
                scalar.push('\n', at);
                for at in &empties {
                    scalar.push('\n', *at);
                }
            }
        }
        empties.clear();
        let text_at = line.start + (line.text.len() - text.len());
        scalar.push_str(text, text_at);
        pending = Some(line.break_at());
        previous_spaced = spaced;
        end = line.next;
    }
    scalar.end = end;
    Some(scalar)
}

/// Where a plain scalar's line ends: before ` #` (a comment), and before
/// trailing blanks.
fn plain_line(text: &str) -> (&str, bool) {
    let mut cut = text.len();
    let mut comment = false;
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && i > 0 && matches!(bytes[i - 1], b' ' | b'\t') {
            cut = i;
            comment = true;
            break;
        }
    }
    (text[..cut].trim_end_matches([' ', '\t']), comment)
}

fn plain_scalar(source: &str, at: usize, indent: usize) -> Option<Scalar> {
    let lines = lines_from(source, at);
    let first = lines.first()?;
    let mut scalar = Scalar::new();
    let (text, mut done) = plain_line(first.text);
    scalar.push_str(text, at);
    let mut pending = first.break_at();
    let mut empties = Vec::new();
    for line in &lines[1..] {
        if done {
            break;
        }
        if line.is_blank() {
            empties.push(line.break_at());
            continue;
        }
        let line_indent = line.indent();
        let body = line.text[line_indent..].trim_start_matches([' ', '\t']);
        if line_indent <= indent || body.starts_with('#') {
            break;
        }
        let (text, comment) = plain_line(body);
        done = comment;
        fold_break(&mut scalar, pending, &empties);
        empties.clear();
        scalar.push_str(text, line.start + (line.text.len() - body.len()));
        pending = line.break_at();
    }
    scalar.end = scalar.map.last().map_or(at, |b| b + 1);
    Some(scalar)
}

/// A line break between two lines of a plain or quoted scalar: a space, or
/// one line feed per empty line between them.
fn fold_break(scalar: &mut Scalar, at: usize, empties: &[usize]) {
    if empties.is_empty() {
        scalar.push(' ', at);
    } else {
        for at in empties {
            scalar.push('\n', *at);
        }
    }
}

fn quoted_scalar(source: &str, at: usize, quote: char) -> Option<Scalar> {
    let mut scalar = Scalar::new();
    // Text length before the blanks that end the current line, which a line
    // break drops.
    let mut blanks_from: Option<usize> = None;
    let mut chars = source[at + 1..]
        .char_indices()
        .map(|(i, c)| (at + 1 + i, c))
        .peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            c if c == quote => {
                if quote == '\'' && chars.peek().map(|(_, n)| *n) == Some('\'') {
                    chars.next();
                    scalar.push('\'', i);
                    blanks_from = None;
                    continue;
                }
                scalar.end = i + 1;
                return Some(scalar);
            }
            '\r' | '\n' => {
                if let Some(len) = blanks_from.take() {
                    scalar.text.truncate(len);
                    scalar.map.truncate(len);
                }
                if c == '\r' && chars.peek().map(|(_, n)| *n) == Some('\n') {
                    chars.next();
                }
                let empties = skip_folded_lines(&mut chars)?;
                fold_break(&mut scalar, i, &empties);
            }
            '\\' if quote == '"' => {
                let (_, e) = chars.next()?;
                if e == '\r' || e == '\n' {
                    // An escaped line break joins the lines with nothing.
                    if e == '\r' && chars.peek().map(|(_, n)| *n) == Some('\n') {
                        chars.next();
                    }
                    for at in skip_folded_lines(&mut chars)? {
                        scalar.push('\n', at);
                    }
                    blanks_from = None;
                    continue;
                }
                let decoded = match e {
                    '0' => '\0',
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    't' | '\t' => '\t',
                    'n' => '\n',
                    'v' => '\u{b}',
                    'f' => '\u{c}',
                    'r' => '\r',
                    'e' => '\u{1b}',
                    ' ' => ' ',
                    '"' => '"',
                    '/' => '/',
                    '\\' => '\\',
                    'N' => '\u{85}',
                    '_' => '\u{a0}',
                    'L' => '\u{2028}',
                    'P' => '\u{2029}',
                    'x' => hex_escape(&mut chars, 2)?,
                    'u' => hex_escape(&mut chars, 4)?,
                    'U' => hex_escape(&mut chars, 8)?,
                    _ => return None,
                };
                // An escape maps onto its backslash.
                scalar.push(decoded, i);
                blanks_from = None;
            }
            ' ' | '\t' => {
                if blanks_from.is_none() {
                    blanks_from = Some(scalar.text.len());
                }
                scalar.push(c, i);
            }
            _ => {
                scalar.push(c, i);
                blanks_from = None;
            }
        }
    }
    // The quote never closes.
    None
}

/// After a line break inside a quoted scalar: skip the next lines' leading
/// blanks. Returns the line breaks of the empty lines skipped, and `None` at
/// the end of the source.
fn skip_folded_lines(
    chars: &mut std::iter::Peekable<impl Iterator<Item = (usize, char)>>,
) -> Option<Vec<usize>> {
    let mut empties = Vec::new();
    loop {
        let &(i, c) = chars.peek()?;
        match c {
            ' ' | '\t' | '\r' => {
                chars.next();
            }
            '\n' => {
                empties.push(i);
                chars.next();
            }
            _ => return Some(empties),
        }
    }
}

fn hex_escape(
    chars: &mut std::iter::Peekable<impl Iterator<Item = (usize, char)>>,
    digits: usize,
) -> Option<char> {
    let text: String = (0..digits)
        .map(|_| chars.next().map(|(_, d)| d))
        .collect::<Option<_>>()?;
    char::from_u32(u32::from_str_radix(&text, 16).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(source, path, value)`: each value is what PyYAML 6 loads at `path`.
    /// Trailing line breaks are compared without chomping, which a query
    /// does not read.
    const CASES: &[(&str, &str, &str)] = &[
        ("q: |\n  a\n   b\n\n  c\n", "q", "a\n b\n\nc\n"),
        ("q: |-\n  a\n  b\n\n\n", "q", "a\nb"),
        ("q: |+\n  a\n  b\n\n\nn: 1\n", "q", "a\nb\n\n\n"),
        ("q: >\n  a\n  b\n\n  c\n   d\n  e\n", "q", "a b\nc\n d\ne\n"),
        (
            "q: >-\n  SigninLogs\n  | take 1\n",
            "q",
            "SigninLogs | take 1",
        ),
        ("q: >+\n  a\n  b\n\n", "q", "a b\n\n"),
        ("q: >-\n  a\n\n\n  b\n", "q", "a\n\nb"),
        (
            "q: >\n  a\n    b\n  c\n\n    d\n\n  e\n",
            "q",
            "a\n  b\nc\n\n  d\n\ne\n",
        ),
        ("q: |2\n    a\n  b\n", "q", "  a\nb\n"),
        ("q: >1-\n   a\n  b\n c\n", "q", "  a\n b\nc"),
        ("q: |-2\n    a\n  b\n", "q", "  a\nb"),
        ("q: |\n\n  a\n  b\n", "q", "\na\nb\n"),
        ("q: | # note\n  a\n", "q", "a\n"),
        ("q: >-\n  a\n  b\nr: x\n", "q", "a b"),
        (
            "c:\n  s:\n    query: >-\n      SigninLogs\n      | where x == 1\n\n      | take 1\n    status: x\n",
            "c.s.query",
            "SigninLogs | where x == 1\n| take 1",
        ),
        (
            "s:\n  - p: a\n    query: >-\n      a\n      b\n  - p: b\n",
            "s.0.query",
            "a b",
        ),
        (
            "s:\n- query: |2\n     a\n    b\n  p: x\n",
            "s.0.query",
            " a\nb\n",
        ),
        ("q: a | where b\n", "q", "a | where b"),
        ("q: a | b # note\n", "q", "a | b"),
        ("q: a\n  | b\n\n  | c\nr: 1\n", "q", "a | b\n| c"),
        ("q:\n  a\n  | b\n", "q", "a | b"),
        ("q: a#b\n", "q", "a#b"),
        ("q: 'it''s a'\n", "q", "it's a"),
        ("q: 'a\n  b\n\n  c  '\n", "q", "a b\nc  "),
        (
            "q: \"a\\tb\\n\\\"c\\\" \\\\ \\x41\\u00e9\"\n",
            "q",
            "a\tb\n\"c\" \\ Aé",
        ),
        (
            "q: \"SecurityEvent\\n| where EventID == 4688\\n| take 1\\n\"\n",
            "q",
            "SecurityEvent\n| where EventID == 4688\n| take 1\n",
        ),
        ("q: \"a  \n    b\n\n    c\"\n", "q", "a b\nc"),
        ("q: \"a \\\n    b\"\n", "q", "a b"),
        ("q:\n  \"a\n  b\"\n", "q", "a b"),
        ("q: !!str |\n  a\n", "q", "a\n"),
        ("q: |\r\n  a\r\n  b\r\n", "q", "a\nb\n"),
        ("q: >-\r\n  a\r\n  b\r\n\r\n  c\r\n", "q", "a b\nc"),
        ("q: a\r\n  b\r\n", "q", "a b"),
        ("q: >-\n  é\n  🔥 x\n", "q", "é 🔥 x"),
    ];

    fn value_at(source: &str, path: &str) -> Option<Scalar> {
        let key = mapping_keys(source)
            .into_iter()
            .find(|key| key.path.join(".") == path)?;
        scalar_at(source, key.scalar?, key.column)
    }

    #[test]
    fn scalars_decode_as_yaml_loads_them() {
        for (source, path, expected) in CASES {
            let scalar = value_at(source, path).unwrap_or_else(|| panic!("{source:?}"));
            assert_eq!(
                scalar.text.trim_end_matches('\n'),
                expected.trim_end_matches('\n'),
                "{source:?}"
            );
            assert_eq!(scalar.map.len(), scalar.text.len(), "{source:?}");
            assert!(
                scalar.map.windows(2).all(|w| w[0] < w[1]),
                "the map runs forward: {source:?} {:?}",
                scalar.map
            );
            // Every character the source spells out maps onto itself.
            for (i, c) in scalar.text.char_indices() {
                let from = source[scalar.map[i]..].chars().next().unwrap();
                if !matches!(c, ' ' | '\n') && from != '\\' {
                    assert_eq!(from, c, "{source:?} at {i}");
                }
            }
            assert!(scalar.end <= source.len(), "{source:?}");
        }
    }
}
