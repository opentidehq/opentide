//! Lexical helpers the SPL checks share: pipeline segments, subsearches,
//! comments, quoted strings and macros. They work on byte offsets into the
//! authored text and never rewrite it.

use super::Catalog;

pub(crate) fn split_segments(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut seg_start = start;
    let mut brackets = 0i32;
    let mut segs = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            // Parentheses are not counted: Splunk splits on `|` inside them.
            b'|' if brackets == 0 => {
                segs.push((seg_start, i));
                seg_start = i + 1;
            }
            b'[' => brackets += 1,
            b']' if brackets > 0 => brackets -= 1,
            _ => {}
        }
        i += 1;
    }
    if seg_start < end {
        segs.push((seg_start, end));
    }
    segs
}

pub(crate) fn command_word(
    source: &str,
    start: usize,
    end: usize,
) -> (String, Option<(usize, usize)>) {
    let bytes = source.as_bytes();
    let mut i = start;
    while i < end && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= end {
        return (String::new(), None);
    }
    let c = bytes[i];
    if !(c.is_ascii_alphabetic() || c == b'_') {
        return (String::new(), None);
    }
    let word_start = i;
    i += 1;
    while i < end && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (source[word_start..i].to_string(), Some((word_start, i)))
}

pub(crate) fn subsearches(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut depth = 0i32;
    let mut inner_start = None;
    let mut out = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        if bytes[i] == b'[' {
            if depth == 0 {
                inner_start = Some(i + 1);
            }
            depth += 1;
        } else if bytes[i] == b']' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                if let Some(open) = inner_start.take() {
                    out.push((open, i));
                }
            }
        }
        i += 1;
    }
    out
}

pub(crate) fn skip_hidden(source: &str, i: usize, end: usize) -> Option<usize> {
    if let Some(next) = skip_comment(source, i, end) {
        return Some(next);
    }
    let bytes = source.as_bytes();
    if i >= end {
        return None;
    }
    if bytes[i] == b'"' || bytes[i] == b'\'' {
        return Some(end_quoted(bytes, i, end));
    }
    if bytes[i] == b'`' {
        return Some(end_of_macro(bytes, i, end));
    }
    None
}

pub(crate) fn skip_comment(source: &str, i: usize, end: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if i + 3 <= end && &bytes[i..i + 3] == b"```" {
        let mut j = i + 3;
        while j + 3 <= end && &bytes[j..j + 3] != b"```" {
            j += 1;
        }
        return Some((j + 3).min(end));
    }
    None
}

pub(crate) fn skip_ws_and_comments(source: &str, mut i: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while i < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            continue;
        }
        break;
    }
    i
}

pub(crate) fn read_word(source: &str, i: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    if i >= end || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        return None;
    }
    let mut j = i + 1;
    while j < end && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
        j += 1;
    }
    Some((i, j))
}

pub(crate) fn end_quoted(bytes: &[u8], start: usize, end: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < end {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return (i + 1).min(end);
        }
        i += 1;
    }
    end
}

pub(crate) fn end_of_macro(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut i = start + 1;
    while i < end && bytes[i] != b'`' {
        i += 1;
    }
    (i + 1).min(end)
}

/// The end of the `[ ... ]` subsearch that opens at `start` (past its `]`).
pub(crate) fn end_of_brackets(source: &str, start: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    end
}

pub(crate) fn skip_ws(bytes: &[u8], mut i: usize, end: usize) -> usize {
    while i < end && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The stage that reads the index: the first stage when the pipeline does
/// not start with `|` (Splunk runs it as `search`), or a leading
/// `| search ...`. A leading `| tstats`, `| inputlookup` and the like read no
/// raw events, and every later stage filters results already in the pipeline.
pub(crate) fn base_search(
    source: &str,
    segments: &[(usize, usize)],
    catalog: &Catalog,
) -> Option<(usize, usize)> {
    let blank = |&(s, e): &(usize, usize)| skip_ws_and_comments(source, s, e) >= e;
    let first = *segments.first()?;
    if !blank(&first) {
        let (word, span) = command_word(source, first.0, first.1);
        let is_command = span.is_some_and(|(_, word_end)| {
            catalog.command(&word).is_some() && !is_field(source, word_end, first.1)
        });
        return (!is_command || word.eq_ignore_ascii_case("search")).then_some(first);
    }
    // A leading `|`: only an explicit `search` reads the index.
    let second = *segments.get(1)?;
    let (word, _) = command_word(source, second.0, second.1);
    word.eq_ignore_ascii_case("search").then_some(second)
}

/// Whether the word ending at `at` is a field (`stats=1`), not a command.
pub(crate) fn is_field(source: &str, at: usize, end: usize) -> bool {
    let i = skip_ws_and_comments(source, at, end);
    matches!(source.as_bytes().get(i), Some(b'=' | b'!' | b'<' | b'>'))
}
