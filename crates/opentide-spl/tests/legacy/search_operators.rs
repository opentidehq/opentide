//! `spl_search_operator`: comparison spellings that Splunk's search syntax
//! does not have.
//!
//! A search clause compares with `=`, `!=`, `<`, `<=`, `>` and `>=`
//! (<https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search>).
//! Splunk 10.6.1 parses `==`, `<>`, `=>`, `=<` and `!~` without complaint and
//! splits them into separate terms (`status==200` becomes `status == 200`),
//! so the comparison never matches: a detection that uses one never fires.
//! In `tstats … where` the same terms fail the search at run time (`WHERE
//! clause is not an exact query`), and in `inputlookup … where` the
//! comparison is ignored, so every row passes. `=~` is `=` with a value that
//! starts with `~` (`status=~200` matches the value `~200`): it is reported as
//! a warning, because a tilde value (`~/.ssh`, `~$doc.docx`) is legitimate.
//!
//! Only search clauses are read: the first stage of a query or subsearch
//! (unless it starts with another command), `| search …`, `tstats … where …`
//! up to `by`, and `inputlookup … where …`. `eval` and `where` take `==`, and
//! quoted values, comments and macro arguments are never read. Stages are
//! found by a quote-, comment-, macro- and bracket-aware split on top-level
//! `|`, not from grammar rule names.

use super::Catalog;
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};

/// Where a search clause sits, which decides what Splunk does with the
/// operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clause {
    Search,
    Tstats,
    Inputlookup,
}

impl Clause {
    fn consequence(self) -> &'static str {
        match self {
            Clause::Search => "Splunk accepts it but the comparison never matches",
            Clause::Tstats => {
                "Splunk fails the search at run time (WHERE clause is not an exact query)"
            }
            Clause::Inputlookup => {
                "Splunk accepts it but ignores the comparison, so every row passes"
            }
        }
    }
}

/// The operators reported. An operator is read greedily from the term
/// (`!=~` is `!=` and a tilde value), so it must equal one of these exactly.
const OPERATORS: &[&str] = &["==", "<>", "=>", "=<", "!~", "=~"];

/// The search-syntax operator that does what the author meant, when there is
/// one to rewrite to.
fn replacement(op: &str) -> Option<&'static str> {
    match op {
        "==" => Some("="),
        "<>" => Some("!="),
        "=>" => Some(">="),
        "=<" => Some("<="),
        _ => None,
    }
}

pub(crate) fn collect(source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    walk(source, 0, source.len(), catalog, out);
}

fn walk(source: &str, start: usize, end: usize, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    for (index, (seg_start, seg_end)) in split_segments(source, start, end).into_iter().enumerate()
    {
        if let Some((clause, from, to)) = clause_of(source, seg_start, seg_end, index == 0, catalog)
        {
            scan(source, from, to, clause, out);
        }
        for (inner_start, inner_end) in subsearches(source, seg_start, seg_end) {
            walk(source, inner_start, inner_end, catalog, out);
        }
    }
}

/// The search clause of one stage, if it has one. `first` is the stage
/// before any `|`, which Splunk runs as `search` unless it names a command.
fn clause_of(
    source: &str,
    start: usize,
    end: usize,
    first: bool,
    catalog: &Catalog,
) -> Option<(Clause, usize, usize)> {
    if let Some((word_start, word_end)) = command_word(source, start, end) {
        let word = &source[word_start..word_end];
        if !is_field(source, word_end, end) {
            if word.eq_ignore_ascii_case("search") {
                return Some((Clause::Search, word_end, end));
            }
            if word.eq_ignore_ascii_case("tstats") {
                return where_clause(source, word_end, end, true)
                    .map(|(from, to)| (Clause::Tstats, from, to));
            }
            if word.eq_ignore_ascii_case("inputlookup") {
                return where_clause(source, word_end, end, false)
                    .map(|(from, to)| (Clause::Inputlookup, from, to));
            }
            if catalog.command(word).is_some() {
                return None;
            }
        }
    }
    first.then_some((Clause::Search, start, end))
}

/// The text after a top-level `where`, up to a top-level `by` / `groupby`
/// when `stop_at_by` (tstats), else to the end of the stage.
fn where_clause(
    source: &str,
    start: usize,
    end: usize,
    stop_at_by: bool,
) -> Option<(usize, usize)> {
    let mut words = top_level_words(source, start, end).into_iter();
    let from = words
        .by_ref()
        .find(|&(s, e)| source[s..e].eq_ignore_ascii_case("where") && !is_field(source, e, end))
        .map(|(_, e)| e)?;
    let to = if stop_at_by {
        words
            .find(|&(s, e)| {
                let w = &source[s..e];
                (w.eq_ignore_ascii_case("by") || w.eq_ignore_ascii_case("groupby"))
                    && !is_field(source, e, end)
            })
            .map_or(end, |(s, _)| s)
    } else {
        end
    };
    Some((from, to))
}

/// Words outside quotes, comments, macros, brackets and parentheses.
fn top_level_words(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut words = Vec::new();
    let mut depth = 0i32;
    let mut i = start;
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'[' | b'(' => {
                depth += 1;
                i += 1;
            }
            b']' | b')' => {
                depth = (depth - 1).max(0);
                i += 1;
            }
            c if is_word_byte(c) => {
                let word_start = i;
                while i < end && is_word_byte(bytes[i]) {
                    i += 1;
                }
                let bounded = word_start == start || !is_term_byte(bytes[word_start - 1]);
                let bounded =
                    bounded && (i >= end || !is_term_byte(bytes[i]) || is_op_byte(bytes[i]));
                if depth == 0 && bounded {
                    words.push((word_start, i));
                }
            }
            _ => i += 1,
        }
    }
    words
}

/// Reports every operator in `OPERATORS` used as a comparison in the search
/// clause `start..end`.
fn scan(source: &str, start: usize, end: usize, clause: Clause, out: &mut Vec<Diagnostic>) {
    let bytes = source.as_bytes();
    let mut i = start;
    // The previous bare term, when it can be the field of a spaced comparison
    // (`status == 200`).
    let mut field_before = false;
    let mut brackets = 0i32;
    while i < end {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if brackets == 0
            && let Some(next) = skip_hidden(source, i, end)
        {
            i = next;
            field_before = false;
            continue;
        }
        match c {
            b'[' => {
                brackets += 1;
                i += 1;
                field_before = false;
                continue;
            }
            b']' => {
                brackets = (brackets - 1).max(0);
                i += 1;
                field_before = false;
                continue;
            }
            _ if brackets > 0 => {
                // A subsearch is its own query; `walk` reads it.
                if let Some(next) = skip_hidden(source, i, end) {
                    i = next;
                } else {
                    i += 1;
                }
                continue;
            }
            b'(' | b')' | b',' => {
                i += 1;
                field_before = false;
                continue;
            }
            _ => {}
        }
        let term_start = i;
        while i < end && is_term_byte(bytes[i]) {
            i += 1;
        }
        if i == term_start {
            // A byte that cannot start a term: a stray `|`.
            i += 1;
            field_before = false;
            continue;
        }
        let term_end = i;
        field_before = check_term(source, term_start, term_end, end, field_before, clause, out);
    }
}

/// Checks one bare term and returns whether it can be the field of a spaced
/// comparison that follows it.
fn check_term(
    source: &str,
    start: usize,
    end: usize,
    clause_end: usize,
    field_before: bool,
    clause: Clause,
    out: &mut Vec<Diagnostic>,
) -> bool {
    let bytes = source.as_bytes();
    let Some(op_start) = (start..end).find(|&j| is_op_byte(bytes[j])) else {
        let term = &source[start..end];
        return is_field_name(term) && !matches!(term, "AND" | "OR" | "NOT" | "IN" | "XOR");
    };
    let mut op_end = op_start;
    while op_end < end && (is_op_byte(bytes[op_end]) || bytes[op_end] == b'~') {
        op_end += 1;
    }
    let op = &source[op_start..op_end];
    if !OPERATORS.contains(&op) {
        return false;
    }
    let reported = if op_start == start {
        // `status == 200`, `status ==200`: the field is the term before.
        field_before
    } else {
        // `status==200`, `status=="200"`. A term with nothing after the
        // operator (`dGVzdA==`, base64 padding) is a keyword, not a
        // comparison.
        let has_value =
            op_end < end || (op_end < clause_end && matches!(bytes[op_end], b'"' | b'\'' | b'`'));
        is_field_name(&source[start..op_start]) && has_value
    };
    if reported {
        push(out, source, op, clause, op_start, op_end);
    }
    false
}

fn push(
    out: &mut Vec<Diagnostic>,
    source: &str,
    op: &str,
    clause: Clause,
    start: usize,
    end: usize,
) {
    let range = span_to_range(source, ByteSpan::new(start, end));
    let diagnostic = match (op, replacement(op)) {
        ("=~", _) => Diagnostic::warning(
            codes::SPL_SEARCH_OPERATOR,
            "'=~' is not a regex match in a search clause: Splunk reads it as '=' and a value that starts with '~'; use match() in a where command for a regular expression, or quote the value (\"~...\") if the tilde is part of it",
            range,
        ),
        (_, Some(fix)) => Diagnostic::error(
            codes::SPL_SEARCH_OPERATOR,
            format!(
                "'{op}' is not a search operator: {}; use '{fix}'",
                clause.consequence()
            ),
            range,
        )
        .with_suggestion(fix),
        (_, None) => Diagnostic::error(
            codes::SPL_SEARCH_OPERATOR,
            format!(
                "'{op}' is not a search operator: {}; use NOT match() in a where command for a regular expression",
                clause.consequence()
            ),
            range,
        ),
    };
    out.push(diagnostic);
}

/// A field name: starts with a letter, digit or `_`, and holds no operator.
fn is_field_name(text: &str) -> bool {
    text.as_bytes()
        .first()
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !text.bytes().any(|c| is_op_byte(c) || c == b'*')
}

fn is_op_byte(c: u8) -> bool {
    matches!(c, b'=' | b'!' | b'<' | b'>')
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Bytes a bare search term is made of: everything but whitespace, quotes,
/// macros, brackets, parentheses, commas and the pipe.
fn is_term_byte(c: u8) -> bool {
    !c.is_ascii_whitespace()
        && !matches!(
            c,
            b'(' | b')' | b'[' | b']' | b',' | b'|' | b'"' | b'\'' | b'`'
        )
}

/// The command word at the start of a stage, after whitespace and comments.
fn command_word(source: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let i = skip_ws_and_comments(source, start, end);
    if i >= end || !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
        return None;
    }
    let mut j = i + 1;
    while j < end && is_word_byte(bytes[j]) {
        j += 1;
    }
    Some((i, j))
}

/// Whether the word ending at `at` is a field (`stats=1`), not a command.
fn is_field(source: &str, at: usize, end: usize) -> bool {
    let i = skip_ws_and_comments(source, at, end);
    i < end && is_op_byte(source.as_bytes()[i])
}

/// Splits `start..end` on `|` outside quotes, comments, macros and brackets.
/// Parentheses do not hide a pipe: Splunk splits
/// `index=a TERM("x" | eval y=1` into two stages and runs it.
fn split_segments(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut seg_start = start;
    let mut depth = 0i32;
    let mut segs = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'|' if depth == 0 => {
                segs.push((seg_start, i));
                seg_start = i + 1;
            }
            b'[' => depth += 1,
            b']' => depth = (depth - 1).max(0),
            _ => {}
        }
        i += 1;
    }
    if seg_start < end {
        segs.push((seg_start, end));
    }
    segs
}

/// The insides of top-level `[ … ]` subsearches in `start..end`.
fn subsearches(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut depth = 0i32;
    let mut inner_start = 0;
    let mut out = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        if bytes[i] == b'[' {
            if depth == 0 {
                inner_start = i + 1;
            }
            depth += 1;
        } else if bytes[i] == b']' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                out.push((inner_start, i));
            }
        }
        i += 1;
    }
    out
}

/// The end of a comment, quoted string or macro starting at `i`.
fn skip_hidden(source: &str, i: usize, end: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if i >= end {
        return None;
    }
    if bytes[i..end].starts_with(b"```") {
        let close = source[i + 3..end]
            .find("```")
            .map_or(end, |at| i + 3 + at + 3);
        return Some(close);
    }
    match bytes[i] {
        b'"' | b'\'' => {
            let quote = bytes[i];
            let mut j = i + 1;
            while j < end {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == quote {
                    return Some(j + 1);
                }
                j += 1;
            }
            Some(end)
        }
        b'`' => Some(
            source[i + 1..end]
                .find('`')
                .map_or(end, |at| i + 1 + at + 1),
        ),
        _ => None,
    }
}

fn skip_ws_and_comments(source: &str, mut i: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while i < end && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < end
            && bytes[i..end].starts_with(b"```")
            && let Some(next) = skip_hidden(source, i, end)
        {
            i = next;
            continue;
        }
        return i;
    }
}
