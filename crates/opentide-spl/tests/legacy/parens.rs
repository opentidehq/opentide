//! A precise `spl_parse_error` message for unbalanced parentheses, which
//! Splunk rejects with "unbalanced parentheses" (opentidehq/language-server#135).
//!
//! The parser reports where it got stuck; this pass only rewrites that
//! diagnostic when the text has a `)` with no `(` or a `(` that is never
//! closed. It scans the text, not the tree, so it does not depend on how the
//! parse errors are positioned.

use opentide_core::{ByteSpan, Diagnostic, Range, codes, span_to_range};

/// Rewrite the syntax error that a stray `)` or an unclosed `(` caused.
pub(crate) fn refine(source: &str, diagnostics: &mut [Diagnostic]) {
    let Some((span, message)) = unbalanced(source) else {
        return;
    };
    let range = span_to_range(source, span);
    let parse_errors = || {
        diagnostics
            .iter()
            .enumerate()
            .filter(|(_, d)| d.code == codes::SPL_PARSE_ERROR)
    };
    // The error reported at the parenthesis itself, else the one around it.
    let target = parse_errors()
        .find(|(_, d)| d.range.start == range.start)
        .or_else(|| parse_errors().find(|(_, d)| covers(d.range, range)))
        .map(|(i, _)| i);
    if let Some(i) = target {
        diagnostics[i].message = message.to_string();
        diagnostics[i].range = range;
    }
}

fn covers(outer: Range, inner: Range) -> bool {
    let key = |p: opentide_core::Position| (p.line, p.character);
    key(outer.start) <= key(inner.start) && key(inner.end) <= key(outer.end)
}

/// The first `)` with no matching `(`, else the last `(` left open. Quoted
/// strings, comments, macros and the raw contents of `TERM(`, `CASE(` and
/// `PREFIX(` (which Splunk lets stay open) do not count.
fn unbalanced(source: &str) -> Option<(ByteSpan, &'static str)> {
    let bytes = source.as_bytes();
    // Each open `(` with the subsearch depth it was opened at.
    let mut open: Vec<(usize, usize)> = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            // Splunk ends a stage at `|` whatever parentheses are open
            // (`TERM("x" | eval ...`), but not inside a subsearch's `[ ]`.
            b'|' => {
                if let Some(&(at, _)) = open.last().filter(|(_, d)| *d == depth) {
                    return Some(unclosed(at));
                }
                i += 1;
            }
            b'`' if source[i..].starts_with("```") => {
                let run = bytes[i..].iter().take_while(|&&b| b == b'`').count();
                i += run;
                i = match source[i..].find("```") {
                    Some(end) => {
                        let close = i + end;
                        close + bytes[close..].iter().take_while(|&&b| b == b'`').count()
                    }
                    None => bytes.len(),
                };
            }
            b'`' => {
                i = source[i + 1..]
                    .find('`')
                    .map_or(bytes.len(), |end| i + 1 + end + 1);
            }
            b'"' => i = end_of_string(bytes, i, b'"'),
            b'\'' if at_token_start(bytes, i) => i = end_of_string(bytes, i, b'\''),
            b'(' => {
                if directive_before(source, i) {
                    i = end_of_directive(bytes, i + 1);
                } else {
                    open.push((i, depth));
                    i += 1;
                }
            }
            b')' => {
                if open.pop().is_none() {
                    return Some((
                        ByteSpan::new(i, i + 1),
                        "unbalanced parentheses: this ')' has no matching '('",
                    ));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    open.pop().map(|(at, _)| unclosed(at))
}

fn unclosed(at: usize) -> (ByteSpan, &'static str) {
    (
        ByteSpan::new(at, at + 1),
        "unbalanced parentheses: this '(' is never closed",
    )
}

fn end_of_string(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// A `'` opens a string only where a token starts (`'a b'`), not inside a
/// word (`don't`).
fn at_token_start(bytes: &[u8], i: usize) -> bool {
    i == 0
        || matches!(
            bytes[i - 1],
            b' ' | b'\t' | b'\n' | b'\r' | b'=' | b'(' | b',' | b'['
        )
}

/// `TERM(`, `CASE(` or `PREFIX(` right before the `(` at `paren`.
fn directive_before(source: &str, paren: usize) -> bool {
    let head = &source[..paren];
    ["TERM", "CASE", "PREFIX"].iter().any(|name| {
        head.ends_with(name) && {
            let before = head.len() - name.len();
            before == 0 || !is_word_byte(source.as_bytes()[before - 1])
        }
    })
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

/// The raw contents of a directive, as the grammar's `term_text`: up to the
/// closing `)` (consumed), or to whitespace or a `|` when it is left open.
fn end_of_directive(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b')' => return i + 1,
            b'"' => i = end_of_string(bytes, i, b'"'),
            b'|' => return i,
            b if b.is_ascii_whitespace() => return i,
            _ => i += 1,
        }
    }
    i
}
