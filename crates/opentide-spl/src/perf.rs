//! Warnings for public slow or silently truncated SPL shapes.
//!
//! Wildcard guidance: <https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search>
//! Leading NOT: <https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions>
//! Subsearch limits (50,000 events / 60 seconds, silent truncation):
//! <https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches>
//!
//! The query text is not rewritten.

use super::Catalog;
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};

const WILDCARD_CITE: &str =
    "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search";
const NOT_CITE: &str =
    "https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions";
const SUBSEARCH_CITE: &str =
    "https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches";
const TRANSACTION_CITE: &str =
    "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Transaction";

pub(crate) fn collect(source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    if source.is_empty() {
        return;
    }
    walk_pipeline(source, 0, source.len(), catalog, out);
}

fn walk_pipeline(
    source: &str,
    start: usize,
    end: usize,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    for (seg_start, seg_end) in split_segments(source, start, end) {
        if seg_start >= seg_end {
            continue;
        }
        let (word, word_span) = command_word(source, seg_start, seg_end);
        if let Some((cmd_start, cmd_end)) = word_span {
            if let Some(message) = truncation_message(&word) {
                push(
                    out,
                    source,
                    codes::SPL_SUBSEARCH_TRUNCATION,
                    message,
                    cmd_start,
                    cmd_end,
                );
            }
        }
        if is_search_context(&word, catalog) {
            scan_search(source, seg_start, seg_end, out);
        }
        for (inner_start, inner_end) in subsearches(source, seg_start, seg_end) {
            walk_pipeline(source, inner_start, inner_end, catalog, out);
        }
    }
}

fn truncation_message(word: &str) -> Option<String> {
    match word.to_ascii_lowercase().as_str() {
        "join" | "append" => Some(format!(
            "`{word}` silently truncates at 50,000 events or 60 seconds without an error ({SUBSEARCH_CITE})"
        )),
        // `transaction` is not a subsearch. Its limit is open transactions, not
        // the 50,000-event / 60-second subsearch cap.
        "transaction" => Some(format!(
            "`transaction` holds events in memory until the group closes and drops events past maxopentxn ({TRANSACTION_CITE})"
        )),
        _ => None,
    }
}

fn is_truncating(word: &str) -> bool {
    truncation_message(word).is_some()
}

fn is_search_context(word: &str, catalog: &Catalog) -> bool {
    if word.is_empty() || word.eq_ignore_ascii_case("search") {
        return true;
    }
    if is_truncating(word) {
        return false;
    }
    catalog.command(word).is_none()
}

fn split_segments(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut seg_start = start;
    let mut brackets = 0i32;
    let mut parens = 0i32;
    let mut segs = Vec::new();
    while i < end {
        if let Some(next) = skip_hidden(source, i, end) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'|' if brackets == 0 && parens == 0 => {
                segs.push((seg_start, i));
                i += 1;
                seg_start = i;
            }
            b'[' => {
                brackets += 1;
                i += 1;
            }
            b']' => {
                if brackets > 0 {
                    brackets -= 1;
                }
                i += 1;
            }
            b'(' => {
                parens += 1;
                i += 1;
            }
            b')' => {
                if parens > 0 {
                    parens -= 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    if seg_start < end {
        segs.push((seg_start, end));
    }
    segs
}

fn command_word(source: &str, start: usize, end: usize) -> (String, Option<(usize, usize)>) {
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

fn scan_search(source: &str, start: usize, end: usize, out: &mut Vec<Diagnostic>) {
    if let Some((not_start, not_end)) = leading_not_span(source, start, end) {
        push(
            out,
            source,
            codes::SPL_LEADING_NOT,
            format!(
                "leading `NOT` used as the search filter scans events before excluding them ({NOT_CITE})"
            ),
            not_start,
            not_end,
        );
    }
    for (wild_start, wild_end) in wildcard_spans(source, start, end) {
        let value = &source[wild_start..wild_end];
        push(
            out,
            source,
            codes::SPL_WILDCARD,
            wildcard_message(value),
            wild_start,
            wild_end,
        );
    }
}

fn wildcard_message(value: &str) -> String {
    if value.chars().all(|c| c == '*') {
        format!("bare `*` matches every event and forces a full scan ({WILDCARD_CITE})")
    } else if value.starts_with('*') {
        format!(
            "leading wildcard `{value}` cannot use the term index; a trailing `fail*` is fine ({WILDCARD_CITE})"
        )
    } else {
        format!(
            "mid-token wildcard `{value}` cannot use the term index; a trailing `fail*` is fine ({WILDCARD_CITE})"
        )
    }
}

fn leading_not_span(source: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = skip_ws_and_comments(source, start, end);
    while i < end && bytes[i] == b'(' {
        i += 1;
        i = skip_ws_and_comments(source, i, end);
    }
    let (word_start, word_end) = read_word(source, i, end)?;
    let mut i = word_end;
    if source[word_start..word_end].eq_ignore_ascii_case("search") {
        i = skip_ws_and_comments(source, i, end);
        while i < end && bytes[i] == b'(' {
            i += 1;
            i = skip_ws_and_comments(source, i, end);
        }
        let (word_start, word_end) = read_word(source, i, end)?;
        if source[word_start..word_end].eq_ignore_ascii_case("not") {
            return Some((word_start, word_end));
        }
        return None;
    }
    if source[word_start..word_end].eq_ignore_ascii_case("not") {
        Some((word_start, word_end))
    } else {
        None
    }
}

fn wildcard_spans(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut brackets = 0i32;
    let mut out = Vec::new();
    while i < end {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            continue;
        }
        if brackets == 0 && bytes[i] == b'`' {
            i = end_of_macro(bytes, i, end);
            continue;
        }
        if bytes[i] == b'[' {
            brackets += 1;
            i += 1;
            continue;
        }
        if bytes[i] == b']' {
            if brackets > 0 {
                brackets -= 1;
            }
            i += 1;
            continue;
        }
        if brackets > 0 {
            i += 1;
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let next = end_quoted(bytes, i, end);
            consider_term(source, i, next, &mut out);
            i = next;
            continue;
        }
        if matches!(bytes[i], b'(' | b')' | b',' | b'|' | b'[' | b']') {
            i += 1;
            continue;
        }
        let term_start = i;
        while i < end {
            let c = bytes[i];
            if c.is_ascii_whitespace()
                || matches!(
                    c,
                    b'(' | b')' | b'[' | b']' | b',' | b'|' | b'"' | b'\'' | b'`'
                )
            {
                break;
            }
            i += 1;
        }
        consider_term(source, term_start, i, &mut out);
    }
    out
}

fn consider_term(source: &str, start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    if start >= end {
        return;
    }
    let term = &source[start..end];
    let pieces: Vec<(&str, usize)> = if term.starts_with('"') || term.starts_with('\'') {
        let (inner, rel) = strip_quotes(term);
        vec![(inner, rel)]
    } else if let Some(eq) = term.find('=') {
        // `process=*fail` is a leading wildcard on the value, not a mid-token
        // wildcard on the whole field=value token.
        vec![(&term[..eq], 0), (&term[eq + 1..], eq + 1)]
    } else {
        vec![(term, 0)]
    };
    for (value, value_rel) in pieces {
        if value.is_empty() || !is_inefficient_wildcard(value) {
            continue;
        }
        let value_start = start + value_rel;
        let value_end = value_start + value.len();
        if value_end <= source.len()
            && !out
                .iter()
                .any(|(s, e)| *s == value_start && *e == value_end)
        {
            out.push((value_start, value_end));
        }
    }
}

fn strip_quotes(term: &str) -> (&str, usize) {
    let bytes = term.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        (&term[1..term.len() - 1], 1)
    } else {
        (term, 0)
    }
}

fn is_inefficient_wildcard(value: &str) -> bool {
    if !value.contains('*') {
        return false;
    }
    if value.chars().all(|c| c == '*') || value.starts_with('*') {
        return true;
    }
    match value.find('*') {
        Some(idx) if value[idx..].chars().all(|c| c == '*') => false,
        Some(_) => true,
        None => false,
    }
}

fn subsearches(source: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
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

fn skip_hidden(source: &str, i: usize, end: usize) -> Option<usize> {
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

fn skip_comment(source: &str, i: usize, end: usize) -> Option<usize> {
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

fn skip_ws_and_comments(source: &str, mut i: usize, end: usize) -> usize {
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

fn read_word(source: &str, i: usize, end: usize) -> Option<(usize, usize)> {
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

fn end_quoted(bytes: &[u8], start: usize, end: usize) -> usize {
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

fn end_of_macro(bytes: &[u8], start: usize, end: usize) -> usize {
    let mut i = start + 1;
    while i < end && bytes[i] != b'`' {
        i += 1;
    }
    (i + 1).min(end)
}

fn push(
    out: &mut Vec<Diagnostic>,
    source: &str,
    code: &str,
    message: String,
    start: usize,
    end: usize,
) {
    let start = start.min(source.len());
    let end = end.min(source.len()).max(start);
    if start >= end {
        return;
    }
    let range = span_to_range(source, ByteSpan::new(start, end));
    if out
        .iter()
        .any(|diag| diag.code == code && diag.range == range)
    {
        return;
    }
    out.push(Diagnostic::warning(code, message, range));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use opentide_core::{Severity, codes};

    fn warnings(src: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect()
    }

    fn has(src: &str, code: &str) -> bool {
        warnings(src).iter().any(|d| d.code == code)
    }

    #[test]
    fn wildcards_warn_except_trailing() {
        for src in [
            "index=main *fail",
            "index=main f*il",
            "index=main *",
            "search *fail",
        ] {
            let found = warnings(src)
                .into_iter()
                .find(|d| d.code == codes::SPL_WILDCARD)
                .unwrap_or_else(|| panic!("missing wildcard warning for {src}"));
            assert_eq!(found.severity, Severity::Warning);
            assert!(found.message.contains(WILDCARD_CITE), "{}", found.message);
            assert!(
                found.range.end.character > found.range.start.character
                    || found.range.end.line > found.range.start.line
            );
        }
        assert!(!has("index=main process=fail*", codes::SPL_WILDCARD));
        assert!(!has("index=main host=webserver*", codes::SPL_WILDCARD));
        let leading_value = warnings("index=main process=*fail");
        let wild = leading_value
            .iter()
            .filter(|d| d.code == codes::SPL_WILDCARD)
            .collect::<Vec<_>>();
        assert_eq!(wild.len(), 1, "{leading_value:?}");
        assert!(
            wild[0].message.contains("leading wildcard"),
            "{}",
            wild[0].message
        );
        let clean = analyze("index=main process=fail* | stats count by host");
        assert!(
            !clean
                .diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_PARSE_ERROR || d.code == codes::SPL_WILDCARD),
            "{:?}",
            clean.diagnostics
        );
    }

    #[test]
    fn leading_not_is_the_search_filter() {
        let src = "search NOT status=200";
        let found = warnings(src)
            .into_iter()
            .find(|d| d.code == codes::SPL_LEADING_NOT)
            .expect("leading not");
        assert!(found.message.contains(NOT_CITE));
        assert_eq!(found.severity, Severity::Warning);
        assert!(!has("index=main NOT status=200", codes::SPL_LEADING_NOT));
        assert!(!has(
            "index=main | where NOT status=200",
            codes::SPL_LEADING_NOT
        ));
    }

    #[test]
    fn join_append_transaction_mention_silent_truncation() {
        for src in [
            "index=main | join host [ search index=other ]",
            "index=main | append [ search index=other ]",
        ] {
            let found = warnings(src)
                .into_iter()
                .find(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION)
                .unwrap_or_else(|| panic!("missing truncation warning for {src}"));
            assert!(found.message.contains("50,000"));
            assert!(found.message.contains("60 seconds"));
            assert!(found.message.contains("silently truncat"));
            assert!(found.message.contains(SUBSEARCH_CITE));
            assert!(
                !found.message.contains("| stats"),
                "{src} must not rewrite the query"
            );
        }
        let txn = warnings("index=main | transaction user")
            .into_iter()
            .find(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION)
            .expect("transaction warning");
        assert!(txn.message.contains("maxopentxn"), "{}", txn.message);
        assert!(txn.message.contains(TRANSACTION_CITE));
        assert!(!txn.message.contains("50,000"));
        assert!(!has(
            "index=main | appendcols [ search index=other ]",
            codes::SPL_SUBSEARCH_TRUNCATION
        ));
    }

    #[test]
    fn ordinary_search_has_no_perf_warning() {
        let src = "index=main | stats count by host | head 1";
        assert!(warnings(src).is_empty(), "{:?}", warnings(src));
        let eval = analyze("index=main | eval x = 1 * 2");
        assert!(
            !eval
                .diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_PARSE_ERROR || d.code == codes::SPL_WILDCARD),
            "multiplication must stay an operator: {:?}",
            eval.diagnostics
        );
    }
}
