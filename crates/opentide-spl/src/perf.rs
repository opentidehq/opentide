//! Warnings for public slow or silently truncated SPL shapes.
//!
//! Wildcard guidance: <https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search>
//! Leading NOT: <https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions>
//! Subsearch limits (50,000 events / 60 seconds, silent truncation):
//! <https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsubsearches>
//!
//! `spl_wildcard` and `spl_leading_not` describe the cost of reading the
//! index, which only a base search pays: the first stage of the query or of a
//! subsearch. A later `| search` filters results already in the pipeline.
//! Stages are found by splitting on top-level `|` (outside quotes, comments,
//! macros and subsearch brackets), not from grammar rule names. Parentheses do
//! not hide a `|`: Splunk splits `index=a TERM("x" | stats count` into two
//! stages, so an unclosed `(` must not pull later stages into the base search.
//!
//! The query text is not rewritten.

use super::Catalog;
use super::scan::{
    base_search, command_word, end_of_macro, end_quoted, read_word, skip_comment,
    skip_ws_and_comments, split_segments, subsearches,
};
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
    let segments = split_segments(source, start, end);
    if let Some((base_start, base_end)) = base_search(source, &segments, catalog) {
        scan_search(source, base_start, base_end, out);
    }
    for &(seg_start, seg_end) in &segments {
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
    let terms = search_terms(source, start, end);
    // `index=`, `sourcetype=`, `TERM()` or a macro already narrow the read,
    // so a wildcard on another term costs little (`src_user!="*$"`).
    if has_indexed_constraint(source, &terms) {
        return;
    }
    for term in &terms {
        for (wild_start, wild_end) in wildcard_spans(source, term) {
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

/// A search term outside subsearches: a word (`field=value`, with a quoted
/// value when one follows `=`), a quoted phrase, or a macro call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Term {
    start: usize,
    end: usize,
    kind: TermKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermKind {
    Word,
    Quoted,
    Macro,
}

fn search_terms(source: &str, start: usize, end: usize) -> Vec<Term> {
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
        if bytes[i] == b'`' {
            let next = end_of_macro(bytes, i, end);
            if brackets == 0 {
                out.push(Term {
                    start: i,
                    end: next,
                    kind: TermKind::Macro,
                });
            }
            i = next;
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
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                i = end_quoted(bytes, i, end);
            } else {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let next = end_quoted(bytes, i, end);
            out.push(Term {
                start: i,
                end: next,
                kind: TermKind::Quoted,
            });
            i = next;
            continue;
        }
        if matches!(bytes[i], b'(' | b')' | b',' | b'|') {
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
        // `field="value"` is one term.
        if i < end && bytes[i - 1] == b'=' && (bytes[i] == b'"' || bytes[i] == b'\'') {
            i = end_quoted(bytes, i, end);
        }
        out.push(Term {
            start: term_start,
            end: i,
            kind: TermKind::Word,
        });
    }
    out
}

/// Fields Splunk indexes for every event, so a value narrows the read.
const INDEXED_FIELDS: &[&str] = &["index", "sourcetype", "source", "host"];

/// `index=a`, `sourcetype IN (...)`, `TERM(...)`, `PREFIX(...)` or a macro,
/// which usually expands to an index and sourcetype. `index=*` and a value
/// with a leading wildcard narrow nothing.
fn has_indexed_constraint(source: &str, terms: &[Term]) -> bool {
    terms.iter().enumerate().any(|(n, term)| {
        let text = &source[term.start..term.end];
        match term.kind {
            TermKind::Macro => true,
            TermKind::Quoted => false,
            TermKind::Word => {
                let indexed =
                    |name: &str| INDEXED_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(name));
                if let Some((field, value)) = text.split_once('=') {
                    let value = strip_quotes(value).0;
                    return indexed(field) && !value.is_empty() && !value.starts_with('*');
                }
                if (text.eq_ignore_ascii_case("TERM") || text.eq_ignore_ascii_case("PREFIX"))
                    && source[term.end..].starts_with('(')
                {
                    return true;
                }
                indexed(text)
                    && terms.get(n + 1).is_some_and(|next| {
                        next.kind == TermKind::Word
                            && source[next.start..next.end].eq_ignore_ascii_case("IN")
                    })
            }
        }
    })
}

/// Wildcards in a term that cannot use the term index. `field=*` and
/// `field="*"` are the existence check, not a scan of every event.
fn wildcard_spans(source: &str, term: &Term) -> Vec<(usize, usize)> {
    let text = &source[term.start..term.end];
    let pieces: Vec<(&str, usize)> = match term.kind {
        TermKind::Macro => Vec::new(),
        TermKind::Quoted => {
            let (inner, rel) = strip_quotes(text);
            vec![(inner, rel)]
        }
        TermKind::Word => match text.find('=') {
            // `process=*fail` is a leading wildcard on the value, not a
            // mid-token wildcard on the whole field=value token.
            Some(eq) => {
                let (value, rel) = strip_quotes(&text[eq + 1..]);
                let value_piece =
                    (!value.chars().all(|c| c == '*')).then_some((value, eq + 1 + rel));
                std::iter::once((&text[..eq], 0))
                    .chain(value_piece)
                    .collect()
            }
            None => vec![(text, 0)],
        },
    };
    pieces
        .into_iter()
        .filter(|(value, _)| !value.is_empty() && is_inefficient_wildcard(value))
        .map(|(value, rel)| (term.start + rel, term.start + rel + value.len()))
        .collect()
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

    fn count(src: &str, code: &str) -> usize {
        warnings(src).iter().filter(|d| d.code == code).count()
    }

    #[test]
    fn wildcards_warn_in_an_unconstrained_base_search() {
        for src in [
            "*fail",
            "f*il",
            "*",
            "search *fail",
            "| search *fail",
            "index=* *foo*",
            "index=\"*\" *foo*",
            "sourcetype=*sysmon user=x",
            "eventtype=x \"*fail\"",
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
        assert!(!has("process=fail*", codes::SPL_WILDCARD));
        assert!(!has("host=webserver*", codes::SPL_WILDCARD));
        let leading_value = warnings("process=*fail");
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
    fn field_star_is_the_existence_check() {
        for src in [
            "api_key_name=*",
            "description.acknowledged=\"*\"",
            "user=* src!=*",
            "index=a api_key_name=*",
        ] {
            assert_eq!(
                count(src, codes::SPL_WILDCARD),
                0,
                "{src}: {:?}",
                warnings(src)
            );
        }
        // A bare `*` term is still every event.
        assert_eq!(count("user=* *", codes::SPL_WILDCARD), 1);
    }

    #[test]
    fn an_indexed_constraint_covers_wildcards_on_other_terms() {
        for src in [
            "index=a sourcetype=b TERM(EventID=4688) src_user!=\"*$\"",
            "index=a *foo*",
            "INDEX=a *foo*",
            "sourcetype=b user=*adm*",
            "source=\"/var/log/x\" *foo*",
            "host=web* *foo*",
            "`m` description=\"*x\"",
            "TERM(10.0.0.1) *foo*",
            "PREFIX(user=) *foo*",
            "index IN (a, b) *foo*",
            "(index=a OR index=b) *foo*",
            "search index=a *foo*",
            "index=a *",
        ] {
            assert_eq!(
                count(src, codes::SPL_WILDCARD),
                0,
                "{src}: {:?}",
                warnings(src)
            );
        }
        // A constraint in a subsearch does not narrow the outer search.
        assert_eq!(
            count(
                "*foo* [ search index=a | fields user ]",
                codes::SPL_WILDCARD
            ),
            1
        );
    }

    #[test]
    fn later_stages_are_not_scanned() {
        for src in [
            "index=a | spath | search valueExtracted=\"*@*.*\"",
            "index=a sourcetype=b | stats count by user, outcome | search NOT outcome=\"Failure\"",
            "| tstats count where index=a by user | search user=*adm*",
            "| inputlookup t.csv | search NOT user=x",
            "* | search *foo*",
            "index=a | where NOT status=200",
        ] {
            let found: Vec<_> = warnings(src)
                .into_iter()
                .filter(|d| d.code == codes::SPL_WILDCARD || d.code == codes::SPL_LEADING_NOT)
                .collect();
            let expected = usize::from(src.starts_with("* "));
            assert_eq!(found.len(), expected, "{src}: {found:?}");
        }
    }

    #[test]
    fn an_unclosed_paren_does_not_swallow_later_stages() {
        // Splunk 10.6 splits on `|` regardless of parentheses.
        let src = r#"index=a TERM("x" | search NOT x=1 | search y=*z"#;
        assert!(warnings(src).is_empty(), "{:?}", warnings(src));
        // Not covered by a constraint: the later `y=*z` must still be skipped.
        let src = "index=* (x=1 | search NOT x=1 | search y=*z";
        assert!(warnings(src).is_empty(), "{:?}", warnings(src));
        let src = "| search (x=1 | search NOT x=1 | search y=*z";
        assert!(warnings(src).is_empty(), "{:?}", warnings(src));
        // The base search before the `|` is still scanned.
        assert_eq!(count("index=* (*foo | search y=*z", codes::SPL_WILDCARD), 1);
        // And a later `join` is still found.
        assert!(has(
            "index=a (x=1 | join d [search index=b]",
            codes::SPL_SUBSEARCH_TRUNCATION
        ));
        // In a subsearch, the bracket still bounds the stages.
        let src = "index=a [search index=* (c=1 | search NOT x=1 | search e=*f] | stats count";
        assert!(warnings(src).is_empty(), "{:?}", warnings(src));
    }

    #[test]
    fn a_subsearch_has_its_own_base_search() {
        assert_eq!(
            count("index=a | join k [ search *foo* ]", codes::SPL_WILDCARD),
            1
        );
        assert_eq!(
            count(
                "index=a | join k [ search index=b *foo* ]",
                codes::SPL_WILDCARD
            ),
            0
        );
        assert_eq!(
            count(
                "index=a | join k [ search NOT x=1 ]",
                codes::SPL_LEADING_NOT
            ),
            1
        );
        assert_eq!(
            count(
                "index=a [ | inputlookup t.csv | search NOT x=1 | fields user ]",
                codes::SPL_LEADING_NOT
            ),
            0
        );
    }

    #[test]
    fn leading_not_is_the_search_filter() {
        for src in [
            "search NOT status=200",
            "NOT status=200",
            "| search NOT status=200",
        ] {
            let found = warnings(src)
                .into_iter()
                .find(|d| d.code == codes::SPL_LEADING_NOT)
                .unwrap_or_else(|| panic!("leading not in {src}"));
            assert!(found.message.contains(NOT_CITE));
            assert_eq!(found.severity, Severity::Warning);
        }
        assert!(!has("index=main NOT status=200", codes::SPL_LEADING_NOT));
        assert!(!has(
            "index=main | where NOT status=200",
            codes::SPL_LEADING_NOT
        ));
    }

    #[test]
    fn a_field_named_like_a_command_starts_a_search() {
        // Without a leading `|`, `stats=1` is a field, not the stats command.
        assert_eq!(count("stats=1 *foo*", codes::SPL_WILDCARD), 1);
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
    fn quoted_wildcards_macros_and_parenthesized_not() {
        let quoted = warnings("process=\"*fail\"");
        let wild = quoted
            .iter()
            .filter(|d| d.code == codes::SPL_WILDCARD)
            .collect::<Vec<_>>();
        assert_eq!(wild.len(), 1, "{quoted:?}");
        assert!(
            wild[0].message.contains("leading wildcard") && wild[0].message.contains("*fail"),
            "{}",
            wild[0].message
        );
        assert!(!has("process=\"fail*\"", codes::SPL_WILDCARD));
        assert!(!has("index=main `my_search(*fail)`", codes::SPL_WILDCARD));
        let both = warnings("*fail OR f*il");
        assert_eq!(
            both.iter()
                .filter(|d| d.code == codes::SPL_WILDCARD)
                .count(),
            2,
            "{both:?}"
        );

        for src in [
            "search (NOT status=200)",
            "search ((NOT status=200))",
            "search ( ```hint``` NOT status=200 )",
            "(NOT status=200)",
        ] {
            assert!(
                has(src, codes::SPL_LEADING_NOT),
                "parenthesized leading NOT should warn: {src}"
            );
        }
    }

    #[test]
    fn quoted_pipe_does_not_invent_a_command_and_join_case_is_kept() {
        let quoted = warnings("\"foo|*fail\" | head 1");
        assert_eq!(
            quoted
                .iter()
                .filter(|d| d.code == codes::SPL_WILDCARD)
                .count(),
            1,
            "{quoted:?}"
        );
        assert!(
            quoted.iter().any(|d| d.code == codes::SPL_WILDCARD
                && d.message.contains("mid-token wildcard")
                && d.message.contains("foo|*fail")),
            "{quoted:?}"
        );
        assert!(
            !quoted
                .iter()
                .any(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION),
            "a pipe inside quotes must not become a command: {quoted:?}"
        );

        let join = warnings("index=main | JOIN host [ search index=other ]");
        let found = join
            .iter()
            .find(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION)
            .expect("JOIN warning");
        assert!(found.message.contains("`JOIN`"), "{}", found.message);
        assert!(found.message.contains("50,000"));
        assert_eq!(
            join.iter()
                .filter(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION)
                .count(),
            1,
            "{join:?}"
        );

        let txn = warnings("index=main | TRANSACTION user");
        let found = txn
            .iter()
            .find(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION)
            .expect("TRANSACTION warning");
        assert!(found.message.contains("maxopentxn"), "{}", found.message);
        assert!(
            found.message.contains(TRANSACTION_CITE),
            "{}",
            found.message
        );
        assert!(!found.message.contains("50,000"), "{}", found.message);

        let inner = warnings("index=main | join host [ search *fail ]");
        assert!(
            inner
                .iter()
                .any(|d| d.code == codes::SPL_SUBSEARCH_TRUNCATION),
            "{inner:?}"
        );
        assert_eq!(
            inner
                .iter()
                .filter(|d| d.code == codes::SPL_WILDCARD)
                .count(),
            1,
            "inner wildcard must be reported once: {inner:?}"
        );
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
