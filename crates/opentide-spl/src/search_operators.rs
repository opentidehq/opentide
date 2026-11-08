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
        if brackets == 0 {
            if let Some(next) = skip_hidden(source, i, end) {
                i = next;
                field_before = false;
                continue;
            }
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
        if i < end && bytes[i..end].starts_with(b"```") {
            if let Some(next) = skip_hidden(source, i, end) {
                i = next;
                continue;
            }
        }
        return i;
    }
}

#[cfg(test)]
mod tests {
    use crate::analyze;
    use opentide_core::{Diagnostic, Severity, codes, offset_to_position};

    fn found(src: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_SEARCH_OPERATOR)
            .collect()
    }

    /// The source text a diagnostic's range covers.
    fn covered<'a>(src: &'a str, d: &Diagnostic) -> &'a str {
        let at = |line: u32, character: u32| {
            (0..=src.len())
                .find(|&i| {
                    src.is_char_boundary(i) && {
                        let p = offset_to_position(src, i);
                        p.line == line && p.character == character
                    }
                })
                .expect("range inside the source")
        };
        &src[at(d.range.start.line, d.range.start.character)
            ..at(d.range.end.line, d.range.end.character)]
    }

    /// The one diagnostic on `src`, which must cover `op`.
    fn one(src: &str, op: &str) -> Diagnostic {
        let diags = found(src);
        assert_eq!(diags.len(), 1, "{src}: {diags:?}");
        let d = diags.into_iter().next().unwrap();
        assert_eq!(covered(src, &d), op, "{src}");
        d
    }

    /// Applies the diagnostic's suggestion the way the server's quick fix does:
    /// the suggestion replaces the range.
    fn apply(src: &str, d: &Diagnostic) -> String {
        let fix = d.suggestion.as_deref().expect("a fix");
        let op = covered(src, d);
        let start = src.find(op).expect("operator in source");
        format!("{}{fix}{}", &src[..start], &src[start + op.len()..])
    }

    const BASE: &str = "| makeresults count=4 | eval status=200 | ";

    #[test]
    fn every_row_of_the_issue_table_is_reported_in_a_search_stage() {
        for (clause, op, fix) in [
            ("search status==200", "==", Some("=")),
            ("search status==\"200\"", "==", Some("=")),
            ("search status<>200", "<>", Some("!=")),
            ("search status!~200", "!~", None),
            ("search status=>300", "=>", Some(">=")),
            ("search status=<300", "=<", Some("<=")),
            ("search NOT status==200", "==", Some("=")),
            ("search status==200 OR status=404", "==", Some("=")),
        ] {
            let src = format!("{BASE}{clause}");
            let d = one(&src, op);
            assert_eq!(d.severity, Severity::Error, "{src}");
            assert_eq!(d.suggestion.as_deref(), fix, "{src}");
            assert!(
                d.message
                    .starts_with(&format!("'{op}' is not a search operator: ")),
                "{}",
                d.message
            );
            assert!(d.message.contains("never matches"), "{}", d.message);
            match fix {
                Some(fix) => assert!(
                    d.message.ends_with(&format!("use '{fix}'")),
                    "{}",
                    d.message
                ),
                None => assert!(d.message.contains("NOT match()"), "{}", d.message),
            }
        }
    }

    #[test]
    fn the_message_names_the_operator_and_its_fix() {
        let d = one("index=a | search status==0", "==");
        assert_eq!(
            d.message,
            "'==' is not a search operator: Splunk accepts it but the comparison never matches; use '='"
        );
    }

    #[test]
    fn tilde_after_equals_is_a_warning_without_a_fix() {
        let d = one(&format!("{BASE}search status=~200"), "=~");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.suggestion, None);
        assert!(d.message.contains("match()"), "{}", d.message);
        assert!(d.message.contains("starts with '~'"), "{}", d.message);
    }

    #[test]
    fn fixes_apply_and_round_trip() {
        for (src, op, fixed) in [
            (
                "index=a | search a==1 b=2",
                "==",
                "index=a | search a=1 b=2",
            ),
            ("index=a | search a<>1", "<>", "index=a | search a!=1"),
            ("index=a | search a=>1", "=>", "index=a | search a>=1"),
            ("index=a | search a=<1", "=<", "index=a | search a<=1"),
            ("index=a a==\"x y\"", "==", "index=a a=\"x y\""),
        ] {
            let d = one(src, op);
            let out = apply(src, &d);
            assert_eq!(out, fixed);
            assert!(found(&out).is_empty(), "{out}: {:?}", found(&out));
        }
    }

    #[test]
    fn every_search_clause_is_read() {
        for src in [
            // The base search, with and without `search`.
            "index=a status==200",
            "search index=a status==200",
            "| search index=a status==200",
            "`m` status==200",
            // A subsearch's search, and its first stage.
            "index=a [ search index=b status==200 | fields host ]",
            "index=a [ index=b status==200 | fields host ]",
            "index=a | join host [ search index=b status==200 ]",
            "index=a | eval x=1 | search [ | inputlookup t.csv where status==200 | fields host ]",
            // tstats where, up to by.
            "| tstats count where index=a status==200 by host",
            "| tstats count from datamodel=Web where Web.status==200 by Web.src",
            "| tstats count WHERE index=a (status==200 OR status=404)",
            // inputlookup where.
            "| inputlookup t.csv where status==200",
            // Spaced, and later in a clause.
            "index=a status == 200",
            "index=a status ==200",
            "index=a (b=1 OR status==200)",
            "index=a status=*\n| search status==200",
        ] {
            one(src, "==");
        }
    }

    #[test]
    fn the_consequence_follows_the_clause() {
        let d = one("| tstats count where index=a status==200 by host", "==");
        assert!(
            d.message.contains("WHERE clause is not an exact query"),
            "{}",
            d.message
        );
        assert_eq!(d.severity, Severity::Error);
        let d = one("| inputlookup t.csv where status<>200", "<>");
        assert!(d.message.contains("every row passes"), "{}", d.message);
        assert_eq!(d.suggestion.as_deref(), Some("!="));
    }

    #[test]
    fn eval_where_and_other_commands_are_not_read() {
        for src in [
            "index=a | where status==200",
            "index=a | where status<>200",
            "index=a | eval ok=if(status==200, 1, 0)",
            "index=a | eval ok=case(status==200, 1, status=>3, 2)",
            "index=a | stats count(eval(status==200)) as ok",
            "index=a | where match(user, \"a=~b\")",
            "| makeresults | eval status=200 | where status==200",
            "| tstats count where index=a by host | where count==1",
            "| tstats count where index=a by host | eval x=y==1",
            "| inputlookup t.csv | where status==200",
            "index=a | rex field=_raw \"x==(?<v>\\d+)\"",
            "index=a | fillnull value==",
        ] {
            assert!(found(src).is_empty(), "{src}: {:?}", found(src));
        }
    }

    #[test]
    fn quoted_values_comments_and_macros_are_not_read() {
        for src in [
            "index=a field=\"a==b\"",
            "index=a field=\"<>\" other='x=>y'",
            "index=a \"status==200\"",
            "index=a ```status==200``` b=1",
            "index=a `m(status==200)`",
            "index=a `m(\"x<>y\")` | search `n(a=~b)`",
            "index=a | eval x=\"| search status==200\"",
        ] {
            assert!(found(src).is_empty(), "{src}: {:?}", found(src));
        }
    }

    #[test]
    fn search_operators_and_values_are_not_reported() {
        for src in [
            "index=a status=200 status!=404 b>=1 c<=2 d>3 e<4",
            "index=a status = 200",
            "index=a NOT status=200",
            "index=a status IN (200, 404)",
            // `!=` followed by a tilde value is `!=`.
            "index=a status!=~200",
            // The operator is the first one: `==` is in the value.
            "index=a cmd=*==* v=abc== w=a==b",
            // Base64 padding is a keyword, not a comparison.
            "index=a dGVzdA== c2VjcmV0==",
            // An operator with no field in front of it.
            "index=a \"x\" == y",
            "index=a b=1 == y",
            "index=a AND == y",
            "index=a *==1",
            // Not search clauses at all.
            "| makeresults | eval a=1",
            "| tstats count where index=a by host==1",
        ] {
            assert!(found(src).is_empty(), "{src}: {:?}", found(src));
        }
    }

    #[test]
    fn each_operator_is_reported_once() {
        let src = "index=a a==1 b<>2 c=>3 d=<4 e!~5 f=~6 [ search g==7 ]";
        let ops: Vec<String> = found(src)
            .iter()
            .map(|d| covered(src, d).to_string())
            .collect();
        assert_eq!(ops, ["==", "<>", "=>", "=<", "!~", "=~", "=="]);
    }

    #[test]
    fn an_unclosed_parenthesis_does_not_hide_the_next_pipe() {
        // Splunk splits stages on `|` whatever the parentheses, and runs this.
        let src = "index=a TERM(\"x\" | eval y=if(s==\"b\", 1, 0) | search z==1";
        let d = one(src, "==");
        // Only the `| search` stage is read, not the eval.
        assert_eq!(d.range.start.character as usize, src.rfind("==").unwrap());
    }

    #[test]
    fn ranges_count_utf16_after_non_ascii_text() {
        let src = "index=a user=\"é🔥\" status==200";
        one(src, "==");
    }
}
