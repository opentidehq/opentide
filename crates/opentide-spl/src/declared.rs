//! Sourcetypes a search reads, checked against the ones the workspace
//! declares as the `name` of its `system = "splunk"` log sources in
//! `visibility.toml` (#115, tiers 2 and 3 of #110; `visibility::1.0`).
//!
//! - `sourcetype=`, `sourcetype::` and `sourcetype IN (...)` in the base
//!   search (the text before the first pipe, or a `search` command that
//!   starts the query, and the same in each subsearch) and in a `tstats`
//!   `where` clause. A negated term (`NOT sourcetype=x`, `sourcetype!=x`) is
//!   not checked: excluding a dataset reads nothing from it.
//! - `index=`, `source=` and macros are not checked: `visibility.toml`
//!   declares sourcetypes only.
//!
//! A sourcetype is checked only when the workspace has at least one Splunk
//! log source; an undeclared one is `spl_dataset_not_declared`, a warning.
//! Fields of raw sourcetypes are never checked: the columns a log source
//! lists are offered in hover and completion ([`declared_fields`]) only.

use super::Catalog;
use super::scan::{
    base_search, command_word, end_of_brackets, end_of_macro, end_quoted, skip_comment, skip_ws,
    split_segments, subsearches,
};
use opentide_core::datasets::{DatasetKind, DeclaredColumn, DeclaredDatasets, current};
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};

const PLATFORM: &str = "splunk";

/// A sourcetype value a search reads, by its byte span.
struct Read {
    start: usize,
    end: usize,
}

impl Read {
    fn name<'s>(&self, source: &'s str) -> &'s str {
        &source[self.start..self.end]
    }

    fn covered_by(&self, source: &str, declared: &str) -> bool {
        DatasetKind::Sourcetypes.covers(declared, self.name(source))
    }
}

pub(crate) fn collect(source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let datasets = current();
    if source.is_empty() || !datasets.declares(PLATFORM) {
        return;
    }
    check(source, catalog, &datasets, out);
}

fn check(source: &str, catalog: &Catalog, datasets: &DeclaredDatasets, out: &mut Vec<Diagnostic>) {
    let declared = datasets.names(PLATFORM);
    if declared.is_empty() {
        return;
    }
    let mut reads = Vec::new();
    walk(source, 0, source.len(), catalog, &mut reads);
    for read in reads {
        if declared.iter().any(|d| read.covered_by(source, d)) {
            continue;
        }
        let name = read.name(source);
        out.push(Diagnostic::warning(
            codes::SPL_DATASET_NOT_DECLARED,
            format!(
                "sourcetype `{name}` is not declared: no Splunk log source in visibility.toml names it"
            ),
            span_to_range(source, ByteSpan::new(read.start, read.end.max(read.start + 1))),
        ));
    }
}

/// The columns `visibility.toml` lists for the sourcetypes `source` reads,
/// with the log source each comes from; every declared Splunk column when
/// the search names no sourcetype. The first declaration of a name
/// (ignoring case) wins.
pub(crate) fn declared_fields(source: &str, catalog: &Catalog) -> Vec<(String, DeclaredColumn)> {
    let datasets = current();
    let mut sources = datasets.sources_with_columns(PLATFORM).peekable();
    if sources.peek().is_none() {
        return Vec::new();
    }
    let mut reads = Vec::new();
    walk(source, 0, source.len(), catalog, &mut reads);
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    // An exact sourcetype's columns win over a pattern's.
    let mut sources: Vec<_> = sources.collect();
    sources.sort_by_key(|s| s.name.contains('*'));
    for declared in sources {
        if !reads.is_empty() && !reads.iter().any(|r| r.covered_by(source, &declared.name)) {
            continue;
        }
        for column in &declared.columns {
            if seen.insert(column.name.to_ascii_lowercase()) {
                out.push((declared.name.clone(), column.clone()));
            }
        }
    }
    out
}

fn walk(source: &str, start: usize, end: usize, catalog: &Catalog, out: &mut Vec<Read>) {
    let segments = split_segments(source, start, end);
    // The stage that reads the index, as the wildcard lints see it (perf.rs).
    let base = base_search(source, &segments, catalog);
    for &(seg_start, seg_end) in &segments {
        for (inner_start, inner_end) in subsearches(source, seg_start, seg_end) {
            walk(source, inner_start, inner_end, catalog, out);
        }
        // The base search, and a `tstats` `where` clause.
        if base == Some((seg_start, seg_end))
            || command_word(source, seg_start, seg_end)
                .0
                .eq_ignore_ascii_case("tstats")
        {
            scan_terms(source, seg_start, seg_end, out);
        }
    }
}

/// Walks search terms, tracking `NOT`, and collects sourcetype values.
fn scan_terms(source: &str, start: usize, end: usize, out: &mut Vec<Read>) {
    let bytes = source.as_bytes();
    let mut i = start;
    let mut negate_next = false;
    let mut groups: Vec<bool> = Vec::new();
    while i < end {
        let negated = negate_next || groups.last().copied().unwrap_or(false);
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if let Some(next) = skip_comment(source, i, end) {
            i = next;
            continue;
        }
        match b {
            b'[' => {
                i = end_of_brackets(source, i, end);
                negate_next = false;
                continue;
            }
            b'(' => {
                groups.push(negated);
                negate_next = false;
                i += 1;
                continue;
            }
            b')' => {
                groups.pop();
                negate_next = false;
                i += 1;
                continue;
            }
            b'`' => {
                i = end_of_macro(bytes, i, end);
                negate_next = false;
                continue;
            }
            b'"' | b'\'' => {
                i = end_quoted(bytes, i, end);
                negate_next = false;
                continue;
            }
            _ => {}
        }
        let word_start = i;
        while i < end && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        if word_start == i {
            // Punctuation or a term that does not start with a name.
            i = end_of_term(bytes, i + 1, end);
            negate_next = false;
            continue;
        }
        let word = &source[word_start..i];
        if word.eq_ignore_ascii_case("not") && i < end && !is_term_char(bytes[i]) {
            negate_next = true;
            continue;
        }
        if !word.eq_ignore_ascii_case("sourcetype") {
            i = end_of_term(bytes, i, end);
            negate_next = false;
            continue;
        }
        let (values, next) = term_values(source, i, end);
        i = next;
        if let Some((values, operator_negates)) = values
            && !negated
            && !operator_negates
        {
            for (value_start, value_end) in values {
                read_name(source, value_start, value_end, out);
            }
        }
        negate_next = false;
    }
}

fn is_term_char(b: u8) -> bool {
    !(b.is_ascii_whitespace() || matches!(b, b'(' | b')'))
}

fn end_of_term(bytes: &[u8], mut i: usize, end: usize) -> usize {
    while i < end {
        match bytes[i] {
            b'"' | b'\'' => i = end_quoted(bytes, i, end),
            b if b.is_ascii_whitespace() || matches!(b, b'(' | b')' | b'[' | b'`') => break,
            _ => i += 1,
        }
    }
    i
}

/// The values after `index`: `=v`, `::v`, `!=v` (negated), ` IN (a, b)`.
#[allow(clippy::type_complexity)]
fn term_values(source: &str, i: usize, end: usize) -> (Option<(Vec<(usize, usize)>, bool)>, usize) {
    let bytes = source.as_bytes();
    let mut j = i;
    while j < end && bytes[j] == b' ' {
        j += 1;
    }
    if j + 1 < end && bytes[j] == b'!' && bytes[j + 1] == b'=' {
        let (_, next) = value(bytes, skip_ws(bytes, j + 2, end), end);
        return (Some((Vec::new(), true)), next);
    }
    if j + 1 < end && bytes[j] == b':' && bytes[j + 1] == b':' {
        let (v, next) = value(bytes, j + 2, end);
        return (Some((v.into_iter().collect(), false)), next);
    }
    if j < end && bytes[j] == b'=' {
        if bytes.get(j + 1) == Some(&b'=') {
            return (None, j + 2);
        }
        let (v, next) = value(bytes, skip_ws(bytes, j + 1, end), end);
        return (Some((v.into_iter().collect(), false)), next);
    }
    if j + 2 <= end && bytes[j..j + 2].eq_ignore_ascii_case(b"in") {
        let mut k = skip_ws(bytes, j + 2, end);
        if k < end && bytes[k] == b'(' {
            k += 1;
            let mut values = Vec::new();
            while k < end && bytes[k] != b')' {
                k = skip_ws(bytes, k, end);
                if k < end && bytes[k] == b',' {
                    k += 1;
                    continue;
                }
                let (v, next) = value(bytes, k, end);
                values.extend(v);
                if next == k {
                    k += 1;
                } else {
                    k = next;
                }
            }
            return (Some((values, false)), (k + 1).min(end));
        }
    }
    (None, end_of_term(bytes, i, end))
}

/// One value: quoted (the span inside the quotes) or bare.
fn value(bytes: &[u8], i: usize, end: usize) -> (Option<(usize, usize)>, usize) {
    if i >= end {
        return (None, i);
    }
    if bytes[i] == b'"' || bytes[i] == b'\'' {
        let close = end_quoted(bytes, i, end);
        let inner_end = if close > i + 1 && bytes[close - 1] == bytes[i] {
            close - 1
        } else {
            close
        };
        return (Some((i + 1, inner_end)), close);
    }
    let mut j = i;
    while j < end && !(bytes[j].is_ascii_whitespace() || matches!(bytes[j], b'(' | b')' | b',')) {
        j += 1;
    }
    if j == i { (None, i) } else { (Some((i, j)), j) }
}

fn read_name(source: &str, start: usize, end: usize, out: &mut Vec<Read>) {
    let name = &source[start..end];
    // Dashboard tokens (`$st$`) and empty values are not names.
    if name.trim().is_empty() || name.contains('$') {
        return;
    }
    out.push(Read { start, end });
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::Severity;

    fn declared() -> DeclaredDatasets {
        DeclaredDatasets::from_names([(
            "splunk",
            &["WinEventLog:Security", "XmlWinEventLog:*"][..],
        )])
    }

    /// The names warned about, in order.
    fn undeclared(src: &str, datasets: &DeclaredDatasets) -> Vec<String> {
        let mut out = Vec::new();
        check(src, Catalog::cached(), datasets, &mut out);
        for d in &out {
            assert_eq!(d.code, codes::SPL_DATASET_NOT_DECLARED);
            assert_eq!(d.severity, Severity::Warning);
        }
        out.iter()
            .map(|d| {
                let r = d.range;
                assert_eq!(r.start.line, r.end.line);
                let line = src.lines().nth(r.start.line as usize).unwrap();
                line[r.start.character as usize..r.end.character as usize].to_string()
            })
            .collect()
    }

    #[test]
    fn declared_sourcetypes_pass_and_undeclared_ones_warn() {
        let d = declared();
        assert!(undeclared("sourcetype=wineventlog:security EventCode=4688", &d).is_empty());
        assert!(undeclared("sourcetype=\"XmlWinEventLog:Security\"", &d).is_empty());
        assert!(undeclared("sourcetype=WinEventLog:* | stats count", &d).is_empty());
        assert_eq!(
            undeclared("index=main sourcetype=syslog | stats count", &d),
            ["syslog"]
        );
        assert_eq!(undeclared("search sourcetype::syslog", &d), ["syslog"]);
        assert_eq!(
            undeclared(
                "sourcetype IN (WinEventLog:Security, \"syslog\", pan:traffic)",
                &d
            ),
            ["syslog", "pan:traffic"]
        );
        // tstats reads sourcetypes in its where clause.
        assert_eq!(
            undeclared("| tstats count where sourcetype=syslog by host", &d),
            ["syslog"]
        );
        // A leading `| search` is the base search.
        assert_eq!(undeclared("| search sourcetype=syslog", &d), ["syslog"]);
        // Each subsearch has its own base search.
        assert_eq!(
            undeclared(
                "sourcetype=WinEventLog:Security [search sourcetype=other | fields user] | stats count",
                &d
            ),
            ["other"]
        );
    }

    #[test]
    fn negated_later_and_other_terms_are_not_checked() {
        let d = declared();
        for src in [
            "sourcetype=WinEventLog:Security NOT sourcetype=syslog",
            "sourcetype=WinEventLog:Security sourcetype!=syslog",
            "sourcetype=WinEventLog:Security NOT (sourcetype=syslog OR index=x)",
            "sourcetype=WinEventLog:Security | search sourcetype=syslog",
            "sourcetype=WinEventLog:Security | where sourcetype=\"syslog\"",
            "sourcetype=$st$",
            // Indexes, sources and macros are not declarable.
            "index=main source=WinEventLog:Security `sysmon` | `drop_dm_object_name(P)`",
            "`wineventlog_security` ```a `sourcetype=x` comment```",
            // A three-byte character right after `sourcetype` is not `IN`.
            "sourcetype=WinEventLog:Security sourcetype€",
        ] {
            assert!(
                undeclared(src, &d).is_empty(),
                "{src}: {:?}",
                undeclared(src, &d)
            );
        }
    }

    #[test]
    fn opt_in_per_platform() {
        let other_platform = DeclaredDatasets::from_names([("sentinel", &["SigninLogs"][..])]);
        assert!(undeclared("sourcetype=syslog", &other_platform).is_empty());
    }
}
