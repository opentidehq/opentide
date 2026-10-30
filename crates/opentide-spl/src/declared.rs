//! Indexes, sourcetypes and macros a search reads, checked against the ones
//! the workspace declares on its `system = "splunk"` log sources in
//! `visibility.toml` (#115, tiers 2 and 3 of #110).
//!
//! - `index=`, `index::`, `index IN (...)`, and the same for `sourcetype`, in
//!   the base search (the text before the first pipe, or a `search` command
//!   that starts the query, and the same in each subsearch) and in a
//!   `tstats` `where` clause. A negated term (`NOT index=x`, `index!=x`) is
//!   not checked: excluding a dataset reads nothing from it.
//! - A macro call in the base search (`` `wineventlog_security` ``,
//!   `` `cim_Endpoint_indexes` ``): that is where a dataset macro expands to
//!   indexes and sourcetypes. A macro after a pipe is a utility
//!   (`drop_dm_object_name`, `security_content_ctime`) or filter macro and is
//!   never checked; neither is `comment` or a `*_filter` macro.
//! - `source=` is not checked: `visibility.toml` declares no kind for it.
//!
//! A name is checked only when the workspace declares at least one name of
//! that kind for Splunk; an undeclared one is `spl_dataset_not_declared`, a
//! warning. Fields of raw sourcetypes are never checked.

use super::Catalog;
use super::scan::{
    base_search, command_word, end_of_brackets, end_of_macro, end_quoted, skip_comment, skip_ws,
    split_segments, subsearches,
};
use opentide_core::datasets::{DatasetKind, Declaration, DeclaredDatasets, current};
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};

const PLATFORM: &str = "splunk";

pub(crate) fn collect(source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let datasets = current();
    let kinds = [
        DatasetKind::Indexes,
        DatasetKind::Sourcetypes,
        DatasetKind::Macros,
    ];
    if source.is_empty() || !kinds.iter().any(|k| datasets.declares(PLATFORM, *k)) {
        return;
    }
    walk(source, 0, source.len(), catalog, &datasets, out);
}

fn walk(
    source: &str,
    start: usize,
    end: usize,
    catalog: &Catalog,
    datasets: &DeclaredDatasets,
    out: &mut Vec<Diagnostic>,
) {
    let segments = split_segments(source, start, end);
    // The stage that reads the index, as the wildcard lints see it (perf.rs).
    let base = base_search(source, &segments, catalog);
    for &(seg_start, seg_end) in &segments {
        for (inner_start, inner_end) in subsearches(source, seg_start, seg_end) {
            walk(source, inner_start, inner_end, catalog, datasets, out);
        }
        if base == Some((seg_start, seg_end)) {
            scan_terms(source, seg_start, seg_end, true, datasets, out);
        } else if command_word(source, seg_start, seg_end)
            .0
            .eq_ignore_ascii_case("tstats")
        {
            scan_terms(source, seg_start, seg_end, false, datasets, out);
        }
    }
}

/// Walks search terms, tracking `NOT`, and checks dataset terms and (in the
/// base search) macro calls.
fn scan_terms(
    source: &str,
    start: usize,
    end: usize,
    macros: bool,
    datasets: &DeclaredDatasets,
    out: &mut Vec<Diagnostic>,
) {
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
                let close = end_of_macro(bytes, i, end);
                if macros && !negated {
                    check_macro(source, i, close, datasets, out);
                }
                i = close;
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
        let kind = if word.eq_ignore_ascii_case("index") {
            Some(DatasetKind::Indexes)
        } else if word.eq_ignore_ascii_case("sourcetype") {
            Some(DatasetKind::Sourcetypes)
        } else {
            None
        };
        let Some(kind) = kind else {
            i = end_of_term(bytes, i, end);
            negate_next = false;
            continue;
        };
        let (values, next) = term_values(source, i, end);
        i = next;
        if let Some((values, operator_negates)) = values {
            if !negated && !operator_negates {
                for (value_start, value_end) in values {
                    check_name(source, kind, value_start, value_end, datasets, out);
                }
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

fn check_name(
    source: &str,
    kind: DatasetKind,
    start: usize,
    end: usize,
    datasets: &DeclaredDatasets,
    out: &mut Vec<Diagnostic>,
) {
    let name = &source[start..end];
    // Dashboard tokens (`$index$`) and empty values are not names.
    if name.trim().is_empty() || name.contains('$') {
        return;
    }
    if datasets.status(PLATFORM, kind, name) != Declaration::Undeclared {
        return;
    }
    warn(source, kind, name, start, end, out);
}

fn warn(
    source: &str,
    kind: DatasetKind,
    name: &str,
    start: usize,
    end: usize,
    out: &mut Vec<Diagnostic>,
) {
    let label = match kind {
        DatasetKind::Indexes => "index",
        DatasetKind::Sourcetypes => "sourcetype",
        _ => "macro",
    };
    out.push(Diagnostic::warning(
        codes::SPL_DATASET_NOT_DECLARED,
        format!(
            "{label} `{name}` is not declared on a Splunk log source in visibility.toml ({})",
            kind.key()
        ),
        span_to_range(source, ByteSpan::new(start, end.max(start + 1))),
    ));
}

/// A macro call `` `name` `` or `` `name(a, b)` `` between `start` and `close`.
fn check_macro(
    source: &str,
    start: usize,
    close: usize,
    datasets: &DeclaredDatasets,
    out: &mut Vec<Diagnostic>,
) {
    let inner_start = start + 1;
    let inner_end = if close > inner_start && source.as_bytes()[close - 1] == b'`' {
        close - 1
    } else {
        close
    };
    let Some(text) = source.get(inner_start..inner_end) else {
        return;
    };
    let (name, args) = match text.find('(') {
        Some(open) => (&text[..open], Some(text[open + 1..].trim_end_matches(')'))),
        None => (text, None),
    };
    let name = name.trim();
    if name.is_empty() || name == "comment" || name.ends_with("_filter") {
        return;
    }
    let declared = |n: &str| datasets.status(PLATFORM, DatasetKind::Macros, n);
    if declared(name) != Declaration::Undeclared {
        return;
    }
    if let Some(args) = args {
        let count = if args.trim().is_empty() {
            0
        } else {
            args.split(',').count()
        };
        if declared(&format!("{name}({count})")) != Declaration::Undeclared {
            return;
        }
    }
    let name_start = inner_start + (text.len() - text.trim_start().len());
    warn(
        source,
        DatasetKind::Macros,
        name,
        name_start,
        name_start + name.len(),
        out,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::Severity;

    fn declared() -> DeclaredDatasets {
        DeclaredDatasets::from_names([
            (
                "splunk",
                DatasetKind::Indexes,
                &["wineventlog", "edr_*"][..],
            ),
            (
                "splunk",
                DatasetKind::Sourcetypes,
                &["XmlWinEventLog:*"][..],
            ),
            (
                "splunk",
                DatasetKind::Macros,
                &[
                    "wineventlog_security",
                    "cim_Endpoint_indexes",
                    "sysmon_for(1)",
                ][..],
            ),
        ])
    }

    /// The names warned about, in order.
    fn undeclared(src: &str, datasets: &DeclaredDatasets) -> Vec<String> {
        let mut out = Vec::new();
        walk(src, 0, src.len(), Catalog::cached(), datasets, &mut out);
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
    fn declared_names_pass_and_undeclared_ones_warn() {
        let d = declared();
        assert!(undeclared("index=wineventlog EventCode=4688 | stats count", &d).is_empty());
        assert!(
            undeclared(
                "index=WinEventLog sourcetype=\"XmlWinEventLog:Security\"",
                &d
            )
            .is_empty()
        );
        assert!(undeclared("index=edr_crowd* OR index=edr_s1", &d).is_empty());
        assert_eq!(
            undeclared("index=main sourcetype=syslog | stats count", &d),
            ["main", "syslog"]
        );
        assert_eq!(undeclared("search index::main", &d), ["main"]);
        assert_eq!(
            undeclared("index IN (wineventlog, \"main\", firewall)", &d),
            ["main", "firewall"]
        );
        // tstats reads indexes in its where clause.
        assert_eq!(
            undeclared("| tstats count where index=main by host", &d),
            ["main"]
        );
        // A leading `| search` is the base search.
        assert_eq!(undeclared("| search index=main", &d), ["main"]);
        // Each subsearch has its own base search.
        assert_eq!(
            undeclared(
                "index=wineventlog [search index=other | fields user] | stats count",
                &d
            ),
            ["other"]
        );
    }

    #[test]
    fn negated_and_later_terms_are_not_checked() {
        let d = declared();
        for src in [
            "index=wineventlog NOT index=main",
            "index=wineventlog index!=main",
            "index=wineventlog NOT (index=main OR sourcetype=syslog)",
            "index=wineventlog | search index=main",
            "index=wineventlog | where index=\"main\"",
            "index=$index$ sourcetype=$st$",
            "index=wineventlog source=WinEventLog:Security",
            // A three-byte character right after `index` is not `IN`.
            "index=wineventlog index€",
        ] {
            assert!(
                undeclared(src, &d).is_empty(),
                "{src}: {:?}",
                undeclared(src, &d)
            );
        }
    }

    #[test]
    fn only_base_search_macros_are_checked() {
        let d = declared();
        assert!(undeclared("`wineventlog_security` EventCode=4625 | stats count", &d).is_empty());
        assert!(undeclared("`sysmon_for(1)` | stats count", &d).is_empty());
        assert_eq!(
            undeclared("`sysmon` EventCode=1 | stats count", &d),
            ["sysmon"]
        );
        assert_eq!(
            undeclared("`powershell(4104)` | stats count", &d),
            ["powershell"]
        );
        for src in [
            "| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes by Processes.dest | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `my_detection_filter`",
            "`wineventlog_security` `comment(\"x\")` `my_detection_filter`",
            "`wineventlog_security` ```a `notamacro` comment```",
        ] {
            assert!(
                undeclared(src, &d).is_empty(),
                "{src}: {:?}",
                undeclared(src, &d)
            );
        }
    }

    #[test]
    fn opt_in_per_kind() {
        let only_indexes =
            DeclaredDatasets::from_names([("splunk", DatasetKind::Indexes, &["wineventlog"][..])]);
        assert_eq!(
            undeclared("index=main sourcetype=syslog `sysmon`", &only_indexes),
            ["main"]
        );
        let other_platform =
            DeclaredDatasets::from_names([("sentinel", DatasetKind::Tables, &["SigninLogs"][..])]);
        assert!(undeclared("index=main sourcetype=syslog `sysmon`", &other_platform).is_empty());
    }
}
