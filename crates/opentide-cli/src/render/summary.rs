//! Markdown for CI job summaries: findings, a deploy plan, query validation results.
//!
//! [`super::ci::append_summary`] writes what these build. Each summary is a
//! `###` heading with the outcome glyph and the command, the outcome line, then
//! a table. Tables stop at [`MAX_ROWS`] (the job log and the report files keep
//! the rest), and a summary at [`MAX_SUMMARY_BYTES`] ([`fit`]). User text is
//! escaped so it shows as written ([`cell`], [`code`]).

use super::diagnostic::{Diagnostic, sort_diagnostics};
use crate::json::Json;

/// The generated reference of diagnostic codes; `#<code>` is each one's section.
pub const DIAGNOSTICS_DOCS_URL: &str = "https://opentide.org/docs/cli/diagnostics";

/// Rows per table.
pub const MAX_ROWS: usize = 100;

/// Bytes one summary may take: GitHub refuses a step summary over 1 MiB, and
/// one step can run several commands, so each stays well under it.
pub const MAX_SUMMARY_BYTES: usize = 256 * 1024;

/// Lines of a deploy error shown after `would fail:`.
pub const MAX_ERROR_LINES: usize = 2;
/// Characters of a deploy error shown after `would fail:`.
pub const MAX_ERROR_CHARS: usize = 300;

/// Where the published `opentide explain <code>` page lives.
pub fn explain_url(code: &str) -> String {
    format!("{DIAGNOSTICS_DOCS_URL}#{code}")
}

/// The line breaks Python's `str.splitlines` splits at.
pub(crate) fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        if matches!(
            ch,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            lines.push(&text[start..at]);
            let mut next = at + ch.len_utf8();
            if ch == '\r' && chars.peek().is_some_and(|(_, c)| *c == '\n') {
                chars.next();
                next += 1;
            }
            start = next;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Whitespace as Python's `str.strip` sees it.
fn is_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// `&`, `<` and `>` as entities (and the quotes, when `quote`).
fn html_escape(text: &str, quote: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// User text as literal Markdown, safe inside a table cell.
///
/// `&`, `<` and `>` become entities, so `<clear>` shows instead of being
/// dropped as an unknown tag; inline Markdown punctuation is backslash-escaped,
/// so `*em*` stays text and `|` cannot end the cell; line breaks become `<br>`.
pub fn cell(value: &str) -> String {
    let escaped: String = html_escape(value, false)
        .chars()
        .flat_map(|ch| {
            let escape = "\\`*_[]()!~|#".contains(ch);
            escape
                .then_some('\\')
                .into_iter()
                .chain(std::iter::once(ch))
        })
        .collect();
    let joined = split_lines(&escaped)
        .into_iter()
        .map(|part| part.trim_matches(is_space))
        .collect::<Vec<_>>()
        .join("<br>");
    if joined.is_empty() {
        " ".to_owned()
    } else {
        joined
    }
}

/// `value` as inline code, fenced with more backticks than it contains; only
/// `|` is escaped (a table splits cells before it reads code spans).
pub fn code(value: &str) -> String {
    let text = value.replace('|', "\\|");
    let mut fence = "`".to_owned();
    while text.contains(&fence) {
        fence.push('`');
    }
    let padded = if text.starts_with('`') || text.ends_with('`') {
        format!(" {text} ")
    } else {
        text
    };
    format!("{fence}{padded}{fence}")
}

/// `### ✓ opentide validate`; `kind` is `ok`, `failed`, `warning` or `skipped`.
pub fn heading(kind: &str, title: &str) -> String {
    let glyph = match kind {
        "ok" => "✓",
        "failed" => "✗",
        "warning" => "!",
        "skipped" => "–",
        _ => return format!("### {title}"),
    };
    format!("### {glyph} {title}")
}

/// A Markdown table, then `… and N more` when `total` is more than the rows given.
pub fn table(header: &[&str], rows: &[Vec<String>], total: usize) -> Vec<String> {
    let mut lines = vec![
        format!("| {} |", header.join(" | ")),
        format!("|{}|", vec!["---"; header.len()].join("|")),
    ];
    for row in rows {
        lines.push(format!("| {} |", row.join(" | ")));
    }
    if total > rows.len() {
        lines.push(String::new());
        lines.push(format!("… and {} more in the job log.", total - rows.len()));
    }
    lines
}

fn location(diagnostic: &Diagnostic, path: Option<&str>) -> String {
    let Some(path) = path else {
        return " ".to_owned();
    };
    let mut place = path.to_owned();
    if let Some(line) = diagnostic.line {
        place.push_str(&format!(":{line}"));
        if let Some(column) = diagnostic.column {
            place.push_str(&format!(":{column}"));
        }
    }
    code(&place)
}

/// Findings as a table: severity, code (linked to its page), location, message.
///
/// `path_for` gives the path to show, when it is not the diagnostic's own
/// `path` (relative to the checkout rather than the workspace).
pub fn diagnostics_summary(
    title: &str,
    outcome: &str,
    diagnostics: &[Diagnostic],
    kind: &str,
    path_for: Option<super::report::PathFor<'_>>,
) -> String {
    let mut lines = vec![heading(kind, title), String::new(), cell(outcome)];
    if !diagnostics.is_empty() {
        let rows: Vec<Vec<String>> = sort_diagnostics(diagnostics)
            .into_iter()
            .take(MAX_ROWS)
            .map(|item| {
                let path = match path_for {
                    Some(path_for) => path_for(item),
                    None => item.path.clone(),
                };
                let mut message = item.message.clone();
                if let Some(help) = item.help.as_ref().filter(|help| !help.is_empty()) {
                    message.push_str(&format!(" — help: {help}"));
                }
                vec![
                    item.severity.as_str().to_owned(),
                    format!("[{}]({})", code(&item.code), explain_url(&item.code)),
                    location(item, path.as_deref()),
                    cell(&message),
                ]
            })
            .collect();
        lines.push(String::new());
        lines.extend(table(
            &["Severity", "Code", "Location", "Message"],
            &rows,
            diagnostics.len(),
        ));
    }
    lines.join("\n") + "\n"
}

/// Python's truth value of a JSON value.
fn truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) => false,
        Some(Json::Bool(value)) => *value,
        Some(Json::Int(value)) => *value != 0,
        Some(Json::UInt(value)) => *value != 0,
        Some(Json::Float(value)) => *value != 0.0,
        Some(Json::Str(value)) => !value.is_empty(),
        Some(Json::Array(items)) => !items.is_empty(),
        Some(Json::Object(members)) => !members.is_empty(),
    }
}

/// A JSON value as text: a string as it is, anything else as its JSON.
fn value_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => crate::json::document_text(other, false)
            .trim_end()
            .to_owned(),
    }
}

/// Python's `len()` of a JSON value.
fn py_len(value: &Json) -> usize {
    match value {
        Json::Str(text) => text.chars().count(),
        Json::Array(items) => items.len(),
        Json::Object(members) => members.len(),
        _ => 0,
    }
}

fn members(value: Option<&Json>) -> &[(String, Json)] {
    match value {
        Some(Json::Object(members)) => members,
        _ => &[],
    }
}

fn items(value: Option<&Json>) -> Vec<&Json> {
    match value {
        Some(Json::Array(items)) => items.iter().collect(),
        Some(Json::Object(members)) => members.iter().map(|(_, value)| value).collect(),
        _ => Vec::new(),
    }
}

fn status_kind(result: &Json) -> &'static str {
    let status = result.get("status").map(value_text).unwrap_or_default();
    if status == "failed" || result.get("ok") == Some(&Json::Bool(false)) {
        return "failed";
    }
    if status == "skipped" {
        return "skipped";
    }
    if truthy(result.get("warnings")) {
        return "warning";
    }
    "ok"
}

/// The first `lines` lines of `text`, at most `chars` characters, with ` …` when cut.
pub fn shorten(text: &str, lines: usize, chars: usize) -> String {
    let full = text.trim_matches(is_space);
    let mut kept = split_lines(full)
        .into_iter()
        .take(lines)
        .collect::<Vec<_>>()
        .join("\n");
    if kept.chars().count() > chars {
        let cut: String = kept.chars().take(chars.saturating_sub(1)).collect();
        cut.trim_end_matches(is_space).clone_into(&mut kept);
    }
    if kept == full { kept } else { kept + " …" }
}

/// `markdown` cut at a line to at most `limit` bytes, saying so; an open
/// `<details>` block is closed, so the rest of the job summary still renders.
pub fn fit(markdown: &str, limit: usize) -> String {
    if markdown.len() <= limit {
        return markdown.to_owned();
    }
    let note = "\n… summary truncated; the job log has everything.\n";
    let budget = limit
        .saturating_sub(note.len())
        .saturating_sub("\n</details>\n".len());
    let mut kept: Vec<&str> = Vec::new();
    let mut used = 0;
    for line in split_lines(markdown) {
        let size = line.len() + 1;
        if used + size > budget {
            break;
        }
        kept.push(line);
        used += size;
    }
    let mut text = kept.join("\n");
    if text.matches("<details>").count() > text.matches("</details>").count() {
        text.push_str("\n</details>");
    }
    text + "\n" + note
}

fn strategies_line(result: &Json, lines: &mut Vec<String>) {
    if truthy(result.get("strategies")) {
        let named: Vec<String> = items(result.get("strategies"))
            .into_iter()
            .map(|item| code(&value_text(item)))
            .collect();
        lines.push(String::new());
        lines.push(format!("Strategies: {}", named.join(", ")));
    }
}

fn message_line(result: &Json, message: Option<&str>) -> String {
    match message.filter(|message| !message.is_empty()) {
        Some(message) => cell(message),
        None => cell(&result.get("message").map(value_text).unwrap_or_default()),
    }
}

fn rule_line(uuid: &str, entry: Option<&Json>) -> String {
    let Some(entry) = entry.filter(|entry| truthy(entry.get("name"))) else {
        return format!("- {}", code(uuid));
    };
    let mut line = format!(
        "- {} ({})",
        cell(&entry.get("name").map(value_text).unwrap_or_default()),
        code(uuid)
    );
    if entry.get("status").map(value_text).as_deref() == Some("failed")
        && truthy(entry.get("error"))
    {
        let error = entry.get("error").map(value_text).unwrap_or_default();
        line.push_str(&format!(
            " — would fail: {}",
            cell(&shorten(&error, MAX_ERROR_LINES, MAX_ERROR_CHARS))
        ));
    }
    line
}

/// The deploy plan: rules per platform and tenant, then the rules themselves.
/// `dry_run` is the command's flag; a payload from a deploy that failed early
/// may not carry it.
pub fn deploy_summary(result: &Json, message: Option<&str>, dry_run: Option<bool>) -> String {
    let dry_run = dry_run.unwrap_or_else(|| truthy(result.get("dry_run")));
    let title = if dry_run {
        "opentide deploy --dry-run"
    } else {
        "opentide deploy"
    };
    let mut lines = vec![
        heading(status_kind(result), title),
        String::new(),
        message_line(result, message),
    ];
    strategies_line(result, &mut lines);
    let plan = members(result.get("plan"));
    if plan.is_empty() {
        return lines.join("\n") + "\n";
    }
    let tenants = members(result.get("tenants"));
    let deployed: Vec<String> = items(result.get("deployed"))
        .into_iter()
        .map(value_text)
        .collect();
    let mut rows: Vec<Vec<String>> = Vec::new();
    for (platform, uuids) in plan {
        let reach = tenants
            .iter()
            .find(|(name, _)| name == platform)
            .map(|(_, value)| value);
        match reach {
            Some(Json::Object(reach)) if !reach.is_empty() => {
                for (tenant, rules) in reach {
                    rows.push(vec![
                        code(platform),
                        cell(tenant),
                        py_len(rules).to_string(),
                    ]);
                }
            }
            _ if dry_run => rows.push(vec![
                code(platform),
                "none".to_owned(),
                py_len(uuids).to_string(),
            ]),
            _ => {
                let done = if deployed.contains(platform) {
                    "deployed"
                } else {
                    "not deployed"
                };
                rows.push(vec![
                    code(platform),
                    done.to_owned(),
                    py_len(uuids).to_string(),
                ]);
            }
        }
    }
    lines.push(String::new());
    let header: [&str; 3] = if dry_run {
        ["Platform", "Tenant", "Rules"]
    } else {
        ["Platform", "Result", "Rules"]
    };
    let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
    lines.extend(table(&header, &shown, rows.len()));
    let payloads = members(result.get("payloads"));
    for (platform, uuids) in plan {
        let entries: Vec<&Json> = payloads
            .iter()
            .find(|(name, _)| name == platform)
            .map(|(_, value)| items(Some(value)))
            .unwrap_or_default();
        let named = |uuid: &str| -> Option<&Json> {
            entries
                .iter()
                .rev()
                .find(|entry| {
                    matches!(entry, Json::Object(_))
                        && entry.get("uuid").map(value_text).as_deref() == Some(uuid)
                })
                .copied()
        };
        let count = py_len(uuids);
        let noun = if count == 1 { "rule" } else { "rules" };
        // An HTML block: Markdown escapes would show, so HTML escaping only.
        lines.push(String::new());
        lines.push(format!(
            "<details><summary>{}: {count} {noun}</summary>",
            html_escape(platform, true)
        ));
        lines.push(String::new());
        for uuid in items(Some(uuids)).into_iter().take(MAX_ROWS) {
            let uuid = value_text(uuid);
            lines.push(rule_line(&uuid, named(&uuid)));
        }
        if count > MAX_ROWS {
            lines.push(format!("- … and {} more", count - MAX_ROWS));
        }
        lines.push(String::new());
        lines.push("</details>".to_owned());
    }
    lines.join("\n") + "\n"
}

/// Live query validation: queries sent per tenant, and the verdict.
pub fn query_summary(result: &Json, message: Option<&str>) -> String {
    let platform = result.get("platform").map(value_text).unwrap_or_default();
    let title = format!("opentide validate query --platform {platform}")
        .trim_end_matches(is_space)
        .to_owned();
    let mut lines = vec![
        heading(status_kind(result), &title),
        String::new(),
        message_line(result, message),
    ];
    strategies_line(result, &mut lines);
    let reach = members(result.get("queries_per_tenant"));
    if !reach.is_empty() {
        let rows: Vec<Vec<String>> = reach
            .iter()
            .map(|(tenant, count)| vec![cell(tenant), value_text(count)])
            .collect();
        lines.push(String::new());
        let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
        lines.extend(table(&["Tenant", "Queries"], &shown, rows.len()));
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(cell("<x> & *y*"), "&lt;x&gt; &amp; \\*y\\*");
        assert_eq!(cell(""), " ");
        assert_eq!(cell(" a \n b "), "a<br>b");
        assert_eq!(code("a`b"), "``a`b``");
        assert_eq!(code("`x`"), "`` `x` ``");
        assert_eq!(heading("plan", "t"), "### t");
        assert_eq!(shorten("a\nb\nc", 2, 300), "a\nb …");
        assert_eq!(shorten("abcdef", 2, 4), "abc …");
        assert_eq!(fit("short\n", 10), "short\n");
    }

    #[test]
    fn code_pads_a_value_that_starts_or_ends_in_a_backtick() {
        assert_eq!(code("a`"), "`` a` ``");
        assert_eq!(code("`a"), "`` `a ``");
        assert_eq!(code("a"), "`a`");
    }

    #[test]
    fn tables_stop_at_max_rows() {
        let findings = |count: usize| -> Vec<Diagnostic> {
            (0..count)
                .map(|at| {
                    Diagnostic::new(
                        "x",
                        super::super::diagnostic::Severity::Error,
                        &format!("m{at}"),
                    )
                })
                .collect()
        };
        let rows = |text: &str| {
            text.lines()
                .filter(|line| line.starts_with("| error"))
                .count()
        };
        let full = diagnostics_summary("t", "o", &findings(MAX_ROWS), "failed", None);
        assert_eq!(rows(&full), MAX_ROWS);
        assert!(!full.contains("more in the job log"));
        let over = diagnostics_summary("t", "o", &findings(MAX_ROWS + 1), "failed", None);
        assert_eq!(rows(&over), MAX_ROWS);
        assert!(over.ends_with("\n… and 1 more in the job log.\n"), "{over}");
    }
}
