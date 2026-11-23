//! Markdown for CI job summaries: findings, a deploy plan, query validation results.
//!
//! [`super::ci::append_summary`] writes what these build. Each summary is a
//! `###` heading with the outcome glyph and the command, the outcome line, then
//! a table. Tables stop at [`MAX_ROWS`] (the job log and the report files keep
//! the rest), and a summary at [`MAX_SUMMARY_BYTES`] ([`fit`]). User text is
//! escaped so it shows as written ([`cell`], [`code`]).

use super::diagnostic::{Diagnostic, sort_diagnostics};
use crate::json::{Json, Object};
use std::sync::LazyLock;

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
    // Markdown ends a line at `\n`, `\r\n` and a lone `\r`: each would end
    // the table row.
    let joined = escaped
        .lines()
        .flat_map(|line| line.split('\r'))
        .map(str::trim)
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

/// The string at `key` of an object, or `""`.
fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).unwrap_or_default()
}

/// The items of the array at `key` of an object; none when it is not an array.
fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_array)
        .map_or(&[], Vec::as_slice)
}

/// What [`members`] reads when there is no object.
static NO_MEMBERS: LazyLock<Object> = LazyLock::new(Object::new);

/// The members of the object at `key` of an object; none when it is not an object.
fn members<'a>(value: &'a Json, key: &str) -> &'a Object {
    value
        .get(key)
        .and_then(Json::as_object)
        .unwrap_or(&NO_MEMBERS)
}

/// The strings of an array, skipping anything else.
fn strings(items: &[Json]) -> impl Iterator<Item = &str> {
    items.iter().filter_map(Json::as_str)
}

/// The number of items of an array, `0` for anything else.
fn len(value: &Json) -> usize {
    value.as_array().map_or(0, Vec::len)
}

fn status_kind(result: &Json) -> &'static str {
    let status = text(result, "status");
    if status == "failed" || result.get("ok").and_then(Json::as_bool) == Some(false) {
        return "failed";
    }
    if status == "skipped" {
        return "skipped";
    }
    if !array(result, "warnings").is_empty() {
        return "warning";
    }
    "ok"
}

/// The first `lines` lines of `text`, at most `chars` characters, with ` …` when cut.
pub fn shorten(text: &str, lines: usize, chars: usize) -> String {
    let full = text.trim();
    let mut kept = full.lines().take(lines).collect::<Vec<_>>().join("\n");
    if kept.chars().count() > chars {
        let cut: String = kept.chars().take(chars.saturating_sub(1)).collect();
        cut.trim_end().clone_into(&mut kept);
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
    for line in markdown.lines() {
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
    let strategies = array(result, "strategies");
    if !strategies.is_empty() {
        let named: Vec<String> = strings(strategies).map(code).collect();
        lines.push(String::new());
        lines.push(format!("Strategies: {}", named.join(", ")));
    }
}

fn message_line(result: &Json, message: Option<&str>) -> String {
    match message.filter(|message| !message.is_empty()) {
        Some(message) => cell(message),
        None => cell(text(result, "message")),
    }
}

fn rule_line(uuid: &str, entry: Option<&Json>) -> String {
    let Some(entry) = entry.filter(|entry| !text(entry, "name").is_empty()) else {
        return format!("- {}", code(uuid));
    };
    let mut line = format!("- {} ({})", cell(text(entry, "name")), code(uuid));
    let error = text(entry, "error");
    if text(entry, "status") == "failed" && !error.is_empty() {
        line.push_str(&format!(
            " — would fail: {}",
            cell(&shorten(error, MAX_ERROR_LINES, MAX_ERROR_CHARS))
        ));
    }
    line
}

/// The deploy plan: rules per platform and tenant, then the rules themselves.
/// `dry_run` is the command's flag; a payload from a deploy that failed early
/// may not carry it.
pub fn deploy_summary(result: &Json, message: Option<&str>, dry_run: Option<bool>) -> String {
    let dry_run =
        dry_run.unwrap_or_else(|| result.get("dry_run").and_then(Json::as_bool) == Some(true));
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
    let plan = members(result, "plan");
    let failures = array(result, "failures");
    if plan.is_empty() {
        failure_lines(failures, &mut lines);
        return lines.join("\n") + "\n";
    }
    let rows = platform_rows(result, plan, failures, dry_run);
    lines.push(String::new());
    let header: [&str; 3] = if dry_run {
        ["Platform", "Tenant", "Rules"]
    } else {
        ["Platform", "Result", "Rules"]
    };
    let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
    lines.extend(table(&header, &shown, rows.len()));
    failure_lines(failures, &mut lines);
    let payloads = members(result, "payloads");
    for (platform, uuids) in plan {
        let entries: &[Json] = payloads
            .get(platform)
            .and_then(Json::as_array)
            .map_or(&[], Vec::as_slice);
        let named = |uuid: &str| -> Option<&Json> {
            entries
                .iter()
                .rev()
                .find(|entry| entry.get("uuid").and_then(Json::as_str) == Some(uuid))
        };
        let uuids = uuids.as_array().map_or(&[][..], Vec::as_slice);
        let count = uuids.len();
        let noun = if count == 1 { "rule" } else { "rules" };
        // An HTML block: Markdown escapes would show, so HTML escaping only.
        lines.push(String::new());
        lines.push(format!(
            "<details><summary>{}: {count} {noun}</summary>",
            html_escape(platform, true)
        ));
        lines.push(String::new());
        for uuid in strings(uuids).take(MAX_ROWS) {
            lines.push(rule_line(uuid, named(uuid)));
        }
        if count > MAX_ROWS {
            lines.push(format!("- … and {} more", count - MAX_ROWS));
        }
        lines.push(String::new());
        lines.push("</details>".to_owned());
    }
    lines.join("\n") + "\n"
}

/// One row per platform (per tenant in a dry run): its tenant or result,
/// and its rule count. A platform the run reached is `partly deployed` when
/// one of its rules failed and another was deployed (also when every
/// tenant failed, one of them after deploying a rule, so the platform is not
/// in `deployed`), `not deployed` when none was.
fn platform_rows(
    result: &Json,
    plan: &Object,
    failures: &[Json],
    dry_run: bool,
) -> Vec<Vec<String>> {
    let tenants = members(result, "tenants");
    let deployed: Vec<&str> = strings(array(result, "deployed")).collect();
    let failed_on = |platform: &str| {
        failures
            .iter()
            .any(|failure| failure.get("platform").and_then(Json::as_str) == Some(platform))
    };
    // A platform the run reached but on which no rule was deployed.
    let none_deployed = |platform: &str| {
        !array(result, "results").iter().any(|row| {
            row.get("platform").and_then(Json::as_str) == Some(platform)
                && row.get("status").and_then(Json::as_str) == Some("deployed")
        })
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    for (platform, uuids) in plan {
        let reach = tenants
            .get(platform)
            .and_then(Json::as_object)
            .unwrap_or(&NO_MEMBERS);
        match reach {
            reach if !reach.is_empty() => {
                for (tenant, rules) in reach {
                    rows.push(vec![code(platform), cell(tenant), len(rules).to_string()]);
                }
            }
            _ if dry_run => rows.push(vec![
                code(platform),
                "none".to_owned(),
                len(uuids).to_string(),
            ]),
            _ => {
                let done = match (deployed.contains(&platform.as_str()), failed_on(platform)) {
                    (true, false) => "deployed",
                    (true, true) if none_deployed(platform) => "not deployed",
                    (true, true) => "partly deployed",
                    // Every tenant failed, some after deploying rules.
                    (false, _) if !none_deployed(platform) => "partly deployed",
                    (false, _) => "not deployed",
                };
                rows.push(vec![
                    code(platform),
                    done.to_owned(),
                    len(uuids).to_string(),
                ]);
            }
        }
    }
    rows
}

/// Every failure of a deploy (`failures`): its platform, tenant, rule and
/// error, so a failed job says what failed without its log.
fn failure_lines(failures: &[Json], lines: &mut Vec<String>) {
    if failures.is_empty() {
        return;
    }
    let field =
        |failure: &Json, key: &str| failure.get(key).and_then(Json::as_str).map(str::to_owned);
    let rows: Vec<Vec<String>> = failures
        .iter()
        .map(|failure| {
            let rule = match (field(failure, "name"), field(failure, "id")) {
                (Some(name), Some(id)) if !name.is_empty() => {
                    format!("{} ({})", cell(&name), code(&id))
                }
                (_, Some(id)) => code(&id),
                _ => "every rule".to_owned(),
            };
            vec![
                field(failure, "platform")
                    .map_or_else(|| "every platform".to_owned(), |platform| code(&platform)),
                field(failure, "tenant")
                    .map_or_else(|| "every tenant".to_owned(), |tenant| cell(&tenant)),
                rule,
                cell(&field(failure, "error").unwrap_or_default()),
            ]
        })
        .collect();
    lines.push(String::new());
    let count = failures.len();
    lines.push(format!(
        "**{count} {}**",
        if count == 1 { "failure" } else { "failures" }
    ));
    lines.push(String::new());
    let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
    lines.extend(table(
        &["Platform", "Tenant", "Rule", "Error"],
        &shown,
        rows.len(),
    ));
}

/// Live query validation: queries sent per tenant, and the verdict.
pub fn query_summary(result: &Json, message: Option<&str>) -> String {
    let platform = text(result, "platform");
    let title = format!("opentide validate query --platform {platform}")
        .trim_end()
        .to_owned();
    let mut lines = vec![
        heading(status_kind(result), &title),
        String::new(),
        message_line(result, message),
    ];
    strategies_line(result, &mut lines);
    let reach = members(result, "queries_per_tenant");
    if !reach.is_empty() {
        let rows: Vec<Vec<String>> = reach
            .iter()
            .map(|(tenant, count)| {
                let count = count
                    .as_u64()
                    .map_or_else(String::new, |count| count.to_string());
                vec![cell(tenant), count]
            })
            .collect();
        lines.push(String::new());
        let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
        lines.extend(table(&["Tenant", "Queries"], &shown, rows.len()));
    }
    rejected_table(result, &mut lines);
    lines.join("\n") + "\n"
}

/// The queries a tenant rejected: the rule's file and line, the tenant and
/// the platform's reason.
fn rejected_table(result: &Json, lines: &mut Vec<String>) {
    let Some(Json::Array(items)) = result.get("rejected") else {
        return;
    };
    if items.is_empty() {
        return;
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let field = |key: &str| item.get(key).and_then(Json::as_str).unwrap_or_default();
            let place = match (field("file"), item.get("line").and_then(Json::as_u64)) {
                ("", _) => field("name").to_owned(),
                (file, Some(line)) => format!("{file}:{line}"),
                (file, None) => file.to_owned(),
            };
            vec![
                cell(&place),
                cell(field("tenant")),
                cell(&shorten(field("message"), 3, 300)),
            ]
        })
        .collect();
    lines.push(String::new());
    lines.push("**Rejected queries**".to_owned());
    lines.push(String::new());
    let shown: Vec<Vec<String>> = rows.iter().take(MAX_ROWS).cloned().collect();
    lines.extend(table(&["Rule", "Tenant", "Reason"], &shown, rows.len()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(cell("<x> & *y*"), "&lt;x&gt; &amp; \\*y\\*");
        assert_eq!(cell(""), " ");
        assert_eq!(cell(" a \n b "), "a<br>b");
        assert_eq!(cell("a\r\nb\rc\t"), "a<br>b<br>c");
        assert_eq!(code("a`b"), "``a`b``");
        assert_eq!(code("`x`"), "`` `x` ``");
        assert_eq!(heading("plan", "t"), "### t");
        assert_eq!(shorten("a\nb\nc", 2, 300), "a\nb …");
        assert_eq!(shorten(" a\r\nb\r\nc\n", 2, 300), "a\nb …");
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
    fn a_dry_run_summary_reads_the_plan_tenants_and_payloads() {
        let result = Json::parse(
            r#"{
              "dry_run": true, "status": "failed", "ok": false,
              "message": "Plan: 1 to create", "strategies": ["PREVIEW", 7],
              "plan": {"sentinel": ["u1", "u2"], "splunk": ["u3"]},
              "tenants": {"sentinel": {"prod": ["u1", "u2"], "dev": ["u1"]}},
              "payloads": {"sentinel": [
                {"uuid": "u1", "name": "Rule <one>", "status": "failed", "error": "bad\nduration"},
                {"uuid": "u2", "name": ""}
              ]}
            }"#,
        )
        .unwrap();
        let summary = deploy_summary(&result, None, None);
        assert_eq!(
            summary,
            "### ✗ opentide deploy --dry-run\n\nPlan: 1 to create\n\nStrategies: `PREVIEW`\n\n\
             | Platform | Tenant | Rules |\n|---|---|---|\n\
             | `sentinel` | prod | 2 |\n| `sentinel` | dev | 1 |\n| `splunk` | none | 1 |\n\n\
             <details><summary>sentinel: 2 rules</summary>\n\n\
             - Rule &lt;one&gt; (`u1`) — would fail: bad<br>duration\n- `u2`\n\n</details>\n\n\
             <details><summary>splunk: 1 rule</summary>\n\n- `u3`\n\n</details>\n"
        );
        // A real run says which platforms were deployed; `dry_run` false.
        let real = Json::parse(
            r#"{"dry_run": false, "status": "completed", "warnings": ["w"],
                "plan": {"sentinel": ["u1"], "splunk": ["u2"]}, "deployed": ["sentinel"]}"#,
        )
        .unwrap();
        let summary = deploy_summary(&real, Some("done"), None);
        assert!(
            summary.starts_with("### ! opentide deploy\n\ndone\n"),
            "{summary}"
        );
        assert!(summary.contains("| `sentinel` | deployed | 1 |\n| `splunk` | not deployed | 1 |"));
    }

    #[test]
    fn a_deploy_summary_lists_every_failure() {
        let result = Json::parse(
            r#"{"dry_run": false, "status": "failed", "message": "Deployment failed",
                "plan": {"sentinel": ["u1", "u2"], "crowdstrike": ["u3"], "splunk": ["u4"]},
                "deployed": ["sentinel", "splunk"],
                "results": [
                  {"platform": "sentinel", "id": "u1", "status": "deployed"},
                  {"platform": "sentinel", "id": "u2", "status": "failed"},
                  {"platform": "splunk", "id": "u4", "status": "failed"}
                ],
                "failures": [
                  {"platform": "sentinel", "tenant": "soc", "id": "u2", "name": "Rule <two>",
                   "error": "HTTP 400 | bad\nrequest"},
                  {"platform": "splunk", "tenant": "lab", "id": "u4", "name": "Four",
                   "error": "refused"},
                  {"id": "u5", "error": "external_id_in_rule: vendor ids"},
                  {"platform": "crowdstrike", "tenant": "lab", "error": "Cannot reach crowdstrike"},
                  {"platform": "exabeam", "error": "no plugin"}
                ]}"#,
        )
        .unwrap();
        let summary = deploy_summary(&result, None, None);
        assert!(
            summary.contains(
                "| `sentinel` | partly deployed | 2 |\n| `crowdstrike` | not deployed | 1 |\n\
                 | `splunk` | not deployed | 1 |"
            ),
            "{summary}"
        );
        assert!(
            summary.contains(
                "**5 failures**\n\n| Platform | Tenant | Rule | Error |\n|---|---|---|---|\n\
                 | `sentinel` | soc | Rule &lt;two&gt; (`u2`) | HTTP 400 \\| bad<br>request |\n\
                 | `splunk` | lab | Four (`u4`) | refused |\n\
                 | every platform | every tenant | `u5` | external\\_id\\_in\\_rule: vendor ids |\n\
                 | `crowdstrike` | lab | every rule | Cannot reach crowdstrike |\n\
                 | `exabeam` | every tenant | every rule | no plugin |\n"
            ),
            "{summary}"
        );
        // Every tenant failed, after one rule went out: the platform is not
        // in `deployed`, and it was partly deployed.
        let stopped = Json::parse(
            r#"{"dry_run": false, "status": "failed", "plan": {"graylog": ["u6", "u7"]},
                "deployed": [],
                "results": [
                  {"platform": "graylog", "id": "u6", "status": "deployed"},
                  {"platform": "graylog", "id": "u7", "status": "failed"}
                ],
                "failures": [{"platform": "graylog", "tenant": "lab", "id": "u7", "error": "401"}]}"#,
        )
        .unwrap();
        let summary = deploy_summary(&stopped, None, None);
        assert!(
            summary.contains("| `graylog` | partly deployed | 2 |"),
            "{summary}"
        );
        // A run without failures has no such section.
        let clean = Json::parse(
            r#"{"dry_run": false, "status": "completed", "plan": {"sentinel": ["u1"]},
                "deployed": ["sentinel"]}"#,
        )
        .unwrap();
        assert!(!deploy_summary(&clean, None, None).contains("failure"));
    }

    #[test]
    fn a_query_summary_counts_queries_per_tenant() {
        let result = Json::parse(
            r#"{"platform": "splunk", "status": "completed", "ok": true,
                "queries_per_tenant": {"prod": 2, "<dev>": 1}}"#,
        )
        .unwrap();
        assert_eq!(
            query_summary(&result, None),
            "### ✓ opentide validate query --platform splunk\n\n \n\n\
             | Tenant | Queries |\n|---|---|\n| prod | 2 |\n| &lt;dev&gt; | 1 |\n"
        );
    }

    #[test]
    fn a_query_summary_lists_the_rejected_queries_with_their_place() {
        let result = Json::parse(
            r#"{"platform": "splunk", "status": "failed", "message": "Queries rejected",
                "rejected": [{"name": "r", "tenant": "lab", "file": "rules/a.yaml", "line": 9,
                              "message": "Unknown search command 'bad'."}]}"#,
        )
        .unwrap();
        let markdown = query_summary(&result, None);
        assert!(markdown.contains("**Rejected queries**"), "{markdown}");
        assert!(
            markdown.contains("rules/a.yaml:9") && markdown.contains("Unknown search command"),
            "{markdown}"
        );
        let clean = Json::parse(r#"{"platform": "splunk", "status": "passed"}"#).unwrap();
        assert!(!query_summary(&clean, None).contains("Rejected"));
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
