//! The pages behind `opentide explain <code>` (`cli/services/explain.py`).
//!
//! One Markdown page per diagnostic code and per `failure.code` lives in
//! `src/opentide/data/diagnostics/`, compiled in by `build.rs`. The analysis
//! engine's codes get a page built from the engine's own sentence
//! (`opentide_core::codes::describe`); a file of the same name wins. A code
//! nothing reports any more keeps a page that says so ([`RETIRED`]).

use crate::render::report::{RuleCatalogue, RulePage};

mod pages {
    include!(concat!(env!("OUT_DIR"), "/explain_pages.rs"));
}

/// A code's page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    /// The code.
    pub code: String,
    /// The first paragraph: what the code means, in one sentence.
    pub summary: String,
    /// The whole page.
    pub markdown: String,
    /// Whether nothing reports the code any more.
    pub retired: bool,
}

/// A code nothing reports any more, which stays explainable.
#[derive(Clone, Copy, Debug)]
pub struct Retired {
    /// The code.
    pub code: &'static str,
    /// The release that stopped reporting it.
    pub retired_in: &'static str,
    /// What reports the problem now, a Markdown sentence fragment.
    pub successor: &'static str,
    /// What the code reported.
    pub meaning: &'static str,
    /// Who reported it and where.
    pub reported_by: &'static str,
    /// A command that shows what reports the problem now.
    pub example: &'static str,
    /// Its severity while it was reported.
    pub level: &'static str,
}

/// The retired codes, as the Python CLI listed them (`retired_codes.py`) until UC-6.2.
pub const RETIRED: &[Retired] = &[
    Retired {
        code: "crowdstrike_unsupported",
        retired_in: "engine 0.12.0",
        successor: "CrowdStrike queries are now checked as CQL: see the `cql_*` codes",
        meaning: "CrowdStrike queries were not validated, and the engine said so rather than \
            fake it.",
        reported_by: "Until engine 0.12.0, the analysis engine reported it as a warning on a \
            CrowdStrike rule's `crowdstrike` block: an editor running `opentide lsp start` and \
            `opentide tui` showed it. Engine 0.12.0 checks the query as the CrowdStrike Query \
            Language (CQL) instead, and reports what it finds with the `cql_*` codes \
            (`opentide explain` lists them). No command reports `crowdstrike_unsupported` now.",
        example: "opentide explain cql_unknown_function",
        level: "warning",
    },
    Retired {
        code: "filename_slug",
        retired_in: "opentide 0.24.0",
        successor: "`opentide lint` reports a file name that is not the object's as \
            `filename_mismatch`",
        meaning: "The file name was not the one `lint.toml`'s `[filenames]` style derives from \
            the object's name.",
        reported_by: "Until opentide 0.24.0, the language server reported it as a warning on an \
            object's `name`, with a looser rule than `opentide lint` (any stem that started with \
            the slug passed). The editor now reports what `opentide validate` reports, and \
            `opentide lint` keeps the one file-name rule, `filename_mismatch` (KG-03).",
        example: "opentide lint --check filenames",
        level: "warning",
    },
    Retired {
        code: "missing_author",
        retired_in: "opentide 0.24.0",
        successor: "`opentide lint` reports a missing recommended metadata field as \
            `metadata_recommended`",
        meaning: "The recommended `metadata.author` field was missing.",
        reported_by: "Until opentide 0.24.0, the language server reported it as a warning on \
            every object without an author, where `opentide validate` reported nothing and \
            `opentide lint` reported `metadata_recommended` (KG-05).",
        example: "opentide lint --check metadata",
        level: "warning",
    },
    Retired {
        code: "missing_organisation",
        retired_in: "opentide 0.24.0",
        successor: "`opentide lint` reports a missing recommended metadata field as \
            `metadata_recommended`",
        meaning: "The recommended `metadata.organisation` field was missing.",
        reported_by: "Until opentide 0.24.0, the language server reported it as a warning on \
            every object without an organisation, where `opentide validate` reported nothing \
            and `opentide lint` reported `metadata_recommended` (KG-05).",
        example: "opentide lint --check metadata",
        level: "warning",
    },
];

/// The engine's advisories on an Elastic rule block (`ELASTIC_ADVISORY_CODES`).
pub const ELASTIC_ADVISORY_CODES: [&str; 5] = [
    "lookback_zero",
    "lookback_long",
    "threshold_lookback",
    "risk_band",
    "technique_not_enterprise",
];

/// The engine's advisories on a Sysdig rule block (`SYSDIG_ADVISORY_CODES`).
pub const SYSDIG_ADVISORY_CODES: [&str; 1] = ["sysdig_list_self_reference"];

/// Where an engine code is reported, for the codes whose reporter is not the
/// one its kind implies: block advisories on a query, the Sysdig block's model
/// constraints that `validate` names in its `schema_validation`, and since
/// UC-2.6 the editor's share of each (`docs/cli/diagnostics.md` held them by
/// hand until the reference was generated again).
const ENGINE_REPORTED_BY: &[(&str, &str)] = &[
    (
        "falco_exception",
        "Reported by the analysis engine on the Sysdig block's `exceptions`, with the condition's findings, since Falco appends them to the condition when it loads the rule: as an error, an exception Falco would reject, by `opentide validate` (its `queries` check); as a warning, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both. An exception whose shape the model refuses (fields, comps and values that do not align) is `sysdig_exception_shape` instead, which `validate` names in its `schema_validation` finding: Falco's checks leave that exception to it.",
    ),
    (
        "falco_unknown_rule",
        "Reported by the analysis engine on the Sysdig block's `append_to_rule`, as a warning: `opentide lint` (its `queries` check) shows it. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
    (
        "falco_unknown_source",
        "Reported by the analysis engine on the Sysdig block's `source`, as a warning, with the condition's findings (its fields go unchecked): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it.",
    ),
    (
        "lookback_long",
        "Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
    (
        "lookback_zero",
        "Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
    (
        "risk_band",
        "Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
    (
        "sysdig_definition_duplicate",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_definition_name",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_definition_order",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_exception_shape",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_list_in_value",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_priority",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_rule_shape",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_source",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "sysdig_tuning_keys",
        "Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.",
    ),
    (
        "technique_not_enterprise",
        "Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
    (
        "threshold_lookback",
        "Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.",
    ),
];

/// The first paragraph that is not a heading, its whitespace collapsed.
fn summary_of(markdown: &str) -> String {
    markdown
        .split("\n\n")
        .map(str::trim)
        .find(|block| !block.is_empty() && !block.starts_with('#'))
        .map(|block| block.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

/// Every code that has a page, the engine's and the retired ones included, sorted.
pub fn codes() -> Vec<&'static str> {
    let mut codes: Vec<&'static str> = pages::PAGES.iter().map(|(code, _)| *code).collect();
    codes.extend(opentide_core::codes::ALL.iter().copied());
    codes.extend(RETIRED.iter().map(|retired| retired.code));
    codes.sort_unstable();
    codes.dedup();
    codes
}

/// The page for `code` (in any case), or `None` when there is none.
pub fn page(code: &str) -> Option<Page> {
    let code = code.trim().to_lowercase();
    if code.is_empty() || code.contains(['/', '\\']) || code == "." || code == ".." {
        return None;
    }
    if let Some((code, markdown)) = pages::PAGES.iter().find(|(name, _)| *name == code) {
        return Some(file_page(code, markdown));
    }
    engine_page(&code).or_else(|| {
        RETIRED
            .iter()
            .find(|retired| retired.code == code)
            .map(retired_page)
    })
}

/// A page from a file of `src/opentide/data/diagnostics/`, its line endings
/// made LF: a checkout that converted the file to CRLF (Windows) builds a
/// binary whose summary and Markdown are the same as an LF checkout's.
fn file_page(code: &str, markdown: &str) -> Page {
    let markdown = markdown.replace("\r\n", "\n");
    Page {
        code: code.to_owned(),
        summary: summary_of(&markdown),
        markdown,
        retired: false,
    }
}

/// Every page, in code order.
pub fn all() -> Vec<Page> {
    codes().into_iter().filter_map(page).collect()
}

/// Where a query code is reported. A code the engine only ever warns about
/// (opentide-yara's `WARNING_CODES`, #1015) never fails `opentide validate`.
fn query_reported_by(code: &str, article: &str, language: &str) -> String {
    if opentide_yara::always_warning(code) {
        format!(
            "Reported by the analysis engine in {article} {language} query, at the place in \
             the query, always as a warning: the platform takes the rule, so `opentide \
             validate` does not fail on it, and `opentide lint` (its `queries` check) and an \
             editor running `opentide lsp start` show it."
        )
    } else {
        format!(
            "Reported by the analysis engine in {article} {language} query, at the place in \
             the query: as an error, a query the platform would reject, by `opentide \
             validate` (its `queries` check) and `opentide validate query`; as a warning or \
             a note, style, by `opentide lint` (its `queries` check). An editor running \
             `opentide lsp start` shows both."
        )
    }
}

/// The example command of a query code's page: `lint` shows a warning-only
/// code, `validate query` any other.
fn query_example(code: &str) -> &'static str {
    if opentide_yara::always_warning(code) {
        "opentide lint --check queries"
    } else {
        "opentide validate query"
    }
}

/// A page for an analysis-engine code, from the engine's sentence.
fn engine_page(code: &str) -> Option<Page> {
    let sentence = opentide_core::codes::describe(code)?;
    let (where_, example, fix) =
        if let Some((language, url)) = crate::render::codeframe::engine_reference(code) {
            let article = if language.starts_with(['A', 'E', 'I', 'O', 'U']) {
                "an"
            } else {
                "a"
            };
            (
                query_reported_by(code, article, language),
                query_example(code),
                format!(
                    "Change the query where the frame points, then run `opentide validate query` \
                 (`--file` for one rule or query file) or `opentide lint --check queries` \
                 again. The [{language} reference]({url}) describes the syntax and the \
                 commands the engine checks against."
                ),
            )
        } else if ELASTIC_ADVISORY_CODES.contains(&code) {
            (
                "Reported by the analysis engine on an Elastic rule block (elastic-1.0): \
             `opentide lint` (its `queries` check) and an editor running `opentide lsp start` \
             show it, and `opentide validate query --platform elastic --live` checks the same \
             settings."
                    .to_owned(),
                "opentide lint --check queries",
                "Change the block's setting the frame points at, then run \
             `opentide lint --check queries` again."
                    .to_owned(),
            )
        } else if SYSDIG_ADVISORY_CODES.contains(&code) {
            (
                "Reported by the analysis engine on a Sysdig rule block (sysdig-1.0): \
             `opentide lint` (its `queries` check) and an editor running `opentide lsp start` \
             show it. It is an advisory: Falco loads the rule, and `opentide validate` does \
             not fail on it."
                    .to_owned(),
                "opentide lint --check queries",
                "Change the block's macros or lists where the frame points, then run \
             `opentide lint --check queries` again."
                    .to_owned(),
            )
        } else {
            (
                "Reported by the analysis engine for an object file: an editor running \
             `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the \
             authority for objects and name the same problem with their own code."
                    .to_owned(),
                "opentide validate",
                "Change the file where the frame points, then run `opentide validate` again."
                    .to_owned(),
            )
        };
    let where_ = ENGINE_REPORTED_BY
        .iter()
        .find(|(name, _)| *name == code)
        .map_or(where_, |(_, reported_by)| (*reported_by).to_owned());
    let markdown = format!(
        "# {code}\n\n{sentence}\n\n{where_}\n\n## Example\n\n```text\n{example}\n```\n\n\
         ## How to fix\n\n{fix}\n"
    );
    Some(Page {
        code: code.to_owned(),
        summary: sentence.to_owned(),
        markdown,
        retired: false,
    })
}

/// The page of a code nothing reports any more.
fn retired_page(retired: &Retired) -> Page {
    let summary = format!("Retired in {}; {}.", retired.retired_in, retired.successor);
    let markdown = format!(
        "# {}\n\n{summary}\n\nSeverity: {}, while it was reported. {}\n\n{}\n\n\
         ## Example\n\n```text\n{}\n```\n\n## How to fix\n\nNothing to fix: no command \
         reports this code any more. A suppression list or SARIF baseline that names it can \
         drop it.\n",
        retired.code, retired.level, retired.meaning, retired.reported_by, retired.example
    );
    Page {
        code: retired.code.to_owned(),
        summary,
        markdown,
        retired: true,
    }
}

/// The lines of `docs/cli/diagnostics.md` above the table of codes.
const REFERENCE_HEAD: &[&str] = &[
    "---",
    "title: Diagnostic codes",
    "description: What each opentide diagnostic code means, an example, and how to fix it.",
    "---",
    "",
    "<!-- Generated from src/opentide/data/diagnostics/ and the analysis engine's codes by",
    "     `cargo xtask codegen`. Edit the pages there. -->",
    "",
    "# Diagnostic codes",
    "",
    "Every finding `opentide validate` and `opentide lint` report carries a stable `code`, \
     and every command that fails sets a `failure.code` \
     ([JSON output](./json-output.md#failure-codes)). \
     `opentide explain <code>` prints the page for either; this reference collects them all. \
     `opentide explain` with no code lists the codes.",
    "",
    "| Code | Meaning |",
    "|------|---------|",
];

/// `docs/cli/diagnostics.md` (`reference_markdown`): a table of every code
/// and its summary, then every page with its headings one level down. A
/// `text` fence that does not hold a command is marked `illustrative`, so
/// the docs check does not run it; prose is made safe for MDX
/// ([`mdx_prose`]). `cargo xtask codegen` writes it.
pub fn reference_markdown() -> String {
    let pages = all();
    let mut lines: Vec<String> = REFERENCE_HEAD
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    lines.extend(pages.iter().map(|page| {
        format!(
            "| [`{code}`](#{code}) | {} |",
            mdx_prose(&page.summary),
            code = page.code
        )
    }));
    for page in &pages {
        lines.push(String::new());
        let source: Vec<&str> = page.markdown.trim_end_matches('\n').lines().collect();
        let mut in_fence = false;
        for (index, line) in source.iter().enumerate() {
            if line.starts_with("```") {
                in_fence = !in_fence;
                let following = source.get(index + 1).copied().unwrap_or_default();
                if in_fence && *line == "```text" && !following.starts_with("opentide ") {
                    // Output an example shows, not a command the docs check could run.
                    lines.push("```text illustrative".to_owned());
                    continue;
                }
                lines.push((*line).to_owned());
            } else if in_fence {
                lines.push((*line).to_owned());
            } else {
                let line = mdx_prose(line);
                if line.starts_with('#') {
                    lines.push(format!("#{line}"));
                } else {
                    lines.push(line);
                }
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `line` with each `<` that cannot open a tag written `&lt;`, code spans
/// left alone (`_mdx_prose`). opentide.org renders the docs as MDX, which
/// reads `<=>` in prose as a broken tag and refuses the page. The engine's
/// sentences are plain text, so the reference escapes them, not the engine,
/// and `opentide explain` prints them as they are.
pub fn mdx_prose(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '`' {
            let end = code_span_end(&chars, index);
            let run = end.unwrap_or_else(|| backtick_run_end(&chars, index));
            out.extend(&chars[index..run]);
            index = run;
            continue;
        }
        let opens_tag = chars
            .get(index + 1)
            .is_some_and(|next| next.is_ascii_alphabetic() || matches!(next, '/' | '!' | '>'));
        if character == '<' && !opens_tag {
            out.push_str("&lt;");
        } else {
            out.push(character);
        }
        index += 1;
    }
    out
}

/// The index after the run of backticks that starts at `start`.
fn backtick_run_end(chars: &[char], start: usize) -> usize {
    chars[start..]
        .iter()
        .position(|character| *character != '`')
        .map_or(chars.len(), |offset| start + offset)
}

/// The end of the code span that opens at `start` (a run of backticks, at
/// least one other character, then a run of backticks), or `None` when no
/// backtick closes it: the regex `` `+(?:(?!`).)+?`+ `` of the oracle.
fn code_span_end(chars: &[char], start: usize) -> Option<usize> {
    let content = backtick_run_end(chars, start);
    let close = content + chars[content..].iter().position(|c| *c == '`')?;
    (close > content).then(|| backtick_run_end(chars, close))
}

/// Every code `validate` and `lint` can emit, and every code with a page
/// (`rule_codes`), as the SARIF driver lists them.
pub fn rule_catalogue() -> RuleCatalogue {
    let mut codes: Vec<String> = codes().into_iter().map(str::to_owned).collect();
    codes.extend(
        opentide_workspace::validate::VALIDATION_CODES
            .iter()
            .map(|code| (*code).to_owned()),
    );
    codes.extend(
        opentide_workspace::lint::LINT_CODES
            .iter()
            .map(|code| (*code).to_owned()),
    );
    codes.sort();
    codes.dedup();
    RuleCatalogue {
        rules: codes
            .into_iter()
            .map(|code| match page(&code) {
                Some(page) => RulePage {
                    code,
                    retired: page.retired,
                    summary: Some(page.summary),
                    markdown: Some(page.markdown),
                },
                None => RulePage {
                    code,
                    retired: false,
                    summary: None,
                    markdown: None,
                },
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_page_wins_and_summarises_its_first_paragraph() {
        let page = page("VOCAB_UNKNOWN").unwrap();
        assert_eq!(page.code, "vocab_unknown");
        assert_eq!(
            page.summary,
            "A value is not in the vocabulary its field uses."
        );
        assert!(page.markdown.starts_with("# vocab_unknown\n"));
        assert!(!page.retired);
    }

    #[test]
    fn a_crlf_page_is_the_lf_page() {
        let (code, markdown) = pages::PAGES
            .iter()
            .find(|(name, _)| *name == "vocab_unknown")
            .unwrap();
        let lf = file_page(code, &markdown.replace("\r\n", "\n"));
        let crlf = file_page(code, &lf.markdown.replace('\n', "\r\n"));
        assert_eq!(crlf, lf);
        assert_eq!(
            crlf.summary,
            "A value is not in the vocabulary its field uses."
        );
        assert!(!crlf.markdown.contains('\r'));
        let terminal = crate::commands::Terminal::plain(crate::mode::Mode::Human);
        assert_eq!(
            crate::commands::explain::render_markdown(&crlf.markdown, &terminal),
            crate::commands::explain::render_markdown(&lf.markdown, &terminal)
        );
    }

    #[test]
    fn engine_and_retired_codes_have_pages() {
        let kql = page("kql_unknown_table").unwrap();
        assert!(kql.markdown.contains("in a KQL query"), "{}", kql.markdown);
        assert!(
            kql.markdown
                .contains("```text\nopentide validate query\n```")
        );
        let retired = page("crowdstrike_unsupported").unwrap();
        assert!(retired.retired);
        assert!(retired.summary.starts_with("Retired in engine 0.12.0; "));
        assert!(
            retired
                .markdown
                .contains("Severity: warning, while it was reported.")
        );
        assert_eq!(page("../vocab_unknown"), None);
        assert_eq!(page("no_such_code"), None);
        assert_eq!(page(""), None);
    }

    /// `recommended_field_missing` is lint's again (opentide 0.28.1, #1028):
    /// a live page, not a retired one, that says it is a note.
    #[test]
    fn recommended_field_missing_is_lints_recommended_check() {
        let live = page("recommended_field_missing").unwrap();
        assert!(!live.retired);
        assert!(
            live.markdown.contains("Severity: note."),
            "{}",
            live.markdown
        );
        assert!(live.markdown.contains("`[recommended]`"));
        assert!(
            !RETIRED
                .iter()
                .any(|retired| retired.code == "recommended_field_missing")
        );
        assert!(codes().contains(&"recommended_field_missing"));
        let metadata = page("metadata_recommended").unwrap();
        assert!(metadata.markdown.contains("prints only with `--verbose`"));
    }

    /// A code the language server stopped reporting keeps its page and its
    /// SARIF rule, tagged retired: a suppression list or baseline may name
    /// it (the Upgrade notes send users to `opentide explain filename_slug`).
    #[test]
    fn the_editors_retired_codes_stay_explainable() {
        let catalogue = rule_catalogue();
        for (code, successor) in [
            ("filename_slug", "`filename_mismatch`"),
            ("missing_author", "`metadata_recommended`"),
            ("missing_organisation", "`metadata_recommended`"),
        ] {
            let page = page(code).unwrap_or_else(|| panic!("{code}: no page"));
            assert!(page.retired, "{code}");
            assert!(
                page.summary.starts_with("Retired in opentide 0.24.0; ")
                    && page.summary.contains(successor),
                "{code}: {}",
                page.summary
            );
            assert!(codes().contains(&code), "{code}");
            assert!(
                catalogue
                    .rules
                    .iter()
                    .any(|rule| rule.code == code && rule.retired),
                "{code}: not a retired SARIF rule"
            );
        }
    }

    /// `build.rs` compiles in every page of the package's folder.
    #[test]
    fn every_page_of_the_package_is_compiled_in() {
        let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../src/opentide/data/diagnostics");
        let mut on_disk: Vec<String> = std::fs::read_dir(folder)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                (path.extension().and_then(|ext| ext.to_str()) == Some("md"))
                    .then(|| path.file_stem().unwrap().to_string_lossy().into_owned())
            })
            .collect();
        on_disk.sort();
        let compiled: Vec<&str> = pages::PAGES.iter().map(|(code, _)| *code).collect();
        assert!(compiled.len() > 100, "{}", compiled.len());
        assert_eq!(compiled, on_disk);
    }

    /// The engine's sentence for this code names the CQL operator `<=>` in
    /// plain prose; MDX on opentide.org reads it as a broken tag and refuses
    /// the whole docs sync (0.24.1, #897). `opentide explain` keeps it.
    #[test]
    fn the_reference_escapes_a_bare_angle_bracket_for_mdx() {
        let reference = reference_markdown();
        let row = reference
            .lines()
            .find(|line| line.starts_with("| [`cql_link_outside_correlate`]"))
            .unwrap();
        assert!(row.contains("&lt;=>"), "{row}");
        assert!(!row.contains("<=>"), "{row}");
        assert!(
            page("cql_link_outside_correlate")
                .unwrap()
                .markdown
                .contains("<=>")
        );
    }

    #[test]
    fn mdx_prose_leaves_code_spans_tags_and_comments_alone() {
        for (line, expected) in [
            ("a <=> b", "a &lt;=> b"),
            ("x < 3 and y<", "x &lt; 3 and y&lt;"),
            ("`<=>` and ``a ` <b``", "`<=>` and ``a ` <b``"),
            ("<Tab> </Tab> <!-- c --> <>", "<Tab> </Tab> <!-- c --> <>"),
            ("an `unclosed <= span", "an `unclosed &lt;= span"),
            ("``", "``"),
            ("é < ü", "é &lt; ü"),
        ] {
            assert_eq!(mdx_prose(line), expected, "{line}");
        }
    }

    #[test]
    fn the_reference_holds_every_page_its_headings_one_level_down() {
        let reference = reference_markdown();
        assert!(reference.starts_with("---\ntitle: Diagnostic codes\n"));
        assert!(reference.ends_with('\n') && !reference.ends_with("\n\n"));
        for code in codes() {
            assert!(
                reference.contains(&format!("\n## {code}\n")),
                "{code}: no section"
            );
            assert!(
                reference.contains(&format!("| [`{code}`](#{code}) | ")),
                "{code}: no row"
            );
        }
        assert!(!reference.contains("\n# vocab_unknown\n"));
        assert!(reference.contains("\n### How to fix\n"));
        // Output an example shows is marked, a command is not.
        assert!(reference.contains("```text illustrative\n"));
        assert!(reference.contains("```text\nopentide validate query\n```"));
    }

    /// The generic query page says a code fails `opentide validate`; the
    /// engine only ever warns on these (opentide-yara's `WARNING_CODES`), so
    /// their pages say so (#1015). `harfanglab_yara_context`, the sixth, has
    /// no query reference: its page is the block's.
    #[test]
    fn a_warning_only_yara_code_is_not_described_as_an_error() {
        for code in [
            "yara_entrypoint_deprecated",
            "yara_meta_missing",
            "yara_module_unconfirmed",
            "yara_slow_pattern",
            "yara_suspicious_expression",
        ] {
            assert!(opentide_yara::always_warning(code), "{code}");
            let page = page(code).unwrap_or_else(|| panic!("{code}: no page"));
            assert!(page.markdown.contains("in a YARA rule query"), "{code}");
            assert!(page.markdown.contains("always as a warning"), "{code}");
            assert!(
                page.markdown
                    .contains("`opentide validate` does not fail on it"),
                "{code}"
            );
            assert!(!page.markdown.contains("as an error"), "{code}");
            assert!(
                page.markdown
                    .contains("```text\nopentide lint --check queries\n```"),
                "{code}"
            );
        }
    }

    #[test]
    fn a_yara_error_keeps_the_generic_query_page() {
        for code in ["yara_unknown_module", "yara_x_incompatible"] {
            let page = page(code).unwrap();
            assert!(
                page.markdown
                    .contains("as an error, a query the platform would reject"),
                "{code}"
            );
            assert!(
                page.markdown
                    .contains("```text\nopentide validate query\n```"),
                "{code}"
            );
        }
    }

    /// Each override names an engine code, and its page says it.
    #[test]
    fn engine_reporters_name_engine_codes() {
        for (code, reported_by) in ENGINE_REPORTED_BY {
            assert!(opentide_core::codes::describe(code).is_some(), "{code}");
            assert!(
                !pages::PAGES.iter().any(|(name, _)| name == code),
                "{code}: a file page wins over the override"
            );
            assert!(page(code).unwrap().markdown.contains(reported_by), "{code}");
        }
        assert!(
            ENGINE_REPORTED_BY
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
        );
    }

    #[test]
    fn codes_are_sorted_and_unique() {
        let codes = codes();
        assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(codes.contains(&"yaml_parse"));
        assert!(codes.contains(&"crowdstrike_unsupported"));
        let catalogue = rule_catalogue();
        assert!(
            catalogue
                .rules
                .iter()
                .any(|rule| rule.code == "filename_mismatch")
        );
    }
}
