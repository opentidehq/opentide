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

/// A page for an analysis-engine code, from the engine's sentence.
fn engine_page(code: &str) -> Option<Page> {
    let sentence = opentide_core::codes::describe(code)?;
    let (where_, example, fix) = if let Some((language, url)) =
        crate::render::codeframe::engine_reference(code)
    {
        let article = if language.starts_with(['A', 'E', 'I', 'O', 'U']) {
            "an"
        } else {
            "a"
        };
        (
            format!(
                "Reported by the analysis engine in {article} {language} query, at the place in \
                 the query: as an error, a query the platform would reject, by `opentide \
                 validate` (its `queries` check) and `opentide validate query`; as a warning or \
                 a note, style, by `opentide lint` (its `queries` check). An editor running \
                 `opentide lsp start` shows both."
            ),
            "opentide validate query",
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
