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

/// A code nothing reports any more, which stays explainable
/// (`cli/services/retired_codes.py`).
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

/// The retired codes.
pub const RETIRED: &[Retired] = &[Retired {
    code: "crowdstrike_unsupported",
    retired_in: "engine 0.12.0",
    successor: "CrowdStrike queries are now checked as CQL: see the `cql_*` codes",
    meaning: "CrowdStrike queries were not validated, and the engine said so rather than fake it.",
    reported_by: "Until engine 0.12.0, the analysis engine reported it as a warning on a \
        CrowdStrike rule's `crowdstrike` block: an editor running `opentide lsp start` and \
        `opentide tui` showed it. Engine 0.12.0 checks the query as the CrowdStrike Query \
        Language (CQL) instead, and reports what it finds with the `cql_*` codes \
        (`opentide explain` lists them). No command reports `crowdstrike_unsupported` now.",
    example: "opentide explain cql_unknown_function",
    level: "warning",
}];

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

/// Engine codes about a Tide object, not a query.
const OBJECT_CODES: [&str; 4] = [
    "filename_slug",
    "filename_pattern",
    "missing_author",
    "missing_organisation",
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
        return Some(Page {
            code: (*code).to_owned(),
            summary: summary_of(markdown),
            markdown: (*markdown).to_owned(),
            retired: false,
        });
    }
    engine_page(&code).or_else(|| {
        RETIRED
            .iter()
            .find(|retired| retired.code == code)
            .map(retired_page)
    })
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
        let scope = if OBJECT_CODES.contains(&code) {
            "a Tide object"
        } else {
            "an object file"
        };
        (
            format!(
                "Reported by the analysis engine for {scope}: an editor running \
                 `opentide lsp start` shows it. `opentide validate` and `opentide lint` are \
                 the authority for objects and name the same problem with their own code."
            ),
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
