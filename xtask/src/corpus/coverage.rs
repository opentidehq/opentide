//! The coverage report: every diagnostic code in scope (plan §5.3:
//! `VALIDATION_CODES`, `LINT_CODES`, the configuration codes and the query
//! codes) mapped to the fault kinds that produce it.
//!
//! The inventory, `tests/corpora/codes.toml`, is recorded from the oracle
//! (`cargo xtask corpus codes --engine python --write`), never written by
//! hand; `COVERAGE.md` is rendered from it and `faults.toml`.

use super::faults::Catalogue;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// The Python the oracle's interpreter runs to list the codes in scope.
pub const INVENTORY_SCRIPT: &str = r#"
import json
from opentide.analysis import engine_codes
from opentide.cli.services.validation import (
    VALIDATION_CODES, _CHECK_ISSUE_CODES, _CHECK_WARNING_CODES,
)
from opentide.cli.ui.diagnostics import LINT_CODES
from opentide.cli.services.explain import pages_root
configuration = set(_CHECK_ISSUE_CODES["configuration"]) | set(
    _CHECK_WARNING_CODES.get("configuration", ())
)
print(json.dumps({
    "validation": sorted(VALIDATION_CODES),
    "lint": sorted(set(LINT_CODES.values())),
    "configuration": sorted(configuration),
    "query": sorted(set(engine_codes())),
    "compile": sorted(p.stem for p in pages_root().glob("compile_*.md")),
}))
"#;

/// The five groups of codes, as the oracle lists them.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// `VALIDATION_CODES`.
    pub validation: Vec<String>,
    /// `LINT_CODES` values.
    pub lint: Vec<String>,
    /// The configuration check's issue and warning codes.
    pub configuration: Vec<String>,
    /// The analysis engine's codes (`opentide.analysis.engine_codes()`).
    pub query: Vec<String>,
    /// The compile check's codes (`compile_*` explain pages): `validate`
    /// reports them, though `VALIDATION_CODES` does not list them (KG-10).
    #[serde(default)]
    pub compile: Vec<String>,
}

const GROUPS: [&str; 5] = ["validation", "lint", "configuration", "query", "compile"];

impl Inventory {
    fn group(&self, name: &str) -> &[String] {
        match name {
            "validation" => &self.validation,
            "lint" => &self.lint,
            "configuration" => &self.configuration,
            "compile" => &self.compile,
            _ => &self.query,
        }
    }

    /// Every distinct code.
    pub fn all(&self) -> BTreeSet<&str> {
        GROUPS
            .iter()
            .flat_map(|g| self.group(g).iter().map(String::as_str))
            .collect()
    }

    /// The number of distinct codes.
    pub fn total(&self) -> usize {
        self.all().len()
    }
}

/// `tests/corpora/codes.toml`, as recorded.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Codes {
    /// The oracle it was recorded from.
    pub oracle: String,
    /// The groups.
    pub groups: Inventory,
}

impl Codes {
    /// Parses `codes.toml`.
    pub fn parse(text: &str) -> Result<Self> {
        let codes: Self = toml::from_str(text).context("codes.toml does not parse")?;
        if codes.groups.total() == 0 {
            bail!("codes.toml lists no code");
        }
        Ok(codes)
    }
}

/// Renders `codes.toml` from an inventory.
pub fn render_codes(inventory: &Inventory, oracle: &str) -> String {
    let mut out = format!(
        "# The diagnostic codes in scope for the fault catalogue (UC-0.6, plan §5.3),\n\
         # recorded from opentide {oracle} by\n\
         # `cargo xtask corpus codes --engine python --write`. Do not edit by hand.\n\
         oracle = \"{oracle}\"\n\n[groups]\n"
    );
    for group in GROUPS {
        let _ = writeln!(out, "{group} = [");
        for code in inventory.group(group) {
            let _ = writeln!(out, "    \"{code}\",");
        }
        out.push_str("]\n");
    }
    out
}

/// The coverage of each code.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Code → the kinds that expect it.
    pub kinds: BTreeMap<String, Vec<String>>,
    /// Code → why no kind can produce it.
    pub unreachable: BTreeMap<String, String>,
    /// Code → the groups it is in.
    pub groups: BTreeMap<String, Vec<&'static str>>,
    /// Codes with neither a kind nor an unreachable entry.
    pub missing: Vec<String>,
    /// Inconsistencies: an unreachable code a kind also produces, a code
    /// out of scope, the inventory recorded from another oracle.
    pub problems: Vec<String>,
}

impl Report {
    /// One line: how many codes, covered, unreachable, missing.
    pub fn summary(&self) -> String {
        let in_scope: Vec<&String> = self
            .groups
            .iter()
            .filter(|(_, groups)| !groups.is_empty())
            .map(|(code, _)| code)
            .collect();
        let extra = self.groups.len() - in_scope.len();
        format!(
            "corpus coverage: {} codes in scope, {} with a fault kind, {} unreachable through the CLI, {} missing, {} problems; {extra} more codes outside the scope have kinds",
            in_scope.len(),
            in_scope
                .iter()
                .filter(|c| self.kinds.contains_key(**c))
                .count(),
            self.unreachable.len(),
            self.missing.len(),
            self.problems.len()
        )
    }
}

/// Maps every code of `codes` to the kinds of `catalogue`.
pub fn report(codes: &Codes, catalogue: &Catalogue) -> Report {
    let mut report = Report::default();
    if codes.oracle != catalogue.oracle {
        report.problems.push(format!(
            "codes.toml is from opentide {}, faults.toml from {}",
            codes.oracle, catalogue.oracle
        ));
    }
    for group in GROUPS {
        for code in codes.groups.group(group) {
            report.groups.entry(code.clone()).or_default().push(group);
        }
    }
    for kind in &catalogue.kinds {
        for code in kind.codes.iter().chain(&kind.covers) {
            report
                .kinds
                .entry(code.clone())
                .or_default()
                .push(kind.id.clone());
            if !report.groups.contains_key(code) {
                // A code outside the five groups (a lint-only engine code is
                // in `query`); listed, not a problem.
                report.groups.entry(code.clone()).or_default();
            }
        }
    }
    for entry in &catalogue.unreachable {
        if report.kinds.contains_key(&entry.code) {
            report.problems.push(format!(
                "`{}` is declared unreachable but fault kinds produce it",
                entry.code
            ));
        }
        if !report.groups.contains_key(&entry.code) {
            report.problems.push(format!(
                "`{}` is declared unreachable but is not in scope",
                entry.code
            ));
        }
        if report
            .unreachable
            .insert(entry.code.clone(), entry.reason.clone())
            .is_some()
        {
            report
                .problems
                .push(format!("`{}` is declared unreachable twice", entry.code));
        }
    }
    report.missing = report
        .groups
        .iter()
        .filter(|(code, groups)| {
            !groups.is_empty()
                && !report.kinds.contains_key(*code)
                && !report.unreachable.contains_key(*code)
        })
        .map(|(code, _)| code.clone())
        .collect();
    report
}

/// Renders `COVERAGE.md`.
pub fn render(report: &Report, catalogue: &Catalogue) -> String {
    let mut out = String::from(
        "# Fault coverage\n\n\
         Generated by `cargo xtask corpus coverage --write` from `codes.toml` (the codes in \
         scope, recorded from the oracle) and `faults.toml`. Do not edit by hand; \
         `cargo xtask corpus coverage --check` fails when this file is stale or a code has \
         no fault kind.\n\n",
    );
    let _ = writeln!(out, "{}\n", report.summary());
    let classes: BTreeMap<&str, usize> =
        catalogue
            .kinds
            .iter()
            .fold(BTreeMap::new(), |mut counts, kind| {
                *counts.entry(kind.class.as_str()).or_default() += 1;
                counts
            });
    let files: usize = catalogue.kinds.iter().map(|k| k.count).sum();
    let _ = writeln!(
        out,
        "{} fault kinds ({}), applied to {files} target files in all.\n",
        catalogue.kinds.len(),
        classes
            .iter()
            .map(|(class, n)| format!("{n} {class}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !report.missing.is_empty() {
        let _ = writeln!(out, "## Missing\n");
        for code in &report.missing {
            let _ = writeln!(out, "- `{code}`");
        }
        out.push('\n');
    }
    if !report.problems.is_empty() {
        let _ = writeln!(out, "## Problems\n");
        for problem in &report.problems {
            let _ = writeln!(out, "- {problem}");
        }
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "## Codes\n\n| Code | Groups | Fault kinds | Files |\n|------|--------|-------------|-------|"
    );
    for (code, groups) in &report.groups {
        let groups = if groups.is_empty() {
            "-".to_string()
        } else {
            groups.join(", ")
        };
        let (kinds, files) = match report.kinds.get(code) {
            Some(kinds) => {
                let files: usize = kinds
                    .iter()
                    .filter_map(|id| catalogue.kind(id))
                    .map(|k| k.count)
                    .sum();
                (
                    kinds
                        .iter()
                        .map(|k| format!("`{k}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    files.to_string(),
                )
            }
            None => match report.unreachable.get(code) {
                Some(reason) => (format!("unreachable: {reason}"), "-".to_string()),
                None => ("**missing**".to_string(), "-".to_string()),
            },
        };
        let _ = writeln!(out, "| `{code}` | {groups} | {kinds} | {files} |");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Codes, Inventory, render_codes, report};
    use crate::corpus::faults::Catalogue;

    const CATALOGUE: &str = r#"
oracle = "0.23.0"
[base]
seed = 1
threats = 1
objectives = 1
rules = 1
layout = "explicit"

[[kind]]
id = "a"
codes = ["invalid_uuid"]
severity = "error"
target = { family = "rule" }
ops = []

[[unreachable]]
code = "engine_unavailable"
reason = "the engine is compiled in"
"#;

    fn codes(validation: &[&str]) -> Codes {
        let inventory = Inventory {
            validation: validation.iter().map(|s| (*s).to_string()).collect(),
            lint: vec![],
            configuration: vec![],
            query: vec!["invalid_uuid".to_string()],
            compile: vec![],
        };
        Codes::parse(&render_codes(&inventory, "0.23.0")).unwrap()
    }

    #[test]
    fn complete_coverage() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let report = report(&codes(&["invalid_uuid", "engine_unavailable"]), &catalogue);
        assert!(report.missing.is_empty());
        assert!(report.problems.is_empty());
        assert_eq!(report.groups["invalid_uuid"], vec!["validation", "query"]);
    }

    #[test]
    fn missing_and_problems() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let report = report(&codes(&["invalid_uuid", "yaml_parse"]), &catalogue);
        assert_eq!(report.missing, vec!["yaml_parse".to_string()]);
        assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
        let rendered = super::render(&report, &catalogue);
        assert!(rendered.contains("## Missing\n\n- `yaml_parse`"));
    }
}
