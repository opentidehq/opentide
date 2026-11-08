//! `cargo xtask mutants report`: the weekly mutation run's summary, the
//! baseline it is compared with, and the issue bodies that list surviving
//! mutants (plan §5.4 "Strength", UC-X.2 #844).
//!
//! cargo-mutants writes `mutants.out/outcomes.json` per run; the weekly
//! workflow (`.github/workflows/mutants.yml`) runs one shard per job and
//! hands every shard's file here. This module merges them, counts the
//! outcomes per crate, and compares each crate with `xtask/mutants.toml`
//! (which crates, and how many survivors file an issue) and with the recorded
//! baseline (`xtask/mutants-baseline.toml`, which this module writes and no
//! one edits by hand). It reads no file and runs no process; `main.rs` does.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

/// The crates the weekly job mutates, as `xtask/mutants.toml` writes them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// One entry per crate.
    #[serde(rename = "crate")]
    pub crates: Vec<CratePolicy>,
}

/// One crate of the policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CratePolicy {
    /// The package name.
    pub name: String,
    /// More surviving mutants than this file an issue that lists them.
    /// `None` while the crate has no baseline yet: every survivor is listed.
    #[serde(default)]
    pub issue_above: Option<u64>,
    /// The work item that creates the crate, while it is not a workspace
    /// member yet; the job mutates it once it is.
    #[serde(default)]
    pub item: Option<String>,
    /// Why this crate is mutated (shown in the report).
    #[serde(default)]
    pub why: Option<String>,
}

impl Policy {
    /// Reads `xtask/mutants.toml`.
    ///
    /// # Errors
    ///
    /// The text is not TOML of that shape.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The crates to mutate now: those that are workspace members, in the
    /// policy's order. A crate that is not a member is skipped only when it
    /// names the work item that creates it.
    ///
    /// # Errors
    ///
    /// A crate that is neither a member nor names a work item, or one named
    /// twice.
    pub fn active<'a>(&'a self, members: &BTreeSet<String>) -> Result<Vec<&'a str>, String> {
        let mut seen = BTreeSet::new();
        let mut active = Vec::new();
        for krate in &self.crates {
            if !seen.insert(krate.name.as_str()) {
                return Err(format!("the policy names `{}` more than once", krate.name));
            }
            if members.contains(&krate.name) {
                active.push(krate.name.as_str());
            } else if krate.item.is_none() {
                return Err(format!(
                    "the policy names `{}`, which is not a workspace member, and no `item` \
                     that creates it: remove the entry, or name the work item",
                    krate.name
                ));
            }
        }
        Ok(active)
    }
}

/// What cargo-mutants decided about one mutant (its `summary` field).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Summary {
    /// The unmutated tree built and passed (the baseline).
    Success,
    /// A test failed on the mutant: the tests caught it.
    CaughtMutant,
    /// Every test passed on the mutant: it survived.
    MissedMutant,
    /// The mutant did not build.
    Unviable,
    /// The baseline failed: nothing about the mutants can be said.
    Failure,
    /// The tests ran past the timeout on the mutant.
    Timeout,
}

/// A mutant, as cargo-mutants serialises it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Mutant {
    /// `file:line:col: replace … with …`.
    pub name: String,
    /// The package it is in.
    pub package: String,
    /// The file, relative to the workspace root.
    pub file: String,
}

#[derive(Debug, Deserialize)]
enum Scenario {
    Baseline,
    Mutant(Mutant),
}

#[derive(Debug, Deserialize)]
struct Outcome {
    scenario: Scenario,
    summary: Summary,
}

#[derive(Debug, Deserialize)]
struct Outcomes {
    outcomes: Vec<Outcome>,
    #[serde(default)]
    cargo_mutants_version: Option<String>,
}

/// One shard's `outcomes.json`, reduced to what the report reads.
#[derive(Debug, Default)]
pub struct Run {
    /// Each mutant with its outcome.
    pub mutants: Vec<(Mutant, Summary)>,
    /// Whether a baseline scenario failed: the run says nothing then.
    pub baseline_failed: bool,
    /// The cargo-mutants version that wrote it.
    pub version: Option<String>,
}

/// Reads one `outcomes.json`.
///
/// # Errors
///
/// The text is not that document.
pub fn parse_run(json: &str) -> Result<Run, serde_json::Error> {
    let outcomes: Outcomes = serde_json::from_str(json)?;
    let mut run = Run {
        version: outcomes.cargo_mutants_version,
        ..Run::default()
    };
    for outcome in outcomes.outcomes {
        match outcome.scenario {
            Scenario::Baseline => run.baseline_failed |= outcome.summary != Summary::Success,
            Scenario::Mutant(mutant) => run.mutants.push((mutant, outcome.summary)),
        }
    }
    Ok(run)
}

/// The counts of one crate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// Every mutant tested.
    pub mutants: u64,
    /// Caught by a failing test.
    pub caught: u64,
    /// Survived: every test passed.
    pub missed: u64,
    /// Ran past the timeout (counted as detected).
    pub timeout: u64,
    /// Did not build (left out of the score).
    pub unviable: u64,
}

impl Counts {
    /// The mutation score in hundredths of a percent: detected (caught or
    /// timed out) over viable mutants, rounded down; `None` with no viable
    /// mutant.
    pub fn score_hundredths(&self) -> Option<u64> {
        let detected = self.caught + self.timeout;
        let viable = detected + self.missed;
        (viable > 0).then(|| detected * 10_000 / viable)
    }

    fn add(&mut self, summary: Summary) {
        self.mutants += 1;
        match summary {
            Summary::CaughtMutant => self.caught += 1,
            Summary::MissedMutant => self.missed += 1,
            Summary::Timeout => self.timeout += 1,
            Summary::Unviable => self.unviable += 1,
            Summary::Success | Summary::Failure => {}
        }
    }
}

fn score(counts: &Counts) -> String {
    counts.score_hundredths().map_or_else(
        || "n/a".to_owned(),
        |h| format!("{}.{:02}%", h / 100, h % 100),
    )
}

/// The recorded baseline, `xtask/mutants-baseline.toml`.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    /// The commit the run mutated.
    pub commit: String,
    /// The cargo-mutants version.
    pub cargo_mutants: String,
    /// The counts per crate.
    #[serde(rename = "crate")]
    pub crates: BTreeMap<String, Counts>,
}

impl Baseline {
    /// Reads the baseline.
    ///
    /// # Errors
    ///
    /// The text is not TOML of that shape.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The baseline as the file holds it, with its header.
    ///
    /// # Errors
    ///
    /// Never in practice: the baseline is plain data.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        Ok(format!(
            "# The mutation baseline: cargo-mutants' counts per crate, written by\n\
             # `cargo xtask mutants report --write-baseline` from a full run (UC-X.2,\n\
             # #844). Generated: never edit it by hand; record a new run instead.\n\
             # The score is detected (caught + timeout) over viable (caught + timeout\n\
             # + missed) mutants; unviable mutants do not count.\n\n{}",
            toml::to_string(self)?
        ))
    }
}

/// Why a set of runs cannot be reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunError {
    /// A shard's baseline (the unmutated tree) failed.
    BaselineFailed,
    /// The same mutant appears twice, in one shard or in two.
    Duplicate(String),
    /// A mutant of a crate the policy does not list.
    Unlisted(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaselineFailed => f.write_str(
                "a shard's baseline failed: the unmutated tree did not build or pass its tests",
            ),
            Self::Duplicate(name) => write!(f, "`{name}` appears twice in the outcomes"),
            Self::Unlisted(krate) => {
                write!(f, "mutants of `{krate}`, which the policy does not list")
            }
        }
    }
}

/// The merged runs.
#[derive(Debug, Default)]
pub struct Report {
    /// Counts per crate, for every crate the runs mutated.
    pub counts: BTreeMap<String, Counts>,
    /// The surviving mutants per crate, by name.
    pub missed: BTreeMap<String, Vec<Mutant>>,
    /// The cargo-mutants version (the first shard's).
    pub version: Option<String>,
}

/// Merges the shards' runs.
///
/// # Errors
///
/// A shard's baseline failed, a mutant appears twice, or a crate the policy
/// does not list was mutated.
pub fn merge(policy: &Policy, runs: &[Run]) -> Result<Report, RunError> {
    let listed: BTreeSet<&str> = policy.crates.iter().map(|c| c.name.as_str()).collect();
    let mut report = Report::default();
    let mut seen = BTreeSet::new();
    for run in runs {
        if run.baseline_failed {
            return Err(RunError::BaselineFailed);
        }
        if report.version.is_none() {
            report.version.clone_from(&run.version);
        }
        for (mutant, summary) in &run.mutants {
            if !listed.contains(mutant.package.as_str()) {
                return Err(RunError::Unlisted(mutant.package.clone()));
            }
            if !seen.insert(mutant.name.as_str()) {
                return Err(RunError::Duplicate(mutant.name.clone()));
            }
            report
                .counts
                .entry(mutant.package.clone())
                .or_default()
                .add(*summary);
            if *summary == Summary::MissedMutant {
                report
                    .missed
                    .entry(mutant.package.clone())
                    .or_default()
                    .push(mutant.clone());
            }
        }
    }
    for missed in report.missed.values_mut() {
        missed.sort_by(|a, b| a.name.cmp(&b.name));
    }
    Ok(report)
}

/// The most surviving mutants one issue lists; the rest are in the run's
/// artifact.
pub const ISSUE_LIST_LIMIT: usize = 300;

/// The most characters the list of survivors takes in one issue body, so
/// that the body stays under GitHub's limit of 65,536 whatever the length of
/// the mutants' names.
pub const ISSUE_LIST_CHARS: usize = 60_000;

impl Report {
    /// The summary as Markdown, for the job summary.
    pub fn markdown(&self, policy: &Policy, baseline: Option<&Baseline>) -> String {
        let mut out = String::from(
            "## Mutation testing (cargo-mutants)\n\n\
             | Crate | Mutants | Caught | Missed | Timeout | Unviable | Score | Baseline score | Issue above |\n\
             |-------|--------:|-------:|-------:|--------:|---------:|------:|---------------:|------------:|\n",
        );
        for krate in &policy.crates {
            let base = baseline
                .and_then(|b| b.crates.get(&krate.name))
                .map_or_else(|| "none".to_owned(), score);
            let above = krate
                .issue_above
                .map_or_else(|| "any".to_owned(), |n| n.to_string());
            match self.counts.get(&krate.name) {
                Some(c) => {
                    let _ = writeln!(
                        out,
                        "| `{}` | {} | {} | {} | {} | {} | {} | {base} | {above} |",
                        krate.name,
                        c.mutants,
                        c.caught,
                        c.missed,
                        c.timeout,
                        c.unviable,
                        score(c)
                    );
                }
                None => {
                    let note = krate.item.as_ref().map_or_else(
                        || "not mutated in this run".to_owned(),
                        |item| format!("pending: {item} creates it"),
                    );
                    let _ = writeln!(
                        out,
                        "| `{}` | {note} | | | | | | {base} | {above} |",
                        krate.name
                    );
                }
            }
        }
        if let Some(version) = &self.version {
            let _ = writeln!(out, "\ncargo-mutants {version}.");
        }
        out
    }

    /// The crates whose survivors exceed their threshold, each with the body
    /// of the issue that lists them.
    pub fn issues(&self, policy: &Policy, run_url: &str) -> Vec<(String, String)> {
        let mut issues = Vec::new();
        for krate in &policy.crates {
            let Some(missed) = self.missed.get(&krate.name) else {
                continue;
            };
            let count = missed.len() as u64;
            if krate.issue_above.is_some_and(|limit| count <= limit) || count == 0 {
                continue;
            }
            let mut body = format!(
                "The weekly mutation run ({run_url}) found **{count} surviving mutants** in \
                 `{}`: each one is a change to the code that every test still passes. \
                 The threshold is {} (`xtask/mutants.toml`).\n\n\
                 Kill a survivor with a test that fails on the mutated code, or say in a \
                 comment why it is equivalent: the workflow rewrites this description every \
                 week. Reproduce one with `cargo mutants -p {} --file <file> \
                 --re '<function>'`.\n\n",
                krate.name,
                krate
                    .issue_above
                    .map_or_else(|| "not set yet".to_owned(), |n| n.to_string()),
                krate.name
            );
            let mut listed = 0;
            let mut chars = 0;
            for mutant in missed.iter().take(ISSUE_LIST_LIMIT) {
                let line = format!("- `{}`\n", mutant.name.replace('`', "'"));
                if chars + line.chars().count() > ISSUE_LIST_CHARS {
                    break;
                }
                chars += line.chars().count();
                body.push_str(&line);
                listed += 1;
            }
            if missed.len() > listed {
                let _ = writeln!(
                    body,
                    "\n…and {} more: the full list is `missed.txt` in the run's artifact.",
                    missed.len() - listed
                );
            }
            body.push_str("\n_Opened and updated by the weekly `mutants` workflow._\n");
            issues.push((krate.name.clone(), body));
        }
        issues
    }

    /// The baseline this report records.
    pub fn baseline(&self, commit: &str) -> Baseline {
        Baseline {
            commit: commit.to_owned(),
            cargo_mutants: self.version.clone().unwrap_or_default(),
            crates: self.counts.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[[crate]]
name = "schema"
item = "UC-1.1 (#807)"

[[crate]]
name = "tide"
issue_above = 1
why = "folds into opentide-workspace"
"#;

    fn outcome(package: &str, name: &str, summary: &str) -> String {
        format!(
            r#"{{"scenario": {{"Mutant": {{"name": "{name}", "package": "{package}", "file": "src/lib.rs",
                "genre": "FnValue", "replacement": "true"}}}}, "summary": "{summary}",
                "log_path": "log", "diff_path": null, "phase_results": []}}"#
        )
    }

    fn run(baseline: &str, mutants: &[String]) -> Run {
        let json = format!(
            r#"{{"outcomes": [{{"scenario": "Baseline", "summary": "{baseline}", "log_path": "b",
                "diff_path": null, "phase_results": []}}{}{}],
                "total_mutants": 0, "missed": 0, "caught": 0, "timeout": 0, "unviable": 0,
                "success": 0, "start_time": "t", "end_time": null, "cargo_mutants_version": "27.1.0"}}"#,
            if mutants.is_empty() { "" } else { "," },
            mutants.join(",")
        );
        parse_run(&json).unwrap()
    }

    fn policy() -> Policy {
        Policy::parse(POLICY).unwrap()
    }

    #[test]
    fn merges_shards_and_counts_per_crate() {
        let report = merge(
            &policy(),
            &[
                run(
                    "Success",
                    &[
                        outcome("tide", "a.rs:1:1: replace f with true", "CaughtMutant"),
                        outcome("tide", "a.rs:2:1: replace g with false", "MissedMutant"),
                    ],
                ),
                run(
                    "Success",
                    &[
                        outcome("tide", "a.rs:3:1: replace h with 0", "Timeout"),
                        outcome("tide", "a.rs:4:1: replace i with 1", "Unviable"),
                        outcome("tide", "a.rs:0:1: replace e with 1", "MissedMutant"),
                    ],
                ),
            ],
        )
        .unwrap();
        let counts = &report.counts["tide"];
        assert_eq!(
            counts,
            &Counts {
                mutants: 5,
                caught: 1,
                missed: 2,
                timeout: 1,
                unviable: 1
            }
        );
        // (1 caught + 1 timeout) / (2 + 2 missed) = 50%.
        assert_eq!(counts.score_hundredths(), Some(5000));
        let names: Vec<&str> = report.missed["tide"]
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "a.rs:0:1: replace e with 1",
                "a.rs:2:1: replace g with false"
            ]
        );
        assert_eq!(report.version.as_deref(), Some("27.1.0"));
    }

    #[test]
    fn a_failed_baseline_a_duplicate_or_an_unlisted_crate_is_an_error() {
        assert_eq!(
            merge(&policy(), &[run("Failure", &[])]).unwrap_err(),
            RunError::BaselineFailed
        );
        let m = outcome("tide", "x", "CaughtMutant");
        assert_eq!(
            merge(
                &policy(),
                &[
                    run("Success", std::slice::from_ref(&m)),
                    run("Success", &[m])
                ]
            )
            .unwrap_err(),
            RunError::Duplicate("x".into())
        );
        assert_eq!(
            merge(
                &policy(),
                &[run("Success", &[outcome("lsp", "y", "CaughtMutant")])]
            )
            .unwrap_err(),
            RunError::Unlisted("lsp".into())
        );
    }

    #[test]
    fn an_issue_lists_survivors_only_above_the_threshold() {
        let one = merge(
            &policy(),
            &[run(
                "Success",
                &[outcome("tide", "a: replace `f`", "MissedMutant")],
            )],
        )
        .unwrap();
        assert!(
            one.issues(&policy(), "RUN").is_empty(),
            "1 survivor is not above 1"
        );
        let two = merge(
            &policy(),
            &[run(
                "Success",
                &[
                    outcome("tide", "a: replace `f`", "MissedMutant"),
                    outcome("tide", "b: replace g", "MissedMutant"),
                ],
            )],
        )
        .unwrap();
        let issues = two.issues(&policy(), "RUN");
        assert_eq!(issues.len(), 1);
        let (krate, body) = &issues[0];
        assert_eq!(krate, "tide");
        assert!(body.contains("**2 surviving mutants**"), "{body}");
        assert!(body.contains("- `a: replace 'f'`"), "{body}");
        assert!(body.contains("RUN"), "{body}");
    }

    #[test]
    fn a_crate_without_a_threshold_lists_every_survivor_up_to_the_limit() {
        let policy = Policy::parse("[[crate]]\nname = \"tide\"").unwrap();
        let mutants: Vec<String> = (0..ISSUE_LIST_LIMIT + 2)
            .map(|i| outcome("tide", &format!("m{i:04}"), "MissedMutant"))
            .collect();
        let report = merge(&policy, &[run("Success", &mutants)]).unwrap();
        let body = &report.issues(&policy, "RUN")[0].1;
        assert_eq!(body.matches("\n- `").count(), ISSUE_LIST_LIMIT);
        assert!(body.contains("…and 2 more"), "{body}");
    }

    #[test]
    fn a_body_of_long_names_stays_under_githubs_limit() {
        let policy = Policy::parse("[[crate]]\nname = \"tide\"").unwrap();
        let long = "x".repeat(400);
        let mutants: Vec<String> = (0..ISSUE_LIST_LIMIT)
            .map(|i| outcome("tide", &format!("{i:04}{long}"), "MissedMutant"))
            .collect();
        let report = merge(&policy, &[run("Success", &mutants)]).unwrap();
        let body = &report.issues(&policy, "RUN")[0].1;
        assert!(body.chars().count() < 65_536, "{}", body.chars().count());
        let listed = body.matches("\n- `").count();
        assert!(listed < ISSUE_LIST_LIMIT, "{listed}");
        assert!(
            body.contains(&format!("…and {} more", ISSUE_LIST_LIMIT - listed)),
            "{body}"
        );
    }

    #[test]
    fn the_policy_skips_pending_crates_and_rejects_stale_ones() {
        let members: BTreeSet<String> = ["tide".to_owned()].into();
        assert_eq!(policy().active(&members).unwrap(), ["tide"]);
        let stale = Policy::parse("[[crate]]\nname = \"gone\"").unwrap();
        assert!(stale.active(&members).unwrap_err().contains("`gone`"));
        let twice =
            Policy::parse("[[crate]]\nname = \"tide\"\n[[crate]]\nname = \"tide\"").unwrap();
        assert!(
            twice
                .active(&members)
                .unwrap_err()
                .contains("more than once")
        );
        assert!(Policy::parse("[[crate]]\nname = \"x\"\nmin_score = 1").is_err());
    }

    #[test]
    fn the_markdown_and_the_baseline_round_trip() {
        let report = merge(
            &policy(),
            &[run(
                "Success",
                &[
                    outcome("tide", "a", "CaughtMutant"),
                    outcome("tide", "b", "MissedMutant"),
                    outcome("tide", "c", "CaughtMutant"),
                ],
            )],
        )
        .unwrap();
        let baseline = report.baseline("abc123");
        let text = baseline.to_toml().unwrap();
        assert!(text.starts_with("# The mutation baseline"));
        assert_eq!(Baseline::parse(&text).unwrap(), baseline);
        let md = report.markdown(&policy(), Some(&baseline));
        assert!(
            md.contains("| `tide` | 3 | 2 | 1 | 0 | 0 | 66.66% | 66.66% | 1 |"),
            "{md}"
        );
        assert!(
            md.contains("| `schema` | pending: UC-1.1 (#807) creates it |"),
            "{md}"
        );
    }
}
