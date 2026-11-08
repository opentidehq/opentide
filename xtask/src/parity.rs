//! `cargo xtask parity dashboard`: the migration's state at a glance (plan
//! §5.4 "Strength", UC-X.2 #844), as `docs/internal/parity.md` and the job
//! summary of the `parity` workflow.
//!
//! One row per command × corpus × mode, each in one of four states: no Rust
//! implementation yet, `compare` passing, `compare` failing, or flipped (Rust
//! is the default). Beside the table: the number of approved diffs and the
//! fault catalogue's coverage of the diagnostic codes.
//!
//! This module computes and renders from [`Inputs`]; the loaders in
//! `parity_inputs.rs` read them from the repository, and `main.rs` runs them.
//! The page is a pure function of its inputs: no date, no commit, so that it
//! changes only when the migration does.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

/// What the dashboard reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// Every recording: (command, mode, corpus). A command path is written
    /// with spaces (`info catalog`).
    pub goldens: BTreeSet<Cell>,
    /// The engine state of each command that has a Rust implementation;
    /// a command absent here has none.
    pub engines: BTreeMap<String, Engine>,
    /// The `compare` results of the last run, per recording; `None` when no
    /// run's results were given.
    pub compare: Option<BTreeMap<Cell, bool>>,
    /// The ledger entries the last compare run found stale (applied to no
    /// case); `None` without a run's results.
    pub stale_entries: Option<usize>,
    /// The entries of `tests/golden/APPROVED_DIFFS.toml`, per command
    /// (`None` when the ledger does not exist yet).
    pub approved_diffs: Option<BTreeMap<String, usize>>,
    /// The fault catalogue: every diagnostic code, and those with a fault
    /// kind (`None` when the catalogue does not exist yet).
    pub faults: Option<FaultCoverage>,
}

/// One recording: a command in one mode on one corpus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cell {
    /// The command path, words separated by spaces.
    pub command: String,
    /// The output mode (`human`, `plain`, `json`, `agent`).
    pub mode: String,
    /// The fixture workspace (the corpus).
    pub corpus: String,
}

/// Where a command's Rust implementation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// It exists; Python is still the default, and `compare` decides.
    Shadow,
    /// Rust is the default (plan §7).
    Flipped,
}

/// The fault catalogue's coverage of the diagnostic codes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultCoverage {
    /// Every diagnostic code in scope (UC-0.6's `codes.toml`).
    pub codes: BTreeSet<String>,
    /// The codes in scope at least one fault kind produces.
    pub covered: BTreeSet<String>,
    /// The codes in scope the catalogue declares unreachable through the CLI.
    pub unreachable: BTreeSet<String>,
    /// Codes outside the scope that fault kinds produce (listed, not wrong).
    pub outside: usize,
    /// The catalogue's own inconsistencies, as UC-0.6's report states them.
    pub problems: Vec<String>,
}

impl FaultCoverage {
    /// The codes in scope with neither a fault kind nor an unreachable entry.
    pub fn missing(&self) -> Vec<&String> {
        self.codes
            .iter()
            .filter(|c| !self.covered.contains(*c) && !self.unreachable.contains(*c))
            .collect()
    }
}

/// The state of one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// No Rust implementation yet.
    NoRust,
    /// A Rust implementation, and `compare` found no difference.
    ComparePassing,
    /// A Rust implementation, and `compare` found a difference.
    CompareFailing,
    /// A Rust implementation whose `compare` result is missing from the run.
    CompareNotRun,
    /// Rust is the default.
    Flipped,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            Self::NoRust => "no Rust yet",
            Self::ComparePassing => "compare passing",
            Self::CompareFailing => "compare failing",
            Self::CompareNotRun => "compare not run",
            Self::Flipped => "flipped",
        }
    }

    const ALL: [Self; 5] = [
        Self::NoRust,
        Self::ComparePassing,
        Self::CompareFailing,
        Self::CompareNotRun,
        Self::Flipped,
    ];
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The state of one recording.
pub fn state(inputs: &Inputs, cell: &Cell) -> State {
    match inputs.engines.get(&cell.command) {
        None => State::NoRust,
        Some(Engine::Flipped) => State::Flipped,
        Some(Engine::Shadow) => match inputs.compare.as_ref().and_then(|c| c.get(cell)) {
            Some(true) => State::ComparePassing,
            Some(false) => State::CompareFailing,
            None => State::CompareNotRun,
        },
    }
}

/// A mistake in the inputs: the dashboard is not written from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// A compare result for a recording that does not exist.
    UnknownRecording(Cell),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRecording(cell) => write!(
                f,
                "a compare result for `{}` in {} on {}, which has no recording",
                cell.command, cell.mode, cell.corpus
            ),
        }
    }
}

/// Checks that the inputs agree with one another: every error, in order.
pub fn check(inputs: &Inputs) -> Vec<InputError> {
    let mut errors = Vec::new();
    if let Some(compare) = &inputs.compare {
        errors.extend(
            compare
                .keys()
                .filter(|cell| !inputs.goldens.contains(cell))
                .map(|cell| InputError::UnknownRecording(cell.clone())),
        );
    }
    errors
}

fn ratio(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "n/a".to_owned();
    }
    let tenths = part * 1000 / whole;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The page, `docs/internal/parity.md`, with its frontmatter.
pub fn page(inputs: &Inputs) -> String {
    let mut out = String::from(
        "---\n\
         title: Parity dashboard\n\
         description: The unified-core migration at a glance, each command × corpus × mode against the Python oracle. Generated by cargo xtask parity dashboard; never edit it by hand.\n\
         ---\n\n\
         # Parity dashboard\n\n\
         > Generated by `cargo xtask parity dashboard` (UC-X.2, \
         [#844](https://github.com/opentidehq/opentide/issues/844)) and committed by the \
         `parity` workflow on every push to `development` and `integration/unified-core`. Do not edit it: change the \
         goldens, the engine state, the ledger or the fault catalogue, and regenerate.\n\n\
         The Python CLI at the frozen tag is the oracle ([plan §5]\
         (https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy)). A row is one command in one output \
         mode on one corpus: **no Rust yet**, **compare passing** (`OPENTIDE_ENGINE=compare` \
         finds no difference), **compare failing**, **compare not run** (a Rust \
         implementation the last run did not compare), or **flipped** (Rust is the \
         default, plan §7).\n\n",
    );

    // Totals.
    let mut totals: BTreeMap<State, usize> = BTreeMap::new();
    for cell in &inputs.goldens {
        *totals.entry(state(inputs, cell)).or_default() += 1;
    }
    let commands: BTreeSet<&str> = inputs.goldens.iter().map(|c| c.command.as_str()).collect();
    let flipped = inputs
        .engines
        .values()
        .filter(|e| **e == Engine::Flipped)
        .count();
    out.push_str("## Summary\n\n| | |\n|---|---:|\n");
    let _ = writeln!(out, "| Commands | {} |", commands.len());
    let _ = writeln!(
        out,
        "| Commands with a Rust implementation | {} |",
        inputs.engines.len()
    );
    let _ = writeln!(out, "| Commands flipped to Rust | {flipped} |");
    let _ = writeln!(
        out,
        "| Recordings (command × corpus × mode) | {} |",
        inputs.goldens.len()
    );
    for state in State::ALL {
        let n = totals.get(&state).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "| … {state} | {n} ({}) |",
            ratio(n, inputs.goldens.len())
        );
    }
    let approved = inputs.approved_diffs.as_ref().map_or_else(
        || "no ledger yet".to_owned(),
        |d| d.values().sum::<usize>().to_string(),
    );
    let _ = writeln!(
        out,
        "| Approved diffs (`tests/golden/APPROVED_DIFFS.toml`) | {approved} |"
    );
    if let Some(stale) = inputs.stale_entries {
        let _ = writeln!(
            out,
            "| Stale ledger entries in the last compare run | {stale} |"
        );
    }
    match &inputs.faults {
        Some(faults) => {
            let _ = writeln!(
                out,
                "| Diagnostic codes with a fault kind | {} of {} ({}) |",
                faults.covered.len(),
                faults.codes.len(),
                ratio(faults.covered.len(), faults.codes.len())
            );
            let _ = writeln!(
                out,
                "| … declared unreachable through the CLI | {} |",
                faults.unreachable.len()
            );
            let _ = writeln!(
                out,
                "| … with neither (missing) | {} |",
                faults.missing().len()
            );
            if faults.outside > 0 {
                let _ = writeln!(
                    out,
                    "| Codes outside the scope with a fault kind | {} |",
                    faults.outside
                );
            }
        }
        None => out.push_str("| Diagnostic codes with a fault kind | no fault catalogue yet |\n"),
    }
    if inputs.compare.is_none() && !inputs.engines.is_empty() {
        out.push_str(
            "\nNo compare results were given: every command with a Rust implementation that is \
             not flipped shows **compare not run**.\n",
        );
    }

    // A Rust implementation with nothing recorded for compare to judge: not an
    // error of the inputs (the dashboard must keep rendering), but a gap.
    let unrecorded: Vec<String> = inputs
        .engines
        .keys()
        .filter(|command| !commands.contains(command.as_str()))
        .map(|command| format!("`{}`", format!("opentide {command}").trim_end()))
        .collect();
    if !unrecorded.is_empty() {
        let _ = write!(
            out,
            "\n## Rust implementations without recordings\n\n{}: compare has nothing to \
             judge them against until their goldens are recorded.\n",
            unrecorded.join(", ")
        );
    }

    // One table per command: corpora down, modes across.
    out.push_str("\n## By command\n");
    if inputs.goldens.is_empty() {
        out.push_str("\nNo recordings yet (`tests/golden/`, UC-0.5).\n");
    }
    for command in &commands {
        let cells: Vec<&Cell> = inputs
            .goldens
            .iter()
            .filter(|c| c.command == *command)
            .collect();
        let modes: BTreeSet<&str> = cells.iter().map(|c| c.mode.as_str()).collect();
        let corpora: BTreeSet<&str> = cells.iter().map(|c| c.corpus.as_str()).collect();
        let diffs = inputs
            .approved_diffs
            .as_ref()
            .and_then(|d| d.get(*command))
            .copied()
            .unwrap_or(0);
        let _ = write!(
            out,
            "\n### `{}`\n\n",
            format!("opentide {command}").trim_end()
        );
        if diffs > 0 {
            let _ = writeln!(out, "{diffs} approved diff(s).\n");
        }
        let _ = write!(out, "| Corpus |");
        for mode in &modes {
            let _ = write!(out, " {mode} |");
        }
        out.push_str("\n|--------|");
        for _ in &modes {
            out.push_str("------|");
        }
        out.push('\n');
        for corpus in &corpora {
            let _ = write!(out, "| {corpus} |");
            for mode in &modes {
                let cell = Cell {
                    command: (*command).to_owned(),
                    mode: (*mode).to_owned(),
                    corpus: (*corpus).to_owned(),
                };
                if inputs.goldens.contains(&cell) {
                    let _ = write!(out, " {} |", state(inputs, &cell));
                } else {
                    out.push_str(" not recorded |");
                }
            }
            out.push('\n');
        }
    }

    if let Some(faults) = &inputs.faults {
        let missing = faults.missing();
        if !missing.is_empty() {
            let _ = write!(
                out,
                "\n## Diagnostic codes without a fault kind\n\n{} code(s), neither covered nor declared unreachable: ",
                missing.len()
            );
            let list: Vec<String> = missing.iter().map(|c| format!("`{c}`")).collect();
            out.push_str(&list.join(", "));
            out.push_str(".\n");
        }
        if !faults.problems.is_empty() {
            out.push_str("\n## Fault catalogue problems\n\n");
            for problem in &faults.problems {
                let _ = writeln!(out, "- {problem}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(command: &str, mode: &str, corpus: &str) -> Cell {
        Cell {
            command: command.into(),
            mode: mode.into(),
            corpus: corpus.into(),
        }
    }

    fn inputs() -> Inputs {
        Inputs {
            goldens: [
                cell("validate", "json", "tide_corpus"),
                cell("validate", "plain", "tide_corpus"),
                cell("info catalog", "json", "tide_corpus"),
                cell("explain", "json", "none"),
            ]
            .into(),
            engines: [
                ("validate".to_owned(), Engine::Shadow),
                ("explain".to_owned(), Engine::Flipped),
            ]
            .into(),
            compare: Some(
                [
                    (cell("validate", "json", "tide_corpus"), true),
                    (cell("validate", "plain", "tide_corpus"), false),
                ]
                .into(),
            ),
            stale_entries: Some(0),
            approved_diffs: Some([("validate".to_owned(), 2)].into()),
            faults: Some(FaultCoverage {
                codes: ["a".into(), "b".into(), "c".into(), "d".into()].into(),
                covered: ["a".into(), "b".into()].into(),
                unreachable: ["d".into()].into(),
                outside: 1,
                problems: vec!["`d` is declared unreachable twice".into()],
            }),
        }
    }

    #[test]
    fn each_recording_has_one_of_the_states() {
        let inputs = inputs();
        let states: Vec<State> = inputs.goldens.iter().map(|c| state(&inputs, c)).collect();
        // Sorted by command: explain, info catalog, validate json, validate plain.
        assert_eq!(
            states,
            [
                State::Flipped,
                State::NoRust,
                State::ComparePassing,
                State::CompareFailing
            ]
        );
        let mut without_run = inputs.clone();
        without_run.compare = None;
        assert_eq!(
            state(&without_run, &cell("validate", "json", "tide_corpus")),
            State::CompareNotRun
        );
    }

    #[test]
    fn the_page_shows_states_diffs_and_fault_coverage() {
        let page = page(&inputs());
        assert!(page.starts_with("---\ntitle: Parity dashboard\n"), "{page}");
        assert!(page.contains("| Commands | 3 |"), "{page}");
        assert!(page.contains("| Commands flipped to Rust | 1 |"), "{page}");
        assert!(page.contains("| … compare failing | 1 (25.0%) |"), "{page}");
        assert!(
            page.contains("| Approved diffs (`tests/golden/APPROVED_DIFFS.toml`) | 2 |"),
            "{page}"
        );
        assert!(
            page.contains("| Diagnostic codes with a fault kind | 2 of 4 (50.0%) |"),
            "{page}"
        );
        assert!(
            page.contains("### `opentide validate`\n\n2 approved diff(s).\n"),
            "{page}"
        );
        assert!(page.contains("| Corpus | json | plain |\n|--------|------|------|\n| tide_corpus | compare passing | compare failing |"), "{page}");
        assert!(
            page.contains("1 code(s), neither covered nor declared unreachable: `c`."),
            "{page}"
        );
        assert!(
            page.contains("| … declared unreachable through the CLI | 1 |"),
            "{page}"
        );
        assert!(
            page.contains("| Codes outside the scope with a fault kind | 1 |"),
            "{page}"
        );
        assert!(
            page.contains("## Fault catalogue problems\n\n- `d` is declared unreachable twice\n"),
            "{page}"
        );
        assert!(
            page.contains("| Stale ledger entries in the last compare run | 0 |"),
            "{page}"
        );
    }

    #[test]
    fn a_cell_that_was_not_recorded_is_marked() {
        let mut inputs = inputs();
        inputs.goldens.insert(cell("validate", "json", "heavy"));
        let page = page(&inputs);
        assert!(
            page.contains("| heavy | compare not run | not recorded |"),
            "{page}"
        );
    }

    #[test]
    fn before_any_data_the_page_says_what_is_missing() {
        let page = page(&Inputs::default());
        assert!(page.contains("No recordings yet"), "{page}");
        assert!(
            page.contains(
                "| Approved diffs (`tests/golden/APPROVED_DIFFS.toml`) | no ledger yet |"
            ),
            "{page}"
        );
        assert!(page.contains("no fault catalogue yet"), "{page}");
        assert!(page.contains("| … no Rust yet | 0 (n/a) |"), "{page}");
    }

    #[test]
    fn the_root_command_is_headed_opentide() {
        let inputs = Inputs {
            goldens: [cell("", "plain", "none")].into(),
            ..Inputs::default()
        };
        let page = page(&inputs);
        assert!(page.contains("\n### `opentide`\n"), "{page}");
    }

    #[test]
    fn a_rust_command_without_recordings_is_listed_not_an_error() {
        let mut inputs = inputs();
        inputs.engines.insert("frobnicate".into(), Engine::Shadow);
        assert!(check(&inputs).is_empty());
        let page = page(&inputs);
        assert!(
            page.contains("## Rust implementations without recordings\n\n`opentide frobnicate`"),
            "{page}"
        );
    }

    #[test]
    fn the_page_is_a_pure_function_of_its_inputs() {
        assert_eq!(page(&inputs()), page(&inputs()));
    }

    #[test]
    fn inputs_that_disagree_are_errors() {
        let mut bad = inputs();
        bad.compare
            .as_mut()
            .unwrap()
            .insert(cell("validate", "agent", "tide_corpus"), true);
        assert_eq!(
            check(&bad),
            [InputError::UnknownRecording(cell(
                "validate",
                "agent",
                "tide_corpus"
            )),]
        );
        assert!(check(&inputs()).is_empty());
    }
}
