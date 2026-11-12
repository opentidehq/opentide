//! The differential comparator of the unified core (plan §5.2): it compares
//! what the oracle (the Python CLI) and a candidate (a Rust implementation)
//! did on the same input, and reports every difference the approved-diffs
//! ledger does not approve.
//!
//! I/O-free: callers read runs and the ledger, and write the report.
//! `cargo xtask compare` and `golden check --engine compare` use it, and so
//! does the CLI's `OPENTIDE_ENGINE=compare` through `opentide._native`.
//!
//! What is compared, for each target:
//!
//! - the exit code;
//! - stdout and stderr: as JSON when both parse as one document (the data,
//!   then the order of every object's keys, which is the oracle's contract,
//!   then the bytes), else as bytes;
//! - every file the command created, changed or deleted: presence, mode and
//!   bytes, the bytes as JSON or text as a stream is. A file only the oracle
//!   wrote is approved missing only in its catalog cache
//!   ([`ledger::ORACLE_CACHE`]), by a `presence` entry naming its path; a
//!   file's permission bits, by a `mode` entry naming its path and both
//!   sides' bits.

#![forbid(unsafe_code)]

pub mod glob;
pub mod help;
pub mod json;
pub mod ledger;
pub mod normalise;

use json::{Json, JsonDifference, LAYOUTS};
use ledger::{Ledger, Rule, Target, Usage};
use serde::Serialize;
use std::collections::BTreeMap;

pub use ledger::{Entry, LedgerError};
pub use normalise::Normaliser;

/// The most differences one target reports; the rest are counted in `omitted`.
pub const MAX_DIFFERENCES_PER_TARGET: usize = 200;

/// The longest excerpt of a value or a line a difference carries.
pub const MAX_EXCERPT: usize = 2000;

/// What one implementation did: its exit code, its output and the files it
/// left different from the workspace it started with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Run {
    /// The process exit code.
    pub exit_code: i32,
    /// Everything written to stdout.
    pub stdout: Vec<u8>,
    /// Everything written to stderr.
    pub stderr: Vec<u8>,
    /// Each file created, changed or deleted, by its path relative to the
    /// workspace with `/` separators.
    pub files: BTreeMap<String, FileState>,
}

/// What a run left at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    /// The file exists after the run with these permission bits and bytes.
    Written {
        /// The permission bits (`0o644`).
        mode: u32,
        /// The contents.
        bytes: Vec<u8>,
    },
    /// The run deleted the file.
    Deleted,
}

/// Which case a comparison is: the command path and the case's id (a golden
/// case's id; empty for a single CLI run).
#[derive(Debug, Clone, Copy)]
pub struct Case<'a> {
    /// The command path, `generate docs rules`.
    pub command: &'a str,
    /// The case id, matched by the ledger's case globs.
    pub id: &'a str,
}

/// The kind of a difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The exit codes differ.
    ExitCode,
    /// A JSON value differs, or is missing on one side.
    JsonValue,
    /// An object has the same keys in another order.
    JsonKeyOrder,
    /// The JSON data and key order are equal, the bytes are not: layout,
    /// escapes, the spelling of a number or the final newline.
    JsonBytes,
    /// The bytes of a non-JSON target differ.
    Bytes,
    /// The oracle wrote or deleted a file the candidate left alone.
    FileMissing,
    /// The candidate wrote or deleted a file the oracle left alone.
    FileExtra,
    /// One side wrote the file, the other deleted it.
    FileState,
    /// The file's permission bits differ.
    FileMode,
    /// Two help screens a `help` entry approves the layout of say different
    /// things: an option, a description, a default, the examples.
    Help,
}

impl Kind {
    /// The kind as the report spells it: `json_value`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::ExitCode => "exit_code",
            Kind::JsonValue => "json_value",
            Kind::JsonKeyOrder => "json_key_order",
            Kind::JsonBytes => "json_bytes",
            Kind::Bytes => "bytes",
            Kind::FileMissing => "file_missing",
            Kind::FileExtra => "file_extra",
            Kind::FileState => "file_state",
            Kind::FileMode => "file_mode",
            Kind::Help => "help",
        }
    }
}

/// One difference the ledger does not approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Difference {
    /// `exit_code`, `stdout`, `stderr` or `file:<path>`.
    pub target: String,
    /// What differs.
    pub kind: Kind,
    /// The JSON pointer, for JSON differences.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// The oracle's side: a JSON text, a line, or `(absent)`.
    pub oracle: String,
    /// The candidate's side.
    pub candidate: String,
    /// Where, for byte differences: `line 3, byte 120`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// A difference the ledger approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Approval {
    /// The target.
    pub target: String,
    /// The entry's position in the ledger, from 1.
    pub entry: usize,
    /// The entry's rule.
    pub rule: String,
    /// The entry's reason.
    pub reason: String,
    /// The entry's issue.
    pub issue: String,
}

/// The comparison of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseReport {
    /// The command path.
    pub command: String,
    /// The case id.
    pub case: String,
    /// Whether nothing differs that the ledger does not approve.
    pub equal: bool,
    /// What differs, in target order.
    pub differences: Vec<Difference>,
    /// Differences left out of `differences`, past the cap per target.
    pub omitted: usize,
    /// What differs and is approved.
    pub approved: Vec<Approval>,
}

impl CaseReport {
    /// The report as one line of JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Compares `candidate` with `oracle` for `case`, applying `ledger`'s entries
/// and marking in `usage` each one that applied. Both runs are compared as
/// given: normalise them first ([`Normaliser`]).
pub fn compare(
    case: Case,
    oracle: &Run,
    candidate: &Run,
    ledger: &Ledger,
    usage: &mut Usage,
) -> CaseReport {
    let mut report = Comparison {
        case,
        ledger,
        usage,
        differences: Vec::new(),
        omitted: 0,
        approved: Vec::new(),
    };
    report.exit_code(oracle.exit_code, candidate.exit_code);
    report.content(&Target::Stdout, &oracle.stdout, &candidate.stdout);
    report.content(&Target::Stderr, &oracle.stderr, &candidate.stderr);
    report.files(&oracle.files, &candidate.files);
    CaseReport {
        command: case.command.to_owned(),
        case: case.id.to_owned(),
        equal: report.differences.is_empty() && report.omitted == 0,
        differences: report.differences,
        omitted: report.omitted,
        approved: report.approved,
    }
}

/// How one CLI run of each side is normalised before it is compared: the
/// command's extra rules (as its golden cases opt into them) and the texts
/// that were there before the run (whose UUIDs are not fresh).
#[derive(Debug, Clone, Copy, Default)]
pub struct Normalisation<'a> {
    /// The command's extra rules: `fresh-uuids`, `host-git`.
    pub rules: &'a [normalise::Rule],
    /// The texts of the workspace before the run.
    pub known: &'a [String],
}

/// One CLI run of each side compared, each normalised first with its own
/// volatile values (each ran in its own copy of the workspace) and the
/// command's rules, as a golden case of the command is, applying `ledger`
/// without checking it for stale entries. `OPENTIDE_ENGINE=compare` calls it
/// through `opentide._native.compare_runs`.
pub fn compare_normalised(
    case: Case,
    (mut oracle, oracle_volatile): (Run, &normalise::Volatile),
    (mut candidate, candidate_volatile): (Run, &normalise::Volatile),
    normalisation: Normalisation,
    ledger: &Ledger,
) -> CaseReport {
    let known = || normalisation.known.iter().map(String::as_str);
    Normaliser::new(oracle_volatile, normalisation.rules, known()).run(&mut oracle);
    Normaliser::new(candidate_volatile, normalisation.rules, known()).run(&mut candidate);
    compare(case, &oracle, &candidate, ledger, &mut Usage::default())
}

struct Comparison<'a> {
    case: Case<'a>,
    ledger: &'a Ledger,
    usage: &'a mut Usage,
    differences: Vec<Difference>,
    omitted: usize,
    approved: Vec<Approval>,
}

impl Comparison<'_> {
    fn approve(&mut self, target: &Target, index: usize) {
        let entry = &self.ledger.entries[index];
        self.usage.mark(index);
        self.approved.push(Approval {
            target: target.to_string(),
            entry: index + 1,
            rule: entry.rule_text.clone(),
            reason: entry.reason.clone(),
            issue: entry.issue.clone(),
        });
    }

    /// Records `found`, the differences of one target, up to the cap.
    fn differ(&mut self, found: Vec<Difference>) {
        let room = MAX_DIFFERENCES_PER_TARGET;
        self.omitted += found.len().saturating_sub(room);
        self.differences.extend(found.into_iter().take(room));
    }

    fn exit_code(&mut self, oracle: i32, candidate: i32) {
        if oracle == candidate {
            return;
        }
        let target = Target::ExitCode;
        let approving = self
            .ledger
            .entries_for(self.case.command, self.case.id, &target)
            .find(|(_, entry)| entry.rule == Rule::ExitCode { oracle, candidate })
            .map(|(index, _)| index);
        match approving {
            Some(index) => self.approve(&target, index),
            None => self.differ(vec![Difference {
                target: target.to_string(),
                kind: Kind::ExitCode,
                pointer: None,
                oracle: oracle.to_string(),
                candidate: candidate.to_string(),
                at: None,
            }]),
        }
    }

    /// A stream or a file's bytes: as JSON when both sides are one document.
    fn content(&mut self, target: &Target, oracle: &[u8], candidate: &[u8]) {
        if oracle == candidate {
            return;
        }
        // A whole file approved by its two digests.
        let digests: Vec<(usize, String, String)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .filter_map(|(index, entry)| match &entry.rule {
                Rule::Sha256 {
                    oracle: expected_oracle,
                    candidate: expected_candidate,
                } => Some((index, expected_oracle.clone(), expected_candidate.clone())),
                _ => None,
            })
            .collect();
        if !digests.is_empty() {
            let (found_oracle, found_candidate) =
                (ledger::sha256_hex(oracle), ledger::sha256_hex(candidate));
            if let Some((index, ..)) = digests
                .iter()
                .find(|(_, o, c)| *o == found_oracle && *c == found_candidate)
            {
                self.approve(target, *index);
                return;
            }
        }
        if self.help_content(target, oracle, candidate) {
            return;
        }
        match (json::parse(oracle), json::parse(candidate)) {
            (Some(oracle_doc), Some(candidate_doc)) => {
                self.json_content(target, oracle, candidate, &oracle_doc, candidate_doc);
            }
            _ => self.text_content(target, oracle, candidate),
        }
    }

    /// A help screen under a `help` entry: compared by what it says
    /// ([`help`]), the layout approved. Whether it was (`false`: no `help`
    /// entry, or a side that is not a help screen of the entry's command, so
    /// the bytes are compared).
    fn help_content(&mut self, target: &Target, oracle: &[u8], candidate: &[u8]) -> bool {
        let entries: Vec<(usize, Rule)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .map(|(index, entry)| (index, entry.rule.clone()))
            .collect();
        let Some(help_entry) = entries
            .iter()
            .find(|(_, rule)| *rule == Rule::Help)
            .map(|(index, _)| *index)
        else {
            return false;
        };
        let (Ok(oracle_text), Ok(candidate_text)) =
            (std::str::from_utf8(oracle), std::str::from_utf8(candidate))
        else {
            return false;
        };
        let (Some(oracle_screen), Some(candidate_screen)) = (
            help::parse_typer(oracle_text),
            help::parse_clap(candidate_text),
        ) else {
            return false;
        };
        let path = if self.case.command.is_empty() {
            "opentide".to_owned()
        } else {
            format!("opentide {}", self.case.command)
        };
        if oracle_screen.path != path || candidate_screen.path != path {
            return false;
        }
        let texts: Vec<(usize, &str, &str)> = entries
            .iter()
            .filter_map(|(index, rule)| match rule {
                Rule::HelpText { oracle, candidate } => {
                    Some((*index, oracle.as_str(), candidate.as_str()))
                }
                _ => None,
            })
            .collect();
        let mut used = Vec::new();
        let found = help::mismatches(&oracle_screen, &candidate_screen, &texts, &mut used);
        if found.is_empty() {
            self.approve(target, help_entry);
            used.sort_unstable();
            used.dedup();
            for index in used {
                self.approve(target, index);
            }
        } else {
            let found = found
                .into_iter()
                .map(|mismatch| Difference {
                    target: target.to_string(),
                    kind: Kind::Help,
                    pointer: None,
                    oracle: excerpt(&mismatch.oracle),
                    candidate: excerpt(&mismatch.candidate),
                    at: Some(mismatch.at),
                })
                .collect();
            self.differ(found);
        }
        true
    }

    fn json_content(
        &mut self,
        target: &Target,
        oracle: &[u8],
        candidate: &[u8],
        oracle_doc: &Json,
        candidate_doc: Json,
    ) {
        let original = candidate_doc.clone();
        let mut applied = Vec::new();
        let entries: Vec<(usize, Rule)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .map(|(index, entry)| (index, entry.rule.clone()))
            .collect();
        // First the arrays the candidate extends: each named element set
        // aside, so the rest lines up with the oracle's array, and `json:`
        // entries address it by the oracle's indices. An outer array first,
        // so that an array inside one of its elements is found by the
        // oracle's index too.
        let mut aligned = candidate_doc;
        let mut extends: Vec<Extend<'_>> = entries
            .iter()
            .filter_map(|(index, rule)| match rule {
                Rule::JsonExtend {
                    pointer,
                    oracle_len,
                    added,
                } => Some((*index, pointer.as_slice(), *oracle_len, added.as_slice())),
                _ => None,
            })
            .collect();
        extends.sort_by_key(|(index, pointer, ..)| (pointer.len(), *index));
        for (index, pointer, oracle_len, added) in extends {
            if let Some(rest) = set_aside(oracle_doc, &aligned, pointer, oracle_len, added)
                && aligned.set(pointer, Some(Json::Array(rest)), None)
            {
                applied.push(index);
            }
        }
        let mut patched = aligned.clone();
        for (index, rule) in entries {
            let Rule::Json {
                pointer,
                oracle: expected_oracle,
                candidate: expected_candidate,
            } = rule
            else {
                continue;
            };
            let found_oracle = oracle_doc.get(&pointer);
            let found_candidate = aligned.get(&pointer);
            if found_oracle != expected_oracle.as_ref()
                || found_candidate != expected_candidate.as_ref()
            {
                continue;
            }
            // Approved: the candidate reads as the oracle there, so what
            // remains to compare is everything else.
            let position = oracle_doc.position(&pointer);
            if patched.set(&pointer, found_oracle.cloned(), position) {
                applied.push(index);
            }
        }
        for index in &applied {
            self.approve(target, *index);
        }

        let values = json::value_differences(oracle_doc, &patched);
        if !values.is_empty() {
            let found = values
                .iter()
                .map(|difference| json_difference(target, difference))
                .collect();
            self.differ(found);
            return;
        }
        let orders = json::key_order_differences(oracle_doc, &patched);
        if !orders.is_empty() {
            let found = orders
                .iter()
                .map(|difference| json_difference(target, difference))
                .collect();
            self.differ(found);
            return;
        }
        // The data and key order agree. The bytes must too, which a run with
        // no approved value shows directly (they differ, or we would not be
        // here); with approved values, both sides must be the same layout of
        // their own data.
        let same_layout = !applied.is_empty()
            && LAYOUTS.iter().any(|(layout, newline)| {
                json::write(oracle_doc, *layout, *newline) == oracle
                    && json::write(&original, *layout, *newline) == candidate
            });
        if !same_layout {
            let (line, oracle_line, candidate_line) = first_different_line(oracle, candidate);
            self.differ(vec![Difference {
                target: target.to_string(),
                kind: Kind::JsonBytes,
                pointer: None,
                oracle: oracle_line,
                candidate: candidate_line,
                at: Some(line),
            }]);
        }
    }

    fn text_content(&mut self, target: &Target, oracle: &[u8], candidate: &[u8]) {
        let rules: Vec<(usize, Vec<u8>, String)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .filter_map(|(index, entry)| match &entry.rule {
                Rule::Text {
                    oracle: expected_oracle,
                    candidate: expected_candidate,
                } => Some((
                    index,
                    expected_oracle.as_bytes().to_vec(),
                    expected_candidate.clone(),
                )),
                _ => None,
            })
            .collect();
        let blocks: Vec<LineBlock> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .filter_map(|(index, entry)| match &entry.rule {
                Rule::Lines {
                    oracle: expected_oracle,
                    candidate: expected_candidate,
                } => Some((
                    index,
                    expected_oracle
                        .iter()
                        .map(|l| l.as_bytes().to_vec())
                        .collect(),
                    expected_candidate
                        .iter()
                        .map(|l| l.as_bytes().to_vec())
                        .collect(),
                )),
                _ => None,
            })
            .collect();
        let candidate_lines: Vec<&[u8]> = candidate.split_inclusive(|b| *b == b'\n').collect();
        let oracle_lines: Vec<Vec<u8>> = oracle
            .split_inclusive(|b| *b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let (oracle_lines, applied) = apply_blocks(oracle_lines, &candidate_lines, &blocks);
        for index in applied {
            self.approve(target, index);
        }
        // Exact, line by line: an entry approves line N only where the
        // oracle's line N is its oracle text and the candidate's line N is its
        // candidate text (with a digest where it writes `<SHA256>`), each the
        // whole line without its newline. The line
        // then reads as the candidate's, keeping the oracle's line ending, so
        // a different ending is still reported. Every other line is compared
        // as it is.
        let mut rewritten: Vec<Vec<u8>> = oracle_lines.clone();
        let mut applied = std::collections::BTreeSet::new();
        for (number, line) in oracle_lines.iter().enumerate() {
            let Some(other) = candidate_lines.get(number) else {
                continue;
            };
            let (body, ending) = split_ending(line);
            let (other_body, _) = split_ending(other);
            for (index, from, to) in &rules {
                if body == from.as_slice() && ledger::text_matches(to, other_body) {
                    rewritten[number] = [other_body, ending].concat();
                    applied.insert(*index);
                }
            }
        }
        for index in applied {
            self.approve(target, index);
        }
        let rewritten = rewritten.concat();
        if rewritten != candidate {
            let (line, oracle_line, candidate_line) = first_different_line(&rewritten, candidate);
            self.differ(vec![Difference {
                target: target.to_string(),
                kind: Kind::Bytes,
                pointer: None,
                oracle: oracle_line,
                candidate: candidate_line,
                at: Some(line),
            }]);
        }
    }

    fn files(
        &mut self,
        oracle: &BTreeMap<String, FileState>,
        candidate: &BTreeMap<String, FileState>,
    ) {
        let paths: std::collections::BTreeSet<&String> =
            oracle.keys().chain(candidate.keys()).collect();
        for path in paths {
            let target = Target::File(path.clone());
            let simple = |kind, oracle: &str, candidate: &str| Difference {
                target: target.to_string(),
                kind,
                pointer: None,
                oracle: oracle.to_owned(),
                candidate: candidate.to_owned(),
                at: None,
            };
            match (oracle.get(path), candidate.get(path)) {
                (Some(left), None) => {
                    // Only a file the oracle wrote in its catalog cache can be
                    // approved missing, by an entry naming its exact path.
                    let approving = matches!(left, FileState::Written { .. })
                        .then(|| {
                            self.ledger
                                .entries_for(self.case.command, self.case.id, &target)
                                .find(|(_, entry)| entry.rule == Rule::Presence)
                                .map(|(index, _)| index)
                        })
                        .flatten();
                    match approving {
                        Some(index) => self.approve(&target, index),
                        None => {
                            let found = simple(Kind::FileMissing, describe(left), ledger::ABSENT);
                            self.differ(vec![found]);
                        }
                    }
                }
                (None, Some(right)) => {
                    let found = simple(Kind::FileExtra, ledger::ABSENT, describe(right));
                    self.differ(vec![found]);
                }
                (Some(FileState::Deleted), Some(FileState::Deleted)) | (None, None) => {}
                (Some(left @ FileState::Deleted), Some(right @ FileState::Written { .. }))
                | (Some(left @ FileState::Written { .. }), Some(right @ FileState::Deleted)) => {
                    let found = simple(Kind::FileState, describe(left), describe(right));
                    self.differ(vec![found]);
                }
                (
                    Some(FileState::Written {
                        mode: left_mode,
                        bytes: left,
                    }),
                    Some(FileState::Written {
                        mode: right_mode,
                        bytes: right,
                    }),
                ) => {
                    if left_mode != right_mode {
                        let expected = Rule::Mode {
                            oracle: *left_mode,
                            candidate: *right_mode,
                        };
                        let approving = self
                            .ledger
                            .entries_for(self.case.command, self.case.id, &target)
                            .find(|(_, entry)| entry.rule == expected)
                            .map(|(index, _)| index);
                        match approving {
                            Some(index) => self.approve(&target, index),
                            None => {
                                let found = simple(
                                    Kind::FileMode,
                                    &format!("{left_mode:o}"),
                                    &format!("{right_mode:o}"),
                                );
                                self.differ(vec![found]);
                            }
                        }
                    }
                    self.content(&target, left, right);
                }
            }
        }
    }
}

/// The candidate's array at `pointer` without the `added` elements, where a
/// `json-extend:` entry applies: the oracle's array there has `oracle_len`
/// elements, and the candidate's has each added element, exactly, at its
/// index, and `oracle_len` others. `None` where it does not apply.
fn set_aside(
    oracle: &Json,
    candidate: &Json,
    pointer: &[String],
    oracle_len: usize,
    added: &[(usize, Json)],
) -> Option<Vec<Json>> {
    let (Some(Json::Array(oracle)), Some(Json::Array(candidate))) =
        (oracle.get(pointer), candidate.get(pointer))
    else {
        return None;
    };
    if oracle.len() != oracle_len || candidate.len() != oracle_len + added.len() {
        return None;
    }
    let mut named = added.iter().peekable();
    let mut rest = Vec::with_capacity(oracle_len);
    for (at, item) in candidate.iter().enumerate() {
        match named.peek() {
            Some((index, value)) if *index == at => {
                if item != value {
                    return None;
                }
                named.next();
            }
            _ => rest.push(item.clone()),
        }
    }
    named.peek().is_none().then_some(rest)
}

/// A `json-extend:` entry: its index, pointer, the oracle array's length
/// and the added elements by candidate index.
type Extend<'a> = (usize, &'a [String], usize, &'a [(usize, Json)]);

/// A `lines` entry: its index, the oracle's lines and the candidate's.
type LineBlock = (usize, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// The oracle's lines with each `lines` entry applied: where the oracle's
/// lines from N are an entry's oracle lines and the candidate's, from the
/// same place, its candidate lines, the oracle reads the candidate's lines
/// there; the place moves by what each block added or removed. The entries
/// that applied, by index.
fn apply_blocks(
    oracle_lines: Vec<Vec<u8>>,
    candidate_lines: &[&[u8]],
    blocks: &[LineBlock],
) -> (Vec<Vec<u8>>, std::collections::BTreeSet<usize>) {
    let mut applied = std::collections::BTreeSet::new();
    if blocks.is_empty() {
        return (oracle_lines, applied);
    }
    let body = |line: &[u8]| split_ending(line).0.to_vec();
    let mut rewritten: Vec<Vec<u8>> = Vec::new();
    let mut number = 0;
    while number < oracle_lines.len() {
        let at = rewritten.len();
        let found = blocks.iter().find(|(_, from, to)| {
            number + from.len() <= oracle_lines.len()
                && at + to.len() <= candidate_lines.len()
                && from
                    .iter()
                    .zip(&oracle_lines[number..])
                    .all(|(want, line)| body(line) == *want)
                && to
                    .iter()
                    .zip(&candidate_lines[at..])
                    .all(|(want, line)| body(line) == *want)
        });
        if let Some((index, from, to)) = found {
            let ending = split_ending(&oracle_lines[number + from.len() - 1])
                .1
                .to_vec();
            for (position, line) in to.iter().enumerate() {
                let end: &[u8] = if position + 1 == to.len() {
                    &ending
                } else {
                    b"\n"
                };
                rewritten.push([line.as_slice(), end].concat());
            }
            applied.insert(*index);
            number += from.len();
        } else {
            rewritten.push(oracle_lines[number].clone());
            number += 1;
        }
    }
    (rewritten, applied)
}

fn describe(state: &FileState) -> &'static str {
    match state {
        FileState::Written { .. } => "written",
        FileState::Deleted => "deleted",
    }
}

fn json_difference(target: &Target, difference: &JsonDifference) -> Difference {
    match difference {
        JsonDifference::Value {
            pointer,
            oracle,
            candidate,
        } => Difference {
            target: target.to_string(),
            kind: Kind::JsonValue,
            pointer: Some(json::format_pointer(pointer)),
            oracle: oracle.as_ref().map_or_else(
                || ledger::ABSENT.to_owned(),
                |value| excerpt(&json::compact(value)),
            ),
            candidate: candidate.as_ref().map_or_else(
                || ledger::ABSENT.to_owned(),
                |value| excerpt(&json::compact(value)),
            ),
            at: None,
        },
        JsonDifference::KeyOrder {
            pointer,
            oracle,
            candidate,
        } => Difference {
            target: target.to_string(),
            kind: Kind::JsonKeyOrder,
            pointer: Some(json::format_pointer(pointer)),
            oracle: excerpt(&oracle.join(", ")),
            candidate: excerpt(&candidate.join(", ")),
            at: None,
        },
    }
}

/// `line N, byte M` of the first difference, and the two lines there (lossy
/// UTF-8, cut to [`MAX_EXCERPT`]); `(end)` past the last line.
fn first_different_line(oracle: &[u8], candidate: &[u8]) -> (String, String, String) {
    let byte = oracle
        .iter()
        .zip(candidate)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| oracle.len().min(candidate.len()));
    let line_start = oracle[..byte]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |at| at + 1);
    let line = oracle[..byte].split(|b| *b == b'\n').count();
    let line_of = |bytes: &[u8]| {
        if line_start > bytes.len() || (line_start == bytes.len() && byte >= bytes.len()) {
            return "(end)".to_owned();
        }
        let rest = &bytes[line_start..];
        let end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
        excerpt(&String::from_utf8_lossy(&rest[..end]))
    };
    (
        format!("line {line}, byte {byte}"),
        line_of(oracle),
        line_of(candidate),
    )
}

fn excerpt(text: &str) -> String {
    if text.chars().count() <= MAX_EXCERPT {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(MAX_EXCERPT).collect();
    out.push('…');
    out
}

/// A line's text and its ending (`\n` or `\r\n`, or nothing on a last line
/// without one).
fn split_ending(line: &[u8]) -> (&[u8], &[u8]) {
    let cut = if line.ends_with(b"\r\n") {
        line.len() - 2
    } else if line.ends_with(b"\n") {
        line.len() - 1
    } else {
        line.len()
    };
    line.split_at(cut)
}

/// A report of a whole run (`golden check --engine compare`, `xtask
/// compare`): every case's report and the stale ledger entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    /// The report format: `1`.
    pub schema_version: u32,
    /// Whether every case is equal and no ledger entry is stale.
    pub equal: bool,
    /// The cases, as compared.
    pub cases: Vec<CaseReport>,
    /// The entries that applied to no case, by their position from 1.
    pub stale: Vec<StaleEntry>,
}

/// A ledger entry that applied nowhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleEntry {
    /// The entry's position in the ledger, from 1.
    pub entry: usize,
    /// Its command.
    pub command: String,
    /// Its case glob.
    pub case: String,
    /// Its target.
    pub target: String,
    /// Its rule.
    pub rule: String,
}

impl RunReport {
    /// The report of a partial run (a filter, or cases that failed to run):
    /// no entry can be called stale from it.
    pub fn partial(cases: Vec<CaseReport>) -> RunReport {
        RunReport {
            schema_version: 1,
            equal: cases.iter().all(|case| case.equal),
            cases,
            stale: Vec::new(),
        }
    }

    /// The report of `cases`, compared with `ledger`, whose entries `usage`
    /// says applied: an entry that applied to none is stale.
    pub fn new(cases: Vec<CaseReport>, ledger: &Ledger, usage: &Usage) -> RunReport {
        let stale: Vec<StaleEntry> = ledger
            .stale(usage)
            .map(|(index, entry)| StaleEntry {
                entry: index + 1,
                command: entry.command.clone(),
                case: entry.case.clone(),
                target: entry.target.to_string(),
                rule: entry.rule_text.clone(),
            })
            .collect();
        RunReport {
            schema_version: 1,
            equal: stale.is_empty() && cases.iter().all(|case| case.equal),
            cases,
            stale,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `text` entry whose line holds a terminal's `\r` approves that line,
    /// and only it: the next line is still compared.
    #[test]
    fn a_text_entry_approves_a_line_with_a_carriage_return() {
        let ledger = Ledger::parse(
            r#"
[[diff]]
command = "generate exports"
case = "human/*"
target = "stderr"
rule = "text"
oracle = "\u001b[?25l<LIVE>x</LIVE>\u001b[?25h\r\u001b[1A\u001b[2K  done"
candidate = "  done"
reason = "no live display"
issue = "https://github.com/opentidehq/opentide/issues/824"
changelog = "**x**"
"#,
        )
        .unwrap();
        let oracle = Run {
            stderr: b"\x1b[?25l<LIVE>x</LIVE>\x1b[?25h\r\x1b[1A\x1b[2K  done\nerror: a\n".to_vec(),
            ..Run::default()
        };
        let case = Case {
            command: "generate exports",
            id: "human/ws/default",
        };
        let mut usage = Usage::default();
        let same = Run {
            stderr: b"  done\nerror: a\n".to_vec(),
            ..Run::default()
        };
        let report = compare(case, &oracle, &same, &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0));
        let other = Run {
            stderr: b"  done\nerror: b\n".to_vec(),
            ..Run::default()
        };
        let report = compare(case, &oracle, &other, &ledger, &mut usage);
        assert!(!report.equal);
        assert_eq!(report.differences[0].at.as_deref(), Some("line 2, byte 14"));
    }

    /// A `text` entry with `<SHA256>` approves the candidate's line with any
    /// digest there, and nothing else on that line or the next.
    #[test]
    fn a_text_entry_with_a_digest_token_approves_any_digest_there() {
        let oracle_digest = "5".repeat(64);
        let ledger = Ledger::parse(&format!(
            r#"
[[diff]]
command = "serve"
case = "plain/*"
target = "stdout"
rule = "text"
oracle = "{{\"digest\":\"{oracle_digest}\"}}"
candidate = "{{\"digest\":\"<SHA256>\"}}"
reason = "a digest over the version"
issue = "https://github.com/opentidehq/opentide/issues/830"
changelog = "**x**"
"#
        ))
        .unwrap();
        let case = Case {
            command: "serve",
            id: "plain/ws/session",
        };
        let oracle = Run {
            stdout: format!("{{\"digest\":\"{oracle_digest}\"}}\nnext\n").into_bytes(),
            ..Run::default()
        };
        let mut usage = Usage::default();
        let run = |line: &str| Run {
            stdout: format!("{line}\nnext\n").into_bytes(),
            ..Run::default()
        };
        for digest in ["a".repeat(64), "0123456789abcdef".repeat(4)] {
            let report = compare(
                case,
                &oracle,
                &run(&format!("{{\"digest\":\"{digest}\"}}")),
                &ledger,
                &mut usage,
            );
            assert!(report.equal, "{report:?}");
        }
        assert!(usage.is_used(0));
        for line in [
            format!("{{\"digest\":\"{}\"}}", "a".repeat(63)),
            format!("{{\"digest\":\"{}\",\"x\":1}}", "a".repeat(64)),
            format!("{{\"Digest\":\"{}\"}}", "a".repeat(64)),
        ] {
            let report = compare(case, &oracle, &run(&line), &ledger, &mut usage);
            assert!(!report.equal, "{line}");
        }
        let next = Run {
            stdout: format!("{{\"digest\":\"{}\"}}\nother\n", "a".repeat(64)).into_bytes(),
            ..Run::default()
        };
        let report = compare(case, &oracle, &next, &ledger, &mut usage);
        assert!(!report.equal);
        assert_eq!(report.differences[0].at.as_deref(), Some("line 2, byte 78"));
    }

    /// A `sha256` entry approves one file exactly: the oracle's and the
    /// candidate's bytes it names, and no other file, side or target.
    #[test]
    fn a_sha256_entry_approves_exactly_the_two_files_it_names() {
        let file = |bytes: &[u8]| {
            BTreeMap::from([(
                "ws/s.json".to_owned(),
                FileState::Written {
                    mode: 0o644,
                    bytes: bytes.to_vec(),
                },
            )])
        };
        let ledger = Ledger::parse(&format!(
            r#"
[[diff]]
command = "generate"
case = "*/tide-corpus/*"
target = "file:ws/s.json"
rule = "sha256"
oracle = "{}"
candidate = "{}"
reason = "compared by verdict"
issue = "https://github.com/opentidehq/opentide/issues/933"
changelog = "**x**"
"#,
            ledger::sha256_hex(b"{\"a\": 1}"),
            ledger::sha256_hex(b"{\"b\": 2}"),
        ))
        .unwrap();
        let case = Case {
            command: "generate",
            id: "generate/json/tide-corpus/schemas",
        };
        let oracle = Run {
            files: file(b"{\"a\": 1}"),
            ..Run::default()
        };
        let mut usage = Usage::default();
        let approved = Run {
            files: file(b"{\"b\": 2}"),
            ..Run::default()
        };
        let report = compare(case, &oracle, &approved, &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0));
        // One byte more on the candidate's side is not that file.
        let other = Run {
            files: file(b"{\"b\": 2} "),
            ..Run::default()
        };
        assert!(!compare(case, &oracle, &other, &ledger, &mut usage).equal);
        // Nor is another oracle file.
        let elsewhere = Run {
            files: file(b"{\"a\": 2}"),
            ..Run::default()
        };
        assert!(!compare(case, &elsewhere, &approved, &ledger, &mut usage).equal);
        // Nor another fixture's case.
        let vscode = Case {
            command: "generate",
            id: "generate/json/vscode/schemas",
        };
        assert!(!compare(vscode, &oracle, &approved, &ledger, &mut Usage::default()).equal);
    }

    /// A `sha256` rule takes two digests and a file target.
    #[test]
    fn a_sha256_rule_is_two_digests_on_a_file() {
        let entry = |target: &str, oracle: &str| {
            format!(
                r#"
[[diff]]
command = "generate"
case = "x"
target = "{target}"
rule = "sha256"
oracle = "{oracle}"
candidate = "{}"
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/933"
changelog = "**x**"
"#,
                "b".repeat(64)
            )
        };
        assert!(Ledger::parse(&entry("file:a.json", &"a".repeat(64))).is_ok());
        assert!(Ledger::parse(&entry("stdout", &"a".repeat(64))).is_err());
        assert!(Ledger::parse(&entry("file:a.json", "abc")).is_err());
        assert!(Ledger::parse(&entry("file:a.json", &"A".repeat(64))).is_err());
        assert!(Ledger::parse(&entry("file:a.json", &"b".repeat(64))).is_err());
    }

    const CACHE_FIELDS: &str =
        "home/.cache/opentide/lsp-catalogs/<CATALOG-FINGERPRINT>/fields.json";

    fn presence_ledger() -> Ledger {
        Ledger::parse(&format!(
            r#"
[[diff]]
command = "doctor"
case = "json/*/offline"
target = "file:{CACHE_FIELDS}"
rule = "presence"
oracle = "written"
candidate = "(absent)"
reason = "the oracle caches the catalog it generates; the candidate's is compiled in"
issue = "https://github.com/opentidehq/opentide/issues/928"
changelog = "**x**"
"#
        ))
        .unwrap()
    }

    fn written(bytes: &[u8]) -> FileState {
        FileState::Written {
            mode: 0o644,
            bytes: bytes.to_vec(),
        }
    }

    fn with_files(files: &[(&str, FileState)]) -> Run {
        Run {
            files: files
                .iter()
                .map(|(path, state)| ((*path).to_owned(), state.clone()))
                .collect(),
            ..Run::default()
        }
    }

    /// A `presence` entry approves the one cache file it names, written by
    /// the oracle and not the candidate, and nothing else.
    #[test]
    fn a_presence_entry_approves_only_its_cache_file_missing() {
        let ledger = presence_ledger();
        let case = Case {
            command: "doctor",
            id: "json/vscode/offline",
        };
        let mut usage = Usage::default();
        let oracle = with_files(&[(CACHE_FIELDS, written(b"{}"))]);
        let report = compare(case, &oracle, &Run::default(), &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert_eq!(report.approved.len(), 1);
        assert!(usage.is_used(0));

        // The candidate wrote it and the oracle did not: still a difference.
        let mut usage = Usage::default();
        let report = compare(case, &Run::default(), &oracle, &ledger, &mut usage);
        assert!(!report.equal);
        assert_eq!(report.differences[0].kind, Kind::FileExtra);
        assert!(!usage.is_used(0));

        // The oracle deleted it: not a file it wrote.
        let deleted = with_files(&[(CACHE_FIELDS, FileState::Deleted)]);
        let report = compare(case, &deleted, &Run::default(), &ledger, &mut usage);
        assert_eq!(report.differences[0].kind, Kind::FileMissing);

        // Another file of the cache, and a workspace file: not approved.
        for path in [
            "home/.cache/opentide/lsp-catalogs/<CATALOG-FINGERPRINT>/deprecations.json",
            "ws/fields.json",
        ] {
            let oracle = with_files(&[(path, written(b"{}"))]);
            let report = compare(case, &oracle, &Run::default(), &ledger, &mut usage);
            assert!(!report.equal, "{path}");
            assert_eq!(report.differences[0].kind, Kind::FileMissing);
            assert_eq!(report.differences[0].target, format!("file:{path}"));
        }

        // Both wrote it: the bytes are compared, the entry approves nothing.
        let candidate = with_files(&[(CACHE_FIELDS, written(b"[]"))]);
        let report = compare(case, &oracle, &candidate, &ledger, &mut usage);
        assert!(!report.equal);
        assert!(report.approved.is_empty());

        // Another case of the command: not approved.
        let other = Case {
            command: "doctor",
            id: "json/vscode/default",
        };
        let report = compare(other, &oracle, &Run::default(), &ledger, &mut usage);
        assert_eq!(report.differences[0].kind, Kind::FileMissing);
    }

    fn mode_ledger(target: &str, oracle: &str, candidate: &str) -> Result<Ledger, LedgerError> {
        Ledger::parse(&format!(
            r#"
[[diff]]
command = "deploy"
case = "deploy/*/deploy-push/promote-push"
target = "{target}"
rule = "mode"
oracle = "{oracle}"
candidate = "{candidate}"
reason = "status promotion keeps a rule file's permission bits"
issue = "https://github.com/opentidehq/opentide/issues/987"
changelog = "**x**"
"#
        ))
    }

    fn with_mode(mode: u32, bytes: &[u8]) -> Run {
        with_files(&[(
            "ws/r.yaml",
            FileState::Written {
                mode,
                bytes: bytes.to_vec(),
            },
        )])
    }

    /// A `mode` entry approves one file's permission bits, exactly the two it
    /// names, in its cases only; the file's bytes are still compared.
    #[test]
    fn a_mode_entry_approves_exactly_the_bits_it_names() {
        let ledger = mode_ledger("file:ws/r.yaml", "0600", "0644").unwrap();
        assert_eq!(
            ledger.entries[0].rule,
            Rule::Mode {
                oracle: 0o600,
                candidate: 0o644
            }
        );
        let case = Case {
            command: "deploy",
            id: "deploy/json/deploy-push/promote-push",
        };
        let mut usage = Usage::default();
        let oracle = with_mode(0o600, b"a");
        let report = compare(case, &oracle, &with_mode(0o644, b"a"), &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert_eq!(report.approved.len(), 1);
        assert!(usage.is_used(0));

        // Other bits, the sides swapped, or the bytes changed as well.
        let mut usage = Usage::default();
        for (oracle_mode, candidate_mode, bytes) in [
            (0o600, 0o664, &b"a"[..]),
            (0o644, 0o600, b"a"),
            (0o600, 0o644, b"b"),
        ] {
            let report = compare(
                case,
                &with_mode(oracle_mode, b"a"),
                &with_mode(candidate_mode, bytes),
                &ledger,
                &mut usage,
            );
            assert!(!report.equal, "{oracle_mode:o} {candidate_mode:o}");
        }
        let report = compare(
            case,
            &with_mode(0o600, b"a"),
            &with_mode(0o664, b"a"),
            &ledger,
            &mut usage,
        );
        assert_eq!(report.differences[0].kind, Kind::FileMode);
        assert_eq!(report.differences[0].oracle, "600");

        // Another case, or another file.
        let mut usage = Usage::default();
        let other = Case {
            command: "deploy",
            id: "deploy/json/deploy-push/promote-skip",
        };
        let report = compare(other, &oracle, &with_mode(0o644, b"a"), &ledger, &mut usage);
        assert_eq!(report.differences[0].kind, Kind::FileMode);
        let elsewhere = |mode| {
            with_files(&[(
                "ws/s.yaml",
                FileState::Written {
                    mode,
                    bytes: b"a".to_vec(),
                },
            )])
        };
        let report = compare(
            case,
            &elsewhere(0o600),
            &elsewhere(0o644),
            &ledger,
            &mut usage,
        );
        assert_eq!(report.differences[0].kind, Kind::FileMode);
        assert!(!usage.is_used(0));
    }

    #[test]
    fn a_mode_rule_is_four_octal_digits_a_side_on_a_file() {
        for (target, oracle, candidate) in [
            ("stdout", "0600", "0644"),
            ("exit_code", "0600", "0644"),
            ("file:ws/r.yaml", "600", "644"),
            ("file:ws/r.yaml", "0600", "0648"),
            ("file:ws/r.yaml", "0o600", "0644"),
            ("file:ws/r.yaml", "0644", "0644"),
            ("file:ws/r.yaml", "(absent)", "0644"),
        ] {
            assert!(
                mode_ledger(target, oracle, candidate).is_err(),
                "{target} {oracle} {candidate}"
            );
        }
    }

    /// A `lines` entry with an `(absent)` candidate approves the oracle's
    /// block where the candidate writes nothing in its place, even a stream
    /// the candidate leaves empty; a block one character off, or a line the
    /// candidate still writes, is reported.
    #[test]
    fn a_lines_entry_approves_a_dropped_block() {
        let ledger = Ledger::parse(
            r#"
[[diff]]
command = "validate"
case = "json/fault/default"
target = "stderr"
rule = "lines"
oracle = "warn: a\nwarn: b"
candidate = "(absent)"
reason = "no such step"
issue = "https://github.com/opentidehq/opentide/issues/827"
changelog = "**x**"
"#,
        )
        .unwrap();
        let case = Case {
            command: "validate",
            id: "json/fault/default",
        };
        let oracle = Run {
            stderr: b"warn: a\nwarn: b\n".to_vec(),
            ..Run::default()
        };
        let mut usage = Usage::default();
        let report = compare(case, &oracle, &Run::default(), &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0));

        let kept = Run {
            stderr: b"warn: z\n".to_vec(),
            ..Run::default()
        };
        let report = compare(case, &oracle, &kept, &ledger, &mut Usage::default());
        assert!(
            !report.equal,
            "a line the candidate writes is still compared"
        );

        let other = Run {
            stderr: b"warn: a\nwarn: c\n".to_vec(),
            ..Run::default()
        };
        let mut usage = Usage::default();
        let report = compare(case, &other, &Run::default(), &ledger, &mut usage);
        assert!(!report.equal, "a block one character off is not approved");
        assert!(!usage.is_used(0));

        let middle = Run {
            stderr: b"x\nwarn: a\nwarn: b\ny\n".to_vec(),
            ..Run::default()
        };
        let candidate = Run {
            stderr: b"x\ny\n".to_vec(),
            ..Run::default()
        };
        let report = compare(case, &middle, &candidate, &ledger, &mut Usage::default());
        assert!(report.equal, "{report:?}");
    }

    /// The ledger entry of the `json-extend:` tests: the oracle's catalogue
    /// has two rules, the candidate adds `c` at index 1 and `d` at index 3.
    const EXTEND: &str = r#"
[[diff]]
command = "lint"
case = "json/*"
target = "stdout"
rule = "json-extend:/rules"
oracle = "2"
candidate = '{"1": {"id": "c", "level": "error"}, "3": {"id": "d"}}'
reason = "codes added since the oracle"
issue = "https://github.com/opentidehq/opentide/issues/827"
changelog = "**x**"
"#;

    /// A document with `rules`, in the CLI's compact layout.
    fn extend_run(rules: &str) -> Run {
        let text = format!("{{\"rules\": {rules}, \"n\": 1}}");
        Run {
            stdout: json::write(
                &json::parse_str(&text).unwrap(),
                json::Layout::Compact,
                true,
            ),
            ..Run::default()
        }
    }

    fn extend_compare(candidate: &str) -> (CaseReport, Usage) {
        let ledger = Ledger::parse(EXTEND).unwrap();
        let oracle = extend_run(r#"[{"id": "a"}, {"id": "b"}]"#);
        let mut usage = Usage::default();
        let case = Case {
            command: "lint",
            id: "json/ws/default",
        };
        let report = compare(case, &oracle, &extend_run(candidate), &ledger, &mut usage);
        (report, usage)
    }

    /// A `json-extend:` entry approves the elements it names, at their
    /// indices, where the oracle's elements stay as they were and in order.
    #[test]
    fn a_json_extend_entry_approves_the_named_elements() {
        let (report, usage) = extend_compare(
            r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "b"}, {"id": "d"}]"#,
        );
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0));
    }

    /// Each way a candidate's array can be more than the oracle's plus the
    /// named elements is still a difference: no looser than quoting the
    /// candidate's whole array.
    #[test]
    fn a_json_extend_entry_approves_nothing_else() {
        for (mutant, candidate) in [
            (
                "an oracle element changed",
                r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "B"}, {"id": "d"}]"#,
            ),
            (
                "the oracle's elements reordered",
                r#"[{"id": "b"}, {"id": "c", "level": "error"}, {"id": "a"}, {"id": "d"}]"#,
            ),
            (
                "an element the entry does not name",
                r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "b"}, {"id": "d"}, {"id": "e"}]"#,
            ),
            (
                "an oracle element dropped",
                r#"[{"id": "c", "level": "error"}, {"id": "b"}, {"id": "d"}]"#,
            ),
            (
                "a named element changed",
                r#"[{"id": "a"}, {"id": "c", "level": "note"}, {"id": "b"}, {"id": "d"}]"#,
            ),
            (
                "a named element moved",
                r#"[{"id": "c", "level": "error"}, {"id": "a"}, {"id": "b"}, {"id": "d"}]"#,
            ),
            (
                "a named element missing",
                r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "b"}]"#,
            ),
            (
                "a named element with its keys in another order",
                r#"[{"id": "a"}, {"level": "error", "id": "c"}, {"id": "b"}, {"id": "d"}]"#,
            ),
        ] {
            let (report, _) = extend_compare(candidate);
            assert!(!report.equal, "{mutant}: approved");
        }
    }

    /// A `json:` entry under an extended array addresses it with the added
    /// elements set aside: the oracle's indices.
    #[test]
    fn a_json_entry_under_an_extended_array_uses_the_oracle_indices() {
        let ledger = Ledger::parse(&format!(
            "{EXTEND}{}",
            r#"
[[diff]]
command = "lint"
case = "json/*"
target = "stdout"
rule = "json:/rules/1/id"
oracle = '"b"'
candidate = '"B"'
reason = "renamed"
issue = "https://github.com/opentidehq/opentide/issues/827"
changelog = "**x**"
"#
        ))
        .unwrap();
        let oracle = extend_run(r#"[{"id": "a"}, {"id": "b"}]"#);
        let candidate =
            extend_run(r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "B"}, {"id": "d"}]"#);
        let case = Case {
            command: "lint",
            id: "json/ws/default",
        };
        let mut usage = Usage::default();
        let report = compare(case, &oracle, &candidate, &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0) && usage.is_used(1));
    }

    /// An array extended inside an element of an extended array is found
    /// by the oracle's index of that element, whatever order the ledger
    /// lists the two entries in.
    #[test]
    fn a_nested_json_extend_entry_uses_the_oracle_index() {
        let inner = EXTEND
            .replace("json-extend:/rules", "json-extend:/rules/1/tags")
            .replace("oracle = \"2\"", "oracle = \"1\"")
            .replace(
                r#"candidate = '{"1": {"id": "c", "level": "error"}, "3": {"id": "d"}}'"#,
                r#"candidate = '{"1": "new"}'"#,
            );
        let oracle = extend_run(r#"[{"id": "a"}, {"id": "b", "tags": ["old"]}]"#);
        let candidate = extend_run(
            r#"[{"id": "a"}, {"id": "c", "level": "error"}, {"id": "b", "tags": ["old", "new"]}, {"id": "d"}]"#,
        );
        let case = Case {
            command: "lint",
            id: "json/ws/default",
        };
        for text in [format!("{inner}{EXTEND}"), format!("{EXTEND}{inner}")] {
            let ledger = Ledger::parse(&text).unwrap();
            let mut usage = Usage::default();
            let report = compare(case, &oracle, &candidate, &ledger, &mut usage);
            assert!(report.equal, "{report:?}");
            assert!(usage.is_used(0) && usage.is_used(1));
        }
    }

    /// Two `lines` entries of one case and target approve two blocks, each
    /// where its own oracle lines are; a block neither names is reported.
    #[test]
    fn two_lines_entries_approve_two_blocks_of_one_case() {
        let entry = |oracle: &str, candidate: &str| {
            format!(
                r#"
[[diff]]
command = "validate"
case = "human/fault/default"
target = "stdout"
rule = "lines"
oracle = "{oracle}"
candidate = "{candidate}"
reason = "r"
issue = "https://github.com/opentidehq/opentide/issues/827"
changelog = "**x**"
"#
            )
        };
        let ledger = Ledger::parse(&format!(
            "{}{}",
            entry("a\\nhelp: x", "a"),
            entry("q: 1", "q: 2")
        ))
        .unwrap();
        let case = Case {
            command: "validate",
            id: "human/fault/default",
        };
        let oracle = Run {
            stdout: b"a\nhelp: x\nkeep\nq: 1\nend\n".to_vec(),
            ..Run::default()
        };
        let candidate = Run {
            stdout: b"a\nkeep\nq: 2\nend\n".to_vec(),
            ..Run::default()
        };
        let mut usage = Usage::default();
        let report = compare(case, &oracle, &candidate, &ledger, &mut usage);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0) && usage.is_used(1));
        let other = Run {
            stdout: b"a\nkeep\nq: 2\nEND\n".to_vec(),
            ..Run::default()
        };
        let report = compare(case, &oracle, &other, &ledger, &mut Usage::default());
        assert!(
            !report.equal,
            "a line neither entry names is still compared"
        );
    }

    #[test]
    fn a_line_splits_from_its_ending() {
        assert_eq!(split_ending(b"a\n"), (&b"a"[..], &b"\n"[..]));
        assert_eq!(split_ending(b"a\r\n"), (&b"a"[..], &b"\r\n"[..]));
        assert_eq!(split_ending(b"a"), (&b"a"[..], &b""[..]));
        assert_eq!(split_ending(b"\n"), (&b""[..], &b"\n"[..]));
    }

    #[test]
    fn kinds_spell_as_serde_does() {
        for kind in [
            Kind::ExitCode,
            Kind::JsonValue,
            Kind::JsonKeyOrder,
            Kind::JsonBytes,
            Kind::Bytes,
            Kind::FileMissing,
            Kind::FileExtra,
            Kind::FileState,
            Kind::FileMode,
            Kind::Help,
        ] {
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind.as_str())
            );
        }
    }

    #[test]
    fn first_different_line_names_the_line() {
        let (at, oracle, candidate) = first_different_line(b"a\nbc\nd", b"a\nbX\nd");
        assert_eq!(at, "line 2, byte 3");
        assert_eq!((oracle.as_str(), candidate.as_str()), ("bc", "bX"));
        let (_, oracle, candidate) = first_different_line(b"a\n", b"a\nb\n");
        assert_eq!((oracle.as_str(), candidate.as_str()), ("(end)", "b"));
    }
}
