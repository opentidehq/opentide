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
//!   bytes, the bytes as JSON or text as a stream is.

#![forbid(unsafe_code)]

pub mod glob;
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
        match (json::parse(oracle), json::parse(candidate)) {
            (Some(oracle_doc), Some(candidate_doc)) => {
                self.json_content(target, oracle, candidate, &oracle_doc, candidate_doc);
            }
            _ => self.text_content(target, oracle, candidate),
        }
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
        let mut patched = candidate_doc;
        let mut applied = Vec::new();
        let entries: Vec<(usize, Rule)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .map(|(index, entry)| (index, entry.rule.clone()))
            .collect();
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
            let found_candidate = original.get(&pointer);
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
        let rules: Vec<(usize, Vec<u8>, Vec<u8>)> = self
            .ledger
            .entries_for(self.case.command, self.case.id, target)
            .filter_map(|(index, entry)| match &entry.rule {
                Rule::Text {
                    oracle: expected_oracle,
                    candidate: expected_candidate,
                } => Some((
                    index,
                    expected_oracle.as_bytes().to_vec(),
                    expected_candidate.as_bytes().to_vec(),
                )),
                _ => None,
            })
            .collect();
        // Narrow, line by line: on line N, every entry whose oracle text is on
        // the oracle's line N and whose candidate text is on the candidate's
        // rewrites that line; the line is approved only if it then reads as
        // the candidate's line exactly. Every other line is compared as it is.
        let oracle_lines: Vec<&[u8]> = oracle.split_inclusive(|b| *b == b'\n').collect();
        let candidate_lines: Vec<&[u8]> = candidate.split_inclusive(|b| *b == b'\n').collect();
        let mut rewritten: Vec<Vec<u8>> = oracle_lines.iter().map(|line| line.to_vec()).collect();
        let mut applied = std::collections::BTreeSet::new();
        for (number, line) in oracle_lines.iter().enumerate() {
            let Some(other) = candidate_lines.get(number) else {
                continue;
            };
            let mut text = line.to_vec();
            let mut here = Vec::new();
            for (index, from, to) in &rules {
                if contains(line, from) && contains(other, to) {
                    text = replace(&text, from, to);
                    here.push(*index);
                }
            }
            if !here.is_empty() && text == *other {
                rewritten[number] = text;
                applied.extend(here);
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
                    let found = simple(Kind::FileMissing, describe(left), ledger::ABSENT);
                    self.differ(vec![found]);
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
                        let found = simple(
                            Kind::FileMode,
                            &format!("{left_mode:o}"),
                            &format!("{right_mode:o}"),
                        );
                        self.differ(vec![found]);
                    }
                    self.content(&target, left, right);
                }
            }
        }
    }
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// `bytes` with every occurrence of `from` replaced by `to`, left to right.
pub(crate) fn replace(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at..].starts_with(from) {
            out.extend_from_slice(to);
            at += from.len();
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
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

    #[test]
    fn replace_is_left_to_right_and_does_not_rescan() {
        assert_eq!(replace(b"aaa", b"aa", b"a"), b"aa");
        assert_eq!(replace(b"x", b"", b"y"), b"x");
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
