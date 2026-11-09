//! The approved-diffs ledger, `tests/golden/APPROVED_DIFFS.toml`: every
//! intended difference between the oracle and a candidate implementation.
//!
//! ```toml
//! [[diff]]
//! command = "commands"                      # the command path, exactly
//! case = "json/*"                           # a glob over case ids
//! target = "stdout"                         # stdout | stderr | exit_code | file:<path>
//! rule = "json:/environment"                # json:<JSON pointer> | text
//! oracle = '[...]'                          # what the oracle has there
//! candidate = '[...]'                       # what the candidate has instead
//! reason = "OPENTIDE_ENGINE is read by the launcher (#805)"
//! issue = "https://github.com/opentidehq/opentide/issues/805"
//! changelog = "**`OPENTIDE_ENGINE`**"       # text found in CHANGELOG.md
//! ```
//!
//! Every field is required. A `json:` rule's values are JSON texts, or
//! `(absent)` where that side has no value; a `text` rule's values are
//! literal text (on `exit_code`, the code in decimal). An entry applies only
//! where both values are found as written; an entry that applies nowhere in a
//! complete run is stale, and a stale entry fails the run.

use crate::glob;
use crate::json::{self, Json};
use serde::Deserialize;
use std::fmt;

/// The value of `oracle` or `candidate` that says this side has no value at
/// the pointer.
pub const ABSENT: &str = "(absent)";

/// What a run compares: the exit code, a stream, or a file the command wrote.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// The process exit code.
    ExitCode,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file, by its path relative to the workspace, with `/` separators.
    File(String),
}

impl Target {
    /// `stdout`, `stderr`, `exit_code` or `file:<path>`.
    pub fn parse(text: &str) -> Option<Target> {
        match text {
            "exit_code" => Some(Target::ExitCode),
            "stdout" => Some(Target::Stdout),
            "stderr" => Some(Target::Stderr),
            other => {
                let path = other.strip_prefix("file:")?;
                let valid = !path.is_empty()
                    && !path.starts_with('/')
                    && !path.contains('\\')
                    && path
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..");
                valid.then(|| Target::File(path.to_owned()))
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Target::ExitCode => formatter.write_str("exit_code"),
            Target::Stdout => formatter.write_str("stdout"),
            Target::Stderr => formatter.write_str("stderr"),
            Target::File(path) => write!(formatter, "file:{path}"),
        }
    }
}

/// What an entry expects on each side.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// The value at a JSON pointer of the target's document; `None` is absent.
    Json {
        /// The pointer's tokens.
        pointer: Vec<String>,
        /// The oracle's value there.
        oracle: Option<Json>,
        /// The candidate's value there.
        candidate: Option<Json>,
    },
    /// Literal text: the oracle's text reads as the candidate's.
    Text {
        /// Text the oracle's target contains.
        oracle: String,
        /// The text the candidate has in its place.
        candidate: String,
    },
    /// The exit code.
    ExitCode {
        /// The oracle's code.
        oracle: i32,
        /// The candidate's code.
        candidate: i32,
    },
}

/// One approved difference.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The command path, words separated by one space: `generate docs rules`.
    pub command: String,
    /// A glob over the ids of the cases it applies to.
    pub case: String,
    /// What it applies to.
    pub target: Target,
    /// The rule, as written in the ledger: `json:/pointer` or `text`.
    pub rule_text: String,
    /// What it expects on each side.
    pub rule: Rule,
    /// Why the difference is intended.
    pub reason: String,
    /// The issue that decided it.
    pub issue: String,
    /// The changelog text that announces it.
    pub changelog: String,
}

/// The ledger: its entries, in file order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ledger {
    /// The entries.
    pub entries: Vec<Entry>,
}

/// Which entries applied somewhere, across the cases of a run.
#[derive(Debug, Clone, Default)]
pub struct Usage {
    used: Vec<bool>,
}

impl Usage {
    /// Records that entry `index` applied.
    pub fn mark(&mut self, index: usize) {
        if self.used.len() <= index {
            self.used.resize(index + 1, false);
        }
        self.used[index] = true;
    }

    /// Whether entry `index` applied.
    pub fn is_used(&self, index: usize) -> bool {
        self.used.get(index).copied().unwrap_or(false)
    }
}

/// A ledger that does not follow the schema: one message per problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerError {
    /// Each problem, naming the entry (1-based) and the field.
    pub problems: Vec<String>,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&self.problems.join("\n"))
    }
}

impl std::error::Error for LedgerError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    #[serde(default)]
    diff: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    command: String,
    case: String,
    target: String,
    rule: String,
    oracle: String,
    candidate: String,
    reason: String,
    issue: String,
    changelog: String,
}

impl Ledger {
    /// Parses and checks a ledger. Every problem is reported, not just the
    /// first: a missing or unknown field, a blank value, a target, rule or
    /// value that does not parse, an entry whose two values are the same, an
    /// issue that is not an opentidehq issue URL, and two entries for the same
    /// command, case glob, target and rule.
    pub fn parse(text: &str) -> Result<Ledger, LedgerError> {
        let file: LedgerFile = toml::from_str(text).map_err(|error| LedgerError {
            problems: vec![error.message().to_owned() + &location(text, error.span())],
        })?;
        let mut problems = Vec::new();
        let mut entries = Vec::new();
        for (index, raw) in file.diff.into_iter().enumerate() {
            match check_entry(raw) {
                Ok(entry) => {
                    let duplicate = entries.iter().position(|other: &Entry| {
                        other.command == entry.command
                            && other.case == entry.case
                            && other.target == entry.target
                            && other.rule_text == entry.rule_text
                    });
                    if let Some(first) = duplicate {
                        problems.push(format!(
                            "entry {}: the same command, case, target and rule as entry {}",
                            index + 1,
                            first + 1
                        ));
                    }
                    entries.push(entry);
                }
                Err(found) => {
                    problems.extend(
                        found
                            .into_iter()
                            .map(|problem| format!("entry {}: {problem}", index + 1)),
                    );
                }
            }
        }
        if problems.is_empty() {
            Ok(Ledger { entries })
        } else {
            Err(LedgerError { problems })
        }
    }

    /// The entries whose `changelog` is not the bold lead of an entry of
    /// `changelog` (the text of `CHANGELOG.md`): `**Lead**`, found as a list
    /// item that starts with it (`- **Lead** …`), in any version's section,
    /// since entries move from `[Unreleased]` to their release.
    pub fn missing_changelog(&self, changelog: &str) -> Vec<String> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let lead = &entry.changelog;
                let bold = lead.len() > 4 && lead.starts_with("**") && lead.ends_with("**");
                let listed = changelog
                    .lines()
                    .any(|line| line.trim_start().strip_prefix("- ").is_some_and(|item| item.starts_with(lead.as_str())));
                match (bold, listed) {
                    (false, _) => Some(format!(
                        "entry {}: changelog {lead:?} is not a bold lead (`**…**`)",
                        index + 1
                    )),
                    (true, false) => Some(format!(
                        "entry {}: changelog {lead:?} begins no entry (`- {lead} …`) of CHANGELOG.md",
                        index + 1
                    )),
                    (true, true) => None,
                }
            })
            .collect()
    }

    /// The entries for `target` of the case `case_id` of `command`, with their indexes.
    pub fn entries_for<'a>(
        &'a self,
        command: &'a str,
        case_id: &'a str,
        target: &'a Target,
    ) -> impl Iterator<Item = (usize, &'a Entry)> + 'a {
        self.entries.iter().enumerate().filter(move |(_, entry)| {
            entry.command == command
                && &entry.target == target
                && glob::matches(&entry.case, case_id)
        })
    }

    /// The entries that applied nowhere: stale, each with its index.
    pub fn stale<'a>(&'a self, usage: &'a Usage) -> impl Iterator<Item = (usize, &'a Entry)> + 'a {
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, _)| !usage.is_used(*index))
    }
}

fn location(text: &str, span: Option<std::ops::Range<usize>>) -> String {
    match span {
        Some(span) => {
            let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
            format!(" (line {line})")
        }
        None => String::new(),
    }
}

fn check_entry(raw: RawEntry) -> Result<Entry, Vec<String>> {
    let mut problems = Vec::new();
    for (field, value) in [
        ("command", &raw.command),
        ("case", &raw.case),
        ("target", &raw.target),
        ("rule", &raw.rule),
        ("oracle", &raw.oracle),
        ("candidate", &raw.candidate),
        ("reason", &raw.reason),
        ("issue", &raw.issue),
        ("changelog", &raw.changelog),
    ] {
        if value.trim().is_empty() {
            problems.push(format!("`{field}` is blank"));
        }
    }
    let command_ok = raw.command.split(' ').all(|word| {
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    if !raw.command.trim().is_empty() && !command_ok {
        problems.push(format!(
            "`command` {:?} is not a command path (lowercase words, one space apart)",
            raw.command
        ));
    }
    if !issue_url(&raw.issue) && !raw.issue.trim().is_empty() {
        problems.push(format!(
            "`issue` {:?} is not https://github.com/opentidehq/<repository>/issues/<number>",
            raw.issue
        ));
    }
    let target = Target::parse(&raw.target);
    if target.is_none() && !raw.target.trim().is_empty() {
        problems.push(format!(
            "`target` {:?} is not stdout, stderr, exit_code or file:<relative path>",
            raw.target
        ));
    }
    let rule = match (&target, raw.rule.as_str()) {
        (Some(Target::ExitCode), "text") => {
            match (raw.oracle.trim().parse(), raw.candidate.trim().parse()) {
                (Ok(oracle), Ok(candidate)) => Some(Rule::ExitCode { oracle, candidate }),
                _ => {
                    problems
                        .push("on `exit_code`, `oracle` and `candidate` are integers".to_owned());
                    None
                }
            }
        }
        (Some(Target::ExitCode), _) => {
            problems.push("on `exit_code`, `rule` is `text`".to_owned());
            None
        }
        (_, "text") if raw.oracle.contains('\n') || raw.candidate.contains('\n') => {
            problems.push(
                "a `text` rule's `oracle` and `candidate` are one line each: it applies line by line"
                    .to_owned(),
            );
            None
        }
        (_, "text") => Some(Rule::Text {
            oracle: raw.oracle.clone(),
            candidate: raw.candidate.clone(),
        }),
        (_, rule) => match rule.strip_prefix("json:") {
            Some(pointer) => match json::parse_pointer(pointer) {
                Some(pointer) => {
                    let oracle = json_value(&raw.oracle, "oracle", &mut problems);
                    let candidate = json_value(&raw.candidate, "candidate", &mut problems);
                    match (oracle, candidate) {
                        (Side::Absent, Side::Absent) => {
                            problems.push("`oracle` and `candidate` are both (absent)".to_owned());
                            None
                        }
                        (Side::Invalid, _) | (_, Side::Invalid) => None,
                        (oracle, candidate) => Some(Rule::Json {
                            pointer,
                            oracle: oracle.value(),
                            candidate: candidate.value(),
                        }),
                    }
                }
                None => {
                    problems.push(format!(
                        "`rule` {rule:?}: {pointer:?} is not a JSON pointer (empty, or starting with /)"
                    ));
                    None
                }
            },
            None => {
                if !rule.trim().is_empty() {
                    problems.push(format!("`rule` {rule:?} is not `text` or `json:<pointer>`"));
                }
                None
            }
        },
    };
    let same = match &rule {
        Some(Rule::Json {
            oracle, candidate, ..
        }) => oracle == candidate,
        Some(Rule::Text { oracle, candidate }) => oracle == candidate,
        Some(Rule::ExitCode { oracle, candidate }) => oracle == candidate,
        None => false,
    };
    if same {
        problems.push(
            "`oracle` and `candidate` are the same: there is no difference to approve".to_owned(),
        );
    }
    match (target, rule) {
        (Some(target), Some(rule)) if problems.is_empty() => Ok(Entry {
            command: raw.command,
            case: raw.case,
            target,
            rule_text: raw.rule,
            rule,
            reason: raw.reason,
            issue: raw.issue,
            changelog: raw.changelog,
        }),
        _ => Err(problems),
    }
}

/// One side of a `json:` rule, as written.
enum Side {
    /// `(absent)`.
    Absent,
    /// A JSON text.
    Value(Json),
    /// Neither: a problem was reported.
    Invalid,
}

impl Side {
    fn value(self) -> Option<Json> {
        match self {
            Side::Value(value) => Some(value),
            Side::Absent | Side::Invalid => None,
        }
    }
}

/// One side of a `json:` rule, reporting a text that is neither.
fn json_value(text: &str, field: &str, problems: &mut Vec<String>) -> Side {
    if text == ABSENT {
        return Side::Absent;
    }
    match json::parse_str(text) {
        Some(value) => Side::Value(value),
        None => {
            if !text.trim().is_empty() {
                problems.push(format!("`{field}` is neither JSON nor {ABSENT}: {text:?}"));
            }
            Side::Invalid
        }
    }
}

fn issue_url(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://github.com/opentidehq/") else {
        return false;
    };
    let mut parts = rest.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(repo), Some("issues"), Some(number), None)
            if !repo.is_empty() && !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: &str = r#"
[[diff]]
command = "info"
case = "json/*"
target = "stdout"
rule = "json:/summary/rules"
oracle = "1"
candidate = "2"
reason = "the Rust index counts nested objects"
issue = "https://github.com/opentidehq/opentide/issues/805"
changelog = "**Nested rules**"
"#;

    #[test]
    fn a_complete_entry_parses() {
        let ledger = Ledger::parse(ENTRY).unwrap();
        assert_eq!(ledger.entries.len(), 1);
        let entry = &ledger.entries[0];
        assert_eq!(entry.target, Target::Stdout);
        assert_eq!(
            entry.rule,
            Rule::Json {
                pointer: vec!["summary".into(), "rules".into()],
                oracle: json::parse_str("1"),
                candidate: json::parse_str("2"),
            }
        );
    }

    #[test]
    fn an_empty_ledger_has_no_entries() {
        assert_eq!(
            Ledger::parse("# nothing approved\n").unwrap(),
            Ledger::default()
        );
    }

    #[test]
    fn every_field_is_required() {
        for field in [
            "command",
            "case",
            "target",
            "rule",
            "oracle",
            "candidate",
            "reason",
            "issue",
            "changelog",
        ] {
            let text = ENTRY
                .lines()
                .filter(|line| !line.starts_with(&format!("{field} =")))
                .collect::<Vec<_>>()
                .join("\n");
            let error = Ledger::parse(&text).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{field}`")),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn a_blank_field_and_an_unknown_field_fail() {
        let blank = ENTRY.replace(
            "reason = \"the Rust index counts nested objects\"",
            "reason = \" \"",
        );
        assert!(
            Ledger::parse(&blank)
                .unwrap_err()
                .to_string()
                .contains("`reason` is blank")
        );
        let unknown = format!("{ENTRY}note = \"x\"\n");
        assert!(
            Ledger::parse(&unknown)
                .unwrap_err()
                .to_string()
                .contains("unknown field `note`")
        );
    }

    #[test]
    fn bad_values_are_each_reported() {
        let text = ENTRY
            .replace("target = \"stdout\"", "target = \"file:../x\"")
            .replace(
                "issue = \"https://github.com/opentidehq/opentide/issues/805\"",
                "issue = \"#805\"",
            )
            .replace("command = \"info\"", "command = \"Info\"");
        let error = Ledger::parse(&text).unwrap_err();
        assert_eq!(error.problems.len(), 3, "{error}");
        let pointer = ENTRY.replace("json:/summary/rules", "json:summary");
        assert!(
            Ledger::parse(&pointer)
                .unwrap_err()
                .to_string()
                .contains("not a JSON pointer")
        );
        let value = ENTRY.replace("oracle = \"1\"", "oracle = \"{\"");
        assert!(
            Ledger::parse(&value)
                .unwrap_err()
                .to_string()
                .contains("neither JSON nor (absent)")
        );
        let same = ENTRY.replace("candidate = \"2\"", "candidate = \"1\"");
        assert!(
            Ledger::parse(&same)
                .unwrap_err()
                .to_string()
                .contains("are the same")
        );
        let both_absent = ENTRY
            .replace("oracle = \"1\"", "oracle = \"(absent)\"")
            .replace("candidate = \"2\"", "candidate = \"(absent)\"");
        assert!(
            Ledger::parse(&both_absent)
                .unwrap_err()
                .to_string()
                .contains("both (absent)")
        );
        let exit = ENTRY
            .replace("target = \"stdout\"", "target = \"exit_code\"")
            .replace("json:/summary/rules", "text")
            .replace("oracle = \"1\"", "oracle = \"one\"");
        assert!(
            Ledger::parse(&exit)
                .unwrap_err()
                .to_string()
                .contains("are integers")
        );
    }

    #[test]
    fn a_text_rule_is_one_line_each_side() {
        let text = ENTRY
            .replace("json:/summary/rules", "text")
            .replace("oracle = \"1\"", "oracle = \"a\\nb\"");
        assert!(
            Ledger::parse(&text)
                .unwrap_err()
                .to_string()
                .contains("one line each")
        );
    }

    #[test]
    fn duplicates_fail() {
        let text = format!("{ENTRY}{ENTRY}");
        assert!(
            Ledger::parse(&text)
                .unwrap_err()
                .to_string()
                .contains("as entry 1")
        );
    }

    #[test]
    fn the_changelog_reference_must_exist() {
        let ledger = Ledger::parse(ENTRY).unwrap();
        assert!(
            ledger
                .missing_changelog("- **Nested rules** are counted")
                .is_empty()
        );
        assert_eq!(ledger.missing_changelog("nothing").len(), 1);
    }

    #[test]
    fn entries_match_command_target_and_case_glob() {
        let ledger = Ledger::parse(ENTRY).unwrap();
        assert_eq!(
            ledger
                .entries_for("info", "json/tide_corpus", &Target::Stdout)
                .count(),
            1
        );
        assert_eq!(
            ledger
                .entries_for("info", "plain/tide_corpus", &Target::Stdout)
                .count(),
            0
        );
        assert_eq!(
            ledger
                .entries_for("info", "json/x", &Target::Stderr)
                .count(),
            0
        );
        assert_eq!(
            ledger
                .entries_for("info rules", "json/x", &Target::Stdout)
                .count(),
            0
        );
    }

    #[test]
    fn targets_parse() {
        assert_eq!(
            Target::parse("file:a/b.json"),
            Some(Target::File("a/b.json".into()))
        );
        assert_eq!(Target::parse("file:/abs"), None);
        assert_eq!(Target::parse("file:a//b"), None);
        assert_eq!(Target::parse("stdin"), None);
        assert_eq!(Target::File("a".into()).to_string(), "file:a");
    }
}
