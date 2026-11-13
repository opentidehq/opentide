//! `cargo xtask vocab diff --against python`: every vocabulary value of every
//! corpus, and over ten thousand generated misspellings, resolved by the
//! oracle (the frozen Python CLI) and by `opentide_schema::vocab`, compared.
//!
//! For each fixture workspace of `tests/golden/cases.toml` (the corpora), the
//! oracle validates the workspace and reports every value its vocabulary
//! check resolved, with the field's vocabulary, stages and scope
//! (`probe.py`). For each such field, and for each field the object schemas
//! declare, both sides then give:
//!
//! - the values the field accepts, in order: must be equal;
//! - for every value, whether it is valid: must be equal;
//! - for every invalid value, the suggestion. Suggestions are
//!   `opentide_core::suggest`'s, not Python `difflib`'s, by decision (#812):
//!   a corpus value whose suggestion differs must be listed in
//!   `tests/golden/vocab/APPROVED.toml`, and an entry that matches nothing is
//!   stale; differences on generated misspellings are counted and reported.
//!
//! And every `vocab_unknown` finding the oracle's `validate --json` reports on
//! a corpus: its `message` must equal, byte for byte, the one
//! `opentide_schema::vocab::Unknown` gives for the same value of the same
//! field, and its `help` too, unless the suggestion difference it carries is
//! approved.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use opentide_schema::vocab::{
    Entry, KeyKind, Metadata, Selector, Unknown, Version, VocabRef, Vocabularies, Vocabulary,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The probe the oracle runs.
const PROBE: &str = include_str!("probe.py");

/// The approved suggestion differences, relative to the repository.
pub const APPROVED: &str = "tests/golden/vocab/APPROVED.toml";

/// The fixtures compared by default: every corpus of `cases.toml` with
/// objects in it.
pub const FIXTURES: [&str; 5] = [
    "vscode",
    "tide-corpus",
    "tide-corpus-typo",
    "heavy-small",
    "fault",
];

/// What the object schemas ask of the bundled vocabularies (`tide.vocab`
/// and `tide.vocab.scoped` in every revision's schema, at the frozen tag).
pub const SCHEMA_SELECTORS: [(&str, bool); 16] = [
    ("actors::1.1", true),
    ("alert_severity::1.0", false),
    ("att&ck::1.2", false),
    ("chaining_relations::1.0", false),
    ("criticality::1.0", false),
    ("detection.composition::1.0", false),
    ("detection.methodology::1.0", false),
    ("detection.types::1.0", false),
    ("impact::1.0", false),
    ("killchain::1.0", false),
    ("leverage::1.0", false),
    ("severity::1.0", false),
    ("signal.entities::1.0", true),
    ("surface::1.0", true),
    ("tlp::1.0", false),
    ("viability::1.0", false),
];

/// One approved suggestion difference on a corpus value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approved {
    /// The vocabulary reference (`severity::1.0`).
    pub vocab: String,
    /// The value.
    pub value: String,
    /// The oracle's suggestion, empty for none.
    pub oracle: String,
    /// The candidate's suggestion, empty for none.
    pub candidate: String,
    /// Why the candidate's is right.
    pub reason: String,
    /// The issue that decided it.
    pub issue: String,
    /// The bold lead of the CHANGELOG.md entry that announces it.
    pub changelog: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedFile {
    #[serde(default)]
    diff: Vec<Approved>,
}

/// Reads the approved differences, checking every field is filled and the
/// changelog holds each lead.
pub fn read_approved(text: &str, changelog: &str) -> Result<Vec<Approved>> {
    let file: ApprovedFile = toml::from_str(text).context("parse the approved differences")?;
    for entry in &file.diff {
        ensure!(
            !entry.reason.is_empty() && entry.issue.starts_with("https://github.com/opentidehq/"),
            "{}: `{}` needs a reason and an opentidehq issue",
            APPROVED,
            entry.value
        );
        ensure!(
            changelog.contains(&entry.changelog),
            "{}: CHANGELOG.md has no entry `{}`",
            APPROVED,
            entry.changelog
        );
    }
    Ok(file.diff)
}

/// A selector as both sides exchange it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Field {
    /// `tide.vocab`.
    pub vocab: String,
    /// `tide.vocab.stages`.
    pub stages: Option<Vec<String>>,
    /// `tide.vocab.scoped`.
    pub scoped: bool,
}

impl Field {
    fn selector(&self) -> Result<Selector> {
        let vocab: VocabRef = self
            .vocab
            .parse()
            .with_context(|| format!("vocabulary reference {}", self.vocab))?;
        Ok(Selector::new(vocab)
            .scoped(self.scoped)
            .stages(self.stages.clone().unwrap_or_default()))
    }
}

#[derive(Debug, Deserialize)]
struct ProbeResult {
    #[serde(default)]
    corpus: Vec<CorpusField>,
    results: Vec<FieldResult>,
    models: BTreeMap<String, Model>,
    #[serde(default)]
    findings: Vec<Finding>,
}

/// A `vocab_unknown` finding of the oracle's `validate --json` report.
#[derive(Debug, Clone, Deserialize)]
struct Finding {
    vocab: String,
    value: String,
    message: String,
    help: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CorpusField {
    vocab: String,
    stages: Option<Vec<String>>,
    scoped: bool,
    values: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FieldResult {
    vocab: String,
    stages: Option<Vec<String>>,
    scoped: bool,
    allowed: Vec<String>,
    checked: Vec<(String, bool, Option<String>)>,
}

#[derive(Debug, Deserialize)]
struct Model {
    name: String,
    entries: Vec<ModelEntry>,
}

#[derive(Debug, Deserialize)]
struct ModelEntry {
    key: String,
    name: String,
    version: String,
    removed: Option<String>,
    stages: Vec<String>,
}

/// The workspace's object vocabularies, as the oracle indexed them.
fn model_vocabulary(field: &str, model: &Model) -> Result<Vocabulary> {
    let mut entries = IndexMap::new();
    for entry in &model.entries {
        let parse = |text: &str| -> Result<Version> {
            text.parse()
                .with_context(|| format!("{field} entry {}: version {text}", entry.key))
        };
        entries.insert(
            entry.key.clone(),
            Entry {
                key: entry.key.clone(),
                name: entry.name.clone(),
                version: parse(&entry.version)?,
                removed: entry.removed.as_deref().map(parse).transpose()?,
                description: String::new(),
                icon: String::new(),
                link: String::new(),
                stages: entry.stages.clone(),
                extra: toml::Table::new(),
            },
        );
    }
    Ok(Vocabulary {
        metadata: Metadata {
            name: model.name.clone(),
            field: field.to_owned(),
            description: String::new(),
            icon: String::new(),
            key: KeyKind::Id,
            stages: Vec::new(),
            extra: toml::Table::new(),
        },
        entries,
        skipped: Vec::new(),
    })
}

/// Single-edit misspellings of `value`: rounds of a deletion, a
/// transposition, a substitution and an insertion, each at a position and
/// with a letter that `seed` and the round choose, so the set is the same on
/// every run.
pub fn misspellings(value: &str, seed: usize) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return Vec::new();
    }
    let letters: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let at = |k: usize| (seed * 31 + k * 17) % chars.len();
    let letter = |k: usize| letters[(seed * 7 + k * 13) % letters.len()];
    let collect = |v: Vec<char>| v.into_iter().collect::<String>();
    let mut typos = Vec::new();
    // One round per position, up to twelve: four edits each.
    for round in 0..chars.len().min(12) {
        let i = at(round);
        let mut deleted = chars.clone();
        deleted.remove(i);
        typos.push(collect(deleted));
        if i + 1 < chars.len() {
            let mut swapped = chars.clone();
            swapped.swap(i, i + 1);
            typos.push(collect(swapped));
        }
        let mut substituted = chars.clone();
        substituted[i] = letter(round);
        typos.push(collect(substituted));
        let mut inserted = chars.clone();
        inserted.insert(i, letter(round + 1));
        typos.push(collect(inserted));
    }
    typos.retain(|typo| !typo.is_empty() && typo != value);
    let mut unique = std::collections::BTreeSet::new();
    typos.retain(|typo| unique.insert(typo.clone()));
    typos
}

/// The generated values to check for each schema field: up to `per_field`
/// of its accepted values, spread over it, each with its misspellings.
pub fn generated(per_field: usize) -> Result<Vec<(Field, Vec<String>)>> {
    let vocabularies = Vocabularies::bundled();
    let mut fields = Vec::new();
    for (vocab, scoped) in SCHEMA_SELECTORS {
        let field = Field {
            vocab: vocab.to_owned(),
            stages: None,
            scoped,
        };
        let allowed = vocabularies.allowed(&field.selector()?);
        let step = (allowed.len() / per_field).max(1);
        let mut values = Vec::new();
        for (n, value) in allowed.iter().enumerate().step_by(step).take(per_field) {
            values.push(value.clone());
            values.extend(misspellings(value, n));
        }
        fields.push((field, values));
    }
    Ok(fields)
}

/// The comparison of one fixture.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    /// The fixture.
    pub fixture: String,
    /// Fields compared.
    pub fields: usize,
    /// Values of the corpus compared.
    pub corpus_values: usize,
    /// Generated values compared.
    pub generated_values: usize,
    /// Accepted-value lists that differ: always a failure.
    pub allowed_mismatches: Vec<String>,
    /// Validity verdicts that differ: always a failure.
    pub validity_mismatches: Vec<String>,
    /// Invalid values whose suggestions agree.
    pub same_suggestions: usize,
    /// Corpus values whose suggestions differ: (vocab, value, oracle, candidate).
    pub corpus_suggestions: Vec<(String, String, String, String)>,
    /// Generated values whose suggestions differ.
    pub generated_suggestions: usize,
    /// Of those, where only the oracle suggests something.
    pub generated_oracle_only: usize,
    /// Of those, where only the candidate suggests something.
    pub generated_candidate_only: usize,
    /// The oracle's `vocab_unknown` findings compared.
    pub findings: usize,
    /// Of those, the ones whose message and help are byte-identical.
    pub identical_findings: usize,
    /// Findings whose message differs, or that the candidate does not report:
    /// always a failure.
    pub finding_mismatches: Vec<String>,
    /// Findings whose help differs: (vocab, value, oracle, candidate), each
    /// help or "" for none. Approved only with the suggestion difference.
    pub finding_helps: Vec<(String, String, String, String)>,
}

/// Compares the probe's `result` with `opentide_schema::vocab`.
fn compare(fixture: &str, result: &ProbeResult) -> Result<Outcome> {
    let mut vocabularies = Vocabularies::bundled();
    for (field, model) in &result.models {
        vocabularies.insert(model_vocabulary(field, model)?);
    }
    let corpus: BTreeMap<Field, Vec<&String>> = result
        .corpus
        .iter()
        .map(|c| {
            (
                Field {
                    vocab: c.vocab.clone(),
                    stages: c.stages.clone(),
                    scoped: c.scoped,
                },
                c.values.iter().collect(),
            )
        })
        .collect();
    let mut outcome = Outcome {
        fixture: fixture.to_owned(),
        ..Outcome::default()
    };
    for field_result in &result.results {
        let field = Field {
            vocab: field_result.vocab.clone(),
            stages: field_result.stages.clone(),
            scoped: field_result.scoped,
        };
        outcome.fields += 1;
        let resolved = vocabularies.resolve(&field.selector()?);
        let allowed: Vec<&str> = resolved.values().collect();
        if allowed
            != field_result
                .allowed
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            outcome.allowed_mismatches.push(format!(
                "{field:?}: the oracle accepts {} values, the candidate {}",
                field_result.allowed.len(),
                allowed.len()
            ));
        }
        let in_corpus = |value: &String| {
            corpus
                .get(&field)
                .is_some_and(|values| values.contains(&value))
        };
        for (value, valid, suggestion) in &field_result.checked {
            let from_corpus = in_corpus(value);
            if from_corpus {
                outcome.corpus_values += 1;
            } else {
                outcome.generated_values += 1;
            }
            let candidate_valid = resolved.is_valid(value);
            if candidate_valid != *valid {
                outcome.validity_mismatches.push(format!(
                    "{} {value:?}: the oracle says {}, the candidate {}",
                    field.vocab,
                    if *valid { "valid" } else { "invalid" },
                    if candidate_valid { "valid" } else { "invalid" }
                ));
                continue;
            }
            if *valid {
                continue;
            }
            let candidate = resolved.suggest(value);
            if candidate == *suggestion {
                outcome.same_suggestions += 1;
            } else if from_corpus {
                outcome.corpus_suggestions.push((
                    field.vocab.clone(),
                    value.clone(),
                    suggestion.clone().unwrap_or_default(),
                    candidate.unwrap_or_default(),
                ));
            } else {
                outcome.generated_suggestions += 1;
                match (suggestion, &candidate) {
                    (Some(_), None) => outcome.generated_oracle_only += 1,
                    (None, Some(_)) => outcome.generated_candidate_only += 1,
                    _ => {}
                }
            }
        }
    }
    compare_findings(&vocabularies, &corpus, &result.findings, &mut outcome)?;
    Ok(outcome)
}

/// Compares each of the oracle's `vocab_unknown` findings with the candidate's
/// for the field of the corpus that holds its value.
fn compare_findings(
    vocabularies: &Vocabularies,
    corpus: &BTreeMap<Field, Vec<&String>>,
    findings: &[Finding],
    outcome: &mut Outcome,
) -> Result<()> {
    for finding in findings {
        outcome.findings += 1;
        let mut unknown = None;
        for (field, values) in corpus {
            if field.vocab == finding.vocab && values.contains(&&finding.value) {
                unknown = vocabularies.check(&finding.value, &field.selector()?);
                if unknown.is_some() {
                    break;
                }
            }
        }
        let Some(unknown) = unknown else {
            outcome.finding_mismatches.push(format!(
                "{} {:?}: the oracle reports vocab_unknown, the candidate accepts it",
                finding.vocab, finding.value
            ));
            continue;
        };
        // The message names the same value and vocabulary in the same words;
        // its quotes are Rust's where the oracle's were Python's repr
        // (**Messages quote values the same way everywhere**).
        let message = unknown.message();
        if unquoted(&message) != unquoted(&finding.message) {
            outcome.finding_mismatches.push(format!(
                "{} {:?}: message {:?}, the oracle's {:?}",
                finding.vocab, finding.value, message, finding.message
            ));
            continue;
        }
        let suggestion = unknown.suggestion.clone().unwrap_or_default();
        let oracle = finding.help.as_deref().map(suggested).unwrap_or_default();
        if suggestion == oracle {
            outcome.identical_findings += 1;
        } else {
            outcome.finding_helps.push((
                finding.vocab.clone(),
                finding.value.clone(),
                oracle,
                suggestion,
            ));
        }
    }
    Ok(())
}

/// `text` without its quote characters.
fn unquoted(text: &str) -> String {
    text.chars().filter(|c| !matches!(c, '\'' | '"')).collect()
}

/// The suggestion a help line names (`did you mean 'clear'?`), whatever
/// quotes it.
fn suggested(help: &str) -> String {
    help.strip_prefix("did you mean ")
        .and_then(|rest| rest.strip_suffix('?'))
        .map_or(help, |quoted| quoted.trim_matches(['\'', '"']))
        .to_owned()
}

/// Whether `entry` approves a finding's `help` difference: the two helps
/// suggest its two suggestions.
fn approves_help(
    entry: &Approved,
    vocab: &str,
    value: &str,
    oracle: &str,
    candidate: &str,
) -> bool {
    entry.vocab == vocab
        && entry.value == value
        && entry.oracle == oracle
        && entry.candidate == candidate
}

/// The repository root and the target directory, from `cargo metadata`.
pub fn workspace() -> Result<(PathBuf, PathBuf)> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(["metadata", "--format-version", "1", "--no-deps"]);
    if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        command.current_dir(dir);
    }
    let output = command.output().context("run cargo metadata")?;
    ensure!(output.status.success(), "cargo metadata failed");
    let doc: Value = serde_json::from_slice(&output.stdout)?;
    let path = |key: &str| -> Result<PathBuf> {
        Ok(PathBuf::from(
            doc[key].as_str().with_context(|| format!("no {key}"))?,
        ))
    };
    Ok((path("workspace_root")?, path("target_directory")?))
}

/// The options of `vocab diff`.
#[derive(Debug, Default)]
pub struct Options {
    /// The oracle's Python; installed from `tests/golden/ORACLE` when `None`.
    pub python: Option<PathBuf>,
    /// The fixtures; [`FIXTURES`] when empty.
    pub fixtures: Vec<String>,
    /// Accepted values sampled per schema field for the generated set.
    pub per_field: usize,
    /// Where to write the JSON report.
    pub report: Option<PathBuf>,
}

/// Runs the comparison. Whether it passed.
pub fn run(options: &Options) -> Result<bool> {
    let (repo, target) = workspace()?;
    let golden = repo.join("tests/golden");
    let python = match &options.python {
        Some(python) => python.clone(),
        None => {
            let oracle =
                crate::golden::oracle::Oracle::parse(&fs::read_to_string(golden.join("ORACLE"))?)?;
            let engine = oracle.provision(&golden, &crate::golden::oracle::cache_dir(&target))?;
            engine.install_dir.join("bin").join("python")
        }
    };
    let spec = crate::golden::case::Spec::parse(&fs::read_to_string(golden.join("cases.toml"))?)?;
    let changelog = fs::read_to_string(repo.join("CHANGELOG.md"))?;
    let approved = read_approved(&fs::read_to_string(repo.join(APPROVED))?, &changelog)?;
    let fixtures: Vec<String> = if options.fixtures.is_empty() {
        FIXTURES.iter().map(|f| (*f).to_owned()).collect()
    } else {
        options.fixtures.clone()
    };
    let generated = generated(options.per_field)?;
    let scratch = tempfile::tempdir()?;
    fs::write(scratch.path().join("probe.py"), PROBE)?;

    let mut outcomes = Vec::new();
    for (n, fixture) in fixtures.iter().enumerate() {
        let fixture_spec = spec
            .fixtures
            .get(fixture)
            .with_context(|| format!("cases.toml has no fixture `{fixture}`"))?;
        let root = scratch.path().join(fixture);
        let ws = root.join("ws");
        fs::create_dir_all(&ws)?;
        fixture_spec
            .materialise(&repo, &ws)
            .with_context(|| format!("materialise {fixture}"))?;
        // The generated set is checked once, against the first fixture.
        let selectors: Vec<Value> = if n == 0 {
            generated
                .iter()
                .map(|(field, values)| {
                    json!({"vocab": field.vocab, "stages": field.stages, "scoped": field.scoped, "values": values})
                })
                .collect()
        } else {
            SCHEMA_SELECTORS
                .iter()
                .map(|(vocab, scoped)| json!({"vocab": vocab, "stages": null, "scoped": scoped, "values": []}))
                .collect()
        };
        let request = root.join("request.json");
        let response = root.join("result.json");
        fs::write(
            &request,
            serde_json::to_string(&json!({"repo": ws, "selectors": selectors}))?,
        )?;
        let home = root.join("home");
        fs::create_dir_all(&home)?;
        let status = Command::new(&python)
            .arg("-I")
            .arg(scratch.path().join("probe.py"))
            .arg(&request)
            .arg(&response)
            .env_clear()
            .env(
                "PATH",
                python.parent().map(Path::as_os_str).unwrap_or_default(),
            )
            .env("HOME", &home)
            .env("NO_COLOR", "1")
            .env("OPENTIDE_NO_UPDATE_CHECK", "1")
            .status()
            .with_context(|| format!("run {}", python.display()))?;
        ensure!(
            status.success(),
            "the oracle's probe failed on {fixture} ({status})"
        );
        let text = fs::read_to_string(&response)
            .with_context(|| format!("the probe wrote no result for {fixture}"))?;
        let result: ProbeResult = serde_json::from_str(&text)
            .with_context(|| format!("read the probe's result for {fixture}"))?;
        let outcome = compare(fixture, &result)?;
        print!("{}", describe(&outcome));
        outcomes.push(outcome);
    }

    let mut passed = true;
    let mut used = vec![false; approved.len()];
    for outcome in &outcomes {
        passed &= outcome.allowed_mismatches.is_empty()
            && outcome.validity_mismatches.is_empty()
            && outcome.finding_mismatches.is_empty();
        for (vocab, value, oracle, candidate) in &outcome.finding_helps {
            if !approved
                .iter()
                .any(|a| approves_help(a, vocab, value, oracle, candidate))
            {
                passed = false;
                eprintln!(
                    "error: {}: the vocab_unknown help of {vocab} {value:?} suggests {candidate:?}, \
                     the oracle's {oracle:?}, and {APPROVED} does not approve the suggestion",
                    outcome.fixture
                );
            }
        }
        for (vocab, value, oracle, candidate) in &outcome.corpus_suggestions {
            match approved.iter().position(|a| {
                &a.vocab == vocab
                    && &a.value == value
                    && &a.oracle == oracle
                    && &a.candidate == candidate
            }) {
                Some(index) => used[index] = true,
                None => {
                    passed = false;
                    eprintln!(
                        "error: {}: {vocab} {value:?} suggests {candidate:?}, the oracle {oracle:?}, \
                         and {APPROVED} does not approve it",
                        outcome.fixture
                    );
                }
            }
        }
    }
    let complete = options.fixtures.is_empty();
    for (entry, used) in approved.iter().zip(&used) {
        if complete && !used {
            passed = false;
            eprintln!(
                "error: {APPROVED}: {} {:?} applied to no corpus value: it is stale, remove it",
                entry.vocab, entry.value
            );
        }
    }
    if let Some(path) = &options.report {
        fs::write(path, serde_json::to_string_pretty(&outcomes)? + "\n")?;
    }
    println!(
        "vocab diff: {}",
        if passed {
            "every difference is approved"
        } else {
            "FAILED"
        }
    );
    Ok(passed)
}

fn describe(outcome: &Outcome) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}: {} fields, {} corpus values, {} generated values; {} accepted-value and {} validity \
         mismatches; {} invalid values suggest the same, {} corpus and {} generated suggest \
         otherwise ({} only the oracle suggests, {} only the candidate); {} of {} vocab_unknown \
         findings byte-identical",
        outcome.fixture,
        outcome.fields,
        outcome.corpus_values,
        outcome.generated_values,
        outcome.allowed_mismatches.len(),
        outcome.validity_mismatches.len(),
        outcome.same_suggestions,
        outcome.corpus_suggestions.len(),
        outcome.generated_suggestions,
        outcome.generated_oracle_only,
        outcome.generated_candidate_only,
        outcome.identical_findings,
        outcome.findings,
    );
    for line in outcome
        .allowed_mismatches
        .iter()
        .chain(&outcome.validity_mismatches)
        .chain(&outcome.finding_mismatches)
    {
        let _ = writeln!(out, "  mismatch: {line}");
    }
    for (vocab, value, oracle, candidate) in &outcome.corpus_suggestions {
        let _ = writeln!(
            out,
            "  suggestion: {vocab} {value:?}: oracle {oracle:?}, candidate {candidate:?}"
        );
    }
    for (vocab, value, oracle, candidate) in &outcome.finding_helps {
        let _ = writeln!(
            out,
            "  help: {vocab} {value:?}: oracle {oracle:?}, candidate {candidate:?}"
        );
    }
    out
}

/// Parses `vocab diff`'s arguments.
pub fn parse(args: &[String]) -> Result<Options> {
    let mut options = Options {
        per_field: 60,
        ..Options::default()
    };
    let mut against = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--against" => against = Some(value()?),
            "--python" => options.python = Some(PathBuf::from(value()?)),
            "--fixture" => options.fixtures.push(value()?),
            "--per-field" => {
                options.per_field = value()?.parse().context("--per-field is a number")?;
            }
            "--report" => options.report = Some(PathBuf::from(value()?)),
            other => bail!("unknown option `{other}`"),
        }
    }
    match against.as_deref() {
        Some("python") => Ok(options),
        Some(other) => bail!("--against {other}: only `python` (the oracle) is supported"),
        None => bail!("vocab diff needs --against python"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misspellings_are_single_edits_and_deterministic() {
        let typos = misspellings("amber", 3);
        assert_eq!(typos, misspellings("amber", 3));
        assert!(!typos.is_empty());
        for typo in &typos {
            let distance = strsim::osa_distance(typo, "amber");
            assert_eq!(distance, 1, "{typo}");
        }
        assert!(misspellings("", 1).is_empty());
    }

    #[test]
    fn the_generated_set_is_over_ten_thousand_values() {
        let total: usize = generated(60).unwrap().iter().map(|(_, v)| v.len()).sum();
        assert!(total > 10_000, "{total}");
    }

    #[test]
    fn options() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let parsed = parse(&args(&["--against", "python", "--fixture", "vscode"])).unwrap();
        assert_eq!(parsed.fixtures, ["vscode"]);
        assert_eq!(parsed.per_field, 60);
        assert!(parse(&args(&["--against", "rust"])).is_err());
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["--against"])).is_err());
        assert!(parse(&args(&["--against", "python", "--bogus"])).is_err());
    }

    #[test]
    fn the_approved_file_reads_and_its_changelog_entries_exist() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = fs::read_to_string(repo.join(APPROVED)).unwrap();
        let changelog = fs::read_to_string(repo.join("CHANGELOG.md")).unwrap();
        let approved = read_approved(&text, &changelog).unwrap();
        assert!(!approved.is_empty());
        assert!(read_approved(&text, "").is_err());
    }

    #[test]
    fn compares_allowed_validity_and_suggestions() {
        let result = ProbeResult {
            corpus: vec![CorpusField {
                vocab: "tlp::1.0".into(),
                stages: None,
                scoped: false,
                values: vec!["ambr".into(), "whitish".into()],
            }],
            results: vec![FieldResult {
                vocab: "tlp::1.0".into(),
                stages: None,
                scoped: false,
                allowed: ["clear", "green", "amber", "amber+strict", "red"]
                    .map(String::from)
                    .to_vec(),
                checked: vec![
                    ("amber".into(), true, None),
                    ("ambr".into(), false, Some("amber".into())),
                    ("whitish".into(), false, Some("clear".into())),
                    ("gren".into(), true, None),
                ],
            }],
            models: BTreeMap::new(),
            findings: vec![
                Finding {
                    vocab: "tlp::1.0".into(),
                    value: "ambr".into(),
                    message: "Value 'ambr' is not a valid 'tlp::1.0' vocabulary entry".into(),
                    help: Some("did you mean 'amber'?".into()),
                },
                Finding {
                    vocab: "tlp::1.0".into(),
                    value: "whitish".into(),
                    message: "Value 'whitish' is not a valid 'tlp::1.0' vocabulary entry".into(),
                    help: Some("did you mean 'clear'?".into()),
                },
                Finding {
                    vocab: "tlp::1.0".into(),
                    value: "ambr".into(),
                    message: "Value 'ambr' is not a valid 'tlp::0.9' vocabulary entry".into(),
                    help: None,
                },
                Finding {
                    vocab: "tlp::1.0".into(),
                    value: "amber".into(),
                    message: "Value 'amber' is not a valid 'tlp::1.0' vocabulary entry".into(),
                    help: None,
                },
            ],
        };
        let outcome = compare("x", &result).unwrap();
        assert_eq!(outcome.findings, 4);
        assert_eq!(outcome.identical_findings, 1);
        assert_eq!(outcome.finding_mismatches.len(), 2, "{outcome:?}");
        assert_eq!(
            outcome.finding_helps,
            [(
                "tlp::1.0".into(),
                "whitish".into(),
                "clear".into(),
                String::new()
            )]
        );
        assert!(outcome.allowed_mismatches.is_empty());
        assert_eq!(outcome.validity_mismatches.len(), 1, "{outcome:?}");
        assert_eq!(outcome.same_suggestions, 1);
        assert_eq!(
            outcome.corpus_suggestions,
            [(
                "tlp::1.0".into(),
                "whitish".into(),
                "clear".into(),
                String::new()
            )]
        );
        assert_eq!(outcome.corpus_values, 2);
        assert_eq!(outcome.generated_values, 2);
    }

    #[test]
    fn a_help_difference_is_approved_only_with_its_suggestion() {
        let entry = Approved {
            vocab: "tlp::1.0".into(),
            value: "whitish".into(),
            oracle: "clear".into(),
            candidate: String::new(),
            reason: "r".into(),
            issue: "https://github.com/opentidehq/opentide/issues/812".into(),
            changelog: "c".into(),
        };
        let approves = |vocab: &str, value: &str, oracle: &str, candidate: &str| {
            approves_help(&entry, vocab, value, oracle, candidate)
        };
        assert!(approves("tlp::1.0", "whitish", "clear", ""));
        assert!(!approves("tlp::1.0", "whitish", "red", ""));
        assert!(!approves("tlp::1.0", "whitish", "clear", "red"));
        assert!(!approves("tlp::1.0", "whitis", "clear", ""));
        assert!(!approves("severity::1.0", "whitish", "clear", ""));
        assert_eq!(suggested("did you mean 'clear'?"), "clear");
        assert_eq!(suggested("did you mean \"clear\"?"), "clear");
    }

    #[test]
    fn object_vocabularies_from_the_probe() {
        let model = Model {
            name: "Objectives".into(),
            entries: vec![ModelEntry {
                key: "6f1c".into(),
                name: "Detect".into(),
                version: "1.0".into(),
                removed: None,
                stages: vec![],
            }],
        };
        let vocabulary = model_vocabulary("objective", &model).unwrap();
        assert_eq!(vocabulary.metadata.key, KeyKind::Id);
        let mut set = Vocabularies::bundled();
        set.insert(vocabulary);
        let selector = Selector::new("objective".parse().unwrap());
        assert!(set.is_valid("6f1c", &selector));
    }
}
