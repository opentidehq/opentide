//! `opentide migrate vocab-scope` (UC-3.5c, #928): re-prefix the authored
//! values of stage-scoped vocabulary fields (`Process` -> `Host::Process`).
//!
//! A field declared scoped authors `<stage>::<key>`. When a field becomes
//! scoped, or a vocabulary's stage identifiers change, the objects already
//! on disk carry the earlier form. This module decides, for each authored
//! value, the scoped form the current vocabulary accepts ([`ScopeIndex`]),
//! and rewrites a document's text over the exact span of each value it
//! changes ([`rewrite`]), so comments, key order, quoting and flow sequences
//! stay as they were. Three properties keep it safe on a real corpus:
//!
//! - **Nothing is guessed.** A bare key defined under several stages is
//!   reported ([`Status::Ambiguous`]) and left as it is; only mechanical
//!   outcomes (an implied single stage, a stage's casing) are applied.
//! - **Only the declared field is touched.** Values are found by their path
//!   through the document ([`SCOPED_FIELDS`]), not by a key's name: a
//!   Sentinel block's `entities` holds entity mappings, not vocabulary.
//! - **Every rewrite is checked** ([`verify`]): the rewritten text is read
//!   again, the field's values must be the planned ones, and nothing outside
//!   the field may differ.
//!
//! The text is read with this crate's YAML 1.2 node tree ([`crate::node`]).
//! The command (`opentide-cli`) reads and writes the files.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::node::{self, Node, Value};
use crate::vocab::{KeyKind, Vocabulary, quote};

/// The separator of a scoped value: `Host::Process`.
pub const SCOPE_SEPARATOR: &str = "::";

/// A path segment that matches every item of a sequence.
pub const ANY: &str = "*";

/// A field authored as `<stage>::<key>`: its vocabulary and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedField {
    /// The field's name on the command line (`--field`).
    pub name: &'static str,
    /// The vocabulary's field (`signal.entities`).
    pub vocab: &'static str,
    /// The path through the document, [`ANY`] for a sequence's items.
    pub path: &'static [&'static str],
}

/// Every field a model declares scoped, by name, in name order. The paths
/// are the vocabulary pins' keys (`data/pins/`).
pub const SCOPED_FIELDS: &[ScopedField] = &[
    ScopedField {
        name: "entities",
        vocab: "signal.entities",
        path: &["objective", "signals", ANY, "entities"],
    },
    ScopedField {
        name: "surface",
        vocab: "surface",
        path: &["threat", "surface"],
    },
];

/// Why a value resolved the way it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Already a valid scoped value: no change.
    Scoped,
    /// A valid scoped value once its casing is normalised
    /// (`host::Process` -> `Host::Process`): applied.
    Rescoped,
    /// A bare key under exactly one stage, which the vocabulary implies:
    /// applied.
    Prefixed,
    /// A bare key under several stages: left for a person.
    Ambiguous,
    /// A real key under a stage it is not defined under: left for a person.
    InvalidStage,
    /// Neither a key nor a scoped value, under any casing.
    Unknown,
}

impl Status {
    /// The status as the report names it (`invalid_stage`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scoped => "scoped",
            Self::Rescoped => "rescoped",
            Self::Prefixed => "prefixed",
            Self::Ambiguous => "ambiguous",
            Self::InvalidStage => "invalid_stage",
            Self::Unknown => "unknown",
        }
    }
}

/// The resolution of one authored value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The value as written.
    pub authored: String,
    /// Why it resolved this way.
    pub status: Status,
    /// The scoped value to write, for the statuses that have one.
    pub resolved: Option<String>,
    /// The scoped forms a person can choose from (ambiguous, invalid stage).
    pub candidates: Vec<String>,
}

impl Outcome {
    fn new(authored: &str, status: Status) -> Self {
        Self {
            authored: authored.to_owned(),
            status,
            resolved: None,
            candidates: Vec::new(),
        }
    }

    /// Whether a value safe to write back was found.
    pub fn is_resolved(&self) -> bool {
        matches!(
            self.status,
            Status::Scoped | Status::Rescoped | Status::Prefixed
        ) && self.resolved.is_some()
    }

    /// Whether applying it changes the authored text.
    pub fn changed(&self) -> bool {
        self.is_resolved() && self.resolved.as_deref() != Some(self.authored.as_str())
    }

    /// One line on what was found.
    pub fn detail(&self) -> String {
        let authored = quote(&self.authored);
        let resolved = quote(self.resolved.as_deref().unwrap_or_default());
        let options = || {
            self.candidates
                .iter()
                .map(|candidate| quote(candidate))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self.status {
            Status::Scoped => format!("{authored} is already scoped"),
            Status::Rescoped => format!("{authored} -> {resolved} (stage casing)"),
            Status::Prefixed => format!("{authored} -> {resolved}"),
            Status::Ambiguous => {
                format!("{authored} is defined under several stages: {}", options())
            }
            Status::InvalidStage => format!(
                "{authored} names a stage the key is not defined under; valid: {}",
                options()
            ),
            Status::Unknown => format!("{authored} is not a known vocabulary value"),
        }
    }
}

/// The scoped forms of one staged vocabulary, built as the vocabulary's
/// resolver builds a scoped field's values ([`crate::vocab::Vocabularies::resolve`]):
/// a name-keyed vocabulary gives one value per stage of a key, an id-keyed
/// one a single value with the key's first stage.
#[derive(Debug, Clone, Default)]
pub struct ScopeIndex {
    stage_by_lower: BTreeMap<String, String>,
    scoped_by_key: BTreeMap<String, Vec<String>>,
    key_by_lower: BTreeMap<String, String>,
    key_by_scoped: BTreeMap<String, String>,
    scoped_by_lower: BTreeMap<String, String>,
}

impl ScopeIndex {
    /// The index of `vocabulary`.
    pub fn new(vocabulary: &Vocabulary) -> Self {
        let mut index = Self::default();
        for stage in vocabulary.stage_ids().filter(|stage| !stage.is_empty()) {
            index
                .stage_by_lower
                .insert(stage.to_lowercase(), stage.to_owned());
        }
        let id_keyed = vocabulary.metadata.key == KeyKind::Id;
        for (key, entry) in &vocabulary.entries {
            let stages: Vec<&String> = entry
                .stages
                .iter()
                .filter(|stage| !stage.is_empty())
                .collect();
            if stages.is_empty() {
                continue;
            }
            let emitted = if id_keyed { &stages[..1] } else { &stages[..] };
            let forms: Vec<String> = emitted
                .iter()
                .map(|stage| format!("{stage}{SCOPE_SEPARATOR}{key}"))
                .collect();
            // Two forms or keys that differ only by case: the later one in
            // the vocabulary wins, as the oracle's dicts keep the last.
            for form in &forms {
                index.key_by_scoped.insert(form.clone(), key.clone());
                index
                    .scoped_by_lower
                    .insert(form.to_lowercase(), form.clone());
            }
            index.key_by_lower.insert(key.to_lowercase(), key.clone());
            index.scoped_by_key.insert(key.clone(), forms);
        }
        index
    }

    /// Whether the vocabulary groups any key under a stage.
    pub fn is_staged(&self) -> bool {
        !self.scoped_by_key.is_empty()
    }

    /// Resolves `authored` to its scoped form, or says why it cannot be.
    ///
    /// The whole value is tried as a key before its first token is read as
    /// a stage: keys hold `::` themselves (`surface`'s `AWS::Compute::EC2`).
    pub fn resolve(&self, authored: &str) -> Outcome {
        let value = authored.trim();
        if value.is_empty() {
            return Outcome::new(authored, Status::Unknown);
        }
        if self.key_by_scoped.contains_key(value) {
            let mut outcome = Outcome::new(authored, Status::Scoped);
            outcome.resolved = Some(value.to_owned());
            return outcome;
        }
        if let Some(outcome) = self.as_key(authored, value) {
            return outcome;
        }
        if let Some(key) = self.key_by_lower.get(&value.to_lowercase())
            && let Some(outcome) = self.as_key(authored, key)
        {
            return outcome;
        }
        if let Some(scoped) = self.scoped_by_lower.get(&value.to_lowercase()) {
            let mut outcome = Outcome::new(authored, Status::Rescoped);
            outcome.resolved = Some(scoped.clone());
            return outcome;
        }
        if let Some((head, tail)) = value.split_once(SCOPE_SEPARATOR)
            && self.stage_by_lower.contains_key(&head.to_lowercase())
            && let Some(key) = self.key_by_lower.get(&tail.to_lowercase())
        {
            let mut outcome = Outcome::new(authored, Status::InvalidStage);
            outcome.candidates = self.scoped_by_key.get(key).cloned().unwrap_or_default();
            return outcome;
        }
        Outcome::new(authored, Status::Unknown)
    }

    fn as_key(&self, authored: &str, key: &str) -> Option<Outcome> {
        let forms = self
            .scoped_by_key
            .get(key)
            .filter(|forms| !forms.is_empty())?;
        if forms.len() > 1 {
            let mut outcome = Outcome::new(authored, Status::Ambiguous);
            outcome.candidates.clone_from(forms);
            return Some(outcome);
        }
        let mut outcome = Outcome::new(authored, Status::Prefixed);
        outcome.resolved = Some(forms[0].clone());
        Some(outcome)
    }
}

/// One authored scalar: its value, and the byte range it occupies in the
/// text the document was read from (quotes included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    /// The value as YAML reads it.
    pub value: String,
    /// Where it starts, in bytes.
    pub start: usize,
    /// Where it ends, in bytes.
    pub end: usize,
}

/// Every scalar at `path` in `document`, in document order. A sequence at
/// the end of the path gives its items.
pub fn scalars(document: &node::Document, path: &[&str]) -> Vec<Scalar> {
    let mut found = Vec::new();
    if let Some(root) = document.root() {
        let offsets = ByteOffsets::new(document.source());
        walk(root, path, document.source(), &offsets, &mut found);
    }
    found
}

/// Code-point offsets as byte offsets in one text.
struct ByteOffsets {
    /// The byte offset of each character, and of the end.
    starts: Vec<usize>,
}

impl ByteOffsets {
    fn new(text: &str) -> Self {
        let mut starts: Vec<usize> = text.char_indices().map(|(at, _)| at).collect();
        starts.push(text.len());
        Self { starts }
    }

    fn byte(&self, index: usize) -> usize {
        self.starts
            .get(index)
            .copied()
            .unwrap_or_else(|| self.starts.last().copied().unwrap_or(0))
    }
}

fn walk(
    node: &Arc<Node>,
    path: &[&str],
    source: &str,
    offsets: &ByteOffsets,
    found: &mut Vec<Scalar>,
) {
    let Some((head, tail)) = path.split_first() else {
        emit(node, source, offsets, found);
        return;
    };
    match &node.value {
        Value::Map(entries) => {
            for entry in entries {
                if entry.key.value.as_str() == Some(head) {
                    walk(&entry.value, tail, source, offsets, found);
                }
            }
        }
        Value::Seq(items) if *head == ANY => {
            for item in items {
                walk(item, tail, source, offsets, found);
            }
        }
        _ => {}
    }
}

fn emit(node: &Arc<Node>, source: &str, offsets: &ByteOffsets, found: &mut Vec<Scalar>) {
    match &node.value {
        Value::Seq(items) => {
            for item in items {
                emit(item, source, offsets, found);
            }
        }
        Value::Map(_) => {}
        value => {
            let start = offsets.byte(node.start.index);
            let end = offsets.byte(node.end.index).max(start);
            let text = source.get(start..end).unwrap_or_default();
            // A string is its value; another scalar (`null`, `12`, an empty
            // value) is the text it is written as.
            let value = match value {
                Value::Str(text) => text.clone(),
                _ => text.trim().to_owned(),
            };
            found.push(Scalar { value, start, end });
        }
    }
}

/// Each value at `path` with the number of times it is written.
pub fn counts(document: &node::Document, path: &[&str]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for scalar in scalars(document, path) {
        *counts.entry(scalar.value).or_insert(0) += 1;
    }
    counts
}

/// What to change: for each field's path, the authored values to replace.
pub type Plan<'a> = Vec<(&'a [&'a str], &'a BTreeMap<String, String>)>;

/// Whether `value` must be quoted to be read back as the same string.
fn needs_quoting(value: &str) -> bool {
    if value.is_empty() || value != value.trim() {
        return true;
    }
    if value.starts_with(|c| "!&*?|>%@`,[]{}#\"'-".contains(c)) {
        return true;
    }
    value.ends_with(':') || value.contains(": ")
}

/// `text` (the source of `document`) with every value of `plan` replaced
/// over its exact span, and the number of values replaced. A quoted value
/// keeps its quotes; a plain one is quoted when its new text needs it.
pub fn rewrite(document: &node::Document, plan: &Plan<'_>) -> (String, usize) {
    let text = document.source();
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for (path, mapping) in plan {
        if mapping.is_empty() {
            continue;
        }
        for scalar in scalars(document, path) {
            let Some(replacement) = mapping.get(&scalar.value) else {
                continue;
            };
            let original = &text[scalar.start..scalar.end];
            let quote = original.chars().next().filter(|c| matches!(c, '"' | '\''));
            let rendered = match quote {
                Some(quote) if original.len() > 1 && original.ends_with(quote) => {
                    format!("{quote}{replacement}{quote}")
                }
                _ if needs_quoting(replacement) => format!("\"{replacement}\""),
                _ => replacement.clone(),
            };
            edits.push((scalar.start, scalar.end, rendered));
        }
    }
    if edits.is_empty() {
        return (text.to_owned(), 0);
    }
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0));
    let mut out = text.to_owned();
    for (start, end, rendered) in &edits {
        out.replace_range(*start..*end, rendered);
    }
    (out, edits.len())
}

/// Why the rewrite of `original` into `updated` is unsafe, or `None` when
/// it is sound: `updated` reads, each planned field holds the values the
/// plan projects, and nothing outside those fields differs.
pub fn verify(original: &node::Document, updated: &str, plan: &Plan<'_>) -> Option<String> {
    let after = match node::load(updated) {
        Ok(after) => after,
        Err(error) => return Some(format!("rewrite produced unparseable YAML: {error}")),
    };
    for (path, mapping) in plan {
        let mut projected: BTreeMap<String, usize> = BTreeMap::new();
        for (value, count) in counts(original, path) {
            let value = mapping.get(&value).cloned().unwrap_or(value);
            *projected.entry(value).or_insert(0) += count;
        }
        let actual = counts(&after, path);
        if projected != actual {
            let field = SCOPED_FIELDS
                .iter()
                .find(|field| field.path == *path)
                .map_or_else(|| path.join("."), |field| field.name.to_owned());
            return Some(format!(
                "rewrite of {} did not match the plan (expected {}, got {})",
                quote(&field),
                pairs(&projected),
                pairs(&actual)
            ));
        }
    }
    let paths: Vec<&[&str]> = plan.iter().map(|(path, _)| *path).collect();
    let blank = |document: &node::Document| {
        document
            .root()
            .map(|root| without(root, &paths))
            .unwrap_or(serde_json::Value::Null)
    };
    (blank(original) != blank(&after))
        .then(|| "rewrite altered a value outside the migration plan".to_owned())
}

/// Each value and how often it occurs, as the map's own `Debug` writes it.
fn pairs(counts: &BTreeMap<String, usize>) -> String {
    format!("{counts:?}")
}

/// The document as JSON with the value at each of `paths` removed.
fn without(root: &Node, paths: &[&[&str]]) -> serde_json::Value {
    let mut value = crate::configuration::merge::to_json(root);
    for path in paths {
        strip(&mut value, path);
    }
    value
}

fn strip(value: &mut serde_json::Value, path: &[&str]) {
    let Some((head, tail)) = path.split_first() else {
        return;
    };
    match value {
        serde_json::Value::Object(map) => {
            if tail.is_empty() {
                map.remove(*head);
            } else if let Some(child) = map.get_mut(*head) {
                strip(child, tail);
            }
        }
        serde_json::Value::Array(items) if *head == ANY => {
            for item in items {
                strip(item, tail);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vocab::Vocabulary;

    const VOCAB: &str = r#"
name = "Entities"
field = "signal.entities"
description = "d"
key = "name"
[[stages]]
id = "Host"

[[stages]]
id = "Cloud"

[[keys]]
version = "1.0"
name = "Process"
"tide.vocab.stages" = "Host"

[[keys]]
version = "1.0"
name = "Account"
"tide.vocab.stages" = ["Host", "Cloud"]

[[keys]]
version = "1.0"
name = "Security::Kerberos"
"tide.vocab.stages" = ["Host"]
"#;

    fn index() -> ScopeIndex {
        let vocabulary = Vocabulary::from_file("signal.entities.vocab.toml", VOCAB).unwrap();
        ScopeIndex::new(&vocabulary)
    }

    #[test]
    fn resolves_each_status() {
        let index = index();
        let status = |value: &str| index.resolve(value).status;
        assert_eq!(status("Host::Process"), Status::Scoped);
        assert_eq!(status("host::process"), Status::Rescoped);
        assert_eq!(status("Process"), Status::Prefixed);
        assert_eq!(status("process"), Status::Prefixed);
        assert_eq!(status("Account"), Status::Ambiguous);
        assert_eq!(status("Cloud::Process"), Status::InvalidStage);
        assert_eq!(status("Gizmo"), Status::Unknown);
        assert_eq!(status("  "), Status::Unknown);
        // Raw first: a key holding `::` is not read as a stage and a key.
        assert_eq!(
            index.resolve("Security::Kerberos").resolved.as_deref(),
            Some("Host::Security::Kerberos")
        );
        assert_eq!(
            index.resolve("host::process").resolved.as_deref(),
            Some("Host::Process")
        );
        assert!(index.is_staged());
    }

    #[test]
    fn a_case_collision_keeps_the_later_key() {
        // Two keys, and two scoped forms, that differ only by case: the
        // oracle's dict comprehensions keep the later one.
        let vocabulary = Vocabulary::from_file(
            "signal.entities.vocab.toml",
            r#"
name = "Entities"
field = "signal.entities"
description = "d"
key = "name"
[[stages]]
id = "Host"

[[keys]]
version = "1.0"
name = "Pipe"
"tide.vocab.stages" = "Host"

[[keys]]
version = "1.0"
name = "PIPE"
"tide.vocab.stages" = "Host"
"#,
        )
        .unwrap();
        let index = ScopeIndex::new(&vocabulary);
        assert_eq!(
            index.resolve("pipe").resolved.as_deref(),
            Some("Host::PIPE")
        );
        assert_eq!(
            index.resolve("host::pipe").resolved.as_deref(),
            Some("Host::PIPE")
        );
        // An exact key or form is never folded.
        assert_eq!(
            index.resolve("Pipe").resolved.as_deref(),
            Some("Host::Pipe")
        );
        assert_eq!(index.resolve("Host::Pipe").status, Status::Scoped);
    }

    #[test]
    fn details_name_the_choices() {
        let index = index();
        assert_eq!(
            index.resolve("Account").detail(),
            "'Account' is defined under several stages: 'Host::Account', 'Cloud::Account'"
        );
        assert_eq!(
            index.resolve("Cloud::Process").detail(),
            "'Cloud::Process' names a stage the key is not defined under; valid: 'Host::Process'"
        );
        assert_eq!(
            index.resolve("Process").detail(),
            "'Process' -> 'Host::Process'"
        );
        assert_eq!(
            index.resolve("host::Process").detail(),
            "'host::Process' -> 'Host::Process' (stage casing)"
        );
        assert_eq!(
            index.resolve("Gizmo").detail(),
            "'Gizmo' is not a known vocabulary value"
        );
        assert!(!index.resolve("Host::Process").changed());
        assert!(index.resolve("Process").changed());
    }

    const OBJECT: &str = "\
name: x  # a comment
objective:
  signals:
    - name: a
      entities: [Process, 'host::process', \"Account\"]
    - entities:
        - Process   # kept comment
        - Host::Process
platforms:
  sentinel:
    entities: Process
";

    fn plan_of(mapping: &BTreeMap<String, String>) -> Plan<'_> {
        vec![(SCOPED_FIELDS[0].path, mapping)]
    }

    #[test]
    fn finds_values_by_path_only() {
        let document = node::load(OBJECT).unwrap();
        let found = scalars(&document, SCOPED_FIELDS[0].path);
        let values: Vec<&str> = found.iter().map(|s| s.value.as_str()).collect();
        assert_eq!(
            values,
            [
                "Process",
                "host::process",
                "Account",
                "Process",
                "Host::Process"
            ]
        );
        // Quotes are part of the span.
        assert_eq!(&OBJECT[found[1].start..found[1].end], "'host::process'");
        assert_eq!(&OBJECT[found[2].start..found[2].end], "\"Account\"");
        assert_eq!(&OBJECT[found[3].start..found[3].end], "Process");
    }

    #[test]
    fn rewrites_spans_and_keeps_the_rest() {
        let document = node::load(OBJECT).unwrap();
        let mapping = BTreeMap::from([
            ("Process".to_owned(), "Host::Process".to_owned()),
            ("host::process".to_owned(), "Host::Process".to_owned()),
        ]);
        let plan = plan_of(&mapping);
        let (updated, changes) = rewrite(&document, &plan);
        assert_eq!(changes, 3);
        assert_eq!(
            updated,
            OBJECT
                .replace(
                    "[Process, 'host::process',",
                    "[Host::Process, 'Host::Process',"
                )
                .replace("- Process   #", "- Host::Process   #")
        );
        // The Sentinel block's `entities` is not the field.
        assert!(updated.contains("    entities: Process\n"));
        assert_eq!(verify(&document, &updated, &plan), None);
    }

    #[test]
    fn quotes_a_replacement_that_needs_it() {
        assert!(needs_quoting("- a"));
        assert!(needs_quoting("a: b"));
        assert!(needs_quoting("a:"));
        assert!(needs_quoting(" a"));
        assert!(needs_quoting(""));
        assert!(!needs_quoting("Host::Process"));
        let text = "threat:\n  surface: [OS]\n";
        let document = node::load(text).unwrap();
        let mapping = BTreeMap::from([("OS".to_owned(), "- odd".to_owned())]);
        let plan = vec![(SCOPED_FIELDS[1].path, &mapping)];
        let (updated, _) = rewrite(&document, &plan);
        assert_eq!(updated, "threat:\n  surface: [\"- odd\"]\n");
    }

    #[test]
    fn verify_refuses_a_rewrite_off_the_plan() {
        let document = node::load(OBJECT).unwrap();
        let mapping = BTreeMap::from([("Process".to_owned(), "Host::Process".to_owned())]);
        let plan = plan_of(&mapping);
        let outside = OBJECT.replace("name: x", "name: y");
        assert_eq!(
            verify(&document, &outside, &plan).as_deref(),
            Some(
                "rewrite of 'entities' did not match the plan (expected {\"Account\": 1, \"Host::Process\": 3, \"host::process\": 1}, got {\"Account\": 1, \"Host::Process\": 1, \"Process\": 2, \"host::process\": 1})"
            )
        );
        let (updated, _) = rewrite(&document, &plan);
        let altered = updated.replace("name: x", "name: y");
        assert_eq!(
            verify(&document, &altered, &plan).as_deref(),
            Some("rewrite altered a value outside the migration plan")
        );
        assert!(
            verify(&document, "a: [", &plan)
                .unwrap()
                .starts_with("rewrite produced unparseable YAML")
        );
    }

    #[test]
    fn keeps_crlf_and_multibyte_text() {
        let text = "# é\r\nthreat:\r\n  surface:\r\n    - Windows # ü\r\n";
        let document = node::load(text).unwrap();
        let mapping = BTreeMap::from([("Windows".to_owned(), "OS::Windows".to_owned())]);
        let plan = vec![(SCOPED_FIELDS[1].path, &mapping)];
        let (updated, changes) = rewrite(&document, &plan);
        assert_eq!(changes, 1);
        assert_eq!(updated, text.replace("- Windows", "- OS::Windows"));
    }
}
