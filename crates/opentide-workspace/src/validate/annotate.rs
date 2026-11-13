//! Where each finding points and the step it suggests
//! (`cli/ui/diagnostics.py` `diagnostic_from_issue`): `path`, `line`,
//! `column`, `end_line`, `end_column`, `help` and `fix`, read from the file
//! the finding is about, and the frame's label and notes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_schema::node::{self, Document, Span, Value};
use opentide_schema::vocab::quote;

use crate::diagnostic::{ContextValue, Diagnostic, Fix, TextEdit};
use crate::fs::FileSystem;
use crate::index::{Index, posix};

/// Codes whose `suggestion` is a replacement for the value at fault.
const VALUE_SUGGESTION_CODES: [&str; 4] = [
    "vocab_unknown",
    "invalid_ref",
    "chaining_relation_unknown",
    "config_enum_unknown",
];

/// Codes whose fix may be `safe`. A reference fix never is: its suggestion
/// is a near match on an object's name.
const SAFE_FIX_CODES: [&str; 3] = [
    "vocab_unknown",
    "chaining_relation_unknown",
    "config_enum_unknown",
];

/// Help for codes whose finding carries no suggestion, so the frame still
/// ends in a step to take.
fn default_help(code: &str) -> Option<&'static str> {
    Some(match code {
        "invalid_uuid" => {
            "replace it with a UUID v4: python -c \"import uuid; print(uuid.uuid4())\""
        }
        "missing_uuid" => "add metadata.uuid with a fresh UUID v4",
        "duplicate_id" => {
            "give one of them a fresh UUID v4; keep the UUID on the object that is deployed or \
             referenced"
        }
        "yaml_parse" => {
            "look at the indentation, a missing ':' or an unclosed quote at or just before this \
             position"
        }
        "schema_validation" => {
            "the template in .opentide/templates/ shows the field and its values"
        }
        _ => return None,
    })
}

/// `yaml_parse` problems that are not syntax: the indentation hint would
/// mislead.
const YAML_PARSE_HELP: [(&str, &str); 3] = [
    (
        "found an empty file",
        "fill it in from a template with opentide new, or delete it",
    ),
    (
        "is not a valid date",
        "write the date as YYYY-MM-DD, with a month from 01 to 12",
    ),
    (
        "is not UTF-8 text",
        "re-save it as UTF-8; most editors offer the encoding under Save As",
    ),
];

/// The step for a root that is not one mapping.
const OBJECT_FILE_HELP: &str =
    "an object file is one mapping of keys such as name, metadata and description";

/// The command that lists what a reference field may point at.
fn reference_listing(field: &str) -> Option<&'static str> {
    match field {
        "detection_model" => Some("opentide info objectives"),
        "threats" | "vector" => Some("opentide info threats"),
        _ => None,
    }
}

/// Whether replacing `value` with `suggestion` is certainly what the author
/// meant: the two spell the same word (case, whitespace, `-` and `_`
/// aside), and neither holds a digit, which is how identifiers look.
pub fn is_safe_replacement(code: &str, value: &str, suggestion: &str) -> bool {
    if !SAFE_FIX_CODES.contains(&code) || value == suggestion {
        return false;
    }
    if value
        .chars()
        .chain(suggestion.chars())
        .any(char::is_numeric)
    {
        return false;
    }
    fold(value) == fold(suggestion)
}

/// `value` without whitespace, `-` or `_`, case-folded.
fn fold(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

/// A file that does not parse: the problem, where, and the frame's notes.
pub(crate) type Problem = (String, Span, Vec<(String, String)>);

/// What makes two findings about one written value the same occurrence.
type OccurrenceKey = (String, Option<PathBuf>, Vec<String>, Option<String>);

/// Each file's document, read once for every finding in it.
pub struct Sources<'a> {
    fs: &'a dyn FileSystem,
    by_path: HashMap<PathBuf, Option<Arc<Document>>>,
    texts: HashMap<PathBuf, Option<String>>,
}

impl<'a> Sources<'a> {
    /// The documents the index holds, and `fs` for any other file.
    pub fn new(fs: &'a dyn FileSystem, index: &Index) -> Self {
        let mut by_path = HashMap::new();
        for object in index.objects.values().flat_map(|objects| objects.values()) {
            by_path.insert(object.path.clone(), Some(Arc::clone(&object.document)));
        }
        for duplicate in &index.duplicates {
            by_path.insert(
                duplicate.path.clone(),
                Some(Arc::clone(&duplicate.document)),
            );
        }
        Self {
            fs,
            by_path,
            texts: HashMap::new(),
        }
    }

    /// No document read yet: every file is read through `fs` when a
    /// finding needs it (lint, which reads no index).
    pub fn files(fs: &'a dyn FileSystem) -> Self {
        Self {
            fs,
            by_path: HashMap::new(),
            texts: HashMap::new(),
        }
    }

    /// The text of line `number` (from 1) of `path`, lines broken where YAML
    /// breaks them.
    pub(crate) fn line(&mut self, path: &Path, number: usize) -> Option<String> {
        let text = self.text(path)?;
        crate::fix::split_keeping_breaks(&text)
            .get(number.checked_sub(1)?)
            .map(|line| line.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn text(&mut self, path: &Path) -> Option<String> {
        self.texts
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let bytes = self.fs.read(path).ok()?;
                let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
                String::from_utf8(body.to_vec()).ok()
            })
            .clone()
    }

    fn document(&mut self, path: &Path) -> Option<Arc<Document>> {
        if let Some(found) = self.by_path.get(path) {
            return found.clone();
        }
        let document = self
            .text(path)
            .and_then(|text| node::load(&text).ok())
            .map(Arc::new);
        self.by_path.insert(path.to_path_buf(), document.clone());
        document
    }

    /// Where a finding about `field_path` points (`SourceFiles.span`): the
    /// value, its key for a block, the deepest key that exists for a
    /// missing one; `value` picks the list item when the path names a whole
    /// list, its `occurrence`-th one when it repeats.
    fn span(
        &mut self,
        path: &Path,
        field_path: &[String],
        value: Option<&str>,
        occurrence: usize,
        at_key: bool,
    ) -> Option<Span> {
        let document = self.document(path)?;
        let mut target: Vec<String> = field_path.to_vec();
        if let Some(value) = value
            && let Some(node) = walk(&document, field_path)
            && let Value::Seq(items) = &node.value
        {
            let hits: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| item.value.as_str() == Some(value))
                .map(|(index, _)| index)
                .collect();
            if let Some(last) = hits.last() {
                target.push(hits.get(occurrence).unwrap_or(last).to_string());
            }
        }
        document.span(&target, at_key)
    }

    /// The problem of a file that does not parse, with its position.
    pub(crate) fn yaml_problem(&mut self, path: &Path) -> Option<Problem> {
        let text = self.text(path)?;
        match node::load(&text) {
            Err(error) => {
                let mark = error.mark?;
                Some((
                    format!(
                        "Could not parse object YAML: {} at line {}, column {}",
                        error.problem, mark.line, mark.column
                    ),
                    Span {
                        line: mark.line,
                        column: mark.column,
                        end_line: mark.line,
                        end_column: mark.column + 1,
                        text: String::new(),
                        found: true,
                    },
                    Vec::new(),
                ))
            }
            Ok(document) => {
                let message = crate::load::root_mapping_problem(&document)?;
                let (line, column, end_column) = first_content_span(&text)?;
                Some((
                    message,
                    Span {
                        line,
                        column,
                        end_line: line,
                        end_column,
                        text: String::new(),
                        found: true,
                    },
                    vec![("help".to_owned(), OBJECT_FILE_HELP.to_owned())],
                ))
            }
        }
    }
}

/// The node at `field_path`.
fn walk<'d>(document: &'d Document, field_path: &[String]) -> Option<&'d node::Node> {
    let mut current: &node::Node = document.root()?;
    for part in field_path {
        current = match &current.value {
            Value::Map(_) => current.get(part)?,
            Value::Seq(items) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

/// `(line, column, end_column)` of the first line holding YAML content.
fn first_content_span(text: &str) -> Option<(usize, usize, usize)> {
    for (number, raw) in text.lines().enumerate() {
        let content = raw.split(" #").next().unwrap_or("").trim_end();
        let stripped = content.trim_start();
        if stripped.is_empty() || stripped.starts_with(['#', '%']) || stripped == "---" {
            continue;
        }
        let column = content.chars().count() - stripped.chars().count() + 1;
        return Some((number + 1, column, content.chars().count() + 1));
    }
    None
}

/// `path` relative to `workspace`, `/`-separated, or as given outside it.
pub fn relative_path(fs: &dyn FileSystem, path: &Path, workspace: &Path) -> String {
    if let Ok(rest) = path.strip_prefix(workspace) {
        return posix(rest);
    }
    if let Ok(rest) = fs.resolve(path).strip_prefix(fs.resolve(workspace)) {
        return posix(rest);
    }
    posix(path)
}

/// Adds the place and the step to each finding of `diagnostics`, in order.
/// A value repeated in a list is found each time it is written.
pub fn annotate(diagnostics: &mut [Diagnostic], sources: &mut Sources<'_>, workspace: &Path) {
    let mut seen: HashMap<OccurrenceKey, usize> = HashMap::new();
    for diagnostic in diagnostics {
        let key = (
            diagnostic.code.clone(),
            diagnostic.file_path.clone(),
            diagnostic.field_path.clone(),
            diagnostic.value().map(str::to_owned),
        );
        let occurrence = *seen.get(&key).unwrap_or(&0);
        seen.insert(key, occurrence + 1);
        annotate_one(diagnostic, sources, workspace, occurrence);
    }
}

fn annotate_one(
    diagnostic: &mut Diagnostic,
    sources: &mut Sources<'_>,
    workspace: &Path,
    occurrence: usize,
) {
    if diagnostic.line.is_some() {
        // The engine placed it (the queries check).
        return;
    }
    let value = diagnostic.value().map(str::to_owned);
    let mut notes: Vec<(String, String)> = Vec::new();
    let mut label = label(diagnostic);
    let mut line = diagnostic.yaml_line.map(|line| line + 1);
    let mut span = None;
    let mut message = diagnostic.message.clone();
    if let Some(file) = diagnostic.file_path.clone() {
        if diagnostic.code == "yaml_parse" {
            if let Some((problem, place, parse_notes)) = sources.yaml_problem(&file) {
                message = problem;
                span = Some(place);
                notes.extend(parse_notes);
            }
        } else if !diagnostic.field_path.is_empty() {
            let at_key = diagnostic.code == "schema_validation"
                && diagnostic
                    .message
                    .starts_with("Extra inputs are not permitted");
            span = sources.span(
                &file,
                &diagnostic.field_path,
                value.as_deref(),
                occurrence,
                at_key,
            );
        }
    }
    if diagnostic.code == "schema_validation"
        && let Some(missing) = diagnostic.field_path.last()
        && let Some(place) = &span
        && !place.found
    {
        let parent = diagnostic.field_path.len() > 1;
        label = Some(format!(
            "add {} {}",
            quote(missing),
            if parent {
                "under this key"
            } else {
                "at the top level"
            }
        ));
    }
    if diagnostic.code == "schema_validation"
        && let Some((missing, parents)) = diagnostic.field_path.split_last()
    {
        if message == "Field required" {
            let place = if parents.is_empty() {
                String::new()
            } else {
                format!(" in {}", parents.join("."))
            };
            message = format!("missing required field {}{place}", quote(missing));
        } else {
            message = format!("{}: {message}", diagnostic.field_path.join("."));
        }
    } else if let Some(value) = &value
        && let Some(own) = value_message(diagnostic, value)
    {
        message = own;
    }
    if let Some(place) = &span {
        line = Some(place.line);
    }
    let mut help = diagnostic.suggestion.clone();
    if diagnostic.code == "platform_not_enabled"
        && help.is_none()
        && let Some((sentence, step)) = message.clone().rsplit_once("; ")
    {
        help = Some(step.to_owned());
        sentence.clone_into(&mut message);
    }
    let mut fix = None;
    if VALUE_SUGGESTION_CODES.contains(&diagnostic.code.as_str())
        && let Some(suggestion) = &diagnostic.suggestion
    {
        help = Some(format!("did you mean {}?", quote(suggestion)));
        if let Some(value) = &value
            && let Some(place) = span
                .as_ref()
                .filter(|place| place.found && &place.text == value && value != suggestion)
        {
            fix = Some(Fix {
                safe: is_safe_replacement(&diagnostic.code, value, suggestion),
                edits: vec![TextEdit {
                    line: place.line,
                    column: place.column,
                    end_line: place.line,
                    end_column: place.end_column,
                    replacement: suggestion.clone(),
                }],
            });
        }
    } else if diagnostic.code == "invalid_ref" && help.is_none() {
        let field = diagnostic
            .field_path
            .iter()
            .rev()
            .find(|part| !part.chars().all(|c| c.is_ascii_digit()))
            .map_or("", String::as_str);
        if let Some(listing) = reference_listing(field) {
            help = Some(format!("{listing} lists the ones that exist"));
        }
    }
    if help.is_none() && diagnostic.code == "yaml_parse" {
        if !notes.iter().any(|(kind, _)| kind == "help") {
            help = Some(
                YAML_PARSE_HELP
                    .iter()
                    .find(|(needle, _)| message.contains(needle))
                    .map_or_else(
                        || default_help("yaml_parse").unwrap_or_default(),
                        |(_, text)| text,
                    )
                    .to_owned(),
            );
        }
    } else if help.is_none() {
        help = default_help(&diagnostic.code).map(str::to_owned);
    }
    if diagnostic.code == "duplicate_id" {
        if let Some(own) = duplicate_message(diagnostic, value.as_deref()) {
            message = own;
        }
        if let Some(also) = duplicate_also(diagnostic, value.as_deref(), sources, workspace) {
            notes.push(("also".to_owned(), also));
        }
    }
    if diagnostic.code == "config_enum_unknown"
        && let Some(ContextValue::List(allowed)) = diagnostic.context.get("allowed")
        && !allowed.is_empty()
    {
        let allowed: Vec<&str> = allowed.iter().filter_map(ContextValue::as_str).collect();
        notes.push((
            "expected".to_owned(),
            format!("one of {}", allowed.join(", ")),
        ));
    }
    diagnostic.path = diagnostic
        .file_path
        .as_ref()
        .map(|file| relative_path(sources.fs, file, workspace));
    diagnostic.line = line;
    diagnostic.column = span.as_ref().map(|place| place.column);
    diagnostic.end_line = line;
    diagnostic.end_column = span.as_ref().map(|place| place.end_column);
    diagnostic.help = help;
    diagnostic.fix = fix;
    diagnostic.label = label;
    diagnostic.notes = notes;
    diagnostic.headline = (message != diagnostic.message).then_some(message);
}

/// `"clearr" is not a TLP value`, `"x" is not a configured status`: the
/// sentence a person reads for a finding about one value.
fn value_message(diagnostic: &Diagnostic, value: &str) -> Option<String> {
    let context = |key: &str| diagnostic.context.get(key).and_then(ContextValue::as_str);
    match diagnostic.code.as_str() {
        "vocab_unknown" => {
            let vocab = context("vocab")?;
            let name = vocab.split("::").next().unwrap_or(vocab);
            let noun = if ["tlp", "pap", "rsit"].contains(&name) {
                name.to_uppercase()
            } else {
                name.split(['.', '_'])
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            Some(format!("{} is not a {noun} value", quote(value)))
        }
        "config_enum_unknown" => {
            let setting = context("setting")?;
            let noun = match setting {
                "statuses" => "status",
                "responders" => "responder",
                other => other,
            };
            Some(format!("{} is not a configured {noun}", quote(value)))
        }
        _ => None,
    }
}

/// `UUID … is also used by 'Name'` (or `another object`).
fn duplicate_message(diagnostic: &Diagnostic, value: Option<&str>) -> Option<String> {
    let ContextValue::Map(original) = diagnostic.context.get("original")? else {
        return None;
    };
    let value = value?;
    let other = original
        .get("name")
        .and_then(ContextValue::as_str)
        .filter(|name| !name.is_empty())
        .map_or_else(|| "another object".to_owned(), quote);
    Some(format!("UUID {value} is also used by {other}"))
}

fn label(diagnostic: &Diagnostic) -> Option<String> {
    let context = |key: &str| diagnostic.context.get(key).and_then(ContextValue::as_str);
    match diagnostic.code.as_str() {
        "vocab_unknown" => context("vocab").map(|vocab| format!("not in {vocab}")),
        "invalid_ref" => Some("no object has this id".to_owned()),
        "config_enum_unknown" => context("setting").map(|setting| format!("not in [[{setting}]]")),
        "chaining_relation_unknown" => Some("not a chaining relation".to_owned()),
        _ => None,
    }
}

/// Where the object a duplicate UUID is also used by writes it.
fn duplicate_also(
    diagnostic: &Diagnostic,
    value: Option<&str>,
    sources: &mut Sources<'_>,
    workspace: &Path,
) -> Option<String> {
    let ContextValue::Map(original) = diagnostic.context.get("original")? else {
        return None;
    };
    let raw = original.get("file_path")?.as_str()?;
    let other = PathBuf::from(raw);
    let mut place = relative_path(sources.fs, &other, workspace);
    if let Some(ContextValue::List(field)) = original.get("field_path") {
        let field: Vec<String> = field
            .iter()
            .filter_map(ContextValue::as_str)
            .map(str::to_owned)
            .collect();
        if let Some(span) = sources.span(&other, &field, value, 0, false)
            && span.found
        {
            place = format!("{place}:{}:{}", span.line, span.column);
        }
    }
    Some(place)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_safe_replacement_is_the_same_word() {
        assert!(is_safe_replacement("vocab_unknown", "AMBER", "amber"));
        assert!(is_safe_replacement(
            "config_enum_unknown",
            "soc_tier",
            "SOC Tier"
        ));
        assert!(!is_safe_replacement("invalid_ref", "AMBER", "amber"));
        assert!(!is_safe_replacement("vocab_unknown", "ambr", "amber"));
        assert!(!is_safe_replacement("vocab_unknown", "t1059", "T1059"));
        assert!(!is_safe_replacement("vocab_unknown", "amber", "amber"));
    }

    fn vocab(vocab: &str) -> Diagnostic {
        Diagnostic::error("vocab_unknown", "x").with("vocab", vocab)
    }

    #[test]
    fn a_value_headline_names_the_vocabulary_as_a_person_reads_it() {
        // The acronyms are upper-case, every other name is words.
        for (name, noun) in [("tlp", "TLP"), ("pap", "PAP"), ("rsit", "RSIT")] {
            assert_eq!(
                value_message(&vocab(&format!("{name}::1.0")), "x").as_deref(),
                Some(format!("\"x\" is not a {noun} value").as_str())
            );
        }
        assert_eq!(
            value_message(&vocab("signal.entities::1.0"), "Host::Gizmo").as_deref(),
            Some("\"Host::Gizmo\" is not a signal entities value")
        );
        assert_eq!(
            value_message(&vocab("alert_severity"), "high").as_deref(),
            Some("\"high\" is not a alert severity value")
        );
        assert_eq!(
            value_message(&Diagnostic::error("vocab_unknown", "x"), "v"),
            None
        );
        let setting =
            |name: &str| Diagnostic::error("config_enum_unknown", "x").with("setting", name);
        assert_eq!(
            value_message(&setting("statuses"), "LIVE").as_deref(),
            Some("\"LIVE\" is not a configured status")
        );
        assert_eq!(
            value_message(&setting("responders"), "soc").as_deref(),
            Some("\"soc\" is not a configured responder")
        );
        assert_eq!(
            value_message(&setting("tiers"), "t9").as_deref(),
            Some("\"t9\" is not a configured tiers")
        );
        assert_eq!(
            value_message(&Diagnostic::error("invalid_ref", "x"), "v"),
            None
        );
    }

    #[test]
    fn a_duplicate_names_the_other_object_or_says_another() {
        let duplicate = |original: serde_json::Value| {
            Diagnostic::error("duplicate_id", "x").with("original", original)
        };
        let uuid = "00000000-0000-4000-8003-000000000001";
        assert_eq!(
            duplicate_message(&duplicate(serde_json::json!({"name": "First"})), Some(uuid))
                .as_deref(),
            Some(format!("UUID {uuid} is also used by \"First\"").as_str())
        );
        for original in [serde_json::json!({"name": ""}), serde_json::json!({})] {
            assert_eq!(
                duplicate_message(&duplicate(original), Some(uuid)).as_deref(),
                Some(format!("UUID {uuid} is also used by another object").as_str())
            );
        }
        // Without the value or the original, the engine's sentence stays.
        assert_eq!(
            duplicate_message(&duplicate(serde_json::json!({"name": "First"})), None),
            None
        );
        assert_eq!(
            duplicate_message(&Diagnostic::error("duplicate_id", "x"), Some(uuid)),
            None
        );
    }

    #[test]
    fn labels_say_where_a_value_is_missing_from() {
        assert_eq!(
            label(&vocab("tlp::1.0")).as_deref(),
            Some("not in tlp::1.0")
        );
        assert_eq!(
            label(&Diagnostic::error("invalid_ref", "x")).as_deref(),
            Some("no object has this id")
        );
        assert_eq!(
            label(&Diagnostic::error("config_enum_unknown", "x").with("setting", "statuses"))
                .as_deref(),
            Some("not in [[statuses]]")
        );
        assert_eq!(
            label(&Diagnostic::error("chaining_relation_unknown", "x")).as_deref(),
            Some("not a chaining relation")
        );
        assert_eq!(label(&Diagnostic::error("yaml_parse", "x")), None);
    }

    #[test]
    fn the_first_content_line_skips_comments_and_markers() {
        assert_eq!(first_content_span("# c\n---\n  - a # x\n"), Some((3, 3, 6)));
        assert_eq!(first_content_span("\n# only\n"), None);
    }
}
