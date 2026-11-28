//! The Configuration tab's content (#776; UC-6.0d, #841): the workspace's
//! configuration read, not as TOML.
//!
//! Each file (`deployment.toml`, `lint.toml`, `documentation.toml`,
//! `sharing.toml` and each `platforms/*.toml`) is shown by section, each
//! setting with its effective value (the bundled file, the workspace's and
//! the parent instance merged, as every command reads them), whether the
//! workspace sets it, and what it does: the description its JSON Schema
//! (`opentide_schema::generate::configuration`) gives, else the bundled
//! file's comment above it. Options the workspace does not set are listed
//! with their descriptions too. Platforms read as cards: enabled or not, and
//! each tenant's strategies, credentials and the rules that reach it.
//!
//! **No credential value is ever held.** A value with a `setup` table, or a
//! key that names a secret (`key`, `token`, `password`...), anywhere on its
//! key path is replaced: a `$NAME` or `${NAME}` reference by its variable
//! name and whether the environment sets it, as `opentide doctor` reports
//! it; anything else by [`HIDDEN`]. The raw file is redacted the same way,
//! then proven redacted ([`redact_toml`]): a file that does not parse, or
//! whose redaction cannot be proven, has no raw view.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use opentide_schema::configuration::toml as config_toml;
use opentide_schema::node::{Node, Value};
use regex::Regex;
use serde_json::Value as JsonValue;

use crate::env::Env;
use crate::redact::{NOT_UTF8, toml_position};

/// What a hidden value reads as. Never the value, its length or a part of it.
pub const HIDDEN: &str = "•••• hidden";

/// Why a raw view is withheld when its redaction cannot be proven.
pub const UNSAFE_RAW: &str = "The raw file cannot be shown safely: a credential in it could \
     not be redacted with certainty. Its settings are listed in the read view.";

/// The files the tab shows, in order; platform files follow.
pub const FILES: [&str; 4] = [
    "deployment.toml",
    "lint.toml",
    "documentation.toml",
    "sharing.toml",
];

/// The tables whose every value is a credential or tenant secret.
const SECRET_TABLES: [&str; 1] = ["setup"];

/// One value of a configuration file, as the tab shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The key path in the file (`tenants.0.setup.api_key`).
    pub path: String,
    /// The last key.
    pub key: String,
    /// The effective value, shown: redacted when it is a secret.
    pub shown: String,
    /// Whether the workspace's file sets it (else it is the bundled default).
    pub set_here: bool,
    /// What it does.
    pub description: String,
    /// Whether it is a credential.
    pub secret: bool,
    /// For a secret that is a `$NAME` reference: the variable.
    pub variable: Option<String>,
    /// And whether the environment sets it.
    pub variable_set: Option<bool>,
}

/// A finding of `validate --check configuration` on one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFinding {
    /// The diagnostic code (`config_parse`).
    pub code: String,
    /// `error` or `warning`.
    pub severity: String,
    /// What is wrong.
    pub message: String,
    /// The key path, in the file.
    pub field_path: Vec<String>,
}

/// One configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigFile {
    /// `deployment.toml`, `platforms/splunk.toml`.
    pub key: String,
    /// The workspace's file, when it has one.
    pub path: Option<PathBuf>,
    /// Every effective value.
    pub settings: Vec<Setting>,
    /// `(path, description)` of options the schema defines that nothing sets.
    pub unset: Vec<(String, String)>,
    /// Its findings.
    pub findings: Vec<ConfigFinding>,
    /// The workspace's file, redacted ([`redact_toml`]); `None` without one,
    /// or when it cannot be shown ([`ConfigFile::raw_problem`] says why).
    pub raw: Option<String>,
    /// Why the workspace's file has no raw view: never its content.
    pub raw_problem: Option<String>,
}

/// One `setup` key of a tenant: never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The setup key (`api_token`).
    pub key: String,
    /// The variable it names, when it is a reference.
    pub variable: Option<String>,
    /// Whether the variable is set; `None` for a literal (shown as [`HIDDEN`]).
    pub is_set: Option<bool>,
    /// A switch (`ssl = true`), which is no credential and is shown.
    pub flag: Option<bool>,
}

/// A tenant of a platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCard {
    /// Its name.
    pub name: String,
    /// The strategies it accepts, in upper case.
    pub strategies: Vec<String>,
    /// Whether only the rules that list it reach it.
    pub manual: bool,
    /// Its `setup`.
    pub credentials: Vec<Credential>,
    /// Rules a deploy run reaches this tenant with, as `deploy` plans them.
    pub rules: Vec<String>,
}

/// A platform on the Configuration tab: whether it is enabled, its tenants
/// and its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCard {
    /// The platform's key.
    pub platform: String,
    /// Whether it is enabled.
    pub enabled: bool,
    /// Its tenants.
    pub tenants: Vec<TenantCard>,
    /// Rules with a block for this platform.
    pub rules: Vec<String>,
}

/// The tab's content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigurationView {
    /// The files, in order.
    pub files: Vec<ConfigFile>,
    /// A card per platform file, by platform.
    pub platforms: Vec<PlatformCard>,
    /// Why the configuration could not be read, when it could not.
    pub problem: Option<String>,
}

impl ConfigurationView {
    /// The file `key`.
    pub fn file(&self, key: &str) -> Option<&ConfigFile> {
        self.files.iter().find(|file| file.key == key)
    }

    /// The card of the platform file `key`, if it is one.
    pub fn card(&self, key: &str) -> Option<&PlatformCard> {
        let platform = key.strip_prefix("platforms/")?.strip_suffix(".toml")?;
        self.platforms.iter().find(|card| card.platform == platform)
    }
}

#[expect(
    clippy::expect_used,
    reason = "the patterns are literals, checked by the tests"
)]
fn pattern(cell: &'static OnceLock<Regex>, text: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(text).expect("a valid pattern"))
}

/// A key that names a secret: every value at or under it is one.
fn secret_key() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"(?i)(secret|token|password|passwd|passphrase|api[_\-\s.]?key|private[_\-\s.]?key|credential|auth|^key$|[_\-\s.]key$|cookie|session)",
    )
}

/// `scheme://user:password@host`: the user part, up to the authority's last `@`.
fn userinfo() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/?#]*@")
}

/// `str.isdigit`: not empty, every character a digit.
fn is_index(part: &str) -> bool {
    !part.is_empty() && part.chars().all(char::is_numeric)
}

/// Whether a value at `parts` is a secret: any key on the path names one.
pub fn is_secret<S: AsRef<str>>(parts: &[S]) -> bool {
    parts.iter().map(AsRef::as_ref).any(|part| {
        !is_index(part) && (SECRET_TABLES.contains(&part) || secret_key().is_match(part))
    })
}

/// `text` with the user part of each URL hidden.
pub fn hide_userinfo(text: &str) -> String {
    userinfo()
        .replace_all(text, |found: &regex::Captures<'_>| {
            format!("{}{HIDDEN}@", &found[1])
        })
        .into_owned()
}

/// The variable `value` names when it is `$NAME` or `${NAME}` as a whole.
fn reference(value: &Node) -> Option<String> {
    match &value.value {
        Value::Str(text) => opentide_workspace::info::env_reference(text).map(str::to_owned),
        _ => None,
    }
}

/// A scalar as text: a string as it is, anything else as YAML writes it
/// (`null`, `true`, `1.5`).
fn scalar_text(value: &Value) -> String {
    match value {
        Value::Str(text) | Value::Datetime(text) => text.to_string(),
        Value::Seq(_) | Value::Map(_) => String::new(),
        other => other.to_string(),
    }
}

/// A value as the tab shows it.
fn format_value(value: &Node) -> String {
    match &value.value {
        Value::Bool(flag) => if *flag { "true" } else { "false" }.to_owned(),
        Value::Str(text) => hide_userinfo(text),
        Value::Seq(items)
            if items
                .iter()
                .all(|item| !matches!(item.value, Value::Map(_) | Value::Seq(_))) =>
        {
            if items.is_empty() {
                "[]".to_owned()
            } else {
                items
                    .iter()
                    .map(|item| format_value(item))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        }
        other => scalar_text(other),
    }
}

/// Each value that is no table, and no array of scalars, with its key path.
fn leaves(value: &Node, parts: &mut Vec<String>, out: &mut Vec<(Vec<String>, Node)>) {
    match &value.value {
        Value::Map(entries) => {
            for entry in entries {
                parts.push(scalar_text(&entry.key.value));
                leaves(&entry.value, parts, out);
                parts.pop();
            }
        }
        Value::Seq(items)
            if items
                .iter()
                .any(|item| matches!(item.value, Value::Map(_) | Value::Seq(_))) =>
        {
            for (index, item) in items.iter().enumerate() {
                parts.push(index.to_string());
                leaves(item, parts, out);
                parts.pop();
            }
        }
        _ => out.push((parts.clone(), value.clone())),
    }
}

/// Every scalar, with its key path, array items by index.
fn scalars(value: &Node, parts: &mut Vec<String>, out: &mut Vec<(Vec<String>, Node)>) {
    match &value.value {
        Value::Map(entries) => {
            for entry in entries {
                parts.push(scalar_text(&entry.key.value));
                scalars(&entry.value, parts, out);
                parts.pop();
            }
        }
        Value::Seq(items) => {
            for (index, item) in items.iter().enumerate() {
                parts.push(index.to_string());
                scalars(item, parts, out);
                parts.pop();
            }
        }
        _ => out.push((parts.clone(), value.clone())),
    }
}

/// The node at `parts`, if any.
fn at<'a, S: AsRef<str>>(document: &'a Node, parts: &[S]) -> Option<&'a Node> {
    let mut node = document;
    for part in parts {
        let part = part.as_ref();
        node = match &node.value {
            Value::Map(_) => node.get(part)?,
            Value::Seq(items) if is_index(part) => items.get(part.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(node)
}

/// A setting at `parts`: a secret is its reference, or hidden.
fn shown(value: &Node, parts: &[String], env: &Env) -> Setting {
    let path = parts.join(".");
    let key = parts.last().cloned().unwrap_or_default();
    let mut setting = Setting {
        path,
        key,
        shown: String::new(),
        set_here: false,
        description: String::new(),
        secret: false,
        variable: None,
        variable_set: None,
    };
    // A switch (`ssl = true`) is no credential: it is shown as it is.
    if is_secret(parts) && !matches!(value.value, Value::Bool(_)) {
        setting.secret = true;
        match reference(value) {
            Some(variable) => {
                let set = env.get(&variable).is_some_and(|value| !value.is_empty());
                setting.shown = format!("${{{variable}}} ({})", if set { "set" } else { "unset" });
                setting.variable = Some(variable);
                setting.variable_set = Some(set);
            }
            None => HIDDEN.clone_into(&mut setting.shown),
        }
        return setting;
    }
    setting.shown = format_value(value);
    setting
}

/// `dotted path → description` from the file's JSON Schema, list items as `*`.
fn schema_descriptions(file_key: &str) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let Some(schema) = opentide_schema::generate::configuration::configuration_schema(file_key)
    else {
        return found;
    };
    let empty = serde_json::Map::new();
    let definitions = schema
        .get("$defs")
        .and_then(JsonValue::as_object)
        .unwrap_or(&empty);
    walk_schema(&schema, "", 0, definitions, &mut found);
    found
}

fn resolve_schema<'a>(
    node: &'a JsonValue,
    definitions: &'a serde_json::Map<String, JsonValue>,
) -> &'a JsonValue {
    if let Some(reference) = node.get("$ref").and_then(JsonValue::as_str)
        && let Some(name) = reference.strip_prefix("#/$defs/")
    {
        let name = name.rsplit('/').next().unwrap_or(name);
        return definitions.get(name).unwrap_or(node);
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        for option in node
            .get(key)
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
        {
            if option.is_object()
                && (option
                    .get("$ref")
                    .is_some_and(|reference| !is_falsy(reference))
                    || option
                        .get("properties")
                        .is_some_and(|properties| !is_falsy(properties)))
            {
                return resolve_schema(option, definitions);
            }
        }
    }
    node
}

fn is_falsy(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => true,
        JsonValue::Bool(flag) => !flag,
        JsonValue::String(text) => text.is_empty(),
        JsonValue::Array(items) => items.is_empty(),
        JsonValue::Object(members) => members.is_empty(),
        JsonValue::Number(number) => number.as_f64() == Some(0.0),
    }
}

fn walk_schema(
    node: &JsonValue,
    prefix: &str,
    depth: usize,
    definitions: &serde_json::Map<String, JsonValue>,
    found: &mut BTreeMap<String, String>,
) {
    if depth > 8 {
        return;
    }
    let node = resolve_schema(node, definitions);
    let Some(properties) = node.get("properties").and_then(JsonValue::as_object) else {
        return;
    };
    for (name, child) in properties {
        if !child.is_object() {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        let resolved = resolve_schema(child, definitions);
        let description = child
            .get("description")
            .filter(|description| !is_falsy(description))
            .or_else(|| resolved.get("description"));
        if let Some(description) = description.and_then(JsonValue::as_str) {
            found.insert(
                path.clone(),
                description.split_whitespace().collect::<Vec<_>>().join(" "),
            );
        }
        walk_schema(resolved, &path, depth + 1, definitions, found);
        if let Some(items) = resolved.get("items").filter(|items| items.is_object()) {
            walk_schema(items, &format!("{path}.*"), depth + 1, definitions, found);
        }
    }
}

/// `dotted path → the comment above it` in a bundled file (`lint.toml` has
/// no schema; `_comment_descriptions`).
fn comment_descriptions(text: Option<&str>) -> BTreeMap<String, String> {
    static EXAMPLE: OnceLock<Regex> = OnceLock::new();
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static ASSIGNMENT: OnceLock<Regex> = OnceLock::new();
    let example = pattern(&EXAMPLE, r#"^[\w.\-"]+\s*="#);
    let header = pattern(&HEADER, r"^\[\[?([^\]]+)\]\]?$");
    let assignment = pattern(&ASSIGNMENT, r"^([\w\-]+)\s*=");
    let mut found = BTreeMap::new();
    let Some(text) = text.filter(|text| !text.is_empty()) else {
        return found;
    };
    let mut comments: Vec<String> = Vec::new();
    let mut table: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            let body = line.trim_start_matches('#').trim();
            // A commented-out key is an example, not a description.
            if !body.is_empty() && !example.is_match(body) && !body.starts_with('[') {
                comments.push(body.to_owned());
            }
            continue;
        }
        if let Some(found_header) = header.captures(line) {
            table = found_header[1]
                .split('.')
                .map(|part| part.trim().to_owned())
                .collect();
            if !comments.is_empty() {
                found.insert(table.join("."), comments.join(" "));
            }
            comments.clear();
            continue;
        }
        if let Some(found_key) = assignment.captures(line)
            && !comments.is_empty()
        {
            let mut path = table.clone();
            path.push(found_key[1].to_owned());
            found.insert(path.join("."), comments.join(" "));
        }
        if !line.is_empty() {
            comments.clear();
        }
    }
    found
}

/// The description of the setting at `parts`.
fn description(descriptions: &BTreeMap<String, String>, parts: &[String]) -> String {
    let starred: Vec<&str> = parts
        .iter()
        .map(|part| if is_index(part) { "*" } else { part.as_str() })
        .collect();
    let plain: Vec<&str> = parts
        .iter()
        .filter(|part| !is_index(part))
        .map(String::as_str)
        .collect();
    descriptions
        .get(&starred.join("."))
        .filter(|text| !text.is_empty())
        .or_else(|| descriptions.get(&plain.join(".")))
        .cloned()
        .unwrap_or_default()
}

fn bundled_text(file_key: &str) -> Option<&'static str> {
    opentide_schema::configuration::bundled::FILES
        .iter()
        .find(|(path, _)| *path == file_key)
        .map(|(_, text)| text())
}

// -- the redaction -------------------------------------------------------------

/// Why a file has no raw view: it does not parse, or its redaction was not
/// proven. The message never quotes the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeRawView(pub String);

/// A value the raw view cannot place (no byte span): the raw view is withheld.
#[derive(Debug)]
struct ScanError;

/// `value` as a TOML basic string.
fn basic_string(value: &str) -> String {
    let mut out = String::from('"');
    for c in value.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' || c == '\u{7f}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What the raw view changes in a document, found on `toml_edit`'s tree of
/// it (`_Redactor`), which keeps each value's bytes: a secret value is
/// replaced, and a string whose URL names a user is written again with the
/// user hidden. Inline tables are read key by key and arrays item by item, so
/// a value is found however it is written; an array whose path is a secret is
/// replaced whole.
struct Redactor<'a> {
    env: &'a Env,
    /// The bytes of each value the view shows as something else, and what.
    replaced: Vec<(Range<usize>, String)>,
    /// The bytes of every value, replaced or not: no comment is read in them.
    values: Vec<Range<usize>>,
}

impl Redactor<'_> {
    /// The values of `table` at `path` (a table header's keys, an array of
    /// tables' without an index), each statement's value at the top.
    fn table(&mut self, table: &toml_edit::Table, path: &mut Vec<String>) -> Result<(), ScanError> {
        for (key, item) in table {
            path.push(key.to_owned());
            match item {
                toml_edit::Item::None => {}
                toml_edit::Item::Value(value) => self.value(value, path, true)?,
                toml_edit::Item::Table(table) => self.table(table, path)?,
                toml_edit::Item::ArrayOfTables(tables) => {
                    for table in tables {
                        self.table(table, path)?;
                    }
                }
            }
            path.pop();
        }
        Ok(())
    }

    /// `value` at `path`; `top` when it is a statement's value, not an
    /// array's item or an inline table's.
    fn value(
        &mut self,
        value: &toml_edit::Value,
        path: &mut Vec<String>,
        top: bool,
    ) -> Result<(), ScanError> {
        if let toml_edit::Value::InlineTable(table) = value {
            // Its keys are no secret: each value is redacted at its own path.
            for (key, value) in table {
                path.push(key.to_owned());
                self.value(value, path, false)?;
                path.pop();
            }
            return Ok(());
        }
        let span = value.span().ok_or(ScanError)?;
        if is_secret(path) && !value.is_bool() {
            let hidden = self.hidden(value.as_str(), top);
            self.replace(span, hidden);
            return Ok(());
        }
        match value {
            toml_edit::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    path.push(index.to_string());
                    self.value(item, path, false)?;
                    path.pop();
                }
            }
            toml_edit::Value::String(text) => {
                let shown = hide_userinfo(text.value());
                if shown == *text.value() {
                    self.values.push(span);
                } else {
                    self.replace(span, basic_string(&shown));
                }
            }
            _ => self.values.push(span),
        }
        Ok(())
    }

    fn replace(&mut self, span: Range<usize>, text: String) {
        self.values.push(span.clone());
        self.replaced.push((span, text));
    }

    /// What a secret value reads as: the variable a string names and whether
    /// it is set (on a statement's value), or [`HIDDEN`].
    fn hidden(&self, text: Option<&str>, top: bool) -> String {
        let Some(variable) = text.and_then(opentide_workspace::info::env_reference) else {
            return basic_string(HIDDEN);
        };
        let quoted = basic_string(&format!("${{{variable}}}"));
        if !top {
            return quoted;
        }
        let state = if self
            .env
            .get(variable)
            .is_some_and(|value| !value.is_empty())
        {
            "set"
        } else {
            "unset"
        };
        format!("{quoted}  # {state}")
    }

    /// `text` with the values replaced and, between the values, each
    /// comment's URL user hidden (and a quoted key's that holds a `#`).
    fn write(mut self, text: &str) -> Result<String, ScanError> {
        self.values.sort_by_key(|span| span.start);
        self.replaced.sort_by_key(|(span, _)| span.start);
        let mut replaced = self.replaced.into_iter().peekable();
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for span in self.values {
            let gap = text.get(pos..span.start).ok_or(ScanError)?;
            out.push_str(&between_values(gap)?);
            match replaced.next_if(|(at, _)| at.start == span.start) {
                Some((_, shown)) => out.push_str(&shown),
                None => out.push_str(text.get(span.clone()).ok_or(ScanError)?),
            }
            pos = span.end;
        }
        out.push_str(&between_values(text.get(pos..).ok_or(ScanError)?)?);
        Ok(out)
    }
}

/// Text between two values (keys, table headers, punctuation, blanks and
/// comments) as the raw view shows it: each comment's URL user hidden, and a
/// quoted key's when it holds a `#`. A [`ScanError`] if a cut fell off a
/// char boundary, which no cut does: each is where `find` found a character,
/// or the end of a quoted key.
fn between_values(gap: &str) -> Result<String, ScanError> {
    let mut out = String::with_capacity(gap.len());
    let mut rest = gap;
    while let Some(at) = rest.find(['#', '"', '\'']) {
        debug_assert!(rest.is_char_boundary(at), "{rest:?} cut at {at}");
        let (plain, from) = rest.split_at_checked(at).ok_or(ScanError)?;
        out.push_str(plain);
        rest = from;
        let end = if rest.starts_with('#') {
            rest.find('\n').unwrap_or(rest.len())
        } else {
            quoted_key_end(rest)
        };
        debug_assert!(rest.is_char_boundary(end), "{rest:?} cut at {end}");
        let (token, after) = rest.split_at_checked(end).ok_or(ScanError)?;
        if token.contains('#') {
            out.push_str(&hide_userinfo(token));
        } else {
            out.push_str(token);
        }
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

/// The length of the quoted key `text` starts with: up to its closing quote
/// (a basic one's escapes skipped), or the line's end.
fn quoted_key_end(text: &str) -> usize {
    let mut chars = text.char_indices();
    let Some((_, quote)) = chars.next() else {
        return 0;
    };
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' if quote == '"' => {
                chars.next();
            }
            '\n' => return at,
            c if c == quote => return at + c.len_utf8(),
            _ => {}
        }
    }
    text.len()
}

/// `text` read by `toml_edit`, with every secret value replaced and every
/// URL user hidden (`_Redactor`).
fn redacted_text(text: &str, env: &Env) -> Result<String, ScanError> {
    let parsed = toml_edit::ImDocument::parse(text).map_err(|_| ScanError)?;
    let mut redactor = Redactor {
        env,
        replaced: Vec::new(),
        values: Vec::new(),
    };
    redactor.table(parsed.as_table(), &mut Vec::new())?;
    redactor.write(text)
}

/// Every text a secret of `document` could show as: never to appear in a
/// raw view.
fn secrets(document: &Node) -> HashSet<String> {
    let mut found = HashSet::new();
    let mut all = Vec::new();
    scalars(document, &mut Vec::new(), &mut all);
    for (parts, value) in all {
        if let Value::Str(text) = &value.value {
            for matched in userinfo().captures_iter(text) {
                let whole = &matched[0];
                let scheme = matched[1].len();
                if let Some(user) = whole.get(scheme..whole.len() - 1) {
                    found.insert(user.to_owned());
                }
            }
        }
        if matches!(value.value, Value::Bool(_)) || !is_secret(&parts) {
            continue;
        }
        match &value.value {
            Value::Str(text) => {
                if opentide_workspace::info::env_reference(text).is_none() {
                    found.insert(text.to_string());
                    found.extend(text.split('\n').map(|line| line.trim().to_owned()));
                }
            }
            other => {
                found.insert(scalar_text(other));
            }
        }
    }
    found.remove("");
    found
}

/// Whether `redacted` holds no secret of `document`, read back as TOML and
/// as text.
fn proven(document: &Node, redacted: &str) -> bool {
    let Ok(shown) = config_toml::parse(redacted) else {
        return false;
    };
    let mut all = Vec::new();
    scalars(&shown, &mut Vec::new(), &mut all);
    for (parts, value) in all {
        if is_secret(&parts) && !matches!(value.value, Value::Bool(_)) {
            let text = match &value.value {
                Value::Str(text) => text.as_str(),
                _ => return false,
            };
            if text != HIDDEN && opentide_workspace::info::env_reference(text).is_none() {
                return false;
            }
            continue;
        }
        let Some(original) = at(document, &parts) else {
            return false;
        };
        let expected = match &original.value {
            Value::Str(text) => Value::Str(hide_userinfo(text).into()),
            other => other.clone(),
        };
        if value.value != expected {
            return false;
        }
    }
    !secrets(document)
        .iter()
        .any(|secret| redacted.contains(secret.as_str()))
}

/// `text` with every secret value replaced, as the raw view shows it
/// (`redact_toml`): a value with a `setup` table or a secret-named key on
/// its key path reads as its variable reference and whether it is set, or as
/// [`HIDDEN`]; the user part of a URL is hidden. Comments and layout stay.
/// The result is then proven.
///
/// # Errors
///
/// [`UnsafeRawView`], whose message never quotes the file, when `text` is
/// not valid TOML or its redaction cannot be proven.
pub fn redact_toml(text: &str, env: &Env) -> Result<String, UnsafeRawView> {
    let document = config_toml::parse(text)
        .map_err(|error| UnsafeRawView(format!("not valid TOML: {}", toml_position(&error))))?;
    let redacted =
        redacted_text(text, env).map_err(|ScanError| UnsafeRawView(UNSAFE_RAW.to_owned()))?;
    if !proven(&document, &redacted) {
        return Err(UnsafeRawView(UNSAFE_RAW.to_owned()));
    }
    Ok(redacted)
}

// -- the view ------------------------------------------------------------------

/// Whether `document` has a value at `parts`.
fn has(document: &Node, parts: &[String]) -> bool {
    at(document, parts).is_some()
}

/// One configuration file.
fn file(
    file_key: &str,
    merged: Option<&Node>,
    workspace_dir: Option<&Path>,
    findings: Vec<ConfigFinding>,
    env: &Env,
) -> ConfigFile {
    let mut path = workspace_dir
        .map(|dir| dir.join(file_key))
        .filter(|path| path.is_file());
    let mut own: Option<Node> = None;
    let (mut raw, mut raw_problem) = (None, None);
    if let Some(file_path) = &path {
        match std::fs::read(file_path) {
            Err(error) => {
                raw_problem = Some(format!("the file could not be read: {error}"));
            }
            Ok(bytes) => {
                let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(&bytes);
                match std::str::from_utf8(bytes) {
                    Err(_) => {
                        raw_problem = Some(NOT_UTF8.to_owned());
                    }
                    Ok(text) => {
                        own = config_toml::parse(text).ok();
                        match redact_toml(text, env) {
                            Ok(redacted) => raw = Some(redacted),
                            Err(UnsafeRawView(problem)) => raw_problem = Some(problem),
                        }
                    }
                }
            }
        }
    } else {
        path = None;
    }
    let mut descriptions = comment_descriptions(bundled_text(file_key));
    descriptions.extend(schema_descriptions(file_key));
    let mut found = Vec::new();
    if let Some(merged) = merged.filter(|merged| matches!(merged.value, Value::Map(_))) {
        leaves(merged, &mut Vec::new(), &mut found);
    }
    let settings: Vec<Setting> = found
        .iter()
        .map(|(parts, value)| {
            let mut setting = shown(value, parts, env);
            setting.set_here = own.as_ref().is_some_and(|own| has(own, parts));
            setting.description = description(&descriptions, parts);
            setting
        })
        .collect();
    let mut present: BTreeSet<String> = BTreeSet::new();
    for setting in &settings {
        let parts: Vec<&str> = setting.path.split('.').collect();
        present.insert(
            parts
                .iter()
                .map(|part| if is_index(part) { "*" } else { part })
                .collect::<Vec<_>>()
                .join("."),
        );
        present.insert(
            parts
                .iter()
                .filter(|part| !is_index(part))
                .copied()
                .collect::<Vec<_>>()
                .join("."),
        );
    }
    let mut prefixes: BTreeSet<String> = BTreeSet::new();
    for known in &present {
        let mut rest = known.as_str();
        while let Some((head, _)) = rest.rsplit_once('.') {
            prefixes.insert(head.to_owned());
            rest = head;
        }
    }
    let unset = descriptions
        .iter()
        .filter(|(path_key, _)| {
            if present.contains(*path_key) || prefixes.contains(*path_key) {
                return false;
            }
            if let Some((parent, _)) = path_key.rsplit_once('.')
                && !(prefixes.contains(parent) || present.contains(parent))
            {
                return false;
            }
            !is_secret(&path_key.split('.').collect::<Vec<_>>())
        })
        .map(|(path_key, text)| (path_key.clone(), text.clone()))
        .collect();
    ConfigFile {
        key: file_key.to_owned(),
        path,
        settings,
        unset,
        findings,
        raw,
        raw_problem,
    }
}

/// `validate --check configuration`'s findings, by the file they name.
fn findings(resolved: &Node) -> BTreeMap<String, Vec<ConfigFinding>> {
    let mut found: BTreeMap<String, Vec<ConfigFinding>> = BTreeMap::new();
    let checked = std::panic::catch_unwind(|| {
        opentide_schema::configuration::checks::workspace_issues(resolved)
    });
    // The checks are validate's: the tab shows what it can.
    let Ok(issues) = checked else {
        return found;
    };
    for issue in issues {
        let file_key = issue
            .context
            .get("file")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        found.entry(file_key).or_default().push(ConfigFinding {
            code: issue.code.clone(),
            severity: issue.severity.as_str().to_owned(),
            message: issue.message.clone(),
            field_path: issue.field_path.clone(),
        });
    }
    found
}

/// `validate --check sharing-config`'s findings (`load_sharing`), shown on
/// `sharing.toml`: the bundled file, then each configuration folder's in
/// `folders`, read as they are. `sharing.toml` has a loader of its own, so
/// the merged configuration does not hold it, and a file that does not
/// parse, or is not UTF-8, is a finding here rather than a catalogue that
/// does not load.
fn sharing_findings(folders: &[PathBuf], resolved: &Node) -> Vec<ConfigFinding> {
    use opentide_schema::configuration::{bundled, checks};
    let mut layers = vec![(
        "<bundled>".to_owned(),
        bundled::text("sharing.toml").map(str::to_owned),
        false,
    )];
    for folder in folders.iter().filter(|folder| folder.is_dir()) {
        let file = folder.join("sharing.toml");
        let text = file
            .is_file()
            .then(|| std::fs::read(&file).ok())
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        layers.push((
            folder.to_string_lossy().into_owned(),
            text,
            folder.join("sharing").is_dir(),
        ));
    }
    let statuses = resolved
        .get("deployment")
        .map_or_else(checks::bundled_status_names, |deployment| {
            checks::status_names(deployment)
        });
    let checked = std::panic::catch_unwind(|| checks::sharing_config_issues(&layers, &statuses));
    // The checks are validate's: the tab shows what it can.
    let Ok(issues) = checked else {
        return Vec::new();
    };
    issues
        .into_iter()
        .map(|issue| ConfigFinding {
            code: issue.code.clone(),
            severity: issue.severity.as_str().to_owned(),
            message: issue.message.clone(),
            field_path: issue.field_path.clone(),
        })
        .collect()
}

/// Status name to strategy, from `deployment.toml` as written.
fn status_strategies(
    deployment: Option<&Node>,
) -> BTreeMap<String, opentide_compile::strategy::StatusStrategy> {
    use opentide_compile::strategy::StatusStrategy;
    let mut found = BTreeMap::new();
    let Some(Value::Seq(entries)) = deployment
        .and_then(|deployment| deployment.get("statuses"))
        .map(|node| &node.value)
    else {
        return found;
    };
    for entry in entries {
        let name = entry.get("name").and_then(|node| node.value.as_str());
        let strategy = entry
            .get("strategy")
            .and_then(|node| node.value.as_str())
            .and_then(|strategy| StatusStrategy::from_name(&strategy.to_uppercase()));
        if let (Some(name), Some(strategy)) = (name, strategy) {
            found.insert(name.to_owned(), strategy);
        }
    }
    found
}

/// A card per platform file: `rules` are the rule
/// bodies by UUID, in the catalogue's order.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn platform_cards(resolved: &Node, rules: &[(String, &Node)], env: &Env) -> Vec<PlatformCard> {
    let strategies = status_strategies(resolved.get("deployment").map(AsRef::as_ref));
    let Some(Value::Map(platforms)) = resolved.get("platforms").map(|node| &node.value) else {
        return Vec::new();
    };
    let mut sorted: Vec<&opentide_schema::node::Entry> = platforms.iter().collect();
    sorted.sort_by_key(|entry| scalar_text(&entry.key.value));
    let mut cards = Vec::new();
    for entry in sorted {
        let platform = scalar_text(&entry.key.value);
        let document = &entry.value;
        if !matches!(document.value, Value::Map(_)) {
            continue;
        }
        // On exactly when `deploy` deploys it: `[platform] enabled` is the
        // boolean `true`; the string "false", or an `enabled` outside the
        // `[platform]` table, is not on.
        let enabled = opentide_schema::configuration::resolve::platform_enabled(
            resolved.get("platforms").map(AsRef::as_ref),
            &platform,
        );
        let with_block: Vec<(&str, &Node)> = rules
            .iter()
            .filter_map(|(uuid, rule)| {
                let block = rule.get("configurations")?.get(&platform)?;
                matches!(block.value, Value::Map(_)).then_some((uuid.as_str(), block.as_ref()))
            })
            .collect();
        let mut tenants = Vec::new();
        let listed_tenants: &[std::sync::Arc<Node>] = match document.get("tenants") {
            Some(node) => match &node.value {
                Value::Seq(items) => items,
                _ => &[],
            },
            None => &[],
        };
        for (index, tenant) in listed_tenants.iter().enumerate() {
            if !matches!(tenant.value, Value::Map(_)) {
                continue;
            }
            let name = tenant
                .get("name")
                .and_then(|name| name.value.as_str())
                .filter(|name| !name.is_empty())
                .map_or_else(|| format!("tenant {}", index + 1), str::to_owned);
            let accepted: Vec<String> = match tenant.get("strategies").map(|node| &node.value) {
                Some(Value::Seq(items)) => items
                    .iter()
                    .map(|item| scalar_text(&item.value).to_uppercase())
                    .collect(),
                _ => Vec::new(),
            };
            let manual = matches!(
                tenant.get("manual").map(|node| &node.value),
                Some(Value::Bool(true))
            );
            let mut credentials = Vec::new();
            if let Some(Value::Map(setup)) = tenant.get("setup").map(|node| &node.value) {
                for field in setup {
                    let variable = reference(&field.value);
                    let is_set = variable
                        .as_ref()
                        .map(|variable| env.get(variable).is_some_and(|value| !value.is_empty()));
                    credentials.push(Credential {
                        key: scalar_text(&field.key.value),
                        variable,
                        is_set,
                        flag: match field.value.value {
                            Value::Bool(flag) => Some(flag),
                            _ => None,
                        },
                    });
                }
            }
            let mut reaching = Vec::new();
            for (uuid, block) in &with_block {
                if matches!(
                    block.get("enabled").map(|node| &node.value),
                    Some(Value::Bool(false))
                ) {
                    continue;
                }
                let listed: Vec<String> = match block.get("tenants").map(|node| &node.value) {
                    Some(Value::Seq(items)) => {
                        items.iter().map(|item| scalar_text(&item.value)).collect()
                    }
                    _ => Vec::new(),
                };
                if !listed.is_empty() {
                    if listed.contains(&name) {
                        reaching.push((*uuid).to_owned());
                    }
                    continue;
                }
                if manual {
                    continue;
                }
                let status = block.get("status").and_then(|status| status.value.as_str());
                let Some(strategy) = status.and_then(|status| strategies.get(status)) else {
                    continue;
                };
                let runs = opentide_compile::strategy::deployed_by(*strategy);
                if runs
                    .iter()
                    .any(|run| accepted.iter().any(|name| name == run.name()))
                {
                    reaching.push((*uuid).to_owned());
                }
            }
            tenants.push(TenantCard {
                name,
                strategies: accepted,
                manual,
                credentials,
                rules: reaching,
            });
        }
        cards.push(PlatformCard {
            platform,
            enabled,
            tenants,
            rules: with_block
                .iter()
                .map(|(uuid, _)| (*uuid).to_owned())
                .collect(),
        });
    }
    cards
}

/// The tab's content for the workspace at `root`, whose configuration
/// resolved to `resolved` from the configuration folders `folders`; `rules`
/// are its rule bodies by UUID (`load_configuration_view`).
pub fn load(
    root: Option<&Path>,
    resolved: &Node,
    folders: &[PathBuf],
    rules: &[(String, &Node)],
    env: &Env,
) -> ConfigurationView {
    let workspace_dir = root.map(|root| root.join(".opentide").join("configurations"));
    let mut found = findings(resolved);
    found
        .entry("sharing.toml".to_owned())
        .or_default()
        .extend(sharing_findings(folders, resolved));
    let mut files: Vec<ConfigFile> = FILES
        .iter()
        .map(|key| {
            let merged_key = key.trim_end_matches(".toml");
            file(
                key,
                resolved.get(merged_key).map(AsRef::as_ref),
                workspace_dir.as_deref(),
                found.remove(*key).unwrap_or_default(),
                env,
            )
        })
        .collect();
    if let Some(Value::Map(platforms)) = resolved.get("platforms").map(|node| &node.value) {
        let mut sorted: Vec<&opentide_schema::node::Entry> = platforms.iter().collect();
        sorted.sort_by_key(|entry| scalar_text(&entry.key.value));
        for entry in sorted {
            let key = format!("platforms/{}.toml", scalar_text(&entry.key.value));
            let findings = found.remove(&key).unwrap_or_default();
            files.push(file(
                &key,
                Some(&entry.value),
                workspace_dir.as_deref(),
                findings,
                env,
            ));
        }
    }
    // Where, never what: a parser's message may quote the file, so a
    // `sharing.toml` that does not parse says what its raw view says.
    if let Some(sharing) = files.iter_mut().find(|item| item.key == "sharing.toml") {
        let problem = sharing
            .raw_problem
            .clone()
            .unwrap_or_else(|| "not valid TOML".to_owned());
        for finding in &mut sharing.findings {
            if finding.code == opentide_schema::configuration::codes::CONFIG_PARSE {
                finding.message = format!("sharing.toml: {problem}");
            }
        }
    }
    ConfigurationView {
        files,
        platforms: platform_cards(resolved, rules, env),
        problem: None,
    }
}

#[cfg(test)]
mod tests;
