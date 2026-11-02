//! Configuration TOML under `.opentide/configurations/`: the host checks, the
//! engine places.
//!
//! opentide's models are the only authority on these files. A host installs a
//! checker ([`set_configuration_checker`]); `opentide lsp start` installs
//! opentide's `configuration_text_issues`. The engine never decides what is
//! wrong with a configuration file. It turns each finding's `field_path` into
//! a range in the buffer, as it does for Tide objects. The host's schemas
//! ([`install_configuration_schemas`]) give hover and completion.
//!
//! Without a checker there are no diagnostics, and without schemas there is no
//! hover and no completion: nothing here guesses what opentide would say.

use opentide_core::{ByteSpan, CompletionItem, Diagnostic, Range, Severity, codes, span_to_range};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use toml_edit::{ImDocument, Item, Table};

/// The directory configuration files live in, relative to the workspace.
pub const CONFIGURATIONS_DIRECTORY: &str = ".opentide/configurations/";

/// What the engine asks the host's checker about one configuration buffer.
#[derive(Debug, Clone, Copy)]
pub struct ConfigRequest<'a> {
    /// The file's path, as the host named it (absolute in the language server).
    pub path: &'a str,
    /// The buffer, without a byte-order mark.
    pub text: &'a str,
    /// The other open configuration buffers, `(path, text)`. An unsaved
    /// `deployment.toml` changes which statuses `sharing.toml` may name.
    pub open: &'a [(String, String)],
}

/// One finding from the host's checker, in the shape opentide's
/// `configuration_text_issues` returns. `field_path` is a key path into the
/// buffer, list items by index (`["misp", "0", "max_tlp"]`); an empty path is
/// about the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    pub code: String,
    pub field_path: Vec<String>,
    pub severity: Severity,
    pub message: String,
}

/// A host's configuration checker. An `Err` is reported as one
/// `config_check_failed` warning on the buffer.
pub type ConfigChecker =
    dyn Fn(&ConfigRequest<'_>) -> Result<Vec<ConfigIssue>, String> + Send + Sync;

fn checker_slot() -> &'static RwLock<Option<Arc<ConfigChecker>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<ConfigChecker>>>> = OnceLock::new();
    SLOT.get_or_init(Default::default)
}

/// Install the host's configuration checker for the whole process, or remove
/// it with `None`. The engine calls it from the thread that analyses a
/// buffer, without holding any engine lock.
pub fn set_configuration_checker(checker: Option<Box<ConfigChecker>>) {
    let mut slot = checker_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = checker.map(Arc::from);
}

/// Whether a host installed a configuration checker.
pub fn has_configuration_checker() -> bool {
    checker_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// The path of `path` relative to `.opentide/configurations/`, when it is a
/// TOML file there (`sharing.toml`, `platforms/sentinel.toml`). A path may use
/// either separator and be absolute or relative to the workspace.
pub fn configuration_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let marker = format!("/{CONFIGURATIONS_DIRECTORY}");
    let rest = match path.rfind(&marker) {
        Some(index) => &path[index + marker.len()..],
        None => path.strip_prefix(CONFIGURATIONS_DIRECTORY)?,
    };
    let stem = rest.strip_suffix(".toml")?;
    (!stem.is_empty() && !stem.ends_with('/')).then(|| rest.to_string())
}

/// Whether `path` is a configuration TOML file ([`configuration_path`]).
pub fn is_configuration_path(path: &str) -> bool {
    configuration_path(path).is_some()
}

/// The host checker's findings on `text`, each at its place in the buffer.
/// No checker: none.
pub fn configuration_diagnostics(
    path: &str,
    text: &str,
    open: &[(String, String)],
) -> Vec<Diagnostic> {
    let checker = checker_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let Some(checker) = checker else {
        return Vec::new();
    };
    let issues = match checker(&ConfigRequest { path, text, open }) {
        Ok(issues) => issues,
        Err(problem) => {
            return vec![Diagnostic::warning(
                codes::CONFIG_CHECK_FAILED,
                format!("opentide could not check this file: {problem}"),
                first_line(text),
            )];
        }
    };
    let parsed = ImDocument::parse(text);
    issues
        .into_iter()
        .map(|issue| place(text, parsed.as_ref(), issue))
        .collect()
}

fn place(
    text: &str,
    parsed: Result<&ImDocument<&str>, &toml_edit::TomlError>,
    issue: ConfigIssue,
) -> Diagnostic {
    let (span, resolved) = match parsed {
        Ok(document) => locate(document.as_table(), &issue.field_path),
        // Not TOML: only the parse error itself has a place.
        Err(error) if issue.field_path.is_empty() => (error.span(), true),
        Err(_) => (None, false),
    };
    let message = if resolved || issue.field_path.is_empty() {
        issue.message
    } else {
        format!("{}: {}", display_path(&issue.field_path), issue.message)
    };
    let range = span
        .map(|span| {
            let start = span.start.min(text.len());
            span_to_range(
                text,
                ByteSpan::new(start, span.end.clamp(start, text.len())),
            )
        })
        .unwrap_or_else(|| first_line(text));
    Diagnostic {
        code: issue.code,
        severity: issue.severity,
        message,
        range,
        field_path: (!issue.field_path.is_empty()).then_some(issue.field_path),
        suggestion: None,
        object_uuid: None,
        object_type: None,
    }
}

/// The first line of `text`, where a finding about the whole file goes.
fn first_line(text: &str) -> Range {
    let end = text.find(['\r', '\n']).unwrap_or(text.len());
    span_to_range(text, ByteSpan::new(0, end))
}

/// `misp[0].max_tlp` for `["misp", "0", "max_tlp"]`.
fn display_path(path: &[String]) -> String {
    let mut out = String::new();
    for segment in path {
        if segment.parse::<usize>().is_ok() {
            out.push_str(&format!("[{segment}]"));
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(segment);
        }
    }
    out
}

enum Node<'a> {
    Table(&'a Table),
    Item(&'a Item),
    Value(&'a toml_edit::Value),
}

type Span = std::ops::Range<usize>;

/// The span of `path` in the document: its last key, or an array-of-tables
/// entry's header, and whether the whole path exists. When only a prefix
/// exists, the deepest part of it that has a span.
fn locate(root: &Table, path: &[String]) -> (Option<Span>, bool) {
    let mut node = Node::Table(root);
    let mut best = None;
    for segment in path {
        let next = match node {
            Node::Table(table) => table_child(table, segment),
            Node::Item(Item::Table(table)) => table_child(table, segment),
            Node::Item(Item::ArrayOfTables(tables)) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| tables.get(index))
                .map(|table| (table.span(), Node::Table(table))),
            Node::Item(Item::Value(value)) | Node::Value(value) => value_child(value, segment),
            Node::Item(Item::None) => None,
        };
        let Some((span, child)) = next else {
            return (best, false);
        };
        if span.is_some() {
            best = span;
        }
        node = child;
    }
    (best, true)
}

fn table_child<'a>(table: &'a Table, key: &str) -> Option<(Option<Span>, Node<'a>)> {
    table
        .get_key_value(key)
        .map(|(key, item)| (key.span().or_else(|| item.span()), Node::Item(item)))
}

fn value_child<'a>(value: &'a toml_edit::Value, segment: &str) -> Option<(Option<Span>, Node<'a>)> {
    match value {
        toml_edit::Value::InlineTable(table) => table
            .get_key_value(segment)
            .map(|(key, item)| (key.span().or_else(|| item.span()), Node::Item(item))),
        toml_edit::Value::Array(array) => segment
            .parse::<usize>()
            .ok()
            .and_then(|index| array.get(index))
            .map(|item| (item.span(), Node::Value(item))),
        _ => None,
    }
}

// --- Schemas, for hover and completion ---------------------------------------

struct Schemas {
    /// The router's `files`: router key → `{ "schema": <file name>, ... }`.
    files: serde_json::Map<String, Value>,
    /// Schema documents by file name.
    documents: HashMap<String, Value>,
}

/// The router key a platform file without a dedicated entry falls back to.
const GENERIC_PLATFORM_FILE: &str = "platforms/*.toml";

fn schemas_slot() -> &'static RwLock<Option<Arc<Schemas>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<Schemas>>>> = OnceLock::new();
    SLOT.get_or_init(Default::default)
}

/// Install the host's configuration schemas for the whole process: the router
/// (`configurations.router.json`) and the schema documents by file name, as
/// opentide's `generate_configuration_schemas()` returns them. `None` removes
/// them. Text that is not JSON, or a router without `files`, is an error and
/// changes nothing.
pub fn install_configuration_schemas(
    router: Option<&str>,
    schemas: &[(String, String)],
) -> Result<(), String> {
    let installed = match router {
        None => None,
        Some(router) => {
            let router: Value = serde_json::from_str(router)
                .map_err(|err| format!("configurations.router.json: {err}"))?;
            let files = router
                .get("files")
                .and_then(Value::as_object)
                .cloned()
                .ok_or("configurations.router.json: no `files` table")?;
            let mut documents = HashMap::new();
            for (name, text) in schemas {
                let document: Value =
                    serde_json::from_str(text).map_err(|err| format!("{name}: {err}"))?;
                documents.insert(name.clone(), document);
            }
            Some(Arc::new(Schemas { files, documents }))
        }
    };
    *schemas_slot()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = installed;
    Ok(())
}

/// Whether a host installed configuration schemas.
pub fn has_configuration_schemas() -> bool {
    schemas_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

fn installed_schemas() -> Option<Arc<Schemas>> {
    schemas_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

impl Schemas {
    /// The schema of the file at `relative` (under the configurations
    /// directory): its router entry, or the generic platform entry.
    fn for_file(&self, relative: &str) -> Option<&Value> {
        let entry = self.files.get(relative).or_else(|| {
            let name = relative.strip_prefix("platforms/")?;
            (!name.contains('/'))
                .then(|| self.files.get(GENERIC_PLATFORM_FILE))
                .flatten()
        })?;
        self.documents.get(entry.get("schema")?.as_str()?)
    }
}

/// A walk over one schema document. It reads the schema; it never validates.
struct Walker<'a> {
    root: &'a Value,
}

const MAX_DEPTH: usize = 16;

impl<'a> Walker<'a> {
    /// `node` with local `$ref`s followed.
    fn resolve(&self, mut node: &'a Value) -> &'a Value {
        for _ in 0..MAX_DEPTH {
            let Some(pointer) = node
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix('#'))
            else {
                break;
            };
            match self.root.pointer(pointer) {
                Some(target) => node = target,
                None => break,
            }
        }
        node
    }

    /// The shapes a node may take: each non-null branch of `anyOf`, `oneOf`
    /// and `allOf`, else the node itself.
    fn branches(&self, node: &'a Value) -> Vec<&'a Value> {
        let mut out = Vec::new();
        self.collect_branches(node, 0, &mut out);
        out
    }

    fn collect_branches(&self, node: &'a Value, depth: usize, out: &mut Vec<&'a Value>) {
        let node = self.resolve(node);
        if depth > MAX_DEPTH || is_null_type(node) {
            return;
        }
        let mut nested = false;
        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(list) = node.get(key).and_then(Value::as_array) {
                nested = true;
                for branch in list {
                    self.collect_branches(branch, depth + 1, out);
                }
            }
        }
        if !nested || node.get("properties").is_some() || node.get("type").is_some() {
            out.push(node);
        }
    }

    /// The tables a node stands for: an array's items (an array of tables),
    /// else the node's own branches.
    fn tables(&self, node: &'a Value) -> Vec<&'a Value> {
        let mut out = Vec::new();
        for branch in self.branches(node) {
            match branch.get("items") {
                Some(items) if is_array(branch) => out.extend(self.branches(items)),
                _ => out.push(branch),
            }
        }
        out
    }

    fn child(&self, node: &'a Value, key: &str) -> Option<&'a Value> {
        let tables = self.tables(node);
        tables
            .iter()
            .find_map(|table| table.get("properties").and_then(|p| p.get(key)))
            .or_else(|| {
                tables.iter().find_map(|table| {
                    table
                        .get("additionalProperties")
                        .filter(|extra| extra.is_object())
                })
            })
    }

    fn at(&self, path: &[String]) -> Option<&'a Value> {
        path.iter()
            .try_fold(self.root, |node, key| self.child(node, key))
    }

    /// Every property of the table `node` stands for, in schema order, once.
    fn properties(&self, node: &'a Value) -> Vec<(&'a str, &'a Value)> {
        let mut out: Vec<(&'a str, &'a Value)> = Vec::new();
        for table in self.tables(node) {
            if let Some(properties) = table.get("properties").and_then(Value::as_object) {
                for (name, schema) in properties {
                    if !out.iter().any(|(seen, _)| *seen == name.as_str()) {
                        out.push((name.as_str(), schema));
                    }
                }
            }
        }
        out
    }

    fn first(&self, node: &'a Value, key: &str) -> Option<&'a Value> {
        let node_value = self.resolve(node).get(key).or_else(|| node.get(key));
        node_value.or_else(|| {
            self.branches(node)
                .into_iter()
                .find_map(|branch| branch.get(key))
        })
    }

    /// `string`, `boolean`, `array of string`, `string or null`…
    fn type_label(&self, node: &'a Value) -> Option<String> {
        let mut labels: Vec<String> = Vec::new();
        for branch in self.branches(node) {
            let label = match branch.get("type") {
                Some(Value::String(kind)) if kind == "array" => match branch.get("items") {
                    Some(items) => match self.type_label(items) {
                        Some(item) => format!("array of {item}"),
                        None => "array".to_string(),
                    },
                    None => "array".to_string(),
                },
                Some(Value::String(kind)) if kind == "object" => "table".to_string(),
                Some(Value::String(kind)) => kind.clone(),
                Some(Value::Array(kinds)) => kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" or "),
                _ if branch.get("properties").is_some() => "table".to_string(),
                _ => continue,
            };
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
        (!labels.is_empty()).then(|| labels.join(" or "))
    }

    /// The values a scalar node allows (`enum`, `const`), in schema order.
    fn values(&self, node: &'a Value) -> Vec<&'a Value> {
        let mut out: Vec<&'a Value> = Vec::new();
        for branch in self.branches(node) {
            let found = branch
                .get("enum")
                .and_then(Value::as_array)
                .map(|values| values.iter().collect::<Vec<_>>())
                .or_else(|| branch.get("const").map(|value| vec![value]))
                .unwrap_or_default();
            for value in found {
                if !value.is_null() && !out.contains(&value) {
                    out.push(value);
                }
            }
        }
        out
    }

    fn is_table(&self, node: &'a Value) -> bool {
        self.branches(node).iter().any(|branch| is_object(branch))
    }

    fn is_array_of_tables(&self, node: &'a Value) -> bool {
        self.branches(node).iter().any(|branch| {
            is_array(branch)
                && branch
                    .get("items")
                    .is_some_and(|items| self.branches(items).iter().any(|item| is_object(item)))
        })
    }

    fn is_boolean(&self, node: &'a Value) -> bool {
        self.branches(node)
            .iter()
            .any(|branch| branch.get("type").and_then(Value::as_str) == Some("boolean"))
    }

    /// Hover text: title, type, description, allowed values, default.
    fn describe(&self, node: &'a Value, key: &str) -> String {
        let title = self
            .first(node, "title")
            .and_then(Value::as_str)
            .unwrap_or(key);
        let mut out = format!("**{title}**");
        if let Some(kind) = self.type_label(node) {
            out.push_str(&format!(" · `{kind}`"));
        }
        if let Some(description) = self.first(node, "description").and_then(Value::as_str) {
            out.push_str("\n\n");
            out.push_str(description);
        }
        let mut values = self.values(node);
        if values.is_empty() {
            if let Some(items) = self.branches(node).into_iter().find_map(|b| b.get("items")) {
                values = self.values(items);
            }
        }
        if !values.is_empty() {
            let listed: Vec<String> = values
                .iter()
                .map(|v| format!("`{}`", toml_value(v)))
                .collect();
            out.push_str(&format!("\n\nValues: {}", listed.join(", ")));
        }
        if let Some(default) = self.first(node, "default").filter(|value| !value.is_null()) {
            out.push_str(&format!("\n\nDefault: `{}`", toml_value(default)));
        }
        out
    }
}

fn is_null_type(node: &Value) -> bool {
    node.get("type").and_then(Value::as_str) == Some("null")
}

fn is_array(node: &Value) -> bool {
    node.get("type").and_then(Value::as_str) == Some("array")
}

fn is_object(node: &Value) -> bool {
    node.get("type").and_then(Value::as_str) == Some("object") || node.get("properties").is_some()
}

/// A JSON value written as TOML writes it.
fn toml_value(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(toml_value).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => format!(
            "{{ {} }}",
            map.iter()
                .map(|(key, value)| format!("{key} = {}", toml_value(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.to_string(),
    }
}

// --- Where the cursor is ------------------------------------------------------

/// What the cursor is on, read from the text around it: a buffer being typed
/// is rarely valid TOML.
#[derive(Debug, PartialEq, Eq)]
enum Cursor {
    /// Inside a `[table]` or `[[array]]` header, after `parent`.
    Header {
        array: bool,
        parent: Vec<String>,
    },
    /// Where a key goes, in `table`, after a dotted `parent`.
    Key {
        table: Vec<String>,
        parent: Vec<String>,
    },
    /// After `key =`, possibly inside an array or a string.
    Value {
        path: Vec<String>,
        in_array: bool,
        quoted: bool,
    },
    Nothing,
}

/// A `[header]` or `[[header]]` line's key path and whether it is an array.
fn header(line: &str) -> Option<(bool, Vec<String>)> {
    let line = line.trim_start();
    let (array, inner) = if let Some(rest) = line.strip_prefix("[[") {
        (true, rest.split("]]").next()?)
    } else {
        (false, line.strip_prefix('[')?.split(']').next()?)
    };
    Some((array, dotted(inner)))
}

/// `a."b.c".d` → `["a", "b.c", "d"]`.
fn dotted(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in text.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '.' => parts.push(std::mem::take(&mut current).trim().to_string()),
            None => current.push(ch),
        }
    }
    parts.push(current.trim().to_string());
    parts
}

/// The table the line holding `offset` belongs to: the last header above it.
fn table_at(text: &str, line_start: usize) -> (Vec<String>, usize) {
    let mut table = Vec::new();
    let mut body_start = 0;
    let mut position = 0;
    for line in text[..line_start].split_inclusive('\n') {
        if let Some((_, path)) = header(line) {
            table = path;
            body_start = position + line.len();
        }
        position += line.len();
    }
    (table, body_start)
}

/// Where `=` is on `line`, outside strings, before any comment.
fn equals(line: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '#' => return None,
            None if ch == '=' => return Some(index),
            None => {}
        }
    }
    None
}

fn cursor(text: &str, offset: usize) -> Cursor {
    let offset = floor_char_boundary(text, offset);
    let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let prefix = &text[line_start..offset];
    if prefix.trim_start().starts_with('[') {
        let inner = prefix.trim_start();
        if inner.contains(']') {
            return Cursor::Nothing;
        }
        let array = inner.starts_with("[[");
        let mut parent = dotted(inner.trim_start_matches('['));
        parent.pop();
        return Cursor::Header { array, parent };
    }
    let (table, body_start) = table_at(text, line_start);
    // Inside the table's body, read up to the cursor: open brackets and
    // strings, and the key of the value being written.
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut key: Option<String> = None;
    let mut statement_start = body_start;
    let mut in_comment = false;
    for (index, ch) in text[body_start..offset].char_indices() {
        let index = body_start + index;
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            } else {
                continue;
            }
        }
        match quote {
            Some(open) if ch == open => {
                quote = None;
                continue;
            }
            Some(_) if ch == '\n' => quote = None,
            Some(_) => continue,
            None => {}
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '#' => in_comment = true,
            '[' | '{' if key.is_some() => depth += 1,
            ']' | '}' => depth = (depth - 1).max(0),
            '=' if depth == 0 && key.is_none() => {
                key = Some(text[statement_start..index].trim().to_string());
            }
            '\n' if depth == 0 => {
                key = None;
                statement_start = index + 1;
            }
            _ => {}
        }
    }
    match key {
        Some(key) => {
            let mut path = table;
            path.extend(dotted(&key));
            Cursor::Value {
                path,
                in_array: depth > 0,
                quoted: quote.is_some(),
            }
        }
        None => {
            let mut parent = dotted(prefix.trim_start());
            parent.pop();
            Cursor::Key { table, parent }
        }
    }
}

fn floor_char_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// Keys already set in the table whose body starts at `body_start`.
fn present_keys(text: &str, body_start: usize) -> Vec<String> {
    let mut keys = Vec::new();
    for line in text[body_start..].lines() {
        if header(line).is_some() {
            break;
        }
        if let Some(index) = equals(line) {
            if let Some(first) = dotted(&line[..index]).into_iter().next() {
                if !first.is_empty() {
                    keys.push(first);
                }
            }
        }
    }
    keys
}

/// Hover on a key or a table header in the configuration file at `path`:
/// its schema's title, type, description, allowed values and default. Never
/// the value in the buffer.
pub fn configuration_hover(path: &str, text: &str, offset: usize) -> Option<String> {
    let relative = configuration_path(path)?;
    let schemas = installed_schemas()?;
    let walker = Walker {
        root: schemas.for_file(&relative)?,
    };
    let offset = floor_char_boundary(text, offset);
    let line_start = text[..offset].rfind('\n').map_or(0, |index| index + 1);
    let line_end = text[offset..]
        .find('\n')
        .map_or(text.len(), |index| offset + index);
    let line = &text[line_start..line_end];
    let column = offset - line_start;
    let path: Vec<String> = if let Some((_, segments)) = header(line) {
        segments
    } else if let Some(index) = equals(line) {
        let (table, _) = table_at(text, line_start);
        let key = &line[..index];
        let mut segments = dotted(key);
        if column <= index {
            // The segment under the cursor and the ones before it.
            let before = dotted(&key[..column.min(key.len())]).len();
            segments.truncate(before.max(1));
        }
        table.into_iter().chain(segments).collect()
    } else {
        match cursor(text, offset) {
            Cursor::Value { path, .. } => path,
            _ => return None,
        }
    };
    let key = path.last()?.clone();
    let node = walker.at(&path)?;
    Some(walker.describe(node, &key))
}

/// Completion in the configuration file at `path`: keys of the table at the
/// cursor (not those already set), table names in a header, and allowed
/// values after `=`.
pub fn configuration_completions(path: &str, text: &str, offset: usize) -> Vec<CompletionItem> {
    let Some(relative) = configuration_path(path) else {
        return Vec::new();
    };
    let Some(schemas) = installed_schemas() else {
        return Vec::new();
    };
    let Some(root) = schemas.for_file(&relative) else {
        return Vec::new();
    };
    let walker = Walker { root };
    let item = |name: &str, node: &Value| {
        let mut item = CompletionItem::new(name, "property");
        if let Some(kind) = walker.type_label(node) {
            item = item.with_detail(kind);
        }
        if let Some(description) = walker.first(node, "description").and_then(Value::as_str) {
            item = item.with_docs(description);
        }
        item
    };
    match cursor(text, offset) {
        Cursor::Header { array, parent } => {
            let Some(node) = walker.at(&parent) else {
                return Vec::new();
            };
            walker
                .properties(node)
                .into_iter()
                .filter(|(_, schema)| {
                    if array {
                        walker.is_array_of_tables(schema)
                    } else {
                        walker.is_table(schema)
                    }
                })
                .map(|(name, schema)| item(name, schema))
                .collect()
        }
        Cursor::Key { table, parent } => {
            let line_start = text[..floor_char_boundary(text, offset)]
                .rfind('\n')
                .map_or(0, |index| index + 1);
            let (_, body_start) = table_at(text, line_start);
            let present = if parent.is_empty() {
                present_keys(text, body_start)
            } else {
                Vec::new()
            };
            let path: Vec<String> = table.into_iter().chain(parent).collect();
            let Some(node) = walker.at(&path) else {
                return Vec::new();
            };
            walker
                .properties(node)
                .into_iter()
                .filter(|(name, schema)| {
                    !present.iter().any(|key| key == name)
                        && !walker.is_table(schema)
                        && !walker.is_array_of_tables(schema)
                })
                .map(|(name, schema)| item(name, schema))
                .collect()
        }
        Cursor::Value {
            path,
            in_array,
            quoted,
        } => {
            let Some(mut node) = walker.at(&path) else {
                return Vec::new();
            };
            if in_array {
                match walker
                    .branches(node)
                    .into_iter()
                    .find_map(|b| b.get("items"))
                {
                    Some(items) => node = items,
                    None => return Vec::new(),
                }
            }
            let mut values: Vec<String> = walker
                .values(node)
                .into_iter()
                .map(|value| match value {
                    Value::String(text) if quoted => text.clone(),
                    other => toml_value(other),
                })
                .collect();
            if values.is_empty() && !in_array && walker.is_boolean(node) {
                values = vec!["true".to_string(), "false".to_string()];
            }
            let detail = walker.type_label(node);
            let docs = walker
                .first(node, "description")
                .or_else(|| {
                    walker
                        .at(&path)
                        .and_then(|field| walker.first(field, "description"))
                })
                .and_then(Value::as_str);
            values
                .into_iter()
                .map(|value| {
                    let mut item = CompletionItem::new(value, "enum");
                    if let Some(detail) = &detail {
                        item = item.with_detail(detail.clone());
                    }
                    if let Some(docs) = docs {
                        item = item.with_docs(docs);
                    }
                    item
                })
                .collect()
        }
        Cursor::Nothing => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_paths_are_toml_files_under_the_directory() {
        assert_eq!(
            configuration_path("/w/.opentide/configurations/sharing.toml").as_deref(),
            Some("sharing.toml")
        );
        assert_eq!(
            configuration_path("C:\\w\\.opentide\\configurations\\platforms\\sentinel.toml")
                .as_deref(),
            Some("platforms/sentinel.toml")
        );
        assert_eq!(
            configuration_path(".opentide/configurations/deployment.toml").as_deref(),
            Some("deployment.toml")
        );
        assert_eq!(configuration_path("/w/Cargo.toml"), None);
        assert_eq!(
            configuration_path("/w/.opentide/configurations/notes.md"),
            None
        );
        assert_eq!(
            configuration_path("/w/.opentide/configurations/.toml"),
            None
        );
        assert_eq!(configuration_path("/w/.opentide/lsp/x.toml"), None);
    }

    #[test]
    fn dotted_keys_split_outside_quotes() {
        assert_eq!(dotted("a.b"), ["a", "b"]);
        assert_eq!(dotted(" a . \"b.c\" .d"), ["a", "b.c", "d"]);
        assert_eq!(dotted("'x.y'"), ["x.y"]);
    }

    #[test]
    fn paths_display_list_items_by_index() {
        let path = ["misp", "0", "max_tlp"].map(String::from);
        assert_eq!(display_path(&path), "misp[0].max_tlp");
    }

    #[test]
    fn the_cursor_is_read_from_the_text_around_it() {
        let text = "[[misp]]\nname = \"a\"\nmax_tlp = \"\nobject_types = [\"threat\", \n[pro";
        let at = |needle: &str| text.find(needle).unwrap() + needle.len();
        assert_eq!(
            cursor(text, at("name")),
            Cursor::Key {
                table: vec!["misp".into()],
                parent: vec![]
            }
        );
        assert_eq!(
            cursor(text, at("max_tlp = \"")),
            Cursor::Value {
                path: vec!["misp".into(), "max_tlp".into()],
                in_array: false,
                quoted: true
            }
        );
        assert_eq!(
            cursor(text, at("\"threat\", ")),
            Cursor::Value {
                path: vec!["misp".into(), "object_types".into()],
                in_array: true,
                quoted: false
            }
        );
        assert_eq!(
            cursor(text, text.len()),
            Cursor::Header {
                array: false,
                parent: vec![]
            }
        );
    }

    #[test]
    fn a_multi_line_array_value_is_still_a_value() {
        let text = "[[misp]]\nobject_types = [\n  \"threat\",\n  ";
        assert_eq!(
            cursor(text, text.len()),
            Cursor::Value {
                path: vec!["misp".into(), "object_types".into()],
                in_array: true,
                quoted: false
            }
        );
    }

    #[test]
    fn locate_finds_keys_headers_and_prefixes() {
        let text = "[promotion]\nenabeld = true\n\n[[misp]]\nname = \"a\"\n\n[[misp]]\nname = \"b\"\nmax_tlp = \"white\"\ninline = { x = 1 }\nlist = [1, 2]\n";
        let document = ImDocument::parse(text).unwrap();
        let span = |path: &[&str]| {
            let path: Vec<String> = path.iter().map(|s| s.to_string()).collect();
            let (span, resolved) = locate(document.as_table(), &path);
            (span.map(|s| &text[s]), resolved)
        };
        assert_eq!(span(&["promotion", "enabeld"]), (Some("enabeld"), true));
        assert_eq!(span(&["misp", "1", "max_tlp"]), (Some("max_tlp"), true));
        assert_eq!(span(&["misp", "1", "inline", "x"]), (Some("x"), true));
        assert_eq!(span(&["misp", "1", "list", "1"]), (Some("2"), true));
        // A missing key: the entry it belongs to.
        let (header, resolved) = span(&["misp", "0", "url"]);
        assert!(!resolved);
        assert!(header.is_some_and(|h| h.contains("[[misp]]")), "{header:?}");
        assert_eq!(span(&[]), (None, true));
    }
}
