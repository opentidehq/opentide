//! The text of a new object (`cli/services/new.py`): the generated template,
//! line by line. Required keys are uncommented and filled in place, every
//! other line is kept as the template writes it, so the comments that list
//! the optional keys stay in the new file. YAML is never parsed and written
//! back: the template's text is the file's.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

/// A field's path, its keys from the root (list indexes are not part of it).
pub type FieldPath = Vec<String>;

/// Trailing comment on every line whose value `new` invented: `opentide lint`
/// reports each marked line as a `placeholder` finding.
pub const PLACEHOLDER_MARKER: &str = "# opentide:placeholder";

/// What an empty free-text value becomes: a valid string nobody will
/// mistake for content.
const TEXT_PLACEHOLDER: &str = "...";

/// Words YAML could read as something else than the string.
const YAML_RESERVED: [&str; 10] = [
    "true", "false", "null", "yes", "no", "on", "off", "y", "n", "~",
];

#[expect(
    clippy::expect_used,
    reason = "literal patterns, compiled by every unit test"
)]
fn pattern(cell: &'static OnceLock<Regex>, text: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(text).expect("a valid pattern"))
}

fn line_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^(?P<indent> *)(?P<hash>#?)(?P<dash>- ?)?(?P<rest>.*)$",
    )
}

fn key_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^(?P<key>[A-Za-z_][\w.\-]*):(?:\s(?P<value>.*))?$")
}

fn plain_scalar() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"^[A-Za-z0-9_./:+-][A-Za-z0-9_./:+ -]*$")
}

/// A value to write.
#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    /// Text.
    Text(String),
    /// `true` or `false`.
    Bool(bool),
    /// A whole number.
    Int(i64),
    /// A date, written as `YYYY-MM-DD`.
    Date(String),
    /// Several values, one item each.
    List(Vec<Scalar>),
}

impl Scalar {
    /// A JSON Schema enum value as a value to write.
    pub fn from_json(value: &Value) -> Scalar {
        match value {
            Value::Bool(flag) => Scalar::Bool(*flag),
            Value::Number(number) => number
                .as_i64()
                .map_or_else(|| Scalar::Text(number.to_string()), Scalar::Int),
            Value::String(text) => Scalar::Text(text.clone()),
            Value::Null => Scalar::Text("null".to_owned()),
            other => Scalar::Text(other.to_string()),
        }
    }
}

/// `value` as a YAML scalar on one line: plain where YAML reads it back as
/// the same string, else a JSON string (a YAML double-quoted scalar).
pub fn scalar_text(value: &Scalar) -> String {
    match value {
        Scalar::Bool(flag) => flag.to_string(),
        Scalar::Int(number) => number.to_string(),
        Scalar::Date(date) => date.clone(),
        Scalar::List(items) => items.first().map_or_else(String::new, scalar_text),
        Scalar::Text(text) => {
            if plain_scalar().is_match(text)
                && !YAML_RESERVED.contains(&text.to_lowercase().as_str())
                && !text.ends_with(' ')
                && !text.starts_with('-')
                && reads_back(text)
            {
                text.clone()
            } else {
                serde_json::to_string(text).unwrap_or_default()
            }
        }
    }
}

/// Whether `k: <text>` reads back as the string `text` (YAML 1.2, the
/// workspace's reader).
fn reads_back(text: &str) -> bool {
    use opentide_schema::node::{Value as NodeValue, load};
    let Ok(document) = load(&format!("k: {text}")) else {
        return false;
    };
    let Some(root) = document.root() else {
        return false;
    };
    match root.get("k").map(|node| &node.value) {
        Some(NodeValue::Str(found)) => found == text,
        _ => false,
    }
}

/// What a model field holds, `Option` unwrapped.
#[derive(Debug, Clone, Default)]
pub struct Shape {
    /// A list of values (or of models).
    pub list: bool,
    /// The model a field holds, as its schema.
    pub model: Option<Value>,
    /// The model a list holds, as its schema.
    pub item_model: Option<Value>,
    /// The values a `Literal` allows, in order.
    pub choices: Vec<Value>,
    /// A boolean.
    pub is_bool: bool,
    /// A whole number.
    pub is_int: bool,
}

impl Shape {
    fn is_model(&self) -> bool {
        self.model.is_some()
    }

    fn is_scalar(&self) -> bool {
        !self.list && self.model.is_none()
    }
}

/// A model's schema (a revision's, from `schemars`), for its fields.
pub struct Model<'s> {
    root: &'s Value,
}

impl<'s> Model<'s> {
    /// The model whose root schema is `root`.
    pub fn new(root: &'s Value) -> Model<'s> {
        Model { root }
    }

    fn deref(&self, node: &'s Value) -> &'s Value {
        let mut current = node;
        for _ in 0..16 {
            let Some(name) = current
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
            else {
                break;
            };
            match self.root.get("$defs").and_then(|defs| defs.get(name)) {
                Some(target) => current = target,
                None => break,
            }
        }
        current
    }

    /// The fields of the model schema `node`: key, whether validation
    /// requires it, and what it holds.
    pub fn fields(&self, node: &'s Value) -> Vec<(String, bool, Shape)> {
        let node = self.deref(node);
        let required: BTreeSet<&str> = node
            .get("required")
            .and_then(Value::as_array)
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let Some(Value::Object(properties)) = node.get("properties") else {
            return Vec::new();
        };
        properties
            .iter()
            .map(|(key, spec)| {
                (
                    key.clone(),
                    required.contains(key.as_str()),
                    self.shape(spec),
                )
            })
            .collect()
    }

    fn has_properties(node: &Value) -> bool {
        node.get("properties")
            .and_then(Value::as_object)
            .is_some_and(|map| !map.is_empty())
    }

    /// What a field holds (`_shape`): `Option` unwrapped; a union of several
    /// types is a plain value.
    pub fn shape(&self, spec: &'s Value) -> Shape {
        let mut node = spec;
        if let Some(Value::Array(branches)) = node.get("anyOf") {
            let others: Vec<&Value> = branches
                .iter()
                .filter(|branch| branch.get("type").and_then(Value::as_str) != Some("null"))
                .collect();
            match others.as_slice() {
                [one] => node = one,
                _ => return Shape::default(),
            }
        }
        let referred = node.get("$ref").is_some();
        let target = self.deref(node);
        if Self::has_properties(target) {
            return Shape {
                model: Some(target.clone()),
                ..Shape::default()
            };
        }
        if target.get("anyOf").is_some() && target.get("type").is_none() {
            // A union of its own (`str | list[str]`).
            return Shape::default();
        }
        let types = types(target);
        if types.contains(&"array") {
            let item_model = target
                .get("items")
                .map(|items| self.deref(items))
                .filter(|items| Self::has_properties(items))
                .cloned();
            return Shape {
                list: true,
                item_model,
                ..Shape::default()
            };
        }
        let choices = if referred {
            // A Rust enum is a Python `Enum`: the template's schema offers
            // its values, not the model.
            Vec::new()
        } else {
            target
                .get("enum")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter(|value| !value.is_null())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        Shape {
            choices,
            is_bool: types.contains(&"boolean"),
            is_int: types.contains(&"integer"),
            ..Shape::default()
        }
    }
}

fn types(node: &Value) -> Vec<&str> {
    match node.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .filter(|kind| *kind != "null")
            .collect(),
        _ => Vec::new(),
    }
}

/// Every required field path of the model `node`, and the `wanted`
/// optional ones (`collect_fields`). A list of models contributes its items'
/// fields under the list's own path.
pub fn collect_fields(
    model: &Model<'_>,
    node: &Value,
    wanted: &[FieldPath],
    prefix: &[String],
) -> HashMap<FieldPath, Shape> {
    let mut fields = HashMap::new();
    for (key, required, shape) in model.fields(node) {
        let mut path = prefix.to_vec();
        path.push(key);
        let is_wanted = wanted.iter().any(|item| item.starts_with(&path));
        if !required && !is_wanted {
            continue;
        }
        let child = shape.model.clone().or_else(|| shape.item_model.clone());
        fields.insert(path.clone(), shape);
        if let Some(child) = child {
            fields.extend(collect_fields(model, &child, wanted, &path));
        }
    }
    fields
}

// --- the generated schema's choices ------------------------------------------------------

/// `node` and every branch it composes (`$ref`, `anyOf`, `oneOf`, `allOf`),
/// in breadth-first order.
fn composed<'s>(node: Option<&'s Value>, defs: &'s Map<String, Value>) -> Vec<&'s Value> {
    let mut found = Vec::new();
    let mut pending: std::collections::VecDeque<&Value> = node.into_iter().collect();
    let mut steps = 0;
    while let Some(current) = pending.pop_front() {
        steps += 1;
        if steps > 10_000 {
            break;
        }
        if !current.is_object() {
            continue;
        }
        found.push(current);
        if let Some(name) = current
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|reference| reference.strip_prefix("#/$defs/"))
            && let Some(target) = defs.get(name)
        {
            pending.push_back(target);
        }
        for keyword in ["anyOf", "oneOf", "allOf"] {
            if let Some(Value::Array(branches)) = current.get(keyword) {
                pending.extend(branches.iter());
            }
        }
    }
    found
}

/// The `enum` the generated JSON Schema gives the field at `path`, items
/// included (`schema_choices`).
pub fn schema_choices(schema: &Value, path: &[String]) -> Vec<Value> {
    let empty = Map::new();
    let defs = schema
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut nodes = composed(Some(schema), defs);
    for key in path {
        let mut children = Vec::new();
        for node in &nodes {
            let mut candidates = vec![*node];
            candidates.extend(composed(node.get("items"), defs));
            for candidate in candidates {
                if let Some(child) = candidate.get("properties").and_then(|map| map.get(key)) {
                    children.extend(composed(Some(child), defs));
                }
            }
        }
        nodes = children;
        if nodes.is_empty() {
            return Vec::new();
        }
    }
    for node in &nodes {
        let mut candidates = vec![*node];
        candidates.extend(composed(node.get("items"), defs));
        for candidate in candidates {
            if let Some(Value::Array(values)) = candidate.get("enum")
                && !values.is_empty()
            {
                return values.clone();
            }
        }
    }
    Vec::new()
}

// --- the template's lines ----------------------------------------------------------------

/// What a template line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// `key: value`.
    Key,
    /// A bare `- value`.
    Item,
    /// Anything else (block text).
    Text,
}

/// A non-blank template line with its YAML path, commented or not.
#[derive(Debug, Clone)]
struct Line {
    index: usize,
    indent: usize,
    commented: bool,
    role: Role,
    path: FieldPath,
    value: String,
    /// Column of the key or item text, after the `#` and the dash.
    column: usize,
}

/// Each non-blank line of `lines` with its YAML path (`index_template`).
/// Template comments hug the key (`  #author:`), so a commented line has the
/// indentation it would have uncommented.
fn index_template(lines: &[String]) -> Vec<Line> {
    let mut entries = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let Some(captures) = line_pattern().captures(raw) else {
            continue;
        };
        let indent = captures.name("indent").map_or(0, |m| m.as_str().len());
        let hash = captures.name("hash").map_or("", |m| m.as_str());
        let dash = captures.name("dash").map(|m| m.as_str());
        let rest = captures.name("rest").map_or("", |m| m.as_str());
        let commented = !hash.is_empty();
        let column = indent + hash.len() + dash.map_or(0, str::len);
        if let Some(key) = key_pattern().captures(rest) {
            let name = key.name("key").map_or("", |m| m.as_str()).to_owned();
            let key_indent = if dash.is_some() { indent + 2 } else { indent };
            while stack.last().is_some_and(|(at, _)| *at >= key_indent) {
                stack.pop();
            }
            let mut path: FieldPath = stack.iter().map(|(_, name)| name.clone()).collect();
            path.push(name.clone());
            stack.push((key_indent, name));
            entries.push(Line {
                index,
                indent,
                commented,
                role: Role::Key,
                path,
                value: key
                    .name("value")
                    .map_or("", |m| m.as_str())
                    .trim()
                    .to_owned(),
                column,
            });
            continue;
        }
        while stack.last().is_some_and(|(at, _)| *at >= indent) {
            stack.pop();
        }
        let path: FieldPath = stack.iter().map(|(_, name)| name.clone()).collect();
        entries.push(Line {
            index,
            indent,
            commented,
            role: if dash.is_some() {
                Role::Item
            } else {
                Role::Text
            },
            path,
            value: rest.trim().to_owned(),
            column,
        });
    }
    entries
}

/// A filled template: its text and the dotted paths of its placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scaffold {
    /// The new file's text.
    pub text: String,
    /// The paths whose value `new` invented, in the file's order.
    pub placeholders: Vec<String>,
}

/// What [`fill_template`] fills a template with.
pub struct Fill<'a> {
    /// The fields the object needs (required, and the wanted optional ones).
    pub fields: &'a HashMap<FieldPath, Shape>,
    /// The known answers (name, UUID, dates, author, references).
    pub values: &'a HashMap<FieldPath, Scalar>,
    /// The generated JSON Schema, for the values a field allows.
    pub schema: &'a Value,
    /// The model, for the fields of a block whose keys are all optional.
    pub model: &'a Model<'a>,
    /// Answers that are stand-ins too.
    pub marked: &'a HashSet<FieldPath>,
    /// Mints a UUID for a `uuid` key without an answer.
    pub make_uuid: &'a dyn Fn() -> String,
}

/// Defaults that are a choice, not a stand-in: TLP starts at `amber` so a
/// new object is never cleared for sharing by accident.
fn default_for(leaf: &str) -> Option<Scalar> {
    match leaf {
        "tlp" => Some(Scalar::Text("amber".to_owned())),
        "version" => Some(Scalar::Int(1)),
        _ => None,
    }
}

fn json_matches(value: &Value, scalar: &Scalar) -> bool {
    match (value, scalar) {
        (Value::String(text), Scalar::Text(other)) => text == other,
        (Value::Number(number), Scalar::Int(other)) => number.as_i64() == Some(*other),
        (Value::Bool(flag), Scalar::Bool(other)) => flag == other,
        _ => false,
    }
}

/// Uncomments the keys in `fill.fields`, fills their values, keeps every
/// other line (`fill_template`). A required field with no answer gets a
/// placeholder; every placeholder line ends in [`PLACEHOLDER_MARKER`].
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the template, as the oracle's, kept in one place"
)]
pub fn fill_template(template: &str, fill: &Fill<'_>) -> Scaffold {
    let mut lines: Vec<String> = template.lines().map(str::to_owned).collect();
    let mut entries = index_template(&lines);
    let live_keys: HashSet<FieldPath> = entries
        .iter()
        .filter(|entry| entry.role == Role::Key)
        .map(|entry| entry.path.clone())
        .collect();
    let mut placeholders: Vec<String> = Vec::new();
    let mut replacements: HashMap<usize, String> = HashMap::new();
    let mut marked_lines: BTreeSet<usize> = BTreeSet::new();
    let fields = fill.fields;

    let live = |entry: &Line| match entry.role {
        Role::Key => fields.contains_key(&entry.path),
        _ => fields.contains_key(&entry.path) && live_keys.contains(&entry.path),
    };
    let uncomment = |lines: &mut Vec<String>, entry: &mut Line| {
        if entry.commented {
            let raw = &lines[entry.index];
            let text = format!("{}{}", &raw[..entry.indent], &raw[entry.indent + 1..]);
            lines[entry.index] = text;
            entry.commented = false;
            entry.column -= 1;
        }
    };

    // Uncomment the keys this object needs, with their items and block text.
    for entry in &mut entries {
        if entry.commented && live(entry) {
            uncomment(&mut lines, entry);
        }
    }

    let below = |entries: &[Line], at: usize| -> Vec<usize> {
        let entry = &entries[at];
        let mut found = Vec::new();
        for (position, other) in entries.iter().enumerate() {
            if other.index <= entry.index {
                continue;
            }
            if other.indent <= entry.indent {
                break;
            }
            found.push(position);
        }
        found
    };

    // A key the template writes live although this object neither requires
    // nor answers it is commented back out: left empty it loads as null.
    for at in 0..entries.len() {
        let entry = &entries[at];
        if entry.role != Role::Key || entry.commented || fields.contains_key(&entry.path) {
            continue;
        }
        if entry.path.len() > 1
            && !fields.contains_key(&entry.path[..entry.path.len() - 1].to_vec())
        {
            continue;
        }
        let mut block = vec![at];
        block.extend(below(&entries, at));
        if block
            .iter()
            .any(|position| !entries[*position].value.is_empty())
        {
            continue;
        }
        for position in block {
            let other = &mut entries[position];
            if !other.commented {
                let raw = &lines[other.index];
                lines[other.index] = format!("{}#{}", &raw[..other.indent], &raw[other.indent..]);
                other.commented = true;
                other.column += 1;
            }
        }
    }

    let items_of = |entries: &[Line], at: usize| -> Vec<usize> {
        let entry = &entries[at];
        let mut found = Vec::new();
        for (position, other) in entries.iter().enumerate() {
            if other.index <= entry.index {
                continue;
            }
            if other.indent <= entry.indent
                && !(other.role == Role::Item && other.path == entry.path)
            {
                break;
            }
            if other.role == Role::Item && other.path == entry.path && !other.commented {
                found.push(position);
            }
        }
        found
    };
    let children = |entries: &[Line], at: usize| -> Vec<usize> {
        let entry = &entries[at];
        let mut found = Vec::new();
        for (position, other) in entries.iter().enumerate() {
            if other.index <= entry.index {
                continue;
            }
            if other.indent <= entry.indent {
                break;
            }
            if other.role == Role::Key && other.path[..other.path.len() - 1] == entry.path[..] {
                found.push(position);
            }
        }
        found
    };
    let set_value = |lines: &[String],
                     entries: &[Line],
                     replacements: &mut HashMap<usize, String>,
                     at: usize,
                     value: &Scalar| {
        let entry = &entries[at];
        let head = &lines[entry.index][..entry.column];
        if entry.role == Role::Key {
            let leaf = entry.path.last().map_or("", String::as_str);
            replacements.insert(entry.index, format!("{head}{leaf}: {}", scalar_text(value)));
            // A scalar replaces the list form the template shows for a
            // `str | list[str]` key: drop its item lines.
            for item in items_of(entries, at) {
                replacements.insert(entries[item].index, String::new());
            }
        } else {
            replacements.insert(entry.index, format!("{head}{}", scalar_text(value)));
        }
    };
    let choose = |path: &FieldPath, shape: &Shape| -> (Scalar, bool) {
        let leaf = path.last().map_or("", String::as_str);
        if let Some(default) = default_for(leaf) {
            let choices = schema_choices(fill.schema, path);
            if choices.is_empty() || choices.iter().any(|choice| json_matches(choice, &default)) {
                return (default, false);
            }
            return (Scalar::from_json(&choices[0]), true);
        }
        if leaf == "uuid" {
            return (Scalar::Text((fill.make_uuid)()), false);
        }
        if let Some(first) = shape.choices.first() {
            return (Scalar::from_json(first), true);
        }
        if shape.is_bool {
            return (Scalar::Bool(false), true);
        }
        if shape.is_int {
            return (Scalar::Int(1), true);
        }
        if let Some(first) = schema_choices(fill.schema, path).first() {
            return (Scalar::from_json(first), true);
        }
        (Scalar::Text(TEXT_PLACEHOLDER.to_owned()), true)
    };

    for at in 0..entries.len() {
        let (role, commented, path) = {
            let entry = &entries[at];
            (entry.role, entry.commented, entry.path.clone())
        };
        if role != Role::Key || commented {
            continue;
        }
        let Some(shape) = fields.get(&path) else {
            continue;
        };
        let given = fill.values.get(&path);
        if shape.is_model() {
            if !entries[at].value.is_empty()
                || fields
                    .keys()
                    .any(|other| other.len() == path.len() + 1 && other.starts_with(&path))
            {
                continue;
            }
            // A required block whose keys are all optional: keep the ones the
            // template shows with a value (their defaults), else fill one key.
            let defaults: Vec<usize> = children(&entries, at)
                .into_iter()
                .filter(|child| !entries[*child].value.is_empty() && entries[*child].value != "|")
                .collect();
            for child in &defaults {
                let mut entry = entries[*child].clone();
                uncomment(&mut lines, &mut entry);
                entries[*child] = entry;
            }
            let mut filled = !defaults.is_empty();
            if !filled {
                // `key: {}` above commented keys breaks the YAML as soon as
                // one is uncommented, so the block gets one live, marked key.
                let infos: HashMap<String, Shape> = shape
                    .model
                    .as_ref()
                    .map(|model| {
                        fill.model
                            .fields(model)
                            .into_iter()
                            .map(|(key, _, shape)| (key, shape))
                            .collect()
                    })
                    .unwrap_or_default();
                for child in children(&entries, at) {
                    let leaf = entries[child].path.last().cloned().unwrap_or_default();
                    let Some(info) = infos.get(&leaf) else {
                        continue;
                    };
                    if entries[child].value == "|" || !info.is_scalar() {
                        continue;
                    }
                    let mut entry = entries[child].clone();
                    uncomment(&mut lines, &mut entry);
                    entries[child] = entry;
                    if entries[child].value.is_empty() {
                        let (value, _) = choose(&entries[child].path, info);
                        set_value(&lines, &entries, &mut replacements, child, &value);
                    }
                    placeholders.push(entries[child].path.join("."));
                    marked_lines.insert(entries[child].index);
                    filled = true;
                    break;
                }
            }
            if !filled {
                let index = entries[at].index;
                replacements.insert(
                    index,
                    format!(
                        "{} {{}}  # delete {{}} before uncommenting a key",
                        lines[index].trim_end()
                    ),
                );
            }
            continue;
        }
        if shape.list {
            if shape.item_model.is_some() {
                continue;
            }
            let items = items_of(&entries, at);
            let mut invented = fill.marked.contains(&path);
            let answers: Vec<Scalar> = if let Some(given) = given {
                match given {
                    Scalar::List(values) => values.clone(),
                    one => vec![one.clone()],
                }
            } else {
                if items
                    .first()
                    .is_some_and(|item| !entries[*item].value.is_empty())
                {
                    continue;
                }
                let (answer, made_up) = choose(&path, shape);
                invented = made_up;
                vec![answer]
            };
            if invented {
                placeholders.push(path.join("."));
            }
            let indent = " ".repeat(entries[at].indent + 2);
            let suffix = if invented {
                format!("  {PLACEHOLDER_MARKER}")
            } else {
                String::new()
            };
            let rendered = answers
                .iter()
                .map(|answer| format!("{indent}- {}{suffix}", scalar_text(answer)))
                .collect::<Vec<_>>()
                .join("\n");
            if let Some((first, rest)) = items.split_first() {
                replacements.insert(entries[*first].index, rendered);
                for extra in rest {
                    replacements.insert(entries[*extra].index, String::new());
                }
            } else {
                let index = entries[at].index;
                replacements.insert(index, format!("{}\n{rendered}", lines[index].trim_end()));
            }
            continue;
        }
        if let Some(given) = given {
            set_value(&lines, &entries, &mut replacements, at, given);
            if fill.marked.contains(&path) {
                placeholders.push(path.join("."));
                marked_lines.insert(entries[at].index);
            }
            continue;
        }
        if entries[at].value == "|" {
            let index = entries[at].index;
            let text: Vec<&Line> = entries
                .iter()
                .filter(|other| {
                    other.role == Role::Text && other.path == path && other.index > index
                })
                .collect();
            if text.iter().all(|other| other.value == TEXT_PLACEHOLDER) {
                placeholders.push(path.join("."));
                marked_lines.insert(index);
            }
            continue;
        }
        if !entries[at].value.is_empty() && path.last().map(String::as_str) != Some("uuid") {
            continue;
        }
        let (answer, invented) = choose(&path, shape);
        set_value(&lines, &entries, &mut replacements, at, &answer);
        if invented {
            placeholders.push(path.join("."));
            marked_lines.insert(entries[at].index);
        }
    }

    let mut output: Vec<String> = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        let text = replacements.get(&index).unwrap_or(raw);
        if replacements.contains_key(&index) && text.is_empty() {
            continue;
        }
        if marked_lines.contains(&index) {
            output.push(format!("{}  {PLACEHOLDER_MARKER}", text.trim_end()));
        } else {
            output.push(text.clone());
        }
    }
    Scaffold {
        text: format!("{}\n", output.join("\n")),
        placeholders,
    }
}

/// Drops the commented `configurations` blocks of every platform not in
/// `platforms` (`keep_platform_blocks`): a new rule keeps its own blocks and
/// one comment that points at `pointer`, the template, for the others.
pub fn keep_platform_blocks(text: &str, platforms: &[String], pointer: &str) -> String {
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let entries = index_template(&lines);
    let dropped: HashSet<usize> = entries
        .iter()
        .filter(|entry| {
            entry.path.len() >= 2
                && entry.path[0] == "configurations"
                && !platforms.contains(&entry.path[1])
        })
        .map(|entry| entry.index)
        .collect();
    if dropped.is_empty() {
        return text.to_owned();
    }
    let header = entries
        .iter()
        .find(|entry| entry.role == Role::Key && entry.path == ["configurations"]);
    let mut output: Vec<String> = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        if dropped.contains(&index)
            || (raw.trim().is_empty() && output.last().is_some_and(|last| last.trim().is_empty()))
        {
            continue;
        }
        output.push(raw.clone());
        if let Some(header) = header
            && index == header.index
        {
            output.push(format!(
                "{}# Other platforms: copy a block from {pointer}",
                " ".repeat(header.indent + 2)
            ));
        }
    }
    format!("{}\n", output.join("\n").trim_end_matches('\n'))
}

/// The `metadata.schema` the template carries (`rule::1.0`).
pub fn template_schema_id(template: &str) -> Option<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    pattern(&CELL, r"(?m)^\s+schema:\s*([\w:.]+)\s*$")
        .captures(template)
        .and_then(|captures| captures.get(1))
        .map(|found| found.as_str().to_owned())
}

#[cfg(test)]
mod tests;
