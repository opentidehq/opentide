//! YAML object skeletons (`pydantic_skeleton.py`), rendered from a model's
//! JSON Schema (schemars) and its field order ([`super::models`]).
//!
//! Required fields are live YAML; an optional field is the same YAML with
//! `#` hugging each line's first token, and the optional fields inside it are
//! not commented again. Hidden fields (`tide.template.hide`) and paths are
//! left out; `tide.template.required` overrides whether a field is required;
//! `tide.template.spacer` puts a blank line before a field;
//! `tide.template.multiline` (and the names `description`, `query`,
//! `analysis` and `sighting`) render `key: |` with `...` under it. Placeholders
//! are typed (`YYYY-MM-DD`, `https://`, `3`, `false`), never YAML `null`.

use schemars::JsonSchema;
use serde_json::{Map, Value};

use super::models::{INTEGER_KEYED, Model, model_named};
use crate::keys;
use crate::revisions::REVISIONS;

/// How deep models nest before the renderer stops (`_MAX_DEPTH`).
const MAX_DEPTH: usize = 24;

const MULTILINE_NAMES: &[&str] = &["description", "query", "analysis", "sighting"];
const DATE_NAMES: &[&str] = &["created", "modified", "reviewed"];
const URI_NAMES: &[&str] = &["link", "url", "uri", "href"];
const YAML_RESERVED: &[&str] = &[
    "true", "false", "null", "yes", "no", "on", "off", "y", "n", "~",
];

/// Why a template could not be rendered: a schema the renderer does not
/// know how to walk. A bug, never a user error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot render a template: {0}")]
pub struct TemplateError(pub String);

/// The options of one render.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `metadata` keys rendered live although the model makes them
    /// optional (`lint.toml` `[metadata].required`).
    pub required_metadata: Vec<String>,
    /// The indentation of the model's own keys (2 for a platform block).
    pub indent: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            required_metadata: crate::configuration::lint::DEFAULT_REQUIRED_METADATA
                .iter()
                .map(|key| (*key).to_owned())
                .collect(),
            indent: 0,
        }
    }
}

/// `T`'s template.
pub fn render<T: JsonSchema>(options: &Options) -> Result<String, TemplateError> {
    let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let root = generator.into_root_schema_for::<T>().to_value();
    render_schema(&root, &T::schema_name(), options)
}

/// The template of a root schema (with its `$defs`) of model `name`.
pub fn render_schema(root: &Value, name: &str, options: &Options) -> Result<String, TemplateError> {
    let empty = Map::new();
    let defs = root
        .get("$defs")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let walker = Walker {
        defs,
        required_metadata: &options.required_metadata,
    };
    let state = State {
        schema_id: None,
        comment_optionals: true,
    };
    let lines = walker.model(name, root, options.indent, &state, 0)?;
    let mut text = lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    Ok(text)
}

#[derive(Debug, Clone)]
struct State {
    schema_id: Option<&'static str>,
    comment_optionals: bool,
}

/// A field's type, once optional and `$ref` are seen through.
enum Core<'s> {
    /// A nested model, by schema name.
    Model(String, &'s Value),
    /// A list of `items`.
    List(Option<&'s Value>),
    /// A map with values of this schema.
    Dict(Option<&'s Value>),
    /// Anything else; `literal` when its `const` or `enum` is the field's own
    /// (a `Literal`), not a named enum's.
    Scalar(&'s Value, bool),
}

struct Walker<'s> {
    defs: &'s Map<String, Value>,
    required_metadata: &'s [String],
}

fn ref_name(schema: &Value) -> Option<&str> {
    schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|target| target.strip_prefix("#/$defs/"))
}

fn is_null(schema: &Value) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("null")
}

fn is_any(schema: &Value) -> bool {
    schema.as_object().is_some_and(Map::is_empty) || schema.as_bool() == Some(true)
}

fn types(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn first_type(schema: &Value) -> Option<&str> {
    types(schema).into_iter().find(|kind| *kind != "null")
}

impl<'s> Walker<'s> {
    fn def(&self, name: &str) -> Result<&'s Value, TemplateError> {
        self.defs
            .get(name)
            .ok_or_else(|| TemplateError(format!("no definition of {name}")))
    }

    /// Optional and `$ref` seen through; of a union, a list, else a model,
    /// else the first member that is not `Any` (`_unwrap_annotation`,
    /// `_pick_union`).
    fn core(&self, schema: &'s Value, depth: usize) -> Result<Core<'s>, TemplateError> {
        if depth > 16 {
            return Err(TemplateError("a schema refers to itself".to_owned()));
        }
        if let Some(name) = ref_name(schema) {
            let target = self.def(name)?;
            if target.get("properties").is_some() {
                return Ok(Core::Model(name.to_owned(), target));
            }
            // A named enum (a Python `Enum`) offers no literal placeholder.
            return Ok(match self.core(target, depth + 1)? {
                Core::Scalar(schema, _) => Core::Scalar(schema, false),
                other => other,
            });
        }
        let union = schema
            .get("anyOf")
            .or_else(|| schema.get("oneOf"))
            .and_then(Value::as_array);
        if let Some(members) = union {
            let members: Vec<&Value> = members.iter().filter(|member| !is_null(member)).collect();
            let mut cores = Vec::new();
            for member in &members {
                cores.push(self.core(member, depth + 1)?);
            }
            if cores.len() == 1 {
                return Ok(cores.remove(0));
            }
            if let Some(index) = cores.iter().position(|core| matches!(core, Core::List(_))) {
                return Ok(cores.remove(index));
            }
            if let Some(index) = cores
                .iter()
                .position(|core| matches!(core, Core::Model(..)))
            {
                return Ok(cores.remove(index));
            }
            if let Some(index) = members.iter().position(|member| !is_any(member)) {
                return Ok(cores.remove(index));
            }
            return Ok(cores
                .into_iter()
                .next()
                .unwrap_or(Core::Scalar(schema, true)));
        }
        if schema.get("properties").is_some() {
            return Err(TemplateError(
                "a nested model without a definition".to_owned(),
            ));
        }
        Ok(match first_type(schema) {
            Some("array") => Core::List(schema.get("items")),
            Some("object") => Core::Dict(schema.get("additionalProperties")),
            _ => Core::Scalar(schema, is_literal(schema)),
        })
    }

    fn model(
        &self,
        name: &str,
        schema: &'s Value,
        indent: usize,
        state: &State,
        depth: usize,
    ) -> Result<Vec<String>, TemplateError> {
        if depth > MAX_DEPTH {
            return Ok(Vec::new());
        }
        let model: &Model = model_named(name)
            .ok_or_else(|| TemplateError(format!("no field order for model {name}")))?;
        let mut state = state.clone();
        if let Some(revision) = REVISIONS.iter().find(|revision| revision.model == name) {
            state.schema_id = Some(revision.identifier);
        }
        let empty = Map::new();
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let required: Vec<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(unordered) = properties
            .keys()
            .find(|key| !model.fields.contains(&key.as_str()))
        {
            return Err(TemplateError(format!(
                "{name}.{unordered} is not in the model's field order"
            )));
        }
        let mut lines: Vec<String> = Vec::new();
        let mut first = true;
        for field in model.fields {
            // serde lists a field's aliases beside it; they have no schema.
            let Some(property) = properties.get(*field) else {
                continue;
            };
            let promoted = model.metadata && self.required_metadata.iter().any(|key| key == field);
            let field_lines = self.field(
                name,
                field,
                property,
                required.contains(field),
                promoted,
                indent,
                &state,
                depth,
            )?;
            if field_lines.is_empty() {
                continue;
            }
            if flag(property, keys::TEMPLATE_SPACER)
                && !first
                && lines.last().is_none_or(|last| !last.is_empty())
            {
                lines.push(String::new());
            }
            lines.extend(field_lines);
            first = false;
        }
        Ok(lines)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the walk's state, as _render_field takes it"
    )]
    fn field(
        &self,
        model: &str,
        key: &str,
        property: &'s Value,
        listed_required: bool,
        promoted: bool,
        indent: usize,
        state: &State,
        depth: usize,
    ) -> Result<Vec<String>, TemplateError> {
        if flag(property, keys::TEMPLATE_HIDE) {
            return Ok(Vec::new());
        }
        let core = self.core(property, 0)?;
        if let Core::Scalar(schema, _) = &core
            && schema.get("format").and_then(Value::as_str) == Some("path")
        {
            return Ok(Vec::new());
        }
        let required = promoted
            || match property.get(keys::TEMPLATE_REQUIRED) {
                Some(Value::Bool(value)) => *value,
                _ => listed_required,
            };
        let comment_now = !required && state.comment_optionals;
        let mut child = state.clone();
        if comment_now {
            child.comment_optionals = false;
        }
        let lines = self.value(model, key, property, core, indent, &child, depth)?;
        Ok(if comment_now { hug(lines) } else { lines })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the walk's state, as _render_value takes it"
    )]
    fn value(
        &self,
        model: &str,
        key: &str,
        property: &'s Value,
        core: Core<'s>,
        indent: usize,
        state: &State,
        depth: usize,
    ) -> Result<Vec<String>, TemplateError> {
        let pad = " ".repeat(indent);
        match core {
            Core::Model(name, schema) => {
                let child = self.model(&name, schema, indent + 2, state, depth + 1)?;
                let mut lines = vec![format!("{pad}{key}:")];
                lines.extend(child);
                Ok(lines)
            }
            Core::List(items) => self.list(model, key, property, items, indent, state, depth),
            Core::Dict(values) => self.dict(model, key, values, indent, state, depth),
            Core::Scalar(schema, literal) => {
                if flag(property, keys::TEMPLATE_MULTILINE) || MULTILINE_NAMES.contains(&key) {
                    return Ok(vec![format!("{pad}{key}: |"), format!("{pad}  ...")]);
                }
                let placeholder = scalar_placeholder(
                    key,
                    schema,
                    literal,
                    property,
                    state,
                    concrete_default(property),
                );
                Ok(vec![if placeholder.is_empty() {
                    format!("{pad}{key}: ")
                } else {
                    format!("{pad}{key}: {placeholder}")
                }])
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the walk's state, as _render_list takes it"
    )]
    fn list(
        &self,
        model: &str,
        key: &str,
        property: &'s Value,
        items: Option<&'s Value>,
        indent: usize,
        state: &State,
        depth: usize,
    ) -> Result<Vec<String>, TemplateError> {
        let pad = " ".repeat(indent);
        let header = format!("{pad}{key}:");
        let item_indent = indent + 2;
        let item_pad = " ".repeat(item_indent);
        let any = Value::Bool(true);
        let item = match items {
            Some(items) => self.core(items, 0)?,
            None => Core::Scalar(&any, true),
        };
        match item {
            Core::Model(name, schema) => {
                let body = self.model(&name, schema, item_indent + 2, state, depth + 1)?;
                let mut lines = vec![header];
                lines.extend(list_item_lines(&body, item_indent));
                Ok(lines)
            }
            Core::Dict(values) => {
                let sample_key = dict_sample_key(model, key);
                let sample = match values.map(|values| self.core(values, 0)).transpose()? {
                    Some(Core::Scalar(schema, literal)) => scalar_placeholder(
                        "value",
                        schema,
                        literal,
                        &Value::Null,
                        state,
                        concrete_default(property),
                    ),
                    _ => format_default(concrete_default(property)).unwrap_or_default(),
                };
                Ok(vec![header, format!("{item_pad}- {sample_key}: {sample}")])
            }
            Core::List(_) => Ok(vec![header, format!("{item_pad}- ")]),
            Core::Scalar(schema, literal) => {
                let placeholder = scalar_placeholder(
                    key,
                    schema,
                    literal,
                    property,
                    state,
                    concrete_default(property),
                );
                Ok(vec![
                    header,
                    if placeholder.is_empty() {
                        format!("{item_pad}- ")
                    } else {
                        format!("{item_pad}- {placeholder}")
                    },
                ])
            }
        }
    }

    fn dict(
        &self,
        model: &str,
        key: &str,
        values: Option<&'s Value>,
        indent: usize,
        state: &State,
        depth: usize,
    ) -> Result<Vec<String>, TemplateError> {
        let pad = " ".repeat(indent);
        let header = format!("{pad}{key}:");
        let child_indent = indent + 2;
        let child_pad = " ".repeat(child_indent);
        let sample_key = dict_sample_key(model, key);
        let any = Value::Bool(true);
        let value = match values {
            Some(values) => self.core(values, 0)?,
            None => Core::Scalar(&any, true),
        };
        match value {
            Core::Model(name, schema) => {
                let child = self.model(&name, schema, child_indent + 2, state, depth + 1)?;
                let mut lines = vec![header, format!("{child_pad}{sample_key}:")];
                lines.extend(child);
                Ok(lines)
            }
            Core::List(_) => Ok(vec![
                header,
                format!("{child_pad}{sample_key}:"),
                format!("{child_pad}  - "),
            ]),
            Core::Dict(_) => Ok(vec![header, format!("{child_pad}{sample_key}: ")]),
            Core::Scalar(schema, literal) => {
                let placeholder =
                    scalar_placeholder("value", schema, literal, &Value::Null, state, None);
                Ok(vec![
                    header,
                    format!("{child_pad}{sample_key}: {placeholder}"),
                ])
            }
        }
    }
}

/// Whether a schema is a `Literal`'s as Pydantic writes it in place: `type`
/// with `enum` or `const` (`literal_schema`), beside the field's own
/// annotations. A string type that documents its values
/// (`SentinelTechnique`'s `markdownEnumDescriptions`) is an annotated `str`,
/// which offers no placeholder.
fn is_literal(schema: &Value) -> bool {
    schema.as_object().is_some_and(|map| {
        (map.contains_key("enum") || map.contains_key("const"))
            && map.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "type" | "enum" | "const" | "description" | "title" | "default"
                ) || key.starts_with("tide.")
            })
    })
}

fn flag(property: &Value, key: &str) -> bool {
    property.get(key).and_then(Value::as_bool) == Some(true)
}

fn dict_sample_key(model: &str, field: &str) -> &'static str {
    if INTEGER_KEYED.contains(&(model, field)) {
        "1"
    } else {
        "key"
    }
}

/// A field's default, unless it is `null` or an empty list or map (what
/// Pydantic's `default_factory` gives: no default in its schema).
fn concrete_default(property: &Value) -> Option<&Value> {
    match property.get("default") {
        None | Some(Value::Null) => None,
        Some(Value::Array(items)) if items.is_empty() => None,
        Some(Value::Object(map)) if map.is_empty() => None,
        Some(value) => Some(value),
    }
}

fn format_default(default: Option<&Value>) -> Option<String> {
    default.map(format_scalar)
}

/// `_format_scalar`.
fn format_scalar(value: &Value) -> String {
    match value {
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::Object(_) | Value::Array(_) | Value::Null => String::new(),
        Value::String(text) => format_string(text),
    }
}

/// `_format_string`: bare when YAML reads it back as the same string, else
/// JSON-quoted.
fn format_string(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let quoted = || {
        super::json::Json::from(value)
            .to_python_text()
            .trim_end()
            .to_owned()
    };
    if YAML_RESERVED.contains(&value.to_lowercase().as_str()) {
        return quoted();
    }
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        return quoted();
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_./:+-".contains(&byte))
    {
        return value.to_owned();
    }
    quoted()
}

/// `_scalar_placeholder`: `extras` is the field's own schema (its `tide.*`
/// keys and `format`), `schema` the type's.
fn scalar_placeholder(
    name: &str,
    schema: &Value,
    literal: bool,
    extras: &Value,
    state: &State,
    default: Option<&Value>,
) -> String {
    if name == "schema"
        && let Some(id) = state.schema_id
    {
        return format_string(id);
    }
    if extras
        .get(keys::VOCAB)
        .is_some_and(|vocab| !vocab.is_null())
    {
        return format_default(default).unwrap_or_default();
    }
    if let Some(default) = default {
        return format_scalar(default);
    }
    let format = extras.get("format").and_then(Value::as_str);
    if format == Some("date") || DATE_NAMES.contains(&name) {
        return "YYYY-MM-DD".to_owned();
    }
    if format == Some("email") {
        return "author@domain.com".to_owned();
    }
    if format == Some("uri") || URI_NAMES.contains(&name) {
        return "https://".to_owned();
    }
    if literal {
        if let Some(constant) = schema.get("const") {
            return format_scalar(constant);
        }
        if let Some(first) = schema
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
        {
            return format_scalar(first);
        }
    }
    match first_type(schema) {
        Some("boolean") => "false".to_owned(),
        Some("integer" | "number") => "3".to_owned(),
        _ => String::new(),
    }
}

/// `_list_item_lines`: `- ` on the first body line, at the item's indent.
fn list_item_lines(body: &[String], item_indent: usize) -> Vec<String> {
    let pad = " ".repeat(item_indent);
    let Some((first, rest)) = body.split_first() else {
        return vec![format!("{pad}- ")];
    };
    let mut lines = vec![format!("{pad}- {}", first.trim_start_matches(' '))];
    lines.extend(rest.iter().cloned());
    lines
}

/// `_comment_hug_keys`: `#` before each line's first token; blank lines stay
/// blank and a commented line stays as it is.
fn hug(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| {
            if line.trim().is_empty() {
                return String::new();
            }
            let rest = line.trim_start_matches(' ');
            if rest.starts_with('#') {
                return line;
            }
            let spaces = line.len() - rest.len();
            format!("{}#{rest}", &line[..spaces])
        })
        .collect()
}

/// The text an author gets by uncommenting every optional block
/// (`uncomment_optional_blocks`): the leading `#` after the indentation
/// removed from each line.
pub fn uncomment_optional_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let rest = body.trim_start_matches(' ');
        let spaces = body.len() - rest.len();
        if !body.trim().is_empty()
            && let Some(uncommented) = rest.strip_prefix('#')
        {
            out.push_str(&body[..spaces]);
            out.push_str(uncommented);
        } else {
            out.push_str(body);
        }
        out.push_str(newline);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_quoted_only_where_yaml_would_read_them_otherwise() {
        assert_eq!(format_string(""), "");
        assert_eq!(format_string("rule::1.1"), "rule::1.1");
        assert_eq!(format_string("Yes"), "\"Yes\"");
        assert_eq!(format_string("123"), "\"123\"");
        assert_eq!(format_string("Single Event"), "\"Single Event\"");
        assert_eq!(format_string("*"), "\"*\"");
        assert_eq!(format_string("5m"), "5m");
    }

    #[test]
    fn hugging_comments_each_token_once_and_keeps_blank_lines_blank() {
        let lines = vec![
            "a:".to_owned(),
            "  #b: ".to_owned(),
            "   ".to_owned(),
            "  c: |".to_owned(),
        ];
        assert_eq!(hug(lines), vec!["#a:", "  #b: ", "", "  #c: |"]);
    }

    #[test]
    fn list_items_take_a_dash_on_their_first_line() {
        let body = vec!["    name: ".to_owned(), "    value: ".to_owned()];
        assert_eq!(list_item_lines(&body, 2), vec!["  - name: ", "    value: "]);
        assert_eq!(list_item_lines(&[], 2), vec!["  - "]);
    }

    #[test]
    fn uncommenting_restores_the_yaml() {
        assert_eq!(
            uncomment_optional_blocks("a: \n#b:\n  #- x\n\n"),
            "a: \nb:\n  - x\n\n"
        );
    }

    #[test]
    fn empty_collections_are_no_default() {
        assert_eq!(concrete_default(&serde_json::json!({"default": []})), None);
        assert_eq!(
            concrete_default(&serde_json::json!({"default": null})),
            None
        );
        assert_eq!(
            concrete_default(&serde_json::json!({"default": false})),
            Some(&Value::Bool(false))
        );
    }
}
