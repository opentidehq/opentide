//! The structural conversion (UC-1.2, #808): a model built from the YAML node
//! tree ([`crate::node`]) with every structural error collected, as Pydantic
//! collects them, in Pydantic's words, with the CLI's positions.
//!
//! serde stops at the first error; Pydantic reports every error of an object
//! at once, and the CLI prints them all. `#[derive(FromNode)]`
//! (`opentide-schema-derive`) writes [`FromNode`] for a model from the serde
//! attributes it already has (`rename`, `alias`, `default`,
//! `deny_unknown_fields`), so the field names, the aliases and the closure are
//! written once. serde keeps the happy path and serialisation.
//!
//! What the conversion reproduces, each checked against Pydantic 2.14 at the
//! oracle (`tests/oracle/from_node_table.json`):
//!
//! - **Order.** Fields in declaration order (a missing field where it is
//!   declared), then the keys no field takes, in the document's order: an
//!   unknown key (`extra_forbidden`) or a key that is not a string
//!   (`invalid_key`).
//! - **Names.** The serialised name (Pydantic's alias) is looked up first, then
//!   each serde `alias` (Pydantic's field name, `populate_by_name`); a second
//!   one present is an unknown key.
//! - **Lax scalars.** `int` from `"42"`, `" 7 "`, `"3.00"`, `3.0`, `true`;
//!   `bool` from `"yes"`, `"off"`, `1`, `0.0`; `float` from `2`, `"2.5"`,
//!   `true`; `str` from a string only.
//! - **Unions** (`#[from_node(union)]`): the first member that takes the value
//!   strictly, else the first that takes it laxly, else every member's errors,
//!   each under the member's tag (`either.str`, `either.int`).
//! - **Paths** as Pydantic's `loc`: keys, list indexes, `[key]` for a mapping
//!   key of the wrong type.
//!
//! Constraints (garde, with the [`crate::Pins`] context) run after a
//! successful conversion: [`validate`].

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{ErrorKind, PathSegment, SchemaError};
use crate::node::{Document, Entry, Node, Value};
use crate::pins::Pins;

/// Pydantic's messages for the errors the conversion reports, byte for byte
/// (pydantic-core 2.14 at the oracle).
pub mod messages {
    /// `missing`.
    pub const FIELD_REQUIRED: &str = "Field required";
    /// `extra_forbidden`.
    pub const EXTRA_FORBIDDEN: &str = "Extra inputs are not permitted";
    /// `invalid_key`: a mapping key that is not a string, on a model.
    pub const INVALID_KEY: &str = "Keys should be strings";
    /// `string_type`.
    pub const STRING_TYPE: &str = "Input should be a valid string";
    /// `int_type`.
    pub const INT_TYPE: &str = "Input should be a valid integer";
    /// `int_parsing`.
    pub const INT_PARSING: &str =
        "Input should be a valid integer, unable to parse string as an integer";
    /// `int_from_float`.
    pub const INT_FROM_FLOAT: &str =
        "Input should be a valid integer, got a number with a fractional part";
    /// `int_parsing_size`.
    pub const INT_PARSING_SIZE: &str =
        "Unable to parse input string as an integer, exceeded maximum size";
    /// `finite_number`.
    pub const FINITE_NUMBER: &str = "Input should be a finite number";
    /// `float_type`.
    pub const FLOAT_TYPE: &str = "Input should be a valid number";
    /// `float_parsing`.
    pub const FLOAT_PARSING: &str =
        "Input should be a valid number, unable to parse string as a number";
    /// `bool_type`.
    pub const BOOL_TYPE: &str = "Input should be a valid boolean";
    /// `bool_parsing`.
    pub const BOOL_PARSING: &str = "Input should be a valid boolean, unable to interpret input";
    /// `list_type`.
    pub const LIST_TYPE: &str = "Input should be a valid list";
    /// `dict_type`.
    pub const DICT_TYPE: &str = "Input should be a valid dictionary";

    /// `model_type`, for the class `class_name`.
    pub fn model_type(class_name: &str) -> String {
        format!("Input should be a valid dictionary or instance of {class_name}")
    }

    /// Pydantic's list of expected values: `'a'`, `'a' or 'b'`,
    /// `'a', 'b' or 'c'` (`literal_error`, `enum`).
    pub fn expected(values: &[&str]) -> String {
        let quoted: Vec<String> = values
            .iter()
            .map(|value| crate::node::python_str_repr(value))
            .collect();
        match quoted.split_last() {
            None => String::new(),
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        }
    }
}

/// How much work one conversion may do (nodes visited plus errors): far above
/// any object file, far below what a tree of nested aliases can demand.
pub const BUDGET: usize = 1_000_000;

/// The conversion state: the path to the value being converted, the errors so
/// far, and whether values are being taken strictly (a union's first pass).
#[derive(Debug)]
pub struct Context {
    path: Vec<PathSegment>,
    errors: Vec<SchemaError>,
    strict: bool,
    remaining: usize,
    stopped: bool,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    /// A context at the document's root.
    pub fn new() -> Self {
        Self {
            path: Vec::new(),
            errors: Vec::new(),
            strict: false,
            remaining: BUDGET,
            stopped: false,
        }
    }

    /// Whether values are taken strictly (no lax coercion).
    pub fn strict(&self) -> bool {
        self.strict
    }

    /// Counts one unit of work; `false` once the budget is spent (the
    /// conversion then stops and reports [`ErrorKind::Limit`] once).
    pub fn tick(&mut self) -> bool {
        if self.remaining == 0 {
            if !self.stopped {
                self.stopped = true;
                self.errors.push(SchemaError::new(
                    ErrorKind::Limit,
                    Vec::new(),
                    "the document is too large to check: it expands to more than \
                     1000000 values",
                ));
            }
            return false;
        }
        self.remaining -= 1;
        true
    }

    /// The path to the value being converted.
    pub fn path(&self) -> &[PathSegment] {
        &self.path
    }

    /// Reports an error about `input` at the current path.
    pub fn error(&mut self, kind: ErrorKind, message: impl Into<String>, input: &Node) {
        self.error_with(kind, message, input, &[]);
    }

    /// Reports an error with Pydantic's `ctx`.
    pub fn error_with(
        &mut self,
        kind: ErrorKind,
        message: impl Into<String>,
        input: &Node,
        context: &[(&str, String)],
    ) {
        if !self.tick() {
            return;
        }
        let mut error = SchemaError::new(kind, self.path.clone(), message);
        error.input = input.value.as_str().map(str::to_owned);
        error.context = context
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect();
        self.errors.push(error);
    }

    /// Runs `f` one step further down the path.
    pub fn at<R>(&mut self, segment: PathSegment, f: impl FnOnce(&mut Self) -> R) -> R {
        self.path.push(segment);
        let result = f(self);
        self.path.pop();
        result
    }

    /// Runs `f` under the mapping key `key`.
    pub fn at_key<R>(&mut self, key: &str, f: impl FnOnce(&mut Self) -> R) -> R {
        self.at(PathSegment::Key(key.to_owned()), f)
    }

    /// Runs `f` under the list index `index`.
    pub fn at_index<R>(&mut self, index: usize, f: impl FnOnce(&mut Self) -> R) -> R {
        self.at(PathSegment::Index(index), f)
    }

    /// The errors reported, in order.
    pub fn into_errors(self) -> Vec<SchemaError> {
        self.errors
    }

    /// The number of errors reported so far.
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// A context for a trial conversion at the current path (a union member):
    /// its errors are the caller's to keep or drop.
    fn trial(&self, strict: bool) -> Self {
        Self {
            path: self.path.clone(),
            errors: Vec::new(),
            strict,
            remaining: self.remaining,
            stopped: self.stopped,
        }
    }

    fn absorb_budget(&mut self, trial: &Self) {
        self.remaining = self.remaining.min(trial.remaining);
        if trial.stopped && !self.stopped {
            self.remaining = 0;
            self.tick();
        }
    }
}

/// A model, or a value of a model's field, built from a node.
pub trait FromNode: Sized {
    /// The value `node` holds, or `None` after reporting, in `cx`, every
    /// error that stops it.
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self>;

    /// Whether `node` is this type's own kind of value, so a union's strict
    /// pass takes it without coercion. The default is the lax conversion.
    fn takes_strictly(node: &Node) -> bool {
        let _ = node;
        true
    }
}

/// Converts a document's root into `T`, with every error placed (span and
/// `yaml_line`) in the document. A document with no node (empty) is `None`,
/// as `model_validate(None)` sees it.
pub fn from_document<T: FromNode>(document: &Document) -> Result<T, Vec<SchemaError>> {
    let mut cx = Context::new();
    let null;
    let root: &Node = match document.root() {
        Some(root) => root,
        None => {
            null = Node {
                value: Value::Null,
                start: crate::node::Mark::default(),
                end: crate::node::Mark::default(),
            };
            &null
        }
    };
    let value = T::from_node(root, &mut cx);
    let mut errors = cx.into_errors();
    if errors.is_empty()
        && let Some(value) = value
    {
        return Ok(value);
    }
    for error in &mut errors {
        let field_path = error.field_path();
        error.span = document.span(&field_path, error.kind == ErrorKind::UnknownKey);
        error.yaml_line = document.yaml_line(&field_path);
    }
    Err(errors)
}

/// Why [`validate`] refused a document.
#[derive(Debug)]
pub enum Invalid {
    /// The structure is wrong: every error, placed.
    Structure(Vec<SchemaError>),
    /// The structure is right and garde's constraints fail. Turning each into
    /// Pydantic's error (type, message, serialised path) is the work of the
    /// item that ports the constraint (UC-1.3, #809, onwards).
    Constraints(garde::Report),
}

/// The conversion, then garde's constraints with `pins`.
pub fn validate<T>(document: &Document, pins: &Pins) -> Result<T, Invalid>
where
    T: FromNode + garde::Validate<Context = Pins>,
{
    let value = from_document::<T>(document).map_err(Invalid::Structure)?;
    value.validate_with(pins).map_err(Invalid::Constraints)?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Models: what the derive's expansion calls.
// ---------------------------------------------------------------------------

/// The entries of a model's mapping, or `model_type` for anything else.
pub fn model_entries<'n>(
    node: &'n Node,
    cx: &mut Context,
    class_name: &str,
) -> Option<&'n [Entry]> {
    if !cx.tick() {
        return None;
    }
    if let Value::Map(entries) = &node.value {
        Some(entries)
    } else {
        cx.error_with(
            ErrorKind::InvalidType("model_type"),
            messages::model_type(class_name),
            node,
            &[("class_name", class_name.to_owned())],
        );
        None
    }
}

/// What a missing key means for a field.
pub enum Missing<T> {
    /// `missing`: "Field required".
    Required,
    /// The field's default.
    Default(fn() -> T),
}

/// A model's mapping, field by field: which entries the fields took.
pub struct Fields<'n> {
    node: &'n Node,
    entries: &'n [Entry],
    used: Vec<bool>,
}

impl<'n> Fields<'n> {
    /// The fields of `node`, whose entries are `entries`.
    pub fn new(node: &'n Node, entries: &'n [Entry]) -> Self {
        Self {
            node,
            entries,
            used: vec![false; entries.len()],
        }
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.key.value.as_str() == Some(name))
    }

    /// One field: the first of `names` (the serialised name, then each alias)
    /// present is converted with `convert` under that key; when none is,
    /// `missing` decides. `before` runs first on the value (a Pydantic
    /// `mode="before"` field validator): `false` stops the field there.
    pub fn field<T>(
        &mut self,
        cx: &mut Context,
        names: &[&str],
        missing: Missing<T>,
        before: Option<fn(&Node, &mut Context) -> bool>,
        convert: impl FnOnce(&Node, &mut Context) -> Option<T>,
    ) -> Option<T> {
        let found = names
            .iter()
            .find_map(|name| self.find(name).map(|index| (index, *name)));
        let Some((index, name)) = found else {
            return match missing {
                Missing::Default(default) => Some(default()),
                Missing::Required => {
                    let key = names.first().copied().unwrap_or_default();
                    let node = self.node;
                    cx.at_key(key, |cx| {
                        cx.error(ErrorKind::Missing, messages::FIELD_REQUIRED, node);
                    });
                    None
                }
            };
        };
        self.used[index] = true;
        let value = &self.entries[index].value;
        cx.at_key(name, |cx| {
            if let Some(before) = before
                && !before(value, cx)
            {
                return None;
            }
            convert(value, cx)
        })
    }

    /// The entries no field took, in the document's order: `invalid_key` for
    /// a key that is not a string, and, on a closed model (`closed`),
    /// `extra_forbidden` for every other key that `tolerated` does not name.
    pub fn finish(self, cx: &mut Context, closed: bool, tolerated: &[&str]) {
        for (entry, used) in self.entries.iter().zip(self.used) {
            if used {
                continue;
            }
            match entry.key.value.as_str() {
                Some(key) => {
                    if closed && !tolerated.contains(&key) {
                        cx.at_key(key, |cx| {
                            cx.error(
                                ErrorKind::UnknownKey,
                                messages::EXTRA_FORBIDDEN,
                                &entry.value,
                            );
                        });
                    }
                }
                None => {
                    let key = entry.key.value.python_str();
                    cx.at_key(&key, |cx| {
                        cx.error(
                            ErrorKind::InvalidType("invalid_key"),
                            messages::INVALID_KEY,
                            &entry.key,
                        );
                    });
                }
            }
        }
    }
}

/// A unit enum's value: the variant whose serialised value equals the text.
/// `literal` chooses `literal_error` (a `Literal[...]`) over `enum` (an
/// `Enum`).
pub fn enum_value<T: Copy>(
    node: &Node,
    cx: &mut Context,
    variants: &[(&str, T)],
    literal: bool,
) -> Option<T> {
    if let Some(text) = node.value.as_str()
        && let Some((_, value)) = variants.iter().find(|(name, _)| *name == text)
    {
        return Some(*value);
    }
    let names: Vec<&str> = variants.iter().map(|(name, _)| *name).collect();
    let expected = messages::expected(&names);
    let kind = if literal {
        ErrorKind::InvalidValue("literal_error")
    } else {
        ErrorKind::InvalidValue("enum")
    };
    cx.error_with(
        kind,
        format!("Input should be {expected}"),
        node,
        &[("expected", expected.clone())],
    );
    None
}

/// `_require_vocab_list` (`models/threat.py`, `ThreatBody.impact` and
/// `.leverage`), a `mode="before"` field validator: a vocabulary list written
/// as one string is `vocab_list_type`, naming the field (the last key of the
/// path) and, when the string packs names with `;`, telling to split it. Use
/// it as `#[from_node(before = "opentide_schema::from_node::require_vocab_list")]`.
pub fn require_vocab_list(node: &Node, cx: &mut Context) -> bool {
    let Some(text) = node.value.as_str() else {
        return true;
    };
    let field = cx
        .path()
        .iter()
        .rev()
        .find_map(|segment| match segment {
            PathSegment::Key(key) => Some(key.clone()),
            PathSegment::Index(_) => None,
        })
        .unwrap_or_default();
    let mut message =
        format!("must be a YAML list of {field} vocabulary names, not a single string");
    if text.contains(';') {
        message.push_str(&format!("; list each name in '{text}' as its own item"));
    }
    cx.error_with(
        ErrorKind::InvalidValue("vocab_list_type"),
        message,
        node,
        &[("field", field.clone()), ("value", text.to_owned())],
    );
    false
}

/// One member of a union: its tag (`str`, `int`, `list[str]`) and its two
/// tries.
pub struct Member<'a, T> {
    /// The tag Pydantic appends to the path of the member's errors.
    pub tag: &'a str,
    /// Whether the value is the member's own kind (the strict pass).
    pub strict: fn(&Node) -> bool,
    /// The conversion.
    pub convert: fn(&Node, &mut Context) -> Option<T>,
}

/// A union in Pydantic's smart mode, as far as YAML values need it: the first
/// member that takes the value strictly, else the first that takes it laxly,
/// else the errors of every member under its tag.
pub fn union_value<T>(node: &Node, cx: &mut Context, members: &[Member<'_, T>]) -> Option<T> {
    for member in members {
        if (member.strict)(node) {
            let mut trial = cx.trial(true);
            let value = (member.convert)(node, &mut trial);
            cx.absorb_budget(&trial);
            if trial.errors.is_empty()
                && let Some(value) = value
            {
                return Some(value);
            }
        }
    }
    let mut failures = Vec::new();
    for member in members {
        let mut trial = cx.trial(false);
        trial.path.push(PathSegment::Key(member.tag.to_owned()));
        let value = (member.convert)(node, &mut trial);
        cx.absorb_budget(&trial);
        if trial.errors.is_empty()
            && let Some(value) = value
        {
            return Some(value);
        }
        failures.extend(trial.errors);
    }
    cx.errors.extend(failures);
    None
}

// ---------------------------------------------------------------------------
// Field types.
// ---------------------------------------------------------------------------

impl FromNode for String {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if let Value::Str(text) = &node.value {
            return Some(text.clone());
        }
        cx.error(
            ErrorKind::InvalidType("string_type"),
            messages::STRING_TYPE,
            node,
        );
        None
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Str(_))
    }
}

/// Pydantic's integer from a string: whitespace around it, one sign, digits
/// with single `_` between them, and a fraction of zeros only (`3.00`).
fn int_from_text(text: &str) -> Option<crate::node::Integer> {
    let text = text.trim();
    let (sign, rest) = match text.as_bytes().first() {
        Some(b'-') => ("-", &text[1..]),
        Some(b'+') => ("", &text[1..]),
        _ => ("", text),
    };
    let (whole, fraction) = match rest.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (rest, None),
    };
    if let Some(fraction) = fraction
        && (fraction.is_empty() || !fraction.bytes().all(|b| b == b'0'))
    {
        return None;
    }
    if whole.is_empty()
        || whole.starts_with('_')
        || whole.ends_with('_')
        || whole.contains("__")
        || !whole.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let digits: String = whole.chars().filter(|&c| c != '_').collect();
    crate::node::Integer::parse_python(&format!("{sign}{digits}"), 10)
}

impl FromNode for i64 {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let parsing_size = |cx: &mut Context| {
            cx.error(
                ErrorKind::InvalidValue("int_parsing_size"),
                messages::INT_PARSING_SIZE,
                node,
            );
            None
        };
        match &node.value {
            Value::Int(integer) => match integer.to_i64() {
                Some(value) => return Some(value),
                // Pydantic takes any Python int; an i64 field cannot.
                None => return parsing_size(cx),
            },
            Value::Bool(flag) if !cx.strict() => return Some(i64::from(*flag)),
            Value::Float(float) if !cx.strict() => {
                if !float.is_finite() {
                    cx.error(
                        ErrorKind::InvalidValue("finite_number"),
                        messages::FINITE_NUMBER,
                        node,
                    );
                    return None;
                }
                if float.fract() != 0.0 {
                    cx.error(
                        ErrorKind::InvalidValue("int_from_float"),
                        messages::INT_FROM_FLOAT,
                        node,
                    );
                    return None;
                }
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "a whole number checked to lie within i64's range"
                )]
                if *float >= -9_223_372_036_854_775_808.0 && *float < 9_223_372_036_854_775_808.0 {
                    return Some(*float as i64);
                }
                return parsing_size(cx);
            }
            Value::Str(text) if !cx.strict() => {
                return match int_from_text(text) {
                    Some(integer) => match integer.to_i64() {
                        Some(value) => Some(value),
                        None => parsing_size(cx),
                    },
                    None => {
                        cx.error(
                            ErrorKind::InvalidValue("int_parsing"),
                            messages::INT_PARSING,
                            node,
                        );
                        None
                    }
                };
            }
            _ => {}
        }
        cx.error(ErrorKind::InvalidType("int_type"), messages::INT_TYPE, node);
        None
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Int(_))
    }
}

/// Pydantic's float from a string: whitespace around it, `_` dropped, then
/// Rust's (and Python's) float syntax, `inf` and `nan` included.
fn float_from_text(text: &str) -> Option<f64> {
    let cleaned: String = text.trim().chars().filter(|&c| c != '_').collect();
    if cleaned.is_empty() || !cleaned.is_ascii() {
        return None;
    }
    cleaned.parse().ok()
}

impl FromNode for f64 {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        match &node.value {
            Value::Float(float) => return Some(*float),
            Value::Int(integer) => {
                if let Some(value) = integer.to_f64() {
                    return Some(value);
                }
            }
            Value::Bool(flag) if !cx.strict() => return Some(f64::from(u8::from(*flag))),
            Value::Str(text) if !cx.strict() => {
                if let Some(value) = float_from_text(text) {
                    return Some(value);
                }
                cx.error(
                    ErrorKind::InvalidValue("float_parsing"),
                    messages::FLOAT_PARSING,
                    node,
                );
                return None;
            }
            _ => {}
        }
        cx.error(
            ErrorKind::InvalidType("float_type"),
            messages::FLOAT_TYPE,
            node,
        );
        None
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Float(_) | Value::Int(_))
    }
}

impl FromNode for bool {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let parsing = |cx: &mut Context| {
            cx.error(
                ErrorKind::InvalidValue("bool_parsing"),
                messages::BOOL_PARSING,
                node,
            );
            None
        };
        match &node.value {
            Value::Bool(flag) => return Some(*flag),
            Value::Int(integer) if !cx.strict() => {
                return match integer.to_i64() {
                    Some(0) => Some(false),
                    Some(1) => Some(true),
                    Some(_) => parsing(cx),
                    None => {
                        cx.error(
                            ErrorKind::InvalidType("bool_type"),
                            messages::BOOL_TYPE,
                            node,
                        );
                        None
                    }
                };
            }
            Value::Float(float) if !cx.strict() => {
                // Exactly 0.0 or 1.0, as Pydantic compares them.
                if float.to_bits() == 0.0f64.to_bits() || float.to_bits() == (-0.0f64).to_bits() {
                    return Some(false);
                }
                if float.to_bits() == 1.0f64.to_bits() {
                    return Some(true);
                }
            }
            Value::Str(text) if !cx.strict() => {
                return match text.to_lowercase().as_str() {
                    "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
                    "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
                    _ => parsing(cx),
                };
            }
            _ => {}
        }
        cx.error(
            ErrorKind::InvalidType("bool_type"),
            messages::BOOL_TYPE,
            node,
        );
        None
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Bool(_))
    }
}

impl<T: FromNode> FromNode for Option<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if matches!(node.value, Value::Null) {
            return Some(None);
        }
        T::from_node(node, cx).map(Some)
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Null) || T::takes_strictly(node)
    }
}

impl<T: FromNode> FromNode for Box<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        T::from_node(node, cx).map(Box::new)
    }

    fn takes_strictly(node: &Node) -> bool {
        T::takes_strictly(node)
    }
}

impl<T: FromNode> FromNode for Vec<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let Value::Seq(items) = &node.value else {
            cx.error(
                ErrorKind::InvalidType("list_type"),
                messages::LIST_TYPE,
                node,
            );
            return None;
        };
        let mut values = Vec::with_capacity(items.len());
        let mut ok = true;
        for (index, item) in items.iter().enumerate() {
            if !cx.tick() {
                return None;
            }
            match cx.at_index(index, |cx| T::from_node(item, cx)) {
                Some(value) => values.push(value),
                None => ok = false,
            }
        }
        ok.then_some(values)
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Seq(_))
    }
}

impl<V: FromNode> FromNode for BTreeMap<String, V> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        let Value::Map(entries) = &node.value else {
            cx.error(
                ErrorKind::InvalidType("dict_type"),
                messages::DICT_TYPE,
                node,
            );
            return None;
        };
        let mut values = BTreeMap::new();
        let mut ok = true;
        for entry in entries {
            if !cx.tick() {
                return None;
            }
            let key = entry.key.value.python_str();
            cx.at_key(&key, |cx| {
                let name = cx.at_key("[key]", |cx| String::from_node(&entry.key, cx));
                let value = V::from_node(&entry.value, cx);
                match (name, value) {
                    (Some(name), Some(value)) => {
                        values.insert(name, value);
                    }
                    _ => ok = false,
                }
            });
        }
        ok.then_some(values)
    }

    fn takes_strictly(node: &Node) -> bool {
        matches!(node.value, Value::Map(_))
    }
}

/// Any value, unchecked: a field whose structure another item checks.
impl FromNode for Arc<Node> {
    fn from_node(node: &Node, _cx: &mut Context) -> Option<Self> {
        Some(Arc::new(node.clone()))
    }
}
