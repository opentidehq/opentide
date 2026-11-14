//! The structural conversion (UC-1.2, #808): a model built from the YAML node
//! tree ([`crate::node`]) with every structural error collected, each with
//! its field path and position.
//!
//! serde stops at the first error; the CLI reports every error of an object
//! at once. `#[derive(FromNode)]` (`opentide-schema-derive`) writes
//! [`FromNode`] for a model from the serde attributes it already has
//! (`rename`, `alias`, `default`, `deny_unknown_fields`), so the field names,
//! the aliases and the closure are written once. serde keeps the happy path
//! and serialisation.
//!
//! - **Types are the declared ones.** A string field takes a string, an
//!   integer field an integer, a boolean field `true` or `false`; a number
//!   field takes an integer or a float. Nothing is coerced: `"42"` is not an
//!   integer and `"yes"` is not a boolean, as the generated JSON Schemas say.
//! - **Order.** Fields in declaration order (a missing field where it is
//!   declared), then the keys no field takes, in the document's order: an
//!   unknown key (`extra_forbidden`) or a key that is not a string
//!   (`invalid_key`).
//! - **Names.** The serialised name is looked up first, then each serde
//!   `alias`; a second one present is an unknown key.
//! - **Unions** (`#[from_node(union)]`): the first member that takes the
//!   value, else every member's errors, each under the member's tag
//!   (`either.str`, `either.int`).
//! - **Paths**: keys, list indexes, `[key]` for a mapping key of the wrong
//!   type; a key that is not a string is written as YAML writes it (`true`,
//!   `12`).
//!
//! The messages are the CLI's (Pydantic's wording, which says what is wrong
//! plainly). Constraints (garde, with the [`crate::Pins`] context) run after a
//! successful conversion: [`validate`].

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{ErrorKind, PathSegment, SchemaError};
use crate::node::{Document, Entry, Mark, Node, Value};
use crate::pins::Pins;

/// The messages the conversion reports.
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
    /// `float_type`.
    pub const FLOAT_TYPE: &str = "Input should be a valid number";
    /// `bool_type`.
    pub const BOOL_TYPE: &str = "Input should be a valid boolean";
    /// `list_type`.
    pub const LIST_TYPE: &str = "Input should be a valid list";
    /// `dict_type`.
    pub const DICT_TYPE: &str = "Input should be a valid dictionary";

    /// `model_type`, for the class `class_name`.
    pub fn model_type(class_name: &str) -> String {
        format!("Input should be a valid dictionary or instance of {class_name}")
    }

    /// The expected values, quoted: `'a'`, `'a' or 'b'`, `'a', 'b' or 'c'`
    /// (`literal_error`, `enum`).
    pub fn expected(values: &[&str]) -> String {
        let quoted: Vec<String> = values.iter().map(|value| format!("{value:?}")).collect();
        match quoted.split_last() {
            None => String::new(),
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        }
    }
}

/// How much work one conversion may do (nodes visited plus errors): far above
/// any object file (the corpora's largest takes a few hundred), far below what
/// a tree of nested aliases can demand.
pub const BUDGET: usize = 100_000;

/// The conversion state: the path to the value being converted, the errors so
/// far, and the work left.
#[derive(Debug)]
pub struct Context {
    path: Vec<PathSegment>,
    errors: Vec<SchemaError>,
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
            remaining: BUDGET,
            stopped: false,
        }
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
                     100000 values",
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
    fn trial(&self) -> Self {
        Self {
            path: self.path.clone(),
            errors: Vec::new(),
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
}

/// A model's class name and fields, written by `#[derive(FromNode)]` on a
/// struct: what the Python classes read for `model_dump`, `__repr__` and the
/// serialised names (UC-1.9, #815).
pub trait Model {
    /// The Pydantic class name (`#[from_node(model = "...")]`, else the Rust
    /// name).
    const CLASS: &'static str;
    /// Each field's attribute name and serialised name, in declaration order
    /// (`("schema_id", "schema")`).
    const FIELDS: &'static [(&'static str, &'static str)];
}

/// Converts a document's root into `T`, with every error placed (span and
/// `yaml_line`) in the document. A document with no node (empty) is `null`.
pub fn from_document<T: FromNode>(document: &Document) -> Result<T, Vec<SchemaError>> {
    let mut cx = Context::new();
    let null;
    let root: &Node = match document.root() {
        Some(root) => root,
        None => {
            null = Node::null_at(Mark {
                index: 0,
                line: 1,
                column: 1,
            });
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
    let locator = document.locator();
    for error in &mut errors {
        let field_path = error.field_path();
        error.span = locator.span(&field_path, error.kind == ErrorKind::UnknownKey);
        error.yaml_line = locator.yaml_line(&field_path);
    }
    Err(errors)
}

/// Why [`validate`] refused a document.
#[derive(Debug)]
pub enum Invalid {
    /// The structure is wrong: every error, placed.
    Structure(Vec<SchemaError>),
    /// The structure is right and garde's constraints fail. Turning each into
    /// a placed [`SchemaError`] is the work of the items that add the
    /// constraints (UC-1.3, #809, onwards).
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
                    let key = entry.key.value.to_string();
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

/// A vocabulary list written as one string (`ThreatBody.impact` and
/// `.leverage`) is `vocab_list_type`, naming the field (the last key of the
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
        message.push_str(&format!("; list each name in {text:?} as its own item"));
    }
    cx.error_with(
        ErrorKind::InvalidValue("vocab_list_type"),
        message,
        node,
        &[("field", field.clone()), ("value", text.to_owned())],
    );
    false
}

/// One member of a union: its tag (`str`, `int`, `list[str]`) and its
/// conversion.
pub struct Member<'a, T> {
    /// The tag added to the path of the member's errors.
    pub tag: &'a str,
    /// The conversion.
    pub convert: fn(&Node, &mut Context) -> Option<T>,
}

/// A union: the first member that takes the value, else the errors of every
/// member, each under its tag.
pub fn union_value<T>(node: &Node, cx: &mut Context, members: &[Member<'_, T>]) -> Option<T> {
    let mut failures = Vec::new();
    for member in members {
        let mut trial = cx.trial();
        trial.path.push(PathSegment::Key(member.tag.to_owned()));
        let value = (member.convert)(node, &mut trial);
        if trial.stopped && !cx.stopped {
            // The budget ran out in this member: the conversion stops here,
            // with the errors so far and one `Limit`, the caller's, last.
            trial.errors.retain(|error| error.kind != ErrorKind::Limit);
            cx.errors.extend(failures);
            cx.errors.append(&mut trial.errors);
            cx.absorb_budget(&trial);
            return None;
        }
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
}

impl FromNode for i64 {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if let Value::Int(integer) = node.value {
            return Some(integer);
        }
        cx.error(ErrorKind::InvalidType("int_type"), messages::INT_TYPE, node);
        None
    }
}

impl FromNode for f64 {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        match node.value {
            Value::Float(float) => Some(float),
            #[expect(
                clippy::cast_precision_loss,
                reason = "a number field takes an integer as the nearest float, as JSON Schema's number does"
            )]
            Value::Int(integer) => Some(integer as f64),
            _ => {
                cx.error(
                    ErrorKind::InvalidType("float_type"),
                    messages::FLOAT_TYPE,
                    node,
                );
                None
            }
        }
    }
}

impl FromNode for bool {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if let Value::Bool(flag) = node.value {
            return Some(flag);
        }
        cx.error(
            ErrorKind::InvalidType("bool_type"),
            messages::BOOL_TYPE,
            node,
        );
        None
    }
}

impl<T: FromNode> FromNode for Option<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        if matches!(node.value, Value::Null) {
            return Some(None);
        }
        T::from_node(node, cx).map(Some)
    }
}

impl<T: FromNode> FromNode for Box<T> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        T::from_node(node, cx).map(Box::new)
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
}

/// A mapping with string keys: Pydantic's `dict[str, V]`. The ordered
/// map keeps the document's order, as a Python `dict` does.
fn string_map<V: FromNode, M: Default>(
    node: &Node,
    cx: &mut Context,
    insert: impl Fn(&mut M, String, V),
) -> Option<M> {
    let Value::Map(entries) = &node.value else {
        cx.error(
            ErrorKind::InvalidType("dict_type"),
            messages::DICT_TYPE,
            node,
        );
        return None;
    };
    let mut values = M::default();
    let mut ok = true;
    for entry in entries {
        if !cx.tick() {
            return None;
        }
        let key = entry.key.value.to_string();
        cx.at_key(&key, |cx| {
            let name = cx.at_key("[key]", |cx| String::from_node(&entry.key, cx));
            let value = V::from_node(&entry.value, cx);
            match (name, value) {
                (Some(name), Some(value)) => {
                    insert(&mut values, name, value);
                }
                _ => ok = false,
            }
        });
    }
    ok.then_some(values)
}

impl<V: FromNode> FromNode for BTreeMap<String, V> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        string_map(node, cx, |map: &mut Self, key, value| {
            map.insert(key, value);
        })
    }
}

impl<V: FromNode> FromNode for indexmap::IndexMap<String, V> {
    fn from_node(node: &Node, cx: &mut Context) -> Option<Self> {
        string_map(node, cx, |map: &mut Self, key, value| {
            map.insert(key, value);
        })
    }
}

/// Any value, unchecked: a field whose structure another item checks.
impl FromNode for Arc<Node> {
    fn from_node(node: &Node, _cx: &mut Context) -> Option<Self> {
        Some(Arc::new(node.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::load;

    /// A union's value: the members convert to different types.
    #[derive(Debug, PartialEq)]
    enum Either {
        Texts(Vec<String>),
        Ints(Vec<i64>),
    }

    fn ints(node: &Node, cx: &mut Context) -> Option<Either> {
        Vec::<i64>::from_node(node, cx).map(Either::Ints)
    }

    fn texts(node: &Node, cx: &mut Context) -> Option<Either> {
        Vec::<String>::from_node(node, cx).map(Either::Texts)
    }

    #[test]
    fn a_union_members_work_is_the_callers() {
        let document = load("[1, 2, 3]\n").unwrap();
        let root = document.root().unwrap();
        let mut cx = Context::new();
        cx.remaining = 100;
        let members = [
            Member {
                tag: "list[str]",
                convert: texts,
            },
            Member {
                tag: "list[int]",
                convert: ints,
            },
        ];
        assert_eq!(
            union_value(root, &mut cx, &members),
            Some(Either::Ints(vec![1, 2, 3]))
        );
        // list[str]: 3 items and 3 errors; list[int]: 3 items.
        assert_eq!(cx.remaining, 100 - 9);
        assert_eq!(cx.error_count(), 0);
    }

    #[test]
    fn a_union_that_spends_the_budget_reports_the_limit_once() {
        let document = load("[1, 2, 3, 4, 5, 6]\n").unwrap();
        let root = document.root().unwrap();
        let mut cx = Context::new();
        cx.remaining = 4;
        let members = [
            Member {
                tag: "list[str]",
                convert: texts,
            },
            Member {
                tag: "list[int]",
                convert: ints,
            },
        ];
        assert_eq!(union_value(root, &mut cx, &members), None);
        assert_eq!(cx.remaining, 0);
        assert!(cx.stopped);
        let errors = cx.into_errors();
        let limits = errors
            .iter()
            .filter(|error| error.kind == ErrorKind::Limit)
            .count();
        assert_eq!(limits, 1, "{errors:#?}");
    }
}
