//! The YAML node tree a model is converted from (UC-1.2, #808).
//!
//! The text is read as **YAML 1.2** with the core schema, by the saphyr
//! project's crates: [`saphyr_parser`] turns the text into events, each with
//! its span, and [`saphyr::Scalar`] resolves each plain scalar (`true`, `null`,
//! `0x1f`, `.inf`, `1.5`; everything else is a string). This module only
//! assembles the events into a tree that keeps every node's position, and
//! refuses what an object file must not hold:
//!
//! - a key written twice in one mapping (the YAML specification requires
//!   unique keys; equal means the same resolved scalar, so `true` and `True`
//!   collide and `1` and `"1"` do not);
//! - a key that is not a scalar (`? [a, b] : c`);
//! - a tag other than the core schema's (`!!str`, `!!int`, `!!float`,
//!   `!!bool`, `!!null`, `!!seq`, `!!map`) or the non-specific `!`, and a
//!   scalar its core tag does not fit (`!!int abc`);
//! - an alias to its own, unfinished, anchor (a recursive alias);
//! - more than one document;
//! - nesting deeper than [`MAX_DEPTH`].
//!
//! An alias shares its anchor's node ([`Arc`]), so a tree of aliases costs one
//! node per anchor however many times it is used.
//!
//! What this reads differently from the oracle (opentide 0.23.0, PyYAML's YAML
//! 1.1 loader) is the table in `crates/opentide-schema/YAML.md`, generated and
//! checked by `tests/yaml_table.rs` from `tests/oracle/yaml_cases.toml`.
//!
//! Positions are the CLI's: lines and columns from 1, columns in Unicode code
//! points. [`Document::span`] and [`Document::yaml_line`] place a field path.

mod dump;
mod locate;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use saphyr::{Scalar, ScalarStyle, Tag};
use saphyr_parser::{Event, Parser, ScanError};

pub use dump::{DumpError, to_yaml};
pub use locate::{Locator, Span};

/// How deeply collections may nest. A Tide object nests a dozen levels; the
/// bound keeps every walk over a tree (comparison, cloning, writing) far from
/// the stack's limit.
pub const MAX_DEPTH: usize = 512;

/// A position in the document: lines and columns from 1, columns in Unicode
/// code points, as the CLI prints them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Mark {
    /// Offset in the text, in code points.
    pub index: usize,
    /// Line, from 1.
    pub line: usize,
    /// Column, from 1, in code points.
    pub column: usize,
}

impl Mark {
    fn from_saphyr(marker: saphyr::Marker) -> Self {
        Self {
            index: marker.index(),
            line: marker.line(),
            column: marker.col() + 1,
        }
    }
}

/// One node of the tree, where it starts and ends.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The value.
    pub value: Value,
    /// Where the node starts (its anchor or tag, when it has one).
    pub start: Mark,
    /// Where it ends: just after a scalar; at the token after a block
    /// collection.
    pub end: Mark,
}

/// A key and its value in a mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The key node, a scalar.
    pub key: Arc<Node>,
    /// The value node.
    pub value: Arc<Node>,
}

/// A value of the YAML 1.2 core schema.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`, `~` or nothing.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer that fits in 64 bits.
    Int(i64),
    /// A floating-point number, `.inf` and `.nan` included.
    Float(f64),
    /// A string: quoted, or plain text no other type takes (dates included).
    Str(String),
    /// A TOML offset date-time, local date-time, local date or local time, as
    /// written (`1979-05-27T07:32:00Z`). YAML 1.2's core schema has no such
    /// type, so only a configuration file ([`crate::configuration`]) holds
    /// one; a field that takes a string does not take it.
    Datetime(String),
    /// A sequence.
    Seq(Vec<Arc<Node>>),
    /// A mapping, in the document's order, keys unique.
    Map(Vec<Entry>),
}

impl Value {
    /// The type's name in messages: `null`, `boolean`, `integer`, `float`,
    /// `string`, `datetime`, `sequence`, `mapping`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "integer",
            Self::Float(_) => "float",
            Self::Str(_) => "string",
            Self::Datetime(_) => "datetime",
            Self::Seq(_) => "sequence",
            Self::Map(_) => "mapping",
        }
    }

    /// The text, for a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }
}

/// A scalar as YAML 1.2 writes it (`null`, `true`, `12`, `1.5`, `.inf`, the
/// text); a collection as `[...]` or `{...}`. A field path holds a key that
/// is not a string this way.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(flag) => write!(f, "{flag}"),
            Self::Int(integer) => write!(f, "{integer}"),
            Self::Float(float) if float.is_nan() => f.write_str(".nan"),
            Self::Float(float) if float.is_infinite() => {
                f.write_str(if *float > 0.0 { ".inf" } else { "-.inf" })
            }
            Self::Float(float) => write!(f, "{float:?}"),
            Self::Str(text) | Self::Datetime(text) => f.write_str(text),
            Self::Seq(_) => f.write_str("[...]"),
            Self::Map(_) => f.write_str("{...}"),
        }
    }
}

impl Node {
    /// The value of `key` in this mapping (a string key equal to `key`).
    pub fn get(&self, key: &str) -> Option<&Arc<Node>> {
        self.entry(key).map(|entry| &entry.value)
    }

    /// The entry of `key` in this mapping (a string key equal to `key`).
    pub fn entry(&self, key: &str) -> Option<&Entry> {
        match &self.value {
            Value::Map(entries) => entries
                .iter()
                .find(|entry| entry.key.value.as_str() == Some(key)),
            _ => None,
        }
    }

    /// A `null` node at `mark`, for a document with no node.
    pub fn null_at(mark: Mark) -> Self {
        Self {
            value: Value::Null,
            start: mark,
            end: mark,
        }
    }
}

// Children are moved out and dropped one by one, so dropping never recurses.
impl Drop for Node {
    fn drop(&mut self) {
        let mut stack: Vec<Arc<Node>> = Vec::new();
        take_children(&mut self.value, &mut stack);
        while let Some(child) = stack.pop() {
            if let Some(mut node) = Arc::into_inner(child) {
                take_children(&mut node.value, &mut stack);
            }
        }
    }
}

fn take_children(value: &mut Value, stack: &mut Vec<Arc<Node>>) {
    match value {
        Value::Seq(items) => stack.append(items),
        Value::Map(entries) => {
            for entry in entries.drain(..) {
                stack.push(entry.key);
                stack.push(entry.value);
            }
        }
        _ => {}
    }
}

/// Why a document could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadErrorKind {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The text is not YAML (the parser's error).
    Syntax,
    /// A mapping repeats a key.
    DuplicateKey,
    /// A mapping key is a sequence or a mapping.
    ComplexKey,
    /// A tag outside the core schema, or a scalar its core tag does not fit.
    Tag,
    /// An alias inside the node its anchor names.
    RecursiveAlias,
    /// A second document in the stream.
    MultipleDocuments,
    /// Collections nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// An integer that does not fit in 64 bits.
    OutOfRange,
}

/// A document that could not be read, and where.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{problem}")]
pub struct LoadError {
    /// What kind of failure.
    pub kind: LoadErrorKind,
    /// The problem, in words.
    pub problem: String,
    /// Where the problem is, when the text has a place for it.
    pub mark: Option<Mark>,
}

impl LoadError {
    fn new(kind: LoadErrorKind, problem: impl Into<String>, mark: Option<Mark>) -> Self {
        Self {
            kind,
            problem: problem.into(),
            mark,
        }
    }

    fn at(kind: LoadErrorKind, problem: impl Into<String>, mark: Mark) -> Self {
        Self::new(kind, problem, Some(mark))
    }

    fn from_scan(error: &ScanError) -> Self {
        Self::at(
            LoadErrorKind::Syntax,
            error.info(),
            Mark::from_saphyr(*error.marker()),
        )
    }
}

/// A document read from text: the text, for positions, and its root node
/// (`None` for a stream with no document: empty, or only comments).
#[derive(Debug, Clone)]
pub struct Document {
    source: String,
    /// Byte ranges of the lines, computed once: every error's span reads one.
    lines: Vec<(usize, usize)>,
    /// Each line as characters, made the first time a span reads it, so many
    /// errors on one long line (a flow mapping) read it once.
    line_chars: Vec<OnceLock<Box<[char]>>>,
    root: Option<Arc<Node>>,
}

impl Document {
    /// The root node.
    pub fn root(&self) -> Option<&Arc<Node>> {
        self.root.as_ref()
    }

    /// The text the document was read from, without its BOM.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Reads `bytes`: UTF-8, then [`load`].
pub fn load_bytes(bytes: &[u8]) -> Result<Document, LoadError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        LoadError::new(
            LoadErrorKind::NotUtf8,
            format!("not UTF-8 at byte offset {}", error.valid_up_to()),
            None,
        )
    })?;
    load(text)
}

/// Reads `text` as one YAML 1.2 document. One leading byte order mark is
/// dropped first, so positions count from the first character after it.
pub fn load(text: &str) -> Result<Document, LoadError> {
    let source = text.strip_prefix('\u{feff}').unwrap_or(text).to_owned();
    let root = Builder::default().run(&source)?;
    let lines = locate::split_lines(&source);
    let line_chars = std::iter::repeat_with(OnceLock::new)
        .take(lines.len())
        .collect();
    Ok(Document {
        source,
        lines,
        line_chars,
        root,
    })
}

/// A collection being built.
#[derive(Debug)]
enum Frame {
    Seq {
        anchor: usize,
        start: Mark,
        items: Vec<Arc<Node>>,
    },
    Map {
        anchor: usize,
        start: Mark,
        entries: Vec<Entry>,
        key: Option<Arc<Node>>,
        /// The keys so far, each with the line it is first written on, so a
        /// repeated key is found in constant time.
        seen: HashMap<KeyId, usize>,
    },
}

/// A mapping key's identity: two keys are the same key when they are the
/// same type and value, as the YAML specification defines node equality
/// (floats by their bits, so `.nan` equals itself).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum KeyId {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(String),
}

impl KeyId {
    /// The key's identity; `None` for a collection, which is never a key.
    fn of(value: &Value) -> Option<Self> {
        Some(match value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Int(integer) => Self::Int(*integer),
            Value::Float(float) => Self::Float(float.to_bits()),
            Value::Str(text) => Self::Str(text.clone()),
            Value::Seq(_) | Value::Map(_) | Value::Datetime(_) => return None,
        })
    }
}

/// Assembles saphyr-parser's events into nodes, in one iterative pass.
#[derive(Debug, Default)]
struct Builder {
    frames: Vec<Frame>,
    /// Finished anchored nodes, by the parser's anchor id.
    anchors: HashMap<usize, Arc<Node>>,
    documents: usize,
    root: Option<Arc<Node>>,
}

/// The core-schema type a tag names (`!!int`, or verbatim
/// `!<tag:yaml.org,2002:int>`), if it is one.
fn core_suffix(tag: &Tag) -> Option<&str> {
    if tag.is_yaml_core_schema() {
        return Some(&tag.suffix);
    }
    if tag.handle.is_empty() {
        return tag.suffix.strip_prefix("tag:yaml.org,2002:");
    }
    None
}

/// The non-specific tag `!`, which makes a scalar a string.
fn is_non_specific(tag: &Tag) -> bool {
    tag.handle.is_empty() && tag.suffix == "!"
}

/// A tag as it is written: `!!int`, `!local`, `!<uri>`.
fn tag_text(tag: &Tag) -> String {
    if let Some(suffix) = core_suffix(tag) {
        format!("!!{suffix}")
    } else if tag.handle.is_empty() {
        format!("!<{}>", tag.suffix)
    } else if tag.handle == "!" {
        format!("!{}", tag.suffix)
    } else {
        format!("{}{}", tag.handle, tag.suffix)
    }
}

/// Whether a collection may carry `tag`: none, `!`, or its own core tag.
fn collection_tag_fits(tag: Option<&Cow<'_, Tag>>, suffix: &str) -> Result<(), String> {
    match tag.map(Cow::as_ref) {
        None => Ok(()),
        Some(tag) if is_non_specific(tag) || core_suffix(tag) == Some(suffix) => Ok(()),
        Some(tag) => Err(format!(
            "the tag {} cannot be used on a {}",
            tag_text(tag),
            if suffix == "seq" {
                "sequence"
            } else {
                "mapping"
            }
        )),
    }
}

/// A scalar's value under the core schema, or why its tag refuses it.
///
/// Untagged, saphyr's [`Scalar`] resolves it (a quoted scalar is a string).
/// With a core tag, the text is resolved as a plain scalar would be and must
/// give the tag's type (`!!int "42"` is 42, `!!int abc` is refused); an
/// integer is a valid `!!float`.
fn scalar_value(
    text: Cow<'_, str>,
    style: ScalarStyle,
    tag: Option<&Tag>,
) -> Result<Value, String> {
    let Some(tag) = tag else {
        if style != ScalarStyle::Plain {
            return Ok(
                match Scalar::parse_from_cow_and_metadata(text, style, None) {
                    Some(scalar) => from_scalar(scalar),
                    None => Value::Null,
                },
            );
        }
        let plain_integer = is_core_integer(&text);
        let value = resolve_plain(text);
        if plain_integer && !matches!(value, Value::Int(_)) {
            return Err(OUT_OF_RANGE.to_owned());
        }
        return Ok(value);
    };
    if is_non_specific(tag) {
        return Ok(Value::Str(text.into_owned()));
    }
    let Some(suffix) = core_suffix(tag) else {
        return Err(format!("the tag {} is not supported", tag_text(tag)));
    };
    if suffix == "str" {
        return Ok(Value::Str(text.into_owned()));
    }
    let shown = text.clone().into_owned();
    let resolved = resolve_plain(text);
    match (suffix, resolved) {
        ("int", value @ Value::Int(_))
        | ("float", value @ Value::Float(_))
        | ("bool", value @ Value::Bool(_))
        | ("null", value @ Value::Null) => Ok(value),
        #[expect(
            clippy::cast_precision_loss,
            reason = "`!!float 1` is the float nearest the integer"
        )]
        ("float", Value::Int(integer)) => Ok(Value::Float(integer as f64)),
        ("int" | "float" | "bool" | "null", _) => Err(format!(
            "'{shown}' is not a valid value for the tag {}",
            tag_text(tag)
        )),
        _ => Err(format!("the tag {} is not supported", tag_text(tag))),
    }
}

/// A plain scalar's value under the core schema: saphyr's resolution, except
/// that an integer must be written as the core schema writes one. saphyr
/// parses `0x`/`0o` digits with Rust's `from_str_radix`, which takes a sign
/// after the prefix (`0x-A`, `0o+7`); the core schema does not, so that text
/// is a string. An empty scalar is `null`.
fn resolve_plain(text: Cow<'_, str>) -> Value {
    if text.is_empty() {
        return Value::Null;
    }
    if is_core_integer(&text) {
        return from_scalar(Scalar::parse_from_cow(text));
    }
    match from_scalar(Scalar::parse_from_cow(Cow::Borrowed(text.as_ref()))) {
        Value::Int(_) => Value::Str(text.into_owned()),
        value => value,
    }
}

const OUT_OF_RANGE: &str = "the integer does not fit in 64 bits";

/// Whether `text` is an integer of the core schema (`[-+]?[0-9]+`,
/// `0o[0-7]+`, `0x[0-9a-fA-F]+`). saphyr reads one beyond 64 bits as an
/// approximate float, or as a string; the loader refuses it instead.
fn is_core_integer(text: &str) -> bool {
    let all = |digits: &str, valid: fn(&u8) -> bool| {
        !digits.is_empty() && digits.bytes().all(|b| valid(&b))
    };
    if let Some(digits) = text.strip_prefix("0o") {
        return all(digits, u8::is_ascii_digit) && !digits.contains(['8', '9']);
    }
    if let Some(digits) = text.strip_prefix("0x") {
        return all(digits, u8::is_ascii_hexdigit);
    }
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    all(digits, u8::is_ascii_digit)
}

fn from_scalar(scalar: Scalar<'_>) -> Value {
    match scalar {
        Scalar::Null => Value::Null,
        Scalar::Boolean(flag) => Value::Bool(flag),
        Scalar::Integer(integer) => Value::Int(integer),
        Scalar::FloatingPoint(float) => Value::Float(float.into_inner()),
        Scalar::String(text) => Value::Str(text.into_owned()),
    }
}

/// The first character YAML 1.2 does not allow in a stream (§5.1: C0
/// controls other than tab and line breaks, DEL, C1 controls other than NEL,
/// U+FFFE and U+FFFF), with its position. saphyr reads them as text.
fn non_printable(source: &str) -> Option<(char, Mark)> {
    let mut line = 1;
    let mut column = 1;
    let mut previous = '\0';
    for (index, character) in source.chars().enumerate() {
        let printable = matches!(character, '\t' | '\n' | '\r' | '\u{85}')
            || ('\u{20}'..='\u{7e}').contains(&character)
            || ('\u{a0}'..='\u{d7ff}').contains(&character)
            || ('\u{e000}'..='\u{fffd}').contains(&character)
            || character >= '\u{10000}';
        if !printable {
            return Some((
                character,
                Mark {
                    index,
                    line,
                    column,
                },
            ));
        }
        match character {
            // The `\n` of a `\r\n`: the `\r` broke the line already.
            '\n' if previous == '\r' => {}
            '\n' | '\r' => {
                line += 1;
                column = 1;
            }
            _ => column += 1,
        }
        previous = character;
    }
    None
}

impl Builder {
    fn run(mut self, source: &str) -> Result<Option<Arc<Node>>, LoadError> {
        if let Some((character, mark)) = non_printable(source) {
            return Err(LoadError::at(
                LoadErrorKind::Syntax,
                format!(
                    "the character U+{:04X} is not allowed in YAML",
                    u32::from(character)
                ),
                mark,
            ));
        }
        // A block scalar that ends the file without a line break: saphyr
        // adds one, which the YAML specification's chomping (§8.1.1.2: the
        // end of the file instead of a final line break) does not.
        // Only when the scalar's last content line is that unterminated last
        // line: after a final line break, or a last line of blanks only (the
        // scalar's trailing indentation), saphyr's line break is the
        // scalar's own.
        let length = source.chars().count();
        let last_line = source.rsplit(['\n', '\r']).next().unwrap_or_default();
        let unterminated_content = !last_line.trim_matches([' ', '\t']).is_empty();
        for event in Parser::new_from_str(source) {
            let (event, span) = event.map_err(|error| LoadError::from_scan(&error))?;
            let start = Mark::from_saphyr(span.start);
            let end = Mark::from_saphyr(span.end);
            match event {
                Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
                Event::DocumentStart(_) => {
                    self.documents += 1;
                    if self.documents > 1 {
                        return Err(LoadError::at(
                            LoadErrorKind::MultipleDocuments,
                            "a file holds one YAML document; a second one starts here",
                            start,
                        ));
                    }
                }
                Event::Scalar(text, style, anchor, tag) => {
                    let mut value =
                        scalar_value(text, style, tag.as_deref()).map_err(|problem| {
                            let kind = if problem == OUT_OF_RANGE {
                                LoadErrorKind::OutOfRange
                            } else {
                                LoadErrorKind::Tag
                            };
                            LoadError::at(kind, problem, start)
                        })?;
                    if matches!(style, ScalarStyle::Literal | ScalarStyle::Folded)
                        && unterminated_content
                        && end.index == length
                        && let Value::Str(text) = &mut value
                        && text.ends_with('\n')
                    {
                        text.pop();
                    }
                    self.finish(Node { value, start, end }, anchor)?;
                }
                Event::Alias(id) => {
                    let Some(node) = self.anchors.get(&id).cloned() else {
                        return Err(LoadError::at(
                            LoadErrorKind::RecursiveAlias,
                            "an alias cannot refer to the node that contains it",
                            start,
                        ));
                    };
                    self.attach(node, start)?;
                }
                Event::SequenceStart(anchor, tag) => {
                    collection_tag_fits(tag.as_ref(), "seq")
                        .map_err(|problem| LoadError::at(LoadErrorKind::Tag, problem, start))?;
                    self.open(
                        Frame::Seq {
                            anchor,
                            start,
                            items: Vec::new(),
                        },
                        start,
                    )?;
                }
                Event::MappingStart(anchor, tag) => {
                    collection_tag_fits(tag.as_ref(), "map")
                        .map_err(|problem| LoadError::at(LoadErrorKind::Tag, problem, start))?;
                    self.open(
                        Frame::Map {
                            anchor,
                            start,
                            entries: Vec::new(),
                            key: None,
                            seen: HashMap::new(),
                        },
                        start,
                    )?;
                }
                Event::SequenceEnd | Event::MappingEnd => {
                    let (node, anchor) = match self.frames.pop() {
                        Some(Frame::Seq {
                            anchor,
                            start,
                            items,
                        }) => (
                            Node {
                                value: Value::Seq(items),
                                start,
                                end,
                            },
                            anchor,
                        ),
                        Some(Frame::Map {
                            anchor,
                            start,
                            entries,
                            ..
                        }) => (
                            Node {
                                value: Value::Map(entries),
                                start,
                                end,
                            },
                            anchor,
                        ),
                        // The parser pairs every end with its start.
                        None => continue,
                    };
                    self.finish(node, anchor)?;
                }
            }
        }
        Ok(self.root)
    }

    fn open(&mut self, frame: Frame, start: Mark) -> Result<(), LoadError> {
        if self.frames.len() >= MAX_DEPTH {
            return Err(LoadError::at(
                LoadErrorKind::TooDeep,
                format!("collections nest deeper than {MAX_DEPTH} levels"),
                start,
            ));
        }
        self.frames.push(frame);
        Ok(())
    }

    fn finish(&mut self, node: Node, anchor: usize) -> Result<(), LoadError> {
        let start = node.start;
        let node = Arc::new(node);
        // Anchor ids start at 1; 0 is no anchor. A later anchor of the same
        // name gets a new id from the parser.
        if anchor > 0 {
            self.anchors.insert(anchor, Arc::clone(&node));
        }
        self.attach(node, start)
    }

    fn attach(&mut self, node: Arc<Node>, start: Mark) -> Result<(), LoadError> {
        match self.frames.last_mut() {
            None => self.root = Some(node),
            Some(Frame::Seq { items, .. }) => items.push(node),
            Some(Frame::Map {
                entries, key, seen, ..
            }) => match key.take() {
                None => {
                    let Some(id) = KeyId::of(&node.value) else {
                        return Err(LoadError::at(
                            LoadErrorKind::ComplexKey,
                            "a mapping key must be a scalar, not a sequence or a mapping",
                            start,
                        ));
                    };
                    match seen.entry(id) {
                        std::collections::hash_map::Entry::Occupied(first) => {
                            return Err(LoadError::at(
                                LoadErrorKind::DuplicateKey,
                                format!(
                                    "the key '{}' is repeated; it is first written on line {}",
                                    node.value,
                                    first.get()
                                ),
                                start,
                            ));
                        }
                        std::collections::hash_map::Entry::Vacant(slot) => {
                            slot.insert(node.start.line);
                        }
                    }
                    *key = Some(node);
                }
                Some(key_node) => entries.push(Entry {
                    key: key_node,
                    value: node,
                }),
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_nesting_is_refused_without_recursion() {
        // saphyr-parser stops flow collections at 256 levels itself.
        let flow = format!("{}{}", "[".repeat(20_000), "]".repeat(20_000));
        assert_eq!(load(&flow).unwrap_err().kind, LoadErrorKind::Syntax);
        // Block sequences, `- - - x`, are bounded here.
        let block = format!("{}x\n", "- ".repeat(MAX_DEPTH + 1));
        assert_eq!(load(&block).unwrap_err().kind, LoadErrorKind::TooDeep);
        let ok = format!("{}x\n", "- ".repeat(MAX_DEPTH));
        drop(load(&ok).unwrap());
    }

    #[test]
    fn aliases_share_one_node() {
        let document = load("a: &x [1, 2]\nb: *x\n").unwrap();
        let root = document.root().unwrap();
        assert!(Arc::ptr_eq(root.get("a").unwrap(), root.get("b").unwrap()));
    }

    #[test]
    fn a_recursive_alias_is_refused() {
        let error = load("a: &x [*x]\n").unwrap_err();
        assert_eq!(error.kind, LoadErrorKind::RecursiveAlias);
    }

    #[test]
    fn keys_are_equal_by_type_and_value() {
        let same_key = |a: &Value, b: &Value| KeyId::of(a).is_some_and(|a| Some(a) == KeyId::of(b));
        assert!(same_key(&Value::Bool(true), &Value::Bool(true)));
        assert!(!same_key(&Value::Bool(true), &Value::Int(1)));
        assert!(!same_key(&Value::Float(1.0), &Value::Int(1)));
        assert!(same_key(&Value::Float(f64::NAN), &Value::Float(f64::NAN)));
        assert!(!same_key(&Value::Float(0.0), &Value::Float(-0.0)));
        assert!(!same_key(&Value::Str("1".into()), &Value::Int(1)));
        assert!(!same_key(&Value::Seq(Vec::new()), &Value::Seq(Vec::new())));
        let error = load("true: 1\nTrue: 2\n").unwrap_err();
        assert_eq!(error.kind, LoadErrorKind::DuplicateKey);
        assert_eq!(error.mark.map(|m| (m.line, m.column)), Some((2, 1)));
        assert!(error.problem.contains("first written on line 1"), "{error}");
    }

    #[test]
    fn a_large_mapping_loads_in_linear_time() {
        // A linear scan per key took 22 s for 40 000 keys in a debug build;
        // with a hash set this takes well under a second.
        let mut text = String::new();
        for key in 0..200_000 {
            text.push_str(&format!("k{key}: {key}\n"));
        }
        let started = std::time::Instant::now();
        let document = load(&text).unwrap();
        let elapsed = started.elapsed();
        let Value::Map(entries) = &document.root().unwrap().value else {
            panic!()
        };
        assert_eq!(entries.len(), 200_000);
        assert!(elapsed.as_secs() < 30, "{elapsed:?}");
        text.push_str("k123456: again\n");
        let error = load(&text).unwrap_err();
        assert_eq!(error.kind, LoadErrorKind::DuplicateKey);
        assert!(
            error.problem.contains("first written on line 123457"),
            "{error}"
        );
    }

    #[test]
    fn positions_are_one_based_code_points() {
        let document = load("é: 1\nb: [x, 'y']\n").unwrap();
        let root = document.root().unwrap();
        let b = root.get("b").unwrap();
        let Value::Seq(items) = &b.value else {
            panic!("{b:?}")
        };
        assert_eq!((items[1].start.line, items[1].start.column), (2, 8));
        assert_eq!((items[1].end.line, items[1].end.column), (2, 11));
        let one = root.get("é").unwrap();
        assert_eq!((one.start.line, one.start.column), (1, 4));
    }

    fn value_of(text: &str) -> Value {
        load(text)
            .unwrap()
            .root()
            .unwrap()
            .get("a")
            .unwrap()
            .value
            .clone()
    }

    #[test]
    fn a_sign_after_the_base_prefix_is_a_string() {
        for text in [
            "0x-A",
            "0x+A",
            "0o-7",
            "0o+7",
            "0x-8000000000000000",
            "-0x1",
        ] {
            assert_eq!(
                value_of(&format!("a: {text}\n")),
                Value::Str(text.to_owned()),
                "{text}"
            );
        }
        assert_eq!(value_of("a: 0x1F\n"), Value::Int(31));
        assert_eq!(value_of("a: 0o17\n"), Value::Int(15));
        assert_eq!(value_of("a: +12\n"), Value::Int(12));
        for text in ["a: !!int 0x-A\n", "a: !!int 0o+7\n", "a: !!float 0x-A\n"] {
            let error = load(text).unwrap_err();
            assert_eq!(error.kind, LoadErrorKind::Tag, "{text}");
        }
        assert_eq!(value_of("a: !!int 0x10\n"), Value::Int(16));
    }

    #[test]
    fn an_integer_beyond_64_bits_is_out_of_range() {
        for text in [
            "a: 12345678901234567890\n",
            "a: -9223372036854775809\n",
            "a: 0xFFFFFFFFFFFFFFFFFFFF\n",
        ] {
            let error = load(text).unwrap_err();
            assert_eq!(error.kind, LoadErrorKind::OutOfRange, "{text}");
            assert_eq!(error.problem, OUT_OF_RANGE);
            assert_eq!(error.mark.map(|m| (m.line, m.column)), Some((1, 4)));
        }
    }

    #[test]
    fn a_forbidden_character_is_placed_by_line_and_column() {
        let error = load("a: 1\r\nb: 2\r\nc: x\u{1}\r\n").unwrap_err();
        assert_eq!(error.kind, LoadErrorKind::Syntax);
        let mark = error.mark.unwrap();
        assert_eq!((mark.line, mark.column, mark.index), (3, 5, 16));
        let error = load("a: 1\rb: \u{7f}\n").unwrap_err();
        let mark = error.mark.unwrap();
        assert_eq!((mark.line, mark.column), (2, 4));
    }

    #[test]
    fn a_block_scalar_keeps_its_line_break_before_a_last_blank_line() {
        for (text, expected) in [
            ("a: |\n  x\n ", "x\n"),
            ("a: >\n  x\n ", "x\n"),
            ("a: |\n  x\n  y\n ", "x\ny\n"),
            ("a: |\n  x\r\n ", "x\n"),
            ("a: |\n  x\n\t", "x\n"),
            ("a: |\n  x\nb: 1", "x\n"),
            ("a: |\n  x\n# c", "x\n"),
            ("a: |\n  x", "x"),
            ("a: |\n  x\n  y", "x\ny"),
            ("a: >\n  x\n  y", "x y"),
        ] {
            assert_eq!(value_of(text), Value::Str(expected.to_owned()), "{text:?}");
        }
        let document = load("- |\n  x\n ").unwrap();
        let Value::Seq(items) = &document.root().unwrap().value else {
            panic!()
        };
        assert_eq!(items[0].value, Value::Str("x\n".to_owned()));
    }

    #[test]
    fn display_writes_yaml_scalars() {
        assert_eq!(Value::Null.to_string(), "null");
        assert_eq!(Value::Bool(true).to_string(), "true");
        assert_eq!(Value::Float(1.0).to_string(), "1.0");
        assert_eq!(Value::Float(f64::NEG_INFINITY).to_string(), "-.inf");
        assert_eq!(Value::Float(f64::NAN).to_string(), ".nan");
    }
}
