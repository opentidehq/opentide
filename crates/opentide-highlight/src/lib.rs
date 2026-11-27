//! Frozen HighlightSpec and semantic-token encoding.
//!
//! Capture rename in `highlights/spec.toml` is a **major** (breaking) change.
//! Adding captures is a minor.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]

mod function_names;
mod keywords;
mod markdown;
mod tide_grammar;
mod tide_model;
pub use tide_grammar::{
    KEY_VALUE_SCOPE, LIST_DASH_SCOPE, LSP_TYPE_SCOPES, block_text_scope, capture_base_scope,
    construct_captures, construct_scope, plain_value_scope,
};
mod tm_extras;

use opentide_core::{ByteSpan, LanguageId, LineIndex, Range};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use thiserror::Error;

pub use keywords::{Capture, Keywords, keywords};
pub use markdown::highlight_markdown_line;
use tide_model::Repr;
pub use tide_model::{Choices, TideField, TideSchemaRoot};
use tide_model::{StoredCatalog, TideFieldsFile};

pub fn spec_toml() -> &'static str {
    opentide_dataset::text!("highlights/spec.toml")
}
/// Tide field catalog generated from the Rust models (`cargo xtask codegen`).
pub fn tide_fields_json() -> &'static str {
    opentide_dataset::text!("data/catalogs/tide/generated/fields.json")
}
#[derive(Debug, Error)]
pub enum HighlightError {
    #[error("highlight spec: {0}")]
    Spec(String),
    #[error("unknown capture '{0}' (not in highlights/spec.toml)")]
    UnknownCapture(String),
    #[error("tide field catalog: {0}")]
    Catalog(String),
}

#[derive(Debug, Clone, Deserialize)]
struct SpecFile {
    meta: SpecMeta,
    captures: BTreeMap<String, CaptureMaps>,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecMeta {
    id: String,
    version: String,
    legend: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureMaps {
    pub tm: String,
    pub monaco: String,
    pub helix: String,
}

#[derive(Debug, Clone)]
pub struct HighlightSpec {
    pub id: String,
    pub version: String,
    pub legend: Vec<String>,
    pub captures: BTreeMap<String, CaptureMaps>,
}

impl HighlightSpec {
    /// A copy of the compiled-in spec ([`HighlightSpec::shared`]).
    pub fn load() -> Result<Self, HighlightError> {
        Self::shared().cloned()
    }

    /// The compiled-in spec (`highlights/spec.toml`), parsed once per
    /// process and borrowed: a copy per analysis, its maps of every capture
    /// cloned, was a few percent of a short query's analysis in every
    /// language.
    pub fn shared() -> Result<&'static Self, HighlightError> {
        static SPEC: OnceLock<HighlightSpec> = OnceLock::new();
        if let Some(spec) = SPEC.get() {
            return Ok(spec);
        }
        let file: SpecFile =
            toml::from_str(spec_toml()).map_err(|e| HighlightError::Spec(e.to_string()))?;
        if file.meta.legend.is_empty() {
            return Err(HighlightError::Spec("empty legend".into()));
        }
        for name in &file.meta.legend {
            if !file.captures.contains_key(name) {
                return Err(HighlightError::Spec(format!(
                    "legend entry '{name}' has no [captures] maps"
                )));
            }
        }
        let spec = Self {
            id: file.meta.id,
            version: file.meta.version,
            legend: file.meta.legend,
            captures: file.captures,
        };
        Ok(SPEC.get_or_init(|| spec))
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "an index into the spec's token types, a few dozen"
    )]
    pub fn token_index(&self, capture: &str) -> Result<u32, HighlightError> {
        self.legend
            .iter()
            .position(|n| n == capture)
            .map(|i| i as u32)
            .ok_or_else(|| HighlightError::UnknownCapture(capture.to_string()))
    }

    pub fn contains_capture(&self, capture: &str) -> bool {
        self.captures.contains_key(capture)
    }
}

struct TideCatalog {
    opentide: String,
    fields: Vec<TideField>,
    schemas: BTreeMap<String, TideSchemaRoot>,
    by_path: BTreeMap<String, BTreeMap<String, usize>>,
    children: BTreeMap<String, BTreeMap<String, Vec<usize>>>,
    /// Family → its newest schema id in the catalog.
    newest: BTreeMap<String, String>,
}

impl TideCatalog {
    /// The catalog key for `schema`: the schema id itself when the catalog
    /// has it; a family key (older catalogs); else the family's newest
    /// revision, so an unknown revision or a bare family still resolves.
    fn resolve<'a>(&'a self, schema: &'a str) -> Option<&'a str> {
        if self.by_path.contains_key(schema) {
            return Some(schema);
        }
        let family = schema.split("::").next().unwrap_or(schema);
        if self.by_path.contains_key(family) {
            return Some(family);
        }
        self.newest.get(family).map(String::as_str)
    }
}

fn revision_key(schema_id: &str) -> Vec<u32> {
    schema_id
        .split_once("::")
        .map(|(_, revision)| {
            revision
                .split('.')
                .map(|part| part.parse().unwrap_or(0))
                .collect()
        })
        .unwrap_or_default()
}

fn build_tide_catalog(json: &str) -> Result<TideCatalog, String> {
    let file: TideFieldsFile = serde_json::from_str(json).map_err(|err| err.to_string())?;
    Ok(catalog_of(file))
}

impl StoredCatalog {
    /// The catalog this stores, as `fields.json` holds it.
    pub fn expand(self) -> TideFieldsFile {
        let text = |at: u32| self.strings[at as usize].clone();
        let fields = self
            .fields
            .iter()
            .map(|f| TideField {
                schema: text(f.schema),
                path: text(f.path),
                name: text(f.name),
                title: text(f.title),
                description: text(f.description),
                type_name: text(f.type_name),
                required: f.required,
                markdown: f.markdown,
                hidden: f.hidden,
                capture: text(f.capture),
                enum_values: f
                    .choices
                    .checked_sub(1)
                    .map_or_else(Choices::default, |at| Choices(Repr::Bundled(at))),
                enum_docs: f.enum_docs.iter().map(|&i| text(i)).collect(),
                // Stored apart ([`tide_field_vocab`]).
                vocab: Vec::new(),
                vocab_scoped: false,
                ref_kind: f.ref_kind.map(text),
                const_value: f.const_value.map(text),
                array: f.array,
                default_value: f.default_value.map(text),
                min_items: f.min_items,
                recommended: f.recommended,
                closed: f.closed,
                legacy: f
                    .legacy
                    .iter()
                    .map(|&(key, value)| (text(key), value.map(text)))
                    .collect(),
            })
            .collect();
        TideFieldsFile {
            opentide: self.opentide,
            schemas: self.schemas,
            fields,
        }
    }
}

/// The bundled catalog's lists of enum values, decoded when one is first read.
fn bundled_choices() -> &'static [Arc<[String]>] {
    static CHOICES: OnceLock<Vec<Arc<[String]>>> = OnceLock::new();
    CHOICES.get_or_init(|| {
        opentide_dataset::compiled_value::<Vec<Vec<String>>>(
            "tide-choices",
            opentide_dataset::blob!("tide-choices"),
        )
        .into_iter()
        .map(Arc::from)
        .collect()
    })
}

impl std::ops::Deref for Choices {
    type Target = [String];

    fn deref(&self) -> &[String] {
        match &self.0 {
            Repr::Own(list) => list,
            // The crate makes every place from the table's own ids; a place past it is no list.
            Repr::Bundled(at) => bundled_choices()
                .get(*at as usize)
                .map_or(&[][..], |list| &list[..]),
        }
    }
}

/// The bundled catalog, pre-parsed by `build.rs` (#1743): each string stored once, given back to
/// each field that has it here.
fn bundled_file() -> TideFieldsFile {
    opentide_dataset::compiled_value::<StoredCatalog>(
        "tide-fields",
        opentide_dataset::blob!("tide-fields"),
    )
    .expand()
}

fn catalog_of(file: TideFieldsFile) -> TideCatalog {
    let mut by_path: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut children: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    for (i, field) in file.fields.iter().enumerate() {
        by_path
            .entry(field.schema.clone())
            .or_default()
            .insert(field.path.clone(), i);
        let parent = match field.path.rsplit_once('.') {
            Some((parent, _)) => parent.to_string(),
            None => String::new(),
        };
        children
            .entry(field.schema.clone())
            .or_default()
            .entry(parent)
            .or_default()
            .push(i);
    }
    let mut newest: BTreeMap<String, String> = BTreeMap::new();
    for schema in by_path.keys() {
        let Some((family, _)) = schema.split_once("::") else {
            continue;
        };
        let replace = newest
            .get(family)
            .is_none_or(|current| revision_key(schema) > revision_key(current));
        if replace {
            newest.insert(family.to_string(), schema.clone());
        }
    }
    TideCatalog {
        opentide: file.opentide,
        fields: file.fields,
        schemas: file.schemas,
        by_path,
        children,
        newest,
    }
}

fn bundled_tide_catalog() -> &'static TideCatalog {
    static CATALOG: OnceLock<TideCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| catalog_of(bundled_file()))
}

/// The workspace catalog a host installed, and the text it was built from.
type InstalledCatalog = Option<(&'static TideCatalog, u64)>;

fn installed_tide_catalog() -> &'static RwLock<InstalledCatalog> {
    static INSTALLED: OnceLock<RwLock<InstalledCatalog>> = OnceLock::new();
    INSTALLED.get_or_init(|| RwLock::new(None))
}

/// The catalog a host set in place of the bundled one ([`set_default_tide_fields`]).
fn default_tide_catalog() -> &'static RwLock<Option<&'static TideCatalog>> {
    static DEFAULT: OnceLock<RwLock<Option<&'static TideCatalog>>> = OnceLock::new();
    DEFAULT.get_or_init(|| RwLock::new(None))
}

thread_local! {
    /// The catalog this thread uses instead of the installed one
    /// ([`scope_tide_fields`]).
    static SCOPED_TIDE_CATALOG: std::cell::Cell<Scoped> =
        const { std::cell::Cell::new(Scoped::None) };
}

/// A thread's own field catalog ([`scope_tide_fields`]).
#[derive(Clone, Copy)]
enum Scoped {
    /// None: the installed one, else the host's, else the bundled one.
    None,
    /// The host's or the bundled one, whatever is installed.
    Default,
    /// A workspace's.
    Workspace(&'static TideCatalog),
}

/// While it lives, the Tide field catalog of [`scope_tide_fields`] is the one
/// its thread uses; dropping it gives back what the thread used before.
#[must_use = "dropping it at once ends the scope at once"]
pub struct TideFieldsScope {
    previous: Scoped,
    /// Not `Send`: the scope belongs to its thread.
    _thread: std::marker::PhantomData<*const ()>,
}

impl Drop for TideFieldsScope {
    fn drop(&mut self) {
        SCOPED_TIDE_CATALOG.with(|scoped| scoped.set(self.previous));
    }
}

/// Use the catalog `json` describes (a workspace's `fields.json`, as for
/// [`install_tide_fields`]) on this thread only, whatever is installed,
/// until the returned scope drops (#1142): a run that reads a workspace's
/// catalog leaves the process's as it is. `None` uses the host's
/// ([`set_default_tide_fields`]) or the bundled one, as
/// `install_tide_fields(None)` makes them current.
///
/// # Errors
///
/// `json` is not a field catalog; nothing changes.
pub fn scope_tide_fields(json: Option<&str>) -> Result<TideFieldsScope, HighlightError> {
    let catalog = match json.map(built_tide_catalog).transpose()? {
        Some(catalog) => Scoped::Workspace(catalog),
        None => Scoped::Default,
    };
    let previous = SCOPED_TIDE_CATALOG.with(|scoped| scoped.replace(catalog));
    Ok(TideFieldsScope {
        previous,
        _thread: std::marker::PhantomData,
    })
}

fn tide_catalog() -> &'static TideCatalog {
    match SCOPED_TIDE_CATALOG.with(std::cell::Cell::get) {
        Scoped::Workspace(catalog) => return catalog,
        Scoped::Default => {}
        Scoped::None => {
            let installed = installed_tide_catalog()
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((catalog, _)) = *installed {
                return catalog;
            }
        }
    }
    let default = default_tide_catalog()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    default.unwrap_or_else(bundled_tide_catalog)
}

fn text_hash(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Replace the bundled Tide field catalog with a workspace one: a
/// `fields.json` in the shape of `data/catalogs/tide/generated/fields.json`, as
/// `opentide generate schemas` writes it to `.opentide/lsp/catalogs/generated/`.
/// `None` goes back to the bundled catalog. Process-wide: every thread sees it.
///
/// Fields are handed out as `&'static`, so each distinct catalog is kept for
/// the life of the process. A catalog is built once per distinct text, so a
/// host may install on every workspace load without growing memory.
pub fn install_tide_fields(json: Option<&str>) -> Result<(), HighlightError> {
    let mut installed = installed_tide_catalog()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(json) = json else {
        *installed = None;
        return Ok(());
    };
    let hash = text_hash(json);
    *installed = Some((built_tide_catalog(json)?, hash));
    Ok(())
}

/// The catalog built from `json`, built once per distinct text and kept for
/// the life of the process (its fields are handed out as `&'static`).
fn built_tide_catalog(json: &str) -> Result<&'static TideCatalog, HighlightError> {
    let hash = text_hash(json);
    static BUILT: OnceLock<Mutex<Vec<(u64, &'static TideCatalog)>>> = OnceLock::new();
    let mut built = BUILT
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, catalog)) = built.iter().find(|(seen, _)| *seen == hash) {
        return Ok(catalog);
    }
    let catalog = build_tide_catalog(json).map_err(HighlightError::Catalog)?;
    if catalog.fields.is_empty() {
        return Err(HighlightError::Catalog(
            "fields.json lists no fields".into(),
        ));
    }
    let catalog: &'static TideCatalog = Box::leak(Box::new(catalog));
    built.push((hash, catalog));
    Ok(catalog)
}

/// Use `json` instead of the bundled catalog whenever no workspace catalog is
/// installed ([`install_tide_fields`]): a host that generates the catalog
/// from its own models (opentide) is never behind the snapshot compiled in.
/// `None` goes back to the bundled catalog. Process-wide.
pub fn set_default_tide_fields(json: Option<&str>) -> Result<(), HighlightError> {
    let catalog = json.map(built_tide_catalog).transpose()?;
    *default_tide_catalog()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = catalog;
    Ok(())
}

/// Whether the Tide field catalog in use is a workspace one
/// ([`install_tide_fields`], or this thread's [`scope_tide_fields`]) rather
/// than the bundled snapshot.
pub fn tide_catalog_is_workspace() -> bool {
    match SCOPED_TIDE_CATALOG.with(std::cell::Cell::get) {
        Scoped::Workspace(_) => true,
        Scoped::Default => false,
        Scoped::None => installed_tide_catalog()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some(),
    }
}

pub fn tide_catalog_version() -> &'static str {
    tide_catalog().opentide.as_str()
}

pub fn load_tide_fields() -> Vec<&'static TideField> {
    tide_catalog().fields.iter().collect()
}

/// Field at `schema` and dotted YAML path. `schema` is the object's schema
/// id (`rule::1.0`), or a family (`rule`) for its newest revision.
pub fn tide_field_at(schema: &str, path: &str) -> Option<&'static TideField> {
    let catalog = tide_catalog();
    let key = catalog.resolve(schema)?;
    let index = *catalog.by_path.get(key)?.get(path)?;
    catalog.fields.get(index)
}

/// The bundled fields' vocabularies by schema and path: the references, and whether the values
/// carry their stage.
type BundledVocabs = BTreeMap<String, BTreeMap<String, (Vec<String>, bool)>>;

/// The vocabularies `field`'s values come from (the references it names, `att&ck::1.2`) and
/// whether its values carry their first stage: its own, as a catalog file gave them, or for a field
/// of the bundled catalog, which stores them apart, those of the bundled field at its schema and
/// path. Empty for a field that names none.
pub fn tide_field_vocab(field: &TideField) -> (&[String], bool) {
    if !field.vocab.is_empty() {
        return (&field.vocab, field.vocab_scoped);
    }
    static BUNDLED: OnceLock<BundledVocabs> = OnceLock::new();
    let bundled = BUNDLED.get_or_init(|| {
        let mut map = BundledVocabs::new();
        for vocab in opentide_dataset::compiled_value::<Vec<tide_model::StoredVocab>>(
            "tide-vocabs",
            opentide_dataset::blob!("tide-vocabs"),
        ) {
            map.entry(vocab.schema)
                .or_default()
                .insert(vocab.path, (vocab.references, vocab.scoped));
        }
        map
    });
    bundled
        .get(&field.schema)
        .and_then(|paths| paths.get(&field.path))
        .map_or((&[], false), |(references, scoped)| {
            (references.as_slice(), *scoped)
        })
}

/// Every field of `schema`'s revision (see [`tide_field_at`]), in catalog order.
pub fn tide_fields_of(schema: &str) -> Vec<&'static TideField> {
    let catalog = tide_catalog();
    let Some(key) = catalog.resolve(schema) else {
        return Vec::new();
    };
    let mut indexes: Vec<usize> = catalog
        .by_path
        .get(key)
        .map(|paths| paths.values().copied().collect())
        .unwrap_or_default();
    indexes.sort_unstable();
    indexes
        .into_iter()
        .filter_map(|index| catalog.fields.get(index))
        .collect()
}

/// The catalog revision `schema` resolves to (`rule::1.1` for `rule`), and
/// its document root: whether it forbids keys it does not define, and the
/// legacy keys it accepts. A catalog without a `schemas` map (an older
/// `opentide generate schemas`) gives an open root. `None` when no revision
/// of the family is in the catalog.
pub fn tide_schema_root(schema: &str) -> Option<(&'static str, &'static TideSchemaRoot)> {
    static OPEN: OnceLock<TideSchemaRoot> = OnceLock::new();
    let catalog = tide_catalog();
    let (key, _) = catalog.by_path.get_key_value(catalog.resolve(schema)?)?;
    let root = catalog
        .schemas
        .get(key)
        .unwrap_or_else(|| OPEN.get_or_init(TideSchemaRoot::default));
    Some((key.as_str(), root))
}

/// Direct children of `parent_path` (empty string = document root).
pub fn tide_children(schema: &str, parent_path: &str) -> Vec<&'static TideField> {
    let catalog = tide_catalog();
    let Some(key) = catalog.resolve(schema) else {
        return Vec::new();
    };
    catalog
        .children
        .get(key)
        .and_then(|by_parent| by_parent.get(parent_path))
        .map(|indexes| {
            indexes
                .iter()
                .filter_map(|index| catalog.fields.get(*index))
                .collect()
        })
        .unwrap_or_default()
}

fn static_capture(capture: Option<&str>) -> &'static str {
    match capture {
        Some("tide.keyword") => "tide.keyword",
        Some("tide.property") => "tide.property",
        Some("tide.schema") => "tide.schema",
        Some("property") => "property",
        _ => "property",
    }
}

/// HighlightSpec capture for a path inside a known object family.
pub fn tide_key_capture_at(schema: &str, path: &str) -> &'static str {
    static_capture(tide_field_at(schema, path).map(|field| field.capture.as_str()))
}

/// Name-only capture. Root keys win when the same name is also a nested property.
pub fn tide_key_capture(key: &str) -> &'static str {
    let catalog = tide_catalog();
    if catalog.fields.iter().any(|field| {
        field.name == key && !field.path.contains('.') && field.capture == "tide.keyword"
    }) {
        return "tide.keyword";
    }
    if catalog
        .fields
        .iter()
        .any(|field| field.name == key && field.capture == "tide.property")
    {
        return "tide.property";
    }
    if catalog
        .fields
        .iter()
        .any(|field| field.name == key && field.capture == "tide.keyword")
    {
        return "tide.keyword";
    }
    "property"
}

pub fn tide_field_is_markdown_at(schema: &str, path: &str) -> bool {
    tide_field_at(schema, path).is_some_and(|field| field.markdown)
}

pub fn tide_keys_for_capture(capture: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for field in &tide_catalog().fields {
        if field.capture == capture {
            names.insert(field.name.clone());
        }
    }
    names.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighlightToken {
    pub span: ByteSpan,
    pub range: Range,
    pub capture: String,
    pub token_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighlightResult {
    pub language_id: String,
    pub tokens: Vec<HighlightToken>,
    pub legend: Vec<String>,
}

/// LSP semantic tokens (delta-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTokens {
    pub data: Vec<u32>,
    pub legend: Vec<String>,
}

/// Standard LSP / VS Code semantic token types. Capture names such as
/// `operator.pipe` are **not** styled by default themes, so encoding uses
/// this legend instead of `HighlightSpec.legend`.
pub const LSP_TOKEN_TYPES: &[&str] = &[
    "namespace",
    "type",
    "class",
    "enum",
    "interface",
    "struct",
    "typeParameter",
    "parameter",
    "variable",
    "property",
    "enumMember",
    "event",
    "function",
    "method",
    "macro",
    "keyword",
    "modifier",
    "comment",
    "string",
    "number",
    "regexp",
    "operator",
    "decorator",
];

#[expect(
    clippy::cast_possible_truncation,
    reason = "an index into LSP_TOKEN_TYPES, a few dozen"
)]
pub fn lsp_token_type_index(capture: &str) -> u32 {
    let name = match capture {
        "comment" => "comment",
        "keyword" | "tide.keyword" => "keyword",
        "operator" | "operator.pipe" => "operator",
        "function" | "function.builtin" => "function",
        "type" | "tide.schema" => "type",
        "variable" => "variable",
        "property" | "tide.property" => "property",
        "string" => "string",
        "number" | "tide.uuid" => "number",
        "boolean" | "constant" => "enumMember",
        "markdown.heading" => "type",
        "markdown.strong" => "keyword",
        "markdown.emphasis" => "variable",
        "markdown.code" => "regexp",
        "markdown.link" => "decorator",
        "markdown.quote" => "comment",
        "macro" => "macro",
        _ => "variable",
    };
    LSP_TOKEN_TYPES.iter().position(|n| *n == name).unwrap_or(8) as u32
}

/// Whether a capture gets a semantic token in the LSP encoding.
///
/// Punctuation (`punctuation*`, a Markdown list marker, the Tide YAML key
/// colon and list dash) and parse errors get none: the TextMate scope already
/// colours punctuation, and diagnostics mark errors. A semantic token of a
/// borrowed type (`operator`, `macro`) would repaint them in the keyword or
/// macro colour in many themes. LSP allows gaps between tokens.
pub fn lsp_capture_has_semantic_token(capture: &str) -> bool {
    !matches!(
        capture,
        "punctuation" | "punctuation.bracket" | "punctuation.delimiter" | "markdown.list" | "error"
    )
}

pub fn encode_semantic_tokens(tokens: &[HighlightToken]) -> Vec<u32> {
    encode_semantic_tokens_with(tokens, |_| true, |t| t.token_type)
}

/// Encode using the standard LSP legend so VS Code / Monaco actually color
/// pipes, builtins, Tide keys, and punctuation.
pub fn encode_lsp_semantic_tokens(tokens: &[HighlightToken]) -> Vec<u32> {
    encode_semantic_tokens_with(
        tokens,
        |t| lsp_capture_has_semantic_token(&t.capture),
        |t| lsp_token_type_index(&t.capture),
    )
}

fn encode_semantic_tokens_with(
    tokens: &[HighlightToken],
    keep: impl Fn(&HighlightToken) -> bool,
    token_type: impl Fn(&HighlightToken) -> u32,
) -> Vec<u32> {
    let mut data = Vec::with_capacity(tokens.len() * 5);
    let mut prev_line = 0u32;
    let mut prev_char = 0u32;
    for token in tokens.iter().filter(|t| keep(t)) {
        let line = token.range.start.line;
        let character = token.range.start.character;
        let delta_line = line.saturating_sub(prev_line);
        let delta_char = if delta_line == 0 {
            character.saturating_sub(prev_char)
        } else {
            character
        };
        let length = token
            .range
            .end
            .character
            .saturating_sub(token.range.start.character)
            .max(1);
        data.extend_from_slice(&[delta_line, delta_char, length, token_type(token), 0]);
        prev_line = line;
        prev_char = character;
    }
    data
}

/// High-contrast HTML for `opentide-lsp highlight --html` and tests.
pub fn tokens_to_html(source: &str, tokens: &[HighlightToken]) -> String {
    let mut html = String::from(
        r#"<!doctype html><meta charset=utf-8>
<title>opentide highlight</title>
<style>
body{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#1e1e1e;color:#d4d4d4;padding:24px;margin:0}
pre{margin:0;white-space:pre-wrap}
.keyword{color:#c586c0;font-weight:700}
.function,.function-builtin{color:#dcdcaa;font-weight:600}
.string{color:#ce9178}
.number{color:#b5cea8}
.comment{color:#6a9955;font-style:italic}
.type{color:#4ec9b0;font-weight:700}
.property{color:#9cdcfe}
.operator{color:#d7ba7d;font-weight:600}
.operator-pipe{color:#ff79c6;font-weight:800}
.error{color:#f44747;text-decoration:underline}
.boolean,.constant{color:#569cd6;font-weight:600}
.punctuation,.punctuation-bracket,.punctuation-delimiter{color:#c8c8c8}
.tide-keyword{color:#c586c0;font-weight:700}
.tide-property{color:#9cdcfe}
.tide-uuid{color:#b5cea8}
.tide-schema{color:#4ec9b0}
.variable{color:#9cdcfe}
.markdown-heading{color:#4fc1ff;font-weight:800}
.markdown-emphasis{color:#d4d4d4;font-style:italic}
.markdown-strong{color:#dcdcaa;font-weight:800}
.markdown-code{color:#e6c07b;background:#2d2d2d}
.markdown-link{color:#4ec9b0;text-decoration:underline}
.markdown-list{color:#c586c0;font-weight:800}
.markdown-quote{color:#6a9955;font-style:italic}
.macro{color:#56b6c2;font-weight:700;font-style:italic}
</style><pre>"#,
    );
    let mut last = 0usize;
    let mut ordered = tokens.to_vec();
    ordered.sort_by_key(|t| (t.span.start, t.span.end));
    for t in &ordered {
        if t.span.start < last {
            continue;
        }
        let start = t.span.start.min(source.len());
        let end = t.span.end.min(source.len());
        html.push_str(&html_escape(&source[last..start]));
        let class = t.capture.replace('.', "-");
        html.push_str(&format!("<span class=\"{class}\">"));
        html.push_str(&html_escape(&source[start..end]));
        html.push_str("</span>");
        last = end;
    }
    html.push_str(&html_escape(&source[last..]));
    html.push_str("</pre>");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The highlight tokens of `spans` in `source`, sorted. Their ranges come
/// from the line table [`opentide_core::with_line_index`] installed for
/// `source`, when one is; otherwise from a [`LineIndex`] built here. An
/// engine that holds a [`LineIndex`] of `source` passes it to
/// [`tokens_in`] instead (ADR 0014 §1: one table per analysis).
pub fn tokens_from_spans(
    spec: &HighlightSpec,
    source: &str,
    spans: &[(ByteSpan, &str)],
) -> Result<Vec<HighlightToken>, HighlightError> {
    if opentide_core::line_index_installed(source) {
        tokens_with(spec, spans, |span| {
            opentide_core::span_to_range(source, span)
        })
    } else {
        tokens_in(spec, &LineIndex::new(source), spans)
    }
}

/// [`tokens_from_spans`], with the ranges from `lines`, the caller's line
/// table of the text.
pub fn tokens_in(
    spec: &HighlightSpec,
    lines: &LineIndex<'_>,
    spans: &[(ByteSpan, &str)],
) -> Result<Vec<HighlightToken>, HighlightError> {
    tokens_with(spec, spans, |span| lines.range(span))
}

fn tokens_with(
    spec: &HighlightSpec,
    spans: &[(ByteSpan, &str)],
    range: impl Fn(ByteSpan) -> opentide_core::Range,
) -> Result<Vec<HighlightToken>, HighlightError> {
    let mut out = Vec::with_capacity(spans.len());
    for (span, capture) in spans {
        let token_type = spec.token_index(capture)?;
        out.push(HighlightToken {
            span: *span,
            range: range(*span),
            capture: (*capture).to_string(),
            token_type,
        });
    }
    out.sort_by_key(|t| (t.span.start, t.token_type));
    Ok(out)
}

/// The TextMate `scopeName` of `language`'s generated grammar (#195).
///
/// ES|QL is `source.opentide.esql`: `source.esql` is the scope of Elastic's own
/// ES|QL extension, which registers the same `esql` language id, and two
/// grammars with one scope replace each other. The other grammars keep
/// `source.<id>`: no known extension owns those scopes (`docs/engine/EDITORS.md`).
/// CQL is `source.opentide.cql` for the same reason: Cassandra's CQL
/// extensions own `source.cql`.
/// YARA is `source.opentide.yara`: the YARA extensions own `source.yara`.
/// YARA-L is `source.yaral` (yara-l-1.0): Google's own grammar is
/// `source.yara-l`, so both can be installed.
/// This is not a HighlightSpec capture, so the rename does not bump
/// `highlights/spec.toml`.
pub fn tm_scope_name(language: LanguageId) -> String {
    match language {
        LanguageId::Esql => "source.opentide.esql".to_string(),
        LanguageId::Cql => "source.opentide.cql".to_string(),
        LanguageId::Yara => "source.opentide.yara".to_string(),
        other => format!("source.{}", other.as_str()),
    }
}

/// Where a token may start in a TextMate pattern: at the line start or after
/// a blank or an opening or separating character.
macro_rules! token_start {
    () => {
        r"(?:^|(?<=[\s|(\[{,;]))"
    };
}

/// A KQL string on one line in the TextMate grammar: `"..."`, `'...'`,
/// `@"..."` and `@'...'`, each with an optional obfuscating `h` or `H` that
/// starts a name, as the lexer reads it (`ah"b"` and `$h"b"` are a name
/// and a string).
const KQL_STRING_MATCH: &str = r#"(?:(?<![A-Za-z0-9_$])[hH])?(?:@"(?:[^"]|"")*"|@'(?:[^']|'')*'|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"#;

/// A KQL number in the TextMate grammar: hexadecimal (`0x1F`, `0X1f`, `0x`)
/// or decimal, with an exponent (`1.5e3`). Timespans (`5m`) stay plain.
const KQL_NUMBER_MATCH: &str = r"\b(?:0[xX][0-9A-Fa-f]*|[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)\b";

/// Generate TextMate / Monaco / Helix maps from the frozen spec.
///
/// The keywords and punctuation come from the language's `KEYWORDS` table
/// ([`keywords`]); Tide YAML and the configuration have none.
pub fn generate_tm_language(language: LanguageId, spec: &HighlightSpec) -> serde_json::Value {
    generate_tm_language_from(language, spec, keywords::language_pairs(language))
}

/// [`generate_tm_language`] over explicit `(token, capture name)` pairs.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn generate_tm_language_from(
    language: LanguageId,
    spec: &HighlightSpec,
    pairs: Vec<(String, String)>,
) -> serde_json::Value {
    let mut patterns: Vec<serde_json::Value> = Vec::new();
    let comment_tm = spec
        .captures
        .get("comment")
        .map(|m| m.tm.as_str())
        .unwrap_or("comment");
    let string_tm = spec
        .captures
        .get("string")
        .map(|m| m.tm.as_str())
        .unwrap_or("string");
    let number_tm = spec
        .captures
        .get("number")
        .map(|m| m.tm.as_str())
        .unwrap_or("constant.numeric");
    let comment_match = match language {
        LanguageId::TideYaml => Some("(?m)^\\s*#.*$"),
        LanguageId::Kql => Some("//.*$|/\\*[\\s\\S]*?\\*/"),
        // A block comment starts only where a token may: `\/*` in a regular
        // expression literal is no comment.
        LanguageId::Esql | LanguageId::Eql | LanguageId::Yara | LanguageId::Yaral => {
            Some(concat!("//.*$|", token_start!(), "/\\*[\\s\\S]*?\\*/"))
        }
        LanguageId::Spl => Some("```[^`]*```"),
        // A CQL comment starts only where a token may: `https://x` is one
        // pattern and `docker/* foo=1` is a value and a pair (the engine's
        // lexer reads `/*` as a comment only when it is terminated).
        LanguageId::Cql => Some(concat!(token_start!(), "(?://.*$|/\\*[\\s\\S]*?\\*/)")),
        // Kibana KQL, Lucene, Falco conditions, the Exabeam Query Language
        // and the Datadog search syntax have no comment syntax.
        LanguageId::Kuery
        | LanguageId::Lucene
        | LanguageId::Falco
        | LanguageId::Exabeam
        | LanguageId::Datadog => None,
        LanguageId::Config => Some("(?m)^\\s*#.*$"),
    };
    if let Some(comment_match) = comment_match {
        patterns.push(serde_json::json!({
            "name": comment_tm,
            "match": comment_match,
            "comment": "capture:comment",
        }));
    }
    // A block comment that goes on past its line: the match rule above takes
    // only one that ends on the line it starts. Not KQL (no block comments)
    // and not CQL (`docker/* foo=1` opens none, and a grammar cannot tell a
    // terminated comment from the rest), and only where a token may start.
    if matches!(
        language,
        LanguageId::Esql | LanguageId::Eql | LanguageId::Yara | LanguageId::Yaral
    ) {
        patterns.push(serde_json::json!({
            "name": comment_tm,
            "begin": concat!(token_start!(), "/\\*"),
            "end": "\\*/",
            "comment": "capture:comment",
        }));
    }
    if language == LanguageId::Spl
        && let Some(maps) = spec.captures.get("macro")
    {
        patterns.push(serde_json::json!({
            "name": maps.tm,
            "match": "`[A-Za-z_][A-Za-z0-9_]*(?:\\([^)`]*\\))?`",
            "comment": "capture:macro",
        }));
    }
    // Tide YAML's rules come before the string and number rules (the leftmost
    // match wins, then the first), and its scopes are each construct's,
    // generated from the semantic-token mapping (`tide_grammar`).
    if language == LanguageId::TideYaml {
        patterns.extend(tide_grammar::structure_rules(spec));
        for (capture, regex) in [
            ("tide.uuid", opentide_core::ids::PATTERN),
            ("tide.schema", "\\b[A-Za-z][A-Za-z0-9_]*::[0-9.]+"),
            ("boolean", "(?<![A-Za-z0-9_])(?:true|false)(?![A-Za-z0-9_])"),
        ] {
            if let Some(scope) = tide_grammar::construct_scope(capture) {
                patterns.push(serde_json::json!({
                    "name": scope,
                    "match": regex,
                    "comment": format!("capture:{capture}"),
                }));
            }
        }
    }
    if language == LanguageId::Kql {
        // KQL's literals as its lexer reads them: any string may be
        // obfuscated (`h` or `H` right before it), the multi-line ```` ``` ````
        // and `~~~` strings span lines, `@"..."` doubles its quote, and an
        // integer may be hexadecimal (`0x1F`, a bare `0x`).
        for fence in ["```", "~~~"] {
            patterns.push(serde_json::json!({
                "name": string_tm,
                "begin": format!("(?:(?<![A-Za-z0-9_$])[hH])?{fence}"),
                "end": fence,
                "comment": "capture:string",
            }));
        }
        patterns.push(serde_json::json!({
            "name": string_tm,
            "match": KQL_STRING_MATCH,
            "comment": "capture:string",
        }));
        patterns.push(serde_json::json!({
            "name": number_tm,
            "match": KQL_NUMBER_MATCH,
            "comment": "capture:number",
        }));
    } else {
        // Datadog's search syntax quotes with `"` only: `'` is a term's character.
        let string_match = if language == LanguageId::Datadog {
            "\"(\\\\.|[^\"\\\\])*\"?"
        } else {
            "\"(\\\\.|[^\"\\\\])*\"|'(\\\\.|[^'\\\\])*'"
        };
        patterns.push(serde_json::json!({
            "name": string_tm,
            "match": string_match,
            "comment": "capture:string",
        }));
        patterns.push(serde_json::json!({
            "name": number_tm,
            "match": "\\b[0-9]+(\\.[0-9]+)?\\b",
            "comment": "capture:number",
        }));
    }
    patterns.extend(tm_extras::before_keywords(language, spec));
    let extras_pairs = pairs.clone();
    for (capture, tokens) in &keywords::by_capture(pairs) {
        let Some(maps) = spec.captures.get(capture) else {
            continue;
        };
        let mut words = Vec::new();
        let mut punct = Vec::new();
        for token in tokens {
            if token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                words.push(regex::escape(token));
            } else {
                punct.push(regex::escape(token));
            }
        }
        if !words.is_empty() {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": format!("(?i)(?<![A-Za-z0-9_])(?:{})(?![A-Za-z0-9_])", words.join("|")),
                "comment": format!("capture:{capture}"),
            }));
        }
        for p in punct {
            patterns.push(serde_json::json!({
                "name": maps.tm,
                "match": p,
                "comment": format!("capture:{capture}"),
            }));
        }
    }
    patterns.extend(tm_extras::after_keywords(language, spec, &extras_pairs));
    if language == LanguageId::TideYaml {
        // First, so a query block is the embedded language, not YAML.
        patterns.insert(0, tide_embedded_queries(spec));
    }
    serde_json::json!({
        "scopeName": tm_scope_name(language),
        "name": format!("opentide {}", language),
        "patterns": patterns,
        "opentideHighlightSpec": spec.version,
    })
}

/// The query fields whose path alone fixes their language, as
/// `docs/engine/ARCHITECTURE.md`'s injection table lists them: each platform block
/// under `configurations`, its query keys, and the language. Elastic is not
/// here: its language follows the block's `type` and `language` keys, which
/// a TextMate grammar cannot read reliably, so its queries are coloured by
/// semantic tokens only.
pub const EMBEDDED_QUERIES: &[(&[&str], &[&str], LanguageId)] = &[
    (
        &["sentinel", "microsoft_defender"],
        &["query"],
        LanguageId::Kql,
    ),
    (&["splunk"], &["query", "search"], LanguageId::Spl),
    (
        &["carbon_black_cloud", "graylog"],
        &["query"],
        LanguageId::Lucene,
    ),
    // The rule's condition; a macro's (`macros[].condition`) is a level
    // deeper and is left to semantic tokens.
    (&["sysdig"], &["condition"], LanguageId::Falco),
    (&["crowdstrike"], &["query"], LanguageId::Cql),
    // The section texts of a Google SecOps block; `match` and `options` are
    // YAML.
    (
        &["google_secops"],
        &["setup", "events", "outcome", "condition", "export"],
        LanguageId::Yaral,
    ),
];

/// The embedded region a query of `language` gets: `meta.embedded.block.<id>`.
pub fn embedded_scope(language: LanguageId) -> String {
    format!("meta.embedded.block.{}", language.as_str())
}

/// The top-level `configurations` block, with each fixed-language query in
/// it as an embedded region of its language's grammar (#171): a block scalar
/// (`query: |`) until the indentation returns, or a value on the key's line.
fn tide_embedded_queries(spec: &HighlightSpec) -> serde_json::Value {
    let key = spec
        .captures
        .get("tide.property")
        .map(|m| m.tm.clone())
        .unwrap_or_else(|| "entity.name.tag.yaml".to_string());
    let comment = spec
        .captures
        .get("comment")
        .map_or("comment", |m| m.tm.as_str())
        .to_string();
    // A line that is neither more indented than the key nor blank ends it.
    let until_dedent = "^(?!\\1\\s+\\S|\\s*$)";
    let platforms: Vec<serde_json::Value> = EMBEDDED_QUERIES
        .iter()
        .map(|(platforms, keys, language)| {
            let scope = embedded_scope(*language);
            let include = tm_scope_name(*language);
            let keys = keys.join("|");
            serde_json::json!({
                "comment": format!("configurations.{{{}}}: {} queries (#171)", platforms.join(","), language.as_str()),
                "begin": format!("^(\\s+)({})(\\s*)(:)\\s*(?:#.*)?$", platforms.join("|")),
                "beginCaptures": { "2": { "name": key }, "4": { "name": tide_grammar::KEY_VALUE_SCOPE } },
                "end": until_dedent,
                "patterns": [
                    {
                        "begin": format!("^(\\s+)({keys})(\\s*)(:)\\s*[|>][-+0-9]*\\s*(?:#.*)?$"),
                        "beginCaptures": { "2": { "name": key }, "4": { "name": tide_grammar::KEY_VALUE_SCOPE } },
                        "end": until_dedent,
                        "contentName": scope,
                        "patterns": [{ "include": include }],
                    },
                    {
                        // An inline value: the quotes of a quoted one are YAML's
                        // (`string.quoted`), its text is the embedded language's, and a
                        // trailing ` # comment` is YAML's too: it ends the query.
                        "match": format!(
                            "^(\\s+)({keys})(\\s*)(:)\\s+(?![|>])(?:(['\"])(.*)(\\5)|(.+?))(?=[ \\t]+#|[ \\t]*$)"
                        ),
                        "captures": {
                            "2": { "name": key },
                            "4": { "name": tide_grammar::KEY_VALUE_SCOPE },
                            "5": { "name": "string.quoted.yaml punctuation.definition.string.begin.yaml" },
                            "6": { "name": scope, "patterns": [{ "include": include }] },
                            "7": { "name": "string.quoted.yaml punctuation.definition.string.end.yaml" },
                            "8": { "name": scope, "patterns": [{ "include": include }] },
                        },
                    },
                    // The ` # note` after an inline query (the line-start comment rule
                    // of the Tide grammar does not see it).
                    {
                        "name": comment,
                        "match": "(?<=[ \\t])#.*$",
                        "comment": "capture:comment",
                    },
                    { "include": "$self" },
                ],
            })
        })
        .collect();
    let mut patterns = platforms;
    patterns.push(serde_json::json!({ "include": "$self" }));
    serde_json::json!({
        "comment": "configurations: the queries whose path fixes their language are embedded regions (#171); Elastic queries are left to semantic tokens",
        "begin": "^(configurations)(\\s*)(:)\\s*(?:#.*)?$",
        "beginCaptures": { "1": { "name": key }, "3": { "name": tide_grammar::KEY_VALUE_SCOPE } },
        "end": "^(?=\\S)",
        "patterns": patterns,
    })
}

/// The `contributes` fragment an editor extension copies for the Tide
/// grammar: its scope and the language id of each embedded region (#171).
pub fn generate_package_contributions() -> serde_json::Value {
    let embedded: serde_json::Map<String, serde_json::Value> = EMBEDDED_QUERIES
        .iter()
        .map(|(_, _, language)| {
            (
                embedded_scope(*language),
                serde_json::Value::String(language.as_str().to_string()),
            )
        })
        .collect();
    serde_json::json!({
        "contributes": {
            "grammars": [{
                "language": LanguageId::TideYaml.as_str(),
                "scopeName": tm_scope_name(LanguageId::TideYaml),
                "path": "./tide.tmLanguage.json",
                "embeddedLanguages": embedded,
            }]
        }
    })
}

pub fn generate_monaco(spec: &HighlightSpec) -> serde_json::Value {
    let token_map: BTreeMap<&String, &String> =
        spec.captures.iter().map(|(k, v)| (k, &v.monaco)).collect();
    serde_json::json!({
        "tokenLegend": spec.legend,
        "tokenMap": token_map,
    })
}

pub fn generate_helix(spec: &HighlightSpec) -> String {
    let mut out = String::from("# Generated from highlights/spec.toml — do not edit.\n");
    for (name, maps) in &spec.captures {
        out.push_str(&format!("\"{name}\" = \"{}\"\n", maps.helix));
    }
    out
}

pub fn generated_artifacts_stale_for(
    spec: &HighlightSpec,
    language: LanguageId,
    tm: &str,
    monaco: &str,
    helix: &str,
) -> Result<(), String> {
    let expected_tm = serde_json::to_string_pretty(&generate_tm_language(language, spec))
        .map_err(|e| e.to_string())?;
    let expected_monaco =
        serde_json::to_string_pretty(&generate_monaco(spec)).map_err(|e| e.to_string())?;
    let expected_helix = generate_helix(spec);
    if tm.trim() != expected_tm.trim() {
        return Err(format!(
            "generated {language} tmLanguage is stale; run opentide-lsp generate-highlights"
        ));
    }
    if monaco.trim() != expected_monaco.trim() {
        return Err("generated monaco map is stale; run opentide-lsp generate-highlights".into());
    }
    if helix.trim() != expected_helix.trim() {
        return Err("generated helix map is stale; run opentide-lsp generate-highlights".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A place past the bundled table is no list, not a panic.
    #[test]
    fn a_place_past_the_bundled_table_reads_as_no_choices() {
        let past = Choices(Repr::Bundled(u32::MAX));
        assert!(past.is_empty());
        assert!(Choices::default().is_empty());
    }

    /// What the build stored (#1743, its strings and enum lists shared) is `fields.json` read whole: the same fields
    /// and schema roots, and the same lookup tables.
    #[test]
    fn the_stored_catalog_is_the_whole_file() {
        let stored = super::catalog_of(super::bundled_file());
        let whole = super::build_tide_catalog(super::tide_fields_json()).expect("fields.json");
        assert_eq!(stored.opentide, whole.opentide);
        assert_eq!(stored.fields.len(), whole.fields.len());
        for (a, b) in stored.fields.iter().zip(&whole.fields) {
            assert_eq!(&*a.enum_values, &*b.enum_values, "{}: {}", a.schema, a.path);
            // The vocabularies, which the build stores apart from the fields.
            assert_eq!(
                super::tide_field_vocab(a),
                super::tide_field_vocab(b),
                "{}: {}",
                a.schema,
                a.path
            );
            let (mut a, mut b) = (a.clone(), b.clone());
            a.enum_values = Choices::default();
            b.enum_values = Choices::default();
            b.vocab.clear();
            b.vocab_scoped = false;
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
        assert!(
            stored
                .fields
                .iter()
                .any(|field| !super::tide_field_vocab(field).0.is_empty())
        );
        assert_eq!(
            format!("{:?}", stored.schemas),
            format!("{:?}", whole.schemas)
        );
        assert_eq!(stored.by_path, whole.by_path);
        assert_eq!(stored.children, whole.children);
        assert_eq!(stored.newest, whole.newest);
        assert!(
            stored
                .fields
                .iter()
                .any(|field| !field.enum_values.is_empty())
        );
    }

    use super::*;

    #[test]
    fn spec_loads_and_legend_matches_captures() {
        let spec = HighlightSpec::load().expect("spec");
        assert!(spec.legend.contains(&"keyword".to_string()));
        assert!(spec.contains_capture("tide.keyword"));
        assert!(spec.contains_capture("tide.property"));
        assert!(spec.contains_capture("comment"));
        assert!(spec.contains_capture("markdown.heading"));
        assert!(spec.contains_capture("macro"));
        assert!(spec.token_index("keyword").is_ok());
        assert!(!load_tide_fields().is_empty());
        let bundled: serde_json::Value =
            serde_json::from_str(tide_fields_json()).expect("fields.json");
        assert_eq!(Some(tide_catalog_version()), bundled["opentide"].as_str());
        assert_eq!(tide_key_capture("description"), "tide.property");
        assert_eq!(tide_key_capture("alert"), "tide.property");
        assert_eq!(tide_key_capture("response"), "tide.property");
        assert_eq!(tide_key_capture_at("rule", "description"), "tide.property");
        assert_eq!(
            tide_key_capture_at("rule", "response.alert_severity"),
            "tide.property"
        );
        assert_eq!(
            tide_key_capture_at("rule", "configurations.sentinel.alert"),
            "tide.property"
        );
        assert!(
            load_tide_fields()
                .iter()
                .all(|field| field.capture == "tide.property"),
            "YAML keys share one capture; nesting must not recolor them"
        );
        assert!(tide_field_is_markdown_at("rule", "description"));
        assert!(tide_field_is_markdown_at(
            "rule",
            "configurations.sentinel.query"
        ));
        assert!(!tide_field_is_markdown_at(
            "rule",
            "configurations.sentinel.alert.description"
        ));
        let detection = tide_field_at("rule", "detection_model").expect("detection_model");
        assert!(!detection.required);
        assert_eq!(detection.ref_kind.as_deref(), Some("objective"));
        assert!(detection.enum_values.is_empty());
        let impact = tide_field_at("threat", "threat.impact").expect("impact");
        assert!(impact.array);
        assert!(impact.required);
        assert!(impact.enum_values.len() > 1);
    }

    /// The tokens read the caller's line table, or the one
    /// `with_line_index` installed, and build none of their own when they can
    /// (ADR 0014 §1), with the same ranges either way.
    #[test]
    fn the_tokens_build_a_line_table_only_when_none_is_given() {
        let spec = HighlightSpec::load().unwrap();
        let source = "a | b\n\"é\u{1F600}\" | c";
        let spans = [
            (ByteSpan::new(0, 1), "keyword"),
            (ByteSpan::new(6, 14), "string"),
            (ByteSpan::new(17, 18), "keyword"),
        ];
        let built = || opentide_core::line_tables_built();
        let before = built();
        let own = tokens_from_spans(&spec, source, &spans).unwrap();
        assert_eq!(built() - before, 1);
        let lines = LineIndex::new(source);
        let before = built();
        assert_eq!(tokens_in(&spec, &lines, &spans).unwrap(), own);
        assert_eq!(built() - before, 0);
        opentide_core::with_line_index(source, || {
            let before = built();
            assert_eq!(tokens_from_spans(&spec, source, &spans).unwrap(), own);
            assert_eq!(built() - before, 0);
        });
    }

    #[test]
    fn an_unknown_capture_fails() {
        let spec = HighlightSpec::load().unwrap();
        let err = spec.token_index("not_a_real_capture").unwrap_err();
        match err {
            HighlightError::UnknownCapture(name) => assert_eq!(name, "not_a_real_capture"),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn semantic_token_encoding_is_delta() {
        let spec = HighlightSpec::load().unwrap();
        let src = "where x";
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, 5), "keyword"),
                (ByteSpan::new(6, 7), "variable"),
            ],
        )
        .unwrap();
        let data = encode_semantic_tokens(&tokens);
        assert_eq!(data.len(), 10);
        assert_eq!(data[0], 0);
        assert_eq!(data[5], 0); // same line
    }

    #[test]
    fn lsp_semantic_token_length_is_utf16_units() {
        let spec = HighlightSpec::load().unwrap();
        let src = "é\n😀";
        let emoji_start = src.len() - "😀".len();
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, "é".len()), "keyword"),
                (ByteSpan::new(emoji_start, src.len()), "string"),
            ],
        )
        .unwrap();
        assert_eq!(tokens[0].range.end.character, 1);
        assert_eq!(tokens[1].range.start, opentide_core::Position::new(1, 0));
        assert_eq!(tokens[1].range.end.character, 2);
        let data = encode_lsp_semantic_tokens(&tokens);
        assert_eq!(&data[0..5], &[0, 0, 1, lsp_token_type_index("keyword"), 0]);
        assert_eq!(&data[5..10], &[1, 0, 2, lsp_token_type_index("string"), 0]);
    }

    #[test]
    fn lsp_encoding_sends_no_token_for_punctuation_or_errors() {
        let spec = HighlightSpec::load().unwrap();
        let src = "a|b:c- d,e";
        let captures = [
            (0, 1, "keyword"),
            (1, 2, "operator.pipe"),
            (2, 3, "punctuation.bracket"),
            (3, 4, "punctuation.delimiter"),
            (4, 5, "punctuation"),
            (5, 6, "operator"),
            (6, 7, "error"),
            (7, 8, "markdown.list"),
            (8, 9, "string"),
        ];
        let spans: Vec<(ByteSpan, &str)> = captures
            .iter()
            .map(|(a, b, c)| (ByteSpan::new(*a, *b), *c))
            .collect();
        let tokens = tokens_from_spans(&spec, src, &spans).unwrap();
        let data = encode_lsp_semantic_tokens(&tokens);
        let operator = lsp_token_type_index("operator");
        // keyword, pipe, operator, string: five u32s each, deltas skip the gaps.
        assert_eq!(
            data,
            vec![
                0,
                0,
                1,
                lsp_token_type_index("keyword"),
                0,
                0,
                1,
                1,
                operator,
                0,
                0,
                4,
                1,
                operator,
                0,
                0,
                3,
                1,
                lsp_token_type_index("string"),
                0,
            ]
        );
        for capture in [
            "punctuation",
            "punctuation.bracket",
            "punctuation.delimiter",
            "markdown.list",
            "error",
        ] {
            assert!(!lsp_capture_has_semantic_token(capture), "{capture}");
        }
        for capture in ["operator", "operator.pipe", "keyword", "macro"] {
            assert!(lsp_capture_has_semantic_token(capture), "{capture}");
        }
    }

    #[test]
    fn lsp_legend_maps_dotted_captures_to_standard_types() {
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("keyword") as usize],
            "keyword"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("operator.pipe") as usize],
            "operator"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("function.builtin") as usize],
            "function"
        );
        assert_eq!(
            LSP_TOKEN_TYPES[lsp_token_type_index("tide.keyword") as usize],
            "keyword"
        );
    }

    #[test]
    fn html_stylesheet_colors_keywords_and_pipes() {
        let spec = HighlightSpec::load().unwrap();
        let src = "SecurityEvent | where x == 1";
        let tokens = tokens_from_spans(
            &spec,
            src,
            &[
                (ByteSpan::new(0, 13), "type"),
                (ByteSpan::new(14, 15), "operator.pipe"),
                (ByteSpan::new(16, 21), "keyword"),
            ],
        )
        .unwrap();
        let html = tokens_to_html(src, &tokens);
        assert!(html.contains("class=\"keyword\""));
        assert!(html.contains("class=\"operator-pipe\""));
        assert!(html.contains("#c586c0"));
        assert!(html.contains("#ff79c6"));
        assert!(html.contains("#4fc1ff"));
        assert!(html.contains(".markdown-heading"));
        assert!(html.contains(".macro"));
    }

    #[test]
    fn each_revision_has_its_own_fields() {
        // metadata.reviewed is a rule::1.1 field.
        assert!(tide_field_at("rule::1.1", "metadata.reviewed").is_some());
        assert!(tide_field_at("rule::1.0", "metadata.reviewed").is_none());
        // A bare family, and a revision the catalog does not know, take the newest.
        assert!(tide_field_at("rule", "metadata.reviewed").is_some());
        assert!(tide_field_at("rule::9.9", "metadata.reviewed").is_some());
        let root = |schema| tide_schema_root(schema).map(|(key, root)| (key, root.closed));
        assert_eq!(root("rule"), Some(("rule::1.1", true)));
        assert_eq!(root("rule::1.0"), Some(("rule::1.0", true)));
        assert_eq!(root("unknown::1.0"), None);
        // opentide#745 retired the objective's root `composition` and the
        // splunk::2.x `search`: no legacy table accepts them any more.
        let (_, objective) = tide_schema_root("objective::1.0").expect("objective");
        assert_eq!(objective.legacy.get("composition"), None);
        let splunk = tide_field_at("rule::1.1", "configurations.splunk").expect("splunk");
        assert_eq!(splunk.legacy.get("search"), None);
        assert!(tide_field_at("rule::1.0", "metadata").is_some_and(|f| f.closed));
        assert!(tide_field_at("rule::1.0", "references.internal").is_some_and(|f| !f.closed));
        let fields = tide_fields_of("rule::1.0");
        assert!(fields.iter().all(|field| field.schema == "rule::1.0"));
        assert!(
            fields
                .iter()
                .any(|field| field.path == "description" && field.required)
        );
    }
}

#[cfg(test)]
mod kql_tm_literals {
    use opentide_core::LanguageId;

    /// The KQL grammar's one-line rules of `capture`, compiled.
    fn rules(capture: &str) -> Vec<regex::Regex> {
        let spec = crate::HighlightSpec::load().expect("spec");
        let tm = crate::generate_tm_language(LanguageId::Kql, &spec);
        tm["patterns"]
            .as_array()
            .expect("patterns")
            .iter()
            .filter(|p| p["comment"] == format!("capture:{capture}"))
            .filter_map(|p| p["match"].as_str())
            .map(|m| regex::Regex::new(m).expect("a regex"))
            .collect()
    }

    fn found<'t>(capture: &str, text: &'t str) -> Vec<&'t str> {
        rules(capture)
            .iter()
            .flat_map(|rule| rule.find_iter(text).map(|m| m.as_str()))
            .collect()
    }

    #[test]
    fn hexadecimal_integers_are_numbers() {
        assert_eq!(
            found(
                "number",
                "x == 0x1F or y == 0X1f or z == 0x or w == 12.5 or v == 0xFFFFFFFFFFFFFFFF or u == 1.5e3"
            ),
            ["0x1F", "0X1f", "0x", "12.5", "0xFFFFFFFFFFFFFFFF", "1.5e3"]
        );
    }

    // The string and fence rules use a lookbehind, which the `regex` crate
    // lacks: `highlights/test/embedded.test.mjs` runs them in vscode-textmate,
    // as an editor does.

    #[test]
    fn kql_literal_rules_snapshot() {
        let spec = crate::HighlightSpec::load().expect("spec");
        let tm = crate::generate_tm_language(LanguageId::Kql, &spec);
        let literals: Vec<&serde_json::Value> = tm["patterns"]
            .as_array()
            .expect("patterns")
            .iter()
            .filter(|p| p["comment"] == "capture:string" || p["comment"] == "capture:number")
            .collect();
        insta::assert_snapshot!(serde_json::to_string_pretty(&literals).expect("json"));
    }
}

#[cfg(test)]
mod tm_language_stub_bug {
    #[test]
    fn generated_kql_tm_language_has_executable_match_rules() {
        let tm = include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/highlights/generated/kql.tmLanguage.json"
        ));
        let v: serde_json::Value = serde_json::from_str(tm).expect("json");
        let patterns = v["patterns"].as_array().expect("patterns");
        let has_match = patterns
            .iter()
            .any(|p| p.get("match").is_some() || p.get("begin").is_some());
        assert!(
            has_match,
            "kql.tmLanguage.json patterns are name-only stubs with no match/begin — TextMate-only editors render uncolored source"
        );
    }

    #[test]
    fn generated_tide_tm_language_does_not_over_escape_whitespace() {
        let spec = crate::HighlightSpec::load().unwrap();
        let tm = crate::generate_tm_language(opentide_core::LanguageId::TideYaml, &spec);
        let patterns = tm["patterns"].as_array().unwrap();
        let key = patterns
            .iter()
            .find(|p| p["comment"] == "capture:tide.property")
            .unwrap();
        let m = key["match"].as_str().unwrap();
        assert!(
            m.contains(r"^(\s*)"),
            "expected real whitespace class, got {m}"
        );
        assert!(
            !m.contains(r"\\s"),
            "over-escaped whitespace in Tide TextMate match: {m}"
        );
        assert!(
            patterns.iter().any(|p| p["comment"] == "capture:tide.uuid"
                && p["match"].as_str().unwrap().contains("8}-")),
            "{tm}"
        );
        let comment = patterns
            .iter()
            .find(|p| p["comment"] == "capture:comment")
            .unwrap();
        assert_eq!(comment["match"], "(?m)^\\s*#.*$");
        // The embedded query regions come first (#171).
        assert_eq!(
            tm["patterns"][0]["begin"],
            "^(configurations)(\\s*)(:)\\s*(?:#.*)?$"
        );
    }

    /// #171: the regions cover the paths with a fixed language, never Elastic.
    #[test]
    fn an_inline_query_splits_its_quotes_and_stops_before_a_comment() {
        let spec = super::HighlightSpec::load().expect("spec");
        let tm = super::generate_tm_language(opentide_core::LanguageId::TideYaml, &spec);
        let text = tm.to_string();
        // The quotes are YAML's string punctuation, the text the embedded
        // language's, and the match stops before ` # note` or the line end.
        assert!(text.contains("punctuation.definition.string.begin.yaml"));
        assert!(text.contains("punctuation.definition.string.end.yaml"));
        assert!(text.contains(r"(?=[ \\t]+#|[ \\t]*$)"), "{text}");
        assert!(
            !text.contains(r"(?![|>])(.+)$"),
            "the whole-line capture is gone"
        );
        // The ` # note` is a comment of the region.
        assert!(text.contains(r"(?<=[ \\t])#.*$"));
    }

    #[test]
    fn embedded_regions_name_their_languages_and_leave_elastic_out() {
        let platforms: Vec<&str> = super::EMBEDDED_QUERIES
            .iter()
            .flat_map(|(p, _, _)| p.iter().copied())
            .collect();
        assert!(!platforms.contains(&"elastic"));
        let contributions = super::generate_package_contributions();
        let embedded = &contributions["contributes"]["grammars"][0]["embeddedLanguages"];
        assert_eq!(embedded["meta.embedded.block.kql"], "kql");
        assert_eq!(embedded["meta.embedded.block.spl"], "spl");
        assert_eq!(embedded["meta.embedded.block.lucene"], "lucene");
        assert_eq!(embedded["meta.embedded.block.falco"], "falco");
        assert_eq!(embedded["meta.embedded.block.cql"], "cql");
    }

    /// CQL's grammar must not take Cassandra's `source.cql` scope, and its
    /// comment pattern must not start inside `https://...`.
    #[test]
    fn cql_grammar_scope_and_comments() {
        let spec = crate::HighlightSpec::load().unwrap();
        let tm = crate::generate_tm_language(opentide_core::LanguageId::Cql, &spec);
        assert_eq!(tm["scopeName"], "source.opentide.cql");
        let comment = tm["patterns"][0]["match"].as_str().unwrap();
        assert!(comment.starts_with("(?:^|(?<=[\\s|"), "{comment}");
    }

    /// #195: ES|QL's grammar must not take Elastic's `source.esql` scope.
    #[test]
    fn esql_grammar_scope_is_opentide_not_elastic() {
        let spec = crate::HighlightSpec::load().unwrap();
        let tm = crate::generate_tm_language(opentide_core::LanguageId::Esql, &spec);
        assert_eq!(tm["scopeName"], "source.opentide.esql");
        let esql = include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/highlights/generated/esql.tmLanguage.json"
        ));
        let v: serde_json::Value = serde_json::from_str(esql).expect("json");
        assert_eq!(v["scopeName"], "source.opentide.esql");
        let generated = [
            ("esql.tmLanguage.json", esql),
            (
                "tide.tmLanguage.json",
                include_str!(concat!(
                    env!("OPENTIDE_ASSETS"),
                    "/highlights/generated/tide.tmLanguage.json"
                )),
            ),
            (
                "package-contributions.json",
                include_str!(concat!(
                    env!("OPENTIDE_ASSETS"),
                    "/highlights/generated/package-contributions.json"
                )),
            ),
            (
                "monaco.json",
                include_str!(concat!(
                    env!("OPENTIDE_ASSETS"),
                    "/highlights/generated/monaco.json"
                )),
            ),
        ];
        for (name, text) in generated {
            assert!(
                !text.contains("\"source.esql\""),
                "{name} still names Elastic's source.esql scope"
            );
        }
        assert_eq!(
            crate::tm_scope_name(opentide_core::LanguageId::Kql),
            "source.kql"
        );
        assert_eq!(
            crate::tm_scope_name(opentide_core::LanguageId::TideYaml),
            "source.opentide-yaml"
        );
    }
}
