//! Tide YAML objects: schema/vocab diagnostics, UUID graph, query injection.
//!
//! Pydantic remains CLI authority. The LSP emits the same `{code, field_path, severity}`
//! with real source ranges. opentide LSP owns Tide diagnostics — disable yamlls on `objects/**`.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]

mod elastic;
mod falco;
mod injection;
mod intel;
mod outline;
mod placeholder;
mod refs;
mod sysdig;
mod vocabs;
mod yaml;
mod yaml_path;
mod yaml_scalar;

use opentide_core::node::{Node, Value};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, Range, span_to_range};
use opentide_highlight::{
    HighlightSpec, HighlightToken, TideField, highlight_markdown_line, tide_field_at,
    tokens_from_spans,
};
use opentide_kql::Profile;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use yaml::YamlNode;

pub use elastic::{ElasticTenant, duration_millis, elastic_query_language, elastic_tenants};
pub use falco::falco_context;
pub use injection::hunt_query_language;
pub use intel::{
    TideInlay, completions_tide, field_markdown, hover_tide, inlay_hints, resolve_completion,
};
pub use outline::{
    LinkTarget, OutlineKind, OutlineNode, ReferenceLens, TideLink, attack_url, document_links,
    outline, reference_lens,
};
pub use placeholder::is_placeholder_query;
pub use refs::{ObjectRef, object_refs};
pub use vocabs::{Vocab, VocabKey, bundled_vocabs, vocab_for_field};
pub use yaml_path::{
    YamlCursor, document_schema_id, key_span, key_span_in, uuid_span, yaml_cursor,
};

const RULE_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/tide/templates/rule.1.0.template.yaml"
));
const OBJECTIVE_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/tide/templates/objective.1.0.template.yaml"
));
const THREAT_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/tide/templates/threat.1.0.template.yaml"
));

/// Map a `configurations` field path to an injected query language.
/// CrowdStrike Next-Gen SIEM correlation rules are CQL. Elastic is not a
/// path: its language comes from the block's `type` and `language`
/// ([`elastic_query_language`]). A hunt's query
/// (`response.procedure.searches.<n>.query`) takes the language its `system`
/// names ([`hunt_query_language`]).
pub fn language_for_field_path(path: &[&str]) -> Option<LanguageId> {
    match path {
        ["configurations", "sentinel", "query"] => Some(LanguageId::Kql),
        ["configurations", "defender_for_endpoint", "query"] => Some(LanguageId::Kql),
        ["configurations", "splunk", "query" | "search"] => Some(LanguageId::Spl),
        ["configurations", "carbon_black_cloud", "query"] => Some(LanguageId::Lucene),
        ["configurations", "sysdig", "condition"] => Some(LanguageId::Falco),
        ["configurations", "crowdstrike", "query"] => Some(LanguageId::Cql),
        _ => None,
    }
}

pub fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "object".into()
    } else {
        slug
    }
}

/// A query block extracted from a YAML document, with indent-stripped text and
/// a mapper back onto host coordinates.
#[derive(Debug, Clone)]
pub struct InjectedQuery {
    pub language: LanguageId,
    /// The platform the query runs on, as a `configurations` key
    /// (`sentinel`, `defender_for_endpoint`, `elastic`): the block's key for a
    /// rule query, the entry's `system` for a hunt. It picks the KQL profile
    /// and the Lucene dialect.
    pub platform: String,
    /// YAML path of the query, list items by index:
    /// `["configurations", "sentinel", "query"]`,
    /// `["response", "procedure", "searches", "0", "query"]`.
    pub field_path: Vec<String>,
    pub inner: String,
    /// Maps inner byte offset → host byte offset.
    pub host_map: Vec<usize>,
    pub host_span: ByteSpan,
}

/// Locate the injected query (if any) covering a host byte offset.
///
/// Offsets are in the text after a leading byte-order mark
/// ([`opentide_core::strip_bom`]); `offset` may count the mark.
pub fn injection_at_offset(source: &str, offset: usize) -> Option<(InjectedQuery, usize)> {
    let (source, offset) = opentide_core::strip_bom_at(source, offset);
    for inj in extract_injections(source) {
        if let Some(inner) = inj.host_map.iter().position(|&h| h == offset) {
            return Some((inj, inner));
        }
        // Right after the query's last character: where the cursor is while
        // the query is typed. It belongs to the query, at its end.
        // A plain scalar drops trailing blanks, so blanks typed after it on its
        // last line count as its end too.
        if inj.host_map.last().is_some_and(|&h| {
            h < offset
                && source
                    .get(h + 1..offset)
                    .is_some_and(|gap| gap.chars().all(|c| c == ' ' || c == '\t'))
        }) {
            let end = inj.inner.len();
            return Some((inj, end));
        }
        if offset >= inj.host_span.start && offset < inj.host_span.end {
            let inner = inj.host_map.iter().position(|&h| h >= offset).unwrap_or(
                inj.inner
                    .len()
                    .saturating_sub(1)
                    .min(inj.host_map.len().saturating_sub(1)),
            );
            return Some((inj, inner));
        }
    }
    None
}

/// Every query a Tide object carries, read from its YAML structure, each as
/// its value (block indentation stripped, folded lines folded, quotes and
/// escapes decoded) with a map back onto the source. A key is a query only
/// at a path opentide models as one: `configurations.<platform>.query`, the
/// legacy `configurations.splunk.search`, Elastic's queries, and each hunt's
/// `response.procedure.searches.<n>.query` in the language its `system`
/// names ([`hunt_query_language`]). A drilldown search is not a query.
///
/// A leading byte-order mark is not part of the document: offsets are in the
/// text after it ([`opentide_core::strip_bom`]), so positions are the ones an
/// editor shows.
pub fn extract_injections(source: &str) -> Vec<InjectedQuery> {
    injection::extract_injections(opentide_core::strip_bom(source))
}

pub fn remap_span(query: &InjectedQuery, inner: ByteSpan) -> ByteSpan {
    if query.host_map.is_empty() {
        return query.host_span;
    }
    let start = query
        .host_map
        .get(inner.start)
        .copied()
        .unwrap_or(query.host_span.start);
    let end = query
        .host_map
        .get(inner.end.saturating_sub(1))
        .copied()
        .map(|b| b + 1)
        .unwrap_or(query.host_span.end);
    ByteSpan::new(start, end.max(start))
}

/// What the engine reads of a Tide object: the fields it shows (`name`,
/// `metadata.uuid`, `metadata.schema`) and the platform blocks, from the
/// root node ([`TideObject::from_node`]).
#[derive(Debug, Clone)]
pub struct TideObject {
    pub name: Option<String>,
    pub metadata: Option<TideMetadata>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub detection_model: Option<String>,
    pub response: Option<Arc<Node>>,
    pub configurations: Option<Arc<Node>>,
    pub objective: Option<Arc<Node>>,
    pub threat: Option<Arc<Node>>,
    pub criticality: Option<String>,
    /// Every other top-level key with a string name, in document order.
    pub extra: BTreeMap<String, Arc<Node>>,
}

#[derive(Debug, Clone)]
pub struct TideMetadata {
    pub uuid: Option<String>,
    pub schema: Option<String>,
    pub version: Option<Arc<Node>>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub tlp: Option<String>,
    pub author: Option<String>,
    pub organisation: Option<Arc<Node>>,
}

/// A field read as text: `null` is no value, a scalar its text as written
/// ([`yaml::written_text`]), a collection a shape the object cannot have.
fn text_field(source: &str, node: Option<&Arc<Node>>) -> Result<Option<String>, ()> {
    match node {
        None => Ok(None),
        Some(node) if node.is_null() => Ok(None),
        Some(node) => yaml::written_text(source, node).map(Some).ok_or(()),
    }
}

/// A field of any shape; `null` is no value.
fn any_field(node: Option<&Arc<Node>>) -> Option<Arc<Node>> {
    node.filter(|node| !node.is_null()).cloned()
}

impl TideMetadata {
    fn from_node(source: &str, node: &Node) -> Result<Self, ()> {
        if !node.is_mapping() {
            return Err(());
        }
        let text = |key: &str| text_field(source, node.get(key));
        Ok(Self {
            uuid: text("uuid")?,
            schema: text("schema")?,
            version: any_field(node.get("version")),
            created: text("created")?,
            modified: text("modified")?,
            tlp: text("tlp")?,
            author: text("author")?,
            organisation: any_field(node.get("organisation")),
        })
    }
}

/// The top-level keys [`TideObject`] reads; every other key is `extra`.
const KNOWN_KEYS: [&str; 11] = [
    "name",
    "metadata",
    "description",
    "status",
    "severity",
    "detection_model",
    "response",
    "configurations",
    "objective",
    "threat",
    "criticality",
];

impl TideObject {
    /// The object `root` holds, `source` being the text it was read from
    /// (without a byte-order mark). `None` when the root is not a mapping,
    /// or a field the engine reads as text (`name`, `metadata.uuid`, ...)
    /// is a sequence or a mapping, or `metadata` is not a mapping: then the
    /// engine reports nothing on the object, and `validate` reports its shape.
    pub fn from_node(source: &str, root: &Node) -> Option<Self> {
        let Value::Map(entries) = &root.value else {
            return None;
        };
        let text = |key: &str| text_field(source, root.get(key)).ok();
        let metadata = match root.get("metadata") {
            Some(node) if !node.is_null() => Some(TideMetadata::from_node(source, node).ok()?),
            _ => None,
        };
        let extra = entries
            .iter()
            .filter_map(|entry| {
                let key = entry.key.as_str()?;
                (!KNOWN_KEYS.contains(&key)).then(|| (key.to_owned(), Arc::clone(&entry.value)))
            })
            .collect();
        Some(Self {
            name: text("name")?,
            metadata,
            description: text("description")?,
            status: text("status")?,
            severity: text("severity")?,
            detection_model: text("detection_model")?,
            response: any_field(root.get("response")),
            configurations: any_field(root.get("configurations")),
            objective: any_field(root.get("objective")),
            threat: any_field(root.get("threat")),
            criticality: text("criticality")?,
            extra,
        })
    }

    /// [`TideObject::from_node`] of the document `source` (without a
    /// byte-order mark).
    pub fn parse(source: &str) -> Option<Self> {
        Self::from_node(source, yaml::parse(source)?.as_ref())
    }
}

/// One object of the workspace index: what its file says, read once per
/// text.
#[derive(Debug, Clone)]
pub struct IndexedObject {
    pub path: String,
    /// The schema family (`rule`, `objective`, `threat`).
    pub object_type: String,
    pub uuid: String,
    pub name: String,
    /// The object's root node.
    pub body: Arc<Node>,
    /// `metadata.schema` as written (`rule::1.1`).
    pub schema: String,
    /// The range of the `name` value (the key's when the value is not on
    /// its line), or the start of the file without one.
    pub name_range: Range,
    /// Each UUID the body's reference fields name, other than the object's
    /// own, with where ([`object_refs`], #198).
    pub refs: Vec<ObjectRef>,
}

impl IndexedObject {
    /// An index entry for an object whose text is not at hand: its
    /// references come from `body` alone, each at the start of the file.
    pub fn from_body(
        path: impl Into<String>,
        object_type: impl Into<String>,
        uuid: impl Into<String>,
        name: impl Into<String>,
        body: Arc<Node>,
    ) -> Self {
        let uuid = uuid.into();
        let refs = object_refs("", &body, &uuid);
        Self {
            path: path.into(),
            object_type: object_type.into(),
            name: name.into(),
            schema: body
                .get("metadata")
                .and_then(|m| m.get("schema"))
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string(),
            uuid,
            body,
            name_range: Range::point(0, 0),
            refs,
        }
    }

    /// Whether the body names `uuid` (not as the object's own).
    pub fn names(&self, uuid: &str) -> bool {
        self.refs.iter().any(|r| r.uuid == uuid)
    }
}

pub struct AnalyzeInput<'a> {
    pub path: &'a str,
    pub source: &'a str,
    /// Tenants from `.opentide/configurations/platforms/elastic.toml`, for
    /// the stack version Elastic queries are checked against.
    pub elastic_tenants: &'a [ElasticTenant],
}

pub struct TideAnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
    pub symbols: Vec<DocumentSymbol>,
}

#[derive(Debug, Clone)]
pub struct DocumentSymbol {
    pub name: String,
    pub kind: String,
    pub range: Range,
    pub detail: Option<String>,
}

/// Spans and ranges are in the text after a leading byte-order mark
/// ([`opentide_core::strip_bom`]).
#[expect(
    clippy::expect_used,
    reason = "loads the HighlightSpec compiled in (highlights/spec.toml): a bad spec fails the tests, never a user's document"
)]
pub fn analyze(input: AnalyzeInput<'_>) -> TideAnalyzeResult {
    let input = AnalyzeInput {
        source: opentide_core::strip_bom(input.source),
        ..input
    };
    let spec = HighlightSpec::load().expect("spec");
    let mut diagnostics = Vec::new();
    // A file that is not YAML is `validate`'s `yaml_parse`: no finding here.
    let root = yaml::parse(input.source);
    let Some(object) = root
        .as_deref()
        .and_then(|root| TideObject::from_node(input.source, root))
    else {
        return TideAnalyzeResult {
            diagnostics,
            tokens: highlight_tide(&spec, input.source, &[]),
            symbols: Vec::new(),
        };
    };

    // The object's own checks (schema, vocabularies, UUIDs, references,
    // chaining, deprecated fields) and its platform blocks' are
    // `opentide-workspace`'s `validate` and `lint`: the language server
    // reports their findings and has no check of its own (UC-2.6, #821;
    // the blocks are [`block_diagnostics`], which only `lint` reads). What
    // stays here is the queries the blocks carry.
    let schema = object_schema_id(&object);
    let object_type = schema.split("::").next().unwrap_or("").to_string();

    // Injected query analysis
    let injections = extract_injections(input.source);
    let skip: Vec<ByteSpan> = injections.iter().map(|inj| inj.host_span).collect();
    let mut tokens = highlight_tide(&spec, input.source, &skip);
    let mut queries = analyze_injections(
        input.source,
        object.configurations.as_ref(),
        input.elastic_tenants,
        injections,
    );
    attach_to_queries(input.source, object.configurations.as_ref(), &mut queries);
    for query in queries {
        diagnostics.extend(query.diagnostics);
        tokens.extend(query.tokens);
    }

    tokens.sort_by_key(|t| (t.span.start, t.span.end));
    let symbols = document_symbols(input.source, &object, &object_type);
    TideAnalyzeResult {
        diagnostics,
        tokens,
        symbols,
    }
}

/// What a rule's platform blocks say that no query of theirs carries: the
/// Elastic block's advisories, the Sysdig block's tuning and list
/// advisories, and, when the block has no query to carry them (none, or a
/// placeholder), its declared datasets, event source and exceptions.
///
/// `opentide lint` reports these (the advisory codes it owns); `validate`
/// reports the block's constraints as the object's schema check, and the
/// language server reports `validate`'s findings and the queries' analysis,
/// so [`analyze`] leaves them out: the editor walking the blocks too showed
/// one fault twice (UC-2.6, #821). Spans and ranges are in the text after a leading byte-order mark
/// ([`opentide_core::strip_bom`]).
pub fn block_diagnostics(source: &str, workspace: &[IndexedObject]) -> Vec<Diagnostic> {
    let source = opentide_core::strip_bom(source);
    let mut out = Vec::new();
    let Some(root) = yaml::parse(source) else {
        return out;
    };
    let Some(object) = TideObject::from_node(source, &root) else {
        return out;
    };
    let object_type = object_schema_id(&object);
    let object_type = object_type.split("::").next().unwrap_or("");
    let configurations = object.configurations.as_ref();
    if let Some(block) = configurations.and_then(|c| c.get("elastic")) {
        if !carried(source, ELASTIC_QUERY) {
            out.extend(elastic::dataset_declarations(source, block));
        }
        if object_type == "rule" {
            out.extend(elastic::block_advisories(source, &root, workspace));
        }
    }
    if let Some(block) = configurations.and_then(|c| c.get("sysdig")) {
        let carried = carried(source, SYSDIG_CONDITION);
        if !carried {
            out.extend(falco::source_diagnostics(source, block));
        }
        out.extend(falco::tuning_diagnostics(source, block));
        out.extend(sysdig::list_self_references(source, block));
        if !carried {
            out.extend(falco::exception_diagnostics(source, block));
        }
    }
    out
}

/// One query injected into a Tide object, analyzed in its language. Ranges and
/// token spans are in the object file's coordinates.
#[derive(Debug, Clone)]
pub struct QueryAnalysis {
    pub query: InjectedQuery,
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Every query injected into a Tide object, each analyzed in its language,
/// including queries with no diagnostic (so a host can count what it checked).
/// The object's other fields are not checked. A file that is not YAML has no
/// queries. Spans and ranges are in the text after a leading byte-order mark
/// ([`opentide_core::strip_bom`]). A query `opentide new` left as a
/// placeholder (`...` under `# opentide:placeholder`) has no diagnostics.
pub fn analyze_queries(source: &str, elastic_tenants: &[ElasticTenant]) -> Vec<QueryAnalysis> {
    let source = opentide_core::strip_bom(source);
    let configurations = TideObject::parse(source).and_then(|object| object.configurations);
    let mut out = analyze_injections(
        source,
        configurations.as_ref(),
        elastic_tenants,
        extract_injections(source),
    );
    attach_to_queries(source, configurations.as_ref(), &mut out);
    out
}

/// The block findings a query carries: the datasets the Elastic block
/// reads (`index`, `threat.index`, `data_view_id`) are its query's, and the
/// Sysdig block's event source and exceptions its condition's (Falco
/// appends the exceptions to the condition when it loads the rule). A
/// placeholder query carries none: `opentide validate` skips it, and
/// [`block_diagnostics`] reports them on the block instead.
fn attach_to_queries(source: &str, configurations: Option<&Arc<Node>>, out: &mut [QueryAnalysis]) {
    let carrier = |out: &mut [QueryAnalysis], path: [&str; 3]| -> Option<usize> {
        out.iter().position(|q| {
            q.query.field_path == path && !placeholder::is_placeholder_query(source, &q.query)
        })
    };
    if let Some(block) = configurations.and_then(|c| c.get("elastic")) {
        if let Some(at) = carrier(out, ELASTIC_QUERY) {
            out[at]
                .diagnostics
                .extend(elastic::dataset_declarations(source, block));
        }
    }
    if let Some(block) = configurations.and_then(|c| c.get("sysdig")) {
        if let Some(at) = carrier(out, SYSDIG_CONDITION) {
            out[at]
                .diagnostics
                .extend(falco::source_diagnostics(source, block));
            out[at]
                .diagnostics
                .extend(exceptions_beyond_the_model(source, block));
        }
    }
}

/// Falco's findings on the Sysdig block's exceptions, but on an exception
/// whose shape the model refuses: `validate` reports that one as the block's
/// `sysdig_exception_shape`, and Falco's own finding would show the fault
/// twice (UC-2.6, #821).
fn exceptions_beyond_the_model(source: &str, block: &Node) -> Vec<Diagnostic> {
    use opentide_schema::objects::platform::sysdig::{block_codes, exception_shape_ok};
    let refused: Vec<String> = if block_codes(block).contains("sysdig_exception_shape") {
        block
            .get("exceptions")
            .and_then(|e| e.as_sequence())
            .unwrap_or_default()
            .iter()
            .enumerate()
            .filter(|(_, entry)| !exception_shape_ok(entry))
            .map(|(index, _)| index.to_string())
            .collect()
    } else {
        Vec::new()
    };
    falco::exception_diagnostics(source, block)
        .into_iter()
        .filter(|d| {
            d.field_path
                .as_deref()
                .and_then(|path| path.get(3))
                .is_none_or(|index| !refused.contains(index))
        })
        .collect()
}

/// Whether a query of `source` (not a placeholder) is at `path`, and so
/// carries the block findings [`attach_to_queries`] gives it.
fn carried(source: &str, path: [&str; 3]) -> bool {
    extract_injections(source)
        .iter()
        .any(|q| q.field_path == path && !placeholder::is_placeholder_query(source, q))
}

const ELASTIC_QUERY: [&str; 3] = ["configurations", "elastic", "query"];
const SYSDIG_CONDITION: [&str; 3] = ["configurations", "sysdig", "condition"];

fn analyze_injections(
    source: &str,
    configurations: Option<&Arc<Node>>,
    elastic_tenants: &[ElasticTenant],
    injections: Vec<InjectedQuery>,
) -> Vec<QueryAnalysis> {
    let mut out = Vec::with_capacity(injections.len());
    // Every token and finding of every query is placed in the file: one
    // index of its lines, not a scan from the start for each (#817).
    let lines = opentide_core::LineIndex::new(source);
    for inj in injections {
        let mut extra = Vec::new();
        let (found, query_tokens) = match inj.language {
            LanguageId::Kql => {
                let profile = if inj.platform == "defender_for_endpoint" {
                    Profile::Defender
                } else {
                    Profile::Sentinel
                };
                let r = opentide_kql::analyze(&inj.inner, profile);
                (r.diagnostics, r.tokens)
            }
            LanguageId::Spl => {
                let r = opentide_spl::analyze(&inj.inner);
                (r.diagnostics, r.tokens)
            }
            LanguageId::Esql => {
                // Hunts have no tenants; only the rule block is targeted.
                let target = (inj.field_path.first().map(String::as_str) == Some("configurations"))
                    .then(|| {
                        elastic::stack_target(
                            configurations.and_then(|c| c.get("elastic")),
                            elastic_tenants,
                        )
                    })
                    .flatten();
                let r = opentide_esql::analyze_for(&inj.inner, target);
                (r.diagnostics, r.tokens)
            }
            LanguageId::Eql => {
                let mut r = opentide_eql::analyze(&inj.inner);
                // Hunts have no schedule; only the rule query is compared.
                if inj.field_path.first().map(String::as_str) == Some("configurations") {
                    extra = elastic::maxspan_advisories(source, configurations, &inj);
                }
                if let Some(indices) = elastic::ecs_indices(configurations, &inj.field_path) {
                    let ecs = opentide_ecs::with_declared_fields(&indices, || {
                        opentide_eql::ecs_diagnostics(&inj.inner)
                    });
                    opentide_ecs::merge(&mut r.diagnostics, ecs);
                }
                (r.diagnostics, r.tokens)
            }
            LanguageId::Kuery => {
                let mut r = opentide_kuery::analyze(&inj.inner);
                if let Some(indices) = elastic::ecs_indices(configurations, &inj.field_path) {
                    let ecs = opentide_ecs::with_declared_fields(&indices, || {
                        opentide_kuery::ecs_diagnostics(&inj.inner)
                    });
                    opentide_ecs::merge(&mut r.diagnostics, ecs);
                }
                (r.diagnostics, r.tokens)
            }
            LanguageId::Lucene => {
                let dialect = if inj.platform == "carbon_black_cloud" {
                    opentide_lucene::Dialect::CarbonBlack
                } else {
                    opentide_lucene::Dialect::Elastic
                };
                let mut r = opentide_lucene::analyze_dialect(&inj.inner, dialect);
                let indices = (dialect == opentide_lucene::Dialect::Elastic)
                    .then(|| elastic::ecs_indices(configurations, &inj.field_path))
                    .flatten();
                if let Some(indices) = indices {
                    let ecs = opentide_ecs::with_declared_fields(&indices, || {
                        opentide_lucene::ecs_diagnostics(&inj.inner)
                    });
                    opentide_ecs::merge(&mut r.diagnostics, ecs);
                }
                (r.diagnostics, r.tokens)
            }
            LanguageId::Falco => {
                let ctx = falco::context_for(
                    configurations
                        .and_then(|c| c.get("sysdig"))
                        .map(Arc::as_ref),
                    &inj.field_path,
                );
                let r = if inj.field_path.last().map(String::as_str) == Some("output") {
                    opentide_falco::analyze_output(&inj.inner, &ctx)
                } else {
                    opentide_falco::analyze_with(&inj.inner, &ctx)
                };
                (r.diagnostics, r.tokens)
            }
            LanguageId::Cql => {
                // The rule block is a Next-Gen SIEM correlation rule; a hunt
                // search is not.
                let ctx = if inj.field_path.first().map(String::as_str) == Some("configurations") {
                    opentide_cql::Context::CORRELATION_RULE
                } else {
                    opentide_cql::Context::default()
                };
                let r = opentide_cql::analyze_with(&inj.inner, &ctx);
                (r.diagnostics, r.tokens)
            }
            LanguageId::TideYaml | LanguageId::Config => (Vec::new(), Vec::new()),
        };
        // The stand-in `opentide new` wrote is lint's `placeholders` finding,
        // not a query to check: `opentide validate` skips it too.
        let mut diagnostics: Vec<Diagnostic> = Vec::new();
        if !placeholder::is_placeholder_query(source, &inj) {
            diagnostics.extend(found.into_iter().map(|d| remap_diagnostic(&lines, &inj, d)));
            diagnostics.extend(extra);
        }
        let tokens = query_tokens
            .iter()
            .filter_map(|t| remap_token(&lines, &inj, t))
            .collect();
        out.push(QueryAnalysis {
            query: inj,
            diagnostics,
            tokens,
        });
    }
    out
}

fn remap_diagnostic(
    lines: &opentide_core::LineIndex<'_>,
    inj: &InjectedQuery,
    mut d: Diagnostic,
) -> Diagnostic {
    let start = inner_offset(&inj.inner, d.range.start);
    let end = inner_offset(&inj.inner, d.range.end).max(start + 1);
    let span = remap_span(inj, ByteSpan::new(start, end));
    d.range = lines.range(span);
    if d.field_path.is_none() {
        d.field_path = Some(inj.field_path.clone());
    }
    d
}

/// Byte offset of an LSP position (UTF-16 columns) inside an injected query.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a char is one or two UTF-16 units"
)]
fn inner_offset(inner: &str, position: opentide_core::Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in inner.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            if line == position.line {
                return idx;
            }
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    inner.len()
}

fn remap_token(
    lines: &opentide_core::LineIndex<'_>,
    inj: &InjectedQuery,
    token: &HighlightToken,
) -> Option<HighlightToken> {
    let mapped = remap_span(inj, token.span);
    Some(HighlightToken {
        span: mapped,
        range: lines.range(mapped),
        capture: token.capture.clone(),
        token_type: token.token_type,
    })
}

fn overlaps(skip: &[ByteSpan], start: usize, end: usize) -> bool {
    skip.iter().any(|s| start < s.end && end > s.start)
}

fn push_span(
    spans: &mut Vec<(ByteSpan, &'static str)>,
    skip: &[ByteSpan],
    start: usize,
    end: usize,
    capture: &'static str,
) {
    if start >= end || overlaps(skip, start, end) {
        return;
    }
    if spans
        .iter()
        .any(|(existing, _)| start < existing.end && end > existing.start)
    {
        return;
    }
    spans.push((ByteSpan::new(start, end), capture));
}

fn lookup_field(schema: &str, path: &str) -> Option<&'static TideField> {
    if path.is_empty() {
        return None;
    }
    if !schema.is_empty() {
        return tide_field_at(schema, path);
    }
    let matches: Vec<_> = ["rule", "objective", "threat"]
        .into_iter()
        .filter_map(|family| tide_field_at(family, path))
        .collect();
    match matches.as_slice() {
        [field] => Some(*field),
        _ => None,
    }
}

fn block_is_query_injection(path: &str, key: &str) -> bool {
    // Platform and hunt queries are KQL/SPL. Example queries are prose.
    matches!(key, "query" | "search") && !path.contains(".examples.")
}

fn join_field_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

/// The patterns [`highlight_scalar`] tells a scalar's kind by, compiled once:
/// it runs on every scalar of every file, and compiling them each time was
/// most of `opentide lint`'s time (#806).
struct ScalarPatterns {
    uuid: Regex,
    schema: Regex,
    technique: Regex,
    number: Regex,
}

#[expect(
    clippy::unwrap_used,
    reason = "regex literals: an invalid pattern fails every test that reaches it"
)]
fn scalar_patterns() -> &'static ScalarPatterns {
    static PATTERNS: std::sync::OnceLock<ScalarPatterns> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| ScalarPatterns {
        uuid: Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .unwrap(),
        schema: Regex::new(r"^[A-Za-z][A-Za-z0-9_]*::[0-9.]+$").unwrap(),
        technique: Regex::new(r"^T[0-9]{4}(\.[0-9]{3})?$").unwrap(),
        number: Regex::new(r"^-?[0-9]+(\.[0-9]+)?$").unwrap(),
    })
}

fn highlight_scalar(
    spans: &mut Vec<(ByteSpan, &'static str)>,
    skip: &[ByteSpan],
    start: usize,
    value: &str,
    field: Option<&TideField>,
) {
    let trimmed = value.trim_end_matches(['\n', '\r', ' ']);
    let leading = value.len() - value.trim_start().len();
    let start = start + leading;
    let value = trimmed.trim_start();
    if value.is_empty()
        || value == "|"
        || value.starts_with("|-")
        || value.starts_with("|+")
        || value.starts_with('>')
    {
        return;
    }
    let end = start + value.len();
    let in_enum = field.is_some_and(|field| {
        field.enum_values.iter().any(|item| item == value)
            || field.default_value.as_deref() == Some(value)
            || field.const_value.as_deref() == Some(value)
    });
    let patterns = scalar_patterns();
    let capture = if patterns.uuid.is_match(value) {
        "tide.uuid"
    } else if patterns.schema.is_match(value) {
        "tide.schema"
    } else if value == "true" || value == "false" {
        "boolean"
    } else if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        "string"
    } else if in_enum || patterns.technique.is_match(value) {
        "constant"
    } else if patterns.number.is_match(value) {
        "number"
    } else {
        "string"
    };
    push_span(spans, skip, start, end, capture);
}

fn is_yaml_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '&' | '-')
}

fn line_key(line: &str) -> Option<(&str, &str, usize, usize)> {
    let body = line.trim_end_matches(['\n', '\r']);
    let indent = body.bytes().take_while(|b| *b == b' ').count();
    let rest = body.get(indent..)?;
    let colon = rest.find(':')?;
    let key = &rest[..colon];
    if key.is_empty() || !key.chars().all(is_yaml_key_char) {
        return None;
    }
    Some((key, &rest[colon + 1..], indent, indent + key.len()))
}

fn line_list_item(line: &str) -> Option<(&str, usize)> {
    let body = line.trim_end_matches(['\n', '\r']);
    let indent = body.bytes().take_while(|b| *b == b' ').count();
    let rest = body.get(indent..)?;
    let item = rest.strip_prefix("- ")?;
    Some((item, indent))
}

fn is_block_scalar(rest: &str) -> bool {
    let t = rest.trim();
    t == "|"
        || t == "|-"
        || t == "|+"
        || t == ">"
        || t == ">-"
        || t == ">+"
        || t.starts_with('|')
        || t.starts_with('>')
}

fn highlight_tide(spec: &HighlightSpec, source: &str, skip: &[ByteSpan]) -> Vec<HighlightToken> {
    let schema = document_schema_id(source);
    let mut spans = Vec::new();
    let mut stack: Vec<(usize, String, bool)> = Vec::new();
    let mut in_block = false;
    let mut block_indent = 0usize;
    let mut block_is_markdown = false;
    let mut byte = 0usize;
    for line in source.split_inclusive('\n') {
        let indent = line.bytes().take_while(|b| *b == b' ').count();
        let trimmed = line.trim();
        if in_block && !trimmed.is_empty() && indent <= block_indent {
            in_block = false;
            block_is_markdown = false;
        }

        if !in_block && trimmed.starts_with('#') {
            if let Some(hash) = line.find('#') {
                let end = byte + line.trim_end_matches(['\n', '\r']).len();
                push_span(&mut spans, skip, byte + hash, end, "comment");
            }
            byte += line.len();
            continue;
        }

        // Block-scalar bodies are literal text, never nested YAML keys.
        if in_block {
            if !trimmed.is_empty() {
                let body = line.trim_end_matches(['\n', '\r']);
                if block_is_markdown {
                    for (span, cap) in highlight_markdown_line(byte, body) {
                        push_span(&mut spans, skip, span.start, span.end, cap);
                    }
                } else {
                    let content_start = byte + indent.min(line.len());
                    let content_end = byte + body.len();
                    push_span(&mut spans, skip, content_start, content_end, "string");
                }
            }
            byte += line.len();
            continue;
        }

        let is_list = trimmed == "-" || trimmed.starts_with("- ");
        while stack.last().is_some_and(|(open, _, from_item)| {
            if is_list {
                *open > indent || (*open == indent && *from_item)
            } else {
                *open >= indent
            }
        }) {
            stack.pop();
        }
        let parent_path = stack
            .iter()
            .map(|(_, key, _)| key.as_str())
            .collect::<Vec<_>>()
            .join(".");

        if let Some((key, rest_text, key_start, key_end)) = line_key(line) {
            let path = join_field_path(&parent_path, key);
            let field = lookup_field(&schema, &path);
            push_span(
                &mut spans,
                skip,
                byte + key_start,
                byte + key_end,
                tide_key_capture_at_or(field),
            );
            let colon_at = byte + key_end;
            if source.as_bytes().get(colon_at) == Some(&b':') {
                push_span(
                    &mut spans,
                    skip,
                    colon_at,
                    colon_at + 1,
                    "punctuation.delimiter",
                );
            }
            let rest_off = key_end + 1;
            let block = is_block_scalar(rest_text);
            if block {
                in_block = true;
                block_indent = indent;
                block_is_markdown = field.is_some_and(|field| field.markdown)
                    && !block_is_query_injection(&path, key);
            } else {
                highlight_scalar(&mut spans, skip, byte + rest_off, rest_text, field);
            }
            if rest_text.trim().is_empty() || block {
                stack.push((indent, key.to_string(), false));
            }
            byte += line.len();
            continue;
        }

        if let Some((item, item_indent)) = line_list_item(line) {
            let dash = byte + item_indent;
            push_span(&mut spans, skip, dash, dash + 1, "punctuation");
            if let Some((key, rest)) = item.split_once(':') {
                if !key.is_empty() && key.chars().all(is_yaml_key_char) {
                    let path = join_field_path(&parent_path, key);
                    let field = lookup_field(&schema, &path);
                    let key_start = byte + item_indent + 2;
                    push_span(
                        &mut spans,
                        skip,
                        key_start,
                        key_start + key.len(),
                        tide_key_capture_at_or(field),
                    );
                    let colon_at = key_start + key.len();
                    push_span(
                        &mut spans,
                        skip,
                        colon_at,
                        colon_at + 1,
                        "punctuation.delimiter",
                    );
                    let block = is_block_scalar(rest);
                    if block {
                        in_block = true;
                        block_indent = item_indent;
                        block_is_markdown = field.is_some_and(|field| field.markdown)
                            && !block_is_query_injection(&path, key);
                    } else {
                        highlight_scalar(&mut spans, skip, key_start + key.len() + 1, rest, field);
                    }
                    if rest.trim().is_empty() || block {
                        stack.push((item_indent, key.to_string(), true));
                    }
                } else {
                    let field = lookup_field(&schema, &parent_path);
                    highlight_scalar(&mut spans, skip, byte + item_indent + 2, item, field);
                }
            } else {
                let field = lookup_field(&schema, &parent_path);
                highlight_scalar(&mut spans, skip, byte + item_indent + 2, item, field);
            }
        }

        byte += line.len();
    }
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
}

fn tide_key_capture_at_or(field: Option<&TideField>) -> &'static str {
    match field {
        Some(field) => match field.capture.as_str() {
            "tide.keyword" => "tide.keyword",
            "tide.property" => "tide.property",
            "tide.schema" => "tide.schema",
            _ => "property",
        },
        None => "property",
    }
}

/// The bundled `deprecations.json`, as compiled into the engine.
pub const DEPRECATIONS_JSON: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/tide/generated/deprecations.json"
));

#[derive(Debug, Clone, Deserialize)]
pub struct FieldDeprecation {
    pub schema: String,
    pub path: String,
    pub message: String,
}

#[derive(Deserialize)]
struct DeprecationFile {
    fields: Vec<DeprecationRow>,
}

#[derive(Deserialize)]
struct DeprecationRow {
    schema: String,
    path: String,
    message: Option<String>,
    deprecated: Option<String>,
}

/// Parse `deprecations.json` or a `fields.json` that carries `deprecated` messages.
pub fn parse_deprecation_overlay(json: &str) -> Result<Vec<FieldDeprecation>, String> {
    let file: DeprecationFile = serde_json::from_str(json).map_err(|err| err.to_string())?;
    Ok(file
        .fields
        .into_iter()
        .filter_map(|row| {
            let message = row.message.or(row.deprecated)?;
            if message.is_empty() {
                return None;
            }
            Some(FieldDeprecation {
                schema: row.schema,
                path: row.path,
                message,
            })
        })
        .collect())
}

fn object_schema_id(object: &TideObject) -> String {
    if let Some(schema) = object
        .metadata
        .as_ref()
        .and_then(|meta| meta.schema.clone())
    {
        return schema;
    }
    object
        .extra
        .get("meta")
        .and_then(|value| value.get("schema"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

/// Whether two paths name one file: separators and a drive letter's case
/// do not count, so `C:\\w\\objects/rules/x.yaml` (a path joined with `/`)
/// and the directory walk's `c:\\w\\objects\\rules\\x.yaml` are the same
/// object, not a `duplicate_id`.
pub fn same_file(a: &str, b: &str) -> bool {
    fn key(path: &str) -> String {
        let mut key = path.replace('\\', "/");
        if key.as_bytes().get(1) == Some(&b':') {
            key[..1].make_ascii_lowercase();
        }
        key
    }
    a == b || key(a) == key(b)
}

fn key_range(source: &str, key: &str) -> Range {
    if let Some(idx) = source.find(&format!("{key}:")) {
        span_to_range(source, ByteSpan::new(idx, idx + key.len()))
    } else {
        Range::point(0, 0)
    }
}

fn document_symbols(source: &str, object: &TideObject, object_type: &str) -> Vec<DocumentSymbol> {
    let mut out = Vec::new();
    if let Some(name) = &object.name {
        out.push(DocumentSymbol {
            name: name.clone(),
            kind: object_type.to_string(),
            range: key_range(source, "name"),
            detail: object.metadata.as_ref().and_then(|m| m.uuid.clone()),
        });
    }
    out
}

pub fn snippet(kind: &str) -> Option<&'static str> {
    match kind {
        "rule" => Some(RULE_TEMPLATE),
        "objective" => Some(OBJECTIVE_TEMPLATE),
        "threat" => Some(THREAT_TEMPLATE),
        _ => None,
    }
}

/// Index one object file: its identity, its name's range and the UUIDs it
/// names ([`object_refs`]). Ranges are in `source` without a byte-order mark,
/// the text an editor shows.
pub fn index_object(path: &str, source: &str) -> Option<IndexedObject> {
    let source = opentide_core::strip_bom(source);
    index_value(path, source, yaml::parse(source)?)
}

/// [`index_object`] for a file a host has already parsed: `value` is what
/// `source` (without a byte-order mark) holds, and the ranges are found in
/// `source`. The language server indexes the parse `opentide-workspace`
/// made of each file this way, not a second one.
pub fn index_value(path: &str, source: &str, value: Arc<Node>) -> Option<IndexedObject> {
    let meta = value.get("metadata")?;
    let uuid = meta.get("uuid")?.as_str()?.to_string();
    let schema = meta.get("schema")?.as_str().unwrap_or("").to_string();
    let object_type = schema.split("::").next()?.to_string();
    let name = value.get("name")?.as_str().unwrap_or("").to_string();
    let refs = object_refs(source, &value, &uuid);
    Some(IndexedObject {
        path: path.to_string(),
        object_type,
        name_range: name_range(source, &name),
        uuid,
        name,
        body: value,
        schema,
        refs,
    })
}

/// The `name` value's range on the key's line, else the key's, else the
/// start of the file.
fn name_range(source: &str, name: &str) -> Range {
    let Some(key) = yaml_path::key_span(source, &["name"]) else {
        return Range::point(0, 0);
    };
    let line_end = source[key.end..]
        .find('\n')
        .map_or(source.len(), |i| key.end + i);
    let span = (!name.is_empty())
        .then(|| source[key.end..line_end].find(name))
        .flatten()
        .map_or(key, |i| {
            ByteSpan::new(key.end + i, key.end + i + name.len())
        });
    span_to_range(source, span)
}

/// The objects of `workspace` other than `uuid`'s own whose body names it,
/// from the references kept in the index.
pub fn find_refs<'a>(workspace: &'a [IndexedObject], uuid: &str) -> Vec<&'a IndexedObject> {
    workspace
        .iter()
        .filter(|o| o.uuid != uuid && o.names(uuid))
        .collect()
}

pub fn definition<'a>(workspace: &'a [IndexedObject], uuid: &str) -> Option<&'a IndexedObject> {
    workspace.iter().find(|o| o.uuid == uuid)
}

pub fn completions_for(workspace: &[IndexedObject], object_type: &str) -> Vec<(String, String)> {
    workspace
        .iter()
        .filter(|o| o.object_type == object_type)
        .map(|o| (o.name.clone(), o.uuid.clone()))
        .collect()
}

pub fn workspace_symbols<'a>(
    workspace: &'a [IndexedObject],
    query: &str,
) -> Vec<&'a IndexedObject> {
    let q = query.to_ascii_lowercase();
    workspace
        .iter()
        .filter(|o| {
            o.name.to_ascii_lowercase().contains(&q)
                || o.uuid.to_ascii_lowercase().contains(&q)
                || o.object_type.to_ascii_lowercase().contains(&q)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn same_file_ignores_separators_and_drive_case() {
        assert!(super::same_file(
            "C:\\w\\objects/rules/x.yaml",
            "c:\\w\\objects\\rules\\x.yaml"
        ));
        assert!(super::same_file("/w/objects/x.yaml", "/w/objects/x.yaml"));
        assert!(!super::same_file("/w/objects/x.yaml", "/w/objects/y.yaml"));
    }

    #[test]
    fn vocabularies_suggest_by_the_shared_rule() {
        let tlp = vocab_for_field("tlp").expect("the tlp vocabulary");
        assert_eq!(tlp.suggest("ambr").as_deref(), Some("amber"));
        assert_eq!(tlp.suggest("AMBER").as_deref(), Some("amber"));
        assert_eq!(tlp.suggest("whitish"), None);
    }
    use super::*;
    use opentide_core::codes;

    /// The object checks are `opentide-workspace`'s `validate` (UC-2.6,
    /// #821): an object with a broken UUID, an unknown TLP, a dangling
    /// reference, a file name that is not its slug, no author, a duplicate
    /// UUID and a deprecated key gets none of those findings here.
    #[test]
    fn the_object_checks_are_left_to_validate() {
        let broken = r#"
name: Some Rule
metadata:
  uuid: not-a-uuid
  schema: rule::1.0
  tlp: clearr
detection_model: 00000000-0000-4000-8002-00000000ffff
meta:
  tlp: clear
"#;
        assert!(index_object("objects/rules/twin.yaml", broken).is_some());
        let diagnostics = analyze(AnalyzeInput {
            path: "objects/rules/not-the-slug.yaml",
            source: broken,
            elastic_tenants: &[],
        })
        .diagnostics;
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        // A file that is not YAML is validate's `yaml_parse`, not a finding here.
        let unparsed = analyze(AnalyzeInput {
            path: "objects/rules/x.yaml",
            source: "name: [",
            elastic_tenants: &[],
        });
        assert!(unparsed.diagnostics.is_empty());
        assert!(!codes::ALL.contains(&"filename_slug"));
    }

    const RULE: &str = r#"
name: Sentinel KQL Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: |
  test
status: STAGING
severity: High
detection_model: 00000000-0000-4000-8002-000000000001
response:
  alert_severity: High
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
      | take 1
"#;

    fn shape_findings(source: &str) -> Vec<(String, String, Range)> {
        analyze(AnalyzeInput {
            path: "objects/rules/rule.yaml",
            source,
            elastic_tenants: &[],
        })
        .diagnostics
        .into_iter()
        .filter(|d| d.code == codes::SCHEMA_VALIDATION)
        .map(|d| {
            (
                d.field_path.unwrap_or_default().join("."),
                d.message,
                d.range,
            )
        })
        .collect()
    }

    const VALID_RULE: &str = r#"name: Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000002
  schema: rule::1.1
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
  author: Someone
  #reviewed: YYYY-MM-DD
description: |
  test
detection_model: 00000000-0000-4000-8002-000000000001
response:
  alert_severity: High
configurations:
  splunk:
    status: DESIGN
    query: index=main
"#;

    #[test]
    fn a_valid_object_has_no_shape_finding() {
        assert_eq!(shape_findings(VALID_RULE), vec![]);
        let older = VALID_RULE.replace("rule::1.1", "rule::1.0");
        assert_eq!(shape_findings(&older), vec![]);
    }

    #[test]
    fn a_merge_key_fills_the_fields_it_merges() {
        // YAML 1.2 leaves `<<` an ordinary key (crates/opentide-schema/YAML.md);
        // the object's shape is `validate`'s, so the engine reports none.
        let source = VALID_RULE.replace(
            "    status: DESIGN\n",
            "    <<: &base\n      status: DESIGN\n",
        );
        assert_eq!(shape_findings(&source), vec![]);
    }

    #[test]
    fn a_quoted_query_key_is_still_the_query() {
        let source = VALID_RULE.replace("rule::1.1", "rule::1.0").replace(
            "    query: index=main\n",
            "    \"query\": |\n      index=main | statz\n",
        );
        let queries = extract_injections(&source);
        assert_eq!(queries.len(), 1, "{queries:?}");
        assert_eq!(queries[0].inner, "index=main | statz");
    }

    #[test]
    fn an_indentation_indicator_with_a_shallower_line_does_not_panic() {
        // `|2`: the first line is indented further than a later one holding
        // a multi-byte character. Cutting that line at the first line's
        // indentation split the character.
        let source = "name: Rule\nmetadata:\n  schema: rule::1.1\nconfigurations:\n  sentinel:\n    query: |2\n        SecurityEvent\n      xé\n";
        let queries = extract_injections(source);
        assert_eq!(queries.len(), 1);
        assert!(queries[0].inner.ends_with("xé"), "{:?}", queries[0].inner);
    }

    #[test]
    fn a_revision_the_catalog_does_not_know_reports_no_unknown_key() {
        let source = VALID_RULE.replace("rule::1.1", "rule::7.0").replace(
            "  author: Someone\n",
            "  author: Someone\n  future_field: 1\n",
        );
        assert!(
            shape_findings(&source)
                .iter()
                .all(|(path, _, _)| path != "metadata.future_field")
        );
    }

    #[test]
    fn non_ascii_text_keeps_later_query_positions_exact() {
        // `🔥` is four bytes and two UTF-16 units; `é` is two bytes and one unit.
        for prefix in ["\"ab\"", "\"é\"", "\"🔥🔥\""] {
            let src = format!(
                "name: Rule\nmetadata:\n  schema: rule::1.0\nconfigurations:\n  sentinel:\n    query: |\n      SecurityEvent\n      | where Account == {prefix} | wher EventID == 1\n"
            );
            let (query,) = match extract_injections(&src).as_slice() {
                [query] => (query.clone(),),
                other => panic!("{other:?}"),
            };
            assert_eq!(query.host_map.len(), query.inner.len());
            assert_eq!(
                &src[query.host_span.start..query.host_span.start + 13],
                "SecurityEvent"
            );
            let r = analyze(AnalyzeInput {
                path: "objects/rules/rule.yaml",
                source: &src,
                elastic_tenants: &[],
            });
            let d = r
                .diagnostics
                .iter()
                .find(|d| d.code == codes::KQL_UNKNOWN_OPERATOR)
                .expect("wher");
            let line = src.lines().nth(d.range.start.line as usize).unwrap();
            let units: Vec<u16> = line.encode_utf16().collect();
            let at = String::from_utf16(&units[d.range.start.character as usize..]).unwrap();
            assert!(at.starts_with("wher"), "{prefix}: {at:?}");
            assert_eq!(d.range.start.line, d.range.end.line, "{prefix}");
        }
    }

    #[test]
    fn parse_deprecation_overlay_accepts_alias_and_drops_empty() {
        let parsed = parse_deprecation_overlay(
            r#"{"fields":[
                {"schema":"rule","path":"old","deprecated":"use new"},
                {"schema":"rule","path":"both","message":"from message","deprecated":"ignored"},
                {"schema":"rule","path":"blank","message":""},
                {"schema":"rule","path":"neither"}
            ]}"#,
        )
        .expect("overlay");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "old");
        assert_eq!(parsed[0].message, "use new");
        assert_eq!(parsed[1].path, "both");
        assert_eq!(parsed[1].message, "from message");
        assert!(parse_deprecation_overlay("{").is_err());
    }

    fn threat_src(threat_body: &str) -> String {
        format!(
            r#"
name: Simulated Actor
criticality: High
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
threat:
{threat_body}"#
        )
    }

    fn analyze_threat(threat_body: &str) -> TideAnalyzeResult {
        let src = threat_src(threat_body);
        analyze(AnalyzeInput {
            path: "objects/threats/t.yaml",
            source: &src,
            elastic_tenants: &[],
        })
    }

    #[test]
    fn valid_threat_lists_are_not_schema_errors() {
        let r = analyze_threat(
            "  severity: Substantial incident\n  impact:\n    - Data Breach\n  leverage:\n    - Information Gathering\n  viability: Likely\n",
        );
        let bad = ["impact", "leverage", "severity", "viability"];
        assert!(
            !r.diagnostics.iter().any(|d| {
                matches!(
                    d.code.as_str(),
                    codes::SCHEMA_VALIDATION | codes::VOCAB_UNKNOWN
                ) && d.field_path.as_ref().is_some_and(|path| {
                    path.len() == 2 && path[0] == "threat" && bad.contains(&path[1].as_str())
                })
            }),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn language_for_field_path_table() {
        assert_eq!(
            language_for_field_path(&["configurations", "sentinel", "query"]),
            Some(LanguageId::Kql)
        );
        assert_eq!(
            language_for_field_path(&["configurations", "splunk", "search"]),
            Some(LanguageId::Spl)
        );
        assert_eq!(
            language_for_field_path(&["configurations", "crowdstrike", "query"]),
            Some(LanguageId::Cql)
        );
        assert_eq!(
            language_for_field_path(&["configurations", "crowdstrike", "details"]),
            None
        );
        assert_eq!(
            language_for_field_path(&["configurations", "carbon_black_cloud", "query"]),
            Some(LanguageId::Lucene)
        );
        assert_eq!(
            language_for_field_path(&["configurations", "sysdig", "condition"]),
            Some(LanguageId::Falco)
        );
    }

    #[test]
    fn slugify_matches_python() {
        assert_eq!(slugify("Sentinel KQL Rule"), "sentinel-kql-rule");
        assert_eq!(slugify("  Hi---There  "), "hi-there");
    }

    #[test]
    fn extracts_block_scalar_kql() {
        let inj = extract_injections(RULE);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Kql);
        assert!(inj[0].inner.contains("SecurityEvent"));
        assert!(
            !inj[0].inner.contains("      SecurityEvent"),
            "indent should be stripped: {:?}",
            inj[0].inner
        );
    }

    #[test]
    fn extracts_splunk_flow_search() {
        let src = "configurations:\n  splunk:\n    search: index=main | head 1\n";
        let inj = extract_injections(src);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Spl);
        assert_eq!(inj[0].inner, "index=main | head 1");
    }

    #[test]
    fn detection_model_absence_is_not_a_schema_error() {
        let src = RULE.replace(
            "detection_model: 00000000-0000-4000-8002-000000000001\n",
            "",
        );
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: &src,
            elastic_tenants: &[],
        });
        assert!(
            !r.diagnostics.iter().any(|d| {
                d.message.contains("detection_model") && d.code == codes::SCHEMA_VALIDATION
            }),
            "{:?}",
            r.diagnostics
        );
    }

    /// The rule fixture with its `detection_model` naming `target`.
    fn rule_naming(target: &str) -> String {
        RULE.replace("00000000-0000-4000-8002-000000000001", target)
    }

    fn invalid_refs(source: &str) -> Vec<Diagnostic> {
        analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source,
            elastic_tenants: &[],
        })
        .diagnostics
        .into_iter()
        .filter(|d| d.code == codes::INVALID_REF)
        .collect()
    }

    #[test]
    fn detection_model_naming_an_objective_is_valid() {
        let found = invalid_refs(&rule_naming("00000000-0000-4000-8002-000000000001"));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn detection_model_naming_a_signal_is_valid() {
        // #213: a signal lives inside its objective; opentide accepts its UUID.
        for signal in [
            "00000000-0000-4000-8099-000000000001",
            "00000000-0000-4000-8099-000000000002",
        ] {
            let found = invalid_refs(&rule_naming(signal));
            assert!(found.is_empty(), "{signal}: {found:?}");
        }
    }

    #[test]
    fn injected_kql_tokens_land_on_yaml() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            elastic_tenants: &[],
        });
        assert!(
            r.tokens.iter().any(|t| t.capture == "tide.property"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| t.capture.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword" || t.capture == "function" || t.capture == "type"),
            "expected inner KQL tokens, got {:?}",
            r.tokens.iter().map(|t| &t.capture).collect::<Vec<_>>()
        );
    }

    fn token_text<'a>(
        source: &'a str,
        tokens: &'a [HighlightToken],
        capture: &str,
    ) -> Vec<&'a str> {
        tokens
            .iter()
            .filter(|t| t.capture == capture)
            .map(|t| &source[t.span.start..t.span.end])
            .collect()
    }

    #[test]
    fn tide_values_use_legend_captures() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            elastic_tenants: &[],
        });
        let uuid_vals = token_text(RULE, &r.tokens, "tide.uuid");
        assert!(
            uuid_vals.contains(&"00000000-0000-4000-8003-000000000001"),
            "{uuid_vals:?}"
        );
        let schema_vals = token_text(RULE, &r.tokens, "tide.schema");
        assert!(schema_vals.contains(&"rule::1.0"), "{schema_vals:?}");
        // A rule-level status has no enum and no default since opentide#745.
        assert!(!token_text(RULE, &r.tokens, "constant").contains(&"STAGING"));
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"clear"));
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"High"));
        let uuid_keys = token_text(RULE, &r.tokens, "tide.property");
        assert!(uuid_keys.contains(&"uuid"), "{uuid_keys:?}");
        let starts: Vec<usize> = r.tokens.iter().map(|t| t.span.start).collect();
        let mut sorted = starts.clone();
        sorted.sort_unstable();
        assert_eq!(starts, sorted, "semantic tokens must be in document order");
    }

    #[test]
    fn carbon_black_query_is_lucene_in_its_dialect() {
        let src = r#"name: Carbon Black rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000019
  schema: rule::1.0
configurations:
  carbon_black_cloud:
    enabled: true
    schema: platform::carbon_black_cloud::1.0
    query: |
      process_name:cmd.exe AND _exists_:parent_name
      AND netconn_count:[1 TO
      5]
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/rules/carbon-black-rule.yaml",
            source: src,
            elastic_tenants: &[],
        });
        let lucene: Vec<_> = r
            .diagnostics
            .iter()
            .filter(|d| d.code.starts_with("lucene_"))
            .collect();
        // `_exists_` is Elasticsearch-only; the newline inside the range is
        // fine because deploy joins lines with spaces.
        assert!(
            lucene
                .iter()
                .any(|d| d.code == codes::LUCENE_ELASTICSEARCH_ONLY
                    && d.field_path.as_deref()
                        == Some(
                            &[
                                "configurations".to_string(),
                                "carbon_black_cloud".into(),
                                "query".into()
                            ][..]
                        )),
            "{lucene:?}"
        );
        assert!(
            lucene
                .iter()
                .all(|d| d.severity != opentide_core::Severity::Error),
            "{lucene:?}"
        );
    }

    #[test]
    fn hunts_query_injects_from_system_field() {
        // Real objects put `system:` and `query:` as same-indent mapping siblings
        // under `- purpose:`, not as a nested child of `- system:`.
        let src = r#"
name: Hunt
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
response:
  procedure:
    searches:
    - purpose: Check for Shai-Hulud network IOC egress from the device
      system: defender_for_endpoint
      query: |-
        DeviceNetworkEvents
        | take 1
configurations:
  crowdstrike:
    query: index=main
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/rules/hunt.yaml",
            source: src,
            elastic_tenants: &[],
        });
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "type"
                    && &src[t.span.start..t.span.end] == "DeviceNetworkEvents"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
                .collect::<Vec<_>>()
        );
        let purpose_keys = token_text(src, &r.tokens, "tide.property");
        assert!(purpose_keys.contains(&"purpose"), "{purpose_keys:?}");
        // The CrowdStrike block's query is CQL: `index` is a field.
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "property" && &src[t.span.start..t.span.end] == "index"),
            "{:?}",
            r.tokens
        );
    }

    #[test]
    fn snippet_matches_generate_templates() {
        // `tests/snippets.rs` compares each with opentide-schema's generator.
        assert!(snippet("rule").unwrap().contains("schema: rule::1.0"));
    }

    #[test]
    fn crowdstrike_query_is_cql() {
        let rule = |query: &str| {
            format!(
                "name: X\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000099\n  schema: rule::1.0\nconfigurations:\n  crowdstrike:\n    query: |\n      {query}\n"
            )
        };
        let found = |src: &str| {
            analyze(AnalyzeInput {
                path: "objects/rules/x.yaml",
                source: src,
                elastic_tenants: &[],
            })
            .diagnostics
            .into_iter()
            .filter(|d| d.code.starts_with("cql_"))
            .collect::<Vec<_>>()
        };
        assert_eq!(
            found(&rule("#event_simpleName=ProcessRollup2 | groupBy(aid)")),
            vec![]
        );
        let src = rule("#event_simpleName=ProcessRollup2 | groupBi(aid)");
        let d = found(&src);
        assert_eq!(d.len(), 1, "{d:#?}");
        assert_eq!(d[0].code, codes::CQL_UNKNOWN_FUNCTION);
        assert_eq!(
            d[0].field_path.as_deref(),
            Some(
                &[
                    "configurations".to_string(),
                    "crowdstrike".into(),
                    "query".into()
                ][..]
            )
        );
        // Placed on the YAML, where `groupBi` is written.
        let start = opentide_core::position_to_offset(&src, d[0].range.start);
        assert!(src[start..].starts_with("groupBi"), "{:?}", &src[start..]);
        // The rule block is a correlation rule: correlate() takes no other aggregate.
        let d = found(&rule(
            "correlate(A: { a=1 }, B: { b=1 | aid <=> A.aid }, within=5m) | count()",
        ));
        assert!(
            d.iter().any(|d| d.code == codes::CQL_CORRELATE_AGGREGATE),
            "{d:#?}"
        );
    }

    #[test]
    fn markdown_description_uses_markdown_captures() {
        let src = r#"
name: Markdown Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
description: |-
  #### MDR Technical Details
  Aggregates `DeviceFileEvents` to flag hosts.
  - Threshold: `PathThreshold = 15`
  1. Review the sample paths
response:
  alert_severity: High
  procedure:
    analysis: |-
      1. Review the sample paths
configurations:
  defender_for_endpoint:
    enabled: true
    alert:
      title: Hello
      recommendation: |-
        Isolate the `host`
    scheduling:
      frequency: PT1H
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/rules/markdown-rule.yaml",
            source: src,
            elastic_tenants: &[],
        });
        let pairs: Vec<(&str, &str)> = r
            .tokens
            .iter()
            .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
            .collect();
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "markdown.heading" && t.contains("####")),
            "{pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "markdown.code" && t.contains("DeviceFileEvents")),
            "{pairs:?}"
        );
        assert!(
            pairs.iter().any(|(c, _)| *c == "markdown.list"),
            "{pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "tide.property" && *t == "alert"),
            "alert should be a Tide property, got {pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "tide.property" && *t == "defender_for_endpoint"),
            "{pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "tide.property" && *t == "scheduling"),
            "{pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "tide.property" && *t == "recommendation"),
            "{pairs:?}"
        );
        assert!(
            !pairs.iter().any(|(c, t)| *c == "property" && *t == "alert"),
            "alert must not fall through to generic property: {pairs:?}"
        );
    }

    #[test]
    fn go_to_definition_and_refs() {
        let obj = index_object("objects/objectives/o.yaml", "name: Obj\nmetadata:\n  uuid: 00000000-0000-4000-8002-000000000001\n  schema: objective::1.0\n").unwrap();
        let ws = [obj];
        assert!(definition(&ws, "00000000-0000-4000-8002-000000000001").is_some());
        let rule = index_object("objects/rules/sentinel-kql-rule.yaml", RULE).unwrap();
        let ws = [ws[0].clone(), rule];
        assert!(!find_refs(&ws, "00000000-0000-4000-8002-000000000001").is_empty());
    }

    /// #850: the engine reads Tide YAML with the loader `validate` uses.
    fn analyzed(source: &str) -> TideAnalyzeResult {
        analyze(AnalyzeInput {
            path: "objects/rules/r.yaml",
            source,
            elastic_tenants: &[],
        })
    }

    const WHER: &str = "name: R\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\nconfigurations:\n  sentinel:\n    query: |\n      SecurityEvent\n      | wher EventID == 1\n";

    #[test]
    fn a_field_read_as_text_keeps_a_scalar_as_written() {
        let source = WHER.replace("name: R", "name: 0x1F");
        let symbols = analyzed(&source).symbols;
        assert_eq!(symbols[0].name, "0x1F");
        let source = WHER.replace("schema: rule::1.0", "schema: 1.10");
        assert_eq!(analyzed(&source).symbols[0].kind, "1.10");
        let object = TideObject::parse(&WHER.replace("name: R", "name: &n !!int 12")).unwrap();
        assert_eq!(object.name.as_deref(), Some("12"));
        assert_eq!(
            TideObject::parse(&WHER.replace("name: R", "name: ~"))
                .unwrap()
                .name,
            None
        );
    }

    #[test]
    fn an_object_of_another_shape_has_no_findings() {
        for shape in ["name: [R]", "name: {a: b}", "metadata: x\nname: R"] {
            let source = WHER.replacen("name: R", shape, 1);
            let result = analyzed(&source);
            assert!(
                result.diagnostics.is_empty(),
                "{shape}: {:?}",
                result.diagnostics
            );
            assert!(result.symbols.is_empty(), "{shape}");
        }
        assert!(TideObject::parse("- a\n").is_none());
        assert!(TideObject::parse("").is_none());
    }

    #[test]
    fn a_text_the_loader_refuses_has_no_findings_and_a_deep_one_has_them() {
        let codes = |source: &str| -> Vec<String> {
            analyzed(source)
                .diagnostics
                .into_iter()
                .map(|d| d.code)
                .collect()
        };
        assert_eq!(codes(WHER), [codes::KQL_UNKNOWN_OPERATOR]);
        // `validate` reports these as `yaml_parse`: a tag outside the core
        // schema, a key written twice, an integer past 64 bits.
        for refused in [
            "extra: !Ref x\n",
            "name: S\n",
            "big: 18446744073709551615\n",
        ] {
            let source = format!("{WHER}{refused}");
            assert!(codes(&source).is_empty(), "{refused}");
            assert!(index_object("r.yaml", &source).is_none(), "{refused}");
        }
        // Nesting past serde_yaml's 128 levels loads, as `validate` loads it.
        let deep = format!("{WHER}deep: {}{}\n", "[".repeat(200), "]".repeat(200));
        assert_eq!(codes(&deep), [codes::KQL_UNKNOWN_OPERATOR]);
        assert!(index_object("r.yaml", &deep).is_some());
    }
}
