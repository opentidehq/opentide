//! Tide YAML objects: schema/vocab diagnostics, UUID graph, query injection.
//!
//! Pydantic remains CLI authority. The LSP emits the same `{code, field_path, severity}`
//! with real source ranges. opentide LSP owns Tide diagnostics — disable yamlls on `objects/**`.

mod elastic;
mod intel;
mod vocabs;
mod yaml_path;

use opentide_core::{ByteSpan, Diagnostic, LanguageId, Range, codes, span_to_range};
use opentide_highlight::{
    HighlightSpec, HighlightToken, TideField, highlight_markdown_line, tide_field_at,
    tide_schema_root, tokens_from_spans,
};
use opentide_kql::Profile;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};
use uuid::Uuid;

pub use elastic::{ElasticTenant, duration_millis, elastic_query_language, elastic_tenants};
pub use intel::{
    TideInlay, completions_tide, field_markdown, hover_tide, inlay_hints, resolve_completion,
};
pub use vocabs::{Vocab, VocabKey, bundled_vocabs, vocab_for_field};
pub use yaml_path::{YamlCursor, document_schema_id, key_span, uuid_span, yaml_cursor};

const RULE_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/tide/templates/rule.1.0.template.yaml"
));
const OBJECTIVE_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/tide/templates/objective.1.0.template.yaml"
));
const THREAT_TEMPLATE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/tide/templates/threat.1.0.template.yaml"
));

/// Map a YAML field path to an injected query language.
/// CrowdStrike is unsupported — never fake validation. Elastic is not a
/// path: its language comes from the block's `type` and `language`
/// ([`elastic_query_language`]).
pub fn language_for_field_path(path: &[&str]) -> Option<LanguageId> {
    match path {
        ["configurations", "sentinel", "query"] => Some(LanguageId::Kql),
        ["configurations", "defender_for_endpoint", "query"] => Some(LanguageId::Kql),
        ["configurations", "splunk", "query"] | ["configurations", "splunk", "search"] => {
            Some(LanguageId::Spl)
        }
        ["configurations", "carbon_black_cloud", "query"] => Some(LanguageId::Lucene),
        ["configurations", "crowdstrike", ..] => None,
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
    pub field_path: Vec<String>,
    pub inner: String,
    /// Maps inner byte offset → host byte offset.
    pub host_map: Vec<usize>,
    pub host_span: ByteSpan,
}

fn intern_platform(name: &str) -> Option<&'static str> {
    match name {
        "sentinel" => Some("sentinel"),
        "defender_for_endpoint" => Some("defender_for_endpoint"),
        "splunk" => Some("splunk"),
        "crowdstrike" => Some("crowdstrike"),
        "sentinel_one" => Some("sentinel_one"),
        "harfanglab" => Some("harfanglab"),
        "carbon_black_cloud" => Some("carbon_black_cloud"),
        _ => None,
    }
}

/// Locate the injected query (if any) covering a host byte offset.
pub fn injection_at_offset(source: &str, offset: usize) -> Option<(InjectedQuery, usize)> {
    for inj in extract_injections(source) {
        if let Some(inner) = inj.host_map.iter().position(|&h| h == offset) {
            return Some((inj, inner));
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

/// Strip block-scalar indent and remap tokens onto YAML coordinates.
pub fn extract_injections(source: &str) -> Vec<InjectedQuery> {
    let mut out = Vec::new();
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let mut i = 0usize;
    let mut byte = 0usize;
    let mut platform: Option<&str> = None;
    let mut platform_indent = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let indent = line.chars().take_while(|c| *c == ' ').count();
        let trimmed = line.trim();
        let content = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        // Keep platform across a same-indent sibling `query:` / `search:` of `system:`.
        // Real hunts look like:
        //   - purpose: ...
        //     system: defender_for_endpoint
        //     query: |-
        let blank_or_comment = trimmed.is_empty() || trimmed.starts_with('#');
        // A blank line has indent 0. It must not drop a `system:` platform
        // before the following `query:` block.
        if !blank_or_comment
            && (indent == 0
                || (platform.is_some()
                    && indent <= platform_indent
                    && !content.starts_with("query:")
                    && !content.starts_with("search:")))
        {
            platform = None;
        }
        if let Some(name) = trimmed.strip_suffix(':').map(str::trim) {
            if let Some(plat) = intern_platform(name) {
                platform = Some(plat);
                platform_indent = indent;
            }
        }
        if let Some(rest) = content.strip_prefix("system:") {
            if let Some(plat) = intern_platform(rest.trim()) {
                platform = Some(plat);
                platform_indent = indent;
            }
        }
        if let Some(plat) = platform {
            if let Some(query) = parse_query_block(source, &lines, i, byte, plat) {
                out.push(query);
            }
        }
        byte += line.len();
        i += 1;
    }
    out.extend(elastic::elastic_injections(source));
    out.sort_by_key(|inj| inj.host_span.start);
    out
}

#[allow(clippy::question_mark)]
fn parse_query_block(
    source: &str,
    lines: &[&str],
    i: usize,
    byte_at_line: usize,
    platform: &str,
) -> Option<InjectedQuery> {
    let line = *lines.get(i)?;
    let indent = line.chars().take_while(|c| *c == ' ').count();
    let trimmed = line.trim().strip_prefix("- ").unwrap_or(line.trim());
    let (key, is_block) = if trimmed == "query: |" || trimmed.starts_with("query: |") {
        ("query", true)
    } else if trimmed == "search: |" || trimmed.starts_with("search: |") {
        ("search", true)
    } else if let Some(rest) = trimmed.strip_prefix("query:") {
        if rest.trim().is_empty() {
            return None;
        }
        ("query", false)
    } else if let Some(rest) = trimmed.strip_prefix("search:") {
        if rest.trim().is_empty() {
            return None;
        }
        ("search", false)
    } else {
        return None;
    };
    let language = language_for_field_path(&["configurations", platform, key])?;
    let field_path = vec![
        "configurations".into(),
        platform.to_string(),
        key.to_string(),
    ];
    if !is_block {
        let colon = line.find(':')?;
        let mut start = byte_at_line + colon + 1;
        let line_end = byte_at_line + line.len();
        while start < line_end
            && source
                .as_bytes()
                .get(start)
                .is_some_and(|b| b.is_ascii_whitespace())
        {
            start += 1;
        }
        let mut end = line_end;
        if source.as_bytes().get(end.saturating_sub(1)) == Some(&b'\n') {
            end -= 1;
        }
        if start >= end {
            return None;
        }
        let inner = source.get(start..end)?.to_string();
        let host_map: Vec<usize> = (start..end).collect();
        return Some(InjectedQuery {
            language,
            field_path,
            inner,
            host_map,
            host_span: ByteSpan::new(start, end),
        });
    }

    let mut inner = String::new();
    let mut host_map = Vec::new();
    let mut j = i + 1;
    let mut b = byte_at_line + line.len();
    let mut host_start = b;
    let mut host_end = b;
    let mut content_indent: Option<usize> = None;
    while j < lines.len() {
        let l = lines[j];
        let ind = l.chars().take_while(|c| *c == ' ').count();
        if l.trim().is_empty() {
            if content_indent.is_some() {
                inner.push('\n');
                if l.ends_with('\n') {
                    host_map.push(b + l.len() - 1);
                }
            }
            host_end = b + l.len();
            b += l.len();
            j += 1;
            continue;
        }
        if ind <= indent {
            break;
        }
        let strip = *content_indent.get_or_insert(ind);
        let body = if l.len() >= strip {
            &l[strip..]
        } else {
            l.trim_start()
        };
        // Where the body starts in the line: `trim_start` may cut fewer bytes.
        let cut = l.len() - body.len();
        if inner.is_empty() {
            // The query starts at its text, not at the line's indentation.
            host_start = b + cut;
        }
        let body = body.strip_suffix('\n').unwrap_or(body);
        if !inner.is_empty() {
            inner.push('\n');
            host_map.push(b.saturating_sub(1));
        }
        // One entry per byte: `host_map` maps inner *byte* offsets, so a
        // multi-byte character takes as many entries as it has bytes.
        for k in 0..body.len() {
            host_map.push(b + cut + k);
        }
        inner.push_str(body);
        host_end = b + l.len();
        b += l.len();
        j += 1;
    }
    if inner.is_empty() {
        return None;
    }
    Some(InjectedQuery {
        language,
        field_path,
        inner,
        host_map,
        host_span: ByteSpan::new(host_start, host_end),
    })
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

#[derive(Debug, Clone, Deserialize)]
pub struct TideObject {
    pub name: Option<String>,
    pub metadata: Option<TideMetadata>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub detection_model: Option<String>,
    pub response: Option<serde_yaml::Value>,
    pub configurations: Option<serde_yaml::Value>,
    pub objective: Option<serde_yaml::Value>,
    pub threat: Option<serde_yaml::Value>,
    pub criticality: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TideMetadata {
    pub uuid: Option<String>,
    pub schema: Option<String>,
    pub version: Option<serde_yaml::Value>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub tlp: Option<String>,
    pub author: Option<String>,
    pub organisation: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone)]
pub struct IndexedObject {
    pub path: String,
    pub object_type: String,
    pub uuid: String,
    pub name: String,
    pub body: serde_yaml::Value,
}

pub struct AnalyzeInput<'a> {
    pub path: &'a str,
    pub source: &'a str,
    pub workspace: &'a [IndexedObject],
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

pub fn analyze(input: AnalyzeInput<'_>) -> TideAnalyzeResult {
    let spec = HighlightSpec::load().expect("spec");
    let vocabs = bundled_vocabs();
    let mut diagnostics = Vec::new();
    let parsed: Result<TideObject, _> = serde_yaml::from_str(input.source);
    let object = match parsed {
        Ok(o) => o,
        Err(e) => {
            diagnostics.push(Diagnostic::error(
                codes::SCHEMA_VALIDATION,
                format!("YAML parse error: {e}"),
                Range::point(0, 0),
            ));
            return TideAnalyzeResult {
                diagnostics,
                tokens: highlight_tide(&spec, input.source, &[]),
                symbols: Vec::new(),
            };
        }
    };

    let schema = object_schema_id(&object);
    let object_type = schema.split("::").next().unwrap_or("").to_string();
    // Catalog lookups take the schema id, so each revision is checked
    // against its own fields; a bare family resolves to its newest revision.
    let catalog_schema = if schema.contains("::") {
        schema.clone()
    } else {
        object_type.clone()
    };

    if object.name.as_deref().unwrap_or("").is_empty() {
        diagnostics.push(
            Diagnostic::error(
                codes::SCHEMA_VALIDATION,
                "missing required field 'name'",
                key_range(input.source, "name"),
            )
            .with_field_path(vec!["name".into()]),
        );
    }
    if object.metadata.is_none() {
        diagnostics.push(
            Diagnostic::error(
                codes::SCHEMA_VALIDATION,
                "missing required field 'metadata'",
                Range::point(0, 0),
            )
            .with_field_path(vec!["metadata".into()]),
        );
    }

    if let Some(meta) = &object.metadata {
        if let Some(uuid) = &meta.uuid {
            if !is_uuidv4(uuid) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::INVALID_UUID,
                        format!("invalid UUID '{uuid}'"),
                        key_range(input.source, "uuid"),
                    )
                    .with_field_path(vec!["metadata".into(), "uuid".into()]),
                );
            }
        } else {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing metadata.uuid",
                    key_range(input.source, "uuid"),
                )
                .with_field_path(vec!["metadata".into(), "uuid".into()]),
            );
        }
        if meta.schema.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'metadata.schema'",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "schema".into()]),
            );
        }
        if meta.version.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'metadata.version'",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "version".into()]),
            );
        }
        if meta.created.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'metadata.created'",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "created".into()]),
            );
        }
        if meta.modified.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'metadata.modified'",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "modified".into()]),
            );
        }
        if meta.tlp.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'metadata.tlp'",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "tlp".into()]),
            );
        }
        if let Some(tlp) = &meta.tlp {
            if let Some(message) = unknown_enum(&object_type, "metadata.tlp", tlp) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::VOCAB_UNKNOWN,
                        message,
                        key_range(input.source, "tlp"),
                    )
                    .with_field_path(vec!["metadata".into(), "tlp".into()]),
                );
            }
        }
        if meta.author.is_none() {
            diagnostics.push(
                Diagnostic::warning(
                    codes::MISSING_AUTHOR,
                    "recommended field metadata.author is missing",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "author".into()]),
            );
        }
        if meta.organisation.is_none() {
            diagnostics.push(
                Diagnostic::warning(
                    codes::MISSING_ORGANISATION,
                    "recommended field metadata.organisation is missing",
                    key_range(input.source, "metadata"),
                )
                .with_field_path(vec!["metadata".into(), "organisation".into()]),
            );
        }
    }

    if let Some(sev) = &object.severity {
        if let Some(message) = unknown_enum(&catalog_schema, "severity", sev) {
            diagnostics.push(
                Diagnostic::error(
                    codes::VOCAB_UNKNOWN,
                    message,
                    key_range(input.source, "severity"),
                )
                .with_field_path(vec!["severity".into()]),
            );
        }
    }

    diagnose_catalog_values(&catalog_schema, &object, input.source, &mut diagnostics);
    diagnose_shape(&schema, input.source, &mut diagnostics);
    diagnose_deprecations(&object_type, input.source, &mut diagnostics);

    let uuid = object
        .metadata
        .as_ref()
        .and_then(|m| m.uuid.clone())
        .unwrap_or_default();

    // duplicate_id across workspace
    if !uuid.is_empty() {
        let dups: Vec<_> = input
            .workspace
            .iter()
            .filter(|o| o.uuid == uuid && o.path != input.path)
            .collect();
        if !dups.is_empty() {
            diagnostics.push(
                Diagnostic::error(
                    codes::DUPLICATE_ID,
                    format!("duplicate uuid {uuid} (also in {})", dups[0].path),
                    key_range(input.source, "uuid"),
                )
                .with_field_path(vec!["metadata".into(), "uuid".into()]),
            );
        }
    }

    // invalid_ref
    if object_type == "rule" {
        if let Some(parent) = &object.detection_model {
            if !input
                .workspace
                .iter()
                .any(|o| o.object_type == "objective" && o.uuid == *parent)
            {
                let suggestion = input
                    .workspace
                    .iter()
                    .find(|o| o.object_type == "objective")
                    .map(|o| o.uuid.clone());
                let mut d = Diagnostic::error(
                    codes::INVALID_REF,
                    format!("invalid_ref: detection_model {parent} is not an indexed objective"),
                    key_range(input.source, "detection_model"),
                )
                .with_field_path(vec!["detection_model".into()]);
                if let Some(s) = suggestion {
                    d = d.with_suggestion(s);
                }
                diagnostics.push(d);
            }
        }
    }

    if let Some(obj) = &object.objective {
        if let Some(threats) = obj.get("threats").and_then(|v| v.as_sequence()) {
            for t in threats {
                if let Some(id) = t.as_str() {
                    if !input
                        .workspace
                        .iter()
                        .any(|o| o.object_type == "threat" && o.uuid == id)
                    {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::INVALID_REF,
                                format!("invalid_ref: threat {id} is not indexed"),
                                key_range(input.source, "threats"),
                            )
                            .with_field_path(vec!["objective".into(), "threats".into()]),
                        );
                    }
                }
            }
        }
    }

    if let Some(threat) = &object.threat {
        if let Some(chaining) = threat.get("chaining").and_then(|v| v.as_sequence()) {
            let vocab = vocabs.get("chaining_relations");
            for (idx, link) in chaining.iter().enumerate() {
                if let Some(rel) = link.get("relation").and_then(|v| v.as_str()) {
                    if let Some(vocab) = vocab {
                        if !vocab.contains(rel) {
                            diagnostics.push(
                                Diagnostic::error(
                                    codes::CHAINING_RELATION_UNKNOWN,
                                    format!("Unknown chaining relation '{rel}'"),
                                    key_range(input.source, "relation"),
                                )
                                .with_field_path(vec![
                                    "threat".into(),
                                    "chaining".into(),
                                    idx.to_string(),
                                    "relation".into(),
                                ]),
                            );
                        }
                    }
                }
                if let Some(vector) = link.get("vector").and_then(|v| v.as_str()) {
                    if !input
                        .workspace
                        .iter()
                        .any(|o| o.object_type == "threat" && o.uuid == vector)
                    {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::INVALID_REF,
                                format!(
                                    "invalid_ref: chaining vector {vector} is not an indexed threat"
                                ),
                                key_range(input.source, "vector"),
                            )
                            .with_field_path(vec![
                                "threat".into(),
                                "chaining".into(),
                                idx.to_string(),
                                "vector".into(),
                            ]),
                        );
                    }
                }
            }
        }
    }

    // CrowdStrike: never fake validation
    if object
        .configurations
        .as_ref()
        .and_then(|c| c.get("crowdstrike"))
        .is_some()
    {
        diagnostics.push(Diagnostic::warning(
            codes::CROWDSTRIKE_UNSUPPORTED,
            "CrowdStrike query validation is unsupported; not faked",
            key_range(input.source, "crowdstrike"),
        ));
    }

    // filename slug
    let stem = std::path::Path::new(input.path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if let Some(name) = &object.name {
        let expected = slugify(name);
        if !stem.is_empty() && stem != expected && !stem.starts_with(&format!("{expected}-")) {
            diagnostics.push(
                Diagnostic::warning(
                    codes::FILENAME_SLUG,
                    format!("filename should be {expected}.yaml (slugify of name)"),
                    key_range(input.source, "name"),
                )
                .with_suggestion(format!("{expected}.yaml")),
            );
        }
    }

    if object_type == "rule"
        && object
            .configurations
            .as_ref()
            .is_some_and(|c| c.get("elastic").is_some())
    {
        if let Ok(rule) = serde_yaml::from_str::<serde_yaml::Value>(input.source) {
            diagnostics.extend(elastic::block_advisories(
                input.source,
                &rule,
                input.workspace,
            ));
        }
    }

    // Injected query analysis
    let injections = extract_injections(input.source);
    let skip: Vec<ByteSpan> = injections.iter().map(|inj| inj.host_span).collect();
    let mut tokens = highlight_tide(&spec, input.source, &skip);
    for query in analyze_injections(
        input.source,
        object.configurations.as_ref(),
        input.elastic_tenants,
        injections,
    ) {
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
/// queries.
pub fn analyze_queries(source: &str, elastic_tenants: &[ElasticTenant]) -> Vec<QueryAnalysis> {
    let configurations = serde_yaml::from_str::<TideObject>(source)
        .ok()
        .and_then(|object| object.configurations);
    analyze_injections(
        source,
        configurations.as_ref(),
        elastic_tenants,
        extract_injections(source),
    )
}

fn analyze_injections(
    source: &str,
    configurations: Option<&serde_yaml::Value>,
    elastic_tenants: &[ElasticTenant],
    injections: Vec<InjectedQuery>,
) -> Vec<QueryAnalysis> {
    let mut out = Vec::with_capacity(injections.len());
    for inj in injections {
        let mut extra = Vec::new();
        let (found, query_tokens) = match inj.language {
            LanguageId::Kql => {
                let profile = if inj.field_path.iter().any(|p| p == "defender_for_endpoint") {
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
                let r = opentide_eql::analyze(&inj.inner);
                // Hunts have no schedule; only the rule query is compared.
                if inj.field_path.first().map(String::as_str) == Some("configurations") {
                    extra = elastic::maxspan_advisories(source, configurations, &inj);
                }
                (r.diagnostics, r.tokens)
            }
            LanguageId::Kuery => {
                let r = opentide_kuery::analyze(&inj.inner);
                (r.diagnostics, r.tokens)
            }
            LanguageId::Lucene => {
                let dialect = if inj.field_path.iter().any(|p| p == "carbon_black_cloud") {
                    opentide_lucene::Dialect::CarbonBlack
                } else {
                    opentide_lucene::Dialect::Elastic
                };
                let r = opentide_lucene::analyze_dialect(&inj.inner, dialect);
                (r.diagnostics, r.tokens)
            }
            LanguageId::TideYaml => (Vec::new(), Vec::new()),
        };
        let mut diagnostics: Vec<Diagnostic> = found
            .into_iter()
            .map(|d| remap_diagnostic(source, &inj, d))
            .collect();
        diagnostics.extend(extra);
        let tokens = query_tokens
            .iter()
            .filter_map(|t| remap_token(source, &inj, t))
            .collect();
        out.push(QueryAnalysis {
            query: inj,
            diagnostics,
            tokens,
        });
    }
    out
}

fn remap_diagnostic(source: &str, inj: &InjectedQuery, mut d: Diagnostic) -> Diagnostic {
    let start = inner_offset(&inj.inner, d.range.start);
    let end = inner_offset(&inj.inner, d.range.end).max(start + 1);
    let span = remap_span(inj, ByteSpan::new(start, end));
    d.range = span_to_range(source, span);
    if d.field_path.is_none() {
        d.field_path = Some(inj.field_path.clone());
    }
    d
}

/// Byte offset of an LSP position (UTF-16 columns) inside an injected query.
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
    source: &str,
    inj: &InjectedQuery,
    token: &HighlightToken,
) -> Option<HighlightToken> {
    let mapped = remap_span(inj, token.span);
    Some(HighlightToken {
        span: mapped,
        range: span_to_range(source, mapped),
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
    let capture =
        if Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .unwrap()
            .is_match(value)
        {
            "tide.uuid"
        } else if Regex::new(r"^[A-Za-z][A-Za-z0-9_]*::[0-9.]+$")
            .unwrap()
            .is_match(value)
        {
            "tide.schema"
        } else if value == "true" || value == "false" {
            "boolean"
        } else if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            "string"
        } else if in_enum
            || Regex::new(r"^T[0-9]{4}(\.[0-9]{3})?$")
                .unwrap()
                .is_match(value)
        {
            "constant"
        } else if Regex::new(r"^-?[0-9]+(\.[0-9]+)?$")
            .unwrap()
            .is_match(value)
        {
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

const DEPRECATIONS_JSON: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/catalogs/tide/generated/deprecations.json"
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

fn deprecation_overlay() -> &'static RwLock<Vec<FieldDeprecation>> {
    static OVERLAY: OnceLock<RwLock<Vec<FieldDeprecation>>> = OnceLock::new();
    OVERLAY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Workspace `.opentide/lsp/catalogs/` entries. Replaces the overlay for the
/// whole process, so a host that analyzes on several threads sees one overlay.
pub fn install_deprecation_overlay(items: Vec<FieldDeprecation>) {
    *deprecation_overlay()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = items;
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

fn bundled_deprecations() -> &'static [FieldDeprecation] {
    static ROWS: OnceLock<Vec<FieldDeprecation>> = OnceLock::new();
    ROWS.get_or_init(|| parse_deprecation_overlay(DEPRECATIONS_JSON).expect("deprecations.json"))
}

fn diagnose_deprecations(object_type: &str, source: &str, diagnostics: &mut Vec<Diagnostic>) {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(source) else {
        return;
    };
    let mut present = Vec::new();
    collect_mapping_paths(&value, &[], &mut present);
    let overlay = deprecation_overlay()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    for path in present {
        let dotted = path.join(".");
        let message = overlay
            .iter()
            .find(|row| row.schema == object_type && row.path == dotted)
            .map(|row| row.message.as_str())
            .or_else(|| {
                bundled_deprecations()
                    .iter()
                    .find(|row| row.schema == object_type && row.path == dotted)
                    .map(|row| row.message.as_str())
            });
        let Some(message) = message else {
            continue;
        };
        let leaf = path.last().map(String::as_str).unwrap_or(&dotted);
        diagnostics.push(
            Diagnostic::warning(
                codes::DEPRECATED_FIELD,
                format!("Field '{dotted}' is deprecated: {message}"),
                key_range(source, leaf),
            )
            .with_field_path(path),
        );
    }
}

fn collect_mapping_paths(value: &serde_yaml::Value, prefix: &[String], out: &mut Vec<Vec<String>>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    for (key, child) in mapping {
        let Some(name) = key.as_str() else {
            continue;
        };
        let mut path = prefix.to_vec();
        path.push(name.to_string());
        out.push(path.clone());
        collect_mapping_paths(child, &path, out);
    }
}

fn diagnose_catalog_values(
    schema: &str,
    object: &TideObject,
    source: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(criticality) = &object.criticality {
        push_unknown_enum(schema, "criticality", criticality, source, diagnostics);
    }
    let Some(threat) = object.threat.as_ref().and_then(|v| v.as_mapping()) else {
        return;
    };
    for key in ["impact", "leverage", "severity", "viability"] {
        let Some(value) = threat.get(serde_yaml::Value::String(key.to_string())) else {
            continue;
        };
        let path = format!("threat.{key}");
        diagnose_field_value(schema, &path, value, source, diagnostics);
    }
}

/// The object's shape against its revision in the field catalog, as
/// opentide's own validation checks it: every required field present, and
/// no key a closed object (or the closed document root) does not define.
///
/// Required fields are checked against the revision `schema` resolves to.
/// Unknown keys only when the catalog has that exact revision: a revision it
/// does not know, or a catalog keyed by family, says nothing about which
/// keys exist. A field another check already reported is not repeated.
fn diagnose_shape(schema: &str, source: &str, diagnostics: &mut Vec<Diagnostic>) {
    let Some((revision, root)) = tide_schema_root(schema) else {
        return;
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(source) else {
        return;
    };
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    let exact = revision == schema;
    let mut shape = ShapeCheck {
        revision,
        exact,
        source,
        reported: diagnostics
            .iter()
            .filter_map(|d| d.field_path.clone())
            .collect(),
        found: Vec::new(),
    };
    shape.mapping(&[], mapping, root.closed, &root.legacy);
    diagnostics.extend(shape.found);
}

struct ShapeCheck<'a> {
    revision: &'static str,
    exact: bool,
    source: &'a str,
    reported: std::collections::BTreeSet<Vec<String>>,
    found: Vec<Diagnostic>,
}

impl ShapeCheck<'_> {
    fn mapping(
        &mut self,
        path: &[String],
        mapping: &serde_yaml::Mapping,
        closed: bool,
        legacy: &BTreeMap<String, Option<String>>,
    ) {
        let dotted = path.join(".");
        let children = opentide_highlight::tide_children(self.revision, &dotted);
        if children.is_empty() {
            return;
        }
        for field in &children {
            let key = serde_yaml::Value::String(field.name.clone());
            if !(field.required || field.recommended) || mapping.contains_key(&key) {
                continue;
            }
            // A legacy spelling that fills the field counts (`search` for `query`).
            let filled = legacy.iter().any(|(old, fills)| {
                fills.as_deref() == Some(field.name.as_str())
                    && mapping.contains_key(serde_yaml::Value::String(old.clone()))
            });
            if filled {
                continue;
            }
            let mut field_path = path.to_vec();
            field_path.push(field.name.clone());
            if !self.reported.insert(field_path.clone()) {
                continue;
            }
            let dotted = field_path.join(".");
            let diagnostic = if field.required {
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    format!("missing required field '{dotted}'"),
                    self.range(path),
                )
            } else {
                Diagnostic::warning(
                    codes::RECOMMENDED_FIELD_MISSING,
                    format!("recommended field '{dotted}' is missing"),
                    self.range(path),
                )
            };
            self.found.push(diagnostic.with_field_path(field_path));
        }
        for (key, value) in mapping {
            let Some(name) = key.as_str() else {
                continue;
            };
            let mut field_path = path.to_vec();
            field_path.push(name.to_string());
            let Some(field) = children.iter().find(|field| field.name == name) else {
                let accepted = legacy.contains_key(name);
                if closed && !accepted && self.exact && self.reported.insert(field_path.clone()) {
                    self.found.push(
                        Diagnostic::error(
                            codes::SCHEMA_VALIDATION,
                            format!(
                                "field '{}' is not defined in {}",
                                field_path.join("."),
                                self.revision
                            ),
                            self.range(&field_path),
                        )
                        .with_field_path(field_path),
                    );
                }
                continue;
            };
            self.values(&field_path, field, value);
            match value {
                serde_yaml::Value::Mapping(child) => {
                    self.mapping(&field_path, child, field.closed, &field.legacy)
                }
                serde_yaml::Value::Sequence(items) => {
                    for item in items {
                        if let Some(child) = item.as_mapping() {
                            self.mapping(&field_path, child, field.closed, &field.legacy);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// A value outside the field's enum (a vocabulary, a fixed set), for a
    /// scalar or for each item of a list: every enum the catalog has, not a
    /// hand-picked few.
    fn values(&mut self, path: &[String], field: &TideField, value: &serde_yaml::Value) {
        if field.enum_values.is_empty() {
            return;
        }
        let items: Vec<&str> = match value {
            serde_yaml::Value::String(text) => vec![text.as_str()],
            serde_yaml::Value::Sequence(items) if field.array => {
                items.iter().filter_map(serde_yaml::Value::as_str).collect()
            }
            _ => Vec::new(),
        };
        let Some(unknown) = items
            .into_iter()
            .find(|item| !field.enum_values.iter().any(|known| known == item))
        else {
            return;
        };
        if !self.reported.insert(path.to_vec()) {
            return;
        }
        self.found.push(
            Diagnostic::error(
                codes::VOCAB_UNKNOWN,
                format!("unknown {} value '{unknown}'", field.name),
                self.range(path),
            )
            .with_field_path(path.to_vec()),
        );
    }

    /// The key at `path`, or the top of the document for the root.
    fn range(&self, path: &[String]) -> Range {
        let keys: Vec<&str> = path.iter().map(String::as_str).collect();
        match key_span(self.source, &keys) {
            Some(span) => span_to_range(self.source, span),
            None => Range::point(0, 0),
        }
    }
}

fn diagnose_field_value(
    schema: &str,
    path: &str,
    value: &serde_yaml::Value,
    source: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(field) = tide_field_at(schema, path) else {
        return;
    };
    let field_path: Vec<String> = path.split('.').map(str::to_string).collect();
    if field.array {
        match value {
            serde_yaml::Value::Sequence(items) => {
                if let Some(min) = field.min_items {
                    if (items.len() as u32) < min {
                        diagnostics.push(
                            Diagnostic::error(
                                codes::SCHEMA_VALIDATION,
                                format!("{path} must contain at least {min} item"),
                                key_range(source, path.rsplit('.').next().unwrap_or(path)),
                            )
                            .with_field_path(field_path.clone()),
                        );
                    }
                }
                for item in items {
                    if let Some(text) = item.as_str() {
                        if let Some(message) = unknown_enum(schema, path, text) {
                            diagnostics.push(
                                Diagnostic::error(
                                    codes::VOCAB_UNKNOWN,
                                    message,
                                    key_range(source, path.rsplit('.').next().unwrap_or(path)),
                                )
                                .with_field_path(field_path.clone()),
                            );
                        }
                    }
                }
            }
            serde_yaml::Value::String(text) => {
                diagnostics.push(
                    Diagnostic::error(
                        codes::SCHEMA_VALIDATION,
                        format!(
                            "{path} must be a YAML list of {} vocabulary names, not a single string",
                            field.name
                        ),
                        key_range(source, path.rsplit('.').next().unwrap_or(path)),
                    )
                    .with_field_path(field_path)
                    .with_suggestion(format!("- {text}")),
                );
            }
            _ => {}
        }
        return;
    }
    if let Some(text) = value.as_str() {
        push_unknown_enum(schema, path, text, source, diagnostics);
    }
}

fn push_unknown_enum(
    schema: &str,
    path: &str,
    value: &str,
    source: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(message) = unknown_enum(schema, path, value) {
        let field_path: Vec<String> = path.split('.').map(str::to_string).collect();
        diagnostics.push(
            Diagnostic::error(
                codes::VOCAB_UNKNOWN,
                message,
                key_range(source, path.rsplit('.').next().unwrap_or(path)),
            )
            .with_field_path(field_path),
        );
    }
}

fn unknown_enum(schema: &str, path: &str, value: &str) -> Option<String> {
    let field = tide_field_at(schema, path)?;
    if field.enum_values.is_empty() || field.enum_values.iter().any(|item| item == value) {
        return None;
    }
    Some(format!("unknown {} value '{value}'", field.name))
}

fn key_range(source: &str, key: &str) -> Range {
    if let Some(idx) = source.find(&format!("{key}:")) {
        span_to_range(source, ByteSpan::new(idx, idx + key.len()))
    } else {
        Range::point(0, 0)
    }
}

fn is_uuidv4(value: &str) -> bool {
    Uuid::parse_str(value)
        .ok()
        .is_some_and(|u| u.get_version_num() == 4)
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

pub fn index_object(path: &str, source: &str) -> Option<IndexedObject> {
    let value: serde_yaml::Value = serde_yaml::from_str(source).ok()?;
    let meta = value.get("metadata")?;
    let uuid = meta.get("uuid")?.as_str()?.to_string();
    let schema = meta.get("schema")?.as_str().unwrap_or("");
    let object_type = schema.split("::").next()?.to_string();
    let name = value.get("name")?.as_str().unwrap_or("").to_string();
    Some(IndexedObject {
        path: path.to_string(),
        object_type,
        uuid,
        name,
        body: value,
    })
}

pub fn find_refs<'a>(workspace: &'a [IndexedObject], uuid: &str) -> Vec<&'a IndexedObject> {
    workspace
        .iter()
        .filter(|o| {
            fn walk(v: &serde_yaml::Value, uuid: &str) -> bool {
                match v {
                    serde_yaml::Value::String(s) => s == uuid,
                    serde_yaml::Value::Sequence(seq) => seq.iter().any(|x| walk(x, uuid)),
                    serde_yaml::Value::Mapping(map) => map.values().any(|x| walk(x, uuid)),
                    _ => false,
                }
            }
            o.uuid != uuid && walk(&o.body, uuid)
        })
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
    use super::*;

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
            workspace: &[],
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
    fn every_revision_requires_its_own_fields() {
        // rule::1.1 requires description as rule::1.0 does: the check was
        // hard-coded for rule::1.0 only.
        let source = VALID_RULE.replace("description: |\n  test\n", "");
        let found = shape_findings(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "description");
        assert_eq!(found[0].1, "missing required field 'description'");
        // Nested: a platform block without its status, under the block's key.
        let source = VALID_RULE.replace("    status: DESIGN\n", "");
        let found = shape_findings(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "configurations.splunk.status");
        assert_eq!(found[0].2.start.line, 16);
    }

    #[test]
    fn a_key_the_revision_does_not_define_is_reported_where_it_is() {
        // metadata.reviewed exists in rule::1.1 only.
        let source = VALID_RULE.replace("rule::1.1", "rule::1.0").replace(
            "  author: Someone\n",
            "  author: Someone\n  reviewed: 2026-01-03\n",
        );
        let found = shape_findings(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        let (path, message, range) = &found[0];
        assert_eq!(path, "metadata.reviewed");
        assert_eq!(
            message,
            "field 'metadata.reviewed' is not defined in rule::1.0"
        );
        // The real key on line 10, not the commented-out template key below it.
        assert_eq!((range.start.line, range.start.character), (9, 2));
        assert_eq!(
            shape_findings(&source.replace("rule::1.0", "rule::1.1")),
            vec![]
        );
        // An unknown root key, and one in a list item of a closed object.
        let source = format!("{VALID_RULE}bogus: 1\n");
        assert_eq!(shape_findings(&source)[0].0, "bogus");
    }

    #[test]
    fn legacy_spellings_opentide_accepts_are_accepted() {
        // splunk::2.x: `search` fills the required `query`, flat `throttling`
        // moves into `trigger`; both validate in opentide.
        let source = VALID_RULE.replace(
            "    query: index=main\n",
            "    search: index=main\n    throttling:\n      period: 1h\n",
        );
        assert_eq!(shape_findings(&source), vec![]);
        // Neither the query nor its legacy spelling: required.
        let source = VALID_RULE.replace("    query: index=main\n", "");
        assert_eq!(shape_findings(&source)[0].0, "configurations.splunk.query");
    }

    #[test]
    fn a_field_only_the_templates_ask_for_is_a_warning() {
        // opentide validate accepts a rule without configurations or response.
        let source = VALID_RULE
            .split("response:")
            .next()
            .expect("head")
            .to_string();
        assert_eq!(shape_findings(&source), vec![]);
        let warnings: Vec<String> = analyze(AnalyzeInput {
            path: "objects/rules/rule.yaml",
            source: &source,
            workspace: &[],
            elastic_tenants: &[],
        })
        .diagnostics
        .into_iter()
        .filter(|d| d.code == codes::RECOMMENDED_FIELD_MISSING)
        .map(|d| d.message)
        .collect();
        assert_eq!(
            warnings,
            vec![
                "recommended field 'configurations' is missing",
                "recommended field 'response' is missing"
            ]
        );
    }

    #[test]
    fn every_enum_in_the_catalog_is_checked() {
        let vocab = |source: &str| -> Vec<String> {
            analyze(AnalyzeInput {
                path: "objects/rules/rule.yaml",
                source,
                workspace: &[],
                elastic_tenants: &[],
            })
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::VOCAB_UNKNOWN)
            .map(|d| d.field_path.unwrap_or_default().join("."))
            .collect()
        };
        assert_eq!(vocab(VALID_RULE), Vec::<String>::new());
        // response.alert_severity had no check of its own.
        let source = VALID_RULE.replace("alert_severity: High", "alert_severity: Severe");
        assert_eq!(vocab(&source), vec!["response.alert_severity"]);
        // A field another check covers is reported once.
        let source = VALID_RULE.replace("tlp: clear", "tlp: clearr");
        assert_eq!(vocab(&source), vec!["metadata.tlp"]);
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
    fn legacy_meta_is_deprecated_field() {
        let src = r#"
name: Legacy
meta:
  uuid: 11111111-1111-4111-8111-111111111111
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/rules/legacy.yaml",
            source: src,
            workspace: &[],
            elastic_tenants: &[],
        });
        let diag = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::DEPRECATED_FIELD)
            .expect("deprecated meta");
        assert_eq!(
            diag.field_path.as_deref(),
            Some(["meta".to_string()].as_slice())
        );
        assert!(diag.message.contains("metadata"));
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
                workspace: &[],
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
    fn workspace_deprecation_overlay_wins() {
        install_deprecation_overlay(vec![FieldDeprecation {
            schema: "rule".into(),
            path: "legacy_note".into(),
            message: "removed in 1.0".into(),
        }]);
        let src = "name: Rule\nlegacy_note: still here\nmetadata:\n  schema: rule::1.0\n";
        let r = analyze(AnalyzeInput {
            path: "objects/rules/overlay.yaml",
            source: src,
            workspace: &[],
            elastic_tenants: &[],
        });
        install_deprecation_overlay(Vec::new());
        assert!(
            r.diagnostics.iter().any(|d| {
                d.code == codes::DEPRECATED_FIELD && d.message.contains("removed in 1.0")
            }),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn scalar_impact_is_schema_validation() {
        let src = r#"
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
  severity: Substantial incident
  impact: Data Breach
  leverage:
    - Information Gathering
  viability: Likely
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/threats/t.yaml",
            source: src,
            workspace: &[],
            elastic_tenants: &[],
        });
        let diag = r
            .diagnostics
            .iter()
            .find(|d| d.message.contains("threat.impact"))
            .expect("scalar impact diagnostic");
        assert_eq!(diag.code, codes::SCHEMA_VALIDATION);
        assert_eq!(
            diag.field_path.as_deref(),
            Some(["threat".to_string(), "impact".to_string()].as_slice())
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
            None
        );
        assert_eq!(
            language_for_field_path(&["configurations", "carbon_black_cloud", "query"]),
            Some(LanguageId::Lucene)
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
    fn unknown_tlp_is_vocab_unknown() {
        let src = RULE.replace("tlp: clear", "tlp: purple");
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: &src,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(
            r.diagnostics.iter().any(|d| d.code == codes::VOCAB_UNKNOWN),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn invalid_uuid_is_flagged() {
        let src = RULE.replace("00000000-0000-4000-8003-000000000001", "not-a-uuid");
        let r = analyze(AnalyzeInput {
            path: "x.yaml",
            source: &src,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(r.diagnostics.iter().any(|d| d.code == codes::INVALID_UUID));
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
            workspace: &[],
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

    #[test]
    fn invalid_ref_detection_model() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(
            r.diagnostics.iter().any(|d| d.code == codes::INVALID_REF),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn injected_kql_tokens_land_on_yaml() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            workspace: &[],
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
    fn rule_severity_is_an_alert_severity() {
        // opentide 0.18.0: a rule's `severity` takes alert_severity values
        // (`High`), not the threat severity scale (`Substantial incident`).
        let check = |severity: &str| {
            let source = RULE.replace("\nseverity: High", &format!("\nseverity: {severity}"));
            analyze(AnalyzeInput {
                path: "objects/rules/sentinel-kql-rule.yaml",
                source: &source,
                workspace: &[],
                elastic_tenants: &[],
            })
            .diagnostics
            .into_iter()
            .filter(|d| d.code == "vocab_unknown" && d.message.contains("severity"))
            .count()
        };
        assert_eq!(check("High"), 0);
        assert_eq!(check("Substantial incident"), 1);
    }

    #[test]
    fn tide_values_use_legend_captures() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            workspace: &[],
            elastic_tenants: &[],
        });
        let uuid_vals = token_text(RULE, &r.tokens, "tide.uuid");
        assert!(
            uuid_vals.contains(&"00000000-0000-4000-8003-000000000001"),
            "{uuid_vals:?}"
        );
        let schema_vals = token_text(RULE, &r.tokens, "tide.schema");
        assert!(schema_vals.contains(&"rule::1.0"), "{schema_vals:?}");
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"STAGING"));
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"clear"));
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"High"));
        let uuid_keys = token_text(RULE, &r.tokens, "tide.property");
        assert!(uuid_keys.contains(&"uuid"), "{uuid_keys:?}");
        let starts: Vec<usize> = r.tokens.iter().map(|t| t.span.start).collect();
        let mut sorted = starts.clone();
        sorted.sort();
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
            workspace: &[],
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
            workspace: &[],
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
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::CROWDSTRIKE_UNSUPPORTED)
        );
    }

    #[test]
    fn snippet_matches_generate_templates() {
        assert!(snippet("rule").unwrap().contains("metadata:"));
    }

    #[test]
    fn duplicate_id_across_workspace() {
        let obj = IndexedObject {
            path: "other.yaml".into(),
            object_type: "rule".into(),
            uuid: "00000000-0000-4000-8003-000000000001".into(),
            name: "Other".into(),
            body: serde_yaml::Value::Null,
        };
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            workspace: &[obj],
            elastic_tenants: &[],
        });
        assert!(r.diagnostics.iter().any(|d| d.code == codes::DUPLICATE_ID));
    }

    #[test]
    fn chaining_relation_unknown() {
        let src = r#"
name: Threat
metadata:
  uuid: 00000000-0000-4000-8001-000000000099
  schema: threat::1.0
threat:
  chaining:
    - relation: not-a-relation
      vector: 00000000-0000-4000-8001-000000000001
"#;
        let r = analyze(AnalyzeInput {
            path: "objects/threats/threat.yaml",
            source: src,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::CHAINING_RELATION_UNKNOWN),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn crowdstrike_never_faked() {
        let src = "name: X\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000099\n  schema: rule::1.0\nconfigurations:\n  crowdstrike:\n    query: index=main\n";
        let r = analyze(AnalyzeInput {
            path: "objects/rules/x.yaml",
            source: src,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::CROWDSTRIKE_UNSUPPORTED)
        );
    }

    #[test]
    fn filename_slug_warning() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/not-the-slug.yaml",
            source: RULE,
            workspace: &[],
            elastic_tenants: &[],
        });
        assert!(r.diagnostics.iter().any(|d| d.code == codes::FILENAME_SLUG));
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
            workspace: &[],
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
}
