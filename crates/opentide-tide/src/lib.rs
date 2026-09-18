//! Tide YAML objects: schema/vocab diagnostics, UUID graph, query injection.
//!
//! Pydantic remains CLI authority. The LSP emits the same `{code, field_path, severity}`
//! with real source ranges. OpenTide LSP owns Tide diagnostics — disable yamlls on `objects/**`.

use opentide_core::{ByteSpan, Diagnostic, LanguageId, Range, codes, span_to_range};
use opentide_highlight::{
    HighlightSpec, HighlightToken, highlight_markdown_line, tide_field_is_markdown,
    tide_key_capture, tokens_from_spans,
};
use opentide_kql::Profile;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use uuid::Uuid;

const RULE_SCHEMA: &str = include_str!("../../../catalogs/tide/schemas/rule.1.0.schema.json");
const OBJECTIVE_SCHEMA: &str =
    include_str!("../../../catalogs/tide/schemas/objective.1.0.schema.json");
const THREAT_SCHEMA: &str = include_str!("../../../catalogs/tide/schemas/threat.1.0.schema.json");
const TLP_VOCAB: &str = include_str!("../../../catalogs/tide/vocabs/tlp.vocab.toml");
const SEVERITY_VOCAB: &str = include_str!("../../../catalogs/tide/vocabs/severity.vocab.toml");
const ALERT_SEVERITY_VOCAB: &str =
    include_str!("../../../catalogs/tide/vocabs/alert_severity.vocab.toml");
const CHAINING_VOCAB: &str =
    include_str!("../../../catalogs/tide/vocabs/chaining_relations.vocab.toml");
const RULE_TEMPLATE: &str = include_str!("../../../catalogs/tide/templates/rule.1.0.template.yaml");
const OBJECTIVE_TEMPLATE: &str =
    include_str!("../../../catalogs/tide/templates/objective.1.0.template.yaml");
const THREAT_TEMPLATE: &str =
    include_str!("../../../catalogs/tide/templates/threat.1.0.template.yaml");

/// Map a YAML field path to an injected query language.
/// CrowdStrike is unsupported — never fake validation.
pub fn language_for_field_path(path: &[&str]) -> Option<LanguageId> {
    match path {
        ["configurations", "sentinel", "query"] => Some(LanguageId::Kql),
        ["configurations", "defender_for_endpoint", "query"] => Some(LanguageId::Kql),
        ["configurations", "splunk", "query"] | ["configurations", "splunk", "search"] => {
            Some(LanguageId::Spl)
        }
        ["configurations", "crowdstrike", ..] => None,
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Vocab {
    pub field: String,
    pub keys: Vec<VocabKey>,
}

#[derive(Debug, Clone)]
pub struct VocabKey {
    pub name: String,
    pub description: Option<String>,
}

impl Vocab {
    pub fn contains(&self, value: &str) -> bool {
        self.keys.iter().any(|k| k.name == value)
    }

    pub fn suggest(&self, value: &str) -> Option<String> {
        self.keys
            .iter()
            .map(|k| {
                let d = k
                    .name
                    .chars()
                    .zip(value.chars())
                    .filter(|(a, b)| a != b)
                    .count()
                    + k.name.len().abs_diff(value.len());
                (k.name.clone(), d)
            })
            .filter(|(_, d)| *d <= 4)
            .min_by_key(|(_, d)| *d)
            .map(|(n, _)| n)
    }

    pub fn hover(&self, value: &str) -> Option<String> {
        self.keys.iter().find(|k| k.name == value).map(|k| {
            format!(
                "**{}** (`{}`)\n\n{}",
                k.name,
                self.field,
                k.description.clone().unwrap_or_default()
            )
        })
    }
}

fn parse_vocab(toml_src: &str) -> Vocab {
    let v: toml::Value = toml::from_str(toml_src).expect("vocab");
    let field = v
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let keys = v
        .get("keys")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|k| {
            Some(VocabKey {
                name: k.get("name")?.as_str()?.to_string(),
                description: k
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(str::to_string),
            })
        })
        .collect();
    Vocab { field, keys }
}

pub fn bundled_vocabs() -> BTreeMap<String, Vocab> {
    let mut m = BTreeMap::new();
    for src in [
        TLP_VOCAB,
        SEVERITY_VOCAB,
        ALERT_SEVERITY_VOCAB,
        CHAINING_VOCAB,
    ] {
        let v = parse_vocab(src);
        m.insert(v.field.clone(), v);
    }
    m
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
        if indent == 0
            || (platform.is_some()
                && indent <= platform_indent
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !content.starts_with("query:")
                && !content.starts_with("search:"))
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
    let trimmed = line.trim();
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
        if inner.is_empty() {
            host_start = b;
        }
        let body = if l.len() >= strip {
            &l[strip..]
        } else {
            l.trim_start()
        };
        let body = body.strip_suffix('\n').unwrap_or(body);
        if !inner.is_empty() {
            inner.push('\n');
            host_map.push(b.saturating_sub(1));
        }
        for (k, ch) in body.char_indices() {
            host_map.push(b + strip + k);
            let _ = ch;
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

    let schema = object
        .metadata
        .as_ref()
        .and_then(|m| m.schema.as_deref())
        .unwrap_or("");
    let object_type = schema.split("::").next().unwrap_or("").to_string();

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
        if let Some(tlp) = &meta.tlp {
            if let Some(vocab) = vocabs.get("tlp") {
                if !vocab.contains(tlp) {
                    let mut d = Diagnostic::error(
                        codes::VOCAB_UNKNOWN,
                        format!("unknown tlp value '{tlp}'"),
                        key_range(input.source, "tlp"),
                    )
                    .with_field_path(vec!["metadata".into(), "tlp".into()]);
                    if let Some(s) = vocab.suggest(tlp) {
                        d = d.with_suggestion(s);
                    }
                    diagnostics.push(d);
                }
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
        if schema == "rule::1.0" && object.description.is_none() {
            diagnostics.push(
                Diagnostic::error(
                    codes::SCHEMA_VALIDATION,
                    "missing required field 'description'",
                    Range::point(0, 0),
                )
                .with_field_path(vec!["description".into()]),
            );
        }
    }

    if let Some(sev) = &object.severity {
        if let Some(vocab) = vocabs.get("severity") {
            if !vocab.contains(sev) {
                diagnostics.push(
                    Diagnostic::error(
                        codes::VOCAB_UNKNOWN,
                        format!("unknown severity '{sev}'"),
                        key_range(input.source, "severity"),
                    )
                    .with_field_path(vec!["severity".into()]),
                );
            }
        }
    }

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

    // Injected query analysis
    let injections = extract_injections(input.source);
    let skip: Vec<ByteSpan> = injections.iter().map(|inj| inj.host_span).collect();
    let mut tokens = highlight_tide(&spec, input.source, &skip);
    for inj in &injections {
        match inj.language {
            LanguageId::Kql => {
                let profile = if inj.field_path.iter().any(|p| p == "defender_for_endpoint") {
                    Profile::Defender
                } else {
                    Profile::Sentinel
                };
                let result = opentide_kql::analyze(&inj.inner, profile);
                for d in result.diagnostics {
                    diagnostics.push(remap_diagnostic(input.source, inj, d));
                }
                for t in result.tokens {
                    if let Some(mapped) = remap_token(input.source, inj, &t) {
                        tokens.push(mapped);
                    }
                }
            }
            LanguageId::Spl => {
                let result = opentide_spl::analyze(&inj.inner);
                for d in result.diagnostics {
                    diagnostics.push(remap_diagnostic(input.source, inj, d));
                }
                for t in result.tokens {
                    if let Some(mapped) = remap_token(input.source, inj, &t) {
                        tokens.push(mapped);
                    }
                }
            }
            LanguageId::TideYaml => {}
        }
    }

    tokens.sort_by_key(|t| (t.span.start, t.span.end));
    let symbols = document_symbols(input.source, &object, &object_type);
    TideAnalyzeResult {
        diagnostics,
        tokens,
        symbols,
    }
}

fn remap_diagnostic(source: &str, inj: &InjectedQuery, mut d: Diagnostic) -> Diagnostic {
    let inner_start = {
        // approximate: use the diagnostic range's start character on line 0 of inner
        let line = d.range.start.line as usize;
        let mut offset = 0usize;
        for (i, l) in inj.inner.split('\n').enumerate() {
            if i == line {
                offset += d.range.start.character as usize;
                break;
            }
            offset += l.len() + 1;
        }
        offset
    };
    let span = remap_span(inj, ByteSpan::new(inner_start, inner_start + 1));
    d.range = span_to_range(source, span);
    if d.field_path.is_none() {
        d.field_path = Some(inj.field_path.clone());
    }
    d
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

const STATUS_VALUES: &[&str] = &["STAGING", "DEVELOPMENT", "PRODUCTION", "DEPRECATED"];

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

fn key_capture(key: &str) -> &'static str {
    tide_key_capture(key)
}

fn highlight_scalar(
    spans: &mut Vec<(ByteSpan, &'static str)>,
    skip: &[ByteSpan],
    start: usize,
    value: &str,
    vocab: &[String],
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
        } else if vocab.iter().any(|v| v == value)
            || STATUS_VALUES.contains(&value)
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

fn highlight_tide(spec: &HighlightSpec, source: &str, skip: &[ByteSpan]) -> Vec<HighlightToken> {
    let mut spans = Vec::new();
    let mut vocab: Vec<String> = bundled_vocabs()
        .values()
        .flat_map(|v| v.keys.iter().map(|k| k.name.clone()))
        .collect();
    vocab.sort_by_key(|s| std::cmp::Reverse(s.len()));

    let mut in_block = false;
    let mut block_indent = 0usize;
    let mut block_is_injected = false;
    let mut block_is_markdown = false;
    let mut byte = 0usize;
    for line in source.split_inclusive('\n') {
        let indent = line.bytes().take_while(|b| *b == b' ').count();
        let trimmed = line.trim();
        if in_block && !trimmed.is_empty() && indent <= block_indent {
            in_block = false;
            block_is_injected = false;
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
            if !block_is_injected && !trimmed.is_empty() {
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

        if let Some((key, rest_text, key_start, key_end)) = line_key(line) {
            push_span(
                &mut spans,
                skip,
                byte + key_start,
                byte + key_end,
                key_capture(key),
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
            let is_block = {
                let t = rest_text.trim();
                t == "|"
                    || t == "|-"
                    || t == "|+"
                    || t == ">"
                    || t == ">-"
                    || t == ">+"
                    || t.starts_with('|')
                    || t.starts_with('>')
            };
            if is_block {
                in_block = true;
                block_indent = indent;
                block_is_injected = matches!(key, "query" | "search");
                block_is_markdown = !block_is_injected && tide_field_is_markdown(key);
            } else {
                highlight_scalar(&mut spans, skip, byte + rest_off, rest_text, &vocab);
            }
            byte += line.len();
            continue;
        }

        if let Some((item, indent)) = line_list_item(line) {
            let dash = byte + indent;
            push_span(&mut spans, skip, dash, dash + 1, "punctuation");
            if let Some((key, rest)) = item.split_once(':') {
                if !key.is_empty() && key.chars().all(is_yaml_key_char) {
                    let key_start = byte + indent + 2;
                    push_span(
                        &mut spans,
                        skip,
                        key_start,
                        key_start + key.len(),
                        key_capture(key),
                    );
                    let colon_at = key_start + key.len();
                    push_span(
                        &mut spans,
                        skip,
                        colon_at,
                        colon_at + 1,
                        "punctuation.delimiter",
                    );
                    highlight_scalar(&mut spans, skip, key_start + key.len() + 1, rest, &vocab);
                } else {
                    highlight_scalar(&mut spans, skip, byte + indent + 2, item, &vocab);
                }
            } else {
                highlight_scalar(&mut spans, skip, byte + indent + 2, item, &vocab);
            }
        }

        byte += line.len();
    }
    tokens_from_spans(spec, source, &spans).unwrap_or_default()
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

pub fn schemas() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("rule::1.0", RULE_SCHEMA),
        ("objective::1.0", OBJECTIVE_SCHEMA),
        ("threat::1.0", THREAT_SCHEMA),
    ])
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
severity: Substantial incident
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
        });
        assert!(r.diagnostics.iter().any(|d| d.code == codes::INVALID_UUID));
    }

    #[test]
    fn invalid_ref_detection_model() {
        let r = analyze(AnalyzeInput {
            path: "objects/rules/sentinel-kql-rule.yaml",
            source: RULE,
            workspace: &[],
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
        });
        assert!(
            r.tokens.iter().any(|t| t.capture == "tide.keyword"),
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
            workspace: &[],
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
        assert!(token_text(RULE, &r.tokens, "constant").contains(&"Substantial incident"));
        let uuid_keys = token_text(RULE, &r.tokens, "tide.property");
        assert!(uuid_keys.contains(&"uuid"), "{uuid_keys:?}");
        let starts: Vec<usize> = r.tokens.iter().map(|t| t.span.start).collect();
        let mut sorted = starts.clone();
        sorted.sort();
        assert_eq!(starts, sorted, "semantic tokens must be in document order");
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
                .any(|(c, t)| *c == "tide.keyword" && *t == "defender_for_endpoint"),
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
