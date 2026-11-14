//! YARA in Tide objects (yara-1.0; harfanglab-1.0 1.2, bitdefender-1.0).
//!
//! Two shapes reach the YARA engine:
//!
//! - **`signature`**: `configurations.{harfanglab,bitdefender}.yara.signature`,
//!   a whole YARA text, analysed as it is written under the platform's profile
//!   (an ordinary one-scalar injection, [`crate::injection`]);
//! - **the decomposed HarfangLab form**: `yara.strings`, `yara.condition` and
//!   `yara.imports` are assembled into the one rule deploy builds
//!   (`compile_yara_deployment`, `platforms/harfanglab/deployer.py`): the
//!   `import` lines, `rule <name> {`, the generated meta, and each body's
//!   lines indented by eight spaces after `strip()`. The bodies keep a map
//!   to their own scalar, so a finding lands where it is written; the text
//!   deploy generates is marked synthetic.
//!
//! The block's constraint codes (`harfanglab_rule_kind`, `_yara_form`,
//! `_yara_section_header`, `_yara_import`, `_yara_rule_name`) are the
//! model's (`opentide_schema::objects::platform::harfanglab::yara`), which
//! `opentide validate` and the editor report on the block; the engine's
//! finding for the same fault gives way ([`on_assembled`]).
//!
//! What a YAML loader gives deploy is read with the workspace's one YAML
//! reader ([`crate::yaml`]).

use std::sync::Arc;

use crate::yaml::{YamlNode, number_text};
use crate::yaml_scalar::{Scalar, YamlKey, scalar_at};
use crate::{InjectedQuery, InjectionPart};
use opentide_core::node::{Node, Value};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, codes};
use opentide_schema::objects::platform::harfanglab::yara::{
    OS_FILE_CONTEXT, derived_rule_name, rule_name_problem,
};

/// harfanglab-1.0 `SCORE_OVERRIDE_MAP`.
const SCORES: &[(&str, &str)] = &[
    ("Informational", "10"),
    ("Low", "30"),
    ("Medium", "50"),
    ("High", "70"),
    ("Critical", "90"),
];

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// The assembled text and its map, built part by part.
pub(crate) struct Builder {
    pub(crate) text: String,
    pub(crate) map: Vec<usize>,
    pub(crate) parts: Vec<InjectionPart>,
}

impl Builder {
    pub(crate) fn synthetic(&mut self, s: &str, host: usize, path: &[String]) {
        self.push(s, &vec![host; s.len()], path, true);
    }

    pub(crate) fn push(&mut self, s: &str, map: &[usize], path: &[String], synthetic: bool) {
        debug_assert_eq!(s.len(), map.len());
        let start = self.text.len();
        self.text.push_str(s);
        self.map.extend_from_slice(map);
        if s.is_empty() {
            return;
        }
        // Merge with the previous part when it is the same field.
        if let Some(last) = self.parts.last_mut()
            && last.field_path == path
            && last.synthetic == synthetic
            && last.end == start
        {
            last.end = self.text.len();
            return;
        }
        self.parts.push(InjectionPart {
            start,
            end: self.text.len(),
            field_path: path.to_vec(),
            synthetic,
        });
    }
}

/// The deployer's `SEVERITY_TO_SCORE` (and `SCORE_OVERRIDE_MAP`, the same
/// table): `response.alert_severity` when `meta.score` names none.
fn score_of(value: &str) -> Option<&'static str> {
    SCORES.iter().find(|(k, _)| *k == value).map(|(_, v)| *v)
}

/// `HarfangLabService.map_confidence`.
fn confidence_of(value: &str) -> &'static str {
    match value {
        "Weak" => "weak",
        "Strong" => "strong",
        _ => "moderate",
    }
}

pub(crate) fn path(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

pub(crate) fn find<'a>(keys: &'a [YamlKey], p: &[&str]) -> Option<&'a YamlKey> {
    keys.iter().find(|k| k.path_is(p))
}

/// A scalar's value as a YAML loader gives it to deploy.
fn deployed_text(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<String> {
    let key = find(keys, p)?;
    let at = key.scalar?;
    Some(chomped(source, at, scalar_at(source, at, key.column)?))
}

/// The value of the scalar at `at`, which [`scalar_at`] read as `scalar`,
/// with the final line breaks [`scalar_at`] leaves out of a block scalar:
/// chomping decides them: clip (`|`) keeps one, strip (`|-`) none, keep
/// (`|+`) every one, including the empty lines after the text.
fn chomped(source: &str, at: usize, scalar: Scalar) -> String {
    let mut text = scalar.text;
    let line_end = source[at..].find('\n').map_or(source.len(), |n| at + n);
    // The header token: `|` or `>`, then indicators up to a blank or comment.
    let header: String = source[at..line_end]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '#')
        .collect();
    if !header.starts_with(['|', '>']) || text.is_empty() {
        return text;
    }
    let indicators = &header[1..];
    if indicators.contains('-') {
        return text;
    }
    text.push('\n');
    if indicators.contains('+') {
        // Every empty line after the last line of text, up to the next
        // line with text (less indented: the scalar has ended) or the end.
        let last = scalar.map.last().copied().unwrap_or(at);
        let after = source[last..]
            .find('\n')
            .map_or(source.len(), |n| last + n + 1);
        for line in source[after..].split_inclusive('\n') {
            if !line.trim().is_empty() || !line.ends_with('\n') {
                break;
            }
            text.push('\n');
        }
    }
    text
}

fn text_of(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<String> {
    let key = find(keys, p)?;
    scalar_at(source, key.scalar?, key.column).map(|s| s.text)
}

/// `p` as the `&str` path the lookups take.
fn strs(p: &[String]) -> Vec<&str> {
    p.iter().map(String::as_str).collect()
}

/// One item of a sequence deploy reads.
pub(crate) struct Item {
    /// The value as deploy's YAML loader gives it.
    pub(crate) text: String,
    /// The source byte of each byte of `text`: exact where the item reads
    /// in place, else every byte at the item's start.
    pub(crate) map: Vec<usize>,
    /// `p.0`, `p.1`, ...
    pub(crate) path: Vec<String>,
    /// Where the item starts in the source.
    pub(crate) start: usize,
}

/// The document as deploy's YAML loader reads it, when it is valid YAML.
pub(crate) fn document(source: &str) -> Option<Arc<Node>> {
    crate::yaml::parse(source)
}

/// The value at `p` in `doc`; a list index is a path component too.
pub(crate) fn value_at<'a>(doc: &'a Arc<Node>, p: &[&str]) -> Option<&'a Arc<Node>> {
    p.iter().try_fold(doc, |v, k| match &v.value {
        Value::Seq(items) => items.get(k.parse::<usize>().ok()?),
        Value::Map(_) => v.get(k),
        _ => None,
    })
}

/// The scalar items of the sequence at `p`, as deploy reads them.
///
/// The values are the YAML loader's (`doc`, read as deploy reads it), so
/// comments, folded lines, escapes and chomping decode as deploy decodes
/// them, and an empty item stays an item. The source maps come from reading
/// the items in place, a block sequence (`- pe`) or a flow one
/// (`[pe, "a,b"]`); an item read differently maps to its start.
pub(crate) fn items(
    keys: &[YamlKey],
    source: &str,
    doc: Option<&Arc<Node>>,
    p: &[&str],
) -> Vec<Item> {
    let raw = raw_items(keys, source, p);
    let item = |index: usize, text: String| {
        let mut item_path = path(p);
        item_path.push(index.to_string());
        let at = raw.get(index);
        let map = match at {
            Some(r) if r.0 == text => r.1.clone(),
            Some(r) => vec![r.2; text.len()],
            None => vec![find(keys, p).map_or(0, |k| k.key_start); text.len()],
        };
        let start = at.map_or_else(|| map.first().copied().unwrap_or(0), |r| r.2);
        Item {
            text,
            map,
            path: item_path,
            start,
        }
    };
    let Some(doc) = doc else {
        // Not valid YAML, which deploy cannot load: the items as they read in place.
        return (0..raw.len())
            .filter(|&i| raw[i].3)
            .map(|i| item(i, raw[i].0.clone()))
            .collect();
    };
    let Some(values) = value_at(doc, p).and_then(|v| v.as_sequence()) else {
        return Vec::new();
    };
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let text = match &v.value {
                Value::Str(s) | Value::Datetime(s) => s.clone(),
                Value::Int(_) | Value::Float(_) => number_text(&v.value)?,
                Value::Bool(_) => raw.get(i)?.0.clone(),
                Value::Null | Value::Seq(_) | Value::Map(_) => return None,
            };
            Some(item(i, text))
        })
        .collect()
}

/// The sequence at `p` read in place: each item's text, source map, start,
/// and whether it is a scalar.
fn raw_items(keys: &[YamlKey], source: &str, p: &[&str]) -> Vec<(String, Vec<usize>, usize, bool)> {
    let Some(i) = keys.iter().position(|k| k.path_is(p)) else {
        return Vec::new();
    };
    let key = &keys[i];
    let Some(colon) = source[key.key_start..].find(':') else {
        return Vec::new();
    };
    let from = key.key_start + colon + 1;
    let end = keys
        .get(i + 1)
        .filter(|next| next.key_start > from)
        .map_or(source.len(), |next| next.key_start);
    let region = &source[from..end];
    let trimmed = region.trim_start_matches([' ', '\t']);
    if trimmed.starts_with('[') {
        flow_items(
            source,
            key.column,
            from + (region.len() - trimmed.len()) + 1,
            end,
        )
    } else {
        block_items(source, from, end)
    }
}

/// Whether `#` at `at` starts a comment: at a line start or after a blank.
fn comment_at(bytes: &[u8], at: usize) -> bool {
    bytes[at] == b'#' && (at == 0 || matches!(bytes[at - 1], b' ' | b'\t' | b'\n' | b'\r'))
}

/// Past blanks, line breaks and comments.
fn skip_separation(bytes: &[u8], mut at: usize, end: usize) -> usize {
    while at < end {
        match bytes[at] {
            b' ' | b'\t' | b'\n' | b'\r' => at += 1,
            b'#' if comment_at(bytes, at) => {
                while at < end && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            _ => break,
        }
    }
    at
}

/// The items of a flow sequence whose `[` ends before `at`.
fn flow_items(
    source: &str,
    column: usize,
    mut at: usize,
    end: usize,
) -> Vec<(String, Vec<usize>, usize, bool)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    loop {
        at = skip_separation(bytes, at, end);
        if at >= end || bytes[at] == b']' {
            break;
        }
        let start = at;
        match bytes[at] {
            b'"' | b'\'' => {
                // A quoted item: the decoder unescapes it and finds its end.
                let Some(item) = scalar_at(source, at, column) else {
                    break;
                };
                at = item.end;
                out.push((item.text, item.map, start, true));
            }
            b'[' | b'{' => {
                // A nested collection: one item, not a scalar.
                let mut depth = 0usize;
                while at < end {
                    match bytes[at] {
                        b'[' | b'{' => depth += 1,
                        b']' | b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                at += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    at += 1;
                }
                out.push((String::new(), Vec::new(), start, false));
            }
            _ => {
                // A plain item runs to `,`, `]` or a comment; its lines fold:
                // one line break is a space, each empty line a line break.
                let mut text = String::new();
                let mut map = Vec::new();
                let mut breaks: Vec<usize> = Vec::new();
                'lines: while at < end {
                    let line_start = at;
                    while at < end
                        && !matches!(bytes[at], b',' | b']' | b'\n')
                        && !comment_at(bytes, at)
                    {
                        at += 1;
                    }
                    let line = source[line_start..at].trim_end_matches([' ', '\t', '\r']);
                    if !line.is_empty() {
                        if !text.is_empty() {
                            match breaks.len() {
                                0 | 1 => {
                                    text.push(' ');
                                    map.push(breaks.first().copied().unwrap_or(line_start));
                                }
                                _ => {
                                    for b in &breaks[1..] {
                                        text.push('\n');
                                        map.push(*b);
                                    }
                                }
                            }
                        }
                        text.push_str(line);
                        map.extend(line_start..line_start + line.len());
                        breaks.clear();
                    }
                    if at >= end || bytes[at] != b'\n' {
                        break;
                    }
                    breaks.push(at);
                    at += 1;
                    while at < end && matches!(bytes[at], b' ' | b'\t') {
                        at += 1;
                    }
                    if at < end && (matches!(bytes[at], b',' | b']') || comment_at(bytes, at)) {
                        break 'lines;
                    }
                }
                out.push((text, map, start, true));
            }
        }
        at = skip_separation(bytes, at, end);
        if at < end && bytes[at] == b',' {
            at += 1;
        } else {
            break;
        }
    }
    out
}

/// The items of a block sequence in `from..end`: the lines whose `-` is at
/// the first item's column.
fn block_items(source: &str, from: usize, end: usize) -> Vec<(String, Vec<usize>, usize, bool)> {
    let mut out = Vec::new();
    let mut at = from;
    let mut item_column = None;
    for line in source[from..end].split_inclusive('\n') {
        let content = line.trim_start_matches([' ', '\t']);
        let dash = at + (line.len() - content.len());
        let column = dash - source[..dash].rfind('\n').map_or(0, |n| n + 1);
        at += line.len();
        let rest = match content.strip_prefix('-') {
            Some(rest) if rest.is_empty() || rest.starts_with([' ', '\t', '\n', '\r']) => rest,
            _ => continue,
        };
        if *item_column.get_or_insert(column) != column {
            continue;
        }
        let lead = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let item_at = dash + 1 + lead;
        // The item as a YAML loader reads it: quoted, plain or a block
        // scalar, with its comment dropped.
        match scalar_at(source, item_at, column) {
            Some(s) => {
                let map = s.map.clone();
                let text = chomped(source, item_at, s);
                let map = if text.len() == map.len() {
                    map
                } else {
                    // Chomping's line breaks: at the last byte of text.
                    let last = map.last().copied().unwrap_or(item_at);
                    let mut m = map;
                    m.resize(text.len(), last);
                    m
                };
                out.push((text, map, item_at, true));
            }
            None => out.push((String::new(), Vec::new(), item_at, false)),
        }
    }
    out
}

/// A body after Python's `strip()`, with its map.
fn stripped(text: &str, map: &[usize]) -> (String, Vec<usize>) {
    let start = text.len() - text.trim_start().len();
    let end = text.trim_end().len().max(start);
    (text[start..end].to_string(), map[start..end].to_vec())
}

/// A section header deploy writes itself, if a fragment has one: the byte
/// range of that line in the fragment's text.
fn section_header(text: &str) -> Option<(usize, usize, &str)> {
    // Comments and text strings are not sections: `/* rule of thumb */`.
    let masked = mask_comments_and_strings(text);
    let mut offset = 0;
    for line in masked.split('\n') {
        let trimmed = line.trim_start();
        let lead = line.len() - trimmed.len();
        let word: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        let rest = trimmed[word.len()..].trim_start();
        let header = match word.as_str() {
            "strings" | "condition" | "meta" if rest.starts_with(':') => Some(word.as_str()),
            "rule" if rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') => {
                Some("rule")
            }
            "private" | "global"
                if rest.starts_with("rule")
                    || rest.starts_with("private")
                    || rest.starts_with("global") =>
            {
                Some("rule")
            }
            _ => None,
        };
        if let Some(h) = header {
            let kind = match h {
                "strings" => "strings:",
                "condition" => "condition:",
                "meta" => "meta:",
                _ => "rule",
            };
            return Some((offset + lead, offset + line.trim_end().len(), kind));
        }
        offset += line.len() + 1;
    }
    None
}

/// `text` with its comments (`//`, `/* */`) and text strings (`"..."`)
/// blanked, byte for byte, newlines kept.
fn mask_comments_and_strings(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in &mut out[from..to] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = text[i..].find('\n').map_or(bytes.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = text[i + 2..]
                    .find("*/")
                    .map_or(bytes.len(), |n| i + 2 + n + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                    j += if bytes[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(bytes.len());
                blank(&mut out, i, end);
                i = end;
            }
            _ => i += 1,
        }
    }
    // Only ASCII bytes were replaced, with ASCII: still UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| text.to_string())
}

/// HarfangLab's decomposed `yara` block as the rule deploy assembles, or
/// `None` when it is not one (a `signature`, a header in a fragment, no
/// `strings` and `condition`).
pub(crate) fn decomposed_injection(source: &str, keys: &[YamlKey]) -> Option<InjectedQuery> {
    let block = ["configurations", "harfanglab", "yara"];
    let yara_key = find(keys, &block)?;
    if find(keys, &["configurations", "harfanglab", "yara", "signature"]).is_some() {
        return None;
    }
    let body = |name: &str| {
        let key = find(keys, &["configurations", "harfanglab", "yara", name])?;
        let s = scalar_at(source, key.scalar?, key.column)?;
        Some((s.text, s.map))
    };
    let (strings, strings_map) = body("strings")?;
    let (condition, condition_map) = body("condition")?;
    if section_header(&strings).is_some() || section_header(&condition).is_some() {
        return None;
    }
    let host = yara_key.key_start;
    let yara_path = path(&block);
    let mut b = Builder {
        text: String::new(),
        map: Vec::new(),
        parts: Vec::new(),
    };

    let doc = document(source);
    let imports = items(
        keys,
        source,
        doc.as_ref(),
        &["configurations", "harfanglab", "yara", "imports"],
    );
    if !imports.is_empty() {
        // The generated `import "…"` is the item's: a finding the engine
        // reports in it (an empty module name) lands on the item.
        for item in &imports {
            b.synthetic("import \"", item.start, &item.path);
            b.push(&item.text, &item.map, &item.path, false);
            b.synthetic("\"\n", item.start, &item.path);
        }
        b.synthetic("\n", host, &yara_path);
    }

    // Where a piece of generated text points: the value of the field it
    // stands for (its key, for a collection), else the `yara` key.
    let host_of = |p: &[&str]| find(keys, p).map_or(host, |k| k.scalar.unwrap_or(k.key_start));
    // A scalar as written, with its source map; `None` when absent or blank.
    let scalar = |p: &[&str]| {
        let key = find(keys, p)?;
        let s = scalar_at(source, key.scalar?, key.column)?;
        (!s.text.is_empty()).then_some((s.text, s.map))
    };

    let name = text_of(source, keys, &["name"]).unwrap_or_default();
    let mut rule_name = derived_rule_name(&name);
    if rule_name_problem(&name).is_some() {
        // `harfanglab_yara_rule_name` reports it; the bodies are still checked.
        rule_name = "opentide_rule".into();
    }
    let name_path = path(&["name"]);
    b.synthetic(
        &format!("rule {rule_name} {{\n"),
        host_of(&["name"]),
        &name_path,
    );

    // The meta lines `compile_yara_deployment` writes, in its order. What it
    // escapes cannot break the rule and is generated text; what it writes
    // as it is (`id`, the dates, `references`, `tags`, `context`, `os`,
    // `arch`) keeps its map, so a `"` in a tag is the parse error the
    // tenant reports, on that tag.
    let meta_path = path(&["configurations", "harfanglab", "yara", "meta"]);
    let meta_field = |name: &str| {
        let mut p = meta_path.clone();
        p.push(name.into());
        p
    };
    b.synthetic("    meta:\n", host_of(&strs(&meta_path)), &meta_path);
    // `key = "value"` with the value as written.
    let verbatim = |b: &mut Builder, key: &str, p: &[&str], value: Option<(String, Vec<usize>)>| {
        let field = path(p);
        let at = host_of(p);
        b.synthetic(&format!("        {key} = \""), at, &field);
        if let Some((text, map)) = value {
            b.push(&text, &map, &field, false);
        }
        b.synthetic("\"\n", at, &field);
    };
    // `key = "value"` with the value escaped.
    let escaped = |b: &mut Builder, key: &str, p: &[&str], value: &str| {
        b.synthetic(
            &format!("        {key} = \"{}\"\n", escape(value)),
            host_of(p),
            &path(p),
        );
    };
    verbatim(
        &mut b,
        "id",
        &["metadata", "uuid"],
        scalar(&["metadata", "uuid"]),
    );
    let title = deployed_text(source, keys, &["name"]).unwrap_or_default();
    escaped(&mut b, "title", &["name"], &title);
    let description = deployed_text(source, keys, &["description"]).unwrap_or_default();
    escaped(&mut b, "description", &["description"], &description);
    let author = deployed_text(source, keys, &["metadata", "author"])
        .filter(|t| !t.is_empty())
        .map(|t| (t, vec!["metadata", "author"]))
        .or_else(|| {
            deployed_text(source, keys, &["metadata", "organisation", "name"])
                .filter(|t| !t.is_empty())
                .map(|t| (t, vec!["metadata", "organisation", "name"]))
        })
        .unwrap_or_else(|| (String::new(), vec!["metadata", "author"]));
    escaped(&mut b, "author", &author.1, &author.0);
    for (key, field) in [("date", "created"), ("modified", "modified")] {
        let p = ["metadata", field];
        if let Some(value) = scalar(&p) {
            verbatim(&mut b, key, &p, Some(value));
        }
    }
    // `references.public` values, joined with `\n` (the two characters).
    let public: Vec<&YamlKey> = keys
        .iter()
        .filter(|k| k.path.len() == 3 && k.path[0] == "references" && k.path[1] == "public")
        .collect();
    let refs: Vec<Item> = public
        .iter()
        .filter_map(|k| {
            let at = k.scalar?;
            let s = scalar_at(source, at, k.column)?;
            Some(Item {
                text: s.text,
                map: s.map,
                path: k.path.clone(),
                start: at,
            })
        })
        .collect();
    let joined = |b: &mut Builder, key: &str, p: &[&str], values: &[Item], sep: &str| {
        let field = path(p);
        let at = host_of(p);
        b.synthetic(&format!("        {key} = \""), at, &field);
        for (i, item) in values.iter().enumerate() {
            if i > 0 {
                b.synthetic(sep, at, &field);
            }
            b.push(&item.text, &item.map, &item.path, false);
        }
        b.synthetic("\"\n", at, &field);
    };
    if !refs.is_empty() {
        joined(
            &mut b,
            "references",
            &["references", "public"],
            &refs,
            "\\n",
        );
    }
    let tags = items(
        keys,
        source,
        doc.as_ref(),
        &["configurations", "harfanglab", "tags"],
    );
    if !tags.is_empty() {
        joined(
            &mut b,
            "tags",
            &["configurations", "harfanglab", "tags"],
            &tags,
            ";",
        );
    }
    let os = scalar(&["configurations", "harfanglab", "yara", "meta", "os"]);
    let os_text = os.as_ref().map(|(t, _)| t.clone()).unwrap_or_default();
    let context_path = meta_field("context");
    let contexts: Vec<Item> = items(keys, source, doc.as_ref(), &strs(&context_path))
        .into_iter()
        .map(|item| {
            match OS_FILE_CONTEXT.iter().find(|(o, _)| *o == os_text) {
                // Deploy writes `file` as the os's file context.
                Some((_, file)) if item.text == "file" => Item {
                    text: file.to_string(),
                    map: vec![item.start; file.len()],
                    ..item
                },
                _ => item,
            }
        })
        .collect();
    if !contexts.is_empty() {
        joined(&mut b, "context", &strs(&context_path), &contexts, ",");
    }
    verbatim(&mut b, "os", &strs(&meta_field("os")), os);
    let arch_path = meta_field("arch");
    let arch_items = items(keys, source, doc.as_ref(), &strs(&arch_path));
    if !arch_items.is_empty() {
        joined(&mut b, "arch", &strs(&arch_path), &arch_items, ",");
    } else if let Some(arch) = scalar(&strs(&arch_path)) {
        verbatim(&mut b, "arch", &strs(&arch_path), Some(arch));
    }
    let classification_path = meta_field("classification");
    if let Some(c) =
        deployed_text(source, keys, &strs(&classification_path)).filter(|c| !c.is_empty())
    {
        escaped(&mut b, "classification", &strs(&classification_path), &c);
    }
    let score_path = meta_field("score");
    let score = scalar(&strs(&score_path))
        .and_then(|(s, _)| score_of(&s))
        .or_else(|| {
            let severity = text_of(source, keys, &["response", "alert_severity"])
                .unwrap_or_else(|| "Informational".into());
            Some(score_of(&severity).unwrap_or("50"))
        })
        .unwrap_or("50");
    b.synthetic(
        &format!("        score = {score}\n"),
        host_of(&strs(&score_path)),
        &score_path,
    );
    let confidence_path = ["configurations", "harfanglab", "confidence"];
    let confidence = text_of(source, keys, &confidence_path).unwrap_or_default();
    b.synthetic(
        &format!("        confidence = \"{}\"\n", confidence_of(&confidence)),
        host_of(&confidence_path),
        &path(&confidence_path),
    );

    let strings_p = ["configurations", "harfanglab", "yara", "strings"];
    let condition_p = ["configurations", "harfanglab", "yara", "condition"];
    let strings_path = path(&strings_p);
    let condition_path = path(&condition_p);
    b.synthetic("    strings:\n", host_of(&strings_p), &strings_path);
    // `condition:` closes the strings: an unclosed hex string is found there.
    for (text, map, field, at, header) in [
        (
            &strings,
            &strings_map,
            &strings_path,
            host_of(&strings_p),
            Some("    condition:\n"),
        ),
        (
            &condition,
            &condition_map,
            &condition_path,
            host_of(&condition_p),
            None,
        ),
    ] {
        let (text, map) = stripped(text, map);
        let mut offset = 0;
        for line in text.split('\n') {
            b.synthetic("        ", at, field);
            b.push(line, &map[offset..offset + line.len()], field, false);
            b.synthetic("\n", at, field);
            offset += line.len() + 1;
        }
        if let Some(h) = header {
            b.synthetic(h, at, field);
        }
    }
    // The closing brace ends the condition: a condition cut short is found here.
    b.synthetic("}", host_of(&condition_p), &condition_path);
    // The assembled text covers the bodies' scalars and what lies between.
    let real: Vec<usize> = b
        .parts
        .iter()
        .filter(|p| !p.synthetic)
        .flat_map(|p| b.map[p.start..p.end].iter().copied())
        .collect();
    let start = real.iter().copied().min()?;
    let end = real.iter().copied().max()? + 1;
    Some(InjectedQuery {
        language: LanguageId::Yara,
        platform: "harfanglab".into(),
        field_path: yara_path,
        inner: b.text,
        host_map: b.map,
        host_span: ByteSpan::new(start, end),
        parts: b.parts,
    })
}

/// A finding of the YARA engine on an assembled rule, as the block reports
/// it, on the bytes the author wrote. A finding inside generated text (an
/// unclosed condition found at the closing brace) moves to the nearest byte
/// of the field it belongs to, or, when that field has none, onto its key.
/// No error is lost.
pub(crate) fn on_assembled(
    inj: &InjectedQuery,
    inner: &opentide_core::LineIndex,
    mut d: Diagnostic,
) -> Option<Diagnostic> {
    if inj.parts.is_empty() {
        return Some(d);
    }
    // `harfanglab_yara_import` (the model's, which `validate` and the editor
    // report) and the block's own checks report these.
    if matches!(
        d.code.as_str(),
        codes::YARA_UNKNOWN_MODULE | codes::YARA_EMPTY_SIGNATURE
    ) {
        return None;
    }
    let len = inj.inner.len();
    if len == 0 {
        return Some(d);
    }
    let start = inner.offset(d.range.start).min(len - 1);
    let end = inner.offset(d.range.end).max(start + 1).min(len);
    let (first, last) = match (start..end).find(|&i| !inj.is_synthetic(i)) {
        Some(first) => {
            let last = (first..end)
                .take_while(|&i| !inj.is_synthetic(i))
                .last()
                .unwrap_or(first);
            (first, last)
        }
        None => {
            let field = inj.part_at(start).map(|p| p.field_path.clone());
            // Text the field wrote, or one of its items (`tags.1` for `tags`).
            let same = |i: usize| {
                inj.part_at(i).is_some_and(|p| {
                    !p.synthetic && field.as_ref().is_some_and(|f| p.field_path.starts_with(f))
                })
            };
            let at = (0..start)
                .rev()
                .find(|&i| same(i))
                .or_else(|| (start..len).find(|&i| same(i)))
                // The field wrote nothing: the generated byte, which maps
                // onto the field's key.
                .unwrap_or(start);
            (at, at)
        }
    };
    d.range = opentide_core::Range::new(inner.position(first), inner.position(last + 1));
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_follow_deploy() {
        assert_eq!(derived_rule_name("Cmd String-Exec"), "cmd_string_exec");
        assert_eq!(derived_rule_name("2024 Loader"), "rule_2024_loader");
        assert_eq!(derived_rule_name("a/b"), "a_b");
        assert_eq!(derived_rule_name("Détection"), "détection");
        assert!(rule_name_problem("Détection").is_some());
        assert!(rule_name_problem("Condition").is_some());
        assert!(rule_name_problem("Cmd String").is_none());
        assert!(rule_name_problem(&"a".repeat(128)).is_none());
        assert!(rule_name_problem(&"a".repeat(129)).is_some());
    }

    /// The model's YARA lists (0.28.1's, copied so `opentide-schema` needs no
    /// YARA engine) are the language catalog's.
    #[test]
    fn the_model_knows_the_catalog_s_modules_and_keywords() {
        use opentide_schema::objects::platform::harfanglab::yara::{YARA_KEYWORDS, YARA_MODULES};
        use opentide_yara::catalog::Catalog;
        let catalog = Catalog::cached();
        let modules: std::collections::BTreeSet<String> =
            YARA_MODULES.iter().map(|m| (*m).to_owned()).collect();
        assert_eq!(modules, catalog.known_modules);
        let keywords: std::collections::BTreeSet<String> =
            YARA_KEYWORDS.iter().map(|k| (*k).to_owned()).collect();
        let missing: Vec<&String> = keywords.difference(&catalog.keywords).collect();
        assert!(
            missing.is_empty(),
            "keywords the catalog lacks: {missing:?}"
        );
    }

    #[test]
    fn section_headers() {
        assert!(section_header("$a = \"x\"\ncondition:\n  $a").is_some());
        assert!(section_header("rule x {").is_some());
        assert!(section_header("$a = \"rule x\"").is_none());
        assert!(section_header("$a and pe.is_dll()").is_none());
        // Comments and text strings hold no header.
        assert!(section_header("/* rule of thumb */\n$a").is_none());
        assert!(section_header("$a // condition: below\nand $b").is_none());
        assert!(section_header("/*\nrule x {\n*/ $a").is_none());
        assert!(section_header("$a = \"x\" /* c */\ncondition:\n  $a").is_some());
    }
}
