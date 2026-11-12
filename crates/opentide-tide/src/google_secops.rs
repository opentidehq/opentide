//! Google SecOps blocks in Tide objects (google-secops-1.0, yara-l-1.0).
//!
//! `configurations.google_secops` carries one rule's YARA-L sections as keys
//! (`YaraLSections`): `setup`, `events`, `outcome`, `condition` and `export`
//! as text, `match` and `options` as YAML objects. They are one injection,
//! the rule deploy assembles ("Assembled rule"): the `rule` header and the
//! generated `meta`, then each section present, its label indented two
//! spaces and its lines four, one blank line before it. Line `n` of a section
//! text is line `L + n` of the assembled rule, `L` its label's line, and its
//! column is four more. Generated text (the header, the meta, the labels,
//! `match` and `options` rendered from YAML) is synthetic: it gets no token,
//! and a finding inside it moves to the field it stands for, or is left to
//! the block's own checks below.
//!
//! The block's constraint codes (`google_secops_*`), the structural YARA-L
//! codes on the YAML (`yaral_section_*`, `yaral_match_shape`,
//! `yaral_match_window`, `yaral_option`) and the advisories are reported here
//! as opentide reports them: `{code, field_path, severity}` with a range.

use crate::yaml_scalar::{YamlKey, scalar_at};
use crate::yara::{Builder, diag, document, find, is_alias, items, path, value_at};
use crate::{InjectedQuery, InjectionPart};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, LineIndex, codes};
use opentide_yaral::catalog::is_keyword;
use serde_yaml::Value;

const BLOCK: [&str; 2] = ["configurations", "google_secops"];
/// The sections that are YARA-L text.
pub(crate) const TEXT_SECTIONS: [&str; 5] = ["setup", "events", "outcome", "condition", "export"];
/// Every section key, in the order deploy writes them.
const SECTION_ORDER: [&str; 7] = [
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
];
/// Every section label, rule and search: a label in a section text is
/// `yaral_section_header`.
const LABELS: [&str; 13] = [
    "meta",
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
    "dedup",
    "order",
    "limit",
    "select",
    "unselect",
];
const SEVERITIES: [&str; 5] = ["Info", "Low", "Medium", "High", "Critical"];
const RUN_FREQUENCIES: [&str; 4] = ["LIVE", "LIVE_CUSTOMIZABLE", "HOURLY_CUSTOMIZABLE", "DAILY"];
const DERIVED_META: [&str; 7] = [
    "author",
    "description",
    "severity",
    "priority",
    "technique",
    "opentide_uuid",
    "opentide_version",
];

fn field(rest: &[&str]) -> Vec<String> {
    let mut p = path(&BLOCK);
    p.extend(rest.iter().map(|s| s.to_string()));
    p
}

fn at<'a>(rest: &'a [&'a str]) -> Vec<&'a str> {
    let mut p: Vec<&str> = BLOCK.to_vec();
    p.extend_from_slice(rest);
    p
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// google-secops-1.0 "Rule name": the block's `name`, else the rule's,
/// lower-cased, runs of other characters as one `_`, `r_` before a digit,
/// `opentide_<uuid>` when nothing is left.
pub fn derived_rule_name(block_name: Option<&str>, rule_name: &str, uuid: &str) -> String {
    if let Some(name) = block_name.filter(|n| !n.is_empty()) {
        return name.to_string();
    }
    let mut out = String::new();
    for c in rule_name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        return format!("opentide_{}", uuid.replace('-', "_"));
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("r_{out}");
    }
    out
}

/// A YARA-L double-quoted string of `text` (google-secops-1.0 "Meta").
fn meta_value(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The meta lines deploy writes, as far as the engine needs them: the keys
/// in their order, with values from the object (google-secops-1.0 1.1: no
/// `tactic`). Techniques inherited through `detection_model` are not resolved
/// here; the engine checks the sections, which the meta does not change.
fn meta_lines(doc: Option<&Value>) -> Vec<(String, String)> {
    let Some(doc) = doc else {
        return Vec::new();
    };
    let block = value_at(doc, &BLOCK);
    let get = |p: &[&str]| scalar_string(value_at(doc, p));
    let mut authors: Vec<String> = Vec::new();
    let contributors: Vec<String> = match block.and_then(|b| b.get("contributors")) {
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(|v| scalar_string(Some(v)))
            .collect(),
        _ => Vec::new(),
    };
    for author in get(&["metadata", "author"]).into_iter().chain(contributors) {
        if !author.is_empty() && !authors.contains(&author) {
            authors.push(author);
        }
    }
    let description = get(&["description"])
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let severity = get(&["configurations", "google_secops", "severity"]).unwrap_or_else(|| {
        match get(&["response", "alert_severity"]).as_deref() {
            Some("Informational") => "Info".into(),
            Some(s @ ("Low" | "Medium" | "High" | "Critical")) => s.into(),
            _ => "Medium".into(),
        }
    });
    let priority =
        get(&["configurations", "google_secops", "priority"]).unwrap_or_else(|| severity.clone());
    let mut lines = vec![
        ("author".to_string(), authors.join(", ")),
        ("description".to_string(), description),
        ("severity".to_string(), severity),
        ("priority".to_string(), priority),
    ];
    if let Some(Value::Sequence(techniques)) = doc.get("techniques") {
        let mut ids: Vec<String> = techniques
            .iter()
            .filter_map(|v| scalar_string(Some(v)))
            .collect();
        ids.sort();
        ids.dedup();
        if !ids.is_empty() {
            lines.push(("technique".to_string(), ids.join(",")));
        }
    }
    lines.push((
        "opentide_uuid".to_string(),
        get(&["metadata", "uuid"]).unwrap_or_default(),
    ));
    lines.push((
        "opentide_version".to_string(),
        get(&["metadata", "version"]).unwrap_or_default(),
    ));
    if let Some(Value::Mapping(meta)) = block.and_then(|b| b.get("meta")) {
        for (k, v) in meta {
            if let (Some(k), Some(v)) = (scalar_string(Some(k)), scalar_string(Some(v)))
                && is_identifier(&k)
                && !is_keyword(&k)
                && !DERIVED_META.contains(&k.as_str())
            {
                lines.push((k, v));
            }
        }
    }
    lines
}

/// `text` with comments and the contents of string, raw string and regex
/// literals blanked, line by line (a section scanner, not a parser): a label
/// or a brace inside a comment or a literal never counts.
fn code_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let mut buf = String::with_capacity(line.len());
        let mut quote: Option<char> = None;
        let mut chars = line.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if in_block {
                if line[i..].starts_with("*/") {
                    in_block = false;
                    chars.next();
                    buf.push_str("  ");
                } else {
                    buf.push(' ');
                }
                continue;
            }
            if let Some(q) = quote {
                if q == '"' && c == '\\' {
                    buf.push(' ');
                    if chars.next().is_some() {
                        buf.push(' ');
                    }
                    continue;
                }
                if c == q {
                    quote = None;
                    buf.push(c);
                } else {
                    buf.push(' ');
                }
                continue;
            }
            if line[i..].starts_with("//") {
                break;
            }
            if line[i..].starts_with("/*") {
                in_block = true;
                chars.next();
                buf.push_str("  ");
                continue;
            }
            if c == '"' || c == '`' {
                quote = Some(c);
            }
            buf.push(c);
        }
        out.push(buf);
    }
    out
}

/// Whether a section text holds a section label, a `rule` header, or braces
/// around a rule; with the byte range of that line in the text.
fn section_header(text: &str) -> Option<(usize, usize)> {
    let mut offset = 0;
    for line in code_lines(text) {
        let trimmed = line.trim_start();
        let lead = line.len() - trimmed.len();
        let word: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let rest = trimmed[word.len()..].trim_start();
        let lower = word.to_ascii_lowercase();
        let label = LABELS.contains(&lower.as_str()) && rest.starts_with(':');
        let header = lower == "rule"
            && rest
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        let brace = matches!(trimmed.trim_end(), "{" | "}");
        if label || header || brace {
            return Some((offset + lead, offset + line.trim_end().len().max(lead + 1)));
        }
        // `code_lines` keeps every byte, so offsets line up with the text.
        offset += line.len() + 1;
    }
    None
}

/// A section text, as deploy reads it: the scalar's value and map, without
/// its leading and trailing blank lines.
struct SectionText {
    text: String,
    map: Vec<usize>,
}

fn section_text(source: &str, key: &YamlKey) -> Option<SectionText> {
    let s = scalar_at(source, key.scalar?, key.column)?;
    let text = s.text;
    let map = s.map;
    // Drop blank lines at both ends.
    let mut start = 0;
    while let Some(nl) = text[start..].find('\n') {
        if text[start..start + nl].trim().is_empty() {
            start += nl + 1;
        } else {
            break;
        }
    }
    let mut end = text.len();
    loop {
        let line_start = text[start..end]
            .rfind('\n')
            .map_or(start, |n| start + n + 1);
        if line_start > start && text[line_start..end].trim().is_empty() {
            end = line_start - 1;
        } else {
            break;
        }
    }
    if text[start..end].trim().is_empty() {
        return None;
    }
    Some(SectionText {
        text: text[start..end].to_string(),
        map: map[start..end].to_vec(),
    })
}

/// A duration's minutes when its unit is m, h, or d (`YaraLMatch.window`,
/// `YaraLOptions.suppression_window`).
fn window_minutes(text: &str) -> Option<u64> {
    let digits = text.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 || text.starts_with('0') {
        return None;
    }
    let amount: u64 = text[..digits].parse().ok()?;
    let per = match &text[digits..] {
        "m" => 1,
        "h" => 60,
        "d" => 24 * 60,
        _ => return None,
    };
    Some(amount * per)
}

fn is_variable(text: &str) -> bool {
    text.strip_prefix('$').is_some_and(is_identifier)
}

/// The block's `match`, when it is a YaraLMatch that renders.
struct Match {
    kind: &'static str,
    window: String,
    sliding: bool,
}

fn renderable_match(value: &Value) -> Option<Match> {
    let Value::Mapping(m) = value else {
        return None;
    };
    let group = match m.get("group_by")? {
        Value::Sequence(items) => items,
        _ => return None,
    };
    let names: Vec<&str> = group.iter().filter_map(Value::as_str).collect();
    let distinct: std::collections::BTreeSet<&&str> = names.iter().collect();
    if names.is_empty()
        || names.len() != group.len()
        || distinct.len() != names.len()
        || !names.iter().all(|n| is_variable(n))
    {
        return None;
    }
    let window = m.get("window")?.as_str()?.to_string();
    let kind = match m.get("type").map(|t| t.as_str()) {
        None | Some(Some("hop")) => "hop",
        Some(Some("tumbling")) => "tumbling",
        Some(Some("sliding")) => "sliding",
        _ => return None,
    };
    let pivot = m.get("pivot").and_then(Value::as_str);
    let direction = m.get("direction").and_then(Value::as_str);
    let sliding = kind == "sliding";
    if sliding != (pivot.is_some() && direction.is_some()) {
        return None;
    }
    if sliding && !(pivot.is_some_and(is_variable) && matches!(direction, Some("before" | "after")))
    {
        return None;
    }
    Some(Match {
        kind: if kind == "tumbling" { "by" } else { "over" },
        window,
        sliding,
    })
}

/// The scalar at `p` as written: its text and map.
fn written(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<(String, Vec<usize>)> {
    let key = find(keys, p)?;
    let s = scalar_at(source, key.scalar?, key.column)?;
    Some((s.text, s.map))
}

/// A label `  <name>:`, the name mapped onto its key.
fn label(b: &mut Builder, name: &str, key: &YamlKey, host: usize) {
    let p = field(&[name]);
    b.synthetic("\n  ", host, &path(&BLOCK));
    let map: Vec<usize> = (0..name.len()).map(|i| key.key_start + i).collect();
    b.push(name, &map, &p, true);
    b.synthetic(":\n", key.key_start, &p);
}

/// A Google SecOps block's sections as the one rule deploy assembles, or
/// `None` when it is not one (no `events` text, or a text that holds a
/// header, which `yaral_section_header` reports).
pub(crate) fn assembled_injection(source: &str, keys: &[YamlKey]) -> Option<InjectedQuery> {
    let block_key = find(keys, &BLOCK)?;
    let host = block_key.key_start;
    let base = path(&BLOCK);
    let mut texts = Vec::new();
    for name in TEXT_SECTIONS {
        let Some(key) = find(keys, &at(&[name])) else {
            continue;
        };
        if is_alias(source, key) {
            continue;
        }
        if let Some(text) = section_text(source, key) {
            if section_header(&text.text).is_some() {
                return None;
            }
            texts.push((name, key, text));
        }
    }
    if !texts.iter().any(|(name, ..)| *name == "events") {
        return None;
    }
    let doc = document(source);
    let get = |p: &[&str]| doc.as_ref().and_then(|d| scalar_string(value_at(d, p)));
    let block_name = get(&at(&["name"]));
    let mut name = derived_rule_name(
        block_name.as_deref(),
        &get(&["name"]).unwrap_or_default(),
        &get(&["metadata", "uuid"]).unwrap_or_default(),
    );
    if !is_identifier(&name) || is_keyword(&name) {
        // `google_secops_rule_name` reports it; the sections are still checked.
        name = "opentide_rule".into();
    }
    let mut b = Builder {
        text: String::new(),
        map: Vec::new(),
        parts: Vec::new(),
    };
    b.synthetic(&format!("rule {name} {{\n  meta:\n"), host, &base);
    for (key, value) in meta_lines(doc.as_ref()) {
        b.synthetic(
            &format!("    {key} = {}\n", meta_value(&value)),
            host,
            &base,
        );
    }
    for name in SECTION_ORDER {
        match name {
            "match" => {
                let (Some(key), Some(value)) = (
                    find(keys, &at(&["match"])),
                    doc.as_ref().and_then(|d| value_at(d, &at(&["match"]))),
                ) else {
                    continue;
                };
                let Some(m) = renderable_match(value) else {
                    continue;
                };
                label(&mut b, "match", key, key.key_start);
                b.synthetic("    ", key.key_start, &field(&["match"]));
                let group = items(keys, source, doc.as_ref(), &at(&["match", "group_by"]));
                for (i, item) in group.iter().enumerate() {
                    if i > 0 {
                        b.synthetic(", ", key.key_start, &field(&["match", "group_by"]));
                    }
                    b.push(&item.text, &item.map, &item.path, true);
                }
                let kind_host = find(keys, &at(&["match", "type"]))
                    .or(find(keys, &at(&["match", "window"])))
                    .map_or(key.key_start, |k| k.key_start);
                b.synthetic(
                    &format!(" {} ", m.kind),
                    kind_host,
                    &field(&["match", "type"]),
                );
                match written(source, keys, &at(&["match", "window"])) {
                    Some((text, map)) if text == m.window => {
                        b.push(&text, &map, &field(&["match", "window"]), true)
                    }
                    _ => b.synthetic(&m.window, key.key_start, &field(&["match", "window"])),
                }
                if m.sliding {
                    for (part, pad) in [("direction", " "), ("pivot", " ")] {
                        b.synthetic(pad, key.key_start, &field(&["match", part]));
                        if let Some((text, map)) = written(source, keys, &at(&["match", part])) {
                            b.push(&text, &map, &field(&["match", part]), true);
                        }
                    }
                }
                b.synthetic("\n", key.key_start, &field(&["match"]));
            }
            "options" => {
                let (Some(key), Some(Value::Mapping(options))) = (
                    find(keys, &at(&["options"])),
                    doc.as_ref().and_then(|d| value_at(d, &at(&["options"]))),
                ) else {
                    continue;
                };
                let mut lines = Vec::new();
                for option in ["allow_zero_values", "suppression_window"] {
                    let value = match (option, options.get(option)) {
                        ("allow_zero_values", Some(Value::Bool(v))) => v.to_string(),
                        ("suppression_window", Some(Value::String(v)))
                            if window_minutes(v).is_some() =>
                        {
                            v.clone()
                        }
                        _ => continue,
                    };
                    lines.push((option, value));
                }
                if lines.is_empty() {
                    continue;
                }
                label(&mut b, "options", key, key.key_start);
                for (option, value) in lines {
                    let p = field(&["options", option]);
                    let option_key = find(keys, &at(&["options", option]));
                    let option_host = option_key.map_or(key.key_start, |k| k.key_start);
                    b.synthetic("    ", option_host, &p);
                    let key_map: Vec<usize> = (0..option.len()).map(|i| option_host + i).collect();
                    b.push(option, &key_map, &p, true);
                    b.synthetic(" = ", option_host, &p);
                    match written(source, keys, &at(&["options", option])) {
                        Some((text, map)) if text == value => b.push(&text, &map, &p, true),
                        _ => b.synthetic(&value, option_host, &p),
                    }
                    b.synthetic("\n", option_host, &p);
                }
            }
            _ => {
                let Some((_, key, text)) = texts.iter().find(|(n, ..)| *n == name) else {
                    continue;
                };
                label(&mut b, name, key, key.key_start);
                let p = field(&[name]);
                let mut start = 0;
                let lines: Vec<&str> = text.text.split('\n').collect();
                for (index, line) in lines.iter().enumerate() {
                    let end = start + line.len();
                    let content = line.strip_suffix('\r').unwrap_or(line);
                    let line_host = text.map.get(start).copied().unwrap_or(key.key_start);
                    if content.trim().is_empty() {
                        b.synthetic("\n", line_host, &p);
                    } else {
                        b.synthetic("    ", line_host, &p);
                        b.push(content, &text.map[start..start + content.len()], &p, false);
                        // The line break: the source's own, so a cursor at
                        // the end of a line is in the section.
                        let last = text.map[start + content.len() - 1];
                        let newline = if index + 1 < lines.len() {
                            text.map.get(end).copied()
                        } else {
                            source[last + 1..]
                                .find('\n')
                                .map(|n| last + 1 + n)
                                .filter(|&n| source[last + 1..n].trim().is_empty())
                        };
                        match newline {
                            Some(at) if source.as_bytes().get(at) == Some(&b'\n') => {
                                b.push("\n", &[at], &p, false)
                            }
                            _ => b.synthetic("\n", last, &p),
                        }
                    }
                    start = end + 1;
                }
            }
        }
    }
    b.synthetic("}\n", host, &base);
    let real: Vec<usize> = b
        .parts
        .iter()
        .filter(|p| !p.synthetic)
        .flat_map(|p| b.map[p.start..p.end].iter().copied())
        .collect();
    let start = real.iter().copied().min()?;
    let end = real.iter().copied().max()? + 1;
    Some(InjectedQuery {
        language: LanguageId::Yaral,
        platform: "google_secops".into(),
        field_path: base,
        inner: b.text,
        host_map: b.map,
        host_span: ByteSpan::new(start, end),
        parts: b.parts,
    })
}

/// A finding of the YARA-L engine on an assembled rule, as the block reports
/// it. What the block's checks report on the YAML is dropped
/// (`yaral_section_*`, `yaral_match_shape`, and the window and option
/// findings on rendered `match` and `options`); a finding in rendered
/// `match` or `options` text lands on the YAML value it was rendered from;
/// one in the generated header or meta is the platform's (a constraint
/// code), except a syntax error, which moves to the nearest text the author
/// wrote.
pub(crate) fn on_assembled(
    inj: &InjectedQuery,
    inner: &LineIndex,
    has_match_key: bool,
    mut d: Diagnostic,
) -> Option<Diagnostic> {
    if inj.parts.is_empty() {
        return Some(d);
    }
    if matches!(
        d.code.as_str(),
        codes::YARAL_SECTION_MISSING
            | codes::YARAL_SECTION_EMPTY
            | codes::YARAL_SECTION_HEADER
            | codes::YARAL_SECTION_ALIAS
            | codes::YARAL_MATCH_SHAPE
    ) {
        return None;
    }
    // A `match` that does not render is a shape the block's checks report.
    if d.code == codes::YARAL_MULTI_EVENT_MATCH && has_match_key {
        return None;
    }
    let len = inj.inner.len();
    if len == 0 {
        return Some(d);
    }
    let start = inner.offset(d.range.start).min(len - 1);
    let end = inner.offset(d.range.end).max(start + 1).min(len);
    let part: Option<&InjectionPart> = inj.part_at(start);
    let Some(part) = part.filter(|p| p.synthetic) else {
        return Some(d);
    };
    let block = path(&BLOCK);
    let rendered =
        part.field_path.len() > 2 && matches!(part.field_path[2].as_str(), "match" | "options");
    if rendered {
        if matches!(
            d.code.as_str(),
            codes::YARAL_MATCH_WINDOW | codes::YARAL_OPTION
        ) {
            return None;
        }
        d.range = opentide_core::Range::new(inner.position(part.start), inner.position(part.end));
        d.field_path = Some(part.field_path.clone());
        return Some(d);
    }
    if part.field_path == block {
        if d.code != codes::YARAL_PARSE_ERROR {
            return None;
        }
        // The closing brace or the meta: the nearest text the author wrote.
        let real = |i: usize| !inj.is_synthetic(i);
        let at = (0..start)
            .rev()
            .find(|&i| real(i) && !inj.inner[i..].starts_with('\n'))
            .or_else(|| (end..len).find(|&i| real(i)))?;
        d.range = opentide_core::Range::new(inner.position(at), inner.position(at + 1));
        return Some(d);
    }
    // A label: the finding is the section's, on its key's name.
    let name = part.field_path.last().map_or(1, String::len);
    let end = (part.start + name).min(part.end);
    d.range = opentide_core::Range::new(inner.position(part.start), inner.position(end));
    Some(d)
}

/// The constraint codes, the structural YARA-L codes on the YAML, and the
/// advisories of a Google SecOps block.
pub(crate) fn constraint_diagnostics(source: &str, keys: &[YamlKey]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if find(keys, &BLOCK).is_none() {
        return out;
    }
    let doc = document(source);
    let block = doc.as_ref().and_then(|d| value_at(d, &BLOCK));
    let Some(Value::Mapping(block)) = block else {
        return out;
    };
    let error = |out: &mut Vec<Diagnostic>, code: &'static str, message: String, rest: &[&str]| {
        out.push(diag(source, code, message, &at(rest)));
    };
    let value_range = |rest: &[&str]| {
        find(keys, &at(rest))
            .and_then(|k| scalar_at(source, k.scalar?, k.column))
            .filter(|s| !s.map.is_empty())
            .map(|s| {
                opentide_core::span_to_range(
                    source,
                    ByteSpan::new(s.map[0], s.map[s.map.len() - 1] + 1),
                )
            })
    };
    let get = |name: &str| block.get(name);

    // google_secops_rule_name
    if let Some(Value::String(name)) = get("name")
        && !name.is_empty()
        && (!is_identifier(name) || is_keyword(name))
    {
        let why = if is_keyword(name) {
            "a YARA-L keyword"
        } else {
            "not a YARA-L identifier ([A-Za-z_][A-Za-z0-9_]*)"
        };
        let mut d = diag(
            source,
            codes::GOOGLE_SECOPS_RULE_NAME,
            format!("`{name}` is {why}: Google SecOps refuses it as a rule name"),
            &at(&["name"]),
        );
        if let Some(r) = value_range(&["name"]) {
            d.range = r;
        }
        out.push(d);
    }
    // google_secops_severity
    for key in ["severity", "priority"] {
        if let Some(value) = get(key)
            && !value.as_str().is_some_and(|v| SEVERITIES.contains(&v))
        {
            let shown = scalar_string(Some(value)).unwrap_or_else(|| "a collection".into());
            let mut d = diag(
                source,
                codes::GOOGLE_SECOPS_SEVERITY,
                format!("`{shown}` is not Info, Low, Medium, High, or Critical"),
                &at(&[key]),
            );
            if let Some(r) = value_range(&[key]) {
                d.range = r;
            }
            out.push(d);
        }
    }
    // google_secops_run_frequency
    let frequency = get("run_frequency").and_then(Value::as_str);
    if let Some(value) = get("run_frequency")
        && !frequency.is_some_and(|f| RUN_FREQUENCIES.contains(&f))
    {
        let shown = scalar_string(Some(value)).unwrap_or_default();
        let legacy = if shown == "HOURLY" {
            ": Google's legacy HOURLY is refused; write HOURLY_CUSTOMIZABLE"
        } else {
            ""
        };
        let mut d = diag(
            source,
            codes::GOOGLE_SECOPS_RUN_FREQUENCY,
            format!(
                "`{shown}` is not LIVE, LIVE_CUSTOMIZABLE, HOURLY_CUSTOMIZABLE, or DAILY{legacy}"
            ),
            &at(&["run_frequency"]),
        );
        if let Some(r) = value_range(&["run_frequency"]) {
            d.range = r;
        }
        out.push(d);
    }
    // google_secops_schedule
    if let Some(schedule) = get("schedule") {
        if !matches!(frequency, Some("LIVE_CUSTOMIZABLE" | "HOURLY_CUSTOMIZABLE")) {
            error(
                &mut out,
                codes::GOOGLE_SECOPS_SCHEDULE,
                "`schedule` customizes LIVE_CUSTOMIZABLE and HOURLY_CUSTOMIZABLE rules only: set `run_frequency` to one of them".into(),
                &["schedule"],
            );
        }
        if let Some(adjustment) = schedule.get("late_arriving_data_adjustment") {
            let text = adjustment.as_str().unwrap_or("");
            let digits = text.chars().take_while(char::is_ascii_digit).count();
            let ok = digits > 0
                && !text.starts_with('0')
                && matches!(&text[digits..], "s" | "m" | "h" | "d");
            if !ok {
                let shown = scalar_string(Some(adjustment)).unwrap_or_default();
                let mut d = diag(
                    source,
                    codes::GOOGLE_SECOPS_SCHEDULE,
                    format!("`{shown}` is not a positive duration (`30m`, `2h`)"),
                    &at(&["schedule", "late_arriving_data_adjustment"]),
                );
                if let Some(r) = value_range(&["schedule", "late_arriving_data_adjustment"]) {
                    d.range = r;
                }
                out.push(d);
            }
        }
    }
    // google_secops_meta_key
    if let Some(Value::Mapping(meta)) = get("meta") {
        for (k, v) in meta {
            let key = scalar_string(Some(k)).unwrap_or_default();
            let problem = if !is_identifier(&key) {
                Some("is not an identifier")
            } else if is_keyword(&key) {
                Some("is a YARA-L keyword")
            } else if DERIVED_META.contains(&key.as_str()) {
                Some("is written by deploy from the rule")
            } else if !v.is_string() {
                Some("needs a string value")
            } else {
                None
            };
            if let Some(problem) = problem {
                out.push(diag(
                    source,
                    codes::GOOGLE_SECOPS_META_KEY,
                    format!("meta `{key}` {problem}"),
                    &at(&["meta", &key]),
                ));
            }
        }
    }
    // yaral_section_missing, _empty, _alias, _header
    for required in ["events", "condition"] {
        if !block.contains_key(required) {
            out.push(
                diag(
                    source,
                    codes::YARAL_SECTION_MISSING,
                    format!("a Google SecOps rule needs `{required}`"),
                    &BLOCK,
                )
                .with_field_path(field(&[required])),
            );
        }
    }
    for name in TEXT_SECTIONS {
        let Some(key) = find(keys, &at(&[name])) else {
            continue;
        };
        if is_alias(source, key) {
            error(
                &mut out,
                codes::YARAL_SECTION_ALIAS,
                format!(
                    "`{name}` is a YAML alias: write the section out in this block, so the block shows what it deploys"
                ),
                &[name],
            );
            continue;
        }
        match block.get(name) {
            None | Some(Value::Null) => {
                let comment = key
                    .scalar
                    .is_none()
                    .then(|| source[key.key_start..].split('\n').next().unwrap_or(""))
                    .is_some_and(|line| {
                        line.split_once(':')
                            .is_some_and(|(_, v)| v.trim_start().starts_with('#'))
                    });
                let hint = if comment {
                    ": a plain scalar that starts with `#` is a YAML comment; write the text as a block scalar (`|`)"
                } else {
                    ""
                };
                error(
                    &mut out,
                    codes::YARAL_SECTION_EMPTY,
                    format!("`{name}` has no text{hint}"),
                    &[name],
                );
            }
            Some(Value::String(text)) if text.trim().is_empty() => error(
                &mut out,
                codes::YARAL_SECTION_EMPTY,
                format!("`{name}` has no text"),
                &[name],
            ),
            Some(Value::String(_)) => {
                if let Some(text) = section_text(source, key)
                    && let Some((s, e)) = section_header(&text.text)
                {
                    let span =
                        ByteSpan::new(text.map[s], text.map[(e - 1).min(text.map.len() - 1)] + 1);
                    out.push(
                        Diagnostic::error(
                            codes::YARAL_SECTION_HEADER,
                            format!("`{name}` holds a section label, a `rule` header or braces: deploy writes those, so write only the {name} section's body"),
                            opentide_core::span_to_range(source, span),
                        )
                        .with_field_path(field(&[name])),
                    );
                }
            }
            Some(_) => error(
                &mut out,
                codes::YARAL_SECTION_EMPTY,
                format!("`{name}` is YARA-L text, not a YAML collection"),
                &[name],
            ),
        }
    }
    for name in ["match", "options"] {
        if let Some(key) = find(keys, &at(&[name]))
            && is_alias(source, key)
        {
            error(
                &mut out,
                codes::YARAL_SECTION_ALIAS,
                format!("`{name}` is a YAML alias: write it out in this block"),
                &[name],
            );
        }
    }
    // yaral_match_shape, yaral_match_window
    let mut match_minutes = None;
    if let Some(m) = get("match") {
        match_minutes = match_checks(source, m, &mut out);
    }
    // yaral_option
    if let Some(options) = get("options") {
        option_checks(source, options, match_minutes, &mut out);
    }
    advisories(source, keys, block, frequency, &mut out);
    out
}

fn match_checks(source: &str, m: &Value, out: &mut Vec<Diagnostic>) -> Option<u64> {
    let push = |out: &mut Vec<Diagnostic>, code: &'static str, message: String, rest: &[&str]| {
        out.push(diag(source, code, message, &at(rest)));
    };
    let Value::Mapping(map) = m else {
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            "`match` is an object with `group_by` and `window`".into(),
            &["match"],
        );
        return None;
    };
    let fields = ["group_by", "window", "type", "pivot", "direction"];
    let unknown: Vec<String> = map
        .keys()
        .filter_map(|k| scalar_string(Some(k)))
        .filter(|k| !fields.contains(&k.as_str()))
        .collect();
    if !unknown.is_empty() {
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            format!("unknown match keys: {}", unknown.join(", ")),
            &["match"],
        );
    }
    let group_ok = match map.get("group_by") {
        Some(Value::Sequence(items)) => {
            let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            let distinct: std::collections::BTreeSet<&&str> = names.iter().collect();
            !items.is_empty()
                && names.len() == items.len()
                && names.iter().all(|n| is_variable(n))
                && distinct.len() == names.len()
        }
        _ => false,
    };
    if !group_ok {
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            "`group_by` is a non-empty list of distinct `$placeholders`".into(),
            &["match", "group_by"],
        );
    }
    let kind = match map.get("type") {
        None => Some("hop"),
        Some(v) => v
            .as_str()
            .filter(|t| matches!(*t, "hop" | "tumbling" | "sliding")),
    };
    if kind.is_none() {
        let shown = map
            .get("type")
            .and_then(|v| scalar_string(Some(v)))
            .unwrap_or_default();
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            format!("`{shown}` is not hop, tumbling, or sliding"),
            &["match", "type"],
        );
    }
    let sliding = kind == Some("sliding");
    let pivot = map.get("pivot");
    let direction = map.get("direction");
    if sliding
        && !(pivot.and_then(Value::as_str).is_some_and(is_variable)
            && matches!(direction.and_then(Value::as_str), Some("before" | "after")))
    {
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            "a sliding window needs `pivot` (the `$event` it is anchored on) and `direction` (before or after)".into(),
            &["match"],
        );
    }
    if !sliding && (pivot.is_some() || direction.is_some()) {
        push(
            out,
            codes::YARAL_MATCH_SHAPE,
            "`pivot` and `direction` belong to a sliding window (`type: sliding`)".into(),
            &["match"],
        );
    }
    let window = map.get("window");
    let minutes = window.and_then(Value::as_str).and_then(window_minutes);
    let shown = window
        .and_then(|w| scalar_string(Some(w)))
        .unwrap_or_default();
    match minutes {
        None => push(
            out,
            codes::YARAL_MATCH_WINDOW,
            format!(
                "`{shown}` is not a window: a number of minutes, hours or days (`10m`, `1h`, `2d`)"
            ),
            &["match", "window"],
        ),
        Some(m) => {
            let (max, bound) = if kind == Some("tumbling") {
                (72 * 60, "72h")
            } else {
                (14 * 24 * 60, "14d")
            };
            if m > max {
                push(
                    out,
                    codes::YARAL_MATCH_WINDOW,
                    format!(
                        "{shown}: a {} window is at most {bound}",
                        kind.unwrap_or("hop")
                    ),
                    &["match", "window"],
                );
            }
        }
    }
    minutes
}

fn option_checks(source: &str, options: &Value, window: Option<u64>, out: &mut Vec<Diagnostic>) {
    let Value::Mapping(map) = options else {
        out.push(diag(
            source,
            codes::YARAL_OPTION,
            "`options` is an object: allow_zero_values, suppression_window".into(),
            &at(&["options"]),
        ));
        return;
    };
    for (k, v) in map {
        let key = scalar_string(Some(k)).unwrap_or_default();
        let ok = match key.as_str() {
            "allow_zero_values" => v.is_bool(),
            "suppression_window" => v.as_str().and_then(window_minutes).is_some(),
            _ => false,
        };
        if !ok {
            let shown = scalar_string(Some(v)).unwrap_or_default();
            out.push(diag(
                source,
                codes::YARAL_OPTION,
                format!("{key}: `{shown}` is not allow_zero_values (boolean) or suppression_window (a duration)"),
                &at(&["options", &key]),
            ));
            continue;
        }
        if key == "suppression_window"
            && let (Some(w), Some(s)) = (window, v.as_str().and_then(window_minutes))
            && s <= w
        {
            out.push(diag(
                source,
                codes::YARAL_OPTION,
                format!(
                    "suppression_window {} must be longer than the match window",
                    v.as_str().unwrap_or("")
                ),
                &at(&["options", "suppression_window"]),
            ));
        }
    }
}

/// The event variables a section text names (`$e` of `$e.metadata...`).
fn event_variables(text: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > start && bytes.get(j) == Some(&b'.') {
                out.insert(text[start..j].to_string());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

fn advisories(
    source: &str,
    keys: &[YamlKey],
    block: &serde_yaml::Mapping,
    frequency: Option<&str>,
    out: &mut Vec<Diagnostic>,
) {
    let text = |name: &str| block.get(name).and_then(Value::as_str).unwrap_or("");
    let has_risk_score = code_lines(text("outcome")).iter().any(|line| {
        let t = line.trim_start();
        t.strip_prefix("$risk_score")
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    });
    if block.contains_key("events") && !has_risk_score {
        let target: &[&str] = if block.contains_key("outcome") {
            &["outcome"]
        } else {
            &[]
        };
        out.push(
            Diagnostic::warning(
                codes::GOOGLE_SECOPS_RISK_SCORE_MISSING,
                "`outcome` assigns no `$risk_score`: Google scores every alert 40 and every non-alerting detection 15, whatever the rule detects",
                crate::elastic::path_range(source, &at(target)),
            )
            .with_field_path(field(target)),
        );
    }
    for name in ["events", "condition"] {
        let Some(key) = find(keys, &at(&[name])) else {
            continue;
        };
        let Some(section) = section_text(source, key) else {
            continue;
        };
        let masked = code_lines(&section.text).join("\n");
        let mut from = 0;
        while let Some(found) = masked[from..].find("detection.detection.rule_id") {
            let after = from + found + "detection.detection.rule_id".len();
            let rest = &section.text[after..];
            let trimmed = rest.trim_start();
            let op = if trimmed.starts_with("!=") {
                2
            } else if trimmed.starts_with('=') {
                1
            } else {
                0
            };
            if op > 0 {
                let value = trimmed[op..].trim_start();
                if value.starts_with("\"ru_") || value.starts_with("`ru_") {
                    let start = after + (rest.len() - value.len());
                    let end = start + value[1..].find(['"', '`']).map_or(value.len(), |n| n + 2);
                    let span = ByteSpan::new(
                        section.map[start],
                        section.map[(end - 1).min(section.map.len() - 1)] + 1,
                    );
                    out.push(
                        Diagnostic::warning(
                            codes::GOOGLE_SECOPS_RULE_ID_LITERAL,
                            "the rule id differs per tenant and changes when a rule is recreated: match the producer with `detection.detection.rule_name`",
                            opentide_core::span_to_range(source, span),
                        )
                        .with_field_path(field(&[name])),
                    );
                }
            }
            from = after;
        }
    }
    if frequency == Some("LIVE") && event_variables(text("events")).len() >= 2 {
        out.push(
            Diagnostic::warning(
                codes::GOOGLE_SECOPS_LIVE_FREQUENCY_UNAVAILABLE,
                "`LIVE` runs single-event rules only: Google stores LIVE_CUSTOMIZABLE for this multi-event rule, so the block differs from the tenant on every deploy",
                crate::elastic::path_range(source, &at(&["run_frequency"])),
            )
            .with_field_path(field(&["run_frequency"])),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_follow_the_spec() {
        assert_eq!(
            derived_rule_name(None, "Office application spawns encoded PowerShell", "u"),
            "office_application_spawns_encoded_powershell"
        );
        assert_eq!(derived_rule_name(None, "2FA bypass!", "u"), "r_2fa_bypass");
        assert_eq!(derived_rule_name(None, "!!!", "a-b"), "opentide_a_b");
        assert_eq!(derived_rule_name(Some("x"), "y", "u"), "x");
    }

    #[test]
    fn meta_values_are_yaral_strings() {
        assert_eq!(meta_value("a \"b\"\\c\nd"), "\"a \\\"b\\\"\\\\c d\"");
    }

    #[test]
    fn section_headers() {
        assert!(section_header("events:\n  $e.metadata.event_type = \"X\"").is_some());
        assert!(section_header("$e\noptions:\n  allow_zero_values = true").is_some());
        assert!(section_header("rule x {").is_some());
        assert!(section_header("}").is_some());
        assert!(
            section_header("$e.metadata.description = \"condition: none\" // match: in a comment")
                .is_none()
        );
        assert!(section_header("/* rule of thumb */ $e").is_none());
    }
}
