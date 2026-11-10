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
//! The block's constraint codes are here too, reported as opentide reports
//! them: `{code, field_path, severity}` with a range.

use crate::yaml_scalar::{YamlKey, scalar_at};
use crate::{InjectedQuery, InjectionPart};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, codes};
use opentide_yara::catalog::Catalog;

/// The platforms whose `yara` block holds a YaraSignature.
pub(crate) const PLATFORMS: &[&str] = &["harfanglab", "bitdefender"];

/// The longest identifier libyara 4.5 accepts.
const MAX_IDENTIFIER: usize = 128;

/// The keys of HarfangLab's decomposed form.
const DECOMPOSED: &[&str] = &["meta", "strings", "condition", "imports"];

/// harfanglab-1.0 `SCORE_OVERRIDE_MAP`.
const SCORES: &[(&str, &str)] = &[
    ("Informational", "10"),
    ("Low", "30"),
    ("Medium", "50"),
    ("High", "70"),
    ("Critical", "90"),
];

/// harfanglab-1.0: the `file` context deploy rewrites by `os`.
const OS_TO_FILE_CONTEXT: &[(&str, &str)] = &[
    ("Windows", "file.pe"),
    ("MacOS", "file.macho"),
    ("Linux", "file.elf"),
];

/// The YARA rule name deploy derives from the Tide rule `name`: lowercased,
/// spaces and `-` as `_`, any other character that is not alphanumeric as
/// `_`, and `rule_` before a leading digit. Python's `str.isalnum` keeps
/// non-ASCII letters, which libyara refuses (`harfanglab_yara_rule_name`).
pub fn derived_rule_name(name: &str) -> String {
    let lowered: String = name.to_lowercase().replace([' ', '-'], "_");
    let mut out: String = lowered
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.chars().next().is_some_and(char::is_numeric) {
        out.insert_str(0, "rule_");
    }
    out
}

/// Why libyara refuses a derived rule name, if it does.
fn rule_name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("the rule `name` derives an empty YARA rule name".into());
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        return Some(format!(
            "deploy derives the YARA rule name `{name}`, which keeps `{c}`: libyara takes only ASCII letters, digits and `_`"
        ));
    }
    if Catalog::cached().keywords.contains(name) {
        return Some(format!(
            "deploy derives the YARA rule name `{name}`, a YARA keyword"
        ));
    }
    if name.len() > MAX_IDENTIFIER {
        return Some(format!(
            "deploy derives a YARA rule name of {} characters from the rule `name`: libyara refuses an identifier longer than {MAX_IDENTIFIER}",
            name.len()
        ));
    }
    None
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "")
}

/// The assembled text and its map, built part by part.
struct Builder {
    text: String,
    map: Vec<usize>,
    parts: Vec<InjectionPart>,
}

impl Builder {
    fn synthetic(&mut self, s: &str, host: usize, path: &[String]) {
        self.push(s, &vec![host; s.len()], path, true);
    }

    fn push(&mut self, s: &str, map: &[usize], path: &[String], synthetic: bool) {
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

fn path(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

fn find<'a>(keys: &'a [YamlKey], p: &[&str]) -> Option<&'a YamlKey> {
    keys.iter().find(|k| k.path_is(p))
}

/// A scalar's value as a YAML loader gives it to deploy: a block scalar keeps
/// its final line break unless chomped with `-` (`|`, `|+`), which
/// [`scalar_at`] leaves out.
fn deployed_text(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<String> {
    let key = find(keys, p)?;
    let at = key.scalar?;
    let mut text = scalar_at(source, at, key.column)?.text;
    let header = source[at..].lines().next().unwrap_or("");
    if header.starts_with(['|', '>']) && !header.contains('-') && !text.is_empty() {
        text.push('\n');
    }
    Some(text)
}

fn text_of(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<String> {
    let key = find(keys, p)?;
    scalar_at(source, key.scalar?, key.column).map(|s| s.text)
}

/// `p` as the `&str` path the lookups take.
fn strs(p: &[String]) -> Vec<&str> {
    p.iter().map(String::as_str).collect()
}

/// The scalar items of the sequence at `p`, each with its source map and
/// its path (`p.0`, `p.1`, ...): a block sequence (`- pe`) or a flow one
/// (`[pe, elf]`), items plain or quoted.
fn items(keys: &[YamlKey], source: &str, p: &[&str]) -> Vec<(String, Vec<usize>, Vec<String>)> {
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
    let mut raw: Vec<(usize, &str)> = Vec::new();
    let trimmed = region.trim_start_matches([' ', '\t']);
    if let Some(flow) = trimmed.strip_prefix('[') {
        let base = from + (region.len() - trimmed.len()) + 1;
        let close = flow.find(']').unwrap_or(flow.len());
        let mut at = 0;
        for part in flow[..close].split(',') {
            raw.push((base + at, part));
            at += part.len() + 1;
        }
    } else {
        let mut at = from;
        for line in region.split_inclusive('\n') {
            let content = line.trim_start_matches([' ', '\t']);
            if let Some(item) = content
                .strip_prefix("- ")
                .or_else(|| content.strip_prefix('-'))
            {
                let item_at = at + (line.len() - content.len()) + (content.len() - item.len());
                raw.push((item_at, item.trim_end_matches(['\n', '\r'])));
            }
            at += line.len();
        }
    }
    let mut out = Vec::new();
    for (index, (at, text)) in raw.into_iter().enumerate() {
        // Drop a trailing comment and the blanks around the value.
        let text = text.split(" #").next().unwrap_or(text);
        let lead = text.len() - text.trim_start().len();
        let value = text.trim();
        let (value, offset) = match value.as_bytes().first() {
            Some(b'"') | Some(b'\'') if value.len() >= 2 => (&value[1..value.len() - 1], 1),
            _ => (value, 0),
        };
        if value.is_empty() {
            continue;
        }
        let start = at + lead + offset;
        let mut item_path = path(p);
        item_path.push(index.to_string());
        out.push((
            value.to_string(),
            (start..start + value.len()).collect(),
            item_path,
        ));
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

    let imports = items(
        keys,
        source,
        &["configurations", "harfanglab", "yara", "imports"],
    );
    if !imports.is_empty() {
        for (module, map, item_path) in &imports {
            b.synthetic("import \"", host, &yara_path);
            b.push(module, map, item_path, false);
            b.synthetic("\"\n", host, &yara_path);
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
    if rule_name_problem(&rule_name).is_some() {
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
    let refs: Vec<(String, Vec<usize>, Vec<String>)> = public
        .iter()
        .filter_map(|k| {
            let s = scalar_at(source, k.scalar?, k.column)?;
            Some((s.text, s.map, k.path.clone()))
        })
        .collect();
    let joined = |b: &mut Builder,
                  key: &str,
                  p: &[&str],
                  values: &[(String, Vec<usize>, Vec<String>)],
                  sep: &str| {
        let field = path(p);
        let at = host_of(p);
        b.synthetic(&format!("        {key} = \""), at, &field);
        for (i, (text, map, item_path)) in values.iter().enumerate() {
            if i > 0 {
                b.synthetic(sep, at, &field);
            }
            b.push(text, map, item_path, false);
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
    let tags = items(keys, source, &["configurations", "harfanglab", "tags"]);
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
    let contexts: Vec<(String, Vec<usize>, Vec<String>)> =
        items(keys, source, &strs(&context_path))
            .into_iter()
            .map(|(c, map, item_path)| {
                match OS_TO_FILE_CONTEXT.iter().find(|(o, _)| *o == os_text) {
                    // Deploy writes `file` as the os's file context.
                    Some((_, file)) if c == "file" => {
                        let file = file.to_string();
                        let map = vec![map[0]; file.len()];
                        (file, map, item_path)
                    }
                    _ => (c, map, item_path),
                }
            })
            .collect();
    if !contexts.is_empty() {
        joined(&mut b, "context", &strs(&context_path), &contexts, ",");
    }
    verbatim(&mut b, "os", &strs(&meta_field("os")), os);
    let arch_path = meta_field("arch");
    let arch_items = items(keys, source, &strs(&arch_path));
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
/// it: what the constraint codes report instead is dropped, and the rest is
/// kept, on the bytes the author wrote. A finding inside generated text (an
/// unclosed condition found at the closing brace) moves to the nearest byte
/// of the field it belongs to, or, when that field has none, onto its key.
/// No error is lost.
pub(crate) fn on_assembled(inj: &InjectedQuery, mut d: Diagnostic) -> Option<Diagnostic> {
    if inj.parts.is_empty() {
        return Some(d);
    }
    if matches!(
        d.code.as_str(),
        // `harfanglab_yara_import` and the block's own checks report these.
        codes::YARA_UNKNOWN_MODULE | codes::YARA_EMPTY_SIGNATURE
    ) {
        return None;
    }
    let len = inj.inner.len();
    if len == 0 {
        return Some(d);
    }
    let start = opentide_core::position_to_offset(&inj.inner, d.range.start).min(len - 1);
    let end = opentide_core::position_to_offset(&inj.inner, d.range.end)
        .max(start + 1)
        .min(len);
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
    d.range = opentide_core::Range::new(
        opentide_core::offset_to_position(&inj.inner, first),
        opentide_core::offset_to_position(&inj.inner, last + 1),
    );
    Some(d)
}

fn diag(source: &str, code: &'static str, message: String, field: &[&str]) -> Diagnostic {
    Diagnostic::error(code, message, crate::elastic::path_range(source, field))
        .with_field_path(field.iter().map(|p| p.to_string()).collect())
}

/// Whether the value after `key` is a YAML alias (`signature: *name`).
fn is_alias(source: &str, key: &YamlKey) -> bool {
    let rest = &source[key.key_start..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    let value = rest[colon + 1..].trim_start_matches([' ', '\t']);
    value.starts_with('*')
}

/// The constraint codes of every `yara` block: `yara_signature_alias`, a
/// blank signature (`yara_empty_signature`), and HarfangLab's
/// `harfanglab_rule_kind`, `harfanglab_yara_form`,
/// `harfanglab_yara_section_header`, `harfanglab_yara_import` and
/// `harfanglab_yara_rule_name`.
pub(crate) fn constraint_diagnostics(source: &str, keys: &[YamlKey]) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for platform in PLATFORMS {
        let block = ["configurations", platform, "yara"];
        if find(keys, &block).is_none() {
            continue;
        }
        let signature_path = ["configurations", platform, "yara", "signature"];
        if let Some(key) = find(keys, &signature_path) {
            if is_alias(source, key) {
                out.push(diag(
                    source,
                    codes::YARA_SIGNATURE_ALIAS,
                    "`signature` is a YAML alias: write the YARA text out in this block, so the block shows what it deploys".into(),
                    &signature_path,
                ));
            } else if text_of(source, keys, &signature_path).is_none_or(|t| t.trim().is_empty()) {
                out.push(diag(
                    source,
                    codes::YARA_EMPTY_SIGNATURE,
                    "`signature` is blank: it holds no YARA rule".into(),
                    &signature_path,
                ));
            }
        }
        if *platform != "harfanglab" {
            continue;
        }
        let has = |name: &str| find(keys, &["configurations", "harfanglab", name]).is_some();
        if has("sigma") {
            out.push(diag(
                source,
                codes::HARFANGLAB_RULE_KIND,
                "a HarfangLab block is a Sigma rule or a YARA file, not both: move one to its own rule".into(),
                &["configurations", "harfanglab"],
            ));
        }
        let decomposed: Vec<&str> = DECOMPOSED
            .iter()
            .copied()
            .filter(|k| find(keys, &["configurations", "harfanglab", "yara", k]).is_some())
            .collect();
        if find(keys, &signature_path).is_some() && !decomposed.is_empty() {
            out.push(diag(
                source,
                codes::HARFANGLAB_YARA_FORM,
                format!(
                    "`signature` and the decomposed keys ({}) are two forms: keep one",
                    decomposed.join(", ")
                ),
                &block,
            ));
            continue;
        }
        if decomposed.is_empty() {
            continue;
        }
        for name in ["strings", "condition"] {
            let field = ["configurations", "harfanglab", "yara", name];
            let Some(key) = find(keys, &field) else {
                continue;
            };
            let Some(s) = key.scalar.and_then(|at| scalar_at(source, at, key.column)) else {
                continue;
            };
            if let Some((start, end, header)) = section_header(&s.text) {
                let span = ByteSpan::new(s.map[start], s.map[end.max(start + 1) - 1] + 1);
                out.push(
                    Diagnostic::error(
                        codes::HARFANGLAB_YARA_SECTION_HEADER,
                        format!("`{name}` holds a `{header}` header: deploy writes the headers, so write only the section's body"),
                        opentide_core::span_to_range(source, span),
                    )
                    .with_field_path(path(&field)),
                );
            }
        }
        let known = &Catalog::cached().known_modules;
        for (module, map, item_path) in items(
            keys,
            source,
            &["configurations", "harfanglab", "yara", "imports"],
        ) {
            if !known.contains(module.as_str()) {
                let span = ByteSpan::new(map[0], map[map.len() - 1] + 1);
                out.push(
                    Diagnostic::error(
                        codes::HARFANGLAB_YARA_IMPORT,
                        format!("`{module}` is not a YARA module the language knows"),
                        opentide_core::span_to_range(source, span),
                    )
                    .with_field_path(item_path),
                );
            }
        }
        let name = text_of(source, keys, &["name"]).unwrap_or_default();
        if let Some(problem) = rule_name_problem(&derived_rule_name(&name)) {
            let value = find(keys, &["name"])
                .and_then(|k| scalar_at(source, k.scalar?, k.column))
                .filter(|s| !s.map.is_empty());
            let d = match value {
                Some(s) => Diagnostic::error(
                    codes::HARFANGLAB_YARA_RULE_NAME,
                    problem,
                    opentide_core::span_to_range(
                        source,
                        ByteSpan::new(s.map[0], s.map[s.map.len() - 1] + 1),
                    ),
                )
                .with_field_path(path(&["name"])),
                None => diag(source, codes::HARFANGLAB_YARA_RULE_NAME, problem, &["name"]),
            };
            out.push(d);
        }
    }
    out
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
        assert!(rule_name_problem("détection").is_some());
        assert!(rule_name_problem("condition").is_some());
        assert!(rule_name_problem("cmd_string").is_none());
        assert!(rule_name_problem(&"a".repeat(128)).is_none());
        assert!(rule_name_problem(&"a".repeat(129)).is_some());
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
