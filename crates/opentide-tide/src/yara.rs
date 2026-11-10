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

fn path(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

fn find<'a>(keys: &'a [YamlKey], p: &[&str]) -> Option<&'a YamlKey> {
    keys.iter().find(|k| k.path_is(p))
}

fn text_of(source: &str, keys: &[YamlKey], p: &[&str]) -> Option<String> {
    let key = find(keys, p)?;
    scalar_at(source, key.scalar?, key.column).map(|s| s.text)
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
    let mut offset = 0;
    for line in text.split('\n') {
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

    let name = text_of(source, keys, &["name"]).unwrap_or_default();
    let mut rule_name = derived_rule_name(&name);
    if rule_name_problem(&rule_name).is_some() {
        // `harfanglab_yara_rule_name` reports it; the bodies are still checked.
        rule_name = "opentide_rule".into();
    }
    b.synthetic(&format!("rule {rule_name} {{\n"), host, &path(&["name"]));

    let meta = ["configurations", "harfanglab", "yara", "meta"];
    let os = text_of(source, keys, &[meta[0], meta[1], meta[2], meta[3], "os"]).unwrap_or_default();
    let contexts: Vec<String> = items(
        keys,
        source,
        &[meta[0], meta[1], meta[2], meta[3], "context"],
    )
    .into_iter()
    .map(
        |(c, _, _)| match OS_TO_FILE_CONTEXT.iter().find(|(o, _)| *o == os) {
            Some((_, file)) if c == "file" => file.to_string(),
            _ => c,
        },
    )
    .collect();
    let uuid = text_of(source, keys, &["metadata", "uuid"]).unwrap_or_default();
    let score = text_of(source, keys, &[meta[0], meta[1], meta[2], meta[3], "score"])
        .and_then(|s| {
            SCORES
                .iter()
                .find(|(k, _)| *k == s)
                .map(|(_, v)| v.to_string())
        })
        .unwrap_or_else(|| "50".into());
    let mut generated = String::from("    meta:\n");
    generated.push_str(&format!("        id = \"{}\"\n", escape(&uuid)));
    generated.push_str(&format!("        title = \"{}\"\n", escape(&name)));
    if !contexts.is_empty() {
        generated.push_str(&format!(
            "        context = \"{}\"\n",
            escape(&contexts.join(","))
        ));
    }
    generated.push_str(&format!("        os = \"{}\"\n", escape(&os)));
    generated.push_str(&format!("        score = {score}\n"));
    generated.push_str("    strings:\n");
    b.synthetic(&generated, host, &path(&meta));

    let strings_path = path(&["configurations", "harfanglab", "yara", "strings"]);
    let condition_path = path(&["configurations", "harfanglab", "yara", "condition"]);
    for (text, map, field, header) in [
        (
            &strings,
            &strings_map,
            &strings_path,
            Some("    condition:\n"),
        ),
        (&condition, &condition_map, &condition_path, None),
    ] {
        let (text, map) = stripped(text, map);
        let mut offset = 0;
        for line in text.split('\n') {
            b.synthetic("        ", host, field);
            b.push(line, &map[offset..offset + line.len()], field, false);
            b.synthetic("\n", host, field);
            offset += line.len() + 1;
        }
        if let Some(h) = header {
            b.synthetic(h, host, &yara_path);
        }
    }
    b.synthetic("}", host, &yara_path);
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
/// it: what the constraint codes report instead is dropped, a finding is
/// moved to the first byte the author wrote, and one wholly inside
/// generated text is dropped.
pub(crate) fn on_assembled(inj: &InjectedQuery, mut d: Diagnostic) -> Option<Diagnostic> {
    if inj.parts.is_empty() {
        return Some(d);
    }
    if matches!(
        d.code.as_str(),
        codes::YARA_UNKNOWN_MODULE
            | codes::YARA_RULE_IDENTIFIER_CONFLICT
            | codes::YARA_EMPTY_SIGNATURE
    ) {
        return None;
    }
    let start = opentide_core::position_to_offset(&inj.inner, d.range.start);
    let end = opentide_core::position_to_offset(&inj.inner, d.range.end).max(start + 1);
    let first = (start..end.min(inj.inner.len())).find(|&i| !inj.is_synthetic(i))?;
    let last = (first..end.min(inj.inner.len()))
        .take_while(|&i| !inj.is_synthetic(i))
        .last()
        .unwrap_or(first);
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
    }

    #[test]
    fn section_headers() {
        assert!(section_header("$a = \"x\"\ncondition:\n  $a").is_some());
        assert!(section_header("rule x {").is_some());
        assert!(section_header("$a = \"rule x\"").is_none());
        assert!(section_header("$a and pe.is_dll()").is_none());
    }
}
