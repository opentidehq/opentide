//! The YARA module catalogue, `data/catalogs/yara/modules.toml`, generated
//! from YARA-X's module reflection (#1225): `cargo xtask codegen` writes it,
//! `--check` compares it.
//!
//! The input is [`DUMP`], YARA-X's reflection of its **default** module set
//! as JSON. `scripts/engine/yara-modules` prints it, by hand: that separate
//! Cargo project builds the `yara-x` crate with its default features, which
//! never enters the workspace lock. Every module in the dump is known, except
//! the ones [`EXCLUDED`] lists. [`UNSUPPORTED`] says why a module opentide
//! refuses is refused, for the `yara_unknown_module` message.
//!
//! libyara is no input: YARA-X is the language. The catalogue of libyara
//! 4.5.4's declarations that came before is provenance only
//! (`data/catalogs/yara/NOTICE`).

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// YARA-X's reflection of its default modules (`scripts/engine/yara-modules`).
pub const DUMP: &str = "data/catalogs/yara/yara-x-modules.json";
/// The generated catalogue.
pub const OUTPUT: &str = "data/catalogs/yara/modules.toml";
/// The `yara-x` crate the dump comes from (`scripts/engine/yara-modules/Cargo.toml`).
pub const YARA_X_VERSION: &str = "1.23.0";

/// Default YARA-X modules opentide does not support: each is in the dump and
/// left out of the catalogue, so importing it is `yara_unknown_module`. The
/// generator fails when one is no longer in the dump, so a stale entry is
/// seen. The `exceptions.toml` `[[yara]]` ledger records the cases where
/// YARA-X compiles what opentide refuses here.
pub const EXCLUDED: &[&str] = &[
    // Maintainer decision on #1225: `vt` describes VirusTotal's own scan
    // metadata, which only VirusTotal's scanning fills in.
    "vt",
];

/// Why a module opentide refuses is refused: the `yara_unknown_module`
/// message names it.
pub const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "magic",
        "YARA-X builds `magic` only with its non-default `magic-module` feature and libmagic \
         (https://virustotal.github.io/yara-x/docs/modules/magic/), so a rule that imports it \
         is not portable",
    ),
    (
        "msi",
        "`msi` is experimental in YARA-X and not built by default",
    ),
    (
        "olecf",
        "`olecf` is experimental in YARA-X and not built by default",
    ),
    (
        "vba",
        "`vba` is experimental in YARA-X and not built by default",
    ),
    (
        "vt",
        "`vt` describes VirusTotal's own scan metadata, which only VirusTotal's scanning fills in",
    ),
];

/// One catalogue row.
struct Row {
    path: String,
    kind: String,
    element: Option<String>,
    doc: Option<String>,
    overloads: Vec<Overload>,
}

struct Overload {
    args: String,
    ret: String,
    doc: Option<String>,
}

/// One argument's letter: `i`, `f`, `s`, `r`, `b`, or `?` for a structure.
fn letter(t: &Value) -> char {
    match t.as_str() {
        Some("integer") => 'i',
        Some("float") => 'f',
        Some("string") => 's',
        Some("regexp") => 'r',
        Some("boolean") => 'b',
        _ => '?',
    }
}

fn doc_of(v: &Value) -> Option<String> {
    v.get("doc")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::to_owned)
}

/// Flattens one module's fields into rows, paths first: `[]` is an array
/// element, `{}` a dictionary value.
fn members(fields: &[Value], prefix: &str, out: &mut BTreeMap<String, Row>) -> Result<()> {
    for f in fields {
        let name = f
            .get("name")
            .and_then(Value::as_str)
            .context("a field without a name")?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}.{name}")
        };
        let t = f.get("type").context("a field without a type")?;
        let doc = doc_of(f);
        let mut row = Row {
            path: path.clone(),
            kind: String::new(),
            element: None,
            doc,
            overloads: Vec::new(),
        };
        if let Some(scalar) = t.as_str() {
            scalar.clone_into(&mut row.kind);
        } else if let Some(inner) = t.get("struct") {
            row.kind = "struct".into();
            members(inner.as_array().context("a struct")?, &path, out)?;
        } else if t.get("array").is_some() || t.get("map").is_some() {
            let (kind, inner, mark) = match t.get("array") {
                Some(inner) => ("array", inner, "[]"),
                None => ("dict", t["map"].get(1).context("a map value")?, "{}"),
            };
            row.kind = kind.into();
            row.element = Some(inner.as_str().unwrap_or("struct").to_owned());
            if let Some(fields) = inner.get("struct") {
                members(
                    fields.as_array().context("a struct")?,
                    &format!("{path}{mark}"),
                    out,
                )?;
            }
        } else if let Some(sigs) = t.get("function").and_then(Value::as_array) {
            row.kind = "function".into();
            for sig in sigs {
                let args: Vec<&Value> = sig
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|pair| pair.get(1)).collect())
                    .unwrap_or_default();
                let mut letters: String = args.iter().map(|t| letter(t)).collect();
                // YARA-X reflects a method of an array element with the
                // element as a leading argument (`signatures[].valid_on`
                // takes `signature, timestamp`, the element as an integer); a
                // rule writes it without.
                if path.contains("[].") && !letters.is_empty() {
                    letters.remove(0);
                }
                let ret = sig
                    .get("ret")
                    .context("a signature without a return type")?;
                row.overloads.push(Overload {
                    args: letters,
                    ret: ret.as_str().unwrap_or("struct").to_owned(),
                    doc: doc_of(sig),
                });
            }
            row.overloads.sort_by(|a, b| a.args.cmp(&b.args));
            row.overloads.dedup_by(|a, b| a.args == b.args);
        } else {
            bail!("{path}: a type the generator does not know: {t}");
        }
        out.insert(path, row);
    }
    Ok(())
}

fn quoted(s: &str) -> String {
    // A JSON string is a TOML basic string.
    serde_json::to_string(s).unwrap_or_default()
}

/// The catalogue generated from the reflection dump's text.
///
/// # Errors
///
/// When the dump is not the reflection's JSON, or an [`EXCLUDED`] module is
/// not in it.
pub fn generate(dump: &str) -> Result<String> {
    let modules: BTreeMap<String, Value> = serde_json::from_str(dump).context(DUMP)?;
    for name in EXCLUDED {
        if !modules.contains_key(*name) {
            bail!("{DUMP}: the excluded module `{name}` is gone; drop it from EXCLUDED");
        }
        // An excluded module is one YARA-X has: its message must say why
        // opentide refuses it, not that YARA has no such module.
        if !UNSUPPORTED.iter().any(|(m, _)| m == name) {
            bail!("the excluded module `{name}` has no reason in UNSUPPORTED");
        }
    }
    let known: Vec<&String> = modules
        .keys()
        .filter(|m| !EXCLUDED.contains(&m.as_str()))
        .collect();
    let mut out = String::new();
    out.push_str(
        "# Generated by `cargo xtask codegen` (xtask/src/yara_modules.rs) from YARA-X's\n\
         # module reflection, yara-x-modules.json; do not edit. YARA-X (BSD-3-Clause):\n\
         # see NOTICE in this directory. A path uses `[]` for an array element and `{}`\n\
         # for a dictionary value.\n\n[meta]\n",
    );
    let _ = writeln!(out, "yara_x = {}", quoted(YARA_X_VERSION));
    let _ = writeln!(
        out,
        "# YARA-X's default modules, less the ones opentide excludes (`excluded`).\nmodules = [{}]",
        known
            .iter()
            .map(|m| quoted(m))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        "excluded = [{}]",
        EXCLUDED
            .iter()
            .map(|m| quoted(m))
            .collect::<Vec<_>>()
            .join(", ")
    );
    out.push_str("\n# Why importing each of these is `yara_unknown_module`.\n[unsupported]\n");
    for (name, why) in UNSUPPORTED {
        let _ = writeln!(out, "{name} = {}", quoted(why));
    }
    for module in known {
        let mut rows = BTreeMap::new();
        members(
            modules[module.as_str()]
                .as_array()
                .with_context(|| format!("{DUMP}: `{module}` is not a field list"))?,
            "",
            &mut rows,
        )
        .with_context(|| format!("{DUMP}: `{module}`"))?;
        for row in rows.values() {
            out.push_str("\n[[member]]\n");
            let _ = writeln!(out, "module = {}", quoted(module));
            let _ = writeln!(out, "path = {}", quoted(&row.path));
            let _ = writeln!(out, "kind = {}", quoted(&row.kind));
            if let Some(element) = &row.element {
                let _ = writeln!(out, "element = {}", quoted(element));
            }
            if let Some(doc) = &row.doc {
                let _ = writeln!(out, "doc = {}", quoted(doc));
            }
            for o in &row.overloads {
                out.push_str("[[member.overload]]\n");
                let _ = writeln!(out, "args = {}", quoted(&o.args));
                let _ = writeln!(out, "ret = {}", quoted(&o.ret));
                if let Some(doc) = &o.doc {
                    let _ = writeln!(out, "doc = {}", quoted(doc));
                }
            }
        }
    }
    Ok(out)
}

/// Writes [`OUTPUT`] from [`DUMP`], or, with `check`, reports how it differs.
///
/// # Errors
///
/// When the dump cannot be read or generated from, or the catalogue cannot
/// be written.
pub fn sync(root: &Path, check: bool) -> Result<Vec<String>> {
    let dump = std::fs::read_to_string(root.join(DUMP)).with_context(|| format!("read {DUMP}"))?;
    let text = generate(&dump)?;
    let file = root.join(OUTPUT);
    if check {
        return Ok(match std::fs::read_to_string(&file) {
            Ok(current) if current == text => Vec::new(),
            Ok(_) => vec![format!(
                "{OUTPUT}: differs from what {DUMP} generates (cargo xtask codegen)"
            )],
            Err(_) => vec![format!("{OUTPUT}: missing")],
        });
    }
    std::fs::write(&file, text).with_context(|| format!("write {OUTPUT}"))?;
    println!("wrote {OUTPUT}");
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP_TEXT: &str = r#"{
      "pe": [
        {"name": "is_pe", "type": "boolean", "const": false, "doc": " True for PE. ", "enum": false},
        {"name": "sections", "type": {"array": {"struct": [
          {"name": "name", "type": "string", "const": false, "doc": null, "enum": false}
        ]}}, "const": false, "doc": null, "enum": false},
        {"name": "exports", "type": {"function": [
          {"args": [["name", "string"]], "ret": "boolean", "doc": "By name."},
          {"args": [["ordinal", "integer"]], "ret": "boolean", "doc": null}
        ]}, "const": false, "doc": null, "enum": false}
      ],
      "vt": [
        {"name": "metadata", "type": "string", "const": false, "doc": null, "enum": false}
      ]
    }"#;

    #[test]
    fn the_catalogue_is_the_dump_less_the_excluded_modules() {
        let text = generate(DUMP_TEXT).expect("generates");
        assert!(text.contains("modules = [\"pe\"]"), "{text}");
        assert!(text.contains("excluded = [\"vt\"]"), "{text}");
        assert!(!text.contains("module = \"vt\""), "{text}");
        assert!(text.contains("path = \"is_pe\"\nkind = \"boolean\"\ndoc = \"True for PE.\""));
        assert!(text.contains("path = \"sections[].name\"\nkind = \"string\""));
        assert!(text.contains("path = \"sections\"\nkind = \"array\"\nelement = \"struct\""));
        // Overloads sorted by their arguments.
        let i = text.find("args = \"i\"").expect("i");
        let s = text.find("args = \"s\"").expect("s");
        assert!(i < s, "{text}");
        // `magic` and `vt` say why they are refused.
        assert!(text.contains("magic = \"YARA-X builds `magic` only"));
        assert!(text.contains("\nvt = \""));
    }

    #[test]
    fn an_excluded_module_missing_from_the_dump_is_an_error() {
        let err = generate(r#"{"pe": []}"#).expect_err("vt is gone");
        assert!(err.to_string().contains("`vt` is gone"), "{err}");
    }

    #[test]
    fn an_element_method_drops_its_element_argument() {
        let dump = r#"{"pe": [{"name": "signatures", "type": {"array": {"struct": [
          {"name": "valid_on", "type": {"function": [
            {"args": [["signature", "integer"], ["timestamp", "integer"]], "ret": "boolean", "doc": null}
          ]}, "const": false, "doc": null, "enum": false}
        ]}}, "const": false, "doc": null, "enum": false}], "vt": []}"#;
        let text = generate(dump).expect("generates");
        assert!(
            text.contains("path = \"signatures[].valid_on\"\nkind = \"function\"\n[[member.overload]]\nargs = \"i\""),
            "{text}"
        );
    }
}
