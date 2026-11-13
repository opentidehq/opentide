//! MITRE ATT&CK STIX 2.1 bundles into vocabulary keys
//! (`opentide.vocabulary.stix_attack`).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::value::{Table, Value, parse_json, py_strip, py_title};

/// The external reference source that carries ATT&CK ids and links.
const MITRE_SOURCE: &str = "mitre-attack";

/// The STIX objects of a bundle file: a list, or a `bundle` (or any object)
/// with `objects`.
pub fn load_bundle(path: &Path) -> Result<Vec<Value>> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let document = parse_json(&bytes).with_context(|| format!("parse {}", path.display()))?;
    bundle_objects(document)
        .with_context(|| format!("Unrecognised STIX bundle format: {}", path.display()))
}

fn bundle_objects(document: Value) -> Result<Vec<Value>> {
    match document {
        Value::Array(objects) => Ok(objects),
        Value::Table(mut table) => match table.shift_remove("objects") {
            // `list(data.get("objects") or [])`
            Some(Value::Array(objects)) => Ok(objects),
            Some(value) if !value.truthy() => Ok(Vec::new()),
            None if table.get("type").and_then(Value::as_str) == Some("bundle") => Ok(Vec::new()),
            _ => bail!("no list of objects"),
        },
        _ => bail!("neither a list nor an object"),
    }
}

fn kind(object: &Value) -> Option<&str> {
    object.get("type").and_then(Value::as_str)
}

fn flag(object: &Value, key: &str) -> bool {
    object.get(key).is_some_and(Value::truthy)
}

/// `x_mitre_deprecated or revoked`.
fn retired(object: &Value) -> bool {
    flag(object, "x_mitre_deprecated") || flag(object, "revoked")
}

fn references(object: &Value) -> &[Value] {
    object
        .get("external_references")
        .filter(|value| value.truthy())
        .and_then(Value::as_array)
        .unwrap_or(&[])
}

fn mitre_reference(object: &Value, field: &str) -> Result<Option<String>> {
    for reference in references(object) {
        if reference.get("source_name").and_then(Value::as_str) == Some(MITRE_SOURCE)
            && let Some(value) = reference.get(field).filter(|value| value.truthy())
        {
            return Ok(Some(value.py_str()?));
        }
    }
    Ok(None)
}

/// The object's ATT&CK id (`_mitre_external_id`).
pub fn mitre_id(object: &Value) -> Result<Option<String>> {
    mitre_reference(object, "external_id")
}

/// The object's ATT&CK page (`_mitre_url`).
pub fn mitre_url(object: &Value) -> Result<Option<String>> {
    mitre_reference(object, "url")
}

/// `str(obj.get(key, ""))`.
fn text(object: &Value, key: &str) -> Result<String> {
    object
        .get(key)
        .map_or_else(|| Ok(String::new()), Value::py_str)
}

/// `obj.get("description") or ""`, the value as it is.
fn description(object: &Value) -> Value {
    object
        .get("description")
        .filter(|value| value.truthy())
        .cloned()
        .unwrap_or_else(|| Value::str(""))
}

/// Tactic short names to display names (`build_tactic_name_map`).
pub fn tactic_names(objects: &[Value]) -> Result<Table> {
    let mut names = Table::new();
    for object in objects {
        if kind(object) != Some("x-mitre-tactic") {
            continue;
        }
        let shortname = object
            .get("x_mitre_shortname")
            .filter(|value| value.truthy())
            .or_else(|| object.get("x-mitre-shortname"));
        let name = object.get("name");
        if let (Some(shortname), Some(name)) = (shortname, name)
            && shortname.truthy()
            && name.truthy()
        {
            names.insert(shortname.py_str()?, Value::str(name.py_str()?));
        }
    }
    Ok(names)
}

fn normalise_tactic(name: &str) -> String {
    if name == "Evasion Ics" {
        return "Defense Evasion".to_owned();
    }
    py_strip(&name.replace("Ics", "")).to_owned()
}

fn technique_stages(object: &Value, tactics: &Table) -> Result<Vec<String>> {
    let mut stages: Vec<String> = Vec::new();
    let phases = object
        .get("kill_chain_phases")
        .filter(|value| value.truthy())
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    for phase in phases {
        let phase_name = text(phase, "phase_name")?;
        let display = match tactics.get(&phase_name) {
            Some(name) => name.py_str()?,
            None => py_title(&phase_name.replace('-', " ")),
        };
        let display = normalise_tactic(&display);
        if !display.is_empty() && !stages.contains(&display) {
            stages.push(display);
        }
    }
    Ok(stages)
}

/// The tactic names of the bundle's live matrix, in matrix order
/// (`parse_matrix_tactics`).
pub fn matrix_tactics(objects: &[Value]) -> Result<Vec<String>> {
    let mut tactics = Table::new();
    for object in objects {
        if kind(object) == Some("x-mitre-tactic")
            && object.get("id").is_some_and(Value::truthy)
            && !retired(object)
        {
            tactics.insert(text(object, "id")?, Value::str(text(object, "name")?));
        }
    }
    let mut stages: Vec<String> = Vec::new();
    for object in objects {
        if kind(object) != Some("x-mitre-matrix") || retired(object) {
            continue;
        }
        let refs = object
            .get("tactic_refs")
            .filter(|value| value.truthy())
            .and_then(Value::as_array)
            .unwrap_or(&[]);
        for reference in refs {
            let name = match tactics.get(&reference.py_str()?) {
                Some(name) => name.py_str()?,
                None => String::new(),
            };
            let name = normalise_tactic(&name);
            if !name.is_empty() && !stages.contains(&name) {
                stages.push(name);
            }
        }
    }
    Ok(stages)
}

fn parent_technique_names(objects: &[Value]) -> Result<Table> {
    let mut names = Table::new();
    for object in objects {
        if kind(object) != Some("attack-pattern") || retired(object) {
            continue;
        }
        if let Some(id) = mitre_id(object)?
            && id.starts_with('T')
            && !id.contains('.')
        {
            names.insert(id, Value::str(text(object, "name")?));
        }
    }
    Ok(names)
}

fn strings(values: Vec<String>) -> Value {
    Value::Array(values.into_iter().map(Value::Str).collect())
}

/// Technique keys from `attack-pattern` objects (`parse_techniques`). An
/// unprefixed (Enterprise) sub-technique is named `"Parent: Sub"`; a
/// prefixed bundle's keys are `"<prefix> : Name"`.
pub fn techniques(objects: &[Value], prefix: &str, tactics: &Table) -> Result<Vec<Table>> {
    let name_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix} : ")
    };
    let parents = if prefix.is_empty() {
        parent_technique_names(objects)?
    } else {
        Table::new()
    };
    let mut entries = Vec::new();
    for object in objects {
        if kind(object) != Some("attack-pattern") || retired(object) {
            continue;
        }
        let Some(id) = mitre_id(object)?.filter(|id| id.starts_with('T')) else {
            continue;
        };
        let mut name = text(object, "name")?;
        if let Some((parent, _)) = id.split_once('.')
            && let Some(parent_name) = parents.get(parent).filter(|value| value.truthy())
        {
            name = format!("{}: {name}", parent_name.py_str()?);
        }
        let mut entry = Table::new();
        entry.insert("id".to_owned(), Value::str(id));
        entry.insert(
            "name".to_owned(),
            Value::str(format!("{name_prefix}{name}")),
        );
        entry.insert("description".to_owned(), description(object));
        if let Some(url) = mitre_url(object)?.filter(|url| !url.is_empty()) {
            entry.insert("link".to_owned(), Value::str(url));
        }
        let stages = technique_stages(object, tactics)?;
        if !stages.is_empty() {
            entry.insert("tide.vocab.stages".to_owned(), strings(stages));
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Group keys from `intrusion-set` objects (`parse_groups`), named
/// `"[<prefix>] Name"`.
pub fn groups(objects: &[Value], prefix: &str) -> Result<Vec<Table>> {
    let name_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("[{prefix}] ")
    };
    let mut entries = Vec::new();
    for object in objects {
        if kind(object) != Some("intrusion-set") || flag(object, "revoked") {
            continue;
        }
        let Some(id) = mitre_id(object)?.filter(|id| id.starts_with('G')) else {
            continue;
        };
        let mut entry = Table::new();
        entry.insert("id".to_owned(), Value::str(id));
        entry.insert(
            "name".to_owned(),
            Value::str(format!("{name_prefix}{}", text(object, "name")?)),
        );
        entry.insert("description".to_owned(), description(object));
        if let Some(url) = mitre_url(object)?.filter(|url| !url.is_empty()) {
            entry.insert("link".to_owned(), Value::str(url));
        }
        if let Some(aliases) = object.get("aliases").filter(|value| value.truthy()) {
            let aliases = match aliases {
                Value::Array(items) => Value::Array(items.clone()),
                // `list(aliases)` of a string is its characters; of a table,
                // its keys.
                Value::Str(text) => Value::Array(text.chars().map(Value::str).collect()),
                Value::Table(table) => {
                    Value::Array(table.keys().map(|key| Value::str(key.clone())).collect())
                }
                other => bail!("aliases is not iterable: {other:?}"),
            };
            entry.insert("alias".to_owned(), aliases);
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Mitigation keys from `course-of-action` objects (`parse_mitigations`).
pub fn mitigations(objects: &[Value], prefix: &str) -> Result<Vec<Table>> {
    let name_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix} : ")
    };
    let mut entries = Vec::new();
    for object in objects {
        if kind(object) != Some("course-of-action") || retired(object) {
            continue;
        }
        let Some(id) = mitre_id(object)?.filter(|id| id.starts_with('M')) else {
            continue;
        };
        let mut entry = Table::new();
        entry.insert("id".to_owned(), Value::str(id));
        entry.insert(
            "name".to_owned(),
            Value::str(format!("{name_prefix}{}", text(object, "name")?)),
        );
        entry.insert("description".to_owned(), description(object));
        if let Some(url) = mitre_url(object)?.filter(|url| !url.is_empty()) {
            entry.insert("link".to_owned(), Value::str(url));
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Data source and data component keys (`parse_datasources`), in bundle
/// order. A component takes its data source's id and link.
pub fn datasources(objects: &[Value]) -> Result<Vec<Table>> {
    struct Source {
        id: String,
        link: String,
    }
    let mut sources: indexmap::IndexMap<String, Source> = indexmap::IndexMap::new();
    for object in objects {
        if kind(object) != Some("x-mitre-data-source") {
            continue;
        }
        let Some(id) = mitre_id(object)? else {
            continue;
        };
        let stix = object
            .get("id")
            .context("a data source without a STIX id")?
            .py_str()?;
        sources.insert(
            stix,
            Source {
                id,
                link: mitre_url(object)?.unwrap_or_default(),
            },
        );
    }

    let mut entries = Vec::new();
    for object in objects {
        match kind(object) {
            Some("x-mitre-data-source") => {
                let Some(id) = mitre_id(object)? else {
                    continue;
                };
                let mut entry = Table::new();
                entry.insert("id".to_owned(), Value::str(id));
                entry.insert("name".to_owned(), Value::str(text(object, "name")?));
                entry.insert("description".to_owned(), description(object));
                if let Some(url) = mitre_url(object)?.filter(|url| !url.is_empty()) {
                    entry.insert("link".to_owned(), Value::str(url));
                }
                entries.push(entry);
            }
            Some("x-mitre-data-component") => {
                let parent_ref = object
                    .get("x_mitre_data_source_ref")
                    .filter(|value| value.truthy())
                    .or_else(|| object.get("x-mitre-data-source-ref"))
                    .filter(|value| value.truthy());
                let parent = match parent_ref {
                    Some(reference) => sources.get(&reference.py_str()?),
                    None => None,
                };
                let link = match parent.map(|source| source.link.clone()) {
                    Some(link) if !link.is_empty() => link,
                    _ => mitre_url(object)?.unwrap_or_default(),
                };
                let mut entry = Table::new();
                entry.insert(
                    "id".to_owned(),
                    Value::str(parent.map(|source| source.id.clone()).unwrap_or_default()),
                );
                // The component's own name, with or without a parent: the
                // old ingest built "Source: Component" (`full_name`) but kept
                // it only when there was no parent name to prefix, where the
                // two are the same.
                entry.insert("name".to_owned(), Value::str(text(object, "name")?));
                entry.insert("description".to_owned(), description(object));
                entry.insert("link".to_owned(), Value::str(link));
                entry.retain(|_, value| value.truthy());
                entries.push(entry);
            }
            _ => {}
        }
    }
    Ok(entries)
}

/// Every technique of the bundles, each with its name prefix
/// (`merge_technique_bundles`).
pub fn merged_techniques(bundles: &[(&[Value], &str)]) -> Result<Vec<Table>> {
    let mut combined = Vec::new();
    for (objects, prefix) in bundles {
        let tactics = tactic_names(objects)?;
        combined.extend(techniques(objects, prefix, &tactics)?);
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects(json: &str) -> Vec<Value> {
        bundle_objects(parse_json(json.as_bytes()).unwrap()).unwrap()
    }

    fn ext(id: &str) -> String {
        format!(
            r#""external_references": [{{"source_name": "other", "external_id": "X"}},
               {{"source_name": "mitre-attack", "external_id": "{id}", "url": "https://attack.mitre.org/{id}"}}]"#
        )
    }

    #[test]
    fn bundles_are_lists_or_objects_with_objects() {
        assert_eq!(objects(r#"[{"type": "x"}]"#).len(), 1);
        assert_eq!(
            objects(r#"{"type": "bundle", "objects": [{}, {}]}"#).len(),
            2
        );
        assert_eq!(objects(r#"{"type": "bundle"}"#).len(), 0);
        assert!(bundle_objects(parse_json(br#"{"type": "x"}"#).unwrap()).is_err());
    }

    #[test]
    fn techniques_take_their_parents_names_and_tactic_stages() {
        let bundle = objects(&format!(
            r#"[{{"type": "x-mitre-tactic", "x_mitre_shortname": "defense-evasion", "name": "Stealth", "id": "t1"}},
                {{"type": "x-mitre-tactic", "x_mitre_shortname": "lateral-movement", "name": "Lateral Movement Ics", "id": "t2"}},
                {{"type": "x-mitre-matrix", "tactic_refs": ["t1", "t2", "t1", "missing"]}},
                {{"type": "x-mitre-matrix", "tactic_refs": ["t3"], "revoked": true}},
                {{"type": "attack-pattern", "name": "Parent", {}, "kill_chain_phases": [
                    {{"phase_name": "defense-evasion"}}, {{"phase_name": "command-and-control"}}, {{"phase_name": "defense-evasion"}}]}},
                {{"type": "attack-pattern", "name": "Child", "description": "d", {}}},
                {{"type": "attack-pattern", "name": "Gone", {}, "x_mitre_deprecated": true}},
                {{"type": "attack-pattern", "name": "Not a technique", {}}}]"#,
            ext("T1000"),
            ext("T1000.001"),
            ext("T1001"),
            ext("S0001"),
        ));
        assert_eq!(
            matrix_tactics(&bundle).unwrap(),
            ["Stealth", "Lateral Movement"]
        );
        let tactics = tactic_names(&bundle).unwrap();
        let keys = techniques(&bundle, "", &tactics).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["description"].as_str(), Some(""));
        let stages = keys[0]["tide.vocab.stages"].as_array().unwrap();
        let stages: Vec<_> = stages.iter().filter_map(Value::as_str).collect();
        assert_eq!(stages, ["Stealth", "Command And Control"]);
        assert_eq!(keys[1]["name"].as_str(), Some("Parent: Child"));
        assert!(!keys[1].contains_key("tide.vocab.stages"));
        let mobile = techniques(&bundle, "Mobile", &tactics).unwrap();
        assert_eq!(mobile[1]["name"].as_str(), Some("Mobile : Child"));
    }

    #[test]
    fn groups_keep_deprecated_sets_and_their_aliases() {
        let bundle = objects(&format!(
            r#"[{{"type": "intrusion-set", "name": "APT", "aliases": ["APT", "Other"], "x_mitre_deprecated": true, {}}},
                {{"type": "intrusion-set", "name": "Old", "revoked": true, {}}}]"#,
            ext("G0001"),
            ext("G0002"),
        ));
        let keys = groups(&bundle, "ICS").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["name"].as_str(), Some("[ICS] APT"));
        assert_eq!(keys[0]["alias"].as_array().unwrap().len(), 2);
        assert_eq!(
            keys[0].keys().collect::<Vec<_>>(),
            ["id", "name", "description", "link", "alias"]
        );
    }

    #[test]
    fn components_take_their_sources_id_and_link() {
        let bundle = objects(&format!(
            r#"[{{"type": "x-mitre-data-component", "name": "Process Creation", "x_mitre_data_source_ref": "ds--1"}},
                {{"type": "x-mitre-data-source", "id": "ds--1", "name": "Process", {}}},
                {{"type": "x-mitre-data-component", "name": "Orphan", "description": "o"}}]"#,
            ext("DS0009"),
        ));
        let keys = datasources(&bundle).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0]["id"].as_str(), Some("DS0009"));
        assert_eq!(keys[0]["name"].as_str(), Some("Process Creation"));
        assert!(!keys[0].contains_key("description"), "empty values dropped");
        assert_eq!(keys[1]["name"].as_str(), Some("Process"));
        assert_eq!(keys[2].keys().collect::<Vec<_>>(), ["name", "description"]);
    }

    #[test]
    fn mitigations_take_only_m_ids() {
        let bundle = objects(&format!(
            r#"[{{"type": "course-of-action", "name": "Audit", {}}},
                {{"type": "course-of-action", "name": "Old", {}}}]"#,
            ext("M1047"),
            ext("T1000"),
        ));
        let keys = mitigations(&bundle, "Mobile").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["name"].as_str(), Some("Mobile : Audit"));
    }
}
