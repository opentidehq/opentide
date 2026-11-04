//! The UUIDs an object's body names, with where it names them (#198).
//!
//! An object is indexed once per text ([`crate::index_object`]): its
//! references are found then and kept in the index, so `find_refs`, the
//! reference lens and `opentide/catalog` read them instead of walking every
//! body again.

use crate::yaml_path::{key_span, key_span_in};
use opentide_core::{ByteSpan, LineIndex, Range};
use std::collections::BTreeSet;

/// One UUID an object's body names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    /// The value, as written: a UUID, or whatever a malformed field holds
    /// (a ref no object carries, as `invalid_ref` reports it).
    pub uuid: String,
    /// Where it sits in the object: mapping keys and list indexes joined
    /// with `.` (`detection_model`, `objective.signals.0.parent`), as
    /// opentide joins a Pydantic `loc`.
    pub field_path: String,
    /// The UUID's range in the indexed text (UTF-16 columns), or the start
    /// of the file when the text does not spell it out.
    pub range: Range,
}

enum Step {
    Key(String),
    Index(usize),
}

/// Whether a field names an object or a signal by its UUID: the reference
/// fields of the Tide schemas, and a signal's own `uuid`, which defines what
/// a `detection_model` or a `parent` names. Other UUID-valued fields are
/// identifiers of something else (`metadata.organisation.uuid`, a Sentinel
/// alert rule template's `configurations.sentinel.template.uuid`) and are not
/// refs.
fn is_reference(path: &[Step]) -> bool {
    let key = |step: &Step, name: &str| matches!(step, Step::Key(k) if k == name);
    match path {
        // rule::1.x: the objective or signal the rule implements.
        [field] => key(field, "detection_model"),
        // objective::1.x: the threat vectors the objective covers.
        [body, field, Step::Index(_)] => key(body, "objective") && key(field, "threats"),
        [body, list, Step::Index(_), field] => {
            // A signal, and the signal it refines.
            (key(body, "objective") && key(list, "signals") && (key(field, "uuid") || key(field, "parent")))
                // threat::1.0: the vector a threat chains to.
                || (key(body, "threat") && key(list, "chaining") && key(field, "vector"))
        }
        _ => false,
    }
}

/// Every reference field of `body` ([`is_reference`]) whose string value is
/// not empty and does not name the object itself (`own`), in document order,
/// each placed in `source`, the text `body` was parsed from. A value that is
/// not a UUID (a typo, `TODO`) is kept: `invalid_ref` reports it, and it is
/// a ref no object carries.
pub fn object_refs(source: &str, body: &serde_yaml::Value, own: &str) -> Vec<ObjectRef> {
    let mut found: Vec<(Vec<Step>, String)> = Vec::new();
    let mut path = Vec::new();
    collect(body, &mut path, own, &mut found);
    if found.is_empty() {
        return Vec::new();
    }
    let lines = LineIndex::new(source);
    let mut used = BTreeSet::new();
    found
        .into_iter()
        .map(|(steps, uuid)| {
            let range = locate(source, &steps, &uuid, &mut used)
                .map(|span| lines.range(span))
                .unwrap_or_else(|| Range::point(0, 0));
            ObjectRef {
                field_path: field_path(&steps),
                uuid,
                range,
            }
        })
        .collect()
}

fn collect(
    value: &serde_yaml::Value,
    path: &mut Vec<Step>,
    own: &str,
    out: &mut Vec<(Vec<Step>, String)>,
) {
    match value {
        serde_yaml::Value::String(text) => {
            if text != own && !text.trim().is_empty() && is_reference(path) {
                let steps = path
                    .iter()
                    .map(|step| match step {
                        Step::Key(k) => Step::Key(k.clone()),
                        Step::Index(i) => Step::Index(*i),
                    })
                    .collect();
                out.push((steps, text.clone()));
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(Step::Index(i));
                collect(item, path, own, out);
                path.pop();
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (key, item) in map {
                let key = match key {
                    serde_yaml::Value::String(k) => k.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                path.push(Step::Key(key));
                collect(item, path, own, out);
                path.pop();
            }
        }
        serde_yaml::Value::Tagged(tagged) => collect(&tagged.value, path, own, out),
        _ => {}
    }
}

fn field_path(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|step| match step {
            Step::Key(k) => k.clone(),
            Step::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The UUID's span: its first occurrence not already taken after the key
/// that holds it ([`key_span_in`], the list item each index names) or, in a
/// flow mapping, after its nearest block ancestor, else anywhere in the text. A UUID quoted in prose before its field is not the
/// field's.
fn locate(
    source: &str,
    steps: &[Step],
    uuid: &str,
    used: &mut BTreeSet<usize>,
) -> Option<ByteSpan> {
    let mut keys: Vec<(&str, Option<usize>)> = Vec::new();
    for step in steps {
        match step {
            Step::Key(k) => keys.push((k.as_str(), None)),
            Step::Index(i) => {
                if let Some(last) = keys.last_mut() {
                    last.1 = Some(*i);
                }
            }
        }
    }
    // The key that holds the UUID, else its deepest ancestor that has a span:
    // a key inside a flow mapping (`objective: { threats: [..] }`) has none,
    // and the search starts after the block key above it.
    let names: Vec<&str> = keys.iter().map(|(k, _)| *k).collect();
    let anchor = (1..=keys.len())
        .rev()
        .find_map(|n| key_span_in(source, &keys[..n]).or_else(|| key_span(source, &names[..n])))
        .map_or(0, |span| span.end);
    let free = |from: usize, used: &BTreeSet<usize>| {
        source[from..]
            .match_indices(uuid)
            .map(|(i, _)| from + i)
            .find(|start| !used.contains(start))
    };
    let start = free(anchor, used).or_else(|| free(0, used))?;
    used.insert(start);
    Some(ByteSpan::new(start, start + uuid.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "00000000-0000-4000-8003-000000000001";
    const MODEL: &str = "00000000-0000-4000-8002-000000000001";

    fn refs(source: &str) -> Vec<ObjectRef> {
        let body: serde_yaml::Value = serde_yaml::from_str(source).unwrap();
        object_refs(source, &body, OWN)
    }

    fn text_at(source: &str, range: Range) -> &str {
        let line = source.lines().nth(range.start.line as usize).unwrap();
        &line[range.start.character as usize..range.end.character as usize]
    }

    #[test]
    fn a_detection_model_is_a_ref_with_its_range_and_the_own_uuid_is_not() {
        let source = format!(
            "name: R\nmetadata:\n  uuid: {OWN}\n  schema: rule::1.0\ndescription: see {MODEL}\ndetection_model: {MODEL}\n"
        );
        let found = refs(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].uuid, MODEL);
        assert_eq!(found[0].field_path, "detection_model");
        // The field's value, not the UUID quoted in the description.
        assert_eq!(found[0].range.start.line, 5);
        assert_eq!(text_at(&source, found[0].range), MODEL);
    }

    #[test]
    fn list_items_get_their_index_and_each_its_own_occurrence() {
        let a = "00000000-0000-4000-8001-00000000000a";
        let b = "00000000-0000-4000-8001-00000000000b";
        let source = format!(
            "objective:\n  threats: [{a}, {b}]\n  signals:\n    - name: one\n      parent: {a}\n    - name: two\n      parent: {a}\n"
        );
        let found = refs(&source);
        let paths: Vec<&str> = found.iter().map(|r| r.field_path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "objective.threats.0",
                "objective.threats.1",
                "objective.signals.0.parent",
                "objective.signals.1.parent"
            ]
        );
        let lines: Vec<u32> = found.iter().map(|r| r.range.start.line).collect();
        assert_eq!(lines, [1, 1, 4, 6]);
        assert!(found.iter().all(|r| text_at(&source, r.range) == r.uuid));
    }

    #[test]
    fn a_ref_in_a_flow_mapping_is_not_the_uuid_quoted_in_prose_above_it() {
        let source = format!(
            "description: replaces {MODEL} in prose\nobjective: {{ threats: [{MODEL}] }}\n"
        );
        let found = refs(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].field_path, "objective.threats.0");
        assert_eq!(found[0].range.start.line, 1, "{found:?}");
        assert_eq!(text_at(&source, found[0].range), MODEL);
    }

    #[test]
    fn columns_count_utf16_units() {
        let source =
            format!("name: \"é😀\"\nobjective: {{ description: \"😀\", threats: [{MODEL}] }}\n");
        let found = refs(&source);
        assert_eq!(found.len(), 1);
        let line = source.lines().nth(1).unwrap();
        let byte = line.find(MODEL).unwrap();
        let utf16 = line[..byte].encode_utf16().count() as u32;
        assert_eq!(found[0].range.start.character, utf16);
    }

    #[test]
    fn uuids_that_name_no_object_are_not_refs() {
        let org = "5f3c2a10-7b6e-4c1d-9a8f-2e4b6d0c1a73";
        let template = "f0c3a1b2-9d8e-4f7a-8b6c-5d4e3f2a1b0c";
        let source = format!(
            "name: R\nmetadata:\n  uuid: {OWN}\n  schema: rule::1.0\n  organisation:\n    uuid: {org}\n    name: ACME\ndetection_model: {MODEL}\nconfigurations:\n  sentinel:\n    template:\n      uuid: {template}\n"
        );
        let found = refs(&source);
        let paths: Vec<&str> = found.iter().map(|r| r.field_path.as_str()).collect();
        assert_eq!(paths, ["detection_model"], "{found:?}");
    }

    #[test]
    fn signals_and_chained_vectors_are_refs() {
        let a = "00000000-0000-4000-8001-00000000000a";
        let b = "00000000-0000-4000-8001-00000000000b";
        let signals = format!(
            "objective:\n  signals:\n    - name: one\n      uuid: {a}\n    - name: two\n      uuid: {b}\n      parent: {a}\n"
        );
        let paths: Vec<String> = refs(&signals).into_iter().map(|r| r.field_path).collect();
        assert_eq!(
            paths,
            [
                "objective.signals.0.uuid",
                "objective.signals.1.uuid",
                "objective.signals.1.parent"
            ]
        );
        let threat = format!(
            "threat:\n  chaining:\n    - relation: preceded_by\n      vector: {a}\n      note: {b}\n"
        );
        let paths: Vec<String> = refs(&threat).into_iter().map(|r| r.field_path).collect();
        assert_eq!(paths, ["threat.chaining.0.vector"]);
    }

    /// `invalid_ref` reports a reference field whatever its value, and
    /// opentide's catalog has a missing edge for it: a value that is not a
    /// UUID is a ref no object carries, not silently dropped.
    #[test]
    fn a_reference_field_whose_value_is_not_a_uuid_is_still_a_ref() {
        let typo = "00000000-0000-4000-8002-00000000001";
        let source = format!(
            "name: R\nmetadata:\n  uuid: {OWN}\n  schema: rule::1.0\ndetection_model: {typo}\n"
        );
        let found = refs(&source);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].uuid, typo);
        assert_eq!(found[0].field_path, "detection_model");
        assert_eq!(found[0].range.start.line, 4);
        assert_eq!(text_at(&source, found[0].range), typo);

        let found = refs(
            "objective:\n  threats:\n    - TODO\n  signals:\n    - name: s\n      parent: tbd\n      uuid: ''\n",
        );
        let found: Vec<(&str, &str)> = found
            .iter()
            .map(|r| (r.field_path.as_str(), r.uuid.as_str()))
            .collect();
        // An empty value names nothing.
        assert_eq!(
            found,
            [
                ("objective.threats.0", "TODO"),
                ("objective.signals.0.parent", "tbd")
            ]
        );
    }

    #[test]
    fn prose_and_non_uuids_are_not_refs() {
        let found = refs(
            "description: names 00000000-0000-4000-8002-000000000001 in prose\nstatus: STAGING\nx: 1234\n",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_index_keeps_schema_name_range_and_refs() {
        let source = format!(
            "\u{feff}name: 'Dump LSASS'\nmetadata:\n  uuid: {OWN}\n  schema: rule::1.1\ndetection_model: {MODEL}\n"
        );
        let object = crate::index_object("/w/objects/rules/r.yaml", &source).unwrap();
        assert_eq!(object.schema, "rule::1.1");
        assert_eq!(object.object_type, "rule");
        // After the byte-order mark, which an editor gives no column.
        assert_eq!(
            object.name_range,
            Range {
                start: opentide_core::Position::new(0, 7),
                end: opentide_core::Position::new(0, 17),
            }
        );
        assert_eq!(object.refs.len(), 1);
        assert_eq!(
            object.refs[0].range.start,
            opentide_core::Position::new(4, 17)
        );
        assert!(object.names(MODEL));
        assert!(!object.names(OWN));
        let nameless = crate::index_object(
            "x.yaml",
            &format!("name:\nmetadata:\n  uuid: {OWN}\n  schema: rule::1.0\n"),
        )
        .unwrap();
        assert_eq!(
            nameless.name_range.start,
            opentide_core::Position::new(0, 0)
        );
    }
}
