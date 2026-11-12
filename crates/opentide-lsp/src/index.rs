//! The editor's index of a root's objects (hover, completion, links,
//! references, lenses, `opentide/catalog`) from `opentide-workspace`'s own
//! parse of each file (#926): the node tree the workspace read for
//! `validate`, not a second parse with another YAML library. A file the
//! workspace has not parsed (a folder it does not read, a document outside
//! every root, what a host supplied) is read with the same parser.

use opentide_analysis::IndexedObject;
use std::sync::Arc;

use opentide_schema::node::{self, Document};

/// The index entry of the object file at `path` whose text is `text`, read
/// with the workspace's parser; `None` for a file that is not YAML or not an
/// object.
pub(crate) fn index_text(path: &str, text: &str) -> Option<IndexedObject> {
    let document = node::load(opentide_core::strip_bom(text)).ok()?;
    index_document(path, &document)
}

/// The index entry of the object file at `path`, from its parse.
pub(crate) fn index_document(path: &str, document: &Document) -> Option<IndexedObject> {
    opentide_tide::index_value(path, document.source(), Arc::clone(document.root()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The workspace's parse indexes an object as the engine's own parse
    /// does: identity, name range, references and their ranges, and body.
    #[test]
    fn the_workspace_s_parse_indexes_as_the_engine_s() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/objects");
        let mut compared = 0;
        for name in ["rule-1.0.yaml", "objective-1.0.yaml", "threat-1.0.yaml"] {
            let text = std::fs::read_to_string(root.join(name)).unwrap();
            let text = format!("\u{feff}{text}");
            let ours = index_text(name, &text).expect("indexed");
            let engine = opentide_analysis::index_object(name, &text).expect("indexed");
            assert_eq!(ours.uuid, engine.uuid);
            assert_eq!(ours.name, engine.name);
            assert_eq!(ours.schema, engine.schema);
            assert_eq!(ours.object_type, engine.object_type);
            assert_eq!(ours.name_range, engine.name_range);
            assert_eq!(ours.body, engine.body);
            let refs = |o: &IndexedObject| {
                o.refs
                    .iter()
                    .map(|r| (r.uuid.clone(), r.field_path.clone(), r.range))
                    .collect::<Vec<_>>()
            };
            assert_eq!(refs(&ours), refs(&engine));
            compared += 1;
        }
        assert_eq!(compared, 3);
    }

    #[test]
    fn a_repeated_key_keeps_its_first_value_and_a_non_object_has_no_entry() {
        let text = "name: A\nname: B\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n";
        if let Ok(document) = node::load_keeping_repeated_keys(text) {
            let entry = index_document("r.yaml", &document).expect("indexed");
            assert_eq!(entry.name, "A");
        }
        assert!(index_text("x.yaml", "- a\n- b\n").is_none());
        assert!(index_text("x.yaml", "name: [\n").is_none());
        assert!(index_text("x.yaml", "name: A\n").is_none());
    }
}
