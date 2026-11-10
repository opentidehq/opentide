//! `opentide.schema.json`, the editor's entry point: one schema that applies
//! the revision schema `metadata.schema` names (`router_schema.py`).

use super::annotate::annotate_editor_schema;
use super::json::{Json, Object};
use crate::revisions::SchemaId;

/// The router's title.
pub const ROUTER_TITLE: &str = "opentide Object Router";

/// The file a revision's schema is written to: `rule.1.1.schema.json`
/// (`registry/artifacts.py` `schema_artifact_name`).
pub fn schema_artifact_name(id: &SchemaId) -> String {
    format!("{}.{}.{}.schema.json", id.family(), id.major(), id.minor())
}

/// The file a revision's template is written to: `rule.1.1.template.yaml`.
pub fn template_artifact_name(id: &SchemaId) -> String {
    format!(
        "{}.{}.{}.template.yaml",
        id.family(),
        id.major(),
        id.minor()
    )
}

fn family_label(family: &str) -> String {
    match family {
        "threat" => "Threat Vector".to_owned(),
        "objective" => "Detection Objective".to_owned(),
        "rule" => "Detection Rule".to_owned(),
        // `str.capitalize()`: the first character upper-cased, the rest lower.
        other => {
            let mut characters = other.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + &characters.as_str().to_lowercase()
            })
        }
    }
}

fn identifier_label(id: &SchemaId) -> String {
    format!(
        "{}, schema revision {}.{}",
        family_label(id.family()),
        id.major(),
        id.minor()
    )
}

fn object(entries: Vec<(&str, Json)>) -> Json {
    Json::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<Object>(),
    )
}

fn strings(values: &[&str]) -> Json {
    Json::Array(values.iter().map(|value| Json::from(*value)).collect())
}

fn route(id: &SchemaId) -> Json {
    object(vec![
        (
            "if",
            object(vec![
                ("type", Json::from("object")),
                ("required", strings(&["metadata"])),
                (
                    "properties",
                    object(vec![(
                        "metadata",
                        object(vec![
                            ("type", Json::from("object")),
                            ("required", strings(&["schema"])),
                            (
                                "properties",
                                object(vec![(
                                    "schema",
                                    object(vec![("const", Json::from(id.to_string()))]),
                                )]),
                            ),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            "then",
            object(vec![("$ref", Json::from(schema_artifact_name(id)))]),
        ),
    ])
}

/// The router over `identifiers` (sorted as the oracle sorts them: by their
/// text), annotated for editors.
pub fn router(identifiers: &[SchemaId]) -> Json {
    let mut ids: Vec<&SchemaId> = identifiers.iter().collect();
    ids.sort_by_key(|id| id.to_string());
    let enum_values = Json::Array(ids.iter().map(|id| Json::from(id.to_string())).collect());
    let labels = Json::Array(
        ids.iter()
            .map(|id| Json::from(identifier_label(id)))
            .collect(),
    );
    let mut schema = object(vec![
        (
            "$schema",
            Json::from("https://json-schema.org/draft/2020-12/schema"),
        ),
        ("title", Json::from(ROUTER_TITLE)),
        (
            "description",
            Json::from(
                "Validates any opentide object against the schema revision named in metadata.schema. Map objects/**/*.yaml to this file in the editor.",
            ),
        ),
        ("type", Json::from("object")),
        ("required", strings(&["metadata"])),
        (
            "properties",
            object(vec![(
                "metadata",
                object(vec![
                    ("title", Json::from("Metadata")),
                    (
                        "description",
                        Json::from("Object metadata. `schema` selects the revision schema."),
                    ),
                    ("type", Json::from("object")),
                    ("required", strings(&["schema"])),
                    (
                        "properties",
                        object(vec![(
                            "schema",
                            object(vec![
                                ("title", Json::from("Schema")),
                                (
                                    "description",
                                    Json::from(
                                        "Schema identifier (family::major.minor). Selects the revision schema that validates this object.",
                                    ),
                                ),
                                ("type", Json::from("string")),
                                ("enum", enum_values),
                                ("enumDescriptions", labels),
                            ]),
                        )]),
                    ),
                ]),
            )]),
        ),
        (
            "allOf",
            Json::Array(ids.iter().map(|id| route(id)).collect()),
        ),
    ]);
    annotate_editor_schema(&mut schema);
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(text: &str) -> SchemaId {
        SchemaId::parse(text).unwrap()
    }

    #[test]
    fn artifact_names() {
        assert_eq!(
            schema_artifact_name(&id("rule::1.1")),
            "rule.1.1.schema.json"
        );
        assert_eq!(
            template_artifact_name(&id("objective::1.0")),
            "objective.1.0.template.yaml"
        );
    }

    #[test]
    fn identifiers_are_sorted_as_text_and_labelled() {
        let schema = router(&[id("threat::1.0"), id("rule::1.1"), id("objective::1.0")]);
        let field = schema
            .get("properties")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("properties"))
            .and_then(|p| p.get("schema"))
            .cloned()
            .unwrap();
        assert_eq!(
            field.get("enum"),
            Some(&strings(&["objective::1.0", "rule::1.1", "threat::1.0"]))
        );
        assert_eq!(
            field.get("enumDescriptions"),
            Some(&strings(&[
                "Detection Objective, schema revision 1.0",
                "Detection Rule, schema revision 1.1",
                "Threat Vector, schema revision 1.0",
            ]))
        );
        let routes = schema.get("allOf").and_then(Json::as_array).unwrap();
        assert_eq!(
            routes[1].get("then"),
            Some(&object(vec![("$ref", Json::from("rule.1.1.schema.json"))]))
        );
    }

    #[test]
    fn an_unknown_family_is_capitalised() {
        assert_eq!(family_label("visibility"), "Visibility");
        assert_eq!(family_label("mIxed"), "Mixed");
    }
}
