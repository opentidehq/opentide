//! Generated JSON documents: [`opentide_core::json::Json`], whose objects keep
//! their keys in the order they are built in (a schema reads in that order),
//! written as a file by serde_json's pretty printer.

pub use opentide_core::json::{Json, Object};

/// `document` as a file: four-space indentation, every character as UTF-8,
/// and a final newline.
pub fn to_text(document: &Json) -> String {
    let mut text = document.to_pretty(4);
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(entries: &[(&str, Json)]) -> Json {
        Json::object(entries.iter().map(|(key, value)| (*key, value.clone())))
    }

    #[test]
    fn keys_keep_their_insertion_order() {
        let document = object(&[("b", Json::from("1")), ("a", Json::from(true))]);
        assert_eq!(
            to_text(&document),
            "{\n    \"b\": \"1\",\n    \"a\": true\n}\n"
        );
    }

    #[test]
    fn nesting_indents_four_spaces_and_empty_containers_stay_inline() {
        let document = object(&[
            (
                "list",
                Json::Array(vec![Json::from("x"), Json::Array(Vec::new())]),
            ),
            ("empty", Json::Object(Object::new())),
            ("null", Json::Null),
            ("number", Json::Int(3)),
        ]);
        assert_eq!(
            to_text(&document),
            "{\n    \"list\": [\n        \"x\",\n        []\n    ],\n    \"empty\": {},\n    \"null\": null,\n    \"number\": 3\n}\n"
        );
    }

    #[test]
    fn non_ascii_stays_utf8() {
        let text = to_text(&Json::from("é — 😀\n\"\\\u{1}"));
        assert_eq!(text, "\"é — 😀\\n\\\"\\\\\\u0001\"\n");
    }

    #[test]
    fn a_schema_writes_the_bytes_serde_json_writes() {
        // A generated schema starts as serde_json's Value (schemars): read
        // into the ordered tree, it is written byte for byte as serde_json's
        // own pretty printer writes it at four spaces.
        let text = r#"{"a":{"minItems":2,"maximum":1.5,"big":18446744073709551615},"b":["x",null,true,-1],"c":"é"}"#;
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut reference = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut reference, formatter);
        serde::Serialize::serialize(&value, &mut serializer).unwrap();
        reference.push(b'\n');
        assert_eq!(to_text(&Json::from(&value)).into_bytes(), reference);
    }
}
