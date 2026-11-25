//! A JSON value as text, where a client puts a value from an answer into a
//! message or a field that holds text: a string as it is, anything else as
//! its JSON (`null`, `true`, `1.5`, `["a",1]`).

use opentide_compile::json::Json;

/// `value` as text: a string as it is, anything else as its compact JSON.
pub fn json_text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_itself_and_anything_else_its_json() {
        assert_eq!(json_text(&Json::Str("it's".into())), "it's");
        assert_eq!(
            json_text(
                &serde_json::from_str::<Json>(r#"{"a": [1, null, true, 1.5]}"#)
                    .unwrap_or(Json::Null)
            ),
            r#"{"a":[1,null,true,1.5]}"#
        );
    }
}
