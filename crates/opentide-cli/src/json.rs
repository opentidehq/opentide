//! The document text the CLI prints, from [`opentide_core::json::Json`],
//! whose objects keep their key order.
//!
//! The envelope's key order is part of the contract (`docs/cli/json-output.md`):
//! a reader may compare documents as text.

pub use opentide_core::json::{Json, Object};

/// `document` as the CLI prints it: indented by two spaces when `indent`,
/// otherwise one compact line; either way ending in exactly one newline.
pub fn document_text(document: &Json, indent: bool) -> String {
    let mut text = if indent {
        document.to_pretty(2)
    } else {
        document.to_compact()
    };
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_keep_their_key_order_through_a_round_trip() {
        let text = r#"{"z":1,"a":[true,null,{"y":"x","b":2.5}],"m":18446744073709551615}"#;
        let json = Json::parse(text).unwrap();
        assert_eq!(document_text(&json, false), format!("{text}\n"));
    }

    #[test]
    fn indented_documents_use_two_spaces_and_one_trailing_newline() {
        let json = Json::object([
            ("a", Json::Int(1)),
            ("b", Json::Array(vec![])),
            ("c", Json::object::<String>([])),
        ]);
        assert_eq!(
            document_text(&json, true),
            "{\n  \"a\": 1,\n  \"b\": [],\n  \"c\": {}\n}\n"
        );
    }

    #[test]
    fn floats_print_as_python_prints_them() {
        assert_eq!(document_text(&Json::Float(120.0), false), "120.0\n");
    }

    #[test]
    fn non_ascii_stays_as_is_and_control_characters_are_escaped() {
        assert_eq!(
            document_text(&Json::str("✓ \u{1b}"), false),
            "\"✓ \\u001b\"\n"
        );
    }

    #[test]
    fn get_reads_a_member() {
        let json = Json::object([("a", Json::Int(1))]);
        assert_eq!(json.get("a"), Some(&Json::Int(1)));
        assert_eq!(json.get("b"), None);
        assert_eq!(Json::Null.get("a"), None);
        assert_eq!(Json::opt_str(None::<String>), Json::Null);
    }
}
