//! Edits to the user's JSON with comments (VS Code's and the MCP hosts'
//! configuration), made on jsonc-parser's concrete syntax tree: only the
//! members setup merges change, and every other byte stays as it was:
//! comments, layout, trailing commas, CRLF line endings and a byte-order
//! mark (#743). The oracle parsed these files with comments stripped and
//! wrote them back with `json.dumps`, which dropped all of that.

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstObject, CstRootNode};

use crate::json::Json;

const BOM: &str = "\u{feff}";

/// How setup reads these files: comments and trailing commas, as VS Code
/// does, but no unquoted keys.
fn options() -> ParseOptions {
    ParseOptions {
        allow_comments: true,
        allow_loose_object_property_names: false,
        allow_trailing_commas: true,
    }
}

/// `text` (a file's, a byte-order mark allowed) as a value, comments and
/// trailing commas allowed.
///
/// # Errors
///
/// The text is not JSON with comments: the parser's message.
pub fn parse(text: &str) -> Result<serde_json::Value, String> {
    let body = text.strip_prefix(BOM).unwrap_or(text);
    match jsonc_parser::parse_to_serde_value(body, &options()) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err("the file is empty".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

/// `value` as the tree's input.
pub fn input(value: &Json) -> CstInputValue {
    match value {
        Json::Null => CstInputValue::Null,
        Json::Bool(value) => CstInputValue::Bool(*value),
        Json::Int(value) => CstInputValue::Number(value.to_string()),
        Json::UInt(value) => CstInputValue::Number(value.to_string()),
        Json::Float(value) => CstInputValue::Number(value.to_string()),
        Json::Str(value) => CstInputValue::String(value.clone()),
        Json::Array(items) => CstInputValue::Array(items.iter().map(input).collect()),
        Json::Object(members) => CstInputValue::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), input(value)))
                .collect(),
        ),
    }
}

/// Why a file could not be merged; the file is left as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeError {
    /// It is not JSON with comments.
    Invalid(String),
    /// Its document is not an object.
    NotAnObject,
    /// A member the template merges into is not an object.
    MemberNotAnObject(String),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::Invalid(problem) => write!(f, "is not valid JSON ({problem})"),
            MergeError::NotAnObject => f.write_str("is not a JSON object"),
            MergeError::MemberNotAnObject(key) => write!(
                f,
                "has a {} that is not a JSON object",
                opentide_schema::configuration::repr::quote(key)
            ),
        }
    }
}

/// The root object of `root`.
fn root_object(root: &CstRootNode) -> Result<CstObject, MergeError> {
    match root.value() {
        Some(value) => value.as_object().ok_or(MergeError::NotAnObject),
        None => Err(MergeError::NotAnObject),
    }
}

/// `text` with `template`'s members merged in, one level deep: a member
/// the file lacks is added; an object member gains (or replaces) each of
/// the template's entries, the file's others kept; a scalar the file
/// already has stays the file's. Everything else in `text` is kept byte
/// for byte.
///
/// # Errors
///
/// The text is not JSON with comments, its document is not an object, or
/// a member to merge into is not an object.
pub fn merge(text: &str, template: &Json) -> Result<String, MergeError> {
    let (bom, body) = match text.strip_prefix(BOM) {
        Some(body) => (BOM, body),
        None => ("", text),
    };
    let root = CstRootNode::parse(body, &options())
        .map_err(|error| MergeError::Invalid(error.to_string()))?;
    let object = root_object(&root)?;
    let Json::Object(members) = template else {
        return Ok(text.to_owned());
    };
    for (key, value) in members {
        let Some(current) = object.get(key) else {
            object.append(key, input(value));
            continue;
        };
        let Json::Object(entries) = value else {
            continue;
        };
        let Some(existing) = current.object_value() else {
            return Err(MergeError::MemberNotAnObject(key.clone()));
        };
        for (name, entry) in entries {
            match existing.get(name) {
                Some(prop) => prop.set_value(input(entry)),
                None => {
                    existing.append(name, input(entry));
                }
            }
        }
    }
    let merged = format!("{bom}{root}");
    // The edit must read back as a document: never write one that does not.
    parse(&merged).map_err(MergeError::Invalid)?;
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Json {
        Json::parse(
            r#"{"servers": {"opentide": {"command": "opentide", "args": ["mcp", "start"]}}}"#,
        )
        .unwrap()
    }

    /// Every byte of `before` outside the merged member is in `after`, in
    /// order: removing the inserted text from `after` gives `before` back.
    fn only_inserted(before: &str, after: &str) -> String {
        let common_start = before
            .bytes()
            .zip(after.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        let common_end = before[common_start..]
            .bytes()
            .rev()
            .zip(after[common_start..].bytes().rev())
            .take_while(|(a, b)| a == b)
            .count();
        assert_eq!(
            common_start + common_end,
            before.len(),
            "bytes of the original changed:\n{before}\n---\n{after}"
        );
        after[common_start..after.len() - common_end].to_owned()
    }

    #[test]
    fn a_new_server_keeps_comments_crlf_and_the_bom() {
        let before = "\u{feff}{\r\n  // the team's servers\r\n  \"servers\": {\r\n    /* keep */ \"other\": {\"command\": \"x\"},\r\n  },\r\n}\r\n";
        let after = merge(before, &template()).unwrap();
        let inserted = only_inserted(before, &after);
        assert!(inserted.contains("\"opentide\""), "{inserted:?}");
        assert!(
            !inserted.contains('\n') || inserted.contains("\r\n"),
            "{inserted:?}"
        );
        assert!(after.starts_with('\u{feff}'));
        let value = parse(&after).unwrap();
        assert_eq!(value["servers"]["other"]["command"], "x");
        assert_eq!(value["servers"]["opentide"]["args"][1], "start");
    }

    #[test]
    fn an_existing_server_is_replaced_in_place() {
        let before = "{\n  \"servers\": {\n    \"opentide\": {\"command\": \"old\"}, // ours\n    \"b\": {}\n  }\n}\n";
        let after = merge(before, &template()).unwrap();
        assert!(after.contains("// ours"), "{after}");
        assert!(after.find("opentide").unwrap() < after.find("\"b\"").unwrap());
        let value = parse(&after).unwrap();
        assert_eq!(value["servers"]["opentide"]["command"], "opentide");
        assert_eq!(after.lines().last(), Some("}"));
    }

    #[test]
    fn a_missing_member_is_added_and_the_rest_kept() {
        let before = "{\n  // nothing yet\n  \"inputs\": []\n}\n";
        let after = merge(before, &template()).unwrap();
        only_inserted(before, &after);
        assert_eq!(parse(&after).unwrap()["inputs"], serde_json::json!([]));
    }

    #[test]
    fn a_scalar_the_file_has_stays_the_files() {
        let template = Json::parse(r#"{"$schema": "theirs", "mcpServers": {}}"#).unwrap();
        let before = "{\"$schema\": \"mine\", \"mcpServers\": {}}";
        let after = merge(before, &template).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn what_cannot_be_merged_is_refused() {
        assert_eq!(merge("[1]", &template()), Err(MergeError::NotAnObject));
        assert_eq!(
            merge("{\"servers\": []}", &template()),
            Err(MergeError::MemberNotAnObject("servers".into()))
        );
        assert!(matches!(
            merge("{", &template()),
            Err(MergeError::Invalid(_))
        ));
        assert_eq!(
            MergeError::MemberNotAnObject("servers".into()).to_string(),
            "has a 'servers' that is not a JSON object"
        );
    }

    #[test]
    fn parse_reads_comments_trailing_commas_and_a_bom() {
        let value = parse("\u{feff}{/* a */ \"a\": [1, 2,], // b\n}").unwrap();
        assert_eq!(value, serde_json::json!({"a": [1, 2]}));
        assert!(parse("{a: 1}").is_err());
    }
}
