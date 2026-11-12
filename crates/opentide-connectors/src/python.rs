//! Python's text forms of a parsed JSON value, as the Python clients
//! interpolate a body or a value into a message: `str(value)` and
//! `repr(value)` (`{'a': [1, None]}`).

use opentide_compile::json::Json;

/// `str(value)` of a JSON value as Python prints the parsed value: a string
/// as is, anything else in Python's `repr`.
pub fn python_str(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        other => python_repr(other),
    }
}

/// Python's `repr` of a parsed JSON value (`{'a': [1, None]}`), as an
/// error message that interpolates a body prints it.
pub fn python_repr(value: &Json) -> String {
    match value {
        Json::Null => "None".to_owned(),
        Json::Bool(true) => "True".to_owned(),
        Json::Bool(false) => "False".to_owned(),
        Json::Int(integer) => integer.to_string(),
        Json::Float(float) => opentide_schema::configuration::repr::float_text(*float),
        Json::Str(text) => python_string_repr(text),
        Json::Array(items) => {
            let inner: Vec<String> = items.iter().map(python_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Json::Object(object) => {
            let inner: Vec<String> = object
                .iter()
                .map(|(key, value)| format!("{}: {}", python_string_repr(key), python_repr(value)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// Python's `repr` of a string: single quotes unless the text holds one and
/// no double quote.
pub fn python_string_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_read_as_python_prints_them() {
        assert_eq!(
            python_repr(
                &serde_json::from_str::<Json>(r#"{"a": [1, null, true], "b": "it's"}"#)
                    .unwrap_or(Json::Null)
            ),
            r#"{'a': [1, None, True], 'b': "it's"}"#
        );
        assert_eq!(python_str(&Json::Str("x".into())), "x");
        assert_eq!(python_string_repr("a\tb'\""), "'a\\tb\\'\"'");
    }
}
