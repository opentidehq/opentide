//! Writing a model as YAML: serde-saphyr's serializer, YAML 1.2. A string
//! that would read back as another type (`true`, `null`, `12`, `.inf`) is
//! quoted, so [`super::load`] reads back the same value.

use serde::Serialize;

/// Why a value could not be written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DumpError(String);

/// `value` as one YAML document, fields in declaration order.
pub fn to_yaml<T: Serialize>(value: &T) -> Result<String, DumpError> {
    serde_saphyr::to_string(value).map_err(|error| DumpError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{Value, load};

    #[test]
    fn strings_that_look_like_other_types_read_back_as_strings() {
        let texts = [
            "yes",
            "true",
            "True",
            "null",
            "~",
            "",
            "12",
            "0x1f",
            "0o17",
            "1.5",
            ".inf",
            "-.inf",
            ".nan",
            "1e3",
            "2026-01-01",
            "<<",
            "=",
            "a: b",
            "- x",
            "#c",
            " lead",
            "it's",
            "line\nbreak",
        ];
        let yaml = to_yaml(&texts).unwrap();
        let document = load(&yaml).unwrap();
        let Value::Seq(items) = &document.root().unwrap().value else {
            panic!("{yaml}")
        };
        let back: Vec<&str> = items.iter().map(|n| n.value.as_str().unwrap()).collect();
        assert_eq!(back, texts, "{yaml}");
    }

    #[test]
    fn floats_read_back_equal() {
        let floats = [0.5, 1e16, 1.0, -0.0, f64::INFINITY, f64::NEG_INFINITY, 1e-7];
        let yaml = to_yaml(&floats).unwrap();
        let document = load(&yaml).unwrap();
        let Value::Seq(items) = &document.root().unwrap().value else {
            panic!("{yaml}")
        };
        for (item, float) in items.iter().zip(floats) {
            match item.value {
                Value::Float(back) => assert_eq!(back.to_bits(), float.to_bits(), "{yaml}"),
                ref other => panic!("{other:?} in {yaml}"),
            }
        }
    }
}
