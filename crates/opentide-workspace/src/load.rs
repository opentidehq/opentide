//! Reading one object file: bytes to a YAML 1.2 document
//! (`opentide_schema::node`), or the reason it cannot be one
//! (`registry/builder.py` `_parse_yaml_file`).

use std::sync::Arc;

use opentide_schema::node::{self, Document, LoadErrorKind, Value};

/// Why an object file did not load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// The file cannot be read (`unreadable_object_file`).
    Unreadable,
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The text is not YAML, as saphyr reads YAML 1.2.
    Yaml(LoadErrorKind),
    /// The document is not one mapping.
    NotMapping,
}

/// An object file that did not load: its kind and the problem in words (the
/// index's `error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// What kind of failure.
    pub kind: FailureKind,
    /// The problem, in words.
    pub error: String,
}

/// An object file, read and parsed once.
#[derive(Debug, Clone)]
pub enum Parsed {
    /// A document whose root is a mapping.
    Document(Arc<Document>),
    /// It did not load.
    Failed(Failure),
}

/// Why a file that is not UTF-8 cannot be read, with the byte at fault
/// (`core/io.py` `not_utf8_problem`). Offsets count from after a byte order
/// mark, as Python's `utf-8-sig` decoder counts them.
pub fn not_utf8_problem(bytes: &[u8], offset: usize) -> String {
    match bytes.get(offset) {
        Some(byte) => format!(
            "the file is not UTF-8 text (byte 0x{byte:02x} at offset {offset}); save it as UTF-8"
        ),
        None => "the file is not UTF-8 text; save it as UTF-8".to_owned(),
    }
}

/// Why a parsed document is not one mapping (`core/io.py`
/// `root_mapping_problem`); `None` when it is.
pub fn root_mapping_problem(document: &Document) -> Option<String> {
    let found = match document.root().map(|root| &root.value) {
        Some(Value::Map(_)) => return None,
        None | Some(Value::Null) => "an empty file",
        Some(Value::Seq(_)) => "a list",
        Some(Value::Str(_)) => "a string",
        Some(_) => "a single value",
    };
    Some(format!(
        "expected a mapping at the top of the file, found {found}"
    ))
}

/// Parses an object file's bytes.
pub fn parse(bytes: &[u8]) -> Parsed {
    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(error) => {
            return Parsed::Failed(Failure {
                kind: FailureKind::NotUtf8,
                error: not_utf8_problem(body, error.valid_up_to()),
            });
        }
    };
    match node::load(text) {
        Ok(document) => match root_mapping_problem(&document) {
            None => Parsed::Document(Arc::new(document)),
            Some(error) => Parsed::Failed(Failure {
                kind: FailureKind::NotMapping,
                error,
            }),
        },
        Err(error) => {
            let mut text = error.problem.clone();
            if let Some(mark) = error.mark {
                text.push_str(&format!(" at line {}, column {}", mark.line, mark.column));
            }
            Parsed::Failed(Failure {
                kind: FailureKind::Yaml(error.kind),
                error: text,
            })
        }
    }
}

/// An unreadable file's failure.
pub fn unreadable(error: &std::io::Error) -> Parsed {
    Parsed::Failed(Failure {
        kind: FailureKind::Unreadable,
        error: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(bytes: &[u8]) -> Failure {
        match parse(bytes) {
            Parsed::Failed(failure) => failure,
            Parsed::Document(_) => panic!("{bytes:?} loaded"),
        }
    }

    #[test]
    fn a_mapping_loads_and_a_bom_is_dropped() {
        assert!(matches!(parse(b"\xef\xbb\xbfa: 1\n"), Parsed::Document(_)));
    }

    #[test]
    fn the_root_must_be_one_mapping() {
        for (text, found) in [
            ("", "an empty file"),
            ("# only a comment\n", "an empty file"),
            ("~\n", "an empty file"),
            ("- a\n", "a list"),
            ("text\n", "a string"),
            ("12\n", "a single value"),
            ("true\n", "a single value"),
        ] {
            let failure = failed(text.as_bytes());
            assert_eq!(failure.kind, FailureKind::NotMapping, "{text:?}");
            assert_eq!(
                failure.error,
                format!("expected a mapping at the top of the file, found {found}")
            );
        }
    }

    #[test]
    fn bytes_that_are_not_utf8_name_the_byte_and_its_offset() {
        let failure = failed(b"a: \xff\n");
        assert_eq!(failure.kind, FailureKind::NotUtf8);
        assert_eq!(
            failure.error,
            "the file is not UTF-8 text (byte 0xff at offset 3); save it as UTF-8"
        );
        // After a BOM, the offset counts from the text.
        let failure = failed(b"\xef\xbb\xbfa: \xe9x\n");
        assert_eq!(
            failure.error,
            "the file is not UTF-8 text (byte 0xe9 at offset 3); save it as UTF-8"
        );
        assert_eq!(
            not_utf8_problem(b"", 4),
            "the file is not UTF-8 text; save it as UTF-8"
        );
    }

    #[test]
    fn yaml_errors_carry_their_position() {
        let failure = failed(b"a: 1\na: 2\n");
        assert_eq!(failure.kind, FailureKind::Yaml(LoadErrorKind::DuplicateKey));
        assert!(
            failure.error.ends_with("at line 2, column 1"),
            "{}",
            failure.error
        );
        let failure = failed(b"a: [1, 2\n");
        assert_eq!(failure.kind, FailureKind::Yaml(LoadErrorKind::Syntax));
        assert!(failure.error.contains(" at line "), "{}", failure.error);
    }

    #[test]
    fn an_io_error_is_unreadable() {
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let Parsed::Failed(failure) = unreadable(&error) else {
            panic!("unreadable loaded");
        };
        assert_eq!(failure.kind, FailureKind::Unreadable);
        assert_eq!(failure.error, "denied");
    }
}
