//! A JSON document as opentide wrote it, its key order kept.

/// A JSON document opentide wrote: the text, with its keys in the order the
/// command line writes them, and the parsed value.
///
/// [`serde_json::Value`] sorts an object's keys, so [`Document::value`] is
/// for reading fields; [`Document::as_str`] is the document itself, byte for
/// byte what every SDK and the command line return for the same run.
///
/// ```
/// let document = opentide::Document::parse("{\"b\":1,\"a\":2}")?;
/// assert_eq!(document.as_str(), "{\"b\":1,\"a\":2}");
/// assert_eq!(document.value()["a"], 2);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    text: String,
    value: serde_json::Value,
}

impl Document {
    /// The document `text` holds.
    ///
    /// # Errors
    ///
    /// `text` is not one JSON value.
    pub fn parse(text: impl Into<String>) -> Result<Self, serde_json::Error> {
        let text = text.into();
        let value = serde_json::from_str(&text)?;
        Ok(Self { text, value })
    }

    /// A document from its text and the value it holds, which the caller
    /// built together.
    #[cfg_attr(
        not(feature = "compile"),
        expect(dead_code, reason = "the deploy plan's")
    )]
    pub(crate) fn from_parts(text: String, value: serde_json::Value) -> Self {
        Self { text, value }
    }

    /// The document as written: its keys in order, its trailing newline (if
    /// any) kept.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The parsed value.
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    /// The parsed value, owned.
    pub fn into_value(self) -> serde_json::Value {
        self.value
    }

    /// The text, owned.
    pub fn into_string(self) -> String {
        self.text
    }
}

impl std::fmt::Display for Document {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_keeps_its_text_and_parses_its_value() {
        let document = Document::parse("{\"z\":[1,2],\"a\":null}\n").unwrap();
        assert_eq!(document.to_string(), "{\"z\":[1,2],\"a\":null}\n");
        assert_eq!(document.value()["z"][1], 2);
        assert_eq!(document.clone().into_value()["a"], serde_json::Value::Null);
        assert_eq!(document.into_string(), "{\"z\":[1,2],\"a\":null}\n");
        assert!(Document::parse("{").is_err());
    }
}
