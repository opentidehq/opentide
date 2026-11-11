//! Request bodies as the Python clients send them.
//!
//! A request body is what the platform receives, so it is byte for byte the
//! Python client's. `requests`' `json=` writes `json.dumps(value)`: `", "`
//! between items, `": "` after a key, and every character outside ASCII as a
//! `\uXXXX` escape (a surrogate pair above the BMP). serde_json writes the
//! value; [`PythonJson`], a serde_json formatter, gives it that layout.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};

/// The bytes `json.dumps(value)` writes for *value*.
pub fn python_json<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut out, PythonJson);
    value.serialize(&mut serializer)?;
    Ok(out)
}

/// serde_json's compact layout with `json.dumps`' separators and ASCII escapes.
#[derive(Clone, Copy, Debug, Default)]
pub struct PythonJson;

impl Formatter for PythonJson {
    fn begin_array_value<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        first: bool,
    ) -> io::Result<()> {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W: ?Sized + Write>(&mut self, writer: &mut W) -> io::Result<()> {
        writer.write_all(b": ")
    }

    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (index, character) in fragment.char_indices() {
            if character.is_ascii() {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..index])?;
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = index + character.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn write_char_escape<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        // json.dumps escapes control characters as \uXXXX, but \b \f \n \r \t
        // by name, as serde_json does.
        match escape {
            CharEscape::AsciiControl(byte) => write!(writer, "\\u{byte:04x}"),
            other => serde_json::ser::CompactFormatter.write_char_escape(writer, other),
        }
    }
}
