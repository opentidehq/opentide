//! The engine catalogs' loader (ADR 0013, #1071): a catalog compiled in as
//! TOML is read one array item at a time, never as a whole document.
//!
//! `toml` builds a whole document (every key, span and string) before it
//! deserialises, which costs several times the catalog it holds: the Falco
//! field table's took 5 to 6 MiB at `opentide validate`'s peak, and the
//! Azure Monitor reference's tens of MiB. Here only one item's document is
//! alive at a time, and only the catalog's own values are kept.
//!
//! The text must be in the form the sync scripts write:
//!
//! - comments and blank lines anywhere outside an item;
//! - before the first array, an optional preamble of `key = value` lines,
//!   each on one line ([`preamble`]);
//! - then top-level arrays of tables: each item starts at a line `[[name]]`,
//!   its sub-tables are `[name.<sub>]` or `[[name.<sub>]]`, and its values
//!   fit on their line.
//!
//! Every header is written exactly so (bare names, at the start of the line,
//! nothing after it), and no value is a `"""` or `'''` string. Anything else
//! is refused with the line, never read differently from `toml`'s reading of
//! the whole file. A catalog's crate tests the equality on its compiled-in
//! files.

use serde::de::DeserializeOwned;

/// A catalog text that is not in the form [`array_items`] and [`preamble`]
/// read, or an item that does not deserialise.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {why}")]
pub struct CatalogError {
    /// The 1-based line it is about; 0 for the preamble as a whole.
    pub line: usize,
    /// What is wrong, with the line's text.
    pub why: String,
}

/// The items of the array of tables `[[key]]` in the catalog `text`, each
/// deserialised on its own; items of another array are skipped.
///
/// # Errors
///
/// An item does not deserialise, or the text is not in the form the module
/// describes.
pub fn array_items<T: DeserializeOwned>(text: &str, key: &str) -> Result<Vec<T>, CatalogError> {
    let mut items = Vec::new();
    // The item being read and the line it starts at: `Some` while in one of
    // `key`'s, `None` in another array's or before the first.
    let mut item: Option<(String, usize)> = None;
    each_line(text, |line, at, kind| {
        match kind {
            Line::Item(name) => {
                if let Some((done, start)) = item.take() {
                    items.push(item_of(&done, key, start)?);
                }
                if name == key {
                    item = Some((String::new(), at));
                }
            }
            Line::Sub { array, name, sub } => {
                if let Some((body, _)) = item.as_mut().filter(|_| name == key) {
                    // `[[key.columns]]` is the item's own `[[columns]]`.
                    let (open, close) = if array { ("[[", "]]") } else { ("[", "]") };
                    body.push_str(open);
                    body.push_str(sub);
                    body.push_str(close);
                    body.push('\n');
                }
            }
            Line::Value => {
                if let Some((body, _)) = item.as_mut() {
                    body.push_str(line);
                }
            }
            Line::Preamble | Line::Blank => {}
        }
        Ok(())
    })?;
    if let Some((done, start)) = item {
        items.push(item_of(&done, key, start)?);
    }
    Ok(items)
}

/// One item of `[[key]]`, whose text (from its first line, `at`) is `body`.
fn item_of<T: DeserializeOwned>(body: &str, key: &str, at: usize) -> Result<T, CatalogError> {
    toml::from_str(body).map_err(|err| CatalogError {
        line: at,
        why: format!("[[{key}]]: {err}"),
    })
}

/// The catalog's preamble, the `key = value` lines before its first array,
/// deserialised as `T`.
///
/// # Errors
///
/// The preamble does not deserialise as `T`, or the text is not in the form
/// the module describes.
pub fn preamble<T: DeserializeOwned>(text: &str) -> Result<T, CatalogError> {
    let mut body = String::new();
    each_line(text, |line, _, kind| {
        if matches!(kind, Line::Preamble) {
            body.push_str(line);
        }
        Ok(())
    })?;
    toml::from_str(&body).map_err(|err| CatalogError {
        line: 0,
        why: format!("the preamble: {err}"),
    })
}

/// What a line of a catalog is.
enum Line<'a> {
    /// A comment or a blank line outside an item.
    Blank,
    /// A `key = value` line before the first array.
    Preamble,
    /// `[[name]]`: an item of the top-level array `name` starts.
    Item(&'a str),
    /// `[name.sub]` or `[[name.sub]]` (`array`): a sub-table of the current
    /// item of `name`.
    Sub {
        array: bool,
        name: &'a str,
        sub: &'a str,
    },
    /// A line of the current item.
    Value,
}

/// Calls `each` with every line of `text`, its 1-based number and what it
/// is, after checking the line is in the module's form.
fn each_line<'t>(
    text: &'t str,
    mut each: impl FnMut(&'t str, usize, Line<'t>) -> Result<(), CatalogError>,
) -> Result<(), CatalogError> {
    // The top-level array the last header opened, if any.
    let mut array: Option<&str> = None;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let at = index + 1;
        let trimmed = line.trim_end();
        let refuse = |why: &str| {
            Err(CatalogError {
                line: at,
                why: format!("{why}: {trimmed:?}"),
            })
        };
        if trimmed.contains("\"\"\"") || trimmed.contains("'''") {
            return refuse("a multi-line string");
        }
        let rest = trimmed.trim_start();
        if !rest.starts_with('[') {
            let blank = rest.is_empty() || rest.starts_with('#');
            let kind = match (array, blank) {
                (_, true) if array.is_none() => Line::Blank,
                (None, false) if rest.len() == trimmed.len() && rest.contains('=') => {
                    Line::Preamble
                }
                (None, false) => return refuse("not a `key = value` line before the first array"),
                _ => Line::Value,
            };
            each(line, at, kind)?;
            continue;
        }
        let Some(header) = Header::of(trimmed) else {
            return refuse("not a header of the form the sync scripts write");
        };
        let kind = match header {
            Header {
                array: true,
                top,
                sub: None,
            } => {
                array = Some(top);
                Line::Item(top)
            }
            Header { sub: None, .. } => return refuse("a top-level table, not an array item"),
            Header {
                array: nested,
                top,
                sub: Some(sub),
            } => {
                if array != Some(top) {
                    return refuse("a sub-table outside its array's last item");
                }
                Line::Sub {
                    array: nested,
                    name: top,
                    sub,
                }
            }
        };
        each(line, at, kind)?;
    }
    Ok(())
}

/// A table header as the sync scripts write it: `[[top]]`, `[[top.sub]]` or
/// `[top.sub]`, bare names only, the whole line.
struct Header<'a> {
    array: bool,
    top: &'a str,
    sub: Option<&'a str>,
}

impl<'a> Header<'a> {
    fn of(line: &'a str) -> Option<Self> {
        let (array, name) = match line.strip_prefix("[[") {
            Some(rest) => (true, rest.strip_suffix("]]")?),
            None => (false, line.strip_prefix('[')?.strip_suffix(']')?),
        };
        let bare = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        };
        let (top, sub) = match name.split_once('.') {
            Some((top, sub)) => (top, Some(sub)),
            None => (name, None),
        };
        (bare(top) && sub.is_none_or(bare)).then_some(Self { array, top, sub })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct File {
        #[serde(default)]
        classes: Vec<String>,
        t: Vec<toml::Value>,
        #[serde(default)]
        u: Vec<toml::Value>,
    }

    /// The whole file's reading, which `array_items` and `preamble` match.
    const TEXT: &str = "# c\n\nclasses = [\"a\", \"b\"]\n\n[[u]]\nname = \"x\"\n[[u.sub]]\nk = 1\n\
                        [[t]]\nname = \"a\"\n[t.meta]\nx = 1\n[[t.columns]]\nname = \"c\"\n\
                        [[t.columns]]\nname = \"d\"\n# between\n[[t]]\nname = \"b\"\n[[u]]\nname = \"y\"\n";

    #[test]
    fn items_and_preamble_are_the_whole_file_s() {
        let whole: File = toml::from_str(TEXT).unwrap();
        let t: Vec<toml::Value> = array_items(TEXT, "t").unwrap();
        let u: Vec<toml::Value> = array_items(TEXT, "u").unwrap();
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Preamble {
            classes: Vec<String>,
        }
        let first: Preamble = preamble(TEXT).unwrap();
        assert_eq!((t, u), (whole.t, whole.u));
        assert_eq!(first.classes, whole.classes);
        assert_eq!(array_items::<toml::Value>(TEXT, "none").unwrap(), []);
        // CRLF reads as LF does.
        let crlf = TEXT.replace('\n', "\r\n");
        assert_eq!(
            array_items::<toml::Value>(&crlf, "t").unwrap(),
            array_items::<toml::Value>(TEXT, "t").unwrap()
        );
    }

    #[test]
    fn what_the_scripts_never_write_is_refused_not_read_otherwise() {
        for (text, why) in [
            (
                "[[t]]\nname = \"a\"\n[[t]] # c\nname = \"b\"\n",
                "trailing comment",
            ),
            (
                "[[t]]\nname = \"a\"\n[[t.columns]] # c\nname = \"c\"\n",
                "sub comment",
            ),
            ("[[ t ]]\nname = \"a\"\n", "spaces"),
            ("[[t]]\n[[ t.columns ]]\nname = \"c\"\n", "sub spaces"),
            ("[[\"t\"]]\nname = \"a\"\n", "quoted"),
            ("[[t]]\nname = \"a\"\n  [[t]]\nname = \"b\"\n", "indented"),
            ("[[t]]\ndocs = \"\"\"\n[t.x]\n\"\"\"\n", "multi-line string"),
            ("[[t]]\ndocs = '''\nx\n'''\n", "literal multi-line"),
            (
                "[[t]]\nname = \"a\"\n[[u]]\nk = 1\n[[t.columns]]\nname = \"c\"\n",
                "late sub",
            ),
            ("[t.x]\nk = 1\n[[t]]\nname = \"a\"\n", "sub before item"),
            ("[[t]]\nname = \"a\"\n[t.x.y]\nk = 1\n", "deep sub"),
            ("[[t]]\nname = \"a\"\n[x]\nk = 1\n", "top-level table"),
            ("  k = 1\n[[t]]\nname = \"a\"\n", "indented preamble"),
            ("words\n[[t]]\nname = \"a\"\n", "not a key = value"),
            ("[[t]]\nname = \n", "an item that does not parse"),
        ] {
            assert!(array_items::<toml::Value>(text, "t").is_err(), "{why}");
        }
        let error =
            array_items::<toml::Value>("[[t]]\nname = \"a\"\n[[t]] # c\n", "t").unwrap_err();
        assert_eq!(error.line, 3);
    }
}
