//! The engine catalogs' loader (ADR 0013, #1071): a catalog compiled in as
//! TOML is read one array item at a time, never as a whole document.
//!
//! `toml` builds a whole document (every key, span and string) before it
//! deserialises, which costs several times the catalog it holds: the Falco
//! field table's took 5 to 6 MiB at `opentide validate`'s peak, and the
//! Azure Monitor reference's tens of MiB. Here the items are parsed a few at
//! a time (about 4 KiB of text), so only a small document is alive, and
//! only the catalog's own values are kept.
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
//! nothing after it), and no value is a `"""` or `'''` string.
//!
//! What this checks, and what it does not: every line's form is checked, and
//! a line outside the items read must at least look like `key = value`; the
//! items of the array asked for are parsed, the other arrays' items and the
//! preamble are not (that is what keeps a read cheap). So a duplicate key in
//! another array, or a preamble key named like an array, is not caught here.
//! What makes a catalog safe is its crate's test, which is mandatory (ADR
//! 0013): the compiled-in files read with these functions equal, field for
//! field, `toml::from_str` of the whole files.

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

/// How much catalog text one parse reads, at most (plus one item): a few
/// items at a time, so that a parser is not set up per item, and the
/// document `toml` builds stays small.
const BATCH_BYTES: usize = 4 * 1024;

/// The items of the array of tables `[[key]]` in the catalog `text`, read a
/// few at a time (never the whole file); items of another array are
/// skipped.
///
/// # Errors
///
/// An item does not deserialise, or the text is not in the form the module
/// describes.
pub fn array_items<T: DeserializeOwned>(text: &str, key: &str) -> Result<Vec<T>, CatalogError> {
    let mut items = Vec::new();
    // The items of `key` read but not yet parsed, verbatim, and where each
    // starts: its line in the file and its offset in `batch`.
    let mut batch = String::new();
    let mut starts: Vec<(usize, usize)> = Vec::new();
    // Whether the current item is one of `key`'s.
    let mut in_item = false;
    each_line(text, |line, at, kind| {
        match kind {
            Line::Item(name) => {
                if batch.len() >= BATCH_BYTES {
                    items.extend(batch_of::<T>(&batch, &starts, key)?);
                    batch.clear();
                    starts.clear();
                }
                in_item = name == key;
                if in_item {
                    starts.push((at, batch.len()));
                    batch.push_str(line);
                }
            }
            Line::Sub => {
                if in_item {
                    batch.push_str(line);
                }
            }
            Line::Value => {
                if in_item {
                    batch.push_str(line);
                } else {
                    // Another array's line, not parsed here: it must at least
                    // look like a value, a comment or nothing.
                    let rest = line.trim();
                    if !(rest.is_empty() || rest.starts_with('#') || rest.contains('=')) {
                        return Err(CatalogError {
                            line: at,
                            why: format!("not a `key = value` line: {rest:?}"),
                        });
                    }
                }
            }
            Line::Preamble | Line::Blank => {}
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        items.extend(batch_of::<T>(&batch, &starts, key)?);
    }
    Ok(items)
}

/// The items of `[[key]]` in `body`, a run of them as the catalog writes
/// them, each starting at a `(line in the file, offset in body)` of
/// `starts`. When the run does not parse, its items are parsed one by one
/// to name the item at fault, and the line within it.
fn batch_of<T: DeserializeOwned>(
    body: &str,
    starts: &[(usize, usize)],
    key: &str,
) -> Result<Vec<T>, CatalogError> {
    type Items<T> = std::collections::BTreeMap<String, Vec<T>>;
    if let Ok(mut parsed) = toml::from_str::<Items<T>>(body) {
        return Ok(parsed.remove(key).unwrap_or_default());
    }
    for (index, &(line, offset)) in starts.iter().enumerate() {
        let end = starts.get(index + 1).map_or(body.len(), |&(_, next)| next);
        if let Err(err) = toml::from_str::<Items<T>>(&body[offset..end]) {
            // `toml` counts lines from the item's header, which is `line`.
            let within = err
                .span()
                .map(|span| body[offset..offset + span.start].matches('\n').count());
            return Err(CatalogError {
                line: line + within.unwrap_or(0),
                why: format!("in the [[{key}]] item of line {line}: {}", err.message()),
            });
        }
    }
    // Every item parses on its own but not together: two items that clash.
    Err(CatalogError {
        line: starts.first().map_or(0, |&(line, _)| line),
        why: format!("the [[{key}]] items from this line do not parse together"),
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
    /// `[name.sub]` or `[[name.sub]]`: a sub-table of the current item.
    Sub,
    /// A line of the current item.
    Value,
}

/// Calls `each` with every line of `text`, its 1-based number and what it
/// is, after checking the line is in the module's form.
fn each_line<'t>(
    text: &'t str,
    mut each: impl FnMut(&'t str, usize, Line<'t>) -> Result<(), CatalogError>,
) -> Result<(), CatalogError> {
    // One search over the whole text, not two per line: no value of a
    // catalog is a multi-line string.
    for marker in ["\"\"\"", "'''"] {
        if let Some(found) = text.find(marker) {
            let line = text[..found].matches('\n').count() + 1;
            let shown = text[found..].lines().next().unwrap_or_default();
            return Err(CatalogError {
                line,
                why: format!("a multi-line string: {shown:?}"),
            });
        }
    }
    // The top-level array the last header opened, if any.
    let mut array: Option<&str> = None;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let at = index + 1;
        // Most lines are an item's values: only their first non-blank byte
        // is looked at.
        let first = line.bytes().find(|byte| !matches!(byte, b' ' | b'\t'));
        if array.is_some() && first != Some(b'[') {
            each(line, at, Line::Value)?;
            continue;
        }
        let trimmed = line.trim_end();
        let refuse = |why: &str| {
            Err(CatalogError {
                line: at,
                why: format!("{why}: {trimmed:?}"),
            })
        };
        let rest = trimmed.trim_start();
        if !rest.starts_with('[') {
            // Before the first array: comments, blank lines and the preamble.
            let kind = if rest.is_empty() || rest.starts_with('#') {
                Line::Blank
            } else if rest.len() == trimmed.len() && rest.contains('=') {
                Line::Preamble
            } else {
                return refuse("not a `key = value` line before the first array");
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
                top, sub: Some(_), ..
            } => {
                if array != Some(top) {
                    return refuse("a sub-table outside its array's last item");
                }
                Line::Sub
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
        // Another array's line that is not even `key = value`.
        assert!(
            array_items::<toml::Value>("[[u]]\nthis is not toml\n[[t]]\nk = 1\n", "t").is_err()
        );
        // A batch that does not parse names its item's line, and the line in
        // it, in the file's numbering.
        let mut text = String::new();
        for i in 0..20 {
            text.push_str(&format!("[[u]]\nk = {i}\n[[t]]\nname = \"{i}\"\n"));
        }
        let bad_at = text.lines().count() + 1;
        text.push_str("[[t]]\nname = \"x\"\nbroken = \n");
        let error = array_items::<toml::Value>(&text, "t").unwrap_err();
        assert_eq!(error.line, bad_at + 2, "{error}");
        assert!(
            error.why.contains(&format!("item of line {bad_at}")),
            "{error}"
        );
    }
}
