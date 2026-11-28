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
//! - before the first array, an optional preamble ([`preamble`]): `key =
//!   value` lines (a value may span lines there) and tables (`[meta]`);
//! - then top-level arrays of tables: each item starts at a line `[[name]]`,
//!   and its sub-tables are `[name.<sub>]` or `[[name.<sub>]]`. A value may
//!   span lines (a long array), but no line of it starts with `[`, which
//!   would read as a header (and is refused as one).
//!
//! Every header is written exactly so (bare names, at the start of the line,
//! nothing after it), and no value is a `"""` or `'''` string (one inside a
//! `"..."` or `'...'` string, or in a comment, is fine). A key written after a
//! preamble table belongs to that table, as in any TOML: a top-level key goes
//! before the first table.
//!
//! What this checks, and what it does not: every line's form is checked, and
//! a line that is not parsed where it is read (the preamble, another array's
//! item) must at least look like TOML (`key = value`, a value's
//! continuation, a comment); the
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
    Ok(read_items(text, key, None)?.0)
}

/// The items of `[[key]]`, as [`array_items`] reads them, each with its own
/// text in `text` (its header to its last line), leaving out of the parse
/// the item lines `keep` refuses: a caller reads what it left out from an
/// item's text when it needs it, so a large value it rarely reads is
/// neither parsed nor kept (a vocabulary's descriptions, #1071). A parse
/// error's line, within an item, does not count the lines left out.
///
/// # Errors
///
/// As [`array_items`].
pub fn array_items_keeping<'t, T: DeserializeOwned>(
    text: &'t str,
    key: &str,
    keep: &dyn Fn(&str) -> bool,
) -> Result<Vec<(T, &'t str)>, CatalogError> {
    let (items, spans) = read_items(text, key, Some(keep))?;
    Ok(items
        .into_iter()
        .zip(spans)
        .map(|(item, span)| (item, text.get(span).unwrap_or_default()))
        .collect())
}

/// The items of `[[key]]` in `text`; with a `keep`, [`array_items_keeping`]'s
/// reading and the items' byte ranges in `text`.
fn read_items<T: DeserializeOwned>(
    text: &str,
    key: &str,
    keep: Option<&dyn Fn(&str) -> bool>,
) -> Result<(Vec<T>, Vec<std::ops::Range<usize>>), CatalogError> {
    // Where `line`, a line of `text`, starts in it.
    let offset = |line: &str| line.as_ptr() as usize - text.as_ptr() as usize;
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
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
                    if keep.is_some() {
                        let start = offset(line);
                        ranges.push(start..start + line.len());
                    }
                }
            }
            Line::Sub | Line::Value if in_item => match keep {
                None => batch.push_str(line),
                Some(keep) => {
                    if keep(line) {
                        batch.push_str(line);
                    }
                    if let Some(range) = ranges.last_mut() {
                        range.end = offset(line) + line.len();
                    }
                }
            },
            Line::Sub => {}
            // Another array's line, not parsed here.
            Line::Value => looks_like_toml(line, at)?,
            Line::Preamble | Line::Blank => {}
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        items.extend(batch_of::<T>(&batch, &starts, key)?);
    }
    Ok((items, ranges))
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
        // Each item starts where a line of it was pushed onto `body`.
        let Some(item) = body.get(offset..end) else {
            debug_assert!(false, "{offset}..{end} in {} bytes", body.len());
            return Err(CatalogError {
                line,
                why: format!("the [[{key}]] item of line {line} could not be cut out"),
            });
        };
        if let Err(err) = toml::from_str::<Items<T>>(item) {
            // `toml` counts lines from the item's header, which is `line`;
            // its span is in bytes.
            let within = err.span().and_then(|span| {
                let before = item.as_bytes().get(..span.start)?;
                Some(memchr::memchr_iter(b'\n', before).count())
            });
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

/// The catalog's preamble, the values and tables before its first array,
/// deserialised as `T`. Only the text before the first array is read.
///
/// # Errors
///
/// The preamble does not deserialise as `T`, or the text is not in the form
/// the module describes.
pub fn preamble<T: DeserializeOwned>(text: &str) -> Result<T, CatalogError> {
    // Headers start their line: the preamble ends at the first `[[`, and
    // keeps the `\n` before it, so a CRLF line ending stays whole.
    let head = if text.starts_with("[[") {
        ""
    } else {
        memchr::memmem::find(text.as_bytes(), b"\n[[")
            .and_then(|at| text.get(..=at))
            .unwrap_or(text)
    };
    let mut body = String::new();
    each_line(head, |line, _, kind| {
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

/// `result`, the reading of the catalog file `file` compiled into the
/// engine: a bad one fails the crate's tests, never a user's document, so it
/// is a bug, and panics with the file and the line.
///
/// # Panics
///
/// `result` is an error.
#[track_caller]
#[expect(
    clippy::panic,
    reason = "a catalog compiled in with include_str!: a bad one fails the tests, never a user's document"
)]
pub fn compiled_in<T>(file: &str, result: Result<T, CatalogError>) -> T {
    match result {
        Ok(read) => read,
        Err(err) => panic!("{file}: {err}"),
    }
}

/// What a line of a catalog is.
enum Line<'a> {
    /// A comment or a blank line outside an item.
    Blank,
    /// A line before the first array that is not a comment: a `key = value`
    /// line, a value's continuation, or a table (`[meta]`) and its lines.
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
    if let Some(error) = multi_line_string(text) {
        return Err(error);
    }
    // The top-level array the last header opened, if any.
    let mut array: Option<&str> = None;
    // The preamble's tables (`meta` of `[meta]`): no array may share a name
    // with one, which `toml` refuses in the whole file.
    let mut tables: Vec<&str> = Vec::new();
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
            // Before the first array: comments, blank lines and the preamble
            // (its values may span lines; `preamble` parses them).
            let kind = if rest.is_empty() || rest.starts_with('#') {
                Line::Blank
            } else {
                looks_like_toml(line, at)?;
                Line::Preamble
            };
            each(line, at, kind)?;
            continue;
        }
        let Some(header) = Header::of(trimmed) else {
            return refuse("not a header of the form the sync scripts write");
        };
        let kind = match header {
            // A table before the first array (`[meta]`, `[profile.x]`) is
            // part of the preamble.
            Header {
                array: false, top, ..
            } if array.is_none() => {
                tables.push(top);
                Line::Preamble
            }
            Header {
                array: true,
                top,
                sub: None,
            } => {
                if tables.contains(&top) {
                    return refuse("an array named like a table of the preamble");
                }
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

/// Refuses a line that is not parsed where it is read (the preamble, another
/// array's item) unless it at least looks like TOML: `key = value`, a
/// value's continuation (indented and starting like a value, or the closing
/// `]` or `}`), a comment or nothing.
fn looks_like_toml(line: &str, at: usize) -> Result<(), CatalogError> {
    let rest = line.trim();
    let continued = line.starts_with([' ', '\t'])
        && (rest.starts_with(['"', '\'', '[', '{', '+', '-'])
            || rest.starts_with(|c: char| c.is_ascii_digit())
            || rest.starts_with("true")
            || rest.starts_with("false"));
    if rest.is_empty()
        || rest.starts_with('#')
        || rest.contains('=')
        || rest.starts_with([']', '}'])
        || continued
    {
        return Ok(());
    }
    Err(CatalogError {
        line: at,
        why: format!("not a `key = value` line: {rest:?}"),
    })
}

/// Where `text` has a `"""` or `'''` that could start a multi-line string:
/// not in a comment, and not inside a `"..."` or `'...'` string on its line
/// (the scripts write strings with JSON escaping, so `'''` may be in one).
/// One search over the whole text, not a check per line.
fn multi_line_string(text: &str) -> Option<CatalogError> {
    for marker in ["\"\"\"", "'''"] {
        for found in memchr::memmem::find_iter(text.as_bytes(), marker) {
            // The marker is ASCII, so it starts on a char boundary.
            let Some((before, from)) = text.split_at_checked(found) else {
                debug_assert!(false, "{found} in {} bytes", text.len());
                return Some(CatalogError {
                    line: 0,
                    why: format!("a {marker} at byte {found} could not be read"),
                });
            };
            let line_before = before.rsplit_once('\n').map_or(before, |(_, line)| line);
            if in_string_or_comment(line_before) {
                continue;
            }
            let shown = format!("{line_before}{}", from.lines().next().unwrap_or_default());
            return Some(CatalogError {
                line: before.matches('\n').count() + 1,
                why: format!("a multi-line string: {shown:?}"),
            });
        }
    }
    None
}

/// Whether the end of `before`, the start of a line, is inside a basic or
/// literal string, or a comment.
fn in_string_or_comment(before: &str) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum At {
        Code,
        Basic,
        Escaped,
        Literal,
    }
    let mut at = At::Code;
    for byte in before.bytes() {
        at = match (at, byte) {
            (At::Code, b'#') => return true,
            (At::Code, b'"') | (At::Escaped, _) => At::Basic,
            (At::Code, b'\'') => At::Literal,
            (At::Basic, b'\\') => At::Escaped,
            (At::Basic, b'"') | (At::Literal, b'\'') => At::Code,
            (state, _) => state,
        };
    }
    at != At::Code
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

    /// A CRLF catalog's preamble reads as the same text with LF: the line
    /// before the first `[[` keeps its whole line ending, never a bare `\r`.
    #[test]
    fn a_crlf_preamble_reads_as_lf() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Preamble {
            classes: Vec<String>,
            name: String,
        }
        let lf = "# c\nclasses = [\"é\", \"😀\"]\nname = \"x\"\n[[t]]\nk = 1\n";
        let crlf = lf.replace('\n', "\r\n");
        let from_lf: Preamble = preamble(lf).unwrap();
        let from_crlf: Preamble = preamble(&crlf).unwrap();
        assert_eq!(from_crlf, from_lf);
        assert_eq!(from_lf.classes, ["é", "😀"]);
        assert_eq!(from_lf.name, "x");
    }

    /// The preamble may hold values over several lines and tables before
    /// the first array; a `'''` inside a `"..."` string or a comment is no
    /// multi-line string.
    #[test]
    fn a_preamble_with_tables_and_long_values_reads_as_the_whole_file() {
        let text = "# a `\"\"\"` in a comment\ntypes = [\n    \"a\", \"b\",\n    \"c\",\n]\n\
                    [meta]\nfetched = \"x\"\n[profile.one]\nk = 1\n\n[[t]]\n\
                    doc = \"and=''') ok\"\n[[t]]\ndoc = \"b\"\n";
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Whole {
            types: Vec<String>,
            meta: toml::Value,
            profile: toml::Value,
            t: Vec<toml::Value>,
        }
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Preamble {
            types: Vec<String>,
            meta: toml::Value,
            profile: toml::Value,
        }
        let whole: Whole = toml::from_str(text).unwrap();
        let first: Preamble = preamble(text).unwrap();
        let t: Vec<toml::Value> = array_items(text, "t").unwrap();
        assert_eq!(
            (first.types, first.meta, first.profile, t),
            (whole.types, whole.meta, whole.profile, whole.t)
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
            (
                "[[t]]\nname = \"a\"\n[x]\nk = 1\n",
                "top-level table after an array",
            ),
            (
                "[[t]]\ndoc = '''x'''\n",
                "a literal multi-line string on one line",
            ),
            (
                "[[t]]\nk = '\"'\nv = '''\nx\n'''\n",
                "a marker after a literal string holding a quote",
            ),
            (
                "garbage\n[[t]]\nk = 1\n",
                "a preamble line that is not TOML",
            ),
            (
                "[[u]]\n  stray words\n[[t]]\nk = 1\n",
                "an indented stray line",
            ),
            ("[[t]]\nname = \n", "an item that does not parse"),
        ] {
            assert!(array_items::<toml::Value>(text, "t").is_err(), "{why}");
        }
        let error =
            array_items::<toml::Value>("[[t]]\nname = \"a\"\n[[t]] # c\n", "t").unwrap_err();
        assert_eq!(error.line, 3);
        // A marker in a comment after a value is no multi-line string.
        let commented: Vec<toml::Value> = array_items("[[t]]\ndoc = \"a\" # '''\n", "t").unwrap();
        assert_eq!(commented.len(), 1);
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

    /// Multi-byte text before a multi-line string, in the preamble and in
    /// an item that does not parse is read whole, and lines are counted
    /// across it.
    #[test]
    fn multi_byte_text_is_read_whole() {
        let error = array_items::<toml::Value>("[[t]]\nname = \"é😀\"\ndocs = 'é' + '''\n", "t")
            .unwrap_err();
        assert_eq!(error.line, 3, "{error}");
        assert!(error.why.contains("docs = 'é' + '''"), "{error}");
        // A marker inside a string that holds multi-byte text is no
        // multi-line string.
        let quoted: Vec<toml::Value> = array_items("[[t]]\nk = \"😀 ''' é\"\n", "t").unwrap();
        assert_eq!(quoted.len(), 1);
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct Preamble {
            classes: Vec<String>,
        }
        let first: Preamble = preamble("classes = [\"é\", \"😀\"]\n[[t]]\nk = \"é\"\n").unwrap();
        assert_eq!(first.classes, ["é", "😀"]);
        let mut text = String::new();
        for i in 0..20 {
            text.push_str(&format!("[[t]]\nname = \"é{i}😀\"\n"));
        }
        let bad_at = text.lines().count() + 1;
        text.push_str("[[t]]\nname = \"é😀\"\nbroken = é\n");
        let error = array_items::<toml::Value>(&text, "t").unwrap_err();
        assert_eq!(error.line, bad_at + 2, "{error}");
    }
}
