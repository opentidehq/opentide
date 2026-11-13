//! HarfangLab's YARA forms (harfanglab-1.0 1.2 and 1.3, yara-1.0), ported
//! from `platforms/harfanglab/yara.py`: the codes a scan of a block decides
//! without a YARA parser, the rule name deploy derives from the Tide rule
//! `name`, and the texts deploy sends.
//!
//! | Oracle | Here |
//! |--------|------|
//! | `YARA_MODULES`, `YARA_KEYWORDS` | [`YARA_MODULES`], [`YARA_KEYWORDS`] (`opentide-tide` tests them against the YARA catalog) |
//! | `_blank` | [`blank`] |
//! | `rule_headers` | [`rule_headers`] |
//! | `signature_codes` | [`signature_codes`] |
//! | `derived_rule_name`, `rule_name_problem` | [`derived_rule_name`], [`rule_name_problem`] |
//! | `context_accepted`, `decomposed_context` | [`context_accepted`], [`decomposed_context`] |
//! | `deployed_signature` | [`deployed_signature`] |
//! | `block_codes` | [`block_codes`], the named check `harfanglab_rule_shape` |

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::node::{Node, Value};

/// The modules the YARA language knows (yara-1.0, Modules).
pub const YARA_MODULES: &[&str] = &[
    "console", "cuckoo", "dex", "dotnet", "elf", "hash", "lnk", "macho", "magic", "math", "pe",
    "string", "time",
];

/// libyara 4.5's reserved words: none of them can name a rule.
pub const YARA_KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "icontains",
    "iendswith",
    "iequals",
    "import",
    "in",
    "include",
    "int16",
    "int16be",
    "int32",
    "int32be",
    "int8",
    "int8be",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "uint16",
    "uint16be",
    "uint32",
    "uint32be",
    "uint8",
    "uint8be",
    "wide",
    "xor",
];

/// The scan contexts a HarfangLab meta `context` joins with commas, without
/// blanks (harfanglab-1.0 1.3, YARA profile).
pub const HARFANGLAB_CONTEXTS: &[&str] = &["file", "file.elf", "file.macho", "file.pe", "memory"];

/// The `context` deploy writes for `file` in the decomposed form, by
/// `meta.os` (the deployer's `OS_TO_FILE_CONTEXT`).
pub const OS_FILE_CONTEXT: &[(&str, &str)] = &[
    ("Windows", "file.pe"),
    ("MacOS", "file.macho"),
    ("Linux", "file.elf"),
];

/// libyara's longest identifier (yara-1.0 1.1, Dialect).
pub const MAX_IDENTIFIER: usize = 128;

/// The decomposed form's keys; a `yara` object with `signature` sets none of
/// them.
pub const DECOMPOSED_KEYS: &[&str] = &["meta", "strings", "condition", "imports"];

/// The codes the named check `harfanglab_rule_shape` reports.
pub mod codes {
    /// `sigma` and `yara` in one block.
    pub const RULE_KIND: &str = "harfanglab_rule_kind";
    /// `signature` beside a decomposed key.
    pub const YARA_FORM: &str = "harfanglab_yara_form";
    /// A decomposed body that writes a header deploy writes.
    pub const SECTION_HEADER: &str = "harfanglab_yara_section_header";
    /// A decomposed import YARA does not know.
    pub const IMPORT: &str = "harfanglab_yara_import";
    /// The rule name deploy derives from `name` is one libyara refuses.
    pub const RULE_NAME: &str = "harfanglab_yara_rule_name";
    /// An `include` directive, which no platform resolves.
    pub const INCLUDE: &str = "yara_include";
    /// A signature with no rule to deploy.
    pub const EMPTY_SIGNATURE: &str = "yara_empty_signature";
    /// Two rules of a signature with one name.
    pub const DUPLICATE_RULE: &str = "yara_duplicate_rule";
}

/// Whether the character before `at` in `text` lets a keyword start there:
/// the oracle's `(?<![\w$#@!])`.
fn starts_word(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '$' | '#' | '@' | '!')))
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| {
        #[expect(
            clippy::expect_used,
            reason = "a pattern compiled in: a bad one fails every test, never a user's document"
        )]
        Regex::new(pattern).expect("pattern")
    })
}

fn section_header_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"(?m)^\s*(?:strings\s*:|condition\s*:|(?:(?:private|global)\s+)*rule\s+[A-Za-z_])",
    )
}

fn include_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r#"include\s*""#)
}

fn rule_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(
        &CELL,
        r"((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
}

/// `text` with comments and the insides of string and regexp literals turned
/// into spaces, as libyara's lexer reads them (`_blank`). Offsets and line
/// breaks are kept; the quotes of a string and the slashes of a regexp stay.
#[must_use]
pub fn blank(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let size = bytes.len();
    let mut index = 0;
    let space = |out: &mut Vec<u8>, from: usize, to: usize, keep_breaks: bool| {
        for byte in &mut out[from..to] {
            if !(keep_breaks && *byte == b'\n') {
                *byte = b' ';
            }
        }
    };
    while index < size {
        let byte = bytes[index];
        let rest = &bytes[index..];
        if byte == b'/' && !rest.starts_with(b"//") && !rest.starts_with(b"/*") {
            let mut end = index + 1;
            while end < size && bytes[end] != b'/' && bytes[end] != b'\n' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            let end = boundary(text, end.min(size));
            space(&mut out, index + 1, end, false);
            index = end + 1;
        } else if rest.starts_with(b"//") {
            let end = text[index..].find('\n').map_or(size, |n| index + n);
            space(&mut out, index, end, false);
            index = end;
        } else if rest.starts_with(b"/*") {
            let end = text[index + 2..]
                .find("*/")
                .map_or(size, |n| index + 2 + n + 2);
            space(&mut out, index, end, true);
            index = end;
        } else if byte == b'"' {
            let mut end = index + 1;
            while end < size && bytes[end] != b'"' && bytes[end] != b'\n' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            let end = boundary(text, end.min(size));
            space(&mut out, index + 1, end, false);
            index = end + 1;
        } else {
            index += 1;
        }
    }
    // Every byte replaced is a whole character's (a space for each of its
    // bytes), so the text stays UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// The first character boundary of `text` at or after `at`: a `\\` before a
/// multi-byte character skips one byte of it.
fn boundary(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// One `rule` of a signature: its name, modifiers and where its text runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraRuleHeader {
    /// The rule's name.
    pub name: String,
    /// `private rule`.
    pub private: bool,
    /// `global rule`.
    pub global: bool,
    /// Where the rule's header starts.
    pub start: usize,
    /// Where its text ends: the next rule's header, or the end.
    pub end: usize,
}

/// Each rule a signature declares, in order, with the span of its text.
#[must_use]
pub fn rule_headers(signature: &str) -> Vec<YaraRuleHeader> {
    let code = blank(signature);
    let found: Vec<_> = rule_pattern()
        .captures_iter(&code)
        .filter(|captures| {
            captures
                .get(0)
                .is_some_and(|m| starts_word(&code, m.start()))
        })
        .collect();
    let mut headers = Vec::with_capacity(found.len());
    for (index, captures) in found.iter().enumerate() {
        let (Some(whole), Some(modifiers), Some(name)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            continue;
        };
        let modifiers: Vec<&str> = modifiers.as_str().split_whitespace().collect();
        let end = found
            .get(index + 1)
            .and_then(|next| next.get(0))
            .map_or(signature.len(), |next| next.start());
        headers.push(YaraRuleHeader {
            name: name.as_str().to_owned(),
            private: modifiers.contains(&"private"),
            global: modifiers.contains(&"global"),
            start: whole.start(),
            end,
        });
    }
    headers
}

/// The yara-1.0 error codes a scan of `signature` decides: `None` is a
/// signature that is not a string, or blank.
#[must_use]
pub fn signature_codes(signature: Option<&str>) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    let Some(signature) = signature.filter(|text| !text.trim().is_empty()) else {
        found.insert(codes::EMPTY_SIGNATURE);
        return found;
    };
    let code = blank(signature);
    if include_pattern()
        .find_iter(&code)
        .any(|m| starts_word(&code, m.start()))
    {
        found.insert(codes::INCLUDE);
    }
    let headers = rule_headers(signature);
    if !headers
        .iter()
        .any(|header| !(header.private || header.global))
    {
        found.insert(codes::EMPTY_SIGNATURE);
    }
    let names: BTreeSet<&str> = headers.iter().map(|header| header.name.as_str()).collect();
    if names.len() != headers.len() {
        found.insert(codes::DUPLICATE_RULE);
    }
    found
}

/// The YARA rule name deploy derives from the Tide rule `name` (decomposed
/// form): lowercased, spaces and `-` as `_`, any other character that is not
/// alphanumeric as `_`, and `rule_` before a leading digit. Python's
/// `str.isalnum` keeps non-ASCII letters, which libyara refuses
/// ([`rule_name_problem`]).
#[must_use]
pub fn derived_rule_name(name: &str) -> String {
    let lowered = name.to_lowercase().replace([' ', '-'], "_");
    let mut derived: String = lowered
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if derived.chars().next().is_some_and(char::is_numeric) {
        derived.insert_str(0, "rule_");
    }
    derived
}

/// Why libyara refuses the rule name deploy derives from `name`, or `None`:
/// a keyword, a character other than ASCII letters, digits and `_`, or more
/// than 128 characters (`harfanglab_yara_rule_name`, harfanglab-1.0 1.3).
#[must_use]
pub fn rule_name_problem(name: &str) -> Option<String> {
    let derived = derived_rule_name(name);
    if YARA_KEYWORDS.contains(&derived.as_str()) {
        return Some(format!(
            "the YARA rule name {} derived from it is a YARA keyword",
            python_repr(&derived)
        ));
    }
    let ascii = |c: char| c.is_ascii_alphanumeric() || c == '_';
    if derived.is_empty() || !derived.chars().all(ascii) {
        let others: BTreeSet<char> = derived.chars().filter(|c| !ascii(*c)).collect();
        let shown = if others.is_empty() {
            "none".to_owned()
        } else {
            others
                .iter()
                .map(|c| python_repr(&c.to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Some(format!(
            "the YARA rule name {} derived from it keeps {shown}; libyara takes only ASCII \
             letters, digits and _",
            python_repr(&derived)
        ));
    }
    let length = derived.chars().count();
    if length > MAX_IDENTIFIER {
        return Some(format!(
            "the YARA rule name derived from it is {length} characters long; libyara takes at \
             most {MAX_IDENTIFIER}"
        ));
    }
    None
}

/// A string as Python's `repr` writes it: in single quotes, unless it holds
/// one and no double quote.
#[must_use]
pub fn python_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Whether `value` is a comma-joined list, without blanks, of HarfangLab scan
/// contexts.
#[must_use]
pub fn context_accepted(value: &str) -> bool {
    value
        .split(',')
        .all(|part| HARFANGLAB_CONTEXTS.contains(&part))
}

/// The meta `context` the decomposed form deploys: `file` rewritten from `os`.
#[must_use]
pub fn decomposed_context(contexts: &[String], os: &str) -> String {
    let file = OS_FILE_CONTEXT
        .iter()
        .find(|(name, _)| *name == os)
        .map(|(_, file)| *file);
    contexts
        .iter()
        .map(|context| match file {
            Some(file) if context == "file" => file,
            _ => context.as_str(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// `signature` as deploy sends it: `\n` line endings, and a trailing newline
/// if it has none. yara-1.0 allows nothing else: blank lines, at the end or
/// anywhere, are sent as written.
#[must_use]
pub fn deployed_signature(signature: &str) -> String {
    let text = signature.replace("\r\n", "\n").replace('\r', "\n");
    if text.ends_with('\n') {
        text
    } else {
        text + "\n"
    }
}

/// The value at `key` of a mapping, `None` when the key is absent or the
/// node is no mapping. A key written with a `null` value is present.
fn entry<'n>(node: &'n Node, key: &str) -> Option<&'n Node> {
    match &node.value {
        Value::Map(_) => node.get(key).map(AsRef::as_ref),
        _ => None,
    }
}

/// Whether `key` holds a value that is not `null` (the oracle's `_set`).
fn set(node: &Node, key: &str) -> bool {
    entry(node, key).is_some_and(|value| !matches!(value.value, Value::Null))
}

/// The constraint and YARA codes a raw `configurations.harfanglab` mapping
/// breaks (`block_codes`): the named check `harfanglab_rule_shape`.
/// `harfanglab_yara_rule_name` needs the Tide rule `name` and is the rule's
/// check ([`rule_name_problem`]); `yara_signature_alias` needs the YAML node
/// graph and is `opentide validate`'s.
#[must_use]
pub fn block_codes(block: &Node) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    if !matches!(block.value, Value::Map(_)) {
        return found;
    }
    if set(block, "sigma") && set(block, "yara") {
        found.insert(codes::RULE_KIND);
    }
    let Some(yara) = entry(block, "yara").filter(|yara| matches!(yara.value, Value::Map(_))) else {
        return found;
    };
    // A key written in the block chooses its form, even with an empty value:
    // `signature` with `imports: null` is still both forms.
    if let Some(signature) = entry(yara, "signature") {
        if DECOMPOSED_KEYS.iter().any(|key| entry(yara, key).is_some()) {
            found.insert(codes::YARA_FORM);
        }
        found.extend(signature_codes(signature.value.as_str()));
        return found;
    }
    for key in ["strings", "condition"] {
        if let Some(body) = entry(yara, key).and_then(|body| body.value.as_str())
            && section_header_pattern().is_match(body)
        {
            found.insert(codes::SECTION_HEADER);
        }
    }
    if let Some(Value::Seq(imports)) = entry(yara, "imports").map(|imports| &imports.value)
        && imports.iter().any(|module| {
            module
                .value
                .as_str()
                .is_none_or(|module| !YARA_MODULES.contains(&module))
        })
    {
        found.insert(codes::IMPORT);
    }
    found
}
