//! The verdict parser: the Exabeam Query Language as exabeam-1.0 defines it,
//! a recursive-descent parser that follows the reference checker of
//! opentidehq/specifications (`scripts/exabeam_language.py`) step for step, so
//! the two agree on every conformance query (`docs/EXABEAM.md`).
//!
//! It reports every language code of the spec, and the two catalogue codes the
//! reference checker cannot (`exabeam_unknown_field`,
//! `exabeam_string_field_number`). Its tokens are the spec's highlight table;
//! the tree-sitter grammar's highlighting is checked against them.
//!
//! Offsets are bytes into the query. Python's checker counts characters; the
//! two agree on every ASCII query, and here a range never splits a character.

use crate::catalog::{Catalog, FieldKind};
use crate::codes;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which use the query is checked for (exabeam-1.0, "Profiles").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A correlation-rule sequence query: the filter only.
    Rule,
    /// A hunt search or a `.exabeam` file: the filter and the advanced operators.
    #[default]
    Search,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Rule => "rule",
            Profile::Search => "search",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rule" => Some(Profile::Rule),
            "search" => Some(Profile::Search),
            _ => None,
        }
    }
}

/// One diagnostic, in bytes of the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub message: String,
    pub start: usize,
    pub end: usize,
}

/// One highlight token, in bytes of the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub start: usize,
    pub end: usize,
    pub capture: &'static str,
}

/// What [`check`] found.
#[derive(Debug, Clone, Default)]
pub struct Checked {
    pub findings: Vec<Finding>,
    pub tokens: Vec<Token>,
    /// The query is in the advanced form (exabeam-1.0, "Profiles").
    pub advanced: bool,
    /// The byte span of each context table lookup, in source order.
    pub context_tables: Vec<(usize, usize)>,
}

/// Every code of the language (exabeam-1.0, "Diagnostics").
pub const LANGUAGE_CODES: [&str; 34] = [
    codes::EXABEAM_PARSE_ERROR,
    codes::EXABEAM_IMPLICIT_OPERATOR,
    codes::EXABEAM_NOT_EQUAL,
    codes::EXABEAM_BARE_WILDCARD,
    codes::EXABEAM_LEADING_SLASH,
    codes::EXABEAM_FREE_TEXT_SPECIAL,
    codes::EXABEAM_UNKNOWN_FUNCTION,
    codes::EXABEAM_FUNCTION_ARITY,
    codes::EXABEAM_REGEX,
    codes::EXABEAM_RANGE,
    codes::EXABEAM_IPV6_RANGE,
    codes::EXABEAM_TIME_EXACT,
    codes::EXABEAM_CONTEXT_TABLE_OR,
    codes::EXABEAM_CONTEXT_TABLE_LIMIT,
    codes::EXABEAM_ADVANCED_IN_RULE,
    codes::EXABEAM_KEYWORD_CASE,
    codes::EXABEAM_CLAUSE_ORDER,
    codes::EXABEAM_PIPE_LIMIT,
    codes::EXABEAM_RGX_EXTRACT_LIMIT,
    codes::EXABEAM_RESERVED_ALIAS,
    codes::EXABEAM_GROUP_BY_SELECT_STAR,
    codes::EXABEAM_GROUP_BY_COLUMN,
    codes::EXABEAM_FOREACH_CLAUSE,
    codes::EXABEAM_FOREACH_REFERENCE,
    codes::EXABEAM_FOREACH_POSITION,
    codes::EXABEAM_MIXED_BOOLEAN,
    codes::EXABEAM_IMPLICIT_AND,
    codes::EXABEAM_SINGLE_GROUP,
    codes::EXABEAM_PIPE_MISUSE,
    codes::EXABEAM_WILDCARD_IN_PHRASE,
    codes::EXABEAM_UNQUOTED_VALUE,
    codes::EXABEAM_LEGACY_REGEX,
    codes::EXABEAM_UNKNOWN_FIELD,
    codes::EXABEAM_STRING_FIELD_NUMBER,
];

/// The names of the filter functions and what each takes.
fn filter_function(upper: &str) -> Option<bool> {
    // `Some(true)`: a regular expression; `Some(false)`: a wildcard pattern.
    match upper {
        "RGX" | "RGXI" => Some(true),
        "WLD" | "WLDI" => Some(false),
        _ => None,
    }
}

const AGGREGATES: [&str; 5] = ["COUNT", "MIN", "MAX", "SUM", "AVG"];
/// Time fields take a range only (exabeam-1.0, "Filter semantics").
pub const TIME_FIELDS: [&str; 4] = ["approxlogtime", "ingest_time", "time", "raw_log_time"];
pub const MAX_PIPES: usize = 5;
pub const MAX_RGX_EXTRACT: usize = 3;
pub const MAX_CONTEXT_TABLES: usize = 2;
/// Nested groups and `NOT`s deeper than this are a parse error, so a query
/// cannot exhaust the stack. The reference checker runs out of Python's
/// recursion limit near 200 levels.
const MAX_DEPTH: usize = 200;

/// The Search guide's reserved words (exabeam-1.0, "Reserved words"): none
/// of them may be an `AS` name.
pub const RESERVED: [&str; 97] = [
    "abort",
    "all",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "assert_rows_modified",
    "at",
    "between",
    "by",
    "case",
    "cast",
    "collate",
    "contains",
    "create",
    "cross",
    "cube",
    "current",
    "default",
    "define",
    "desc",
    "distinct",
    "else",
    "end",
    "enum",
    "escape",
    "except",
    "exclude",
    "exists",
    "extract",
    "false",
    "fetch",
    "following",
    "for",
    "from",
    "full",
    "group",
    "grouping",
    "groups",
    "hash",
    "having",
    "if",
    "ignore",
    "in",
    "inner",
    "intersect",
    "interval",
    "into",
    "is",
    "join",
    "lateral",
    "left",
    "like",
    "limit",
    "lookup",
    "merge",
    "natural",
    "new",
    "no",
    "not",
    "null",
    "nulls",
    "of",
    "offset",
    "on",
    "or",
    "order",
    "outer",
    "over",
    "partition",
    "preceding",
    "proto",
    "range",
    "recursive",
    "respect",
    "right",
    "rollup",
    "rows",
    "select",
    "set",
    "some",
    "struct",
    "tablesample",
    "then",
    "to",
    "treat",
    "true",
    "unbounded",
    "union",
    "unnest",
    "using",
    "when",
    "where",
    "window",
    "with",
    "within",
];

pub fn is_reserved(word: &str) -> bool {
    RESERVED.contains(&word.to_lowercase().as_str())
}

const CLAUSES: [&str; 7] = [
    "SELECT", "FROM", "WHERE", "AS", "GROUP-BY", "ORDER-BY", "LIMIT",
];
/// Every clause keyword ends a statement's filter (exabeam-1.0: `WHERE a:"b"
/// SELECT c` is `exabeam_clause_order`, not free text).
const STOP: [&str; 8] = [
    "SELECT", "FROM", "WHERE", "AS", "GROUP-BY", "ORDER-BY", "LIMIT", "FOREACH",
];
/// Filter operators: never a term (exabeam-1.0: a missing operand).
const OPERATOR_WORDS: [&str; 5] = ["AND", "OR", "NOT", "TO", "IN"];
/// Epoch milliseconds above this compare as this (the reference checker's cap).
const EPOCH_MS_CAP: i128 = 100_000_000_000_000_000_000_000_000_000_000_000_000;

struct ParseError {
    message: String,
    pos: usize,
}

type Parsed<T> = Result<T, ParseError>;

fn fail<T>(message: impl Into<String>, pos: usize) -> Parsed<T> {
    Err(ParseError {
        message: message.into(),
        pos,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Or,
    And,
    Not,
    Group,
    Term,
    Text,
    Context,
}

#[derive(Debug, Clone)]
struct Node {
    kind: Kind,
    children: Vec<Node>,
    start: usize,
    end: usize,
}

impl Node {
    fn leaf(kind: Kind, start: usize, end: usize) -> Self {
        Node {
            kind,
            children: Vec::new(),
            start,
            end,
        }
    }
}

/// What one advanced statement selects and uses, for the pipe guardrail.
#[derive(Debug, Default)]
struct Statement {
    foreach: bool,
    star: bool,
    has_select: bool,
    select: BTreeSet<String>,
    fields: BTreeSet<String>,
}

/// A word at the cursor: text, start, end.
type Word<'a> = (&'a str, usize, usize);

/// A selected column: its name (the function's for an aggregation), whether
/// it is aggregated, its span.
type Column<'a> = (&'a str, bool, usize, usize);

/// What `SELECT` lists: the span of `*` if there is one, and the columns.
type SelectList<'a> = (Option<(usize, usize)>, Vec<Column<'a>>);

/// A field name the catalogue is asked about once the whole query is read
/// (an `AS` name later in the query does not count).
struct FieldUse {
    name: String,
    start: usize,
    end: usize,
}

struct Parser<'a> {
    text: &'a str,
    profile: Profile,
    pos: usize,
    out: Checked,
    context_tables: Vec<(usize, usize)>,
    rgx_extract: usize,
    in_foreach: usize,
    depth: usize,
    fields: Vec<FieldUse>,
    aliases: Vec<(String, usize)>,
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Python's `str.isupper()` / `str.islower()` on a keyword: one case for every
/// cased character, and at least one cased character.
fn one_case(word: &str) -> bool {
    let cased: Vec<char> = word.chars().filter(|c| c.is_alphabetic()).collect();
    !cased.is_empty()
        && (cased.iter().all(|c| c.is_uppercase()) || cased.iter().all(|c| c.is_lowercase()))
}

/// `IDENT` at `at`: `[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*`.
fn ident_end(text: &str, at: usize) -> Option<usize> {
    ident_like_end(text, at, false)
}

/// `FIELD` at `at`: as `IDENT`, with `-` inside a part.
fn field_end(text: &str, at: usize) -> Option<usize> {
    ident_like_end(text, at, true)
}

fn ident_like_end(text: &str, at: usize, hyphen: bool) -> Option<usize> {
    let b = text.as_bytes();
    let part = |mut i: usize| -> Option<usize> {
        if i >= b.len() || !is_ident_start(b[i]) {
            return None;
        }
        i += 1;
        while i < b.len() && (is_ident_char(b[i]) || (hyphen && b[i] == b'-')) {
            i += 1;
        }
        Some(i)
    };
    let mut end = part(at)?;
    while end < b.len() && b[end] == b'.' {
        match part(end + 1) {
            Some(next) => end = next,
            None => break,
        }
    }
    Some(end)
}

/// `(?i)(group|order)-by\b` at `at`.
fn hyphen_word_end(text: &str, at: usize) -> Option<usize> {
    let rest = text.get(at..)?;
    for word in ["group-by", "order-by"] {
        if rest.len() >= word.len()
            && rest.as_bytes()[..word.len()].eq_ignore_ascii_case(word.as_bytes())
        {
            let after = rest[word.len()..].chars().next();
            if after.is_none_or(|c| !is_word_char(c)) {
                return Some(at + word.len());
            }
        }
    }
    None
}

/// `BARE`: a run of anything but whitespace, `()[]{},"'|=<>!`.
fn bare_end(text: &str, at: usize) -> Option<usize> {
    let mut end = at;
    for (i, c) in text[at..].char_indices() {
        if c.is_whitespace() || "()[]{},\"'|=<>!".contains(c) {
            break;
        }
        end = at + i + c.len_utf8();
    }
    (end > at).then_some(end)
}

/// `[+-]?\d+(\.\d+)?` as the whole text.
pub fn is_number(text: &str) -> bool {
    let t = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (int, frac) = match t.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (t, None),
    };
    !int.is_empty()
        && int.bytes().all(|b| b.is_ascii_digit())
        && frac.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

fn is_time_field(field: &str) -> bool {
    TIME_FIELDS.contains(&field.to_lowercase().as_str())
}

/// Ten or more digits: epoch milliseconds on a time field.
fn is_epoch_ms(text: &str) -> bool {
    text.len() >= 10 && text.bytes().all(|b| b.is_ascii_digit())
}

/// Epoch milliseconds, capped as the reference checker caps them.
fn epoch_ms(text: &str) -> i128 {
    let digits = text.trim_start_matches('0');
    if digits.len() > 38 {
        return EPOCH_MS_CAP;
    }
    digits.parse::<i128>().unwrap_or(0).min(EPOCH_MS_CAP)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), as the reference checker computes it.
fn days_from_civil(y: i128, m: i128, d: i128) -> i128 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2).div_euclid(5) + d - 1;
    let doe = yoe * 365 + yoe.div_euclid(4) - yoe.div_euclid(100) + doy;
    era * 146_097 + doe - 719_468
}

/// A `YYYY-MM-DDThh:mm:ss[.sss][Z|±hh:mm]` datetime as epoch milliseconds
/// (no zone is UTC), or `None` when `text` is not one.
fn datetime_ms(text: &str) -> Option<i128> {
    if !is_datetime(text) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| text[r].parse::<i128>().unwrap_or(0);
    let (y, mo, d, hh, mi, ss) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    );
    let mut i = 19;
    let mut millis = 0;
    if text.as_bytes().get(i) == Some(&b'.') {
        let digits: String = text[i + 1..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        i += 1 + digits.len();
        millis = format!("{digits:0<3}").parse::<i128>().unwrap_or(0);
    }
    let offset = match text.as_bytes().get(i) {
        Some(sign @ (b'+' | b'-')) => {
            let minutes = num(i + 1..i + 3) * 60 + num(i + 4..i + 6);
            if *sign == b'-' { -minutes } else { minutes }
        }
        _ => 0,
    };
    Some(((((days_from_civil(y, mo, d) * 24 + hh) * 60 + mi - offset) * 60) + ss) * 1000 + millis)
}

/// `YYYY-MM-DDThh:mm:ss[.sss][Z|±hh:mm]` as the whole text.
fn is_datetime(text: &str) -> bool {
    let b = text.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|s| s.iter().all(u8::is_ascii_digit));
    if b.len() < 19
        || !digits(0..4)
        || b[4] != b'-'
        || !digits(5..7)
        || b[7] != b'-'
        || !digits(8..10)
        || b[10] != b'T'
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
    {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start || j - start > 3 {
            return false;
        }
        i = j;
    }
    match b.get(i) {
        None => true,
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6)
        }
        _ => false,
    }
}

/// Python's `ipaddress.ip_address`: an IPv4 or IPv6 address, an IPv6 one
/// with an optional `%scope`.
pub fn parse_ip(text: &str) -> Option<IpAddr> {
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    let (addr, scope) = match text.split_once('%') {
        Some((a, s)) => (a, Some(s)),
        None => (text, None),
    };
    if scope.is_some_and(|s| s.is_empty() || s.contains('%')) {
        return None;
    }
    addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// A query string's value: `\"`, `\'`, `` \` `` and `\\` lose their
/// backslash; other escapes stay as written.
pub fn unescape(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && "\"'`\\".contains(next)
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

/// Whether `text` has `target` at a position not right after a backslash.
fn unescaped(text: &str, target: impl Fn(char) -> bool) -> bool {
    let mut previous = None;
    for c in text.chars() {
        if target(c) && previous != Some('\\') {
            return true;
        }
        previous = Some(c);
    }
    false
}

/// Why RE2 refuses `pattern`, or `None` (exabeam-1.0: RGX patterns are RE2).
/// The refusals RE2 adds to a regular-expression syntax come first, with the
/// reference checker's tests; then the `regex` crate's parser, whose syntax
/// is RE2's.
pub fn re2_refusal(pattern: &str) -> Option<String> {
    // Look-around, atomic groups and possessive quantifiers are refused by
    // `re2_rewrite`, outside character classes only: `[a?+]` and `[(?=]`
    // are sets of literals.
    let rewritten = match re2_rewrite(pattern) {
        Ok(p) => p,
        Err(why) => return Some(why),
    };
    // `re2_rewrite` holds the depth to RE2's limit; the `regex` crate's own
    // limit (250) would refuse what RE2 takes.
    match regex_syntax::ParserBuilder::new()
        .nest_limit(4 * RE2_MAX_DEPTH)
        .build()
        .parse(&rewritten)
    {
        Ok(_) => None,
        Err(err) => Some(re2_message(&err)),
    }
}

/// RE2's largest repetition count.
const RE2_MAX_REPEAT: u32 = 1000;
/// RE2's deepest nesting of groups.
const RE2_MAX_DEPTH: u32 = 1000;
/// RE2's ASCII classes, `[[:alpha:]]`.
const POSIX_CLASSES: [&str; 14] = [
    "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print", "punct",
    "space", "upper", "word", "xdigit",
];

/// `pattern` as the `regex` crate's parser reads the same RE2 syntax, or why
/// RE2 refuses it. The two syntaxes differ where RE2 is looser or stricter:
///
/// - a `{` that does not open `{n}`, `{n,}` or `{n,m}` is a literal in RE2;
/// - a backslash before any ASCII character that is not a letter, digit or
///   `_` escapes it in RE2 (`\ `, `\'`);
/// - `\Q…\E` quotes its text in RE2;
/// - RE2 refuses a repetition of a repetition (`a**`, `a{2}{3}`), a count
///   above 1000, and a flag other than `i`, `m`, `s`, `U`.
fn re2_rewrite(pattern: &str) -> Result<String, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    let mut class_depth = 0usize;
    // The last item was a repetition operator (`*`, `+`, `?`, `{n,m}`).
    let mut repeated = false;
    let mut depth = 0u32;
    let mut names: Vec<String> = Vec::new();
    let escape = |c: char, out: &mut String| out.push_str(&format!("\\x{{{:X}}}", c as u32));
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            let Some(&next) = chars.get(i + 1) else {
                return Err("trailing backslash at end of expression".into());
            };
            if next == 'Q' && class_depth > 0 {
                return Err("\\Q is not an escape inside a class".into());
            }
            if next.is_ascii_digit() {
                // RE2: `\0`, and `\1`-`\7` before another octal digit, are octal
                // (up to three digits); any other digit is a back-reference.
                let octal = |j: usize| chars.get(j).is_some_and(|c| ('0'..='7').contains(c));
                if next == '0' || (next <= '7' && octal(i + 2)) {
                    let mut j = i + 2;
                    while j < i + 4 && octal(j) {
                        j += 1;
                    }
                    let digits: String = chars[i + 1..j].iter().collect();
                    let code = u32::from_str_radix(&digits, 8).unwrap_or(0);
                    out.push_str(&format!("\\x{{{code:X}}}"));
                    i = j;
                    repeated = false;
                    continue;
                }
                return Err("back-references are not RE2".into());
            }
            if next == 'Q' {
                // `\Q…\E` (or to the end): every character is literal.
                let mut j = i + 2;
                while j < chars.len() && !(chars[j] == '\\' && chars.get(j + 1) == Some(&'E')) {
                    escape(chars[j], &mut out);
                    j += 1;
                }
                i = (j + 2).min(chars.len());
                repeated = false;
                continue;
            }
            if matches!(next, 'p' | 'P' | 'x') && chars.get(i + 2) == Some(&'{') {
                // `\p{Greek}`, `\x{263a}`: the braces belong to the escape.
                let Some(close) = (i + 3..chars.len()).find(|&j| chars[j] == '}') else {
                    return Err("missing } in an escape".into());
                };
                out.extend(&chars[i..=close]);
                i = close + 1;
                repeated = false;
                continue;
            }
            if next.is_ascii() && !next.is_ascii_alphanumeric() && next != '_' {
                escape(next, &mut out);
            } else {
                out.push(c);
                out.push(next);
            }
            i += 2;
            repeated = false;
            continue;
        }
        if class_depth > 0 {
            match c {
                '[' if chars.get(i + 1) == Some(&':') => {
                    // A POSIX class `[:alpha:]` inside a class.
                    if let Some(end) = (i + 2..chars.len().saturating_sub(1))
                        .find(|&j| chars[j] == ':' && chars[j + 1] == ']')
                    {
                        let name: String = chars[i + 2..end].iter().collect();
                        let name = name.strip_prefix('^').unwrap_or(&name);
                        if name.chars().all(|c| c.is_ascii_lowercase())
                            && !POSIX_CLASSES.contains(&name)
                        {
                            return Err(format!("[:{name}:] is not an RE2 character class"));
                        }
                        out.extend(&chars[i..end + 2]);
                        i = end + 2;
                        continue;
                    }
                    out.push_str("\\[");
                }
                // A literal in RE2; nesting or a set operation (`&&`, `~~`)
                // for the `regex` crate.
                '[' | '&' | '~' => escape(c, &mut out),
                ']' => {
                    class_depth -= 1;
                    out.push(c);
                }
                _ => out.push(c),
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                class_depth = 1;
                out.push(c);
                i += 1;
                // `[]` and `[^]` start with a literal `]`.
                if chars.get(i) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    out.push_str("\\]");
                    i += 1;
                }
                repeated = false;
                continue;
            }
            '*' | '+' | '?' => {
                if repeated {
                    if c == '+' {
                        return Err("possessive quantifiers are not RE2".into());
                    }
                    return Err(format!("bad repetition operator: {c}"));
                }
                out.push(c);
                i += 1;
                if chars.get(i) == Some(&'?') {
                    out.push('?');
                    i += 1;
                }
                repeated = true;
                continue;
            }
            '{' => {
                if let Some((end, low, high)) = repetition_at(&chars, i) {
                    if repeated {
                        return Err("bad repetition operator: {".into());
                    }
                    if low > RE2_MAX_REPEAT || high.is_some_and(|h| h > RE2_MAX_REPEAT) {
                        return Err(format!(
                            "bad repetition operator: counts are at most {RE2_MAX_REPEAT}"
                        ));
                    }
                    out.extend(&chars[i..end]);
                    i = end;
                    if chars.get(i) == Some(&'?') {
                        out.push('?');
                        i += 1;
                    }
                    repeated = true;
                    continue;
                }
                out.push_str("\\{");
            }
            // Literals in RE2 outside a class.
            ']' | '}' => escape(c, &mut out),
            '(' if chars.get(i + 1) == Some(&'?') => {
                let after: String = chars[i + 2..chars.len().min(i + 4)].iter().collect();
                if after.starts_with(['=', '!']) || after == "<=" || after == "<!" {
                    return Err("look-around is not RE2".into());
                }
                if after.starts_with('>') {
                    return Err("atomic groups are not RE2".into());
                }
                if after.starts_with('<') || after == "P<" {
                    // A named group: RE2 takes `[A-Za-z0-9_]+`, once each; the
                    // `regex` crate wants a letter or `_` first, so it gets `n_`.
                    let start = i + if after.starts_with('<') { 3 } else { 4 };
                    let close = (start..chars.len()).find(|&j| chars[j] == '>');
                    let name: String =
                        close.map_or(String::new(), |c| chars[start..c].iter().collect());
                    if name.is_empty()
                        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Err(format!("invalid capture group name `{name}`"));
                    }
                    if names.contains(&name) {
                        return Err(format!("duplicate capture group name `{name}`"));
                    }
                    out.push_str(&format!("(?P<n_{name}>"));
                    names.push(name);
                    depth += 1;
                    if depth > RE2_MAX_DEPTH {
                        return Err(format!("nesting deeper than {RE2_MAX_DEPTH}"));
                    }
                    i = close.map_or(chars.len(), |c| c + 1);
                    repeated = false;
                    continue;
                }
                // Flags: `(?i)`, `(?i-s:`; names and groups pass through.
                let mut j = i + 2;
                while j < chars.len() && (chars[j].is_ascii_alphabetic() || chars[j] == '-') {
                    j += 1;
                }
                if j > i + 2
                    && matches!(chars.get(j), Some(':' | ')'))
                    && chars[i + 2] != 'P'
                    && let Some(bad) = chars[i + 2..j]
                        .iter()
                        .find(|f| !matches!(f, 'i' | 'm' | 's' | 'U' | '-'))
                {
                    return Err(format!("invalid named capture or flag: {bad}"));
                }
                if chars.get(j) == Some(&')') {
                    // `(?i)`: flags from here on, not a group.
                    out.extend(&chars[i..=j]);
                    i = j + 1;
                    repeated = false;
                    continue;
                }
                depth += 1;
                if depth > RE2_MAX_DEPTH {
                    return Err(format!("nesting deeper than {RE2_MAX_DEPTH}"));
                }
                out.push(c);
            }
            '(' => {
                depth += 1;
                if depth > RE2_MAX_DEPTH {
                    return Err(format!("nesting deeper than {RE2_MAX_DEPTH}"));
                }
                out.push(c);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                out.push(c);
            }
            _ => out.push(c),
        }
        repeated = false;
        i += 1;
    }
    Ok(out)
}

/// `{n}`, `{n,}` or `{n,m}` at `at`: the index after `}` and the counts.
fn repetition_at(chars: &[char], at: usize) -> Option<(usize, u32, Option<u32>)> {
    let mut i = at + 1;
    let digits = |i: &mut usize| -> Option<u32> {
        let start = *i;
        while *i < chars.len() && chars[*i].is_ascii_digit() {
            *i += 1;
        }
        (*i > start).then(|| {
            chars[start..*i]
                .iter()
                .collect::<String>()
                .parse()
                .unwrap_or(u32::MAX)
        })
    };
    let low = digits(&mut i)?;
    let high = match chars.get(i)? {
        '}' => Some(low),
        ',' => {
            i += 1;
            if chars.get(i) == Some(&'}') {
                None
            } else {
                Some(digits(&mut i)?)
            }
        }
        _ => return None,
    };
    if chars.get(i) != Some(&'}') {
        return None;
    }
    Some((i + 1, low, high))
}

/// The parser's error on one line: its kind, without the pattern it repeats.
fn re2_message(err: &regex_syntax::Error) -> String {
    match err {
        regex_syntax::Error::Parse(e) => e.kind().to_string(),
        regex_syntax::Error::Translate(e) => e.kind().to_string(),
        other => other.to_string(),
    }
}

/// The Exabeam form of a function other SIEMs have (exabeam-1.0: "The engine
/// names the Exabeam form in the diagnostic").
fn foreign_hint(upper: &str) -> Option<&'static str> {
    Some(match upper {
        "CONTAINS" => "Exabeam writes contains as WLD(\"*x*\")",
        "STARTSWITH" | "SW" => "Exabeam writes startswith as RGX(\"^x\")",
        "ENDSWITH" | "EW" => "Exabeam writes endswith as RGX(\"x$\")",
        "CIDR" => "Exabeam writes a CIDR block as field:[a.b.c.d/n]",
        "EXISTS" => "Exabeam writes exists as NOT field:null",
        "WC" | "LIKE" | "MATCH" => "Exabeam writes a wildcard match as WLD(\"…\")",
        "REGEX" => "Exabeam writes a regular expression as RGX(\"…\")",
        "IN" => "Exabeam writes a list as field:(\"a\", \"b\")",
        _ => return None,
    })
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, profile: Profile) -> Self {
        Parser {
            text,
            profile,
            pos: 0,
            out: Checked::default(),
            context_tables: Vec::new(),
            rgx_extract: 0,
            in_foreach: 0,
            depth: 0,
            fields: Vec::new(),
            aliases: Vec::new(),
        }
    }

    // -- low level ------------------------------------------------------------

    /// The end of a range that starts at `start`: at least one character.
    fn at_least_one(&self, start: usize, end: usize) -> usize {
        if end > start {
            return end;
        }
        let next = self.text[start.min(self.text.len())..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        start + next
    }

    fn diag(&mut self, code: &'static str, message: impl Into<String>, start: usize, end: usize) {
        let end = self.at_least_one(start, end);
        self.out.findings.push(Finding {
            code,
            message: message.into(),
            start,
            end,
        });
    }

    fn tok(&mut self, start: usize, end: usize, capture: &'static str) {
        self.out.tokens.push(Token {
            start,
            end,
            capture,
        });
    }

    fn rest(&self) -> &'a str {
        &self.text[self.pos.min(self.text.len())..]
    }

    fn ws(&mut self) {
        let rest = self.rest();
        let trimmed = rest.trim_start_matches(char::is_whitespace);
        self.pos += rest.len() - trimmed.len();
    }

    fn peek(&mut self) -> Option<char> {
        self.ws();
        self.rest().chars().next()
    }

    fn at_end(&mut self) -> bool {
        self.ws();
        self.pos >= self.text.len()
    }

    fn char_at(&self, at: usize) -> Option<char> {
        self.text.get(at..).and_then(|s| s.chars().next())
    }

    /// The identifier-like word at the cursor (`GROUP-BY` and `ORDER-BY` are
    /// one word).
    fn word_at(&mut self) -> Option<Word<'a>> {
        self.ws();
        let end =
            hyphen_word_end(self.text, self.pos).or_else(|| ident_end(self.text, self.pos))?;
        Some((&self.text[self.pos..end], self.pos, end))
    }

    /// A field name at the cursor, `-` included (`c-uri`); GROUP-BY and
    /// ORDER-BY stay keywords.
    fn column_at(&mut self) -> Option<Word<'a>> {
        self.ws();
        if hyphen_word_end(self.text, self.pos).is_some() {
            return None;
        }
        let end = field_end(self.text, self.pos)?;
        Some((&self.text[self.pos..end], self.pos, end))
    }

    fn keyword_at(&mut self, words: &[&str]) -> Option<Word<'a>> {
        let w = self.word_at()?;
        if !words.contains(&w.0.to_uppercase().as_str()) {
            return None;
        }
        match self.char_at(w.2) {
            Some(c) if c.is_alphanumeric() || c == '_' || c == '.' => None,
            _ => Some(w),
        }
    }

    fn take_keyword(&mut self, words: &[&str], clause: bool) -> Option<Word<'a>> {
        let w = self.keyword_at(words)?;
        if clause && !one_case(w.0) {
            self.diag(
                codes::EXABEAM_KEYWORD_CASE,
                format!("`{}`: clause keywords are all upper or all lower case", w.0),
                w.1,
                w.2,
            );
        }
        self.tok(w.1, w.2, "keyword");
        self.pos = w.2;
        Some(w)
    }

    fn expect(&mut self, ch: char, capture: &'static str) -> Parsed<usize> {
        self.ws();
        if !self.rest().starts_with(ch) {
            return fail(format!("expected `{ch}`"), self.pos);
        }
        let start = self.pos;
        self.tok(start, start + ch.len_utf8(), capture);
        self.pos += ch.len_utf8();
        Ok(start)
    }

    /// A quoted string at the cursor: its raw body (escapes kept), start, end.
    fn string(&mut self) -> Parsed<(&'a str, usize, usize)> {
        self.ws();
        let start = self.pos;
        let quote = self.rest().chars().next().unwrap_or('"');
        let mut chars = self.text[start + 1..].char_indices();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                chars.next();
                continue;
            }
            if c == quote {
                let end = start + 1 + i + 1;
                self.pos = end;
                self.tok(start, end, "string");
                return Ok((&self.text[start + 1..end - 1], start, end));
            }
        }
        fail("unterminated string", start)
    }

    fn note_field(&mut self, name: &str, start: usize, end: usize) {
        self.fields.push(FieldUse {
            name: name.to_string(),
            start,
            end,
        });
    }

    // -- entry ----------------------------------------------------------------

    fn parse(mut self) -> Checked {
        if let Err(err) = self.top() {
            // One character from the error, never part of one (`diag`).
            self.diag(codes::EXABEAM_PARSE_ERROR, err.message, err.pos, err.pos);
        }
        self.check_context_tables();
        self.out.context_tables = self.context_tables.clone();
        self.check_fields();
        self.out.tokens.sort_by_key(|t| (t.start, t.end));
        self.out
    }

    fn top(&mut self) -> Parsed<()> {
        if self.at_end() {
            if self.profile == Profile::Search {
                return Ok(()); // an empty search queries every log
            }
            return fail("a sequence query cannot be empty", 0);
        }
        if self.rest().starts_with('/') {
            let start = self.pos;
            self.diag(
                codes::EXABEAM_LEADING_SLASH,
                "a query cannot start with `/`",
                start,
                start + 1,
            );
            self.fields.clear();
            return Ok(());
        }
        if self.looks_advanced() {
            self.out.advanced = true;
            if self.profile == Profile::Rule {
                let start = self.word_at().map_or(self.pos, |w| w.1);
                self.diag(
                    codes::EXABEAM_ADVANCED_IN_RULE,
                    "a correlation rule sequence query is a filter: SELECT, WHERE, pipes, and the other advanced operators are Search only",
                    start,
                    self.text.len(),
                );
                return Ok(());
            }
            self.advanced()?;
        } else {
            let tree = self.filter(&[])?;
            self.check_tree(&tree, false);
        }
        if !self.at_end() {
            let c = self.rest().chars().next().unwrap_or(' ');
            return fail(format!("unexpected `{c}`"), self.pos);
        }
        Ok(())
    }

    /// The advanced form: it opens with SELECT, WHERE, FROM, or FOREACH, or
    /// has a pipe, a GROUP-BY, an ORDER-BY, a statement `AS name`, or a
    /// trailing `LIMIT <n>` outside strings and brackets, each a whole word.
    fn looks_advanced(&mut self) -> bool {
        if self
            .keyword_at(&["SELECT", "WHERE", "FROM", "FOREACH"])
            .is_some()
        {
            return true;
        }
        let text = self.text;
        let mut depth: i64 = 0;
        let mut previous: Option<char> = None;
        let mut chars = text.char_indices();
        while let Some((i, ch)) = chars.next() {
            if ch == '"' || ch == '\'' {
                // Skip the string; a backslash skips the next character.
                let mut last = ch;
                while let Some((_, c)) = chars.next() {
                    last = c;
                    if c == '\\' {
                        if let Some((_, escaped)) = chars.next() {
                            last = escaped;
                        }
                        continue;
                    }
                    if c == ch {
                        break;
                    }
                }
                previous = Some(last);
                continue;
            }
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                '|' if depth == 0 => return true,
                _ if depth == 0
                    && previous.is_none_or(|p| {
                        !(p.is_alphanumeric() || p == '_' || p == '.' || p == '-')
                    })
                    && (hyphen_word_end(text, i).is_some()
                        || trailing_limit(&text[i..])
                        || (i > 0 && statement_alias(&text[i..]))) =>
                {
                    return true;
                }
                _ => {}
            }
            previous = Some(ch);
        }
        false
    }

    // -- filter ---------------------------------------------------------------

    fn filter(&mut self, stop: &[&str]) -> Parsed<Node> {
        self.or_expr(stop)
    }

    fn at_stop(&mut self, stop: &[&str]) -> bool {
        if self.at_end() {
            return true;
        }
        if matches!(self.peek(), Some(')' | ']' | '|')) {
            return true;
        }
        !stop.is_empty() && self.keyword_at(stop).is_some()
    }

    fn or_expr(&mut self, stop: &[&str]) -> Parsed<Node> {
        let start = self.pos;
        let mut branches = vec![self.and_expr(stop)?];
        while self.take_keyword(&["OR"], false).is_some() {
            branches.push(self.and_expr(stop)?);
        }
        if branches.len() == 1 {
            return Ok(branches.pop().expect("one branch"));
        }
        if branches.iter().any(|b| b.kind == Kind::And) {
            self.diag(
                codes::EXABEAM_MIXED_BOOLEAN,
                "AND and OR at one level: AND binds tighter, but Exabeam does not document it; add parentheses",
                start,
                self.pos,
            );
        }
        Ok(Node {
            kind: Kind::Or,
            children: branches,
            start,
            end: self.pos,
        })
    }

    fn and_expr(&mut self, stop: &[&str]) -> Parsed<Node> {
        let start = self.pos;
        let mut items = vec![self.unary(false)?];
        loop {
            if self.take_keyword(&["AND"], false).is_some() {
                items.push(self.unary(false)?);
                continue;
            }
            if self.at_stop(stop) || self.keyword_at(&["OR"]).is_some() {
                break;
            }
            let here = self.pos;
            if self.keyword_at(&["NOT"]).is_some() {
                self.diag(
                    codes::EXABEAM_IMPLICIT_OPERATOR,
                    "NOT without AND or OR: Exabeam calls it invalid; write AND NOT or OR NOT",
                    here,
                    here + 3,
                );
                items.push(self.unary(false)?);
                continue;
            }
            let next = self.unary(false)?;
            let previous = items.last().map(|n| n.kind);
            if !(previous == Some(Kind::Text) && next.kind == Kind::Text) {
                self.diag(
                    codes::EXABEAM_IMPLICIT_AND,
                    "two terms with no operator are read as AND: write AND",
                    here,
                    next.end,
                );
            }
            items.push(next);
        }
        if items.len() == 1 {
            return Ok(items.pop().expect("one item"));
        }
        Ok(Node {
            kind: Kind::And,
            children: items,
            start,
            end: self.pos,
        })
    }

    fn deeper(&mut self) -> Parsed<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return fail(format!("nesting deeper than {MAX_DEPTH} levels"), self.pos);
        }
        Ok(())
    }

    fn unary(&mut self, negated: bool) -> Parsed<Node> {
        let start = self.pos;
        self.deeper()?;
        let node = if self.take_keyword(&["NOT"], false).is_some() {
            let inner = self.unary(true)?;
            Node {
                kind: Kind::Not,
                children: vec![inner],
                start,
                end: self.pos,
            }
        } else {
            self.primary(negated)?
        };
        self.depth -= 1;
        Ok(node)
    }

    fn primary(&mut self, negated: bool) -> Parsed<Node> {
        self.ws();
        let start = self.pos;
        if self.peek() == Some('(') {
            self.expect('(', "punctuation.bracket")?;
            let inner = self.or_expr(&[])?;
            self.expect(')', "punctuation.bracket")?;
            let single = matches!(
                inner.kind,
                Kind::Term | Kind::Text | Kind::Context | Kind::Not | Kind::Group
            );
            if single && !negated {
                self.diag(
                    codes::EXABEAM_SINGLE_GROUP,
                    "parentheses around a single expression: Exabeam's guide calls it an error; drop them",
                    start,
                    self.pos,
                );
            }
            return Ok(Node {
                kind: Kind::Group,
                children: vec![inner],
                start,
                end: self.pos,
            });
        }
        self.term()
    }

    fn term(&mut self) -> Parsed<Node> {
        self.ws();
        let start = self.pos;
        if self.at_end() {
            return fail("expected a term", self.pos);
        }
        let ch = self.rest().chars().next().unwrap_or(' ');
        if ch == '"' || ch == '\'' {
            let (body, s, e) = self.string()?;
            self.check_phrase(body, s, e);
            return Ok(Node::leaf(Kind::Text, s, e));
        }
        if ch == '*'
            && self
                .char_at(self.pos + 1)
                .is_none_or(|c| c.is_whitespace() || c == ')')
        {
            self.diag(
                codes::EXABEAM_BARE_WILDCARD,
                "`*` alone is not a query",
                self.pos,
                self.pos + 1,
            );
            self.tok(self.pos, self.pos + 1, "error");
            self.pos += 1;
            return Ok(Node::leaf(Kind::Term, start, self.pos));
        }
        if let Some(end) = field_end(self.text, self.pos) {
            let name = &self.text[self.pos..end];
            let after = self.text[end..].trim_start();
            if name.contains('-') && starts_with_operator(after) {
                return self.field_term(name, self.pos, end);
            }
            if name.contains('-')
                && starts_with_in(after)
                && after[2..].trim_start().starts_with(['"', '\''])
            {
                return self.context_term(name, self.pos, end);
            }
        }
        if let Some((name, s, e)) = self.word_at() {
            let after = self.text[e..].trim_start();
            if after.starts_with('(') {
                return self.call(name, s, e);
            }
            if starts_with_operator(after) {
                return self.field_term(name, s, e);
            }
            if starts_with_in(after) {
                return self.context_term(name, s, e);
            }
        }
        // Free text: a bare word.
        let Some(end) = bare_end(self.text, self.pos) else {
            return fail(format!("unexpected `{ch}`"), self.pos);
        };
        let word = &self.text[self.pos..end];
        if OPERATOR_WORDS
            .iter()
            .any(|op| word.eq_ignore_ascii_case(op))
        {
            return fail(
                format!("`{word}` is an operator, not a term: an operand is missing"),
                self.pos,
            );
        }
        if !word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '*' | '?'))
        {
            self.diag(
                codes::EXABEAM_FREE_TEXT_SPECIAL,
                format!("free text `{word}` has special characters: put it in double quotes"),
                self.pos,
                end,
            );
        }
        self.tok(self.pos, end, "string");
        self.pos = end;
        Ok(Node::leaf(Kind::Text, start, self.pos))
    }

    fn field_term(&mut self, name: &'a str, s: usize, e: usize) -> Parsed<Node> {
        self.tok(s, e, "property");
        self.note_field(name, s, e);
        self.pos = e;
        self.ws();
        let op_start = self.pos;
        let rest = self.rest();
        if rest.starts_with("!=") {
            self.diag(
                codes::EXABEAM_NOT_EQUAL,
                format!("there is no `!=` in a filter: write NOT {name}:value"),
                op_start,
                op_start + 2,
            );
            self.tok(op_start, op_start + 2, "error");
            self.pos += 2;
            self.value(name)?;
            return Ok(Node::leaf(Kind::Term, s, self.pos));
        }
        let mut op: &str =
            if rest.starts_with("==") || rest.starts_with("<=") || rest.starts_with(">=") {
                &rest[..2]
            } else {
                &rest[..rest.chars().next().map_or(0, char::len_utf8)]
            };
        self.tok(self.pos, self.pos + op.len(), "operator");
        self.pos += op.len();
        if op == ":" || op == "=" {
            self.ws();
            let rest = self.rest();
            if rest.starts_with("<=") || rest.starts_with(">=") {
                op = &rest[..2];
                self.tok(self.pos, self.pos + 2, "operator");
                self.pos += 2;
            } else if rest.starts_with('<') || rest.starts_with('>') {
                op = &rest[..1];
                self.tok(self.pos, self.pos + 1, "operator");
                self.pos += 1;
            }
        }
        if matches!(op, "<" | ">" | "<=" | ">=") {
            self.scalar(name, true)?;
        } else {
            self.value(name)?;
        }
        Ok(Node::leaf(Kind::Term, s, self.pos))
    }

    fn context_term(&mut self, name: &'a str, s: usize, e: usize) -> Parsed<Node> {
        self.tok(s, e, "property");
        self.note_field(name, s, e);
        self.pos = e;
        self.take_keyword(&["IN"], false);
        if !matches!(self.peek(), Some('"' | '\'')) {
            return fail("IN takes a context table name in double quotes", self.pos);
        }
        let (_, _, table_end) = self.string()?;
        self.retag_last("type");
        let mut end = table_end;
        if self.rest().starts_with('.') {
            self.tok(self.pos, self.pos + 1, "punctuation.delimiter");
            self.pos += 1;
            if !self.rest().starts_with(['"', '\'']) {
                return fail("a context table column is a quoted name", self.pos);
            }
            let (_, _, column_end) = self.string()?;
            self.retag_last("type");
            end = column_end;
        }
        self.context_tables.push((s, end));
        Ok(Node::leaf(Kind::Context, s, end))
    }

    fn retag_last(&mut self, capture: &'static str) {
        if let Some(last) = self.out.tokens.last_mut() {
            last.capture = capture;
        }
    }

    fn value(&mut self, field: &'a str) -> Parsed<()> {
        self.ws();
        match self.rest().chars().next() {
            Some('"' | '\'') => {
                let (body, s, e) = self.string()?;
                if is_time_field(field) {
                    self.diag(
                        codes::EXABEAM_TIME_EXACT,
                        format!(
                            "{field} takes a range, not an exact value: write {field}:[low TO high]"
                        ),
                        s,
                        e,
                    );
                }
                self.check_phrase(body, s, e);
                return Ok(());
            }
            Some('(') => return self.list_value(field),
            Some('[' | '{') => return self.range_value(field),
            _ => {}
        }
        if let Some((name, s, e)) = self.word_at()
            && self.text[e..].trim_start().starts_with('(')
        {
            self.call(name, s, e)?;
            return Ok(());
        }
        if is_time_field(field)
            && let Some(end) = bare_end(self.text, self.pos)
            && !self.text[self.pos..end].eq_ignore_ascii_case("null")
        {
            let start = self.pos;
            let word = &self.text[start..end];
            self.diag(
                codes::EXABEAM_TIME_EXACT,
                format!("{field} takes a range, not an exact value: write {field}:[low TO high]"),
                start,
                end,
            );
            self.tok(
                start,
                end,
                if is_number(word) {
                    "number"
                } else {
                    "constant"
                },
            );
            self.pos = end;
            return Ok(());
        }
        self.scalar(field, false)
    }

    fn scalar(&mut self, field: &'a str, comparison: bool) -> Parsed<()> {
        self.ws();
        if self.rest().starts_with(['"', '\'']) {
            let (body, s, e) = self.string()?;
            if comparison && !is_number(&unescape(body)) {
                self.diag(
                    codes::EXABEAM_PARSE_ERROR,
                    "a comparison takes a number",
                    s,
                    e,
                );
            }
            return Ok(());
        }
        let Some(end) = bare_end(self.text, self.pos) else {
            return fail("expected a value", self.pos);
        };
        let start = self.pos;
        let word = &self.text[start..end];
        self.pos = end;
        let capture = self.bare_capture(word, field, start, end, comparison)?;
        self.tok(start, end, capture);
        Ok(())
    }

    fn bare_capture(
        &mut self,
        word: &str,
        field: &str,
        s: usize,
        e: usize,
        comparison: bool,
    ) -> Parsed<&'static str> {
        if word.starts_with('@') {
            if self.in_foreach == 0 {
                self.diag(
                    codes::EXABEAM_FOREACH_REFERENCE,
                    format!("{word} refers to a FOREACH value outside FOREACH"),
                    s,
                    e,
                );
            }
            return Ok("variable");
        }
        if is_number(word) {
            if !comparison
                && Catalog::cached()
                    .field(field)
                    .is_some_and(|f| f.kind() == FieldKind::String)
            {
                self.diag(
                    codes::EXABEAM_STRING_FIELD_NUMBER,
                    format!(
                        "{field} is a string field: Exabeam matches it with a quoted value, \"{word}\""
                    ),
                    s,
                    e,
                );
            }
            return Ok("number");
        }
        if comparison {
            return fail("a comparison takes a number", s);
        }
        let lower = word.to_lowercase();
        if lower == "true" || lower == "false" {
            return Ok("boolean");
        }
        if lower == "null" || parse_ip(word).is_some() {
            return Ok("constant");
        }
        self.diag(
            codes::EXABEAM_UNQUOTED_VALUE,
            format!("`{word}` is not quoted: Exabeam documents string values in double quotes"),
            s,
            e,
        );
        Ok("string")
    }

    fn list_value(&mut self, field: &'a str) -> Parsed<()> {
        self.expect('(', "punctuation.bracket")?;
        loop {
            self.ws();
            if self.rest().starts_with(['"', '\'']) {
                let (body, s, e) = self.string()?;
                self.check_phrase(body, s, e);
            } else {
                self.scalar(field, false)?;
            }
            if self.peek() == Some(',') {
                self.expect(',', "punctuation.delimiter")?;
                continue;
            }
            break;
        }
        self.expect(')', "punctuation.bracket")?;
        Ok(())
    }

    fn range_value(&mut self, field: &str) -> Parsed<()> {
        self.ws();
        let open = self.rest().chars().next().unwrap_or('[');
        let start = self.pos;
        self.expect(open, "punctuation.bracket")?;
        if open == '['
            && let Some((net_start, net_end)) = cidr_at(self.text, self.pos)
        {
            self.tok(net_start, net_end, "constant");
            let net = &self.text[net_start..net_end];
            match cidr_version(net) {
                None => self.diag(
                    codes::EXABEAM_RANGE,
                    format!("`{net}` is not a CIDR network"),
                    net_start,
                    net_end,
                ),
                Some(6) => self.diag(
                    codes::EXABEAM_IPV6_RANGE,
                    "CIDR is IPv4 only in Exabeam Search",
                    net_start,
                    net_end,
                ),
                Some(_) => {}
            }
            self.pos = net_end;
            self.expect(']', "punctuation.bracket")?;
            return Ok(());
        }
        let (lo, lo_s, _) = self.bound()?;
        if self.take_keyword(&["TO"], false).is_none() {
            return fail("a range is [low TO high]", self.pos);
        }
        let (hi, _, hi_e) = self.bound()?;
        self.ws();
        let close = match self.rest().chars().next() {
            Some(c @ (']' | '}')) => c,
            _ => return fail("a range closes with ] or }", self.pos),
        };
        self.expect(close, "punctuation.bracket")?;
        if (open == '[') != (close == ']') {
            self.diag(
                codes::EXABEAM_RANGE,
                "a range opens and closes with the same kind of bracket",
                start,
                self.pos,
            );
        }
        self.check_range(&lo, &hi, lo_s, hi_e, is_time_field(field));
        Ok(())
    }

    fn bound(&mut self) -> Parsed<(String, usize, usize)> {
        self.ws();
        if self.rest().starts_with(['"', '\'']) {
            let (body, s, e) = self.string()?;
            return Ok((unescape(body), s, e));
        }
        let start = self.pos;
        let mut end = start;
        for (i, c) in self.rest().char_indices() {
            if c.is_whitespace() || c == ']' || c == '}' {
                break;
            }
            end = start + i + c.len_utf8();
        }
        if end == start {
            return fail("expected a range bound", self.pos);
        }
        let word = &self.text[start..end];
        self.pos = end;
        let capture = if word != "*" && is_number(word) {
            "number"
        } else {
            "constant"
        };
        self.tok(start, end, capture);
        Ok((word.to_string(), start, end))
    }

    fn check_range(&mut self, lo: &str, hi: &str, s: usize, e: usize, time_field: bool) {
        let mut kinds: Vec<Bound> = Vec::new();
        for b in [lo, hi] {
            let kind = if b == "*" {
                Bound::Open
            } else if time_field && is_epoch_ms(b) {
                Bound::Datetime(epoch_ms(b))
            } else if is_number(b) {
                Bound::Number(b.parse::<f64>().unwrap_or(f64::NAN))
            } else if let Some(ms) = datetime_ms(b) {
                Bound::Datetime(ms)
            } else if let Some(ip) = parse_ip(b) {
                Bound::Ip(ip)
            } else {
                self.diag(
                    codes::EXABEAM_RANGE,
                    format!("`{b}` is not a number, IPv4 address, datetime, or *"),
                    s,
                    e,
                );
                return;
            };
            kinds.push(kind);
        }
        let closed: Vec<&Bound> = kinds.iter().filter(|k| !matches!(k, Bound::Open)).collect();
        if closed.is_empty() {
            self.diag(
                codes::EXABEAM_RANGE,
                "a range needs at least one bound",
                s,
                e,
            );
            return;
        }
        let first = std::mem::discriminant(closed[0]);
        if closed.iter().any(|k| std::mem::discriminant(*k) != first) {
            self.diag(
                codes::EXABEAM_RANGE,
                "the bounds are of different kinds: both numbers, IPv4 addresses, or datetimes",
                s,
                e,
            );
            return;
        }
        if closed.iter().any(|k| matches!(k, Bound::Ip(IpAddr::V6(_)))) {
            self.diag(
                codes::EXABEAM_IPV6_RANGE,
                "IP ranges are IPv4 only in Exabeam Search",
                s,
                e,
            );
            return;
        }
        if closed.len() == 2 {
            let greater = match (closed[0], closed[1]) {
                (Bound::Number(a), Bound::Number(b)) => a > b,
                (Bound::Datetime(a), Bound::Datetime(b)) => a > b,
                (Bound::Ip(a), Bound::Ip(b)) => a > b,
                _ => false,
            };
            if greater {
                self.diag(
                    codes::EXABEAM_RANGE,
                    "the low bound is greater than the high bound",
                    s,
                    e,
                );
            }
        }
    }

    fn call(&mut self, name: &'a str, s: usize, e: usize) -> Parsed<Node> {
        let upper = name.to_uppercase();
        let function = filter_function(&upper);
        self.pos = e;
        match function {
            None => {
                self.tok(s, e, "error");
                let message = match foreign_hint(&upper) {
                    Some(hint) => format!("{name}() is not an Exabeam filter function: {hint}"),
                    None => {
                        format!("{name}() is not an Exabeam filter function (RGX, RGXi, WLD, WLDi)")
                    }
                };
                self.diag(codes::EXABEAM_UNKNOWN_FUNCTION, message, s, e);
            }
            Some(_) => self.tok(s, e, "function.builtin"),
        }
        self.expect('(', "punctuation.bracket")?;
        let mut args: Vec<(&'a str, usize, usize)> = Vec::new();
        while self.peek() != Some(')') {
            if self.at_end() {
                return fail("unclosed function call", self.pos);
            }
            if matches!(self.peek(), Some('"' | '\'')) {
                args.push(self.string()?);
            } else {
                let Some(end) = bare_end(self.text, self.pos) else {
                    return fail("expected a function argument", self.pos);
                };
                let start = self.pos;
                self.tok(start, end, "error");
                self.pos = end;
                args.push((&self.text[start..end], start, end));
                if function.is_some() {
                    self.diag(
                        codes::EXABEAM_FUNCTION_ARITY,
                        format!("{name}() takes one double-quoted pattern"),
                        start,
                        end,
                    );
                }
            }
            if self.peek() == Some(',') {
                self.expect(',', "punctuation.delimiter")?;
            }
        }
        self.expect(')', "punctuation.bracket")?;
        if function.is_some() && args.len() != 1 {
            self.diag(
                codes::EXABEAM_FUNCTION_ARITY,
                format!("{name}() takes exactly one pattern"),
                s,
                self.pos,
            );
        }
        if function == Some(true)
            && let [(body, start, end)] = args.as_slice()
            && let Some(why) = re2_refusal(&unescape(body))
        {
            self.diag(
                codes::EXABEAM_REGEX,
                format!("invalid RE2 pattern: {why}"),
                *start,
                *end,
            );
        }
        Ok(Node::leaf(Kind::Term, s, self.pos))
    }

    fn check_phrase(&mut self, body: &str, s: usize, e: usize) {
        let value = unescape(body);
        if value.chars().count() > 2 && value.starts_with('/') && value.ends_with('/') {
            self.diag(
                codes::EXABEAM_LEGACY_REGEX,
                "a value between slashes may be read as a regular expression: write RGX(\"…\") for a pattern, or drop the slashes for a path",
                s,
                e,
            );
            return;
        }
        let inner = value.trim_matches('`');
        if unescaped(inner, |c| c == '*' || c == '?') && unescaped(body.trim(), char::is_whitespace)
        {
            self.diag(
                codes::EXABEAM_WILDCARD_IN_PHRASE,
                "wildcards do not work inside a quoted phrase",
                s,
                e,
            );
        }
    }

    fn check_tree(&mut self, node: &Node, under_or: bool) {
        // Iterative: a long chain of ORs is wide, not deep, but groups nest.
        let mut stack = vec![(node, under_or)];
        while let Some((node, under_or)) = stack.pop() {
            if node.kind == Kind::Context && under_or {
                self.diag(
                    codes::EXABEAM_CONTEXT_TABLE_OR,
                    "a context table lookup is combined with AND or AND NOT only",
                    node.start,
                    node.end,
                );
            }
            let child_or = under_or || (node.kind == Kind::Or && node.children.len() > 1);
            for child in node.children.iter().rev() {
                stack.push((child, child_or));
            }
        }
    }

    fn check_context_tables(&mut self) {
        if let Some(&(s, e)) = self.context_tables.get(MAX_CONTEXT_TABLES) {
            self.diag(
                codes::EXABEAM_CONTEXT_TABLE_LIMIT,
                format!("at most {MAX_CONTEXT_TABLES} context table lookups per query"),
                s,
                e,
            );
        }
    }

    /// `exabeam_unknown_field`: every field the query names, once the whole
    /// query is read. `c_` and `m_` fields, and `AS` names defined earlier,
    /// are known.
    fn check_fields(&mut self) {
        let catalog = Catalog::cached();
        let uses = std::mem::take(&mut self.fields);
        // Where each `AS` name is first defined, and each unknown name's
        // suggestion, computed once per name: a long query repeats them.
        let mut first_alias: HashMap<String, usize> = HashMap::new();
        for (alias, at) in &self.aliases {
            let at_min = first_alias.entry(alias.to_lowercase()).or_insert(*at);
            *at_min = (*at_min).min(*at);
        }
        let mut verdicts: HashMap<String, Option<Option<String>>> = HashMap::new();
        for f in uses {
            let lower = f.name.to_lowercase();
            if first_alias.get(&lower).is_some_and(|at| *at < f.start) {
                continue;
            }
            let verdict = verdicts.entry(lower).or_insert_with(|| {
                (!catalog.knows(&f.name)).then(|| catalog.suggest(&f.name).map(str::to_string))
            });
            let Some(suggestion) = verdict.clone() else {
                continue;
            };
            let message = match suggestion {
                Some(near) => format!(
                    "`{}` is not a field of Exabeam's Common Information Model; did you mean `{near}`? A tenant's parsers may still define it",
                    f.name
                ),
                None => format!(
                    "`{}` is not a field of Exabeam's Common Information Model; a tenant's parsers or custom fields (`c_`) may still define it",
                    f.name
                ),
            };
            self.diag(codes::EXABEAM_UNKNOWN_FIELD, message, f.start, f.end);
        }
    }

    // -- advanced (Search only) -------------------------------------------------

    fn advanced(&mut self) -> Parsed<()> {
        let mut pipes = 0;
        if let Some((_, s, e)) = self.keyword_at(&["FOREACH"]) {
            self.diag(
                codes::EXABEAM_FOREACH_POSITION,
                "FOREACH runs on the result of a preceding query: put a query and | before it",
                s,
                e,
            );
        }
        let mut previous = self.statement()?;
        while self.peek() == Some('|') {
            let ps = self.pos;
            self.expect('|', "operator.pipe")?;
            pipes += 1;
            if pipes == MAX_PIPES + 1 {
                self.diag(
                    codes::EXABEAM_PIPE_LIMIT,
                    format!("at most {MAX_PIPES} pipes"),
                    ps,
                    ps + 1,
                );
            }
            let current = self.statement()?;
            if !current.foreach {
                if !previous.has_select || previous.select.is_empty() {
                    self.diag(
                        codes::EXABEAM_PIPE_MISUSE,
                        "the query before a pipe has no SELECT: write one query with AND or WHERE",
                        ps,
                        ps + 1,
                    );
                } else if !previous.star && current.fields.is_disjoint(&previous.select) {
                    self.diag(
                        codes::EXABEAM_PIPE_MISUSE,
                        "the query after a pipe uses no column the query before it selects: write one query with AND or WHERE",
                        ps,
                        ps + 1,
                    );
                }
            }
            previous = current;
        }
        Ok(())
    }

    fn statement(&mut self) -> Parsed<Statement> {
        let tokens_before = self.out.tokens.len();
        if self.keyword_at(&["FOREACH"]).is_some() {
            let mut info = self.foreach()?;
            info.foreach = true;
            return Ok(info);
        }
        let mut seen: Vec<&'static str> = Vec::new();
        let mut select_items: Vec<Column<'a>> = Vec::new();
        let mut select_star: Option<(usize, usize)> = None;
        let mut group_by: Vec<&'a str> = Vec::new();
        let mut first = true;
        if self.at_end() || matches!(self.peek(), Some('|' | ']')) {
            return fail("an empty statement: a pipe joins two statements", self.pos);
        }
        while !self.at_end() && !matches!(self.peek(), Some('|' | ']')) {
            let Some(kw) = self.keyword_at(&CLAUSES) else {
                if first || seen.last() == Some(&"FROM") {
                    // A bare filter is an implicit WHERE.
                    let tree = self.filter(&STOP)?;
                    self.check_tree(&tree, false);
                    seen.push("WHERE");
                    first = false;
                    continue;
                }
                return fail("expected a clause", self.pos);
            };
            let upper = kw.0.to_uppercase();
            let word = CLAUSES
                .iter()
                .copied()
                .find(|c| *c == upper)
                .expect("a clause keyword");
            let index = |w: &str| CLAUSES.iter().position(|c| *c == w).unwrap_or(0);
            if let Some(last) = seen.last()
                && index(word) < index(last)
            {
                self.diag(
                    codes::EXABEAM_CLAUSE_ORDER,
                    format!("{word} comes before {last}: [SELECT] [FROM] [WHERE] [AS] [GROUP-BY] [ORDER-BY] [LIMIT]"),
                    kw.1,
                    kw.2,
                );
            }
            if seen.contains(&word) {
                self.diag(
                    codes::EXABEAM_CLAUSE_ORDER,
                    format!("{word} appears twice"),
                    kw.1,
                    kw.2,
                );
            }
            seen.push(word);
            first = false;
            self.take_keyword(&[word], true);
            match word {
                "SELECT" => {
                    let (star, items) = self.select_list()?;
                    select_star = star;
                    select_items = items;
                }
                "FROM" | "AS" => self.alias("type")?,
                "WHERE" => {
                    let tree = self.filter(&STOP)?;
                    self.check_tree(&tree, false);
                }
                "GROUP-BY" => group_by = self.name_list(false)?,
                "ORDER-BY" => {
                    self.name_list(true)?;
                }
                _ => self.limit()?,
            }
        }
        if self.in_foreach > 0 && seen.iter().any(|w| matches!(*w, "GROUP-BY" | "ORDER-BY")) {
            // The character before the cursor, whole (a `]` or a multi-byte one).
            let at = self.text[..self.pos]
                .char_indices()
                .last()
                .map_or(0, |(i, _)| i);
            self.diag(
                codes::EXABEAM_FOREACH_CLAUSE,
                "a FOREACH sub-query has no GROUP-BY or ORDER-BY",
                at,
                self.pos,
            );
        }
        if !group_by.is_empty() {
            if let Some((s, e)) = select_star {
                self.diag(
                    codes::EXABEAM_GROUP_BY_SELECT_STAR,
                    "GROUP-BY does not combine with SELECT *",
                    s,
                    e,
                );
            }
            let grouped: HashSet<String> = group_by.iter().map(|g| g.to_lowercase()).collect();
            for (column, aggregated, s, e) in select_items.clone() {
                if !aggregated && !grouped.contains(&column.to_lowercase()) {
                    self.diag(
                        codes::EXABEAM_GROUP_BY_COLUMN,
                        format!("{column} is selected but neither grouped nor aggregated"),
                        s,
                        e,
                    );
                }
            }
        }
        let text = self.text;
        let new = &self.out.tokens[tokens_before..];
        let mut info = Statement {
            star: select_star.is_some(),
            ..Statement::default()
        };
        info.fields = new
            .iter()
            .filter(|t| matches!(t.capture, "property" | "type"))
            .map(|t| text[t.start..t.end].to_lowercase())
            .collect();
        if seen.contains(&"SELECT") {
            info.has_select = true;
            info.select = select_items
                .iter()
                .map(|(c, ..)| c.to_lowercase())
                .chain(
                    new.iter()
                        .filter(|t| t.capture == "variable")
                        .map(|t| text[t.start..t.end].to_lowercase()),
                )
                .collect();
            if select_star.is_some() {
                info.select.insert("*".into());
            }
        }
        Ok(info)
    }

    fn limit(&mut self) -> Parsed<()> {
        self.ws();
        let start = self.pos;
        let digits = self.rest().bytes().take_while(u8::is_ascii_digit).count();
        let value = &self.text[start..start + digits];
        if digits == 0 || value.bytes().all(|b| b == b'0') {
            return fail("LIMIT takes a positive integer", self.pos);
        }
        self.tok(start, start + digits, "number");
        self.pos = start + digits;
        Ok(())
    }

    fn foreach(&mut self) -> Parsed<Statement> {
        self.take_keyword(&["FOREACH"], true);
        let Some((name, s, e)) = self.column_at() else {
            return fail("FOREACH names a field", self.pos);
        };
        self.tok(s, e, "property");
        self.note_field(name, s, e);
        self.pos = e;
        self.expect('[', "punctuation.bracket")?;
        self.in_foreach += 1;
        let inner = self.statement()?;
        self.in_foreach -= 1;
        self.expect(']', "punctuation.bracket")?;
        if self.take_keyword(&["LIMIT"], true).is_some() {
            self.limit()?;
        }
        Ok(inner)
    }

    /// The columns of `SELECT`: the span of `*` if there is one, and each
    /// other column with whether it is aggregated.
    fn select_list(&mut self) -> Parsed<SelectList<'a>> {
        let mut star = None;
        let mut items = Vec::new();
        self.take_keyword(&["DISTINCT"], true);
        loop {
            self.ws();
            if self.rest().starts_with('*') {
                self.tok(self.pos, self.pos + 1, "operator");
                star = Some((self.pos, self.pos + 1));
                self.pos += 1;
            } else {
                let Some((name, s, e)) = self.column_at() else {
                    return fail("expected a column", self.pos);
                };
                if self.text[e..].trim_start().starts_with('(') {
                    self.select_call(name, s, e)?;
                    items.push((name, true, s, e));
                } else {
                    self.tok(s, e, "property");
                    self.note_field(name, s, e);
                    self.pos = e;
                    items.push((name, false, s, e));
                }
            }
            if self.take_keyword(&["AS"], true).is_some() {
                self.alias("variable")?;
            }
            if self.peek() == Some(',') {
                self.expect(',', "punctuation.delimiter")?;
                continue;
            }
            return Ok((star, items));
        }
    }

    fn select_call(&mut self, name: &'a str, s: usize, e: usize) -> Parsed<()> {
        let upper = name.to_uppercase();
        self.pos = e;
        if upper == "RGX_EXTRACT" {
            self.rgx_extract += 1;
            if self.rgx_extract == MAX_RGX_EXTRACT + 1 {
                self.diag(
                    codes::EXABEAM_RGX_EXTRACT_LIMIT,
                    format!("at most {MAX_RGX_EXTRACT} RGX_EXTRACT per query"),
                    s,
                    e,
                );
            }
            if !one_case(name) {
                self.diag(
                    codes::EXABEAM_KEYWORD_CASE,
                    format!("`{name}`: write RGX_EXTRACT or rgx_extract"),
                    s,
                    e,
                );
            }
            self.tok(s, e, "function.builtin");
            self.expect('(', "punctuation.bracket")?;
            let mut args = 0;
            let mut pattern: Option<(&'a str, usize, usize)> = None;
            while self.peek() != Some(')') {
                if matches!(self.peek(), Some('"' | '\'')) {
                    pattern = Some(self.string()?);
                } else {
                    let Some((field, fs, fe)) = self.column_at() else {
                        return fail("expected a field or a pattern", self.pos);
                    };
                    self.tok(fs, fe, "property");
                    self.note_field(field, fs, fe);
                    self.pos = fe;
                }
                args += 1;
                if self.peek() == Some(',') {
                    self.expect(',', "punctuation.delimiter")?;
                }
            }
            self.expect(')', "punctuation.bracket")?;
            match pattern {
                Some((body, ps, pe)) if args == 1 || args == 2 => {
                    if let Some(why) = re2_refusal(&unescape(body)) {
                        self.diag(
                            codes::EXABEAM_REGEX,
                            format!("invalid RE2 pattern: {why}"),
                            ps,
                            pe,
                        );
                    }
                }
                _ => self.diag(
                    codes::EXABEAM_FUNCTION_ARITY,
                    "RGX_EXTRACT takes an optional field and a double-quoted pattern: RGX_EXTRACT([field,] \"pattern\")",
                    s,
                    self.pos,
                ),
            }
            return Ok(());
        }
        let aggregate = AGGREGATES.contains(&upper.as_str());
        if aggregate && !one_case(name) {
            self.diag(
                codes::EXABEAM_KEYWORD_CASE,
                format!("`{name}`: write {upper} or {}", upper.to_lowercase()),
                s,
                e,
            );
        }
        if aggregate {
            self.tok(s, e, "function.builtin");
        } else {
            self.tok(s, e, "error");
            let message = match foreign_hint(&upper) {
                Some(hint) => format!(
                    "{name}() is not an Exabeam aggregation (COUNT, MIN, MAX, SUM, AVG, RGX_EXTRACT): {hint}"
                ),
                None => format!(
                    "{name}() is not an Exabeam aggregation (COUNT, MIN, MAX, SUM, AVG, RGX_EXTRACT)"
                ),
            };
            self.diag(codes::EXABEAM_UNKNOWN_FUNCTION, message, s, e);
        }
        self.expect('(', "punctuation.bracket")?;
        self.ws();
        if self.rest().starts_with('*') {
            if upper != "COUNT" {
                self.diag(
                    codes::EXABEAM_FUNCTION_ARITY,
                    format!("{name}(*): only COUNT takes *"),
                    self.pos,
                    self.pos + 1,
                );
            }
            self.tok(self.pos, self.pos + 1, "operator");
            self.pos += 1;
        } else {
            let Some((field, fs, fe)) = self.column_at() else {
                return fail("an aggregation takes one field", self.pos);
            };
            self.tok(fs, fe, "property");
            self.note_field(field, fs, fe);
            self.pos = fe;
        }
        if self.peek() == Some(',') {
            self.diag(
                codes::EXABEAM_FUNCTION_ARITY,
                format!("{name}() takes one field"),
                self.pos,
                self.pos + 1,
            );
            while self.peek() != Some(')') && !self.at_end() {
                self.pos += self.rest().chars().next().map_or(1, char::len_utf8);
            }
        }
        self.expect(')', "punctuation.bracket")?;
        Ok(())
    }

    fn alias(&mut self, capture: &'static str) -> Parsed<()> {
        let Some((name, s, e)) = self.word_at() else {
            return fail("expected a name", self.pos);
        };
        if is_reserved(name) {
            self.diag(
                codes::EXABEAM_RESERVED_ALIAS,
                format!("`{name}` is a reserved word"),
                s,
                e,
            );
        }
        self.tok(s, e, capture);
        self.aliases.push((name.to_string(), s));
        self.pos = e;
        Ok(())
    }

    fn name_list(&mut self, order_by: bool) -> Parsed<Vec<&'a str>> {
        let mut names = Vec::new();
        loop {
            let Some((name, s, e)) = self.column_at() else {
                return fail("expected a column", self.pos);
            };
            self.tok(s, e, "property");
            self.note_field(name, s, e);
            self.pos = e;
            names.push(name);
            if order_by {
                self.take_keyword(&["ASC", "DESC"], true);
            }
            if self.peek() == Some(',') {
                self.expect(',', "punctuation.delimiter")?;
                continue;
            }
            return Ok(names);
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Bound {
    Open,
    Number(f64),
    /// An instant, in epoch milliseconds.
    Datetime(i128),
    Ip(IpAddr),
}

/// Whether `text` (already trimmed) starts with a comparison or match operator.
fn starts_with_operator(text: &str) -> bool {
    ["==", "!=", "<=", ">="]
        .iter()
        .any(|op| text.starts_with(op))
        || text.starts_with([':', '=', '<', '>'])
}

/// `(?i)in\b` at the start of `text`.
fn starts_with_in(text: &str) -> bool {
    text.len() >= 2
        && text.as_bytes()[..2].eq_ignore_ascii_case(b"in")
        && text[2..].chars().next().is_none_or(|c| !is_word_char(c))
}

/// `(?i)as\s+name\s*` before the end, a pipe, GROUP-BY, ORDER-BY, or LIMIT:
/// a statement alias (`WHERE vendor:"x" AS t`).
fn statement_alias(text: &str) -> bool {
    if text.len() < 2 || !text.as_bytes()[..2].eq_ignore_ascii_case(b"as") {
        return false;
    }
    let rest = &text[2..];
    let after_ws = rest.trim_start_matches(char::is_whitespace);
    if after_ws.len() == rest.len() {
        return false;
    }
    let Some(end) = ident_like_end(after_ws, 0, false) else {
        return false;
    };
    if after_ws[..end].contains('.') {
        return false;
    }
    let tail = after_ws[end..].trim_start_matches(char::is_whitespace);
    if tail.len() == after_ws[end..].len() && !tail.is_empty() && !tail.starts_with('|') {
        return false; // the name runs on: not a whole word
    }
    tail.is_empty()
        || tail.starts_with('|')
        || hyphen_word_end(tail, 0).is_some()
        || (tail.len() >= 5
            && tail.as_bytes()[..5].eq_ignore_ascii_case(b"limit")
            && tail[5..].chars().next().is_none_or(|c| !is_word_char(c)))
}

/// `(?i)limit\s+\d+\s*\Z`: a trailing `LIMIT <n>`.
fn trailing_limit(text: &str) -> bool {
    if text.len() < 5 || !text.as_bytes()[..5].eq_ignore_ascii_case(b"limit") {
        return false;
    }
    let rest = &text[5..];
    let after_ws = rest.trim_start_matches(char::is_whitespace);
    if after_ws.len() == rest.len() {
        return false;
    }
    let digits = after_ws.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0
        && after_ws[digits..]
            .trim_start_matches(char::is_whitespace)
            .is_empty()
}

/// `\s*([0-9A-Fa-f:.]+)/(\d{1,3})\s*\]` at `at`: the network's span.
fn cidr_at(text: &str, at: usize) -> Option<(usize, usize)> {
    let rest = &text[at..];
    let lead = rest.len() - rest.trim_start_matches(char::is_whitespace).len();
    let start = at + lead;
    let b = text.as_bytes();
    let mut i = start;
    while i < b.len() && (b[i].is_ascii_hexdigit() || b[i] == b':' || b[i] == b'.') {
        i += 1;
    }
    if i == start || b.get(i) != Some(&b'/') {
        return None;
    }
    let digits_start = i + 1;
    let mut j = digits_start;
    while j < b.len() && b[j].is_ascii_digit() && j - digits_start < 3 {
        j += 1;
    }
    if j == digits_start {
        return None;
    }
    let after = &text[j..];
    let close = j + (after.len() - after.trim_start_matches(char::is_whitespace).len());
    (b.get(close) == Some(&b']')).then_some((start, j))
}

/// Python's `ipaddress.ip_network(net, strict=False)`: the IP version of a
/// valid `address/prefix`, or `None`.
fn cidr_version(net: &str) -> Option<u8> {
    let (addr, prefix) = net.split_once('/')?;
    let prefix: u32 = prefix.parse().ok()?;
    if let Ok(_v4) = addr.parse::<Ipv4Addr>() {
        return (prefix <= 32).then_some(4);
    }
    if let Ok(_v6) = addr.parse::<Ipv6Addr>() {
        return (prefix <= 128).then_some(6);
    }
    None
}

/// Check `text` under `profile`: every finding and the highlight tokens.
pub fn check(text: &str, profile: Profile) -> Checked {
    Parser::new(text, profile).parse()
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn numbers_and_datetimes() {
        assert!(is_number("12"));
        assert!(is_number("-1.5"));
        assert!(!is_number("1."));
        assert!(!is_number("1e3"));
        assert!(is_datetime("2026-11-01T00:00:00Z"));
        assert!(is_datetime("2026-11-01T00:00:00.123+01:00"));
        assert!(!is_datetime("2026-11-01"));
    }

    #[test]
    fn re2_refusals() {
        assert!(re2_refusal("^a+b$").is_none());
        assert!(re2_refusal("(?i)admin").is_none());
        assert!(re2_refusal(r"(a)\1").is_some());
        assert!(re2_refusal(r"\\1").is_none());
        assert!(re2_refusal("foo(?=bar)").is_some());
        assert!(re2_refusal("(?>a)").is_some());
        assert!(re2_refusal("a++").is_some());
        assert!(re2_refusal("[a-").is_some());
        // RE2 reads these as literals or escapes; the `regex` crate would not.
        assert!(re2_refusal("a{2,").is_none());
        assert!(re2_refusal("${?input}?").is_none());
        assert!(re2_refusal(r"({\d}){2,}").is_none());
        assert!(re2_refusal(r".*\ .*").is_none());
        assert!(re2_refusal(r"[a[b]").is_none());
        assert!(re2_refusal(r"[&&]").is_none());
        assert!(re2_refusal(r"\Q.*\E+").is_none());
        assert!(re2_refusal("a]").is_none());
        // ... and refuses what the `regex` crate takes.
        assert!(re2_refusal(".**").is_some());
        assert!(re2_refusal("a{2}{3}").is_some());
        assert!(re2_refusal("a{1001}").is_some());
        assert!(re2_refusal("(?x)a b").is_some());
        assert!(re2_refusal("a*?").is_none());
        assert!(re2_refusal("(?i)a").is_none());
        assert!(re2_refusal("(?P<n>a)").is_none());
        assert!(re2_refusal("[[:alpha:]]").is_none());
        // The spec review's cases (exabeam-1.0, `exabeam_regex`).
        for ok in [
            r"\pL+",
            r"\p{Greek}",
            r"end\z",
            r"\x{263a}",
            "(?<n>a)",
            "[a?+]",
            "[*+]",
            "[(?=]",
            "a(?i)b",
            "(?U)a+",
            "a$?",
            "^*a",
            r"\b+",
            r"\0",
            r"\012",
            r"\12",
            r"[\01]",
            "[[:^alpha:]]",
            "(?P<1a>x)",
            "(?i:(a))",
        ] {
            assert!(re2_refusal(ok).is_none(), "{ok}: {:?}", re2_refusal(ok));
        }
        for bad in [
            r"end\Z",
            "a{2,1001}",
            "a*+",
            "a{2}+",
            "(?P=n)",
            "(?#note)a",
            "a\\\u{a0}b",
            r"\1",
            r"\18",
            r"\8",
            r"[\1]",
            "[[:foo:]]",
            "(?P<a.b>x)",
            "(?<n>a)(?<n>b)",
            r"[\Q]\E]",
        ] {
            assert!(re2_refusal(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn ip_addresses() {
        assert!(parse_ip("10.0.0.1").is_some());
        assert!(parse_ip("fe80::1%eth0").is_some());
        assert!(parse_ip("010.0.0.1").is_none());
        assert_eq!(cidr_version("10.0.0.0/8"), Some(4));
        assert_eq!(cidr_version("10.0.0.0/33"), None);
        assert_eq!(cidr_version("fd00::/8"), Some(6));
    }
}
