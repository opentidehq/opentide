//! The parts of YARA-L 2.0 opentide checks without a parser (yara-l-1.0),
//! ported from 0.28.0's `platforms/google_secops/yaral.py`.
//!
//! A `configurations.google_secops` block carries a rule's sections as keys:
//! `setup`, `events`, `outcome`, `condition` and `export` as YARA-L text,
//! `match` and `options` as YAML objects. This module checks the structural
//! codes of the language spec that need no parser (`yaral_section_missing`,
//! `yaral_section_empty`, `yaral_section_header`, `yaral_match_shape`,
//! `yaral_match_window`, `yaral_option`) and renders `match` and `options` as
//! deploy writes them. Everything else in the language (scope, UDM fields,
//! functions, condition shape) is the analysis engine's.
//!
//! The scanner keeps line numbers and columns: a label or a keyword inside a
//! comment or a string, raw-string or regex literal never counts.

use std::sync::OnceLock;

use regex::Regex;

use crate::configuration::repr;
use crate::node::{Node, Value};

/// Case-insensitive keywords (yara-l-1.0, Lexical structure), section names
/// included.
pub const KEYWORDS: [&str; 34] = [
    "rule",
    "meta",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "dedup",
    "order",
    "limit",
    "select",
    "unselect",
    "and",
    "or",
    "not",
    "nocase",
    "in",
    "regex",
    "cidr",
    "any",
    "all",
    "over",
    "by",
    "before",
    "after",
    "if",
    "of",
    "true",
    "false",
    "asc",
    "desc",
    "setup",
    "export",
    "stage",
];

/// Every section label, rule and search (yara-l-1.0, Sections).
pub const SECTION_LABELS: [&str; 13] = [
    "meta",
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
    "dedup",
    "order",
    "limit",
    "select",
    "unselect",
];

/// The block's section keys, in the order deploy writes them.
pub const SECTION_KEYS: [&str; 7] = [
    "setup",
    "events",
    "match",
    "outcome",
    "condition",
    "options",
    "export",
];

/// The section keys that hold YARA-L text.
pub const TEXT_SECTIONS: [&str; 5] = ["setup", "events", "outcome", "condition", "export"];

/// The sections a rule cannot do without.
pub const REQUIRED_SECTIONS: [&str; 2] = ["events", "condition"];

/// `options` keys, in the order deploy writes them.
pub const OPTION_KEYS: [&str; 2] = ["allow_zero_values", "suppression_window"];

/// The `match` keys.
const MATCH_FIELDS: [&str; 5] = ["group_by", "window", "type", "pivot", "direction"];

/// What a YAML scalar that starts with `#` loads as, said in
/// `yaral_section_empty`.
pub const EMPTY_HINT: &str = "; a plain YAML scalar that starts with # is a YAML comment, so it loads as null: \
     write the text as a block scalar (|)";

/// A code, the path it is reported at relative to the block, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The diagnostic code.
    pub code: &'static str,
    /// The path relative to the block (`["match", "window"]`).
    pub path: Vec<String>,
    /// The message.
    pub message: String,
}

impl Finding {
    pub(crate) fn new(code: &'static str, path: &[&str], message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.iter().map(|segment| (*segment).to_owned()).collect(),
            message: message.into(),
        }
    }
}

/// Whether `word` is a YARA-L keyword, compared case-insensitively.
pub fn is_keyword(word: &str) -> bool {
    let lower = word.to_lowercase();
    KEYWORDS.contains(&lower.as_str())
}

/// A YARA-L identifier that is not a keyword.
pub fn is_identifier(value: &str) -> bool {
    identifier_shape(value) && !is_keyword(value)
}

/// `[A-Za-z_][A-Za-z0-9_]*`.
pub(crate) fn identifier_shape(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// `$` then an identifier.
fn is_variable(value: &str) -> bool {
    value.strip_prefix('$').is_some_and(identifier_shape)
}

/// Line endings as `\n`.
pub fn normalise_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Python's `str.strip()` emptiness: only whitespace, or nothing.
fn blank(text: &str) -> bool {
    crate::objects::platform::python_strip(text).is_empty()
}

/// Whether a `/` after `buf` starts a regex literal rather than dividing.
fn operand_expected(buf: &[char]) -> bool {
    let before: String = buf.iter().collect();
    let before = before.trim_end();
    let Some(last) = before.chars().last() else {
        return true;
    };
    if "=!<>(,[".contains(last) {
        return true;
    }
    let word: String = before
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphabetic() || *ch == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    !word.is_empty()
        && matches!(
            word.to_lowercase().as_str(),
            "and" | "or" | "not" | "in" | "regex"
        )
}

/// `text`'s lines with comments and string, raw-string and regex contents
/// blanked.
///
/// Lengths are kept (in characters), so a column in a blanked line is the
/// column in `text`. A `/` starts a regex literal only where an operand is
/// expected, so division is left alone. With `blank_literals` false, only
/// comments are blanked.
pub fn code_lines(text: &str, blank_literals: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in normalise_newlines(text).split('\n') {
        let chars: Vec<char> = line.chars().collect();
        let mut buf: Vec<char> = Vec::with_capacity(chars.len());
        let mut index = 0;
        let mut quote: Option<char> = None;
        let starts = |at: usize, pair: [char; 2]| {
            chars.get(at) == Some(&pair[0]) && chars.get(at + 1) == Some(&pair[1])
        };
        while index < chars.len() {
            let ch = chars[index];
            if in_block {
                if starts(index, ['*', '/']) {
                    in_block = false;
                    buf.extend([' ', ' ']);
                    index += 2;
                    continue;
                }
                buf.push(' ');
            } else if let Some(open) = quote {
                if open != '`' && ch == '\\' && index + 1 < chars.len() {
                    if blank_literals {
                        buf.extend([' ', ' ']);
                    } else {
                        buf.extend([ch, chars[index + 1]]);
                    }
                    index += 2;
                    continue;
                }
                if ch == open {
                    quote = None;
                    buf.push(ch);
                } else {
                    buf.push(if blank_literals { ' ' } else { ch });
                }
            } else if starts(index, ['/', '/']) {
                buf.extend(std::iter::repeat_n(' ', chars.len() - index));
                break;
            } else if starts(index, ['/', '*']) {
                in_block = true;
                buf.extend([' ', ' ']);
                index += 2;
                continue;
            } else if ch == '"' || ch == '`' || (ch == '/' && operand_expected(&buf)) {
                quote = Some(ch);
                buf.push(ch);
            } else {
                buf.push(ch);
            }
            index += 1;
        }
        out.push(buf.into_iter().collect());
    }
    out
}

/// A text section's lines as deploy writes them, and how many leading lines
/// it dropped.
///
/// Line endings become `\n`; leading and trailing blank lines go. Nothing
/// else changes: not a character of an expression, a comment or a literal.
pub fn section_lines(text: &str) -> (Vec<String>, usize) {
    let normalised = normalise_newlines(text);
    let mut lines: Vec<&str> = normalised.split('\n').collect();
    let leading = lines.iter().take_while(|line| blank(line)).count();
    lines.drain(..leading);
    while lines.last().is_some_and(|line| blank(line)) {
        lines.pop();
    }
    (lines.into_iter().map(str::to_owned).collect(), leading)
}

#[expect(
    clippy::expect_used,
    reason = "regex literals, exercised by every section test"
)]
fn patterns() -> &'static (Regex, Regex, Regex) {
    static PATTERNS: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        (
            Regex::new(&format!(r"(?i)^\s*({})\s*:", SECTION_LABELS.join("|")))
                .expect("a valid pattern"),
            Regex::new(r"(?i)^\s*rule\s+[A-Za-z_][A-Za-z0-9_]*").expect("a valid pattern"),
            Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*\.").expect("a valid pattern"),
        )
    })
}

/// The event variables `events` uses (`e` of `$e.metadata…`), in order, each
/// once.
pub fn event_variables(events: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in code_lines(events, true) {
        for captures in patterns().2.captures_iter(&line) {
            let name = captures[1].to_owned();
            if !found.contains(&name) {
                found.push(name);
            }
        }
    }
    found
}

/// The 1-based line of `text` holding a section label, a `rule` header or a
/// lone brace.
pub fn section_header_line(text: &str) -> Option<usize> {
    let (label, header, _) = patterns();
    code_lines(text, true)
        .iter()
        .position(|line| {
            let stripped = crate::objects::platform::python_strip(line);
            header.is_match(line) || label.is_match(line) || stripped == "{" || stripped == "}"
        })
        .map(|index| index + 1)
}

/// Python's `type(value).__name__` of a YAML value.
pub(crate) fn python_type(node: &Node) -> &'static str {
    match &node.value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Datetime(_) => "datetime",
        Value::Seq(_) => "list",
        Value::Map(_) => "dict",
    }
}

fn yaml_kind(node: &Node) -> &'static str {
    match &node.value {
        Value::Map(_) => "mapping",
        Value::Seq(_) => "list",
        _ => python_type(node),
    }
}

/// A mapping's entries whose key is a string, with their key.
fn string_entries(node: &Node) -> Vec<(String, &Node)> {
    match &node.value {
        Value::Map(entries) => entries
            .iter()
            .map(|entry| (key_text(&entry.key), entry.value.as_ref()))
            .collect(),
        _ => Vec::new(),
    }
}

/// A mapping key as Python's `str()` writes it.
pub(crate) fn key_text(key: &Node) -> String {
    match &key.value {
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        _ => repr::node(key),
    }
}

/// The value of `key` in a mapping node.
fn lookup<'n>(block: &'n Node, key: &str) -> Option<&'n Node> {
    block.get(key).map(AsRef::as_ref)
}

// --- YaraLSections ---------------------------------------------------------

/// The structural codes of the block's sections (yara-l-1.0, YaraLSections).
pub fn section_findings(block: &Node) -> Vec<Finding> {
    let mut found: Vec<Finding> = REQUIRED_SECTIONS
        .iter()
        .filter(|key| lookup(block, key).is_none())
        .map(|key| {
            Finding::new(
                "yaral_section_missing",
                &[key],
                format!(
                    "a rule needs a {key} section: write it under configurations.google_secops.{key}"
                ),
            )
        })
        .collect();
    for key in TEXT_SECTIONS {
        let Some(text) = lookup(block, key) else {
            continue;
        };
        match &text.value {
            Value::Null => found.push(Finding::new(
                "yaral_section_empty",
                &[key],
                format!("{key} has no text{EMPTY_HINT}"),
            )),
            Value::Str(text) if blank(text) => found.push(Finding::new(
                "yaral_section_empty",
                &[key],
                format!("{key} has no text{EMPTY_HINT}"),
            )),
            Value::Str(text) => {
                if let Some(header) = section_header_line(text) {
                    found.push(Finding::new(
                        "yaral_section_header",
                        &[key],
                        format!(
                            "{key} holds a section label, a rule header or a rule's braces (line \
                             {header}); deploy writes the header and meta, and each section is its \
                             own key"
                        ),
                    ));
                }
            }
            _ => found.push(Finding::new(
                "yaral_section_empty",
                &[key],
                format!(
                    "{key} is YARA-L text, not a YAML {}: write it as a block scalar (|)",
                    yaml_kind(text)
                ),
            )),
        }
    }
    if let Some(node) = lookup(block, "match") {
        found.extend(match_findings(node));
    }
    if let Some(node) = lookup(block, "options") {
        found.extend(options_findings(node));
    }
    found
}

// --- YaraLMatch ------------------------------------------------------------

/// A `<n>m`, `<n>h` or `<n>d` duration in minutes, or `None`.
pub fn window_minutes(window: &str) -> Option<u64> {
    let unit = window.chars().last()?;
    let factor = match unit {
        'm' => 1,
        'h' => 60,
        'd' => 1440,
        _ => return None,
    };
    positive_number(&window[..window.len() - 1]).map(|count| count.saturating_mul(factor))
}

/// `[1-9][0-9]*`, as a number.
pub(crate) fn positive_number(digits: &str) -> Option<u64> {
    if digits.is_empty() || digits.starts_with('0') || !digits.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    // Digits past u64 are still a duration Python reads; they exceed every bound.
    Some(digits.parse().unwrap_or(u64::MAX))
}

/// `match.type` and the keyword it renders.
pub fn match_keyword(kind: &str) -> Option<&'static str> {
    match kind {
        "hop" | "sliding" => Some("over"),
        "tumbling" => Some("by"),
        _ => None,
    }
}

/// `yaral_match_shape` and `yaral_match_window` (yara-l-1.0, YaraLMatch).
pub fn match_findings(node: &Node) -> Vec<Finding> {
    if !matches!(node.value, Value::Map(_)) {
        return vec![Finding::new(
            "yaral_match_shape",
            &["match"],
            "match is an object with group_by and window",
        )];
    }
    // An unset field (YAML null) is absent.
    let entries: Vec<(String, &Node)> = string_entries(node)
        .into_iter()
        .filter(|(_, value)| !matches!(value.value, Value::Null))
        .collect();
    let get = |key: &str| {
        entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| *value)
    };
    let mut found = Vec::new();
    let mut unknown: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str())
        .filter(|key| !MATCH_FIELDS.contains(key))
        .collect();
    unknown.sort_unstable();
    if let Some(first) = unknown.first() {
        found.push(Finding::new(
            "yaral_match_shape",
            &["match", first],
            format!(
                "unknown match key(s) {}: match takes group_by, window, type, pivot and direction",
                unknown.join(", ")
            ),
        ));
    }
    let group_by_ok = get("group_by").is_some_and(|group_by| match &group_by.value {
        Value::Seq(items) if !items.is_empty() => {
            let names: Vec<Option<&str>> = items.iter().map(|item| item.value.as_str()).collect();
            names.iter().all(|name| name.is_some_and(is_variable))
                && names
                    .iter()
                    .enumerate()
                    .all(|(index, name)| !names[..index].contains(name))
        }
        _ => false,
    });
    if !group_by_ok {
        found.push(Finding::new(
            "yaral_match_shape",
            &["match", "group_by"],
            "group_by is a non-empty list of distinct placeholders, each $name",
        ));
    }
    let kind_node = get("type");
    let kind = kind_node.map_or(Some("hop"), |node| node.value.as_str());
    let known_kind = kind.filter(|kind| match_keyword(kind).is_some());
    if known_kind.is_none() {
        let shown = kind_node.map_or_else(|| repr::quote("hop"), repr::node);
        found.push(Finding::new(
            "yaral_match_shape",
            &["match", "type"],
            format!("type {shown} is not hop, tumbling or sliding"),
        ));
    }
    let pivot = get("pivot");
    let direction = get("direction");
    if kind == Some("sliding") {
        let pivot_ok = pivot
            .and_then(|node| node.value.as_str())
            .is_some_and(is_variable);
        let direction_ok = direction
            .and_then(|node| node.value.as_str())
            .is_some_and(|text| text == "before" || text == "after");
        if !(pivot_ok && direction_ok) {
            found.push(Finding::new(
                "yaral_match_shape",
                &["match"],
                "a sliding window needs pivot (the $event it is anchored on) and direction \
                 (before or after)",
            ));
        }
    } else if pivot.is_some() || direction.is_some() {
        found.push(Finding::new(
            "yaral_match_shape",
            &[
                "match",
                if pivot.is_some() {
                    "pivot"
                } else {
                    "direction"
                },
            ],
            "pivot and direction belong to a sliding window (type: sliding)",
        ));
    }
    let window = get("window");
    match window
        .and_then(|node| node.value.as_str())
        .map(|text| (text, window_minutes(text)))
    {
        Some((text, Some(minutes))) => {
            let tumbling = kind == Some("tumbling");
            let bound = if tumbling { 72 * 60 } else { 14 * 1440 };
            if minutes > bound {
                let label = known_kind.unwrap_or("hop");
                let shown = if tumbling { "72h" } else { "14d" };
                found.push(Finding::new(
                    "yaral_match_window",
                    &["match", "window"],
                    format!("window {text}: a {label} window in a rule is at most {shown}"),
                ));
            }
        }
        _ => {
            let shown = window.map_or_else(|| "None".to_owned(), repr::node);
            found.push(Finding::new(
                "yaral_match_window",
                &["match", "window"],
                format!("window {shown} is not a duration in m, h or d (10m, 1h, 2d)"),
            ));
        }
    }
    found
}

/// The `match:` line deploy writes from a block's `match`, or `None` when it
/// is not a mapping with `group_by` and `window`.
pub fn render_match(node: &Node) -> Option<String> {
    let entries = string_entries(node);
    let get = |key: &str| {
        entries
            .iter()
            .find(|(name, value)| name == key && !matches!(value.value, Value::Null))
            .map(|(_, value)| *value)
    };
    let kind = get("type")
        .and_then(|node| node.value.as_str())
        .unwrap_or("hop");
    let keyword = match_keyword(kind)?;
    let Value::Seq(group_by) = &get("group_by")?.value else {
        return None;
    };
    let names: Vec<String> = group_by.iter().map(|item| scalar_text(item)).collect();
    let window = scalar_text(get("window")?);
    let text = format!("{} {keyword} {window}", names.join(", "));
    if kind == "sliding" {
        let direction = get("direction").map(scalar_text).unwrap_or_default();
        let pivot = get("pivot").map(scalar_text).unwrap_or_default();
        return Some(format!("{text} {direction} {pivot}"));
    }
    Some(text)
}

/// A scalar as YARA-L spells it: a string as written, a boolean as `true`
/// or `false`, anything else as its YAML text.
fn scalar_text(node: &Node) -> String {
    match &node.value {
        Value::Str(text) | Value::Datetime(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        _ => repr::node(node),
    }
}

// --- YaraLOptions ----------------------------------------------------------

/// `yaral_option` (yara-l-1.0, YaraLOptions).
pub fn options_findings(node: &Node) -> Vec<Finding> {
    let Value::Map(entries) = &node.value else {
        return vec![Finding::new(
            "yaral_option",
            &["options"],
            "options is an object with allow_zero_values and suppression_window",
        )];
    };
    let mut found = Vec::new();
    for entry in entries {
        let value = entry.value.as_ref();
        if matches!(value.value, Value::Null) {
            continue; // unset
        }
        let key = key_text(&entry.key);
        let is_str_key = matches!(entry.key.value, Value::Str(_));
        if is_str_key && key == "allow_zero_values" && matches!(value.value, Value::Bool(_)) {
            continue;
        }
        if is_str_key
            && key == "suppression_window"
            && value.value.as_str().and_then(window_minutes).is_some()
        {
            continue;
        }
        let message = if is_str_key && OPTION_KEYS.contains(&key.as_str()) {
            let expected = if key == "allow_zero_values" {
                "true or false"
            } else {
                "a duration (5m, 1h, 1d)"
            };
            format!("options.{key} is {expected}, not {}", repr::node(value))
        } else {
            format!(
                "{} is not an option: options takes allow_zero_values and suppression_window",
                repr::node(&entry.key)
            )
        };
        found.push(Finding::new("yaral_option", &["options", &key], message));
    }
    found
}

/// The `options:` lines deploy writes: only the keys set, in [`OPTION_KEYS`]
/// order.
pub fn render_options(node: &Node) -> Vec<String> {
    let entries = string_entries(node);
    OPTION_KEYS
        .iter()
        .filter_map(|key| {
            let (_, value) = entries
                .iter()
                .find(|(name, value)| name == key && !matches!(value.value, Value::Null))?;
            Some(format!("{key} = {}", scalar_text(value)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Node {
        let document = crate::node::load(text).unwrap_or_else(|error| panic!("{error:?}"));
        document
            .root()
            .map(|root| (**root).clone())
            .unwrap_or_else(|| panic!("empty"))
    }

    fn codes(findings: &[Finding]) -> Vec<(&'static str, String)> {
        findings
            .iter()
            .map(|finding| (finding.code, finding.path.join(".")))
            .collect()
    }

    #[test]
    fn code_lines_blank_comments_and_literals_keeping_columns() {
        let text = "$e.x = \"rule a {\" // events:\n/* match:\n*/ $e.y = /a\\/b/ nocase";
        let lines = code_lines(text, true);
        assert_eq!(lines[0], "$e.x = \"        \"           ");
        assert_eq!(lines[1], "         ");
        assert_eq!(lines[2], "   $e.y = /    / nocase");
        let kept = code_lines("$a = \"x\\\"y\" // c", false);
        assert_eq!(kept[0], "$a = \"x\\\"y\"     ");
        // Division is not a regex literal.
        assert_eq!(code_lines("$a = $b / 2 / 3", true)[0], "$a = $b / 2 / 3");
        // After a keyword, `/` opens a regex.
        assert_eq!(code_lines("not /ab/", true)[0], "not /  /");
        assert_eq!(code_lines("`raw\\` x", true)[0], "`    ` x");
    }

    #[test]
    fn section_lines_drop_leading_and_trailing_blank_lines_only() {
        let (lines, dropped) = section_lines("\r\n  \n$e.a = 1\r\n\n  $e.b = 2  \n\n");
        assert_eq!(lines, ["$e.a = 1", "", "  $e.b = 2  "]);
        assert_eq!(dropped, 2);
        assert_eq!(section_lines("   ").0, Vec::<String>::new());
    }

    #[test]
    fn headers_and_labels_are_found_outside_literals() {
        assert_eq!(section_header_line("$e\nevents:\n"), Some(2));
        assert_eq!(section_header_line("RULE abc {\n$e"), Some(1));
        assert_eq!(section_header_line("$e\n}\n"), Some(2));
        assert_eq!(section_header_line("$e.a = \"events:\""), None);
        assert_eq!(section_header_line("// condition:\n$e"), None);
    }

    #[test]
    fn event_variables_in_order() {
        assert_eq!(
            event_variables("$b.x = 1\n$a.y = $b.z\n// $c.q\n"),
            ["b", "a"]
        );
    }

    #[test]
    fn identifiers_and_keywords() {
        assert!(is_identifier("password_spray"));
        assert!(!is_identifier("Any"));
        assert!(!is_identifier("1abc"));
        assert!(!is_identifier("a-b"));
        assert!(!is_identifier(""));
    }

    #[test]
    fn windows() {
        assert_eq!(window_minutes("30m"), Some(30));
        assert_eq!(window_minutes("2h"), Some(120));
        assert_eq!(window_minutes("14d"), Some(14 * 1440));
        assert_eq!(window_minutes("0m"), None);
        assert_eq!(window_minutes("10s"), None);
        assert_eq!(window_minutes("m"), None);
        assert_eq!(window_minutes("1é"), None);
    }

    #[test]
    fn sections_missing_empty_and_with_headers() {
        let block = yaml("events: |\n  events:\n  $e\nsetup:\noutcome: [a]\nexport: \"  \"\n");
        assert_eq!(
            codes(&section_findings(&block)),
            [
                ("yaral_section_missing", "condition".to_owned()),
                ("yaral_section_empty", "setup".to_owned()),
                ("yaral_section_header", "events".to_owned()),
                ("yaral_section_empty", "outcome".to_owned()),
                ("yaral_section_empty", "export".to_owned()),
            ]
        );
        let findings = section_findings(&block);
        assert!(
            findings[1].message.ends_with("(|)"),
            "{}",
            findings[1].message
        );
        assert_eq!(
            findings[3].message,
            "outcome is YARA-L text, not a YAML list: write it as a block scalar (|)"
        );
        assert!(findings[2].message.contains("(line 1)"));
    }

    #[test]
    fn match_shapes() {
        let ok = yaml("group_by: [$user, $ip]\nwindow: 30m\n");
        assert!(match_findings(&ok).is_empty());
        assert_eq!(render_match(&ok).as_deref(), Some("$user, $ip over 30m"));
        let sliding =
            yaml("group_by: [$u]\nwindow: 1h\ntype: sliding\npivot: $e\ndirection: after\n");
        assert!(match_findings(&sliding).is_empty());
        assert_eq!(
            render_match(&sliding).as_deref(),
            Some("$u over 1h after $e")
        );
        let tumbling = yaml("group_by: [$u]\nwindow: 73h\ntype: tumbling\n");
        assert_eq!(
            codes(&match_findings(&tumbling)),
            [("yaral_match_window", "match.window".to_owned())]
        );
        assert_eq!(
            match_findings(&tumbling)[0].message,
            "window 73h: a tumbling window in a rule is at most 72h"
        );
        assert_eq!(render_match(&tumbling).as_deref(), Some("$u by 73h"));
        let bad =
            yaml("group_by: [$u, $u]\nwindow: 15d\ntype: hopping\npivot: $e\nzeta: 1\nalpha: 2\n");
        assert_eq!(
            codes(&match_findings(&bad)),
            [
                ("yaral_match_shape", "match.alpha".to_owned()),
                ("yaral_match_shape", "match.group_by".to_owned()),
                ("yaral_match_shape", "match.type".to_owned()),
                ("yaral_match_shape", "match.pivot".to_owned()),
                ("yaral_match_window", "match.window".to_owned()),
            ]
        );
        let found = match_findings(&bad);
        assert_eq!(
            found[0].message,
            "unknown match key(s) alpha, zeta: match takes group_by, window, type, pivot and direction"
        );
        assert_eq!(
            found[2].message,
            "type \"hopping\" is not hop, tumbling or sliding"
        );
        assert_eq!(
            found[4].message,
            "window 15d: a hop window in a rule is at most 14d"
        );
        let no_pivot = yaml("group_by: [$u]\nwindow: 1h\ntype: sliding\n");
        assert_eq!(
            codes(&match_findings(&no_pivot)),
            [("yaral_match_shape", "match".to_owned())]
        );
        let missing = yaml("[a]");
        assert_eq!(
            codes(&match_findings(&missing)),
            [("yaral_match_shape", "match".to_owned())]
        );
        let no_window = yaml("group_by: [$u]\n");
        assert_eq!(
            match_findings(&no_window)[0].message,
            "window None is not a duration in m, h or d (10m, 1h, 2d)"
        );
        assert_eq!(render_match(&no_window), None);
    }

    /// A boolean in `match` is refused, and deploy writes it as YARA-L spells
    /// it, never Python's `True`.
    #[test]
    fn a_boolean_in_match_is_written_lowercase() {
        let flagged =
            yaml("group_by: [true]\nwindow: 1h\ntype: sliding\npivot: $e\ndirection: false\n");
        assert_eq!(
            codes(&match_findings(&flagged)),
            [
                ("yaral_match_shape", "match.group_by".to_owned()),
                ("yaral_match_shape", "match".to_owned()),
            ]
        );
        assert_eq!(
            render_match(&flagged).as_deref(),
            Some("true over 1h false $e")
        );
    }

    #[test]
    fn options() {
        let ok = yaml("suppression_window: 1h\nallow_zero_values: true\n");
        assert!(options_findings(&ok).is_empty());
        assert_eq!(
            render_options(&ok),
            ["allow_zero_values = true", "suppression_window = 1h"]
        );
        let bad = yaml("allow_zero_values: 'yes'\nsuppression_window: 10s\nother: 1\nx:\n");
        let found = options_findings(&bad);
        assert_eq!(
            codes(&found),
            [
                ("yaral_option", "options.allow_zero_values".to_owned()),
                ("yaral_option", "options.suppression_window".to_owned()),
                ("yaral_option", "options.other".to_owned()),
            ]
        );
        assert_eq!(
            found[0].message,
            "options.allow_zero_values is true or false, not \"yes\""
        );
        assert_eq!(
            found[2].message,
            "\"other\" is not an option: options takes allow_zero_values and suppression_window"
        );
        assert_eq!(
            codes(&options_findings(&yaml("[1]"))),
            [("yaral_option", "options".to_owned())]
        );
    }
}
