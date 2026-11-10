//! Falco's terms, as the Sysdig block's constraints judge them
//! (`sysdig-1.0`, "Constraints"; the oracle's `SysdigConfig` validator and
//! `platforms/sysdig/expansion.py`): the operators, modifiers, priorities,
//! keywords, and the string rules over them.
//!
//! One copy for both engines: opentide-schema's `sysdig_rule_shape` (the
//! CLI's model, on the YAML node tree) and opentide-tide's `sysdig` module
//! (the language server's findings, on `serde_yaml` values) call these, so
//! the editor and `validate` cannot drift apart on an operator, a priority
//! or a name. What each keeps is how it walks its own value type and where
//! it places a finding.

/// Falco's priorities, lower case (`sysdig_priority`).
pub const PRIORITIES: [&str; 9] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "info",
    "debug",
];

/// Keys a tuning inherits from the rule it tunes (`sysdig_tuning_keys`).
pub const TUNING_FORBIDDEN: [&str; 5] = ["output", "priority", "policies", "source", "name"];

/// `parser::supported_operators()`: Falco's comparison operators.
pub const OPERATORS: [&str; 20] = [
    "exists",
    "<=",
    "<",
    ">=",
    ">",
    "==",
    "=",
    "!=",
    "glob",
    "iglob",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "regex",
    "intersects",
    "in",
    "pmatch",
];

/// Operators whose right-hand side is a value list.
pub const LIST_OPERATORS: [&str; 3] = ["intersects", "in", "pmatch"];

/// `cmpop_supports_modifier`: the operators a [`MODIFIERS`] word may follow.
pub const MODIFIABLE_OPERATORS: [&str; 12] = [
    "=",
    "==",
    "!=",
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
];

/// The modifiers a [`MODIFIABLE_OPERATORS`] operator takes (`= oneof`).
pub const MODIFIERS: [&str; 3] = ["oneof", "anyof", "allof"];

/// Words that never name a block macro or list: the keywords and the
/// operators written as words.
pub const RESERVED_WORDS: [&str; 6] = ["and", "or", "not", "in", "exists", "val"];

/// Falco's blanks (`resolve_list`, `normalize_comp`): ASCII space, tab and
/// the two line ends.
pub const BLANKS: [char; 4] = [' ', '\t', '\n', '\r'];

/// Python's `str.isspace()` for one character: Unicode's `White_Space`
/// (Rust's `char::is_whitespace`) and the four separators U+001C to U+001F,
/// which Python counts as whitespace too.
pub fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// Python's `text.strip()`.
pub fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

/// A string with nothing but whitespace, by Python's `str.strip()` (the
/// oracle's `_non_blank`, negated).
pub fn is_blank(text: &str) -> bool {
    python_strip(text).is_empty()
}

/// Falco's `normalize_comp`: leading and trailing [`BLANKS`] stripped.
pub fn normalize_comp(comp: &str) -> &str {
    comp.trim_matches(BLANKS)
}

/// Falco's `is_str_operator_with_modifier`: `<op> oneof|anyof|allof`, split
/// at the first space.
pub fn is_modified_operator(op: &str) -> bool {
    op.split_once(' ').is_some_and(|(head, modifier)| {
        MODIFIABLE_OPERATORS.contains(&head) && MODIFIERS.contains(&modifier)
    })
}

/// An operator an exception's `comps` may use.
pub fn is_exception_operator(op: &str) -> bool {
    OPERATORS.contains(&op) || is_modified_operator(op)
}

/// Falco's `is_operator_for_list`: the comparison takes a value list.
pub fn is_list_comparison(op: &str) -> bool {
    LIST_OPERATORS.contains(&op) || is_modified_operator(op)
}

/// `sysdig_definition_name`: `[A-Za-z_][A-Za-z0-9_]*`, not a keyword, and not
/// an operator written as a word.
pub fn definition_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !RESERVED_WORDS.contains(&name)
        && !(OPERATORS.contains(&name) && name.chars().all(char::is_alphabetic))
}

/// `sysdig_priority`: a Falco priority, any case, around whitespace.
pub fn priority_ok(text: &str) -> bool {
    PRIORITIES.contains(&python_strip(text).to_lowercase().as_str())
}

/// `sysdig_source`: a Falco event source name, `[a-z][a-z0-9_]*`.
pub fn source_ok(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

/// `resolve_list`'s blanks ([`BLANKS`]).
fn blank(ch: char) -> bool {
    BLANKS.contains(&ch)
}

/// `resolve_list`'s delimiters: the blanks, `(`, `)`, `,` and `=`.
fn delimiter(ch: char) -> bool {
    blank(ch) || matches!(ch, '(' | ')' | ',' | '=')
}

/// The first index at or after `from` where `name` occurs in `text`.
fn find(text: &[char], name: &[char], from: usize) -> Option<usize> {
    if name.is_empty() || from > text.len() {
        return None;
    }
    (from..=text.len().saturating_sub(name.len()))
        .find(|&at| at + name.len() <= text.len() && text[at..at + name.len()] == *name)
}

/// Whether `name` at `start..end` has a delimiter (or the text's edge) on
/// each side.
fn delimited(text: &[char], start: usize, end: usize) -> bool {
    (start == 0 || delimiter(text[start - 1])) && (end >= text.len() || delimiter(text[end]))
}

/// Falco's `quote_item`: double-quoted when it holds a space and is not
/// quoted already.
fn quote_item(item: &str) -> String {
    if item.contains(' ') && !item.starts_with(['"', '\'']) {
        format!("\"{item}\"")
    } else {
        item.to_owned()
    }
}

/// Falco's `resolve_list`: `name` replaced by `items` in `condition`, where it
/// occurs between delimiters. The blanks around an occurrence are consumed
/// and it becomes `" " + items + " "` (no leading blank at the start of the
/// text); an empty list removes one comma beside it, the left one first.
pub fn resolve_list(condition: &str, name: &str, items: &[String]) -> String {
    let name: Vec<char> = name.chars().collect();
    let mut text: Vec<char> = condition.chars().collect();
    let substitute: Vec<char> = items
        .iter()
        .map(|item| quote_item(item))
        .collect::<Vec<_>>()
        .join(", ")
        .chars()
        .collect();
    let mut next = find(&text, &name, 0);
    while let Some(found) = next {
        let mut start = found;
        let mut end = start + name.len();
        if delimited(&text, start, end) {
            while start > 0 && blank(text[start - 1]) {
                start -= 1;
            }
            while end < text.len() && blank(text[end]) {
                end += 1;
            }
            if substitute.is_empty() {
                if start > 0 && text[start - 1] == ',' {
                    start -= 1;
                } else if end < text.len() && text[end] == ',' {
                    end += 1;
                }
            }
            let mut replaced = Vec::with_capacity(text.len() + substitute.len() + 2);
            if start > 0 {
                replaced.extend_from_slice(&text[..start]);
                replaced.push(' ');
            }
            replaced.extend_from_slice(&substitute);
            replaced.push(' ');
            if end <= text.len() {
                replaced.extend_from_slice(&text[end..]);
            }
            text = replaced;
            start += substitute.len() + 1;
        }
        next = find(&text, &name, start + 1);
    }
    text.into_iter().collect()
}

/// `occurs`: whether [`resolve_list`] would replace an occurrence of `name`
/// in `text`.
pub fn occurs(text: &str, name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut next = find(&text, &name, 0);
    while let Some(start) = next {
        if delimited(&text, start, start + name.len()) {
            return true;
        }
        next = find(&text, &name, start + 1);
    }
    false
}

/// How many items a list or a value list may expand to, and (times 16) how
/// many bytes a macro's condition may grow to with the lists resolved: a
/// block whose lists name earlier lists over and over grows exponentially
/// (the oracle grew with it, without bound). Far above any rule; a bound so
/// a crafted file cannot exhaust memory.
pub const EXPANSION_LIMIT: usize = 100_000;

/// A dictionary's `d[name] = value`: replaced in place, or appended.
pub fn upsert<T>(entries: &mut Vec<(String, T)>, name: &str, value: T) {
    match entries.iter_mut().find(|(known, _)| known == name) {
        Some(entry) => entry.1 = value,
        None => entries.push((name.to_owned(), value)),
    }
}

/// Falco's `compile_list_infos` over a block's lists, in block order: an
/// item naming an earlier block list is that list's items. A later list of
/// the same name replaces the earlier one in place.
pub fn flatten_lists(lists: &[(String, Vec<String>)]) -> Vec<(String, Vec<String>)> {
    let mut flat: Vec<(String, Vec<String>)> = Vec::new();
    for (name, raw) in lists {
        let mut items = Vec::new();
        for item in raw {
            match flat.iter().find(|(known, _)| known == item) {
                Some((_, earlier)) => items.extend(earlier.iter().cloned()),
                None => items.push(item.clone()),
            }
            // Lists that name earlier lists twice over double at each step:
            // past the bound the rest cannot change a finding a file of sane
            // size can have.
            items.truncate(EXPANSION_LIMIT);
        }
        upsert(&mut flat, name, items);
    }
    flat
}

/// The oracle's `_passes`: a value list after Falco's `resolve_list` passes,
/// one per (flattened) block list in block order; a member equal to the
/// list's name becomes its items. Each member is its text, or `None` for a
/// list or a mapping, which no pass replaces.
pub fn value_passes(
    flat_lists: &[(String, Vec<String>)],
    values: Vec<Option<String>>,
) -> Vec<Option<String>> {
    let mut out = values;
    for (name, items) in flat_lists {
        let mut current = Vec::with_capacity(out.len());
        for value in out {
            match value {
                Some(text) if &text == name => current.extend(items.iter().cloned().map(Some)),
                other => current.push(other),
            }
        }
        current.truncate(EXPANSION_LIMIT);
        out = current;
    }
    out
}

/// The oracle's `_list_in`: the first block list whose name occurs inside
/// `text` between delimiters, but is not all of it.
pub fn list_inside<'a>(flat_lists: &'a [(String, Vec<String>)], text: &str) -> Option<&'a str> {
    flat_lists
        .iter()
        .map(|(name, _)| name.as_str())
        .find(|name| text != *name && occurs(text, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The expected texts are the oracle's (`expansion.resolve_list`).
    #[test]
    fn resolve_list_follows_falco() {
        assert_eq!(
            resolve_list("proc.name in (shells)", "shells", &items(&["bash", "sh"])),
            "proc.name in ( bash, sh )"
        );
        assert_eq!(
            resolve_list("shells", "shells", &items(&["a b"])),
            "\"a b\" "
        );
        // Not between delimiters: kept.
        assert_eq!(
            resolve_list("my_shells.x = 1", "shells", &items(&["bash"])),
            "my_shells.x = 1"
        );
        // An empty list removes a comma beside it, the left one first.
        assert_eq!(
            resolve_list("x in (a, shells)", "shells", &[]),
            "x in (a  )"
        );
        // The oracle's outputs (`expansion.resolve_list`, opentide 0.23.0):
        // `=` is a delimiter; an empty list with no comma to its left removes
        // the one to its right; an item already in quotes is kept as written,
        // space and all.
        assert_eq!(
            resolve_list("x=shells", "shells", &items(&["bash", "sh"])),
            "x= bash, sh "
        );
        assert_eq!(
            resolve_list("x in (shells, a)", "shells", &[]),
            "x in (   a)"
        );
        assert_eq!(
            resolve_list("x in (shells)", "shells", &items(&["\"a b\"", "'c d'"])),
            "x in ( \"a b\", 'c d' )"
        );
        assert!(occurs("run shells", "shells"));
        assert!(!occurs("run_shells", "shells"));
        assert!(!occurs("", "shells"));
    }

    #[test]
    fn lists_flatten_and_values_pass_in_block_order() {
        let lists = vec![
            ("l0".to_owned(), items(&["a"])),
            ("l1".to_owned(), items(&["x l0"])),
            ("l2".to_owned(), items(&["l1", "l0", "y"])),
        ];
        let flat = flatten_lists(&lists);
        assert_eq!(flat[2].1, items(&["x l0", "a", "y"]));
        let passed = value_passes(
            &flat,
            vec![Some("l2".to_owned()), None, Some("l1".to_owned())],
        );
        assert_eq!(
            passed,
            [Some("x l0"), Some("a"), Some("y"), None, Some("x l0")]
                .map(|value| value.map(str::to_owned))
        );
        assert_eq!(list_inside(&flat, "x l0"), Some("l0"));
        assert_eq!(
            list_inside(&flat, "l0"),
            None,
            "all of it is a list, not inside one"
        );
    }

    #[test]
    fn operators_and_modifiers() {
        assert!(is_modified_operator("= oneof"));
        assert!(is_modified_operator("contains allof"));
        assert!(!is_modified_operator("in oneof"), "in takes no modifier");
        assert!(
            !is_modified_operator("=  oneof"),
            "split at the first space"
        );
        assert!(is_exception_operator("pmatch"));
        assert!(is_exception_operator("startswith anyof"));
        assert!(!is_exception_operator("like"));
        assert!(is_list_comparison("intersects"));
        assert!(is_list_comparison("glob oneof"));
        assert!(!is_list_comparison("="));
        assert_eq!(normalize_comp(" \tin\r\n"), "in");
        assert_eq!(normalize_comp("\u{a0}in"), "\u{a0}in", "ASCII blanks only");
    }

    #[test]
    fn names_priorities_and_sources() {
        for name in ["m1", "_x", "shell_binaries", "Contains"] {
            assert!(definition_name_ok(name), "{name}");
        }
        for name in [
            "", "1m", "a-b", "and", "val", "contains", "pmatch", "exists", "é",
        ] {
            assert!(!definition_name_ok(name), "{name}");
        }
        assert!(priority_ok(" Warning "));
        assert!(priority_ok("INFO"));
        assert!(!priority_ok("warn"));
        assert!(source_ok("k8s_audit"));
        for source in ["", "1abc", "Syscall", "aws-cloudtrail"] {
            assert!(!source_ok(source), "{source}");
        }
        assert!(is_blank(" \u{1c}\u{2028}\t"));
        assert!(!is_blank(" x "));
    }
}
