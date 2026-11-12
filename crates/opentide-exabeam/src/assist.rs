//! Hover and completion for the Exabeam Query Language, from the CIM
//! catalogue: fields, the values of `activity_type`, `subject` and
//! `outcome`, the functions and the keywords.

use crate::catalog::{ActivityType, Catalog, Field, Subject};
use opentide_core::CompletionItem;

const SEARCH_GUIDE: &str = "https://docs.exabeam.com/en/search/all/search-guide/";

/// The functions of the language, with what each does (exabeam-1.0).
pub const FUNCTIONS: [(&str, &str, &str); 10] = [
    (
        "RGX",
        "RGX(\"pattern\")",
        "Matches an RE2 regular expression, case-sensitively.",
    ),
    (
        "RGXi",
        "RGXi(\"pattern\")",
        "Matches an RE2 regular expression, case-insensitively.",
    ),
    (
        "WLD",
        "WLD(\"pattern\")",
        "Matches a wildcard pattern (`*` any run, `?` one character), case-sensitively.",
    ),
    (
        "WLDi",
        "WLDi(\"pattern\")",
        "Matches a wildcard pattern (`*` any run, `?` one character), case-insensitively.",
    ),
    (
        "COUNT",
        "COUNT(field | *)",
        "Search only: counts the values of a field, or the events with `*`.",
    ),
    (
        "MIN",
        "MIN(field)",
        "Search only: the smallest value of a field.",
    ),
    (
        "MAX",
        "MAX(field)",
        "Search only: the largest value of a field.",
    ),
    (
        "SUM",
        "SUM(field)",
        "Search only: the sum of a field's values.",
    ),
    (
        "AVG",
        "AVG(field)",
        "Search only: the average of a field's values.",
    ),
    (
        "RGX_EXTRACT",
        "RGX_EXTRACT([field,] \"pattern\")",
        "Search only: extracts the first capture group of an RE2 pattern into a column. At most three per query; Exabeam cannot convert such a search into a rule.",
    ),
];

/// The keywords, with what each does.
pub const KEYWORDS: [(&str, &str); 16] = [
    (
        "AND",
        "Both sides match. Two terms side by side are also an AND.",
    ),
    (
        "OR",
        "Either side matches. `AND` binds tighter: add parentheses.",
    ),
    (
        "NOT",
        "The term does not match. Write `AND NOT` or `OR NOT` after a term.",
    ),
    ("TO", "Separates the bounds of a range: `[low TO high]`."),
    (
        "IN",
        "A context table lookup: `field IN \"Table\"` or `field IN \"Table\".\"Column\"`. At most two per query, joined by AND.",
    ),
    ("SELECT", "Search only: the columns a search returns."),
    ("DISTINCT", "Search only: drop duplicate rows."),
    ("FROM", "Search only: the source a statement reads."),
    (
        "WHERE",
        "Search only: the filter. A bare filter is an implicit WHERE.",
    ),
    ("AS", "Search only: names a column or a statement."),
    ("GROUP-BY", "Search only: groups rows by the listed fields."),
    ("ORDER-BY", "Search only: sorts rows by the listed fields."),
    ("ASC", "Search only: ascending order."),
    ("DESC", "Search only: descending order."),
    ("LIMIT", "Search only: at most this many rows."),
    (
        "FOREACH",
        "Search only: runs a sub-query for each value of a field of the preceding result, `@field` being the current value.",
    ),
];

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')
}

/// The word around byte `offset`, and its span.
fn word_around(source: &str, offset: usize) -> Option<(&str, usize, usize)> {
    let offset = offset.min(source.len());
    let before = source.get(..offset)?;
    let start = opentide_core::word_start(before, word_char);
    let end = offset
        + source[offset..]
            .char_indices()
            .find(|(_, c)| !word_char(*c))
            .map_or(source.len() - offset, |(i, _)| i);
    (end > start).then(|| (&source[start..end], start, end))
}

/// The field a value at `start` belongs to: the name before `:` or `=`.
fn field_before(source: &str, start: usize) -> Option<&str> {
    let head = source[..start]
        .trim_end()
        .trim_end_matches(['"', '\''])
        .trim_end()
        .trim_end_matches('(')
        .trim_end();
    let head = head.strip_suffix(':').or_else(|| head.strip_suffix('='))?;
    let head = head.trim_end().trim_end_matches('=');
    let begin = opentide_core::word_start(head, word_char);
    let name = &head[begin..];
    (!name.is_empty()).then_some(name)
}

pub fn field_markdown(f: &Field) -> String {
    let origin = if f.platform {
        "Exabeam platform field"
    } else {
        "Exabeam Common Information Model"
    };
    format!(
        "```exabeam\n{}\n```\n_{}_ · {origin}\n\n{}",
        f.name, f.ty, f.description
    )
}

fn activity_markdown(a: &ActivityType) -> String {
    format!(
        "**{}** (`activity_type`)\n\n{}: subject `{}`, activity `{}`; outcomes {}.",
        a.name,
        if a.pretty_name.is_empty() {
            a.name.as_str()
        } else {
            a.pretty_name.as_str()
        },
        a.subject,
        a.activity,
        a.outcomes
            .iter()
            .map(|o| format!("`{o}`"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn subject_markdown(s: &Subject) -> String {
    if s.description.is_empty() {
        format!("**{}** (`subject`)", s.name)
    } else {
        format!("**{}** (`subject`)\n\n{}", s.name, s.description)
    }
}

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let catalog = Catalog::cached();
    let (word, start, end) = word_around(source, offset)?;
    let quoted = start > 0
        && matches!(source.as_bytes()[start - 1], b'"' | b'\'')
        && source
            .as_bytes()
            .get(end)
            .is_some_and(|b| matches!(b, b'"' | b'\''));
    if quoted {
        let field = field_before(source, start)?.to_lowercase();
        return match field.as_str() {
            "activity_type" => catalog.activity_type(word).map(activity_markdown),
            "subject" => catalog.subject(word).map(subject_markdown),
            "outcome"
                if catalog
                    .outcomes
                    .iter()
                    .any(|o| o.eq_ignore_ascii_case(word)) =>
            {
                Some(format!("**{word}** (`outcome`)"))
            }
            _ => None,
        };
    }
    let next = source[end..].trim_start();
    let upper = word.to_uppercase();
    if next.starts_with('(')
        && let Some((name, signature, doc)) =
            FUNCTIONS.iter().find(|(n, ..)| n.to_uppercase() == upper)
    {
        return Some(format!(
            "```exabeam\n{signature}\n```\n\n{doc}\n\n[Exabeam Search guide]({SEARCH_GUIDE}) · `{name}`"
        ));
    }
    if let Some((keyword, doc)) = KEYWORDS.iter().find(|(k, _)| *k == upper) {
        return Some(format!("`{keyword}`: {doc}"));
    }
    if let Some(f) = catalog.field(word) {
        return Some(field_markdown(f));
    }
    if let Some((prefix, rest)) = word.split_at_checked(2)
        && !rest.is_empty()
        && let Some(p) = catalog.prefix(prefix)
    {
        return Some(format!("```exabeam\n{word}\n```\n\n{}", p.description));
    }
    None
}

/// Completion at byte `offset` of `source`: the values of `activity_type`,
/// `subject` and `outcome` after their operator; otherwise fields, functions
/// and keywords.
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
    let offset = offset.min(source.len());
    let Some(before) = source.get(..offset) else {
        return Vec::new();
    };
    let start = opentide_core::word_start(before, word_char);
    if let Some(field) = field_before(source, start) {
        match field.to_lowercase().as_str() {
            "activity_type" => {
                return catalog
                    .activity_types
                    .iter()
                    .map(|a| {
                        CompletionItem::new(a.name.clone(), "enum")
                            .with_detail(a.pretty_name.clone())
                    })
                    .collect();
            }
            "subject" => {
                return catalog
                    .subjects
                    .iter()
                    .map(|s| CompletionItem::new(s.name.clone(), "enum"))
                    .collect();
            }
            "outcome" => {
                return catalog
                    .outcomes
                    .iter()
                    .map(|o| CompletionItem::new(o.clone(), "enum"))
                    .collect();
            }
            _ => return Vec::new(),
        }
    }
    let mut items: Vec<CompletionItem> = catalog
        .fields
        .iter()
        .map(|f| CompletionItem::new(f.name.clone(), "field").with_detail(f.ty.clone()))
        .collect();
    items.extend(FUNCTIONS.iter().map(|(name, signature, _)| {
        CompletionItem::new(*name, "function").with_detail(*signature)
    }));
    items.extend(
        KEYWORDS
            .iter()
            .map(|(k, _)| CompletionItem::new(*k, "keyword")),
    );
    items
}
