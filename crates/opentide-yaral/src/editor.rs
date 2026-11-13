//! Editor features for YARA-L: hover with the UDM type and Google's function
//! documentation, completion of UDM paths, enum values and functions, and
//! signature help. Offsets are bytes; the host converts editor positions.

use crate::catalog::{Field, Function, Functions, Segment, TypeKind, Udm, is_keyword};
use opentide_core::{
    CompletionItem, LanguageId, ParameterInformation, SignatureHelp, SignatureInformation,
};

/// Outcome names Google gives a meaning (yara-l-1.0 "outcome").
const PLATFORM_OUTCOMES: &[(&str, &str)] = &[
    (
        "$risk_score",
        "The alert's risk score, stored in `security_result.risk_score`. Google defaults it to 40 on an alerting rule and 15 otherwise.",
    ),
    (
        "$risk_entity_to_score",
        "The user or asset the risk score is attributed to.",
    ),
    (
        "$suppression_key",
        "The key `options: suppression_window` suppresses on, for single-event rules.",
    ),
];

const SECTIONS: &[&str] = &[
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

fn type_label(udm: &Udm, field: &Field) -> String {
    let base = match udm.kind_of(field) {
        TypeKind::Enum(name, _) => format!("enum {name}"),
        TypeKind::Message(m) => m.name.clone(),
        TypeKind::Scalar(s) => s.to_string(),
        TypeKind::Free => {
            if field.ty.is_empty() {
                "unspecified".to_string()
            } else {
                field.ty.clone()
            }
        }
    };
    if field.repeated {
        format!("repeated {base}")
    } else {
        base
    }
}

fn function_markdown(f: &Function) -> String {
    let mut out = format!("```yaral\n{}\n```\n\n", f.signature);
    if !f.summary.is_empty() {
        out.push_str(&f.summary);
        out.push_str("\n\n");
    }
    if let Some(result) = &f.result {
        out.push_str(&format!("Returns `{result}`. "));
    }
    if !f.availability.is_empty() {
        out.push_str(&format!("Available in: {}.", f.availability.join(", ")));
    }
    if !f.url.is_empty() {
        out.push_str(&format!("\n\n[Google SecOps documentation]({})", f.url));
    }
    out
}

fn field_markdown(udm: &Udm, path: &str, field: &Field) -> String {
    let mut out = format!("**{path}**: `{}`", type_label(udm, field));
    if field.deprecated {
        out.push_str(" (deprecated)");
    }
    if let Some(doc) = field.doc.as_deref().filter(|d| !d.is_empty()) {
        out.push_str("\n\n");
        out.push_str(doc);
    }
    if let TypeKind::Enum(_, values) = udm.kind_of(field) {
        let shown: Vec<String> = values.iter().take(12).map(|v| format!("`{v}`")).collect();
        let more = if values.len() > 12 {
            format!(", and {} more", values.len() - 12)
        } else {
            String::new()
        };
        out.push_str(&format!("\n\nValues: {}{more}.", shown.join(", ")));
    }
    out
}

/// Hover at byte `offset`.
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let tree = opentide_syntax::parse(LanguageId::Yaral, source)?;
    let node = tree
        .root_node()
        .named_descendant_for_byte_range(offset, offset)?;
    let parent = node.parent();
    let text = |n: tree_sitter::Node<'_>| &source[n.byte_range()];
    match (node.kind(), parent.map(|p| p.kind())) {
        ("field_name", Some("udm_field" | "bare_field")) => {
            let field = parent?;
            let mut segs = Vec::new();
            if field.kind() == "bare_field"
                && let Some(root) = field.child_by_field_name("root")
            {
                segs.push(Segment::Name(
                    text(root).to_string(),
                    (root.start_byte(), root.end_byte()),
                ));
            }
            for s in crate::check::segments(field, source) {
                if matches!(&s, Segment::Name(_, at) if at.0 == segs.first().map_or(usize::MAX, |f: &Segment| match f { Segment::Name(_, a) => a.0, _ => usize::MAX }))
                {
                    continue;
                }
                let past = match &s {
                    Segment::Name(_, at) | Segment::Key(at) | Segment::Position(at) => {
                        at.0 > node.start_byte()
                    }
                };
                if past {
                    break;
                }
                segs.push(s);
            }
            let udm = Udm::cached();
            let path: Vec<&str> = segs
                .iter()
                .filter_map(|s| match s {
                    Segment::Name(n, _) => Some(n.as_str()),
                    _ => None,
                })
                .collect();
            if path.len() == 1
                && let Some((name, doc)) = Udm::SOURCES.iter().find(|(n, _)| *n == path[0])
            {
                return Some(format!("**{name}**: {doc}"));
            }
            let resolution = udm.resolve(&segs);
            let field_row = resolution.field?;
            if resolution.unknown.is_some() {
                return None;
            }
            Some(field_markdown(udm, &path.join("."), field_row))
        }
        ("name" | "namespace", Some("function_name")) | ("function_name", _) => {
            let call = if node.kind() == "function_name" {
                node
            } else {
                parent?
            };
            let name: String = text(call).split_whitespace().collect();
            let functions = Functions::cached();
            if node.kind() == "namespace" && functions.get(&name).is_none() {
                return None;
            }
            functions.get(&name).map(function_markdown)
        }
        ("variable", _) => {
            let name = text(node);
            PLATFORM_OUTCOMES
                .iter()
                .find(|(n, _)| {
                    *n == name
                        || (name.starts_with("$risk_entity_to_score_")
                            && *n == "$risk_entity_to_score")
                })
                .map(|(n, doc)| format!("**{n}**: {doc}"))
        }
        ("reference_list", _) => Some(format!(
            "**{}**: a reference list. Google retires reference lists in 2027: use a data table (`%table.column`). Its contents live in the tenant.",
            text(node)
        )),
        _ => None,
    }
}

/// The path being typed before `offset`: its root and its complete
/// segments, and the partial last segment.
struct Typed {
    root: String,
    segments: Vec<Segment>,
    partial: String,
}

fn typed_path(before: &str) -> Option<Typed> {
    let start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '[' | ']' | '"')
        })
        .last()
        .map(|(i, _)| i)?;
    let token = &before[start..];
    if !token.contains('.') {
        return None;
    }
    let (head, partial) = token.rsplit_once('.')?;
    let mut parts = head.split('.');
    let root = parts.next()?.to_string();
    let mut segments = Vec::new();
    let push_name = |name: &str, segments: &mut Vec<Segment>| {
        let (name, rest) = name.split_once('[').map_or((name, ""), |(n, r)| (n, r));
        if !name.is_empty() {
            segments.push(Segment::Name(name.to_string(), (0, 0)));
        }
        for index in rest.split('[') {
            let index = index.trim_end_matches(']');
            if index.is_empty() {
                continue;
            }
            if index.starts_with('"') {
                segments.push(Segment::Key((0, 0)));
            } else {
                segments.push(Segment::Position((0, 0)));
            }
        }
    };
    if !root.starts_with('$') {
        push_name(&root, &mut segments);
    } else if let Some((_, rest)) = root.split_once('[') {
        push_name(&format!("[{rest}"), &mut segments);
    }
    for part in parts {
        push_name(part, &mut segments);
    }
    Some(Typed {
        root,
        segments,
        partial: partial.to_string(),
    })
}

fn field_item(udm: &Udm, field: &Field) -> CompletionItem {
    let mut item =
        CompletionItem::new(field.name.clone(), "field").with_detail(type_label(udm, field));
    if let Some(doc) = field.doc.as_deref().filter(|d| !d.is_empty()) {
        item = item.with_docs(doc.to_string());
    }
    item
}

/// Completion at byte `offset`.
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let offset = offset.min(source.len());
    let before = &source[..offset];
    let line = before.rsplit('\n').next().unwrap_or(before);
    let udm = Udm::cached();
    let functions = Functions::cached();

    // An enum value after `<path> =` or `<path> !=`.
    if let Some(items) = enum_values(line) {
        return items;
    }

    if let Some(typed) = typed_path(line) {
        // A function of a namespace: `strings.`.
        if !typed.root.starts_with('$')
            && typed.segments.len() == 1
            && functions.is_namespace(&typed.root)
        {
            return functions
                .in_namespace(&typed.root)
                .map(|f| {
                    CompletionItem::new(f.short_name().to_string(), "function")
                        .with_detail(f.signature.clone())
                        .with_docs(function_markdown(f))
                })
                .collect();
        }
        let mut items = Vec::new();
        if typed.segments.is_empty() {
            for (name, doc) in Udm::SOURCES {
                items.push(CompletionItem::new(*name, "module").with_detail(doc.to_string()));
            }
        }
        if let Some(message) = udm.members(&typed.segments) {
            items.extend(message.fields.iter().map(|f| field_item(udm, f)));
        }
        let _ = &typed.partial;
        return items;
    }

    // Anything else: sections at the start of a line, keywords, functions,
    // the variables the text already uses.
    let mut items = Vec::new();
    let at_line_start = line
        .trim_start()
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if at_line_start {
        for s in SECTIONS {
            items.push(CompletionItem::new(format!("{s}:"), "keyword"));
        }
    }
    for kw in [
        "and", "or", "not", "nocase", "in", "regex", "cidr", "any", "all", "over", "by", "before",
        "after", "if", "of", "true", "false",
    ] {
        items.push(CompletionItem::new(kw, "keyword"));
    }
    let mut namespaces: Vec<&str> = functions
        .all()
        .filter_map(|f| f.namespace.as_deref())
        .collect();
    namespaces.sort_unstable();
    namespaces.dedup();
    for ns in namespaces {
        items.push(CompletionItem::new(ns, "module").with_detail("YARA-L function namespace"));
    }
    for f in functions.all().filter(|f| f.namespace.is_none()) {
        items.push(
            CompletionItem::new(f.name.clone(), "function")
                .with_detail(f.signature.clone())
                .with_docs(function_markdown(f)),
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for word in source.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$')) {
        if word.len() > 1 && word.starts_with('$') && !is_keyword(&word[1..]) && seen.insert(word) {
            items.push(CompletionItem::new(word, "variable"));
        }
    }
    items
}

/// The values of the enumerated field compared on `line`, if the cursor is
/// where its value goes.
fn enum_values(line: &str) -> Option<Vec<CompletionItem>> {
    let trimmed = line.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    let quoted = trimmed.ends_with('"');
    let trimmed = trimmed.trim_end_matches('"').trim_end();
    let trimmed = trimmed
        .strip_suffix("!=")
        .or_else(|| trimmed.strip_suffix('='))?
        .trim_end();
    let typed = typed_path(&format!("{trimmed}.x"))?;
    let mut segments = typed.segments;
    if let Some(Segment::Name(last, _)) = segments.last()
        && last == "x"
    {
        segments.pop();
    }
    let resolution = Udm::cached().resolve(&segments);
    let Some(TypeKind::Enum(name, values)) = resolution.kind else {
        return None;
    };
    Some(
        values
            .iter()
            .map(|v| {
                let label = if quoted {
                    v.clone()
                } else {
                    format!("\"{v}\"")
                };
                CompletionItem::new(label, "enum").with_detail(name.to_string())
            })
            .collect(),
    )
}

/// Signature help at byte `offset`: the call whose parentheses hold it.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a call has far fewer than 2^32 arguments"
)]
pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let offset = offset.min(source.len());
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut commas = 0u32;
    let mut i = offset;
    let mut in_string = false;
    while i > 0 {
        i -= 1;
        let c = bytes[i];
        if c == b'"' || c == b'`' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match c {
            b')' | b']' => depth += 1,
            b'[' if depth > 0 => depth -= 1,
            b'(' if depth > 0 => depth -= 1,
            b'(' => break,
            b',' if depth == 0 => commas += 1,
            b'\n' if depth == 0 && i + 1 < offset && source[i + 1..offset].trim().is_empty() => {}
            _ => {}
        }
        if i == 0 {
            return None;
        }
    }
    if bytes.get(i) != Some(&b'(') {
        return None;
    }
    let head = source[..i].trim_end();
    let name_start = head
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
        .last()
        .map(|(j, _)| j)?;
    let name = &head[name_start..];
    let function = Functions::cached().get(name)?;
    let parameters: Vec<ParameterInformation> = function
        .parameters()
        .into_iter()
        .map(|p| ParameterInformation {
            label: p,
            documentation: None,
        })
        .collect();
    let last = parameters.len().saturating_sub(1) as u32;
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: function.signature.clone(),
            documentation: Some(function_markdown(function)),
            parameters,
        }],
        active_signature: 0,
        active_parameter: commas.min(last),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(items: &[CompletionItem]) -> Vec<&str> {
        items.iter().map(|i| i.label.as_str()).collect()
    }

    #[test]
    fn udm_paths_complete_after_a_variable() {
        let source = "rule r {\n  events:\n    $e.";
        let items = completions(source, source.len());
        assert!(labels(&items).contains(&"metadata"), "{:?}", labels(&items));
        assert!(labels(&items).contains(&"graph"));
        let source = "rule r {\n  events:\n    $e.principal.process.";
        let items = completions(source, source.len());
        assert!(
            labels(&items).contains(&"command_line"),
            "{:?}",
            labels(&items)
        );
        let source = "metadata.event_type = \"USER_LOGIN\"\nprincipal.";
        assert!(labels(&completions(source, source.len())).contains(&"hostname"));
    }

    #[test]
    fn enum_values_complete_after_a_comparison() {
        let source = "rule r {\n  events:\n    $e.metadata.event_type = ";
        let items = completions(source, source.len());
        assert!(
            labels(&items).contains(&"\"PROCESS_LAUNCH\""),
            "{:?}",
            labels(&items)
        );
        let source = "rule r {\n  events:\n    $e.metadata.event_type = \"PROC";
        let items = completions(source, source.len());
        assert!(labels(&items).contains(&"PROCESS_LAUNCH"));
    }

    #[test]
    fn functions_complete_after_a_namespace() {
        let source = "rule r {\n  events:\n    $x = strings.";
        let items = completions(source, source.len());
        assert!(labels(&items).contains(&"to_lower"), "{:?}", labels(&items));
    }

    #[test]
    fn hover_shows_udm_types_and_function_docs() {
        let source = "rule r {\n  meta:\n    a = \"b\"\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n    $h = strings.to_lower($e.principal.hostname)\n  condition:\n    $e\n}\n";
        let at = source.find("event_type").unwrap() + 2;
        let h = hover(source, at).expect("hover");
        assert!(
            h.contains("metadata.event_type") && h.contains("enum"),
            "{h}"
        );
        let at = source.find("to_lower").unwrap() + 2;
        let h = hover(source, at).expect("hover");
        assert!(
            h.contains("strings.to_lower(") && h.contains("rules"),
            "{h}"
        );
    }

    #[test]
    fn signature_help_tracks_the_argument() {
        let source = "rule r {\n  events:\n    re.regex($e.principal.hostname, ";
        let help = signature_help(source, source.len()).expect("help");
        assert!(help.signatures[0].label.starts_with("re.regex("));
        assert_eq!(help.active_parameter, 1);
    }
}
