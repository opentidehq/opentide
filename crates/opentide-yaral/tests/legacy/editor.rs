//! The tree-sitter hover (was in `src/editor.rs`, with the helpers it calls).
//! Completions and signature help read the text, not the tree: they stayed in
//! the library, and the differential calls them for both sides.

use opentide_core::LanguageId;
use opentide_yaral::catalog::{Field, Function, Functions, Segment, TypeKind, Udm};

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
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset.min(source.len())) {
        return None;
    }
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
            for s in super::check::segments(field, source) {
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
