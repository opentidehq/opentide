//! Hover, completion and signature help for CQL, from the catalogs.

use crate::catalog::{Catalog, Event, Field, Function, Parameter};
use crate::check::{call_name, name_text, unquote};
use crate::text;
use opentide_core::{
    CompletionItem, LanguageId, ParameterInformation, SignatureHelp, SignatureInformation,
};
use opentide_syntax::parse as ts_parse;
use tree_sitter::Node;

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    let tree = ts_parse(LanguageId::Cql, source)?;
    let catalog = Catalog::cached();
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let parent = node.parent();
    let is_field =
        |p: Node, field: &str| p.child_by_field_name(field).map(|n| n.id()) == Some(node.id());
    if let Some(p) = parent {
        if p.kind() == "function_call" && is_field(p, "name") {
            return catalog.function(text(node, source)).map(function_hover);
        }
        if p.kind() == "named_argument" && is_field(p, "name") {
            let call = p.parent().and_then(|list| list.parent())?;
            let function = catalog.function(call_name(call, source))?;
            let parameter = function.parameter(name_text(node, source))?;
            return Some(parameter_hover(function, parameter));
        }
        if p.kind() == "field_filter" && is_field(p, "value") {
            let field = p
                .child_by_field_name("field")
                .map(|f| unquote(text(f, source)))
                .unwrap_or("");
            if field == "#event_simpleName" || field == "event_simpleName" {
                if let Some(e) = catalog.event(unquote(text(node, source))) {
                    return Some(event_hover(e));
                }
            }
        }
    }
    if matches!(node.kind(), "field_name" | "tag" | "string") {
        return catalog.field(unquote(text(node, source))).map(field_hover);
    }
    None
}

fn function_hover(f: &Function) -> String {
    let mut out = format!("```cql\n{}\n```\n\n{}", f.signature(), f.docs);
    let mut facts = Vec::new();
    if f.aggregate {
        facts.push("Aggregate function.".to_string());
    }
    if f.removed {
        let mut s = "Removed from CQL".to_string();
        if let Some(r) = &f.replacement {
            s.push_str(&format!("; use `{r}()`"));
        }
        facts.push(s + ".");
    } else if f.deprecated {
        facts.push(format!(
            "Deprecated. {}",
            f.deprecated_note.as_deref().unwrap_or("")
        ));
    }
    if f.experimental {
        facts.push("Experimental.".to_string());
    }
    if f.logscale == Some(false) {
        facts.push("Next-Gen SIEM only.".to_string());
    }
    if let Some(since) = &f.since {
        facts.push(format!("Since LogScale {since}."));
    }
    if !facts.is_empty() {
        out.push_str("\n\n");
        out.push_str(facts.join(" ").trim());
    }
    out.push_str(&format!("\n\n[CrowdStrike docs]({})", f.citation));
    out
}

fn parameter_detail(p: &Parameter) -> String {
    let mut parts = vec![format!("_{}_", p.ty)];
    if p.required {
        parts.push("required".into());
    }
    if p.unnamed {
        parts.push("name may be omitted".into());
    }
    if let Some(d) = &p.default {
        parts.push(format!("default `{d}`"));
    }
    if !p.values.is_empty() {
        let values = p
            .values
            .iter()
            .map(|v| format!("`{v}`"))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(if p.values_open {
            format!("{values} or a number")
        } else {
            format!("one of {values}")
        });
    }
    match (p.min, p.max) {
        (Some(min), Some(max)) => parts.push(format!("{min}..{max}")),
        (Some(min), None) => parts.push(format!("at least {min}")),
        (None, Some(max)) => parts.push(format!("at most {max}")),
        (None, None) => {}
    }
    if p.deprecated {
        parts.push("deprecated".into());
    }
    parts.join(", ")
}

fn parameter_hover(f: &Function, p: &Parameter) -> String {
    format!(
        "`{}` of `{}()`: {}\n\n[CrowdStrike docs]({})",
        p.name,
        f.name,
        parameter_detail(p),
        f.citation
    )
}

fn layer_name(layer: &str) -> &str {
    match layer {
        "logscale" => "LogScale built-in",
        "falcon" => "Falcon",
        "cps" => "CrowdStrike Parsing Standard (ECS-based)",
        other => other,
    }
}

fn field_hover(f: &Field) -> String {
    let mut out = format!("`{}`: _{}_, {}", f.name, f.ty, layer_name(&f.layer));
    if let Some(docs) = &f.docs {
        out.push_str(&format!("\n\n{docs}"));
    }
    if !f.values.is_empty() {
        out.push_str(&format!("\n\nValues: {}", f.values.join(", ")));
    }
    out
}

fn event_hover(e: &Event) -> String {
    let mut out = format!("`{}`: Falcon sensor event", e.name);
    if !e.platforms.is_empty() {
        out.push_str(&format!(" ({})", e.platforms.join(", ")));
    }
    if !e.fields.is_empty() {
        let shown: Vec<&str> = e.fields.iter().take(24).map(String::as_str).collect();
        let more = if e.fields.len() > shown.len() {
            ", …"
        } else {
            ""
        };
        out.push_str(&format!("\n\nSeen with: {}{more}", shown.join(", ")));
    }
    out
}

/// A character of a function, parameter, field or tag name being typed.
fn word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | ':' | '#' | '@' | '.')
}

/// The innermost call left open before the cursor: its name, the text of its
/// argument list so far, and where that text starts.
fn open_call(before: &str) -> Option<(String, &str)> {
    let (code, open_string) = code_chars(before);
    if open_string {
        return None;
    }
    let mut stack: Vec<usize> = Vec::new();
    for (i, c) in code {
        match c {
            '(' => stack.push(i),
            ')' => {
                stack.pop();
            }
            _ => {}
        }
    }
    let open = *stack.last()?;
    let name_start = opentide_core::word_start(&before[..open], |c| {
        c.is_ascii_alphanumeric() || c == '_' || c == ':'
    });
    let name = &before[name_start..open];
    (!name.is_empty()).then(|| (name.to_string(), &before[open + 1..]))
}

/// The characters of `text` outside strings and comments, with their byte
/// offsets, and whether `text` ends inside a string or a comment. A comment
/// starts only where a token may, as in CQL: `https://x` is not one.
fn code_chars(text: &str) -> (Vec<(usize, char)>, bool) {
    #[derive(PartialEq)]
    enum In {
        Code,
        String { escaped: bool },
        Line,
        Block,
    }
    let mut state = In::Code;
    let mut out = Vec::new();
    let mut prev = ' ';
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let next = chars.peek().map(|&(_, n)| n);
        match state {
            In::String { escaped } => {
                state = if escaped {
                    In::String { escaped: false }
                } else if c == '\\' {
                    In::String { escaped: true }
                } else if c == '"' {
                    In::Code
                } else {
                    In::String { escaped: false }
                };
            }
            In::Line => {
                if c == '\n' {
                    state = In::Code;
                }
            }
            In::Block => {
                if c == '*' && next == Some('/') {
                    chars.next();
                    state = In::Code;
                }
            }
            In::Code => {
                let token_start = prev.is_whitespace() || "|([{,;=".contains(prev);
                if c == '/' && token_start && next == Some('/') {
                    state = In::Line;
                } else if c == '/' && token_start && next == Some('*') {
                    chars.next();
                    state = In::Block;
                } else if c == '"' {
                    state = In::String { escaped: false };
                } else {
                    out.push((i, c));
                }
            }
        }
        prev = c;
    }
    (out, matches!(state, In::String { .. } | In::Block))
}

/// Split argument text at top-level commas, comments left out.
fn top_level_arguments(args: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0i32;
    for (_, c) in code_chars(args).0 {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
}

/// `name` of a `name=value` argument (not `==`), if the argument has one.
fn argument_name(arg: &str) -> Option<&str> {
    let arg = arg.trim_start();
    let end = arg.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    let rest = arg[end..].trim_start();
    (end > 0 && rest.starts_with('=') && !rest.starts_with("==")).then(|| &arg[..end])
}

/// Signature help at byte `offset` of `source`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the active parameter indexes a catalogued function's parameters, a few dozen at most; LSP positions are u32"
)]
pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let before = source.get(..offset.min(source.len()))?;
    let (name, args) = open_call(before)?;
    let function = Catalog::cached().function(&name)?;
    if function.removed {
        return None;
    }
    let shown: Vec<&Parameter> = function
        .parameters
        .iter()
        .filter(|p| !p.deprecated)
        .collect();
    let parameters: Vec<ParameterInformation> = shown
        .iter()
        .map(|p| ParameterInformation {
            label: p.name.clone(),
            documentation: Some(parameter_detail(p)),
        })
        .collect();
    let current = top_level_arguments(args).pop().unwrap_or_default();
    let active = match argument_name(&current) {
        Some(n) => shown.iter().position(|p| p.answers_to(n)),
        None => shown.iter().position(|p| p.unnamed),
    }
    .unwrap_or(0) as u32;
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: function.signature(),
            documentation: Some(format!(
                "{}\n\n[CrowdStrike docs]({})",
                function.docs, function.citation
            )),
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    })
}

fn function_items(catalog: &Catalog) -> impl Iterator<Item = CompletionItem> + '_ {
    catalog
        .functions
        .iter()
        .filter(|f| !f.removed && !f.unavailable && f.in_queries())
        .map(|f| {
            let mut item = CompletionItem::new(f.name.clone(), "function");
            item.detail = Some(f.signature());
            item.documentation = Some(f.docs.clone());
            item
        })
}

fn field_items(catalog: &Catalog) -> impl Iterator<Item = CompletionItem> + '_ {
    catalog
        .fields
        .iter()
        .filter(|f| f.kind != "namespace")
        .map(|f| {
            let mut item = CompletionItem::new(f.name.clone(), "property");
            item.detail = Some(format!("{} ({})", f.ty, layer_name(&f.layer)));
            item.documentation.clone_from(&f.docs);
            item
        })
}

fn event_items(catalog: &Catalog) -> Vec<CompletionItem> {
    let mut events: Vec<&Event> = catalog.events.iter().collect();
    events.sort_by(|a, b| b.mentions.cmp(&a.mentions).then(a.name.cmp(&b.name)));
    events
        .into_iter()
        .map(|e| {
            let mut item = CompletionItem::new(e.name.clone(), "enum");
            item.detail = Some("Falcon event".into());
            item
        })
        .collect()
}

/// Completion at byte `offset` of `source`.
pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    let word_start = opentide_core::word_start(before, word_char);
    let head = before[..word_start].trim_end();

    // `#event_simpleName!=`: events, as after `=`.
    if let Some(lhs) = head.strip_suffix("!=") {
        let lhs = lhs.trim_end();
        let name = unquote(&lhs[opentide_core::word_start(lhs, |c| word_char(c) || c == '"')..]);
        if name == "#event_simpleName" || name == "event_simpleName" {
            return event_items(catalog);
        }
    }
    // `field=` / `param=`: values.
    if let Some(lhs) = head
        .strip_suffix('=')
        .filter(|h| !h.ends_with(['!', '<', '>', '=', ':']))
    {
        let lhs = lhs.trim_end();
        let name = &lhs[opentide_core::word_start(lhs, |c| word_char(c) || c == '"')..];
        let name = unquote(name);
        if name == "#event_simpleName" || name == "event_simpleName" {
            return event_items(catalog);
        }
        if let Some((call, args)) = open_call(before) {
            let current = top_level_arguments(args).pop().unwrap_or_default();
            if let (Some(f), Some(arg)) = (catalog.function(&call), argument_name(&current)) {
                if let Some(p) = f.parameter(arg) {
                    if !p.values.is_empty() {
                        return p
                            .values
                            .iter()
                            .map(|v| CompletionItem::new(v.clone(), "enum"))
                            .collect();
                    }
                    if p.query || p.ty.contains("function") {
                        return function_items(catalog).collect();
                    }
                    if p.ty == "boolean" {
                        return ["true", "false"]
                            .into_iter()
                            .map(|v| CompletionItem::new(v, "constant"))
                            .collect();
                    }
                }
            }
        }
        if let Some(field) = catalog.field(name) {
            return field
                .values
                .iter()
                .map(|v| CompletionItem::new(v.clone(), "enum"))
                .collect();
        }
        return Vec::new();
    }

    // Right after `(` or `,` of a known call: the parameters not given yet.
    if head.ends_with('(') || head.ends_with(',') {
        if let Some((call, args)) = open_call(before) {
            if let Some(f) = catalog.function(&call) {
                let arguments = top_level_arguments(args);
                let mut given: Vec<&str> =
                    arguments.iter().filter_map(|a| argument_name(a)).collect();
                // A finished argument without a name binds the omittable parameter.
                let finished = &arguments[..arguments.len().saturating_sub(1)];
                if finished
                    .iter()
                    .any(|a| argument_name(a).is_none() && !a.trim().is_empty())
                {
                    if let Some(p) = f.unnamed_parameter() {
                        given.push(p.name.as_str());
                    }
                }
                let mut items: Vec<CompletionItem> = f
                    .parameters
                    .iter()
                    .filter(|p| !p.deprecated && !given.iter().any(|g| p.answers_to(g)))
                    .map(|p| {
                        let mut item = CompletionItem::new(p.name.clone(), "property");
                        item.detail = Some(parameter_detail(p));
                        item
                    })
                    .collect();
                items.extend(field_items(catalog));
                return items;
            }
        }
    }

    // A step or a filter: functions, tags and fields.
    let mut items: Vec<CompletionItem> = function_items(catalog).collect();
    items.extend(field_items(catalog));
    items
}
