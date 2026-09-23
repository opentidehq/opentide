//! I/O-free SPL engine. Catalogs compiled in; unknown commands are never silently eaten.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Range, SignatureHelp,
    SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{has_error, parse as ts_parse};
use serde::Deserialize;
use tree_sitter::Node;

const COMMANDS_TOML: &str = include_str!("../../../catalogs/spl/commands.toml");
const FIELDS_TOML: &str = include_str!("../../../catalogs/spl/fields.toml");
const DATAMODELS_TOML: &str = include_str!("../../../catalogs/spl/datamodels.toml");
const MACROS_TOML: &str = include_str!("../../../catalogs/spl/macros.toml");
const OPTIONS_TOML: &str = include_str!("../../../catalogs/spl/command-options.toml");

#[derive(Debug, Clone, Deserialize)]
struct CommandsFile {
    commands: Vec<CommandRow>,
    #[serde(default)]
    functions: Vec<FunctionRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandRow {
    pub name: String,
    pub kind: String,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub kind: Option<String>,
    pub docs: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FieldsFile {
    fields: Vec<FieldRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldRow {
    pub name: String,
    #[serde(default)]
    pub models: Vec<String>,
    pub kind: Option<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DatamodelsFile {
    datamodels: Vec<DatamodelRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatamodelRow {
    pub name: String,
    pub prefix: String,
    pub model: Option<String>,
    pub docs: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MacrosFile {
    macros: Vec<MacroRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MacroRow {
    pub name: String,
    pub signature: Option<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OptionsFile {
    options: Vec<CommandOption>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandOption {
    pub command: String,
    pub name: String,
    #[serde(default)]
    pub values: Vec<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub commands: Vec<CommandRow>,
    pub functions: Vec<FunctionRow>,
    pub fields: Vec<FieldRow>,
    pub datamodels: Vec<DatamodelRow>,
    pub macros: Vec<MacroRow>,
    pub options: Vec<CommandOption>,
}

impl Catalog {
    pub fn load() -> Self {
        let file: CommandsFile = toml::from_str(COMMANDS_TOML).expect("commands.toml");
        let fields: FieldsFile = toml::from_str(FIELDS_TOML).expect("fields.toml");
        let datamodels: DatamodelsFile = toml::from_str(DATAMODELS_TOML).expect("datamodels.toml");
        let macros: MacrosFile = toml::from_str(MACROS_TOML).expect("macros.toml");
        let options: OptionsFile = toml::from_str(OPTIONS_TOML).expect("command-options.toml");
        Self {
            commands: file.commands,
            functions: file.functions,
            fields: fields.fields,
            datamodels: datamodels.datamodels,
            macros: macros.macros,
            options: options.options,
        }
    }

    pub fn command(&self, name: &str) -> Option<&CommandRow> {
        self.commands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        self.functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    pub fn suggest_command(&self, name: &str) -> Option<String> {
        self.commands
            .iter()
            .map(|c| {
                let dist = levenshtein(&c.name.to_ascii_lowercase(), &name.to_ascii_lowercase());
                (c.name.clone(), dist)
            })
            .filter(|(_, d)| *d <= 3)
            .min_by_key(|(_, d)| *d)
            .map(|(n, _)| n)
    }

    pub fn field(&self, name: &str) -> Option<&FieldRow> {
        let bare = name.rsplit('.').next().unwrap_or(name);
        self.fields
            .iter()
            .find(|f| f.name == name || f.name == bare)
    }

    pub fn datamodel(&self, name: &str) -> Option<&DatamodelRow> {
        self.datamodels
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name) || d.prefix.eq_ignore_ascii_case(name))
    }

    pub fn macro_named(&self, name: &str) -> Option<&MacroRow> {
        let bare = name.trim_matches('`').split('(').next().unwrap_or(name);
        self.macros
            .iter()
            .find(|m| m.name == bare || m.name == name)
    }

    pub fn active_datamodel(&self, source: &str) -> Option<&DatamodelRow> {
        self.datamodels
            .iter()
            .find(|d| source.contains(&d.name) || source.contains(&format!("datamodel={}", d.name)))
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let catalog = Catalog::load();
    let spec = HighlightSpec::load().expect("spec");
    let mut diagnostics = Vec::new();
    let Some(tree) = ts_parse(LanguageId::Spl, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::SPL_PARSE_ERROR,
                "failed to initialize SPL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    if has_error(&tree) {
        diagnostics.push(Diagnostic::error(
            codes::SPL_PARSE_ERROR,
            "SPL syntax error",
            node_range(source, tree.root_node()),
        ));
    }
    collect_unknown_commands(tree.root_node(), source, &catalog, &mut diagnostics);
    let tokens = highlight_tree(&spec, source, tree.root_node()).unwrap_or_default();
    AnalyzeResult {
        diagnostics,
        tokens,
    }
}

fn node_range(source: &str, node: Node) -> Range {
    span_to_range(
        source,
        ByteSpan::new(
            node.start_byte(),
            node.end_byte().max(node.start_byte() + 1),
        ),
    )
}

fn collect_unknown_commands(
    node: Node,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    if node.kind() == "unknown_command" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .unwrap_or("")
            .to_string();
        if catalog.command(&name).is_none() {
            let mut d = Diagnostic::error(
                codes::SPL_UNKNOWN_COMMAND,
                format!("unknown SPL command '{name}'"),
                node_range(source, node),
            );
            if let Some(s) = catalog.suggest_command(&name) {
                d = d.with_suggestion(s);
            }
            out.push(d);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_unknown_commands(child, source, catalog, out);
    }
}

fn highlight_tree(
    spec: &HighlightSpec,
    source: &str,
    root: Node,
) -> Result<Vec<HighlightToken>, opentide_highlight::HighlightError> {
    let catalog = Catalog::load();
    match opentide_syntax::query_captures(
        LanguageId::Spl,
        source,
        opentide_highlight::SPL_HIGHLIGHTS_SCM,
    ) {
        Ok(mut owned) => {
            for (span, capture) in owned.iter_mut() {
                let end = span.end.min(source.len());
                if span.start >= end {
                    continue;
                }
                let text = &source[span.start..end];
                if catalog.function(text).is_some()
                    && (*capture == "variable" || *capture == "function")
                {
                    *capture = "function.builtin".into();
                } else if (matches!(
                    text,
                    "by" | "AS" | "as" | "from" | "datamodel" | "summariesonly"
                ) && *capture == "variable")
                    || (catalog.command(text).is_some()
                        && (*capture == "variable" || *capture == "error"))
                {
                    *capture = "keyword".into();
                } else if looks_like_macro(text)
                    || (*capture == "comment" && looks_like_macro(text))
                {
                    *capture = "macro".into();
                } else if catalog.datamodel(text).is_some() && *capture == "variable" {
                    *capture = "type".into();
                } else if catalog.field(text).is_some() && *capture == "variable" {
                    *capture = "property".into();
                }
            }
            let refs: Vec<(ByteSpan, &str)> = owned
                .iter()
                .map(|(span, cap)| (*span, cap.as_str()))
                .collect();
            tokens_from_spans(spec, source, &refs)
        }
        Err(err) => {
            if cfg!(debug_assertions) {
                panic!("SPL highlights.scm query failed: {err}");
            }
            let mut spans = Vec::new();
            collect_highlights(root, source, &mut spans);
            tokens_from_spans(spec, source, &spans)
        }
    }
}

fn collect_highlights(node: Node, _source: &str, out: &mut Vec<(ByteSpan, &'static str)>) {
    let kind = node.kind();
    let capture = match kind {
        "comment" => Some("comment"),
        "string" => Some("string"),
        "number" => Some("number"),
        "boolean" => Some("boolean"),
        "|" => Some("operator.pipe"),
        "catalog_command_name" => Some("keyword"),
        "macro" => Some("macro"),
        "search" | "where" | "eval" | "stats" | "rex" | "table" | "rename" | "fields" | "dedup"
        | "sort" | "head" | "tail" | "join" | "lookup" | "makemv" | "mvexpand" | "tstats"
        | "AS" | "as" | "by" | "from" | "datamodel" | "summariesonly" | "TERM" | "CASE" | "IN" => {
            Some("keyword")
        }
        "identifier" => {
            if node.parent().map(|p| p.kind()) == Some("function_call") {
                Some("function")
            } else if node.parent().map(|p| p.kind()) == Some("field_value")
                && node
                    .parent()
                    .and_then(|p| p.child_by_field_name("field"))
                    .map(|n| n.id())
                    == Some(node.id())
            {
                Some("property")
            } else if node.parent().map(|p| p.kind()) == Some("unknown_command") {
                Some("error")
            } else {
                Some("variable")
            }
        }
        "AND" | "OR" | "NOT" | "and" | "or" | "not" | "=" | "==" | "!=" => Some("operator"),
        "(" | ")" | "[" | "]" => Some("punctuation.bracket"),
        "," => Some("punctuation.delimiter"),
        _ => None,
    };
    if let Some(capture) = capture {
        if node.child_count() == 0 || matches!(kind, "string" | "comment" | "number" | "macro") {
            out.push((ByteSpan::new(node.start_byte(), node.end_byte()), capture));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_highlights(child, _source, out);
    }
}

fn looks_like_macro(text: &str) -> bool {
    let t = text.trim();
    t.starts_with('`') && t.ends_with('`') && !t.starts_with("```") && t.len() >= 3
}

fn complete_item(
    label: impl Into<String>,
    kind: &str,
    detail: Option<String>,
    docs: Option<String>,
) -> CompletionItem {
    let mut item = CompletionItem::new(label, kind);
    if let Some(d) = detail {
        item = item.with_detail(d);
    }
    if let Some(d) = docs {
        item = item.with_docs(d);
    }
    item
}

fn last_command(before: &str) -> Option<String> {
    let chunk = before
        .rsplit('|')
        .next()?
        .trim_start()
        .trim_start_matches('|')
        .trim_start();
    let op = chunk
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()?
        .to_ascii_lowercase();
    if op.is_empty() { None } else { Some(op) }
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::load();
    let before = &source[..offset.min(source.len())];
    let trimmed = before.trim_end();
    if trimmed.ends_with('`') && !trimmed.ends_with("```") {
        return catalog
            .macros
            .iter()
            .map(|m| {
                complete_item(
                    format!("`{}`", m.name.trim_matches('`')),
                    "macro",
                    m.docs.clone(),
                    m.docs.clone(),
                )
            })
            .collect();
    }
    if trimmed.to_ascii_lowercase().ends_with("datamodel=") {
        return catalog
            .datamodels
            .iter()
            .map(|d| complete_item(d.name.clone(), "type", d.docs.clone(), d.docs.clone()))
            .collect();
    }
    if before.trim_end().ends_with('|') || before.ends_with("| ") {
        return catalog
            .commands
            .iter()
            .map(|c| complete_item(c.name.clone(), "command", c.docs.clone(), c.docs.clone()))
            .collect();
    }
    if let Some(cmd) = last_command(before) {
        if matches!(
            cmd.as_str(),
            "tstats" | "stats" | "where" | "table" | "fields" | "eval"
        ) {
            let mut items = Vec::new();
            if let Some(dm) = catalog.active_datamodel(source) {
                for f in &dm.fields {
                    items.push(complete_item(
                        format!("{}.{}", dm.prefix, f),
                        "column",
                        Some(format!("{} field", dm.name)),
                        catalog.field(f).and_then(|row| row.docs.clone()),
                    ));
                    items.push(complete_item(
                        f.clone(),
                        "column",
                        Some(format!("{} field", dm.name)),
                        catalog.field(f).and_then(|row| row.docs.clone()),
                    ));
                }
            }
            for field in &catalog.fields {
                items.push(complete_item(
                    field.name.clone(),
                    "column",
                    Some(field.kind.clone().unwrap_or_else(|| "field".into())),
                    field.docs.clone(),
                ));
            }
            if cmd == "tstats" {
                for m in &catalog.macros {
                    items.push(complete_item(
                        format!("`{}`", m.name.trim_matches('`')),
                        "macro",
                        m.docs.clone(),
                        m.docs.clone(),
                    ));
                }
            }
            if !items.is_empty() {
                return items;
            }
        }
    }
    catalog
        .functions
        .iter()
        .map(|f| complete_item(f.name.clone(), "function", f.docs.clone(), f.docs.clone()))
        .collect()
}

fn spl_word_at(source: &str, offset: usize) -> Option<String> {
    let bytes = source.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut i = offset.min(bytes.len().saturating_sub(1));
    while i > 0 && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.' | b'`')) {
        i -= 1;
    }
    if !(bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'`')) {
        i += 1;
    }
    let mut j = offset.min(bytes.len());
    while j < bytes.len()
        && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'.' | b'`'))
    {
        j += 1;
    }
    if i >= j {
        None
    } else {
        Some(source[i..j].to_string())
    }
}

pub fn hover(source: &str, position: opentide_core::Position) -> Option<String> {
    let catalog = Catalog::load();
    let offset = {
        let mut line = 0u32;
        let mut col = 0u32;
        let mut at = source.len();
        for (idx, ch) in source.char_indices() {
            if line == position.line && col >= position.character {
                at = idx;
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 0;
            } else {
                col += 1;
            }
        }
        at
    };
    let word = spl_word_at(source, offset)?;
    let macro_name = word.trim_matches('`');
    if let Some(m) = catalog.macro_named(macro_name) {
        let mut md = format!(
            "**`{}`** (search macro)\n\n{}",
            m.name,
            m.docs.clone().unwrap_or_default()
        );
        if let Some(s) = &m.signature {
            md.push_str(&format!("\n\n`{s}`"));
        }
        return Some(md);
    }
    if let Some(c) = catalog.command(&word) {
        let citation = c
            .citation
            .as_deref()
            .map(|c| format!("\n\n[searchbnf]({c})"))
            .unwrap_or_default();
        return Some(format!(
            "**{}** ({})\n\n{}{citation}",
            c.name,
            c.kind,
            c.docs.clone().unwrap_or_default()
        ));
    }
    if let Some(f) = catalog.function(&word) {
        let kind = f.kind.clone().unwrap_or_else(|| "function".into());
        return Some(format!(
            "**{}** ({})\n\n{}",
            f.name,
            kind,
            f.docs.clone().unwrap_or_default()
        ));
    }
    if let Some(d) = catalog.datamodel(&word) {
        return Some(format!(
            "**{}** CIM data model (prefix `{}`)\n\n{}",
            d.name,
            d.prefix,
            d.docs.clone().unwrap_or_default()
        ));
    }
    if let Some(field) = catalog.field(&word) {
        let models = field.models.join(", ");
        let mut md = format!(
            "**{}** field ({})\n\n{}",
            field.name,
            field.kind.as_deref().unwrap_or("cim"),
            field.docs.clone().unwrap_or_default()
        );
        if !models.is_empty() {
            md.push_str(&format!("\n\nModels: {models}"));
        }
        return Some(md);
    }
    None
}

pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let catalog = Catalog::load();
    let before = &source[..offset.min(source.len())];
    if let Some(cmd) = last_command(before) {
        if cmd == "tstats" {
            return Some(SignatureHelp {
                signatures: vec![SignatureInformation {
                    label: "tstats [summariesonly=] <aggregates> [from datamodel=Model.Dataset] [where] [by]".into(),
                    documentation: Some(
                        "Statistical aggregation on indexed fields / accelerated datamodels."
                            .into(),
                    ),
                    parameters: vec![
                        ParameterInformation {
                            label: "aggregates".into(),
                            documentation: Some("count, min(_time) as firstTime, …".into()),
                        },
                        ParameterInformation {
                            label: "from datamodel=".into(),
                            documentation: Some("CIM path such as Endpoint.Processes.".into()),
                        },
                        ParameterInformation {
                            label: "where".into(),
                            documentation: Some("Predicate over prefixed CIM fields.".into()),
                        },
                        ParameterInformation {
                            label: "by".into(),
                            documentation: Some("Split-by fields (Processes.user, …).".into()),
                        },
                    ],
                }],
                active_signature: 0,
                active_parameter: if before.to_ascii_lowercase().contains(" by ") {
                    3
                } else if before.to_ascii_lowercase().contains(" where ") {
                    2
                } else if before.to_ascii_lowercase().contains("datamodel=") {
                    1
                } else {
                    0
                },
            });
        }
    }
    let bytes = before.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for (i, b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                if depth == 0 {
                    open = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let open = open?;
    let mut i = open;
    while i > 0 {
        let c = bytes[i - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'`' {
            i -= 1;
        } else {
            break;
        }
    }
    let name = before[i..open].trim_matches('`').to_string();
    if let Some(f) = catalog.function(&name) {
        return Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label: format!("{}()", f.name),
                documentation: f.docs.clone(),
                parameters: vec![ParameterInformation {
                    label: "args".into(),
                    documentation: None,
                }],
            }],
            active_signature: 0,
            active_parameter: 0,
        });
    }
    if let Some(m) = catalog.macro_named(&name) {
        return Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label: m
                    .signature
                    .clone()
                    .unwrap_or_else(|| format!("`{}`", m.name)),
                documentation: m.docs.clone(),
                parameters: Vec::new(),
            }],
            active_signature: 0,
            active_parameter: 0,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_core_commands() {
        let c = Catalog::load();
        for name in ["search", "where", "eval", "stats", "rex", "tstats"] {
            assert!(c.command(name).is_some(), "{name}");
        }
    }

    #[test]
    fn unknown_command_is_not_silent() {
        let r = analyze("index=main | bogus foo=bar | head 1");
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND && d.message.contains("bogus")),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn known_pipeline_has_no_unknown_command() {
        let r = analyze("index=main | stats count by host | head 1");
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn authored_text_is_not_rewritten() {
        // Implicit `| search` is semantic; the source stays `index=main`.
        let r = analyze("index=main | head 1");
        assert!(r.tokens.iter().any(|t| t.capture == "property"));
        assert!(!r.tokens.iter().any(|t| t.capture == "keyword" && {
            let s = &"index=main | head 1"[t.span.start..t.span.end];
            s == "search"
        }));
    }

    #[test]
    fn highlight_has_pipe() {
        let r = analyze("index=main | head 1");
        assert!(r.tokens.iter().any(|t| t.capture == "operator.pipe"));
    }

    #[test]
    fn completions_after_pipe_include_catalog_commands() {
        let items = completions("index=main | ", 14);
        assert!(items.iter().any(|i| i.label == "stats"));
        assert!(items.iter().any(|i| i.label == "timechart"));
        assert!(items.iter().any(|i| i.kind == "command"));
    }

    #[test]
    fn hover_stats() {
        let h = hover(
            "index=main | stats count by host",
            opentide_core::Position::new(0, 14),
        );
        assert!(h.unwrap().to_lowercase().contains("stats"));
    }

    #[test]
    fn hover_function_from_catalog() {
        let h = hover(
            "index=main | eval x=lower(user)",
            opentide_core::Position::new(0, 22),
        );
        let text = h.expect("hover");
        assert!(text.to_lowercase().contains("lower"), "{text}");
    }

    #[test]
    fn catalog_includes_trig_and_stats_aliases() {
        let c = Catalog::load();
        assert!(c.function("sin").is_some());
        assert!(c.function("acos").is_some());
        assert!(c.function("c").is_some());
        assert!(c.function("distinct_count").is_some());
        assert!(c.functions.len() >= 140, "{}", c.functions.len());
    }

    #[test]
    fn catalog_covers_es_surface() {
        let c = Catalog::load();
        for name in [
            "timechart",
            "eventstats",
            "inputlookup",
            "makeresults",
            "spath",
        ] {
            assert!(c.command(name).is_some(), "{name}");
        }
        assert!(c.function("if").is_some());
        assert!(c.function("count").is_some());
        assert!(c.commands.len() > 140, "{}", c.commands.len());
        assert!(c.functions.len() > 80, "{}", c.functions.len());
        assert!(c.command("abstract").is_some());
        assert!(c.command("predict").is_some());
        assert!(c.command("timechart").is_some());
    }

    #[test]
    fn highlight_scm_query_emits_spl_keywords() {
        let src = "index=main | stats count by host | head 1";
        let r = analyze(src);
        let slice =
            |t: &opentide_highlight::HighlightToken| src[t.span.start..t.span.end].to_string();
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword" && slice(t) == "stats"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), slice(t)))
                .collect::<Vec<_>>()
        );
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword" && slice(t) == "head")
        );
        assert!(r.tokens.iter().any(|t| t.capture == "operator.pipe"));
        assert!(
            r.tokens.iter().any(|t| {
                slice(t) == "count" && (t.capture == "function" || t.capture == "function.builtin")
            }),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), slice(t)))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn macros_are_not_comments() {
        let src = "| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes by Processes.user";
        let r = analyze(src);
        let pairs: Vec<(&str, &str)> = r
            .tokens
            .iter()
            .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
            .collect();
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "macro" && t.contains("security_content_summariesonly")),
            "{pairs:?}"
        );
        assert!(
            !pairs
                .iter()
                .any(|(c, t)| *c == "comment" && t.contains("security_content_summariesonly")),
            "macro must not highlight as comment: {pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "property" && *t == "Processes.user")
                || pairs
                    .iter()
                    .any(|(c, t)| *c == "variable" && t.contains("user")),
            "{pairs:?}"
        );
        let h = hover(
            src,
            opentide_core::Position::new(0, (src.find("Processes.user").unwrap() + 11) as u32),
        );
        assert!(
            h.as_deref().unwrap_or("").to_lowercase().contains("user"),
            "{h:?}"
        );
        let items = completions(src, src.find("by ").unwrap() + 3);
        assert!(
            items
                .iter()
                .any(|i| i.label.contains("user") || i.label.contains("process_name")),
            "{:?}",
            items.iter().map(|i| &i.label).take(15).collect::<Vec<_>>()
        );
        let help = signature_help(src, src.find("tstats").unwrap() + 6).expect("tstats signature");
        assert!(help.signatures[0].label.contains("tstats"));
    }

    #[test]
    fn drop_dm_object_name_hover() {
        let src = "index=main | `drop_dm_object_name(Processes)`";
        let h = hover(src, opentide_core::Position::new(0, 16)).expect("macro hover");
        assert!(h.contains("drop_dm_object_name"), "{h}");
    }
}
