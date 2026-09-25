//! I/O-free SPL engine. Catalogs compiled in; unknown commands are never silently eaten.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Range, SignatureHelp,
    SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{has_error, parse as ts_parse};
use serde::Deserialize;
use std::sync::OnceLock;
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
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub citation: Option<String>,
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

    pub fn cached() -> &'static Self {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(Self::load)
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

    /// Eval and aggregate rows can share a name (`sum`, `avg`, `min`, `max`).
    /// `aggregate` selects the stats/chart form; otherwise the eval form wins.
    pub fn function_in_context(&self, name: &str, aggregate: bool) -> Option<&FunctionRow> {
        let mut fallback = None;
        for f in &self.functions {
            if !f.name.eq_ignore_ascii_case(name) {
                continue;
            }
            let is_agg = f.kind.as_deref() == Some("aggregate");
            if fallback.is_none() {
                fallback = Some(f);
            }
            if aggregate == is_agg {
                return Some(f);
            }
        }
        fallback
    }

    pub fn options_for<'a>(&'a self, command: &str) -> Vec<&'a CommandOption> {
        self.options
            .iter()
            .filter(|o| o.command.eq_ignore_ascii_case(command))
            .collect()
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
    let catalog = Catalog::cached();
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
    collect_unknown_commands(tree.root_node(), source, catalog, &mut diagnostics);
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
    let catalog = Catalog::cached();
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
                    "by" | "AS"
                        | "as"
                        | "from"
                        | "datamodel"
                        | "summariesonly"
                        | "where"
                        | "prestats"
                        | "allow_old_summaries"
                        | "fillnull_value"
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
        "search"
        | "where"
        | "eval"
        | "stats"
        | "rex"
        | "table"
        | "rename"
        | "fields"
        | "dedup"
        | "sort"
        | "head"
        | "tail"
        | "join"
        | "lookup"
        | "makemv"
        | "mvexpand"
        | "tstats"
        | "AS"
        | "as"
        | "by"
        | "from"
        | "datamodel"
        | "summariesonly"
        | "prestats"
        | "allow_old_summaries"
        | "fillnull_value"
        | "TERM"
        | "CASE"
        | "IN" => Some("keyword"),
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

const AGGREGATE_COMMANDS: &[&str] = &[
    "stats",
    "eventstats",
    "streamstats",
    "tstats",
    "chart",
    "timechart",
    "mstats",
    "sistats",
    "sichart",
    "sitimechart",
];

fn aggregate_command(cmd: &str) -> bool {
    AGGREGATE_COMMANDS.contains(&cmd)
}

/// `bucket` is the Search Reference alias of `bin` and takes the same arguments.
fn argument_command(cmd: &str) -> &str {
    match cmd {
        "bucket" => "bin",
        _ => cmd,
    }
}

fn eval_command(cmd: &str) -> bool {
    matches!(cmd, "eval" | "where" | "fieldformat")
}

fn field_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "tstats" | "stats" | "where" | "table" | "fields" | "eval"
    )
}

fn option_is_clause(opt: &CommandOption) -> bool {
    let name = opt.name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "from"
            | "where"
            | "by"
            | "over"
            | "output"
            | "outputnew"
            | "search"
            | "flat"
            | "acceleration_search"
            | "search_string"
            | "flat_string"
            | "acceleration_search_string"
            | "lookup"
            | "savedsearch"
            | "assignment"
    ) || (opt.command.eq_ignore_ascii_case("from") && name == "datamodel")
}

fn option_fragment(opt: &CommandOption) -> String {
    if option_is_clause(opt) {
        format!("[{}]", opt.name)
    } else {
        format!("[{}=]", opt.name)
    }
}

fn assigned_option<'a>(before: &str, catalog: &'a Catalog, cmd: &str) -> Option<&'a CommandOption> {
    let trimmed = before.trim_end();
    if !trimmed.ends_with('=') {
        return None;
    }
    let left = trimmed[..trimmed.len() - 1].trim_end();
    let name = left
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    if name.is_empty() {
        return None;
    }
    catalog
        .options_for(argument_command(cmd))
        .into_iter()
        .find(|o| o.name.eq_ignore_ascii_case(name) && !o.values.is_empty())
}

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
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
        if let Some(opt) = assigned_option(before, catalog, &cmd) {
            return opt
                .values
                .iter()
                .map(|v| {
                    complete_item(
                        v.clone(),
                        "keyword",
                        Some(format!("{cmd} {}=", opt.name)),
                        opt.docs.clone(),
                    )
                })
                .collect();
        }
        let opts = catalog.options_for(argument_command(&cmd));
        let wants_fields = field_command(&cmd);
        let wants_agg = aggregate_command(&cmd);
        let wants_eval = eval_command(&cmd);
        if !opts.is_empty() || wants_fields || wants_agg || wants_eval {
            let mut items = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for opt in &opts {
                if seen.insert(opt.name.to_ascii_lowercase()) {
                    items.push(complete_item(
                        opt.name.clone(),
                        "keyword",
                        opt.docs.clone(),
                        opt.citation.clone(),
                    ));
                }
            }
            if wants_agg {
                for f in catalog
                    .functions
                    .iter()
                    .filter(|f| f.kind.as_deref() == Some("aggregate"))
                {
                    if seen.insert(f.name.to_ascii_lowercase()) {
                        items.push(complete_item(
                            f.name.clone(),
                            "function",
                            f.signature.clone().or(f.docs.clone()),
                            f.docs.clone(),
                        ));
                    }
                }
            } else if wants_eval {
                for f in catalog
                    .functions
                    .iter()
                    .filter(|f| f.kind.as_deref() != Some("aggregate"))
                {
                    if seen.insert(f.name.to_ascii_lowercase()) {
                        items.push(complete_item(
                            f.name.clone(),
                            "function",
                            f.signature.clone().or(f.docs.clone()),
                            f.docs.clone(),
                        ));
                    }
                }
            }
            if wants_fields {
                if let Some(dm) = catalog.active_datamodel(source) {
                    for f in &dm.fields {
                        let prefixed = format!("{}.{}", dm.prefix, f);
                        if seen.insert(prefixed.to_ascii_lowercase()) {
                            items.push(complete_item(
                                prefixed,
                                "column",
                                Some(format!("{} field", dm.name)),
                                catalog.field(f).and_then(|row| row.docs.clone()),
                            ));
                        }
                        if seen.insert(f.to_ascii_lowercase()) {
                            items.push(complete_item(
                                f.clone(),
                                "column",
                                Some(format!("{} field", dm.name)),
                                catalog.field(f).and_then(|row| row.docs.clone()),
                            ));
                        }
                    }
                }
                for field in &catalog.fields {
                    if seen.insert(field.name.to_ascii_lowercase()) {
                        items.push(complete_item(
                            field.name.clone(),
                            "column",
                            Some(field.kind.clone().unwrap_or_else(|| "field".into())),
                            field.docs.clone(),
                        ));
                    }
                }
            }
            if cmd == "tstats" {
                for m in &catalog.macros {
                    let label = format!("`{}`", m.name.trim_matches('`'));
                    if seen.insert(label.to_ascii_lowercase()) {
                        items.push(complete_item(
                            label,
                            "macro",
                            m.docs.clone(),
                            m.docs.clone(),
                        ));
                    }
                }
            }
            if !items.is_empty() {
                return items;
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    catalog
        .functions
        .iter()
        .filter(|f| seen.insert(f.name.to_ascii_lowercase()))
        .map(|f| {
            complete_item(
                f.name.clone(),
                "function",
                f.signature.clone().or(f.docs.clone()),
                f.docs.clone(),
            )
        })
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
    let catalog = Catalog::cached();
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
    if let Some(cmd) = last_command(&source[..offset]) {
        if let Some(opt) = catalog
            .options_for(argument_command(&cmd))
            .into_iter()
            .find(|o| o.name.eq_ignore_ascii_case(&word))
        {
            return Some(option_markdown(opt));
        }
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
    let aggregate = last_command(&source[..offset]).is_some_and(|cmd| aggregate_command(&cmd));
    if let Some(f) = catalog.function_in_context(&word, aggregate) {
        return Some(function_markdown(f));
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

fn function_markdown(f: &FunctionRow) -> String {
    let kind = f.kind.clone().unwrap_or_else(|| "function".into());
    let mut md = format!(
        "**{}** ({})\n\n{}",
        f.name,
        kind,
        f.docs.clone().unwrap_or_default()
    );
    if let Some(s) = &f.signature {
        md.push_str(&format!("\n\n`{s}`"));
    }
    if let Some(c) = &f.citation {
        md.push_str(&format!("\n\n[Search Reference]({c})"));
    }
    md
}

fn option_markdown(opt: &CommandOption) -> String {
    let mut md = format!(
        "**{}** (`{}` argument)\n\n{}",
        opt.name,
        opt.command,
        opt.docs.clone().unwrap_or_default()
    );
    if !opt.values.is_empty() {
        md.push_str(&format!("\n\nValues: {}", opt.values.join(", ")));
    }
    if let Some(c) = &opt.citation {
        md.push_str(&format!("\n\n[Search Reference]({c})"));
    }
    md
}

pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let catalog = Catalog::cached();
    let before = &source[..offset.min(source.len())];
    if let Some((name, active)) = innermost_call(before) {
        let cmd = last_command(before);
        let same_as_command = cmd.as_ref().is_some_and(|c| c.eq_ignore_ascii_case(&name));
        if !same_as_command {
            let aggregate = cmd.as_ref().is_some_and(|c| aggregate_command(c));
            if let Some(f) = catalog.function_in_context(&name, aggregate) {
                if let Some(help) = function_signature(f, active) {
                    return Some(help);
                }
            }
        }
        if let Some(m) = catalog.macro_named(&name) {
            let label = m
                .signature
                .clone()
                .unwrap_or_else(|| format!("`{}`", m.name));
            return Some(signature_from_label(label, m.docs.clone(), active));
        }
    }
    let cmd = last_command(before)?;
    command_signature(catalog, &cmd, before)
}

fn function_signature(f: &FunctionRow, active: u32) -> Option<SignatureHelp> {
    let label = f.signature.clone()?;
    if !label.contains('(') {
        return None;
    }
    Some(signature_from_label(label, f.docs.clone(), active))
}

fn signature_from_label(
    label: String,
    documentation: Option<String>,
    active: u32,
) -> SignatureHelp {
    let parameters = parameters_from_signature(&label);
    let active = if parameters.is_empty() {
        0
    } else {
        active.min(parameters.len().saturating_sub(1) as u32)
    };
    SignatureHelp {
        signatures: vec![SignatureInformation {
            label,
            documentation,
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    }
}

fn command_signature(catalog: &Catalog, cmd: &str, before: &str) -> Option<SignatureHelp> {
    let opts = catalog.options_for(argument_command(cmd));
    if opts.is_empty() {
        return None;
    }
    let label = format!(
        "{cmd} {}",
        opts.iter()
            .map(|opt| option_fragment(opt))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let parameters = opts
        .iter()
        .map(|opt| ParameterInformation {
            label: opt.name.clone(),
            documentation: opt.docs.clone(),
        })
        .collect();
    let row = catalog.command(cmd);
    let mut documentation = row.and_then(|c| c.docs.clone());
    if let Some(citation) = row.and_then(|c| c.citation.clone()) {
        let line = format!("[Search Reference]({citation})");
        documentation = Some(match documentation {
            Some(docs) if !docs.is_empty() => format!("{docs}\n\n{line}"),
            _ => line,
        });
    }
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label,
            documentation,
            parameters,
        }],
        active_signature: 0,
        active_parameter: active_option(before, &opts),
    })
}

fn active_option(before: &str, opts: &[&CommandOption]) -> u32 {
    let lower = before.to_ascii_lowercase();
    let mut best: Option<(usize, u32)> = None;
    for (i, opt) in opts.iter().enumerate() {
        let needle = opt.name.to_ascii_lowercase();
        if let Some(pos) = rfind_word(&lower, &needle) {
            if best.map(|(at, _)| pos >= at).unwrap_or(true) {
                best = Some((pos, i as u32));
            }
        }
    }
    best.map(|(_, index)| index).unwrap_or(0)
}

fn rfind_word(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || needle.len() > bytes.len() {
        return None;
    }
    let mut i = bytes.len() - needle.len();
    loop {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let after = i + needle.len();
            let after_ok = after == bytes.len() || !bytes[after].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return Some(i);
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

fn innermost_call(before: &str) -> Option<(String, u32)> {
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
    if name.is_empty() {
        return None;
    }
    let inside = &before[open + 1..];
    let mut commas = 0u32;
    let mut nested = 0i32;
    for b in inside.bytes() {
        match b {
            b'(' => nested += 1,
            b')' => nested -= 1,
            b',' if nested == 0 => commas += 1,
            _ => {}
        }
    }
    Some((name, commas))
}

fn parameters_from_signature(sig: &str) -> Vec<ParameterInformation> {
    let Some(open) = sig.find('(') else {
        return Vec::new();
    };
    let start = open + 1;
    let end = sig.rfind(')').unwrap_or(sig.len());
    if start >= end {
        return Vec::new();
    }
    let mut params = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in sig[start..end].chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                push_param(&mut params, &cur);
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    push_param(&mut params, &cur);
    params
}

fn push_param(out: &mut Vec<ParameterInformation>, raw: &str) {
    let label = raw.trim();
    if label.is_empty() {
        return;
    }
    out.push(ParameterInformation {
        label: label.to_string(),
        documentation: None,
    });
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
    fn tstats_as_and_where_are_keywords() {
        let src = "| tstats count min(_time) as firstTime from datamodel=Endpoint.Processes where Processes.user=foo by Processes.user";
        let r = analyze(src);
        let pairs: Vec<(&str, &str)> = r
            .tokens
            .iter()
            .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
            .collect();
        assert!(
            pairs.iter().any(|(c, t)| *c == "keyword" && *t == "as"),
            "as should be a keyword: {pairs:?}"
        );
        assert!(
            pairs.iter().any(|(c, t)| *c == "keyword" && *t == "where"),
            "tstats where should be a keyword: {pairs:?}"
        );
        assert!(
            pairs.iter().any(|(c, t)| *c == "keyword" && *t == "from"),
            "{pairs:?}"
        );
        assert!(
            pairs
                .iter()
                .any(|(c, t)| *c == "type" && *t == "Endpoint.Processes"),
            "{pairs:?}"
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

    #[test]
    fn eval_signatures_come_from_search_reference() {
        let c = Catalog::load();
        let mut problems = Vec::new();
        for f in &c.functions {
            let sig = f.signature.as_deref().unwrap_or("");
            let citation = f.citation.as_deref().unwrap_or("");
            if !sig.starts_with(&f.name) || !sig.contains('(') {
                problems.push(format!("{} missing signature ({sig})", f.name));
            }
            if !citation
                .starts_with("https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/")
            {
                problems.push(format!("{} missing citation", f.name));
            }
        }
        assert!(problems.is_empty(), "{problems:?}");
        let evals = c
            .functions
            .iter()
            .filter(|f| f.kind.as_deref() == Some("eval"))
            .count();
        let aggs = c
            .functions
            .iter()
            .filter(|f| f.kind.as_deref() == Some("aggregate"))
            .count();
        assert_eq!(evals, 109, "{evals}");
        assert!(aggs >= 39, "{aggs}");
        assert!(
            c.functions
                .iter()
                .filter(|f| f.name == "sum")
                .any(|f| f.kind.as_deref() == Some("aggregate")),
        );
    }

    #[test]
    fn eval_signature_help_uses_real_parameters() {
        let src = "| eval x=if(1, ";
        let help = signature_help(src, src.len()).expect("if");
        assert_eq!(help.signatures[0].label, "if(X,Y,Z)");
        let labels: Vec<&str> = help.signatures[0]
            .parameters
            .iter()
            .map(|p| p.label.as_str())
            .collect();
        assert_eq!(labels, ["X", "Y", "Z"]);
        assert_eq!(help.active_parameter, 1);
        assert!(labels.iter().all(|l| *l != "args"));

        let lower = "| eval x=lower(";
        let help = signature_help(lower, lower.len()).expect("lower");
        assert_eq!(help.signatures[0].label, "lower(X)");
        assert_eq!(help.signatures[0].parameters[0].label, "X");

        let pi = "| eval x=pi(";
        let help = signature_help(pi, pi.len()).expect("pi");
        assert_eq!(help.signatures[0].label, "pi()");
        assert!(help.signatures[0].parameters.is_empty());
    }

    #[test]
    fn stats_sum_hovers_as_aggregate() {
        let src = "| stats sum(bytes) avg(bytes) min(bytes) max(bytes) by host";
        for name in ["sum", "avg", "min", "max"] {
            let at = src.find(&format!("{name}(")).unwrap() as u32;
            let text = hover(src, opentide_core::Position::new(0, at)).expect(name);
            assert!(text.contains("(aggregate)"), "{name}: {text}");
            assert!(text.contains(&format!("{name}(field)")), "{name}: {text}");
            assert!(!text.contains("eval args"), "{name}: {text}");
        }
        let eval_src = "| eval total=sum(a, b)";
        let at = eval_src.find("sum(").unwrap() as u32;
        let text = hover(eval_src, opentide_core::Position::new(0, at)).expect("eval sum");
        assert!(text.contains("(eval)"), "{text}");
        assert!(text.contains("sum(X,...)"), "{text}");

        let call = "| stats sum(";
        let help = signature_help(call, call.len()).expect("agg sum");
        assert_eq!(help.signatures[0].label, "sum(field)");
        let eval_call = "| eval total=sum(";
        let help = signature_help(eval_call, eval_call.len()).expect("eval sum");
        assert_eq!(help.signatures[0].label, "sum(X,...)");
    }

    #[test]
    fn macro_signature_is_unchanged() {
        let src = "| `drop_dm_object_name(";
        let help = signature_help(src, src.len()).expect("macro");
        assert_eq!(help.signatures[0].label, "drop_dm_object_name(object)");
        assert_eq!(help.signatures[0].parameters[0].label, "object");
        let bare = "| `security_content_ctime(firstTime)`";
        let h = hover(
            bare,
            opentide_core::Position::new(0, bare.find("security_content_ctime").unwrap() as u32),
        )
        .expect("macro hover");
        assert!(h.contains("security_content_ctime(field)"), "{h}");

        let notable = "| `notable(";
        let help = signature_help(notable, notable.len()).expect("notable");
        assert_eq!(help.signatures[0].label, "notable");
        assert!(
            help.signatures[0].parameters.is_empty(),
            "a macro signature without parentheses has no parameters: {:?}",
            help.signatures[0].parameters
        );
    }

    #[test]
    fn command_options_drive_signature_help() {
        let src = "| tstats ";
        let help = signature_help(src, src.len()).expect("tstats");
        let label = &help.signatures[0].label;
        assert!(label.starts_with("tstats "), "{label}");
        for arg in ["summariesonly=", "from", "where", "by", "datamodel="] {
            assert!(label.contains(arg), "{arg} missing from {label}");
        }
        assert!(
            help.signatures[0]
                .parameters
                .iter()
                .any(|p| p.label == "summariesonly")
        );
        let rex = "| rex field=_raw ";
        let help = signature_help(rex, rex.len()).expect("rex");
        assert!(
            help.signatures[0].label.contains("[field=]"),
            "{:?}",
            help.signatures[0].label
        );
        assert!(help.signatures[0].label.contains("[mode=]"));
        let by = help.signatures[0]
            .parameters
            .iter()
            .position(|p| p.label == "field")
            .unwrap() as u32;
        assert_eq!(help.active_parameter, by);
    }

    #[derive(Debug, Deserialize)]
    struct ArgumentFixture {
        cases: Vec<ArgumentCase>,
    }

    #[derive(Debug, Deserialize)]
    struct ArgumentCase {
        command: String,
        source: String,
        citation: String,
        expect: Vec<String>,
        #[serde(default)]
        absent: Vec<String>,
    }

    #[test]
    fn argument_completion_matches_search_reference_fixture() {
        let raw = include_str!("../../../testdata/conformance/spl/argument-completion.toml");
        let fixture: ArgumentFixture = toml::from_str(raw).expect("argument fixture");
        let required = ["tstats", "stats", "rex", "lookup", "join", "timechart"];
        for command in required {
            assert!(
                fixture.cases.iter().any(|c| c.command == command),
                "fixture missing {command}"
            );
        }
        for case in &fixture.cases {
            assert!(
                case.citation.starts_with(
                    "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/"
                ),
                "{} citation {}",
                case.command,
                case.citation
            );
            let items = completions(&case.source, case.source.len());
            let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
            for expected in &case.expect {
                assert!(
                    labels.iter().any(|l| l.eq_ignore_ascii_case(expected)),
                    "{} missing {expected} in {:?}",
                    case.command,
                    labels.iter().take(20).collect::<Vec<_>>()
                );
            }
            for banned in &case.absent {
                assert!(
                    !labels.iter().any(|l| l.eq_ignore_ascii_case(banned)),
                    "{} should not offer {banned}",
                    case.command
                );
            }
        }
    }
}
