//! I/O-free SPL engine. Catalogs compiled in; unknown commands are never silently eaten.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

#![expect(
    missing_docs,
    reason = "imported from language-server with public items undocumented: crates/AGENTS.md, Lints"
)]
#![expect(
    clippy::too_many_lines,
    reason = "engine dispatchers match every node kind in one function"
)]

use opentide_core::{
    CompletionItem, Diagnostic, ParameterInformation, Range, SignatureHelp, SignatureInformation,
    codes, suggest,
};
use opentide_highlight::HighlightToken;
mod cim;
mod declared;
mod perf;
mod scan;
mod search_operators;
#[doc(hidden)]
pub mod syntax;

#[cfg(debug_assertions)]
#[doc(hidden)]
pub use scan::nested_scans;

// What the generated typed AST names from the crate root (`use crate::{..}`).
#[doc(hidden)]
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};

/// The typed AST `cargo xtask codegen` writes from `spl.ungram`.
#[doc(hidden)]
#[path = "generated/ast.rs"]
pub mod ast;

use std::sync::OnceLock;

pub use catalog_model::{CommandOption, CommandRow, DatamodelRow, FieldRow, FunctionRow, MacroRow};

mod catalog_model;
mod index;
mod parens;

impl DatamodelRow {
    /// The model name: `model`, or the part of `name` before the first dot.
    pub fn model_name(&self) -> &str {
        self.model
            .as_deref()
            .unwrap_or_else(|| self.name.split('.').next().unwrap_or(&self.name))
    }

    /// Root to dataset, dot-separated.
    pub fn lineage(&self) -> &str {
        self.lineage.as_deref().unwrap_or(&self.prefix)
    }

    /// The dataset's object name (the last lineage segment).
    pub fn object(&self) -> &str {
        self.lineage().rsplit('.').next().unwrap_or(&self.prefix)
    }
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub commands: Vec<CommandRow>,
    pub functions: Vec<FunctionRow>,
    pub fields: Vec<FieldRow>,
    pub datamodels: Vec<DatamodelRow>,
    /// Data models known by name only, beyond the ones `datamodels` covers.
    pub extra_models: Vec<String>,
    pub macros: Vec<MacroRow>,
    pub options: Vec<CommandOption>,
}

/// What `build.rs` stores (#1743), parsed once at build time: the commands, the functions, the
/// fields, the datamodels, the models known by name only, the macros and the command options.
type Model = (
    Vec<CommandRow>,
    Vec<FunctionRow>,
    Vec<FieldRow>,
    Vec<DatamodelRow>,
    Vec<String>,
    Vec<MacroRow>,
    Vec<CommandOption>,
);

/// The catalogs, pre-parsed by `build.rs` and decoded on first use.
fn model() -> Model {
    opentide_dataset::compiled_value("spl-catalog", opentide_dataset::blob!("spl-catalog"))
}

impl Catalog {
    pub fn load() -> Self {
        let (commands, functions, fields, datamodels, extra_models, macros, options) = model();
        Self {
            commands,
            functions,
            fields,
            datamodels,
            extra_models,
            macros,
            options,
        }
    }

    pub fn cached() -> &'static Self {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(Self::load)
    }

    pub fn command(&self, name: &str) -> Option<&CommandRow> {
        if let Some(index) = index::Index::of(self) {
            return index.command(name).and_then(|i| self.commands.get(i));
        }
        index::scanned(self.commands.len());
        self.commands
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        if let Some(index) = index::Index::of(self) {
            return index
                .functions(name)
                .first()
                .and_then(|&i| self.functions.get(i));
        }
        index::scanned(self.functions.len());
        self.functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    /// Eval and aggregate rows can share a name (`sum`, `avg`, `min`, `max`).
    /// `aggregate` selects the stats/chart form; otherwise the eval form wins.
    pub fn function_in_context(&self, name: &str, aggregate: bool) -> Option<&FunctionRow> {
        // The rows named `name`: through the index, or every row, scanned.
        let (indexed, all): (&[usize], &[FunctionRow]) = match index::Index::of(self) {
            Some(index) => (index.functions(name), &[]),
            None => {
                index::scanned(self.functions.len());
                (&[], &self.functions)
            }
        };
        let named = indexed
            .iter()
            .filter_map(|&i| self.functions.get(i))
            .chain(all);
        let mut fallback = None;
        for f in named {
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

    /// The catalogued command `name` most likely means
    /// ([`opentide_core::suggest`]). A name one typo from a command (one
    /// edit, or swapped neighbours, which `spl_unknown_command` reports as an
    /// error) names the best of those commands, so an error that calls the
    /// name a typo always says of what (`tsast`, two swaps, is `stats`).
    pub fn suggest_command(&self, name: &str) -> Option<String> {
        let typos = self.command_typos(name);
        if typos.is_empty() {
            match index::Index::of(self) {
                // The names prepared once: the same ranking as `closest`.
                Some(index) => index
                    .command_names
                    .closest(name)
                    .and_then(|i| self.commands.get(i))
                    .map(|c| c.name.as_str()),
                None => suggest::closest(name, self.commands.iter().map(|c| c.name.as_str())),
            }
        } else {
            suggest::best(name, typos)
        }
        .map(str::to_string)
    }

    /// The catalogued commands `name` is one typo from ([`one_typo`]).
    fn command_typos(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        let Some(index) = index::Index::of(self) else {
            return self
                .commands
                .iter()
                .filter(|c| one_typo(&c.name.to_ascii_lowercase(), &lower))
                .map(|c| c.name.as_str())
                .collect();
        };
        // One typo is at most two edits, and two only as swaps, which keep
        // the length: a name longer or shorter by more than one character,
        // or with more than two characters the other lacks, is none, and
        // its distance is not measured (ADR 0014, rule 4).
        let length = lower.chars().count();
        index
            .lowered_commands
            .iter()
            .zip(&self.commands)
            .filter(|((other, other_length), _)| {
                other_length.abs_diff(length) <= 1
                    && suggest::bag_distance(other, &lower).is_none_or(|d| d <= 2)
                    && one_typo(other, &lower)
            })
            .map(|(_, c)| c.name.as_str())
            .collect()
    }

    /// Whether `name` is one typo from a catalogued command ([`one_typo`]):
    /// then `spl_unknown_command` is an error, not a warning an app may
    /// explain.
    fn is_command_typo(&self, name: &str) -> bool {
        !self.command_typos(name).is_empty()
    }

    pub fn field(&self, name: &str) -> Option<&FieldRow> {
        let bare = name.rsplit('.').next().unwrap_or(name);
        if let Some(index) = index::Index::of(self) {
            return index.field(name, bare).and_then(|i| self.fields.get(i));
        }
        index::scanned(self.fields.len());
        self.fields
            .iter()
            .find(|f| f.name == name || f.name == bare)
    }

    pub fn datamodel(&self, name: &str) -> Option<&DatamodelRow> {
        if let Some(index) = index::Index::of(self) {
            return index.datamodel(name).and_then(|i| self.datamodels.get(i));
        }
        index::scanned(self.datamodels.len());
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

    /// The first data model dataset the search reads (`tstats ... from
    /// datamodel=Endpoint.Processes`, `| datamodel Endpoint Processes`,
    /// `| from datamodel:Endpoint.Processes`).
    pub fn active_datamodel(&self, source: &str) -> Option<&'static DatamodelRow> {
        cim::first_dataset(source)
    }
}

/// Whether `a` and `b` are one typo apart: one insertion, deletion or
/// substitution, or swapped neighbours, once or twice (`stast` and `tsast`
/// are `stats`). Equal strings are not.
fn one_typo(a: &str, b: &str) -> bool {
    #[cfg(test)]
    DISTANCES.set(DISTANCES.get() + 1);
    match strsim::osa_distance(a, b) {
        1 => true,
        2 => only_swaps(a, b),
        _ => false,
    }
}

/// Whether `b` is `a` with disjoint pairs of neighbours swapped and nothing
/// else changed.
fn only_swaps(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] == b[i] {
            i += 1;
        } else if i + 1 < a.len() && a[i] == b[i + 1] && a[i + 1] == b[i] {
            i += 2;
        } else {
            return false;
        }
    }
    true
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

/// Analyzes `source`: syntax errors, the catalog checks, and highlighting,
/// on the pure-Rust parser (`syntax`).
pub fn analyze(source: &str) -> AnalyzeResult {
    syntax::analyze(source)
}

/// The Splunk SPL [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Spl
    }

    fn analyze_for(
        &self,
        source: &str,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> opentide_highlight::AnalyzeResult {
        let r = analyze(source);
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }

    fn hover(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Option<String> {
        hover(source, offset)
    }

    fn completions(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Vec<opentide_core::CompletionItem> {
        completions(source, offset)
    }

    fn signature_help(
        &self,
        source: &str,
        offset: usize,
        _setting: &opentide_highlight::Setting<'_>,
    ) -> Option<opentide_core::SignatureHelp> {
        signature_help(source, offset)
    }
}

#[cfg(test)]
thread_local! {
    /// Typo distances measured on this thread ([`one_typo`]).
    static DISTANCES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(debug_assertions)]
thread_local! {
    /// The unknown-command findings made on this thread: [`unknown_command_findings`].
    static UNKNOWN_COMMAND_FINDINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many unknown-command findings this thread has built, each with a scan
/// of the command catalog: one per distinct name in an analysis
/// (`tests/many_findings.rs`). Debug builds only; not API.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn unknown_command_findings() -> usize {
    UNKNOWN_COMMAND_FINDINGS.get()
}

pub(crate) fn unknown_command(name: &str, range: Range, catalog: &Catalog) -> Diagnostic {
    #[cfg(debug_assertions)]
    UNKNOWN_COMMAND_FINDINGS.set(UNKNOWN_COMMAND_FINDINGS.get() + 1);
    // A near miss is an error, which `[queries.codes]` in lint.toml cannot
    // lower: it says to check the spelling. Any other name is a warning, which
    // it can (nothing declares an app's commands yet).
    let mut d = if catalog.is_command_typo(name) {
        let message = format!(
            "'{name}' is not a command opentide knows; it looks like a misspelt known command, so check the spelling"
        );
        Diagnostic::error(codes::SPL_UNKNOWN_COMMAND, message, range)
    } else {
        let message = format!(
            "'{name}' is not a command opentide knows; if an app on the search head provides it, set `spl_unknown_command = \"info\"` under `[queries.codes]` in lint.toml"
        );
        Diagnostic::warning(codes::SPL_UNKNOWN_COMMAND, message, range)
    };
    if let Some(suggestion) = catalog.suggest_command(name) {
        d = d.with_suggestion(suggestion);
    }
    d
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
    let left = before.trim_end().strip_suffix('=')?.trim_end();
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
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
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
    if let Some(values) = cim::expected_values(source, before) {
        return values
            .iter()
            .map(|v| complete_item(v.clone(), "enum", Some("CIM expected value".into()), None))
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
                for (dataset, column) in declared::declared_fields(source, catalog) {
                    if seen.insert(column.name.to_ascii_lowercase()) {
                        let detail = format!(
                            "{dataset} ({})",
                            column.type_name.as_deref().unwrap_or("field")
                        );
                        items.push(complete_item(
                            column.name,
                            "column",
                            Some(detail),
                            column.description,
                        ));
                    }
                }
                if let Some(dm) = catalog.active_datamodel(source) {
                    for (prefixed, f) in cim::visible_fields(dm) {
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
                                f,
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
        #[expect(
            clippy::string_slice,
            reason = "with `i < j`, `i..j` is a run of ASCII name bytes: char boundaries"
        )]
        let word = &source[i..j];
        Some(word.to_string())
    }
}

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    let before = source.get(..offset)?;
    let catalog = Catalog::cached();
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
    if let Some(cmd) = last_command(before)
        && let Some(opt) = catalog
            .options_for(argument_command(&cmd))
            .into_iter()
            .find(|o| o.name.eq_ignore_ascii_case(&word))
    {
        return Some(option_markdown(opt));
    }
    if let Some(c) = catalog.command(&word) {
        let source_label = c.app.as_deref().unwrap_or("searchbnf");
        let citation = c
            .citation
            .as_deref()
            .map(|c| format!("\n\n[{source_label}]({c})"))
            .unwrap_or_default();
        let kind = match &c.app {
            Some(app) => format!("{}, {app} app", c.kind),
            None => c.kind.clone(),
        };
        return Some(format!(
            "**{}** ({kind})\n\n{}{citation}",
            c.name,
            c.docs.clone().unwrap_or_default()
        ));
    }
    let aggregate = last_command(before).is_some_and(|cmd| aggregate_command(&cmd));
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
    if let Some((dataset, column)) = declared::declared_fields(source, catalog)
        .into_iter()
        .find(|(_, c)| c.name == word)
    {
        let mut md = format!(
            "**{}** field (`{}`), declared in visibility.toml on `{dataset}`",
            column.name,
            column.type_name.as_deref().unwrap_or("field")
        );
        if let Some(description) = &column.description {
            md.push_str(&format!("\n\n{description}"));
        }
        return Some(md);
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
    // An offset inside a character (a decoded escape) has nothing to show.
    let before = source.get(..offset.min(source.len()))?;
    let catalog = Catalog::cached();
    if let Some((name, active)) = innermost_call(before) {
        let cmd = last_command(before);
        let same_as_command = cmd.as_ref().is_some_and(|c| c.eq_ignore_ascii_case(&name));
        if !same_as_command {
            let aggregate = cmd.as_ref().is_some_and(|c| aggregate_command(c));
            if let Some(f) = catalog.function_in_context(&name, aggregate)
                && let Some(help) = function_signature(f, active)
            {
                return Some(help);
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

#[expect(
    clippy::cast_possible_truncation,
    reason = "a signature has a handful of parameters, far below u32::MAX"
)]
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

#[expect(
    clippy::cast_possible_truncation,
    reason = "an index into one command's options, a handful"
)]
fn active_option(before: &str, opts: &[&CommandOption]) -> u32 {
    let lower = before.to_ascii_lowercase();
    let mut best: Option<(usize, u32)> = None;
    for (i, opt) in opts.iter().enumerate() {
        let needle = opt.name.to_ascii_lowercase();
        if let Some(pos) = rfind_word(&lower, &needle)
            && best.map(|(at, _)| pos >= at).unwrap_or(true)
        {
            best = Some((pos, i as u32));
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
    #[expect(
        clippy::string_slice,
        reason = "`i` and `open` index ASCII bytes (name bytes or the `(`): char boundaries"
    )]
    let (name, inside) = (&before[i..open], &before[open + 1..]);
    let name = name.trim_matches('`').to_string();
    if name.is_empty() {
        return None;
    }
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
    let Some((head, rest)) = sig.split_once('(') else {
        return Vec::new();
    };
    // Up to the last `)`, which must come after the `(`.
    let inner = match rest.rsplit_once(')') {
        Some((inner, _)) => inner,
        None if head.contains(')') => return Vec::new(),
        None => rest,
    };
    if inner.is_empty() {
        return Vec::new();
    }
    let mut params = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in inner.chars() {
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

/// Whether `source` parses without an error: the parse alone, with no
/// analysis, for the throughput benchmark (`cargo bench --bench throughput`, ADR
/// 0014). Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn parses(source: &str) -> bool {
    syntax::parse(source).1.errors.is_empty()
}

/// Whether the grammar reports an error in `source`, and the `Debug` names of
/// the kinds of its tree, nodes and tokens in preorder: what the corpus gate of
/// `opentide-analysis` reads. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_kinds(source: &str) -> (bool, Vec<String>) {
    opentide_parse::debug_kinds::<Lang>(&syntax::parse(source).1)
}

/// For each syntax error of `source`, the `Debug` names of the nodes it was recorded in: what
/// the corpus gate of `opentide-analysis` reads to check that an invalid fixture fails in
/// the production it names. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_error_kinds(source: &str) -> Vec<Vec<String>> {
    opentide_parse::debug_error_kinds::<Lang>(&syntax::parse(source).1)
}

/// The `Debug` names of the node kinds the grammar declares, the error node
/// left out: the productions the corpus gate of `opentide-analysis` asks a
/// fixture of. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn debug_node_kinds() -> Vec<String> {
    (SyntaxKind::SOURCE_FILE as u16..SyntaxKind::ERROR as u16)
        .map(|raw| {
            format!(
                "{:?}",
                <Lang as rowan::Language>::kind_from_raw(rowan::SyntaxKind(raw))
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn commands_toml() -> &'static str {
        opentide_dataset::text!("data/catalogs/spl/commands.toml")
    }
    fn fields_toml() -> &'static str {
        opentide_dataset::text!("data/catalogs/spl/fields.toml")
    }
    fn datamodels_toml() -> &'static str {
        opentide_dataset::text!("data/catalogs/spl/datamodels.toml")
    }
    fn macros_toml() -> &'static str {
        opentide_dataset::text!("data/catalogs/spl/macros.toml")
    }
    fn options_toml() -> &'static str {
        opentide_dataset::text!("data/catalogs/spl/command-options.toml")
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CommandsFile {
        commands: Vec<CommandRow>,
        #[serde(default)]
        functions: Vec<FunctionRow>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FieldsFile {
        fields: Vec<FieldRow>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DatamodelsFile {
        #[serde(default)]
        models: Vec<String>,
        datamodels: Vec<DatamodelRow>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MacrosFile {
        macros: Vec<MacroRow>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OptionsFile {
        options: Vec<CommandOption>,
    }

    /// What the build stored is the whole-file parse, field for field (#1743).
    #[test]
    fn the_stored_catalogs_are_the_whole_files() {
        let (commands, functions, fields, datamodels, extra_models, macros, options) = model();
        let whole: CommandsFile = toml::from_str(commands_toml()).unwrap();
        assert_eq!(format!("{commands:?}"), format!("{:?}", whole.commands));
        assert_eq!(format!("{functions:?}"), format!("{:?}", whole.functions));
        let whole: FieldsFile = toml::from_str(fields_toml()).unwrap();
        assert_eq!(format!("{fields:?}"), format!("{:?}", whole.fields));
        let whole: DatamodelsFile = toml::from_str(datamodels_toml()).unwrap();
        assert_eq!(format!("{datamodels:?}"), format!("{:?}", whole.datamodels));
        assert_eq!(extra_models, whole.models);
        let whole: MacrosFile = toml::from_str(macros_toml()).unwrap();
        assert_eq!(format!("{macros:?}"), format!("{:?}", whole.macros));
        let whole: OptionsFile = toml::from_str(options_toml()).unwrap();
        assert_eq!(format!("{options:?}"), format!("{:?}", whole.options));
    }

    /// #179: tree-sitter's `prev_sibling()` cycled between a MISSING `)` and a
    /// zero-width node, so `analyze` never returned on this query.
    #[test]
    fn a_recovered_tree_with_zero_width_nodes_does_not_hang_analysis() {
        let query = "index=main | eval s=case(bytes>1, 1, true((), 0), t=if(us lik\r\ne \"a%\", 1,";
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = analyze(query);
            let _ = done.send(result.diagnostics.len());
        });
        let found = finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("analyze returned within 10 s");
        assert!(found > 0, "the broken query is reported");
    }

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

    fn unknown_commands(src: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_UNKNOWN_COMMAND)
            .collect()
    }

    #[test]
    fn unknown_command_is_a_warning_an_app_may_explain() {
        let found = unknown_commands("index=a | mispsearch field=user");
        assert_eq!(found.len(), 1, "{found:?}");
        let d = &found[0];
        assert_eq!(d.severity, opentide_core::Severity::Warning, "{d:?}");
        assert_eq!(
            d.message,
            "'mispsearch' is not a command opentide knows; if an app on the search head provides it, set `spl_unknown_command = \"info\"` under `[queries.codes]` in lint.toml"
        );
    }

    #[test]
    fn misspelt_command_keeps_its_suggestion() {
        let found = unknown_commands("index=a | stast count");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].suggestion.as_deref(), Some("stats"), "{found:?}");
        // One edit from a known command is a typo Splunk rejects.
        assert_eq!(found[0].severity, opentide_core::Severity::Error);
        assert_eq!(
            found[0].message,
            "'stast' is not a command opentide knows; it looks like a misspelt known command, so check the spelling"
        );
        let typo = unknown_commands("index=a | statz count");
        assert_eq!(typo.len(), 1, "{typo:?}");
        assert_eq!(typo[0].severity, opentide_core::Severity::Error, "{typo:?}");
        assert_eq!(typo[0].suggestion.as_deref(), Some("stats"));
        // Two swaps are still one typo, and the error names the command.
        let swaps = unknown_commands("index=a | tsast count");
        assert_eq!(
            swaps[0].severity,
            opentide_core::Severity::Error,
            "{swaps:?}"
        );
        assert_eq!(swaps[0].suggestion.as_deref(), Some("stats"), "{swaps:?}");
        // Further away it may be an app's command: a warning, still with a
        // hint while the shared rule finds one (two edits in a long name).
        let far = unknown_commands("index=a | evntstatss count");
        assert_eq!(far[0].severity, opentide_core::Severity::Warning, "{far:?}");
        assert_eq!(far[0].suggestion.as_deref(), Some("eventstats"), "{far:?}");
        // Two edits side by side in a six-letter name: a warning (not one
        // typo), still with its hint (a third of the word, two edits).
        let short = unknown_commands("index=a | stattz count");
        assert_eq!(
            short[0].severity,
            opentide_core::Severity::Warning,
            "{short:?}"
        );
        assert_eq!(short[0].suggestion.as_deref(), Some("stats"), "{short:?}");
        // Three edits in a five-letter name: no hint.
        let far = unknown_commands("index=a | xtatzz count");
        assert_eq!(far[0].suggestion, None, "{far:?}");
    }

    #[test]
    fn one_typo_is_one_edit_or_swapped_neighbours() {
        assert!(!one_typo("stats", "stats"));
        assert!(one_typo("stats", "stast"));
        assert!(one_typo("stats", "tsast"));
        assert!(one_typo("stats", "tsats"));
        assert!(one_typo("stats", "statz"));
        assert!(one_typo("stats", "stat"));
        assert!(one_typo("stats", "sstats"));
        // Two edits, one of them not a swap: not one typo.
        assert!(!one_typo("stats", "tsatz"));
        assert!(!one_typo("stats", "stattz"));
        assert!(!one_typo("stats", "sats1"));
        assert!(!one_typo("", "abc"));
        assert!(!one_typo("head", "tail"));
        assert!(only_swaps("abcd", "badc"));
        assert!(!only_swaps("abc", "cba"));
        assert!(!only_swaps("abc", "ab"));
    }

    #[test]
    fn mltk_commands_are_catalogued_as_an_app() {
        let c = Catalog::load();
        for name in [
            "fit",
            "apply",
            "score",
            "summary",
            "listmodels",
            "deletemodel",
        ] {
            let row = c.command(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(row.app.as_deref(), Some("MLTK"), "{name}");
        }
        assert!(c.command("stats").unwrap().app.is_none());
        for src in [
            "index=a | apply m",
            "index=a | fit LinearRegression y from x into m",
            "| listmodels",
        ] {
            let r = analyze(src);
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::SPL_UNKNOWN_COMMAND),
                "{src}: {:?}",
                r.diagnostics
            );
        }
        let h = hover("index=a | apply m", 11).expect("hover");
        assert!(h.contains("MLTK"), "{h}");
    }

    #[test]
    fn recovery_fragments_are_not_unknown_commands() {
        // The stray `=` breaks the stats by-list; recovery strands `head`,
        // `x` and `y`, none of which is in command position.
        let src = "index=a | stats count by host , , = head x y";
        let r = analyze(src);
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::SPL_PARSE_ERROR),
            "{:?}",
            r.diagnostics
        );
        assert!(unknown_commands(src).is_empty(), "{:?}", r.diagnostics);
    }

    #[test]
    fn unknown_command_in_command_position_is_reported() {
        for (src, name) in [
            ("index=a | bogus x", "bogus"),
            ("| bogus x", "bogus"),
            ("index=a | join k [ bogus x ]", "bogus"),
            ("index=a | join k [ search index=b | bogus x ]", "bogus"),
            ("index=a | ```note``` bogus x", "bogus"),
        ] {
            let found = unknown_commands(src);
            assert_eq!(found.len(), 1, "{src}: {found:?}");
            assert!(found[0].message.contains(name), "{src}: {found:?}");
        }
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
            let s = "index=main | head 1".get(t.span.start..t.span.end).unwrap();
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
        let h = hover("index=main | stats count by host", 14);
        assert!(h.unwrap().to_lowercase().contains("stats"));
    }

    #[test]
    fn hover_function_from_catalog() {
        let h = hover("index=main | eval x=lower(user)", 22);
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
        let slice = |t: &opentide_highlight::HighlightToken| {
            src.get(t.span.start..t.span.end).unwrap().to_string()
        };
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
            .map(|t| {
                (
                    t.capture.as_str(),
                    src.get(t.span.start..t.span.end).unwrap(),
                )
            })
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
            .map(|t| {
                (
                    t.capture.as_str(),
                    src.get(t.span.start..t.span.end).unwrap(),
                )
            })
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
        let h = hover(src, src.find("Processes.user").unwrap() + 11);
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
        let h = hover(src, 16).expect("macro hover");
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
            let at = src.find(&format!("{name}(")).unwrap();
            let text = hover(src, at).expect(name);
            assert!(text.contains("(aggregate)"), "{name}: {text}");
            assert!(text.contains(&format!("{name}(field)")), "{name}: {text}");
            assert!(!text.contains("eval args"), "{name}: {text}");
        }
        let eval_src = "| eval total=sum(a, b)";
        let at = eval_src.find("sum(").unwrap();
        let text = hover(eval_src, at).expect("eval sum");
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
        let h = hover(bare, bare.find("security_content_ctime").unwrap()).expect("macro hover");
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
    #[expect(
        clippy::cast_possible_truncation,
        reason = "positions in a test document of a few lines"
    )]
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
        let raw = include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/crates/testdata/conformance/spl/argument-completion.toml"
        ));
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

    #[test]
    fn bucket_signature_uses_bin_arguments() {
        let src = "| bucket ";
        let help = signature_help(src, src.len()).expect("bucket");
        assert!(
            help.signatures[0].label.starts_with("bucket "),
            "{}",
            help.signatures[0].label
        );
        assert!(
            help.signatures[0]
                .parameters
                .iter()
                .any(|p| p.label == "bins"),
            "{:?}",
            help.signatures[0].parameters
        );
        assert!(
            help.signatures[0]
                .documentation
                .as_deref()
                .unwrap_or("")
                .contains("Search Reference"),
            "{:?}",
            help.signatures[0].documentation
        );

        let minspan = "| bin minspan=";
        let help = signature_help(minspan, minspan.len()).expect("minspan");
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label, "minspan",
            "`span` is a suffix of `minspan` and must not steal the active parameter: {:?}",
            help.signatures[0].parameters
        );

        let span = "| bin span=";
        let help = signature_help(span, span.len()).expect("span");
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label,
            "span"
        );
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "index=main user=\"\u{e9}\" | stats count";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside).is_empty());
        assert_eq!(hover(src, inside), None);
        assert!(signature_help(src, inside).is_none());
    }

    /// Queries with multi-byte text in every place the scanners cut: the
    /// data model checks, declared sourcetypes, the performance and search
    /// operator checks, parentheses, directives and signs. The spans they
    /// cut are checked in debug builds (`scan::cut`).
    const MULTI_BYTE: &[&str] = &[
        "index=é sourcetype=\"😀\" | tstats count from datamodel=Endpoint.Processes where Processes.é😀=* by Processes.user | rename Processes.* as é",
        "| datamodel Endpoint Processes search | search Processes.process_name=é*😀 Processes.usér=x",
        "search é*😀 \"é😀\" TERM(é😀) CASE(é) PREFIX(😀) | eval x=é😀(1) | fields + é😀+x - y | sort -é",
        "index=x é😀==200 ``` é😀 ``` | where é😀=\"x\" | stats count(é😀) as n by é😀",
        "index=x (é😀 | eval a=\"(é\" | stats count",
        "`é😀(1)` | inputlookup é😀 where é=1 | tstats count where index=é by dst=é",
        "index=x sourcetype=é😀 sourcetype IN (é, \"😀\") | search NOT é😀=*x* | rename é😀 as 'é'x",
        "index=x a=\"é\"😀\\é b='😀'é | `drop_dm_object_name(é😀)` | eval y=coalesce(é, \"😀\", ",
    ];

    #[test]
    fn multi_byte_text_is_read_whole_everywhere() {
        for query in MULTI_BYTE {
            let result = analyze(query);
            for token in &result.tokens {
                assert!(
                    query.get(token.span.start..token.span.end).is_some(),
                    "{query}"
                );
            }
            for (offset, _) in query.char_indices().chain([(query.len(), ' ')]) {
                let _ = hover(query, offset);
                let _ = completions(query, offset);
                let _ = signature_help(query, offset);
            }
        }
    }

    #[test]
    fn helpers_read_multi_byte_text() {
        let source = "é😀 abc.d é";
        let at = source.find('b').unwrap();
        assert_eq!(spl_word_at(source, at).as_deref(), Some("abc.d"));
        assert_eq!(spl_word_at(source, 0), None);
        assert_eq!(spl_word_at(source, source.len()), None);
        assert_eq!(spl_word_at("aé", 1), None);
        assert_eq!(
            innermost_call("eval x=coalesce(é, \"😀\", "),
            Some(("coalesce".to_owned(), 2))
        );
        assert_eq!(innermost_call("é😀(é"), None);
        let labels = |sig: &str| -> Vec<String> {
            parameters_from_signature(sig)
                .into_iter()
                .map(|p| format!("{:?}", p.label))
                .collect()
        };
        assert_eq!(labels("f(é, 😀)").len(), 2);
        assert_eq!(labels("f(é").len(), 1);
        assert!(labels(")é(x").is_empty());
        assert!(labels("é()").is_empty());
        assert!(labels("é").is_empty());
        assert_eq!(
            hover("index=x | eval y=é😀", "index=x | eval y=é".len()),
            None
        );
    }
}
