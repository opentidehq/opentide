//! I/O-free KQL engine. Catalogs are compiled in; no `std::fs`.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Range, SignatureHelp,
    SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
mod perf;

use opentide_syntax::{has_error, parse as ts_parse};
use serde::Deserialize;
use std::sync::OnceLock;
use tree_sitter::Node;

const OPERATORS_TOML: &str = include_str!("../../../catalogs/kql/core/operators.toml");
const FUNCTIONS_TOML: &str = include_str!("../../../catalogs/kql/core/functions.toml");
const TYPES_TOML: &str = include_str!("../../../catalogs/kql/core/types.toml");
const SCALAR_OPERATORS_TOML: &str =
    include_str!("../../../catalogs/kql/core/operators-scalar.toml");
const PLUGINS_TOML: &str = include_str!("../../../catalogs/kql/core/evaluate-plugins.toml");
const SENTINEL_TABLES: &str = include_str!("../../../catalogs/kql/sentinel/tables.toml");
const DEFENDER_TABLES: &str = include_str!("../../../catalogs/kql/defender/tables.toml");
const SENTINEL_COLUMNS: &str = include_str!("../../../catalogs/kql/sentinel/columns.toml");
const DEFENDER_COLUMNS: &str = include_str!("../../../catalogs/kql/defender/columns.toml");
const OPERATOR_OPTIONS: &str = include_str!("../../../catalogs/kql/core/operator-options.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Core,
    Sentinel,
    Defender,
}

#[derive(Debug, Clone, Deserialize)]
struct OperatorsFile {
    operators: Vec<OperatorRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParamRow {
    pub name: String,
    #[serde(default)]
    pub docs: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorRow {
    pub name: String,
    pub kind: String,
    pub docs: Option<String>,
    pub warning: Option<String>,
    pub citation: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
    #[serde(default)]
    pub alias_of: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FunctionsFile {
    functions: Vec<FunctionRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub signature: Option<String>,
    pub docs: Option<String>,
    pub kind: Option<String>,
    pub citation: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ScalarOperatorsFile {
    scalar_operators: Vec<ScalarOperatorRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScalarOperatorRow {
    pub name: String,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginsFile {
    plugins: Vec<PluginRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginRow {
    pub name: String,
    pub docs: Option<String>,
    pub citation: Option<String>,
    pub warning: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct TypesFile {
    types: Vec<TypeRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct TypeRow {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TablesFile {
    tables: Vec<TableRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TableRow {
    pub name: String,
    pub profile: Option<String>,
    pub category: Option<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ColumnsFile {
    columns: Vec<ColumnRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ColumnRow {
    pub table: String,
    pub profile: Option<String>,
    pub name: String,
    #[serde(default, rename = "type")]
    pub type_name: Option<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OptionsFile {
    options: Vec<OperatorOption>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorOption {
    pub operator: String,
    pub name: String,
    pub kind: Option<String>,
    #[serde(default)]
    pub values: Vec<String>,
    pub docs: Option<String>,
    pub citation: Option<String>,
    pub signature: Option<String>,
    /// Where the option is typed: `equals` (`name=`), `value` (bare enum),
    /// `token` (bare keyword in the operator prefix), `alongside` (offered with
    /// ordinary completions for the rest of the clause).
    #[serde(default)]
    pub place: Option<String>,
    /// When set, values complete inside `operator(` at this zero-based argument.
    #[serde(default)]
    pub parameter_index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub operators: Vec<OperatorRow>,
    pub functions: Vec<FunctionRow>,
    pub scalar_operators: Vec<ScalarOperatorRow>,
    pub plugins: Vec<PluginRow>,
    pub types: Vec<String>,
    pub tables: Vec<TableRow>,
    pub columns: Vec<ColumnRow>,
    pub options: Vec<OperatorOption>,
}

impl Catalog {
    pub fn core() -> Self {
        let operators: OperatorsFile = toml::from_str(OPERATORS_TOML).expect("operators.toml");
        let functions: FunctionsFile = toml::from_str(FUNCTIONS_TOML).expect("functions.toml");
        let types: TypesFile = toml::from_str(TYPES_TOML).expect("types.toml");
        let scalar: ScalarOperatorsFile =
            toml::from_str(SCALAR_OPERATORS_TOML).expect("operators-scalar.toml");
        let plugins: PluginsFile = toml::from_str(PLUGINS_TOML).expect("evaluate-plugins.toml");
        Self {
            operators: operators.operators,
            functions: functions.functions,
            scalar_operators: scalar.scalar_operators,
            plugins: plugins.plugins,
            types: types.types.into_iter().map(|t| t.name).collect(),
            tables: Vec::new(),
            columns: Vec::new(),
            options: {
                let file: OptionsFile =
                    toml::from_str(OPERATOR_OPTIONS).expect("operator-options.toml");
                file.options
            },
        }
    }

    pub fn with_profile(mut self, profile: Profile) -> Self {
        let extra = match profile {
            Profile::Core => return self,
            Profile::Sentinel => SENTINEL_TABLES,
            Profile::Defender => DEFENDER_TABLES,
        };
        let tables: TablesFile = toml::from_str(extra).expect("tables.toml");
        self.tables = tables.tables;
        let mut columns = Vec::new();
        match profile {
            Profile::Core => {}
            Profile::Sentinel => {
                let s: ColumnsFile = toml::from_str(SENTINEL_COLUMNS).expect("sentinel columns");
                let d: ColumnsFile = toml::from_str(DEFENDER_COLUMNS).expect("defender columns");
                columns.extend(s.columns);
                columns.extend(d.columns);
            }
            Profile::Defender => {
                let d: ColumnsFile = toml::from_str(DEFENDER_COLUMNS).expect("defender columns");
                columns.extend(d.columns);
            }
        }
        self.columns = columns;
        self
    }

    /// Parsed once per profile for the process. `core()` still reparses for tests.
    pub fn cached(profile: Profile) -> &'static Self {
        match profile {
            Profile::Core => {
                static CORE: OnceLock<Catalog> = OnceLock::new();
                CORE.get_or_init(Self::core)
            }
            Profile::Sentinel => {
                static SENTINEL: OnceLock<Catalog> = OnceLock::new();
                SENTINEL.get_or_init(|| Self::core().with_profile(Profile::Sentinel))
            }
            Profile::Defender => {
                static DEFENDER: OnceLock<Catalog> = OnceLock::new();
                DEFENDER.get_or_init(|| Self::core().with_profile(Profile::Defender))
            }
        }
    }

    pub fn operator(&self, name: &str) -> Option<&OperatorRow> {
        self.operators
            .iter()
            .find(|o| o.name.eq_ignore_ascii_case(name))
    }

    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        self.functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    pub fn table(&self, name: &str) -> Option<&TableRow> {
        self.tables.iter().find(|t| t.name == name)
    }

    pub fn plugin(&self, name: &str) -> Option<&PluginRow> {
        self.plugins
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }

    pub fn suggest_table(&self, name: &str) -> Option<String> {
        self.tables
            .iter()
            .map(|t| {
                (
                    t.name.clone(),
                    strsim_distance(&t.name.to_ascii_lowercase(), &name.to_ascii_lowercase()),
                )
            })
            .filter(|(_, d)| *d <= 4)
            .min_by_key(|(_, d)| *d)
            .map(|(n, _)| n)
    }

    pub fn operator_names(&self) -> Vec<String> {
        self.operators.iter().map(|o| o.name.clone()).collect()
    }

    pub fn function_names(&self) -> Vec<String> {
        self.functions.iter().map(|f| f.name.clone()).collect()
    }

    pub fn columns_for_table(&self, table: &str) -> Vec<&ColumnRow> {
        self.columns
            .iter()
            .filter(|c| c.table.eq_ignore_ascii_case(table))
            .collect()
    }

    pub fn resolve_column(&self, source: &str, name: &str) -> Option<&ColumnRow> {
        let mentioned: Vec<&str> = self
            .tables
            .iter()
            .filter(|t| contains_ident(source, &t.name))
            .map(|t| t.name.as_str())
            .collect();
        if let Some(col) = mentioned.iter().find_map(|table| {
            self.columns
                .iter()
                .find(|c| c.table.eq_ignore_ascii_case(table) && c.name == name)
        }) {
            return Some(col);
        }
        self.columns.iter().find(|c| c.name == name)
    }

    pub fn option_values(&self, operator: &str, option: &str) -> &[String] {
        self.options
            .iter()
            .find(|o| {
                o.operator.eq_ignore_ascii_case(operator) && o.name.eq_ignore_ascii_case(option)
            })
            .map(|o| o.values.as_slice())
            .unwrap_or(&[])
    }

    pub fn is_join_kind(&self, name: &str) -> bool {
        self.option_values("join", "kind")
            .iter()
            .any(|v| v.eq_ignore_ascii_case(name))
    }

    fn canonical_operator(&self, name: &str) -> String {
        self.operator(name)
            .and_then(|op| op.alias_of.clone())
            .unwrap_or_else(|| name.to_string())
    }

    pub fn options_for(&self, operator: &str) -> Vec<&OperatorOption> {
        let canonical = self.canonical_operator(operator);
        self.options
            .iter()
            .filter(|o| {
                o.operator.eq_ignore_ascii_case(operator)
                    || o.operator.eq_ignore_ascii_case(&canonical)
            })
            .collect()
    }
}

fn strsim_distance(a: &str, b: &str) -> usize {
    // Tiny Levenshtein for suggestions.
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut cur = vec![0; b_chars.len() + 1];
    for (i, ca) in a_chars.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_chars.len()]
}

/// Lowered HIR (snapshots via Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hir {
    Query {
        lets: Vec<(String, String)>,
        source: String,
        operators: Vec<HirOp>,
    },
    ControlCommand {
        name: String,
    },
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HirOp {
    pub name: String,
    pub args: String,
}

impl std::fmt::Display for Hir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Hir::Empty => write!(f, "(empty)"),
            Hir::ControlCommand { name } => write!(f, "(control .{name})"),
            Hir::Query {
                lets,
                source,
                operators,
            } => {
                for (n, v) in lets {
                    writeln!(f, "(let {n} = {v})")?;
                }
                write!(f, "(query {source}")?;
                for op in operators {
                    write!(f, " | {} {}", op.name, op.args)?;
                }
                write!(f, ")")
            }
        }
    }
}

pub fn lower(source: &str) -> Hir {
    let Some(tree) = ts_parse(LanguageId::Kql, source) else {
        return Hir::Empty;
    };
    let root = tree.root_node();
    let mut lets = Vec::new();
    let mut source_name = String::new();
    let mut operators = Vec::new();
    if let Some(hir) = walk(&root, source, &mut |node| {
        if node.kind() == "let_statement" {
            let name = child_text(node, "name", source).unwrap_or_default();
            let value = child_text(node, "value", source).unwrap_or_default();
            lets.push((name, value));
        }
        if node.kind() == "control_command" {
            let name = child_text(node, "name", source).unwrap_or_default();
            return Walk::Stop(Hir::ControlCommand { name });
        }
        if node.kind() == "tabular_primary" && source_name.is_empty() {
            source_name = node
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .trim()
                .to_string();
        }
        if node.kind().ends_with("_operator") && node.kind() != "tabular_operator" {
            let name = if node.kind() == "keyword_operator" {
                child_text(node, "name", source).unwrap_or_else(|| "unknown".into())
            } else {
                node.kind().trim_end_matches("_operator").replace('_', "-")
            };
            let args = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            operators.push(HirOp { name, args });
        }
        Walk::Continue
    }) {
        return hir;
    }
    if source_name.is_empty() && operators.is_empty() && lets.is_empty() {
        Hir::Empty
    } else {
        Hir::Query {
            lets,
            source: source_name,
            operators,
        }
    }
}

enum Walk<T> {
    Continue,
    Stop(T),
}

fn walk<T>(node: &Node, _source: &str, f: &mut impl FnMut(Node) -> Walk<T>) -> Option<T> {
    match f(*node) {
        Walk::Stop(v) => return Some(v),
        Walk::Continue => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(v) = walk(&child, _source, f) {
            return Some(v);
        }
    }
    None
}

fn child_text(node: Node, field: &str, source: &str) -> Option<String> {
    node.child_by_field_name(field)
        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        .map(|s| s.to_string())
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub hir: Hir,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str, profile: Profile) -> AnalyzeResult {
    let catalog = Catalog::cached(profile);
    analyze_with_catalog(source, catalog)
}

pub fn analyze_with_catalog(source: &str, catalog: &Catalog) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let mut diagnostics = Vec::new();
    let Some(tree) = ts_parse(LanguageId::Kql, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::KQL_PARSE_ERROR,
                "failed to initialize KQL parser",
                Range::point(0, 0),
            )],
            hir: Hir::Empty,
            tokens: Vec::new(),
        };
    };
    if has_error(&tree) {
        let err = first_error_node(tree.root_node());
        let range = node_range(source, err.unwrap_or(tree.root_node()));
        diagnostics.push(Diagnostic::error(
            codes::KQL_PARSE_ERROR,
            "KQL syntax error",
            range,
        ));
    }

    let hir = lower(source);
    collect_control_commands(tree.root_node(), source, &mut diagnostics);

    collect_operator_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);
    collect_function_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);
    collect_table_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);
    perf::collect(tree.root_node(), source, &mut diagnostics);

    let tokens = highlight_tree(&spec, source, tree.root_node(), catalog).unwrap_or_default();
    AnalyzeResult {
        diagnostics,
        hir,
        tokens,
    }
}

fn first_error_node(node: Node) -> Option<Node> {
    if node.is_error() || node.is_missing() {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(n) = first_error_node(child) {
            return Some(n);
        }
    }
    None
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

fn collect_control_commands(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    if node.kind() == "control_command" {
        let name = child_text(node, "name", source).unwrap_or_else(|| ".".into());
        if !out
            .iter()
            .any(|d| d.code == codes::KQL_CONTROL_COMMAND_UNSUPPORTED)
        {
            out.push(Diagnostic::error(
                codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
                format!("KQL control command '.{name}' is not valid in detections"),
                node_range(source, node),
            ));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_control_commands(child, source, out);
    }
}

fn collect_operator_diagnostics(
    node: Node,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    if node.kind() == "unknown_operator" {
        let name = child_text(node, "name", source).unwrap_or_default();
        if catalog.operator(&name).is_none() {
            let mut d = Diagnostic::error(
                codes::KQL_UNKNOWN_OPERATOR,
                format!("unknown tabular operator '{name}'"),
                node_range(source, node),
            );
            if let Some(s) = catalog
                .operators
                .iter()
                .map(|o| (o.name.clone(), strsim_distance(&o.name, &name)))
                .filter(|(_, d)| *d <= 3)
                .min_by_key(|(_, d)| *d)
                .map(|(n, _)| n)
            {
                d = d.with_suggestion(s);
            }
            out.push(d);
        }
    }
    if node.kind() == "render_operator" {
        out.push(Diagnostic::warning(
            codes::KQL_RENDER_NOT_VALID,
            "`render` is not valid in detection queries",
            node_range(source, node),
        ));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_operator_diagnostics(child, source, catalog, out);
    }
}

fn collect_function_diagnostics(
    node: Node,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    if node.kind() == "function_call" {
        if let Some(name) = child_text(node, "name", source) {
            if catalog.function(&name).is_none() && catalog.operator(&name).is_none() {
                // Operators used as functions are fine; unknown names get a diagnostic.
                // Many scalar functions are not yet catalogued — only flag if it looks like a typo of a known one.
                if let Some(suggestion) = catalog
                    .functions
                    .iter()
                    .map(|f| (f.name.clone(), strsim_distance(&f.name, &name)))
                    .filter(|(_, d)| *d > 0 && *d <= 2)
                    .min_by_key(|(_, d)| *d)
                    .map(|(n, _)| n)
                {
                    out.push(
                        Diagnostic::error(
                            codes::KQL_UNKNOWN_FUNCTION,
                            format!("unknown function '{name}'"),
                            node_range(source, node),
                        )
                        .with_suggestion(suggestion),
                    );
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_diagnostics(child, source, catalog, out);
    }
}

fn collect_table_diagnostics(
    node: Node,
    source: &str,
    catalog: &Catalog,
    out: &mut Vec<Diagnostic>,
) {
    if catalog.tables.is_empty() {
        return;
    }
    if node.kind() == "tabular_primary" {
        if let Some(table) = child_text(node, "table", source) {
            if catalog.table(&table).is_none()
                && catalog.operator(&table).is_none()
                && table.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            {
                let mut d = Diagnostic::error(
                    codes::KQL_UNKNOWN_TABLE,
                    format!("unknown table '{table}'"),
                    node_range(source, node),
                );
                if let Some(s) = catalog.suggest_table(&table) {
                    d = d.with_suggestion(s);
                }
                out.push(d);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_table_diagnostics(child, source, catalog, out);
    }
}

fn highlight_tree(
    spec: &HighlightSpec,
    source: &str,
    root: Node,
    catalog: &Catalog,
) -> Result<Vec<HighlightToken>, opentide_highlight::HighlightError> {
    match opentide_syntax::query_captures(
        LanguageId::Kql,
        source,
        opentide_highlight::KQL_HIGHLIGHTS_SCM,
    ) {
        Ok(mut owned) => {
            overlay_catalog_captures(source, &mut owned, catalog);
            let refs: Vec<(ByteSpan, &str)> = owned
                .iter()
                .map(|(span, cap)| (*span, cap.as_str()))
                .collect();
            tokens_from_spans(spec, source, &refs)
        }
        Err(err) => {
            if cfg!(debug_assertions) {
                panic!("KQL highlights.scm query failed: {err}");
            }
            let mut spans = Vec::new();
            collect_highlights(root, source, &mut spans);
            tokens_from_spans(spec, source, &spans)
        }
    }
}

fn overlay_catalog_captures(source: &str, spans: &mut [(ByteSpan, String)], catalog: &Catalog) {
    for (span, capture) in spans.iter_mut() {
        let end = span.end.min(source.len());
        if span.start >= end {
            continue;
        }
        let text = &source[span.start..end];
        if matches!(text, "dynamic" | "datatable" | "timespan" | "datetime")
            && (*capture == "function" || *capture == "function.builtin" || *capture == "variable")
        {
            *capture = "type".into();
        } else if (catalog.function(text).is_some() || catalog.plugin(text).is_some())
            && (*capture == "variable" || *capture == "function")
        {
            *capture = "function.builtin".into();
        } else if (catalog.operator(text).is_some()
            && (*capture == "variable" || *capture == "error"))
            || (catalog.is_join_kind(text) && *capture == "variable")
        {
            *capture = "keyword".into();
        } else if catalog
            .scalar_operators
            .iter()
            .any(|o| o.name.eq_ignore_ascii_case(text))
            && *capture == "variable"
        {
            *capture = "operator".into();
        } else if catalog.resolve_column(source, text).is_some() && *capture == "variable" {
            *capture = "property".into();
        }
    }
}

fn collect_highlights(node: Node, _source: &str, out: &mut Vec<(ByteSpan, &'static str)>) {
    let kind = node.kind();
    let capture = match kind {
        "comment" => Some("comment"),
        "string" => Some("string"),
        "number" | "timespan" => Some("number"),
        "boolean" => Some("boolean"),
        "null" => Some("constant"),
        "|" => Some("operator.pipe"),
        "let" | "where" | "filter" | "project" | "project-away" | "project-rename"
        | "project-keep" | "project-reorder" | "extend" | "summarize" | "join" | "union"
        | "parse" | "parse-where" | "parse-kv" | "lookup" | "take" | "limit" | "sort" | "order"
        | "distinct" | "render" | "print" | "by" | "on" | "with" | "and" | "or" | "not" | "top"
        | "count" | "mv-expand" | "mvexpand" | "search" | "find" | "invoke" | "evaluate"
        | "serialize" | "as" => Some("keyword"),
        "identifier" => {
            if node.parent().map(|p| p.kind()) == Some("function_call")
                && node
                    .parent()
                    .and_then(|p| p.child_by_field_name("name"))
                    .map(|n| n.id())
                    == Some(node.id())
            {
                Some("function")
            } else if node.parent().map(|p| p.kind()) == Some("tabular_primary") {
                Some("type")
            } else {
                Some("variable")
            }
        }
        "==" | "!=" | "=~" | "=" | "+" | "-" | "*" | "/" => Some("operator"),
        "(" | ")" => Some("punctuation.bracket"),
        "," | ";" => Some("punctuation.delimiter"),
        _ => None,
    };
    if let Some(capture) = capture {
        if node.child_count() == 0 || matches!(kind, "string" | "comment" | "number" | "timespan") {
            out.push((ByteSpan::new(node.start_byte(), node.end_byte()), capture));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_highlights(child, _source, out);
    }
}

/// Compile a KQL query by prepending `let` statements and appending exclusion filters.
/// Port of `opentide.platforms.kql.compile_kql_query`.
#[derive(Debug, Clone)]
pub struct Exclusion {
    pub tenant: Option<String>,
    pub query: String,
    pub lets: Vec<(String, LetValue)>,
}

#[derive(Debug, Clone)]
pub enum LetValue {
    Bool(bool),
    Number(String),
    String(String),
}

pub fn compile_kql_query(base: &str, exclusions: &[Exclusion], tenant: &str) -> String {
    let mut lets: Vec<(String, String)> = Vec::new();
    let mut tails = Vec::new();
    for exclusion in exclusions {
        if exclusion.tenant.as_deref().is_none_or(|t| t == tenant) {
            tails.push(exclusion.query.as_str());
            for (name, value) in &exclusion.lets {
                let formatted = match value {
                    LetValue::Bool(true) => "true".to_string(),
                    LetValue::Bool(false) => "false".to_string(),
                    LetValue::Number(n) => n.clone(),
                    LetValue::String(s) => format!("\"{s}\""),
                };
                if let Some(existing) = lets.iter_mut().find(|(n, _)| n == name) {
                    existing.1 = formatted;
                } else {
                    lets.push((name.clone(), formatted));
                }
            }
        }
    }
    let mut out = String::new();
    for (name, val) in &lets {
        out.push_str(&format!("let {name} = {val};\n"));
    }
    out.push_str(base);
    for tail in tails {
        out.push('\n');
        out.push_str(tail);
    }
    out
}

/// 1.0 Defender profile: the 18 tables whose output-column groups are known.
/// `defender/tables.toml` lists more tables; those are completable but do not
/// select an NRT column group until a group is catalogued for them.
/// Defender required output column groups (OR-groups).
pub fn defender_required_column_groups(query: &str) -> Vec<Vec<&'static str>> {
    let stripped = strip_kql_literals_and_comments(query);
    let mut categories = std::collections::BTreeSet::new();
    for (table, category) in DEFENDER_TABLES_MAP {
        if contains_ident(&stripped, table) {
            categories.insert(*category);
        }
    }
    let mut groups: Vec<Vec<&str>> = Vec::new();
    if categories.is_empty() {
        groups.push(vec!["Timestamp", "TimeGenerated"]);
    } else {
        groups.push(vec!["Timestamp"]);
    }
    if categories.contains(&"endpoint") {
        groups.push(vec!["DeviceId"]);
        groups.push(vec!["ReportId"]);
    }
    if categories.contains(&"observation") {
        groups.push(vec!["ObservationId"]);
    }
    if (categories.contains(&"xdr") || categories.is_empty())
        && !groups.iter().any(|g| g == &["ReportId"])
    {
        groups.push(vec!["ReportId"]);
    }
    if !categories.contains(&"endpoint") {
        groups.push(vec![
            "DeviceId",
            "DeviceName",
            "RemoteDeviceName",
            "RecipientEmailAddress",
            "SenderFromAddress",
            "SenderMailFromAddress",
            "SenderObjectId",
            "RecipientObjectId",
            "AccountObjectId",
            "AccountSid",
            "AccountUpn",
            "InitiatingProcessAccountSid",
            "InitiatingProcessAccountUpn",
            "InitiatingProcessAccountObjectId",
        ]);
    }
    groups
}

const DEFENDER_TABLES_MAP: &[(&str, &str)] = &[
    ("DeviceEvents", "endpoint"),
    ("DeviceFileCertificateInfo", "endpoint"),
    ("DeviceFileEvents", "endpoint"),
    ("DeviceImageLoadEvents", "endpoint"),
    ("DeviceInfo", "endpoint"),
    ("DeviceLogonEvents", "endpoint"),
    ("DeviceNetworkEvents", "endpoint"),
    ("DeviceNetworkInfo", "endpoint"),
    ("DeviceProcessEvents", "endpoint"),
    ("DeviceRegistryEvents", "endpoint"),
    ("AlertEvidence", "alert"),
    ("AlertInfo", "alert"),
    ("EmailEvents", "xdr"),
    ("EmailAttachmentInfo", "xdr"),
    ("EmailUrlInfo", "xdr"),
    ("UrlClickEvents", "xdr"),
    ("IdentityLogonEvents", "xdr"),
    ("CloudAppEvents", "xdr"),
];

fn strip_kql_literals_and_comments(query: &str) -> String {
    let re_block = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap();
    let re_line = regex::Regex::new(r"//.*").unwrap();
    let re_s = regex::Regex::new(r#"'([^']|'')*'"#).unwrap();
    let re_d = regex::Regex::new(r#""([^"]|"")*""#).unwrap();
    let mut s = re_block.replace_all(query, " ").into_owned();
    s = re_line.replace_all(&s, " ").into_owned();
    s = re_s.replace_all(&s, " ").into_owned();
    s = re_d.replace_all(&s, " ").into_owned();
    s
}

fn contains_ident(haystack: &str, ident: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|t| t == ident)
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

fn last_operator(before: &str) -> Option<String> {
    let chunk = before.rsplit('|').next()?.trim_start();
    let op = chunk
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .next()?
        .to_ascii_lowercase();
    if op.is_empty() { None } else { Some(op) }
}

const COLUMN_OPERATORS: &[&str] = &[
    "where",
    "filter",
    "project",
    "project-away",
    "project-keep",
    "project-reorder",
    "extend",
    "summarize",
    "distinct",
    "sort",
    "order",
    "top",
    "parse",
];

pub fn completions(source: &str, offset: usize, profile: Profile) -> Vec<CompletionItem> {
    let catalog = Catalog::cached(profile);
    let before = &source[..offset.min(source.len())];
    let trimmed = before.trim_end();
    let lower = trimmed.to_ascii_lowercase();
    if lower.ends_with("evaluate") && before.ends_with(' ') || lower.ends_with("| evaluate") {
        return catalog
            .plugins
            .iter()
            .map(|p| complete_item(p.name.clone(), "plugin", p.docs.clone(), p.docs.clone()))
            .collect();
    }
    if let Some((call, index)) = innermost_call(before) {
        let named = before.trim_end().to_ascii_lowercase();
        if let Some(opt) = catalog.options.iter().find(|opt| {
            opt.operator.eq_ignore_ascii_case(&call)
                && !opt.values.is_empty()
                && named.ends_with(&format!("{}=", opt.name.to_ascii_lowercase()))
        }) {
            return opt
                .values
                .iter()
                .map(|value| {
                    complete_item(
                        value.clone(),
                        "keyword",
                        Some(format!("{call} {}", opt.name)),
                        opt.docs.clone(),
                    )
                })
                .collect();
        }
        let argument_options: Vec<&OperatorOption> = catalog
            .options
            .iter()
            .filter(|o| {
                o.operator.eq_ignore_ascii_case(&call)
                    && o.parameter_index == Some(index)
                    && !o.values.is_empty()
            })
            .collect();
        if !argument_options.is_empty() {
            return argument_options
                .iter()
                .flat_map(|opt| {
                    opt.values.iter().map(|value| {
                        complete_item(
                            value.clone(),
                            "keyword",
                            Some(format!("{call} {}", opt.name)),
                            opt.docs.clone(),
                        )
                    })
                })
                .collect();
        }
    }
    if let Some(op) = last_operator(before) {
        let opts = catalog.options_for(&op);
        if !opts.is_empty() {
            let after = text_after_operator(before, &op);
            if let Some(opt) = trailing_equals_option(after, &opts) {
                return opt
                    .values
                    .iter()
                    .map(|value| {
                        complete_item(
                            value.clone(),
                            "keyword",
                            Some(format!("{op} {}", opt.name)),
                            opt.docs.clone(),
                        )
                    })
                    .collect();
            }
        }
    }
    if before.trim_end().ends_with('|') || before.ends_with("| ") {
        return catalog
            .operators
            .iter()
            .map(|o| complete_item(o.name.clone(), "operator", o.docs.clone(), o.docs.clone()))
            .collect();
    }
    if let Some(op) = last_operator(before) {
        if COLUMN_OPERATORS.iter().any(|n| *n == op) {
            let mut seen = std::collections::BTreeSet::new();
            let mut items = Vec::new();
            let mentioned: Vec<&str> = catalog
                .tables
                .iter()
                .filter(|t| contains_ident(source, &t.name))
                .map(|t| t.name.as_str())
                .collect();
            let rows: Vec<&ColumnRow> = if mentioned.is_empty() {
                catalog.columns.iter().collect()
            } else {
                catalog
                    .columns
                    .iter()
                    .filter(|c| mentioned.iter().any(|t| c.table.eq_ignore_ascii_case(t)))
                    .collect()
            };
            for col in rows {
                if seen.insert(col.name.clone()) {
                    let detail = format!(
                        "{} ({})",
                        col.table,
                        col.type_name.as_deref().unwrap_or("column")
                    );
                    items.push(complete_item(
                        col.name.clone(),
                        "column",
                        Some(detail),
                        col.docs.clone(),
                    ));
                }
            }
            if !items.is_empty() {
                let opts = catalog.options_for(&op);
                if !opts.is_empty() && text_after_operator(before, &op).trim().is_empty() {
                    items.extend(prefix_option_items(&op, &opts));
                }
                return items;
            }
        }
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .map(|f| {
            complete_item(
                f.name.clone(),
                "function",
                f.docs.clone().or(f.signature.clone()),
                f.docs.clone(),
            )
        })
        .collect();
    items.extend(
        catalog
            .tables
            .iter()
            .map(|t| complete_item(t.name.clone(), "table", t.docs.clone(), t.docs.clone())),
    );
    items.extend(
        catalog
            .scalar_operators
            .iter()
            .map(|o| complete_item(o.name.clone(), "operator", o.docs.clone(), o.docs.clone())),
    );
    items.extend(
        catalog
            .plugins
            .iter()
            .map(|p| complete_item(p.name.clone(), "plugin", p.docs.clone(), p.docs.clone())),
    );
    items.extend(
        catalog
            .types
            .iter()
            .map(|t| complete_item(t.clone(), "type", Some("KQL scalar type".into()), None)),
    );
    if let Some(op) = last_operator(before) {
        let opts = catalog.options_for(&op);
        if !opts.is_empty() && text_after_operator(before, &op).trim().is_empty() {
            items.extend(prefix_option_items(&op, &opts));
        }
    }
    items
}

fn text_after_operator<'a>(before: &'a str, op: &str) -> &'a str {
    let chunk = before.rsplit('|').next().unwrap_or(before);
    let lower = chunk.to_ascii_lowercase();
    let op_l = op.to_ascii_lowercase();
    if let Some(idx) = lower.find(&op_l) {
        let end = idx + op_l.len();
        let next = lower.as_bytes().get(end).copied();
        let boundary = match next {
            None => true,
            Some(b) if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' => false,
            Some(_) => true,
        };
        if boundary {
            return &chunk[end..];
        }
    }
    ""
}

fn trailing_equals_option<'a>(
    after: &str,
    options: &[&'a OperatorOption],
) -> Option<&'a OperatorOption> {
    let lower = after.trim_start().to_ascii_lowercase();
    options
        .iter()
        .copied()
        .filter(|opt| !opt.values.is_empty())
        .filter(|opt| {
            let key = format!("{}=", opt.name.to_ascii_lowercase());
            lower.ends_with(&key)
        })
        .max_by_key(|opt| opt.name.len())
}

fn prefix_option_items(op: &str, options: &[&OperatorOption]) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    for opt in options {
        match opt.place.as_deref() {
            Some("value") => {
                for value in &opt.values {
                    items.push(complete_item(
                        value.clone(),
                        "keyword",
                        Some(format!("{op} {}", opt.name)),
                        opt.docs.clone(),
                    ));
                }
            }
            Some("token") | Some("alongside") => {
                items.push(complete_item(
                    opt.name.clone(),
                    "keyword",
                    opt.docs.clone(),
                    opt.docs.clone(),
                ));
            }
            _ => {
                let label = if opt.name.ends_with('=') {
                    opt.name.clone()
                } else {
                    format!("{}=", opt.name)
                };
                items.push(complete_item(
                    label,
                    "keyword",
                    opt.docs.clone(),
                    opt.docs.clone(),
                ));
            }
        }
    }
    items
}

pub fn hover(source: &str, position: opentide_core::Position, profile: Profile) -> Option<String> {
    let catalog = Catalog::cached(profile);
    let offset = position_to_offset(source, position);
    let word = word_at(source, offset)?;
    if let Some(op) = catalog.operator(&word) {
        let mut md = format!(
            "**{}** (tabular operator)\n\n{}",
            op.name,
            op.docs.clone().unwrap_or_default()
        );
        if let Some(c) = &op.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    if let Some(op) = catalog
        .scalar_operators
        .iter()
        .find(|o| o.name.eq_ignore_ascii_case(&word))
    {
        let mut md = format!(
            "**{}** (scalar operator)\n\n{}",
            op.name,
            op.docs.clone().unwrap_or_default()
        );
        if let Some(c) = &op.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    if let Some(f) = catalog.function(&word) {
        let mut md = format!(
            "**{}** {}\n\n{}",
            f.name,
            f.signature.clone().unwrap_or_default(),
            f.docs.clone().unwrap_or_default()
        );
        if let Some(c) = &f.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    if let Some(t) = catalog.table(&word) {
        let cols = catalog.columns_for_table(&t.name);
        let mut md = format!(
            "**{}** table\n\n{}",
            t.name,
            t.docs.clone().unwrap_or_default()
        );
        if !cols.is_empty() {
            md.push_str("\n\n**Columns**\n");
            for col in cols.iter().take(24) {
                md.push_str(&format!(
                    "\n- `{}` _{}_ — {}",
                    col.name,
                    col.type_name.as_deref().unwrap_or("column"),
                    col.docs.as_deref().unwrap_or("")
                ));
            }
            if cols.len() > 24 {
                md.push_str(&format!("\n- … {} more", cols.len() - 24));
            }
        }
        if let Some(c) = &t.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    if let Some(p) = catalog.plugin(&word) {
        let mut md = format!(
            "**{}** (evaluate plugin)\n\n{}",
            p.name,
            p.docs.clone().unwrap_or_default()
        );
        if let Some(c) = &p.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        if let Some(w) = &p.warning {
            md.push_str(&format!("\n\nWarning: `{w}`"));
        }
        return Some(md);
    }
    if catalog.types.iter().any(|t| t.eq_ignore_ascii_case(&word)) {
        return Some(format!("**{word}** (KQL scalar type)"));
    }
    if catalog.is_join_kind(&word) {
        return Some(format!(
            "**{word}** (`join kind=`)\n\nJoin flavor. See [join operator](https://learn.microsoft.com/kusto/query/join-operator)."
        ));
    }
    if let Some(col) = catalog.resolve_column(source, &word) {
        let mut md = format!(
            "**{}** column on `{}` (`{}`)\n\n{}",
            col.name,
            col.table,
            col.type_name.as_deref().unwrap_or("column"),
            col.docs.clone().unwrap_or_default()
        );
        if let Some(c) = &col.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    None
}

pub fn signature_help(source: &str, offset: usize, profile: Profile) -> Option<SignatureHelp> {
    let catalog = Catalog::cached(profile);
    let before = &source[..offset.min(source.len())];
    if let Some((name, active)) = innermost_call(before) {
        if let Some(help) = signature_for_name(catalog, &name, active) {
            return Some(help);
        }
    }
    if let Some(op_name) = last_operator(before) {
        if let Some(op) = catalog.operator(&op_name) {
            if let Some(sig) = op.signature.clone() {
                let params = parameter_list(&op.parameters, &sig);
                let active = active_operator_parameter(before, &params);
                return Some(SignatureHelp {
                    signatures: vec![SignatureInformation {
                        label: sig,
                        documentation: op.docs.clone(),
                        parameters: params,
                    }],
                    active_signature: 0,
                    active_parameter: active,
                });
            }
        }
    }
    None
}

fn signature_for_name(catalog: &Catalog, name: &str, active: u32) -> Option<SignatureHelp> {
    if let Some(f) = catalog.function(name) {
        let sig = f.signature.clone().unwrap_or_else(|| format!("{name}(…)"));
        let params = parameter_list(&f.parameters, &sig);
        let active = active.min(params.len().saturating_sub(1) as u32);
        return Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label: sig,
                documentation: f.docs.clone(),
                parameters: params,
            }],
            active_signature: 0,
            active_parameter: active,
        });
    }
    if let Some(plugin) = catalog.plugin(name) {
        let sig = plugin.signature.clone()?;
        let params = parameter_list(&plugin.parameters, &sig);
        let active = active.min(params.len().saturating_sub(1) as u32);
        return Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label: sig,
                documentation: plugin.docs.clone(),
                parameters: params,
            }],
            active_signature: 0,
            active_parameter: active,
        });
    }
    None
}

fn parameter_list(params: &[ParamRow], signature: &str) -> Vec<ParameterInformation> {
    if !params.is_empty() {
        return params
            .iter()
            .map(|param| ParameterInformation {
                label: param.name.clone(),
                documentation: param.docs.clone(),
            })
            .collect();
    }
    parameters_from_signature(signature)
}

fn active_operator_parameter(before: &str, params: &[ParameterInformation]) -> u32 {
    let lower = before.to_ascii_lowercase();
    if lower.contains(" on ") {
        if let Some(index) = params.iter().position(|param| {
            let label = param.label.to_ascii_lowercase();
            label.contains("condition") || label.contains("attribute") || label == "on"
        }) {
            return index as u32;
        }
    }
    if lower.contains("kind=") {
        if let Some(index) = params.iter().position(|param| {
            let label = param.label.to_ascii_lowercase();
            label.contains("kind") || label.contains("flavor")
        }) {
            return index as u32;
        }
    }
    0
}

fn innermost_call(before: &str) -> Option<(String, u32)> {
    let bytes = before.as_bytes();
    let mut depth = 0i32;
    let mut last_open = None;
    for (i, b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                if depth == 0 {
                    last_open = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let open = last_open?;
    let name_end = open;
    let mut i = name_end;
    while i > 0 {
        let c = bytes[i - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            i -= 1;
        } else {
            break;
        }
    }
    if i >= name_end {
        return None;
    }
    let name = before[i..name_end].to_string();
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
    let start = sig.find('(').map(|i| i + 1).unwrap_or(0);
    let end = sig.rfind(')').unwrap_or(sig.len());
    if start >= end {
        return Vec::new();
    }
    sig[start..end]
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && *p != "…")
        .map(|p| ParameterInformation {
            label: p.to_string(),
            documentation: None,
        })
        .collect()
}

fn position_to_offset(source: &str, position: opentide_core::Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    source.len()
}

fn word_at(source: &str, offset: usize) -> Option<String> {
    let bytes = source.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut i = offset.min(bytes.len().saturating_sub(1));
    while i > 0 && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-') {
        i -= 1;
    }
    if bytes[i] == b'!' {
        // keep `!has` / `!in` as a single operator token
    } else if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let start = i;
    let mut j = offset.min(bytes.len());
    while j < bytes.len()
        && (bytes[j].is_ascii_alphanumeric()
            || bytes[j] == b'_'
            || bytes[j] == b'-'
            || bytes[j] == b'~')
    {
        j += 1;
    }
    if start >= j {
        None
    } else {
        Some(source[start..j].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_loads() {
        let c = Catalog::core().with_profile(Profile::Sentinel);
        assert!(c.operator("where").is_some());
        assert!(c.function("ago").is_some());
        assert!(c.table("SecurityEvent").is_some());
    }

    #[test]
    fn control_command_is_unsupported() {
        let r = analyze(".show tables", Profile::Core);
        let diag = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::KQL_CONTROL_COMMAND_UNSUPPORTED)
            .expect("control command diagnostic");
        assert!(
            diag.range.end.character > diag.range.start.character
                || diag.range.end.line > diag.range.start.line,
            "control command range must cover the command, got {:?}",
            diag.range
        );
    }

    #[test]
    fn hll_merge_is_aggregate() {
        let c = Catalog::cached(Profile::Core);
        let row = c.function("hll_merge").expect("hll_merge");
        assert_eq!(row.kind.as_deref(), Some("aggregate"));
    }

    #[test]
    fn unknown_operator_is_not_silent() {
        let r = analyze("SecurityEvent | frobnicate x", Profile::Core);
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_UNKNOWN_OPERATOR),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn render_is_warning() {
        let r = analyze("SecurityEvent | render table", Profile::Core);
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_RENDER_NOT_VALID)
        );
    }

    #[test]
    fn hir_snapshot_simple() {
        let hir = lower("SecurityEvent | where EventID == 4688 | take 1");
        let s = hir.to_string();
        assert!(s.contains("query SecurityEvent"));
        assert!(s.contains("where"));
        assert!(s.contains("take"));
    }

    #[test]
    fn compile_exclusions_last_write_wins() {
        let compiled = compile_kql_query(
            "DeviceEvents | take 1",
            &[
                Exclusion {
                    tenant: None,
                    query: "| where DeviceName != \"skip\"".into(),
                    lets: vec![("x".into(), LetValue::String("a".into()))],
                },
                Exclusion {
                    tenant: None,
                    query: "| where 1 == 1".into(),
                    lets: vec![("x".into(), LetValue::String("b".into()))],
                },
            ],
            "tenant-a",
        );
        assert!(compiled.starts_with("let x = \"b\";"));
        assert!(compiled.contains("DeviceEvents | take 1"));
        assert!(compiled.contains("DeviceName"));
    }

    #[test]
    fn compile_no_exclusions_is_identity() {
        assert_eq!(
            compile_kql_query("DeviceEvents | take 1", &[], "t"),
            "DeviceEvents | take 1"
        );
    }

    #[test]
    fn defender_endpoint_requires_device_and_report() {
        let groups = defender_required_column_groups("DeviceProcessEvents | take 1");
        assert!(groups.iter().any(|g| g == &["DeviceId"]));
        assert!(groups.iter().any(|g| g == &["ReportId"]));
    }

    #[test]
    fn unknown_table_suggests() {
        let r = analyze("SecurityEvnt | take 1", Profile::Sentinel);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::KQL_UNKNOWN_TABLE)
            .expect("table diag");
        assert_eq!(d.suggestion.as_deref(), Some("SecurityEvent"));
    }

    #[test]
    fn completions_after_pipe() {
        let items = completions("SecurityEvent | ", 16, Profile::Core);
        assert!(items.iter().any(|i| i.label == "where"));
        assert!(items.iter().any(|i| i.label == "mv-expand"));
        assert!(items.iter().any(|i| i.label == "top"));
    }

    #[test]
    fn highlight_tokens_include_keyword_and_pipe() {
        let r = analyze("SecurityEvent | take 1", Profile::Core);
        assert!(r.tokens.iter().any(|t| t.capture == "keyword"));
        assert!(r.tokens.iter().any(|t| t.capture == "operator.pipe"));
    }

    #[test]
    fn parses_core_operators() {
        let samples = [
            "SecurityEvent | where EventID == 1",
            "SecurityEvent | project EventID",
            "SecurityEvent | project-away EventID",
            "SecurityEvent | project-rename X = EventID",
            "SecurityEvent | extend x = 1",
            "SecurityEvent | summarize count() by Computer",
            "SecurityEvent | union SecurityAlert",
            "SecurityEvent | take 1",
            "SecurityEvent | limit 1",
            "SecurityEvent | sort by EventID desc",
            "SecurityEvent | distinct Computer",
            "SecurityEvent | mv-expand AdditionalFields",
            "SecurityEvent | top 10 by EventID",
            "SecurityEvent | where EventID has 4688",
            "SecurityEvent | where Computer hasprefix \"DC\"",
            "SecurityEvent | evaluate bag_unpack(AdditionalFields)",
        ];
        for src in samples {
            let r = analyze(src, Profile::Core);
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::KQL_PARSE_ERROR),
                "{src} {:?}",
                r.diagnostics
            );
        }
    }

    #[test]
    fn hover_where_operator() {
        let h = hover(
            "SecurityEvent | where EventID == 1",
            opentide_core::Position::new(0, 16),
            Profile::Core,
        );
        assert!(h.unwrap().contains("where"));
    }

    #[test]
    fn engine_has_no_sql() {
        assert!(LanguageId::parse("sql").is_none());
    }

    #[test]
    fn catalog_covers_hunting_surface() {
        let c = Catalog::core().with_profile(Profile::Sentinel);
        assert!(c.function("ago").is_some());
        assert!(c.function("parse_json").is_some() || c.function("todynamic").is_some());
        assert!(c.function("iff").is_some() || c.function("iif").is_some());
        assert!(c.operator("mv-expand").is_some());
        assert!(c.operator("top").is_some());
        assert!(c.operator("filter").is_some());
        assert!(c.tables.iter().any(|t| t.name == "SigninLogs"));
        assert!(
            c.functions.len() > 400,
            "expected full scalar/agg catalog, got {}",
            c.functions.len()
        );
        assert!(c.operators.len() > 40, "{}", c.operators.len());
        assert!(c.function("series_fft").is_some());
        assert!(c.function("geo_point_in_polygon").is_some());
        assert!(c.function("convert_length").is_some());
        assert!(c.plugin("bag_unpack").is_some());
        assert!(c.plugin("sql_request").is_some());
    }

    #[test]
    fn highlight_scm_query_emits_visible_tokens() {
        let src = "SecurityEvent | where TimeGenerated > ago(1d) | take 1";
        let r = analyze(src, Profile::Core);
        let slice =
            |t: &opentide_highlight::HighlightToken| src[t.span.start..t.span.end].to_string();
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword" && slice(t) == "where"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), slice(t)))
                .collect::<Vec<_>>()
        );
        assert!(r.tokens.iter().any(|t| t.capture == "operator.pipe"));
        assert!(
            r.tokens.iter().any(|t| {
                let s = slice(t);
                s == "ago" && (t.capture == "function" || t.capture == "function.builtin")
            }),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), slice(t)))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn sentinel_columns_hover_and_complete() {
        let src = "SecurityEvent | where EventID == 4688";
        let h = hover(src, opentide_core::Position::new(0, 24), Profile::Sentinel)
            .expect("EventID hover");
        assert!(h.contains("EventID"), "{h}");
        assert!(h.contains("SecurityEvent"), "{h}");
        let table =
            hover(src, opentide_core::Position::new(0, 0), Profile::Sentinel).expect("table hover");
        assert!(
            table.contains("EventID") || table.contains("Columns"),
            "{table}"
        );
        let where_off = src.find("where ").unwrap() + 6;
        let items = completions(src, where_off, Profile::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "EventID"),
            "{:?}",
            items.iter().map(|i| &i.label).take(20).collect::<Vec<_>>()
        );
        assert!(items.iter().any(|i| i.label == "TimeGenerated"));
        let r = analyze(src, Profile::Sentinel);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "property" && &src[t.span.start..t.span.end] == "EventID"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn join_kind_signature_and_highlight() {
        let src = "SecurityEvent | join kind=inner SecurityAlert on EventID";
        let r = analyze(src, Profile::Sentinel);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "inner"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
                .collect::<Vec<_>>()
        );
        let eq = src.find("kind=").unwrap() + 5;
        let items = completions(src, eq, Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "leftouter"), "{items:?}");
        let help = signature_help(src, src.find("join ").unwrap() + 5, Profile::Sentinel)
            .expect("signature");
        assert!(
            help.signatures[0].label.to_lowercase().contains("join"),
            "{}",
            help.signatures[0].label
        );
        assert!(
            help.signatures[0].parameters.iter().any(|p| {
                p.label.to_ascii_lowercase().contains("flavor")
                    || p.label.to_ascii_lowercase().contains("kind")
            }),
            "{:?}",
            help.signatures[0].parameters
        );
        let ago = "SecurityEvent | where TimeGenerated > ago(1d)";
        let help = signature_help(ago, ago.find("ago(").unwrap() + 4, Profile::Sentinel)
            .expect("ago signature");
        assert!(help.signatures[0].label.to_lowercase().contains("ago"));
        assert!(
            help.signatures[0]
                .parameters
                .iter()
                .any(|p| p.documentation.as_ref().is_some_and(|d| !d.is_empty())),
            "ago parameters need Learn docs: {:?}",
            help.signatures[0].parameters
        );
    }

    #[test]
    fn signatures_use_own_name_and_docs_are_not_pipe_tails() {
        let catalog = Catalog::core();
        for function in &catalog.functions {
            assert_named_signature(&function.name, function.signature.as_deref());
            if let Some(docs) = &function.docs {
                assert!(
                    !docs_hold_pipe_split_tail(function.signature.as_deref().unwrap_or(""), docs),
                    "{} docs look like a pipe-split signature tail: {:?} (signature {:?})",
                    function.name,
                    docs,
                    function.signature
                );
            }
        }
        for operator in &catalog.operators {
            assert_named_signature(&operator.name, operator.signature.as_deref());
            if let Some(docs) = &operator.docs {
                assert!(
                    !docs_hold_pipe_split_tail(operator.signature.as_deref().unwrap_or(""), docs),
                    "{} docs look like a pipe-split signature tail: {:?} (signature {:?})",
                    operator.name,
                    docs,
                    operator.signature
                );
            }
        }
        for plugin in &catalog.plugins {
            assert_named_signature(&plugin.name, plugin.signature.as_deref());
        }
        let arg_max = catalog.function("arg_max").expect("arg_max");
        let sig = arg_max.signature.as_deref().unwrap_or("");
        assert!(sig.contains("ExprToReturn") && sig.contains(')'), "{sig}");
        assert_ne!(
            arg_max.docs.as_deref(),
            Some("ExprToReturn [, …])"),
            "arg_max docs still hold the pipe-split tail"
        );
        let parse_json = catalog.function("parse_json").expect("parse_json");
        assert!(
            parse_json
                .signature
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .starts_with("parse_json("),
            "{:?}",
            parse_json.signature
        );
    }

    #[test]
    fn operator_options_complete_where_the_syntax_puts_them() {
        let render = "StormEvents | render ";
        let items = completions(render, render.len(), Profile::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "timechart"),
            "render chart types complete after the operator, got {:?}",
            items.iter().map(|i| &i.label).collect::<Vec<_>>()
        );
        assert!(
            !render.trim_end().ends_with("kind="),
            "this fixture must not depend on kind="
        );

        let series = "StormEvents | make-series ";
        let items = completions(series, series.len(), Profile::Sentinel);
        for keyword in ["on", "from", "to", "step", "by", "default"] {
            assert!(
                items.iter().any(|i| i.label == keyword),
                "make-series missing {keyword}: {:?}",
                items.iter().map(|i| &i.label).collect::<Vec<_>>()
            );
        }

        let union = "StormEvents | union ";
        let items = completions(union, union.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "withsource="), "{items:?}");
        assert!(items.iter().any(|i| i.label == "isfuzzy="), "{items:?}");

        let search = "search ";
        let items = completions(search, search.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "kind="), "{items:?}");
        assert!(items.iter().any(|i| i.label == "in"), "{items:?}");

        let parse = "StormEvents | parse ";
        let items = completions(parse, parse.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "flags="), "{items:?}");

        let expand = "StormEvents | mv-expand ";
        let items = completions(expand, expand.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "kind="), "{items:?}");
        let kind = "StormEvents | mv-expand kind=";
        let items = completions(kind, kind.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "bag"), "{items:?}");
        assert!(items.iter().any(|i| i.label == "array"), "{items:?}");

        let join_prefix = "StormEvents | join ";
        let items = completions(join_prefix, join_prefix.len(), Profile::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "kind="),
            "join options stay available: {items:?}"
        );
        assert!(
            items.iter().any(|i| i.kind == "table"),
            "join must still offer tables, got {:?}",
            items
                .iter()
                .map(|i| (&i.label, &i.kind))
                .take(12)
                .collect::<Vec<_>>()
        );

        let named = "StormEvents | evaluate bag_unpack(Parsed, columnsConflict=";
        let items = completions(named, named.len(), Profile::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "replace_source"),
            "named columnsConflict= should complete: {items:?}"
        );

        let join = "StormEvents | join kind=";
        let items = completions(join, join.len(), Profile::Sentinel);
        assert!(items.iter().any(|i| i.label == "leftantisemi"), "{items:?}");
        assert!(
            items.iter().any(|i| i.label == "rightantisemi"),
            "{items:?}"
        );

        let unpack = "StormEvents | evaluate bag_unpack(Parsed, \"pre\", ";
        let items = completions(unpack, unpack.len(), Profile::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "replace_source"),
            "{items:?}"
        );
    }

    fn assert_named_signature(name: &str, signature: Option<&str>) {
        let sig = signature.unwrap_or("");
        assert!(
            sig.to_ascii_lowercase()
                .contains(&name.to_ascii_lowercase())
                && sig.contains('(')
                && sig.contains(')'),
            "{name} signature {sig:?} must contain its own name and a parenthesized argument list"
        );
    }

    /// A `|` split of a markdown table parks the rest of the signature in `docs`
    /// (`arg_max(ExprToMaximize, * ` + docs `ExprToReturn [, …])`).
    fn docs_hold_pipe_split_tail(signature: &str, docs: &str) -> bool {
        let docs = docs.trim();
        if docs.is_empty() {
            return false;
        }
        let open = signature.matches('(').count();
        let close = signature.matches(')').count();
        if open > close && docs.contains(')') {
            return true;
        }
        if docs.ends_with(')') && !docs.contains('.') {
            let sentence = docs.split_whitespace().any(|word| {
                let word = word
                    .trim_matches(|c: char| !c.is_ascii_alphabetic())
                    .to_ascii_lowercase();
                matches!(
                    word.as_str(),
                    "the"
                        | "a"
                        | "an"
                        | "to"
                        | "of"
                        | "for"
                        | "from"
                        | "with"
                        | "returns"
                        | "return"
                        | "calculates"
                        | "provides"
                        | "when"
                        | "that"
                        | "and"
                        | "or"
                        | "in"
                        | "is"
                        | "by"
                        | "which"
                        | "was"
                        | "this"
                        | "into"
                        | "over"
                        | "all"
                        | "not"
                )
            });
            return !sentence;
        }
        false
    }

    #[test]
    fn dynamic_is_type_constructor() {
        let src = "let x = dynamic(\"[]\"); SecurityEvent | take 1";
        let r = analyze(src, Profile::Core);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "type" && &src[t.span.start..t.span.end] == "dynamic"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (t.capture.as_str(), &src[t.span.start..t.span.end]))
                .collect::<Vec<_>>()
        );
    }
}
