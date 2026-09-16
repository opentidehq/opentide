//! I/O-free KQL engine. Catalogs are compiled in; no `std::fs`.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, Range, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{has_error, parse as ts_parse};
use serde::Deserialize;
use tree_sitter::Node;

const OPERATORS_TOML: &str = include_str!("../../../catalogs/kql/core/operators.toml");
const FUNCTIONS_TOML: &str = include_str!("../../../catalogs/kql/core/functions.toml");
const TYPES_TOML: &str = include_str!("../../../catalogs/kql/core/types.toml");
const SCALAR_OPERATORS_TOML: &str =
    include_str!("../../../catalogs/kql/core/operators-scalar.toml");
const PLUGINS_TOML: &str = include_str!("../../../catalogs/kql/core/evaluate-plugins.toml");
const SENTINEL_TABLES: &str = include_str!("../../../catalogs/kql/sentinel/tables.toml");
const DEFENDER_TABLES: &str = include_str!("../../../catalogs/kql/defender/tables.toml");

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
pub struct OperatorRow {
    pub name: String,
    pub kind: String,
    pub docs: Option<String>,
    pub warning: Option<String>,
    pub citation: Option<String>,
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

#[derive(Debug, Clone)]
pub struct Catalog {
    pub operators: Vec<OperatorRow>,
    pub functions: Vec<FunctionRow>,
    pub scalar_operators: Vec<ScalarOperatorRow>,
    pub plugins: Vec<PluginRow>,
    pub types: Vec<String>,
    pub tables: Vec<TableRow>,
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
        self
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
    let catalog = Catalog::core().with_profile(profile);
    analyze_with_catalog(source, &catalog)
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
    if let Hir::ControlCommand { name } = &hir {
        diagnostics.push(Diagnostic::error(
            codes::KQL_CONTROL_COMMAND_UNSUPPORTED,
            format!("KQL control command '.{name}' is not valid in detections"),
            Range::point(0, 0),
        ));
    }
    collect_control_commands(tree.root_node(), source, &mut diagnostics);

    collect_operator_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);
    collect_function_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);
    collect_table_diagnostics(tree.root_node(), source, catalog, &mut diagnostics);

    let tokens = highlight_tree(&spec, source, tree.root_node()).unwrap_or_default();
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
) -> Result<Vec<HighlightToken>, opentide_highlight::HighlightError> {
    let catalog = Catalog::core();
    match opentide_syntax::query_captures(
        LanguageId::Kql,
        source,
        opentide_highlight::KQL_HIGHLIGHTS_SCM,
    ) {
        Ok(mut owned) => {
            overlay_catalog_captures(source, &mut owned, &catalog);
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
        if (catalog.function(text).is_some() || catalog.plugin(text).is_some())
            && (*capture == "variable" || *capture == "function")
        {
            *capture = "function.builtin".into();
        } else if catalog.operator(text).is_some()
            && (*capture == "variable" || *capture == "error")
        {
            *capture = "keyword".into();
        } else if catalog
            .scalar_operators
            .iter()
            .any(|o| o.name.eq_ignore_ascii_case(text))
            && *capture == "variable"
        {
            *capture = "operator".into();
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

pub fn completions(source: &str, offset: usize, profile: Profile) -> Vec<CompletionItem> {
    let catalog = Catalog::core().with_profile(profile);
    let before = &source[..offset.min(source.len())];
    let trimmed = before.trim_end();
    if trimmed.to_ascii_lowercase().ends_with("evaluate") && before.ends_with(' ')
        || trimmed.to_ascii_lowercase().ends_with("| evaluate")
    {
        return catalog
            .plugins
            .iter()
            .map(|p| CompletionItem {
                label: p.name.clone(),
                detail: p.docs.clone(),
                kind: "plugin".into(),
            })
            .collect();
    }
    if before.trim_end().ends_with('|') || before.ends_with("| ") {
        return catalog
            .operators
            .iter()
            .map(|o| CompletionItem {
                label: o.name.clone(),
                detail: o.docs.clone(),
                kind: "operator".into(),
            })
            .collect();
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .map(|f| CompletionItem {
            label: f.name.clone(),
            detail: f.docs.clone().or(f.signature.clone()),
            kind: "function".into(),
        })
        .collect();
    items.extend(catalog.tables.iter().map(|t| CompletionItem {
        label: t.name.clone(),
        detail: t.docs.clone(),
        kind: "table".into(),
    }));
    items.extend(catalog.scalar_operators.iter().map(|o| CompletionItem {
        label: o.name.clone(),
        detail: o.docs.clone(),
        kind: "operator".into(),
    }));
    items.extend(catalog.plugins.iter().map(|p| CompletionItem {
        label: p.name.clone(),
        detail: p.docs.clone(),
        kind: "plugin".into(),
    }));
    items.extend(catalog.types.iter().map(|t| CompletionItem {
        label: t.clone(),
        detail: Some("KQL scalar type".into()),
        kind: "type".into(),
    }));
    items
}

pub fn hover(source: &str, position: opentide_core::Position, profile: Profile) -> Option<String> {
    let catalog = Catalog::core().with_profile(profile);
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
        return Some(format!(
            "**{}** table\n\n{}",
            t.name,
            t.docs.clone().unwrap_or_default()
        ));
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
    None
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
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_CONTROL_COMMAND_UNSUPPORTED)
        );
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
}
