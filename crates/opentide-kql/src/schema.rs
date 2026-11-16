//! Columns through a KQL query (#112).
//!
//! A pass over each tabular expression that knows, at every operator, which
//! columns the rows hold, their types, and which operator made each one. It
//! follows `let` bindings (tabular values and tabular functions), `datatable`,
//! `print`, `union`, `join`, `lookup`, `summarize`, the `project` family,
//! `extend`, `mv-expand`, `mv-apply`, `parse` and `distinct`.
//!
//! How much the pass knows about a pipeline's columns is [`Known`]:
//!
//! - `Closed`: the query itself says which columns exist (after `project`,
//!   `summarize`, `distinct`, `count`; a `datatable`, `print`), so a name
//!   that is not one of them is not a column: `kql_unknown_column`.
//! - `Typos`: a documented source (an Azure Monitor Logs or advanced hunting
//!   table, an ASIM parser). Its documented columns are known, but a table
//!   gains columns before the reference lists them and ASIM source parsers
//!   can add their own, so only a near miss of a documented column is
//!   reported, with the column it misspells.
//! - `Open`: an unknown source, an `evaluate` plugin, `bag_unpack`, an
//!   operator whose output naming the pass does not model. Nothing below it
//!   gets a column diagnostic.
//!
//! The pass never reports on a query that does not parse.

use crate::{Catalog, Profile, tables};
use opentide_core::{ByteSpan, Diagnostic, codes};
use std::collections::{BTreeSet, HashMap};

pub(crate) mod new_tree;

/// The operator that made a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MadeBy {
    /// The operator's node kind (`extend_operator`, `summarize_operator`, ...).
    pub operator: &'static str,
    /// The operator's span in the query.
    pub span: ByteSpan,
}

impl MadeBy {
    /// The operator as written in a query (`extend`, `project-rename`).
    pub fn keyword(&self) -> &'static str {
        operator_keyword(self.operator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    /// The Kusto scalar type, when known.
    pub type_name: Option<String>,
    /// The operator that made it; `None` for a column of the source.
    pub made_by: Option<MadeBy>,
    /// The column it renames (`project-rename New = Old`, `project New = Old`).
    pub renamed_from: Option<String>,
    /// The catalog table or ASIM schema it comes from; `None` for a column
    /// the query makes or a source the catalog does not know.
    pub origin: Option<Origin>,
}

impl Column {
    fn new(name: impl Into<String>, type_name: Option<String>) -> Self {
        Self {
            name: name.into(),
            type_name,
            made_by: None,
            renamed_from: None,
            origin: None,
        }
    }

    fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }
}

/// Where a column of a source comes from: what hover describes it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A catalog table (`SigninLogs`): its catalog row has the column's docs.
    Table(String),
    /// An ASIM schema, with the column's class (`Mandatory`, `Optional`, ...).
    Asim { schema: String, class: String },
}

/// How completely the pass knows a pipeline's columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Known {
    /// Columns may exist that the pass does not know: no column diagnostic.
    Open,
    /// The documented columns are known, others may exist: only near misses.
    Typos,
    /// The columns are exactly these.
    Closed,
}

/// Where a pipeline's rows come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A catalog table.
    Table(String),
    /// An ASIM parser and the schema it returns.
    Asim { parser: String, schema: String },
    /// A `let`-bound tabular value or function.
    Let(String),
    /// A name the catalog does not know and no `let` binds (a custom `_CL`
    /// table, a workspace function).
    Named(String),
    /// `datatable`, `externaldata`, `range`.
    Literal,
    /// `print`.
    Print,
    /// A `union` of several sources.
    Union,
    /// Anything else: an unknown name, `search`, `externaldata`.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Schema {
    pub columns: Vec<Column>,
    pub known: Known,
    pub source: Source,
    /// `project`, `summarize` or `distinct` narrowed the columns (in this
    /// pipeline or in the `let` it starts from).
    pub narrowed: bool,
    /// `_CF` custom columns may exist: a data collection rule can add them to
    /// a Log Analytics table.
    custom_columns: bool,
    /// The last operator that replaced the set of columns, for messages.
    reshaped_by: Option<&'static str>,
    /// Columns `project-away`, `project-rename` or `project-keep` removed,
    /// with the operator: certainly not columns, whatever the source.
    removed: HashMap<String, &'static str>,
    pub citation: Option<String>,
}

impl Schema {
    fn open() -> Self {
        Self {
            columns: Vec::new(),
            known: Known::Open,
            source: Source::Unknown,
            narrowed: false,
            custom_columns: false,
            reshaped_by: None,
            removed: HashMap::new(),
            citation: None,
        }
    }

    fn closed(columns: Vec<Column>, source: Source) -> Self {
        Self {
            columns,
            known: Known::Closed,
            source,
            ..Self::open()
        }
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    fn has(&self, name: &str) -> bool {
        self.column(name).is_some()
    }

    /// Add `column`, replacing one of the same name (as `extend` does).
    fn set(&mut self, column: Column) {
        self.removed.remove(&column.name);
        if let Some(existing) = self.columns.iter_mut().find(|c| c.name == column.name) {
            *existing = column;
        } else {
            self.columns.push(column);
        }
    }

    /// Add `column` under a name not yet taken: `Name`, `Name1`, `Name2`, ...
    /// as Kusto names the columns `join`, `lookup` and `summarize` repeat.
    fn push_unique(&mut self, mut column: Column) {
        if self.has(&column.name) {
            let base = column.name.clone();
            let mut n = 1;
            while self.has(&format!("{base}{n}")) {
                n += 1;
            }
            column.name = format!("{base}{n}");
        }
        self.removed.remove(&column.name);
        self.columns.push(column);
    }

    fn remove(&mut self, name: &str, by: &'static str) {
        self.columns.retain(|c| c.name != name);
        self.removed.insert(name.to_string(), by);
    }

    fn weaken(&mut self, known: Known) {
        self.known = self.known.min(known);
    }

    fn make_open(&mut self) {
        self.known = Known::Open;
    }

    /// What the pipeline reads, for messages.
    pub fn describe_source(&self) -> String {
        match &self.source {
            Source::Table(t) => t.clone(),
            Source::Asim { parser, schema } => format!("{parser} (ASIM {schema} schema)"),
            Source::Let(name) | Source::Named(name) => name.clone(),
            Source::Literal => "the datatable".into(),
            Source::Print => "the print".into(),
            Source::Union => "the union".into(),
            Source::Unknown => "the source".into(),
        }
    }
}

/// One column reference in the query.
#[derive(Debug, Clone)]
pub struct Reference {
    pub name: String,
    pub span: ByteSpan,
    /// The column it resolves to, if the pass knows it.
    pub column: Option<Column>,
    /// The tabular operator (or source) it is part of.
    pub operator: ByteSpan,
}

/// A column an operator defines (`extend New = ...`, `project-rename New = Old`).
#[derive(Debug, Clone)]
pub struct Definition {
    pub column: Column,
    pub span: ByteSpan,
}

/// One operator of a pipeline with the columns it reads and writes.
#[derive(Debug, Clone)]
pub struct Stage {
    pub operator: &'static str,
    pub span: ByteSpan,
    pub input: Schema,
    pub output: Schema,
}

/// One tabular expression: the schema its source gives, then each operator.
#[derive(Debug, Clone)]
pub struct Pipeline {
    pub span: ByteSpan,
    pub source: Schema,
    pub stages: Vec<Stage>,
}

impl Pipeline {
    /// The rows come straight from a table or an ASIM parser (a name no `let`
    /// binds), not a `let`, a `union` or a literal.
    pub fn reads_dataset(&self) -> bool {
        matches!(
            self.source.source,
            Source::Table(_) | Source::Asim { .. } | Source::Named(_)
        )
    }
}

/// What the pass learned about one query.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub pipelines: Vec<Pipeline>,
    pub references: Vec<Reference>,
    pub definitions: Vec<Definition>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Analysis {
    /// The pipeline of the `tabular_expression` at `span`.
    pub fn pipeline(&self, span: ByteSpan) -> Option<&Pipeline> {
        self.pipelines.iter().find(|p| p.span == span)
    }

    /// The column references inside `span` (a predicate, an operator): which
    /// columns it reads, and for each the operator that made it.
    pub fn reads(&self, span: ByteSpan) -> impl Iterator<Item = &Reference> {
        self.references
            .iter()
            .filter(move |r| r.span.start >= span.start && r.span.end <= span.end)
    }

    /// The column reference or definition at a byte offset, for hover.
    pub fn column_at(&self, offset: usize) -> Option<&Column> {
        self.references
            .iter()
            .filter(|r| r.span.start <= offset && offset <= r.span.end)
            .find_map(|r| r.column.as_ref())
            .or_else(|| {
                self.definitions
                    .iter()
                    .find(|d| d.span.start <= offset && offset <= d.span.end)
                    .map(|d| &d.column)
            })
    }
}

/// Where a column reference is resolved.
#[derive(Clone, Copy)]
enum Ctx<'s> {
    One(&'s Schema),
    /// A join or lookup condition: `$left.X`, `$right.X`, or `X` on both sides.
    Join(&'s Schema, &'s Schema),
}

// Functions whose arguments are literals of their type, not expressions over
// columns: `datetime(2024-01-01T10:00:00Z)`, `real(nan)`, `typeof(long)`.
const LITERAL_FUNCTIONS: &[&str] = &[
    "datetime", "date", "time", "timespan", "int", "long", "real", "double", "decimal", "bool",
    "boolean", "guid", "uniqueid", "dynamic", "string", "typeof",
];

const STRING_OPERATORS: &[&str] = &[
    "has",
    "!has",
    "has_cs",
    "!has_cs",
    "contains",
    "!contains",
    "contains_cs",
    "!contains_cs",
    "startswith",
    "!startswith",
    "startswith_cs",
    "!startswith_cs",
    "endswith",
    "!endswith",
    "endswith_cs",
    "!endswith_cs",
    "hasprefix",
    "!hasprefix",
    "hasprefix_cs",
    "!hasprefix_cs",
    "hassuffix",
    "!hassuffix",
    "hassuffix_cs",
    "!hassuffix_cs",
    "=~",
    "!~",
    "matches regex",
];
const STRING_SET_OPERATORS: &[&str] = &["has_any", "has_all", "in~", "!in~"];
const ORDERING: &[&str] = &["<", ">", "<=", ">="];
const NUMERIC: &[&str] = &["int", "long", "real", "decimal"];

enum Item {
    /// `A = ...` or `(A, B) = ...`, with the type when it is plain.
    Named(Vec<String>, Option<String>),
    /// An expression without a name: a bare column keeps its own; anything
    /// else gets a generated name (`Column1`), which is `None`.
    Unnamed(Option<Column>),
}

/// The columns an operator such as `project` leaves are exactly those it
/// names, unless the pass already lost track of the rows' columns.
fn reshaped(input: Known) -> Known {
    if input == Known::Open {
        Known::Open
    } else {
        Known::Closed
    }
}

/// Whether `name` matches a column pattern: `*` stands for any run of
/// characters, everything else matches itself (case-sensitive, as Kusto
/// column names are).
fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        // No `*` at all: the pattern is a plain name.
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// The keyword an operator node is written with.
fn operator_keyword(kind: &str) -> &'static str {
    match kind {
        "where_operator" => "where",
        "filter_operator" => "filter",
        "project_operator" => "project",
        "project_away_operator" => "project-away",
        "project_keep_operator" => "project-keep",
        "project_rename_operator" => "project-rename",
        "project_reorder_operator" => "project-reorder",
        "extend_operator" => "extend",
        "summarize_operator" => "summarize",
        "distinct_operator" => "distinct",
        "join_operator" => "join",
        "lookup_operator" => "lookup",
        "union_operator" => "union",
        "mv_expand_operator" => "mv-expand",
        "mv_apply_operator" => "mv-apply",
        "parse_operator" => "parse",
        "count_operator" => "count",
        "make_series_operator" => "make-series",
        "evaluate_operator" => "evaluate",
        _ => "the operator",
    }
}

/// The name a quoted identifier holds: `['a b']` and `["a b"]` are `a b`.
pub(crate) fn unquote_name(text: &str) -> &str {
    let inner = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text)
        .trim();
    inner
        .strip_prefix(['\'', '"'])
        .and_then(|t| t.strip_suffix(['\'', '"']))
        .unwrap_or(inner)
}

/// A table, `let`-bound tabular value or ASIM parser named by `word`; `binds`
/// when a scope binds the word to something else.
pub(crate) fn source_schema(
    catalog: &Catalog,
    word: &str,
    tabular: &HashMap<String, Schema>,
    binds: bool,
) -> Option<Schema> {
    if let Some(schema) = tabular.get(word) {
        return Some(schema.clone());
    }
    if binds {
        return None;
    }
    table_schema(catalog, word).or_else(|| asim_schema(catalog, word))
}

fn table_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    let table = catalog.table(name)?;
    let columns: Vec<Column> = catalog
        .columns_for_table(name)
        .into_iter()
        .filter(|c| c.table == name)
        .map(|c| {
            Column::new(c.name.clone(), c.type_name.clone())
                .with_origin(Origin::Table(name.to_string()))
        })
        .collect();
    // The documented columns are reliable but not complete: tables gain
    // columns before the reference lists them. A near miss of one is a
    // typo; any other name is left alone.
    let known = if table.documented {
        Known::Typos
    } else {
        Known::Open
    };
    let mut schema = Schema {
        columns,
        known,
        source: Source::Table(name.to_string()),
        custom_columns: true,
        citation: table.citation.clone(),
        ..Schema::open()
    };
    // Every Log Analytics table has the standard columns.
    if catalog.profile == Profile::Sentinel && table.documented {
        for (column, type_name) in tables::STANDARD_COLUMNS {
            if !schema.has(column) {
                schema.columns.push(
                    Column::new(*column, Some((*type_name).to_string()))
                        .with_origin(Origin::Table(name.to_string())),
                );
            }
        }
    }
    Some(schema)
}

pub(crate) fn asim_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    let parser = catalog.asim_parser(name)?;
    let asim = tables::asim();
    let schema = asim.schemas.get(&parser.schema)?;
    Some(Schema {
        columns: schema
            .columns
            .iter()
            .map(|c| {
                Column::new(c.name.clone(), Some(c.type_name.clone())).with_origin(Origin::Asim {
                    schema: parser.schema.clone(),
                    class: c.class.clone(),
                })
            })
            .collect(),
        known: Known::Typos,
        source: Source::Asim {
            parser: parser.name.clone(),
            schema: parser.schema.clone(),
        },
        citation: schema.citation.clone(),
        ..Schema::open()
    })
}

/// The schema of a `union` of `legs`, with the `withsource` column.
pub(crate) fn merge_union(legs: &[Schema], withsource: Option<String>) -> Schema {
    let mut out = Schema::closed(Vec::new(), Source::Union);
    let mut types: HashMap<String, Option<String>> = HashMap::new();
    let mut conflicts = BTreeSet::new();
    for leg in legs {
        out.weaken(leg.known);
        out.custom_columns |= leg.custom_columns;
        for column in &leg.columns {
            match types.get(&column.name) {
                None => {
                    types.insert(column.name.clone(), column.type_name.clone());
                    out.columns.push(column.clone());
                }
                Some(t) if *t != column.type_name => {
                    conflicts.insert(column.name.clone());
                }
                Some(_) => {}
            }
        }
    }
    // A name with two types becomes one column per type (`A_string`,
    // `A_long`); with a type the pass does not know, it cannot name them.
    for name in conflicts {
        let mut kinds: Vec<Option<String>> = legs
            .iter()
            .filter_map(|leg| leg.column(&name).map(|c| c.type_name.clone()))
            .collect();
        kinds.dedup();
        out.columns.retain(|c| c.name != name);
        if kinds.iter().any(Option::is_none) {
            out.make_open();
            continue;
        }
        for kind in kinds.into_iter().flatten() {
            let renamed = format!("{name}_{kind}");
            if !out.has(&renamed) {
                out.columns.push(Column::new(renamed, Some(kind)));
            }
        }
    }
    if let Some(name) = withsource {
        out.set(Column::new(name, Some("string".into())));
    }
    // A union of narrowed legs (`let`s that end in project or summarize) is narrow.
    out.narrowed = !legs.is_empty() && legs.iter().all(|leg| leg.narrowed);
    if legs.is_empty() {
        out.make_open();
    }
    out
}

/// An argument of an aggregate call, as its naming reads it.
pub(crate) enum AggArg {
    /// `*`
    Star,
    /// A bare column.
    Name(String),
    /// Anything else.
    Other,
}

/// The columns an unnamed aggregate `name(args)` makes (lower-case `name`), as
/// Kusto names them; `None` when the naming is not modelled.
pub(crate) fn aggregate_columns_for(
    name: &str,
    args: &[AggArg],
    input: &Schema,
) -> Option<Vec<Column>> {
    let first = || match args.first() {
        Some(AggArg::Name(name)) => Some(name.clone()),
        _ => None,
    };
    let typed = |column: &str| input.column(column).and_then(|c| c.type_name.clone());
    let one = |name: String, type_name: Option<String>| Some(vec![Column::new(name, type_name)]);
    match name {
        "count" => one("count_".into(), Some("long".into())),
        "countif" => one("countif_".into(), Some("long".into())),
        "make_bag" | "make_bag_if" => one("bag_".into(), Some("dynamic".into())),
        "dcount" | "dcountif" => one(format!("{name}_{}", first()?), Some("long".into())),
        "sum" | "sumif" | "min" | "max" | "minif" | "maxif" => {
            let column = first()?;
            let type_name = typed(&column);
            one(format!("{name}_{column}"), type_name)
        }
        "avg" | "avgif" | "stdev" | "stdevif" | "variance" | "varianceif" => {
            one(format!("{name}_{}", first()?), Some("real".into()))
        }
        "make_set" | "make_set_if" => one(format!("set_{}", first()?), Some("dynamic".into())),
        "make_list" | "make_list_if" => one(format!("list_{}", first()?), Some("dynamic".into())),
        "take_any" => {
            let column = first()?;
            let type_name = typed(&column);
            one(column, type_name)
        }
        "arg_max" | "arg_min" => {
            let mut out = Vec::new();
            for arg in args {
                let column = match arg {
                    AggArg::Star => {
                        for column in &input.columns {
                            if !out.iter().any(|c: &Column| c.name == column.name) {
                                out.push(Column::new(
                                    column.name.clone(),
                                    column.type_name.clone(),
                                ));
                            }
                        }
                        continue;
                    }
                    AggArg::Name(name) => name.clone(),
                    AggArg::Other => return None,
                };
                let type_name = typed(&column);
                out.push(Column::new(column, type_name));
            }
            Some(out)
        }
        _ => None,
    }
}

/// A plain expression, as [`primary_type`] reads it.
pub(crate) enum Primary<'s> {
    /// A column (unquoted).
    Name(&'s str),
    String,
    Boolean,
    Timespan,
    Dynamic,
    /// `datetime(2024-01-01)`: the literal's text.
    Typed(&'s str),
    /// The number's text.
    Number(&'s str),
    /// A call: the function's name.
    Call(&'s str),
}

/// The type of a plain expression, when the pass knows it.
pub(crate) fn primary_type(primary: &Primary<'_>, input: &Schema) -> Option<String> {
    match primary {
        Primary::Name(name) => input.column(name)?.type_name.clone(),
        Primary::String => Some("string".into()),
        Primary::Boolean => Some("bool".into()),
        Primary::Timespan => Some("timespan".into()),
        Primary::Dynamic => Some("dynamic".into()),
        // `datetime(2024-01-01)`, `long(null)`: the literal's type.
        Primary::Typed(text) => {
            let name = text[..text.find('(')?].trim().to_ascii_lowercase();
            Some(match name.as_str() {
                "date" => "datetime".into(),
                "time" => "timespan".into(),
                "double" => "real".into(),
                "boolean" => "bool".into(),
                "uniqueid" => "guid".into(),
                other => other.to_string(),
            })
        }
        Primary::Number(text) => Some(if text.contains(['.', 'e', 'E']) {
            "real".into()
        } else {
            "long".into()
        }),
        Primary::Call(name) => {
            let name = name.to_ascii_lowercase();
            let t = match name.as_str() {
                "tostring" | "tolower" | "toupper" | "strcat" | "trim" | "substring"
                | "replace_string" | "extract" | "strcat_delim" | "format_datetime" => "string",
                "toint" => "int",
                "tolong" | "strlen" | "array_length" => "long",
                "todouble" | "toreal" => "real",
                "tobool" | "toboolean" | "isempty" | "isnotempty" | "isnull" | "isnotnull" => {
                    "bool"
                }
                "todatetime" | "now" | "ago" | "datetime" => "datetime",
                "count" | "countif" | "dcount" | "dcountif" => "long",
                "make_set" | "make_list" | "make_bag" | "make_set_if" | "make_list_if" => "dynamic",
                "avg" | "avgif" | "stdev" | "variance" => "real",
                "totimespan" => "timespan",
                "todynamic" | "parse_json" | "pack" | "bag_pack" | "pack_array" | "split" => {
                    "dynamic"
                }
                _ => return None,
            };
            Some(t.into())
        }
    }
}

/// The column and type a comparison `left op right` uses wrongly
/// (`kql_type_mismatch`), from the column each side is and the literal each
/// side is.
pub(crate) fn type_mismatch(
    op: &str,
    left_column: Option<(String, String)>,
    right_column: Option<(String, String)>,
    left_literal: Option<&'static str>,
    right_literal: Option<&'static str>,
) -> Option<(String, String)> {
    if STRING_OPERATORS.contains(&op) || STRING_SET_OPERATORS.contains(&op) {
        let (column, kind) = left_column?;
        return (NUMERIC.contains(&kind.as_str())
            || matches!(kind.as_str(), "datetime" | "timespan" | "bool"))
        .then_some((column, kind));
    }
    if op == "between" || op == "!between" {
        let (column, kind) = left_column?;
        return matches!(kind.as_str(), "string" | "bool" | "guid").then_some((column, kind));
    }
    if !ORDERING.contains(&op) {
        return None;
    }
    for (column, literal) in [(left_column, right_literal), (right_column, left_literal)] {
        let (Some((column, kind)), Some(lit)) = (column, literal) else {
            continue;
        };
        let bad = match kind.as_str() {
            "string" | "guid" | "datetime" | "timespan" => true,
            k if NUMERIC.contains(&k) => lit == "string",
            _ => false,
        };
        if bad {
            return Some((column, kind));
        }
    }
    None
}

/// The message of `kql_type_mismatch`.
pub(crate) fn mismatch_message(op: &str, column: &str, kind: &str) -> String {
    format!(
        "`{op}` is not defined for `{column}`, {} {kind} column; Kusto rejects the query",
        if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
            "an"
        } else {
            "a"
        }
    )
}

/// The column `name` is in `schemas` (one, or both sides of a join), when the
/// pass knows it: a join key (`on Key`) must be on both sides.
pub(crate) fn resolve_column(name: &str, schemas: &[&Schema]) -> Option<Column> {
    if schemas
        .iter()
        .all(|s| s.has(name) || s.known == Known::Open)
    {
        schemas.iter().find_map(|s| s.column(name)).cloned()
    } else {
        None
    }
}

/// `kql_unknown_column` at `range` for a name [`resolve_column`] did not find;
/// `None` where the pass cannot say it is not a column.
pub(crate) fn unknown_column(
    name: &str,
    schemas: &[&Schema],
    range: opentide_core::Range,
) -> Option<Diagnostic> {
    // A join key must be on both sides; report against the first that lacks it.
    let schema = schemas
        .iter()
        .copied()
        .find(|s| !s.has(name) && s.known != Known::Open)?;
    if schema.custom_columns && tables::is_custom_column(name) {
        return None;
    }
    // A column an operator removed is gone, whatever the source documents.
    if let Some(op) = schema.removed.get(name) {
        return Some(Diagnostic::error(
            codes::KQL_UNKNOWN_COLUMN,
            format!("'{name}' is not a column after `{}`", operator_keyword(op)),
            range,
        ));
    }
    // A near miss is within two edits (strsim's Levenshtein distance,
    // ignoring case) and less than half the name: the threshold decides
    // whether a documented table reports the column at all
    // (`Known::Typos`). Among the columns within it, the shared rule
    // chooses ([`opentide_core::suggest::best`]).
    let lower = name.to_ascii_lowercase();
    let suggestion = opentide_core::suggest::best(
        name,
        schema.columns.iter().map(|c| c.name.as_str()).filter(|c| {
            let d = strsim::levenshtein(&c.to_ascii_lowercase(), &lower);
            d <= 2 && d * 2 < name.len()
        }),
    )
    .map(str::to_string);
    let report = match schema.known {
        Known::Closed => true,
        Known::Typos => suggestion.is_some(),
        Known::Open => false,
    };
    if !report {
        return None;
    }
    let message = match schema.reshaped_by {
        Some(op) => format!("'{name}' is not a column after `{}`", operator_keyword(op)),
        None => format!("'{name}' is not a column of {}", schema.describe_source()),
    };
    let mut d = Diagnostic::error(codes::KQL_UNKNOWN_COLUMN, message, range);
    if let Some(s) = suggestion {
        d = d.with_suggestion(s);
    }
    Some(d)
}

#[cfg(test)]
mod tests {
    use super::glob_matches;

    #[test]
    fn column_patterns_glob_over_names() {
        assert!(glob_matches("*", "Anything"));
        assert!(glob_matches("User*", "UserPrincipalName"));
        assert!(glob_matches("User*", "User"));
        assert!(glob_matches("*Id", "TenantId"));
        assert!(glob_matches("Device*Name", "DeviceName"));
        assert!(glob_matches("Device*Name", "DeviceHostName"));
        assert!(glob_matches("a*b*c", "aXbYc"));
        assert!(!glob_matches("User*", "user"));
        assert!(!glob_matches("User*", "AppUser"));
        assert!(!glob_matches("*Id", "Identity"));
        assert!(!glob_matches("a*a", "a"));
        assert!(!glob_matches("a*b*c", "acb"));
    }
}
