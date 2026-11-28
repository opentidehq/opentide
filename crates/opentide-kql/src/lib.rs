//! I/O-free KQL engine. Catalogs are compiled in; no `std::fs`.
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
// Slicing a `str` by byte index panics off a char boundary, and this crate
// reads user queries: every slice is checked or says why it is safe (#1946;
// the lint moves to `[workspace.lints]` once every crate is clean).
#![warn(clippy::string_slice)]

use opentide_core::datasets::{Declaration, DeclaredSource};
use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, ParameterInformation, Range, SignatureHelp,
    SignatureInformation, codes, suggest,
};
use opentide_highlight::HighlightToken;
pub mod output;
mod perf;
mod rows_model;
pub mod schema;
pub mod shape;
pub mod tables;
mod tables_model;

// The pure-Rust parser (#1230, ADR 0012): a logos lexer, a recursive
// descent on opentide-parse, a rowan tree. Generated from kql.ungram by `cargo xtask codegen`: an accessor for every
// child of every node, most of which the engine never calls, and names the
// grammar chooses (`TabularOperator::WhereOperator`, `RenameItem::new`).
// Public but hidden, as SPL's: `tests/ast_accessors.rs` calls every accessor
// on the corpus's trees, which keeps them right and measured.
#[doc(hidden)]
#[expect(
    clippy::new_ret_no_self,
    reason = "generated from kql.ungram: every accessor of every node, named by the grammar"
)]
#[path = "generated/ast.rs"]
pub mod ast;
mod diagnose;
mod highlight;
mod lexer;
mod parser;
#[doc(hidden)]
pub mod syntax;
mod syntax_util;
// The typed AST names the kinds from the crate root.
#[doc(hidden)]
pub use syntax::{Lang, SyntaxKind, SyntaxNode, SyntaxToken};
#[doc(hidden)]
pub mod inspect;

#[cfg(test)]
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use rows_model::TypeRow;
pub use rows_model::{
    ColumnRow, FunctionRow, OperatorOption, OperatorRow, ParamRow, PluginRow, ScalarOperatorRow,
    TableRow,
};

#[cfg(test)]
fn operators_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/operators.toml")
}
#[cfg(test)]
fn functions_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/functions.toml")
}
#[cfg(test)]
fn types_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/types.toml")
}
#[cfg(test)]
fn scalar_operators_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/operators-scalar.toml")
}
#[cfg(test)]
fn plugins_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/evaluate-plugins.toml")
}
#[cfg(test)]
fn sentinel_tables() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/sentinel/tables.toml")
}
#[cfg(test)]
fn defender_tables() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/defender/tables.toml")
}
#[cfg(test)]
fn sentinel_columns() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/sentinel/columns.toml")
}
#[cfg(test)]
fn defender_columns() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/defender/columns.toml")
}
#[cfg(test)]
fn operator_options() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/core/operator-options.toml")
}

/// The rows of `core/*.toml`: operators, functions, scalar operators, plugins, types and operator
/// options, pre-parsed by the build script (`build.rs`) and decoded here (#1743).
type CoreRows = (
    Vec<OperatorRow>,
    Vec<FunctionRow>,
    Vec<ScalarOperatorRow>,
    Vec<PluginRow>,
    Vec<TypeRow>,
    Vec<OperatorOption>,
);

fn core_rows() -> CoreRows {
    opentide_dataset::compiled_value("kql-core-rows", opentide_dataset::blob!("kql-core-rows"))
}

/// Advanced hunting's own functions (`FileProfile`, `DeviceFromIP`, `SeenBy`,
/// `AssignedIPAddresses`), as the build script pre-parsed them from
/// `data/catalogs/kql/defender/functions.toml`: the Defender dialect's catalog lists them, and
/// the Sentinel dialect reports a call to one as `kql_function_unavailable` (ADR 0015, §5.1).
pub fn defender_functions() -> &'static [FunctionRow] {
    static ROWS: OnceLock<Vec<FunctionRow>> = OnceLock::new();
    ROWS.get_or_init(|| {
        opentide_dataset::compiled_value(
            "kql-defender-functions",
            opentide_dataset::blob!("kql-defender-functions"),
        )
    })
}

/// The compiled-in text of the Defender functions, as the test reads it to compare (ADR 0013).
#[cfg(test)]
fn defender_functions_toml() -> &'static str {
    opentide_dataset::text!("data/catalogs/kql/defender/functions.toml")
}

/// A profile's hand-written tables and columns, with the types settled against the reference
/// ([`rows_model::profile_rows`]), as the build script pre-parsed them.
fn hand_written_rows(profile: Dialect) -> (Vec<TableRow>, Vec<ColumnRow>) {
    match profile {
        Dialect::Defender => opentide_dataset::compiled_value(
            "kql-defender-rows",
            opentide_dataset::blob!("kql-defender-rows"),
        ),
        _ => opentide_dataset::compiled_value(
            "kql-sentinel-rows",
            opentide_dataset::blob!("kql-sentinel-rows"),
        ),
    }
}

/// The product a KQL query runs on (ADR 0015 §1: a dialect): its
/// tables, columns and functions, and how strictly an unknown table is
/// reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// No product tables: tests and the throughput benchmark.
    Core,
    /// Microsoft Sentinel, the default: its open schema makes an unknown
    /// table a warning.
    Sentinel,
    /// Microsoft Defender XDR's advanced hunting schema, closed: an unknown
    /// table is an error.
    Defender,
}

impl Dialect {
    /// The dialect of a detection platform, as a `configurations` key or a
    /// hunt's `system`: `microsoft_defender` is Defender's, every other
    /// platform (and none) Sentinel's. The only map from a platform to a KQL
    /// dialect (ADR 0015 §3): Tide and analysis call it and keep no copy.
    #[must_use]
    pub fn for_platform(platform: &str) -> Self {
        match platform {
            "microsoft_defender" => Dialect::Defender,
            _ => Dialect::Sentinel,
        }
    }

    /// The platform whose `visibility.toml` declarations the dialect reads:
    /// [`Dialect::for_platform`]'s inverse, with `Core` reading Sentinel's.
    #[must_use]
    pub fn platform(self) -> &'static str {
        match self {
            Dialect::Defender => "microsoft_defender",
            Dialect::Core | Dialect::Sentinel => "sentinel",
        }
    }
}

/// What a KQL query is used as (ADR 0015 §1: a profile), chosen by its
/// position, never by its platform: a block's query is a [`Profile::Rule`], a
/// hunt's search or a `.kql` file a [`Profile::Search`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// A scheduled detection rule: a `configurations.<platform>.query`.
    Rule,
    /// A search run by hand: a hunt, `opentide query`, a `.kql` file.
    #[default]
    Search,
}

/// The longest query a Microsoft Sentinel scheduled analytics rule takes, in
/// characters ([`rule_findings`]).
pub const SENTINEL_RULE_MAX_CHARS: usize = 10_000;

/// The findings a query gets only as a [`Profile::Rule`] of `dialect`, on top
/// of [`analyze`]'s. Under Sentinel, Microsoft's scheduled analytics rules
/// page (learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview,
/// read 2026-11-27) says "The query length should be between 1 and 10,000
/// characters and can't contain `search *` or `union *`": each is an error,
/// `kql_rule_search_star`, `kql_rule_union_star` and `kql_rule_too_long`.
/// Defender's custom detection page sets none of these limits, so Defender
/// and Core rules get none; a search gets none in any dialect.
///
/// `search *` is a `search` with no `in (...)` list whose predicate is a bare
/// `*`; `union *` a `union` whose tables include a bare `*` (not `Sec*`).
/// They take the place of the performance warnings at the same place
/// (`kql_unscoped_search`, `kql_unscoped_union`), which [`analyze`] reports:
/// [`apply_profile`] drops those.
#[must_use]
pub fn rule_findings(source: &str, dialect: Dialect, profile: Profile) -> Vec<Diagnostic> {
    if dialect != Dialect::Sentinel || profile != Profile::Rule {
        return Vec::new();
    }
    let lines = opentide_core::LineIndex::new(source);
    let mut out = Vec::new();
    perf::rule_scope(source, &lines, &mut out);
    let length = source.trim().chars().count();
    if length > SENTINEL_RULE_MAX_CHARS {
        let trimmed = source.trim_start();
        let start = source.len() - trimmed.len();
        let first_line_end = trimmed.find('\n').map_or(source.len(), |at| start + at);
        out.push(Diagnostic::error(
            codes::KQL_RULE_TOO_LONG,
            format!(
                "the query is {length} characters long: a Microsoft Sentinel analytics rule's \
                 query is at most {SENTINEL_RULE_MAX_CHARS}; move parts of it into a saved \
                 workspace function"
            ),
            lines.range(ByteSpan::new(start, first_line_end.max(start))),
        ));
    }
    out
}

/// [`rule_findings`] added to `diagnostics` ([`analyze`]'s for the same
/// `source`), each in place of the performance warning at the same range.
pub fn apply_profile(
    source: &str,
    dialect: Dialect,
    profile: Profile,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let found = rule_findings(source, dialect, profile);
    if found.is_empty() {
        return;
    }
    let replaces = |code: &str| match code {
        codes::KQL_UNSCOPED_SEARCH => Some(codes::KQL_RULE_SEARCH_STAR),
        codes::KQL_UNSCOPED_UNION => Some(codes::KQL_RULE_UNION_STAR),
        _ => None,
    };
    diagnostics.retain(|d| {
        replaces(&d.code)
            .is_none_or(|rule| !found.iter().any(|f| f.code == rule && f.range == d.range))
    });
    diagnostics.extend(found);
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct OperatorsFile {
    operators: Vec<OperatorRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct FunctionsFile {
    functions: Vec<FunctionRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct ScalarOperatorsFile {
    scalar_operators: Vec<ScalarOperatorRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct PluginsFile {
    plugins: Vec<PluginRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct TypesFile {
    types: Vec<TypeRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct TablesFile {
    tables: Vec<TableRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct ColumnsFile {
    columns: Vec<ColumnRow>,
}

/// The whole file, as the test reads it to compare (ADR 0013).
#[cfg(test)]
#[derive(Debug, Deserialize)]
struct OptionsFile {
    options: Vec<OperatorOption>,
}

impl ColumnRow {
    /// A column of the hand-written catalog with its docs: the columns offered
    /// before the query names a table, out of the whole reference's.
    fn hand_written(&self) -> bool {
        !self.from_reference && !self.declared && self.docs.is_some()
    }
}

/// A dialect's KQL catalog: operators, functions, plugins, types, tables and
/// columns.
///
/// Reading it builds indexes and schemas once and keeps them on it, for
/// every thread ([`Catalog::for_workspace`]'s catalogs included). Its
/// methods that change rows rebuild them; a caller that changes the public
/// rows directly does so on a fresh copy ([`Clone`] keeps none of them),
/// before any read.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// The dialect the tables and columns come from.
    pub profile: Dialect,
    pub operators: Vec<OperatorRow>,
    pub functions: Vec<FunctionRow>,
    pub scalar_operators: Vec<ScalarOperatorRow>,
    pub plugins: Vec<PluginRow>,
    pub types: Vec<String>,
    pub tables: Vec<TableRow>,
    /// The hand-written columns, then the ones a workspace declares
    /// ([`Catalog::for_workspace`]). The Azure Monitor Logs reference's columns are not here:
    /// a table's are read when something first asks for them
    /// ([`Catalog::columns_for_table`]), which is nearly all of a catalog's columns.
    pub columns: Vec<ColumnRow>,
    pub options: Vec<OperatorOption>,
    /// `tables` by name.
    table_index: HashMap<String, usize>,
    /// `columns` by lower-cased table name.
    column_index: HashMap<String, Vec<usize>>,
    /// How many of `columns` are the profile's own: those after them were declared.
    hand_len: usize,
    /// The reference's columns of each of `tables`, by position, read when first asked for.
    lazy: Vec<Lazy>,
    /// What reading it builds once, for every thread.
    memo: Memo,
}

/// The columns the reference lists for one table, as rows: where they are stored, and the rows
/// built from them the first time they are asked for (#1767).
#[derive(Debug, Clone)]
struct Lazy {
    /// Where the table's columns are, and the reference page they come from; `None` for a table
    /// the reference lists no columns of.
    at: Option<(tables::ColumnsAt, Arc<str>)>,
    /// What follows the hand-written columns of the table: the reference's other columns and, for
    /// an advanced hunting table, its time column.
    rows: OnceLock<Vec<ColumnRow>>,
}

/// What reading a catalog builds once and keeps on it, shared by every
/// thread: the lower-cased name indexes of its operators, functions, scalar
/// operators and plugins ([`Catalog::by_name`]), the schemas of its tables
/// and ASIM parsers (`schema::table_schema`), its table names prepared for
/// [`Catalog::suggest_table`] and the names of its hand-written columns.
/// Each is built on first
/// use, for a profile's bundled catalog and a workspace's catalog with
/// declared columns alike, so a workspace that declares columns analyses as
/// fast as one that does not, and a declared catalog's memo goes with it
/// when [`Catalog::for_workspace`] lets it go. A copy of a catalog starts
/// with an empty memo, and changing its rows through its methods empties
/// it; a caller that changes a catalog's public rows directly does so
/// before reading it.
#[derive(Default)]
struct Memo {
    /// Operators, functions, scalar operators and plugins, in that order.
    names: [OnceLock<HashMap<String, usize>>; 4],
    /// Tables, then ASIM parsers: the schema built for each name.
    schemas: [RwLock<HashMap<String, schema::Schema>>; 2],
    /// The table names, lower-cased and folded ([`Catalog::suggest_table`]).
    table_names: OnceLock<suggest::Candidates>,
    /// The names of the hand-written columns.
    hand_written: OnceLock<HashSet<Box<str>>>,
    /// The position in `tables` of each table, by lower-cased name.
    table_lower: OnceLock<HashMap<String, usize>>,
}

impl Clone for Memo {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for Memo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memo").finish_non_exhaustive()
    }
}

/// The catalog a query is checked against ([`Catalog::for_workspace`]).
#[derive(Debug, Clone)]
pub enum CatalogRef {
    /// The profile's cached catalog: the workspace declares no columns.
    Bundled(&'static Catalog),
    /// The profile's catalog with the workspace's declared columns.
    Declared(Arc<Catalog>),
}

impl std::ops::Deref for CatalogRef {
    type Target = Catalog;

    fn deref(&self) -> &Catalog {
        match self {
            Self::Bundled(catalog) => catalog,
            Self::Declared(catalog) => catalog,
        }
    }
}

/// The items of the array `key` of the compiled-in catalog `text`
/// (`data/catalogs/kql/<file>`), read item by item (ADR 0013): what the tests compare the
/// pre-parsed rows with.
#[cfg(test)]
fn rows<T: serde::de::DeserializeOwned>(file: &str, text: &str, key: &str) -> Vec<T> {
    opentide_core::catalog::compiled_in(
        &format!("data/catalogs/kql/{file}"),
        opentide_core::catalog::array_items(text, key),
    )
}

impl Catalog {
    pub fn core() -> Self {
        let (operators, functions, scalar_operators, plugins, types, options) = core_rows();
        Self {
            profile: Dialect::Core,
            operators,
            functions,
            scalar_operators,
            plugins,
            types: types.into_iter().map(|t| t.name).collect(),
            tables: Vec::new(),
            columns: Vec::new(),
            options,
            table_index: HashMap::new(),
            column_index: HashMap::new(),
            hand_len: 0,
            lazy: Vec::new(),
            memo: Memo::default(),
        }
    }

    /// The tables and columns of a profile:
    ///
    /// - `sentinel`: the hand-written Sentinel tables, the Defender XDR tables
    ///   the Defender XDR connector streams into a workspace, and every table
    ///   of the Azure Monitor Logs reference with its columns; ASIM parsers
    ///   are known sources ([`Catalog::asim_parser`]).
    /// - `microsoft_defender`: the advanced hunting tables, with the
    ///   columns the reference lists for those it has, but the Log Analytics
    ///   standard columns of its copies (`TimeGenerated`, `TenantId`, ...),
    ///   and advanced hunting's own functions ([`defender_functions`]).
    ///
    /// Hand-written columns keep their docs and are added to the reference's,
    /// never removed: a column either lists is known.
    pub fn with_profile(mut self, profile: Dialect) -> Self {
        if profile == Dialect::Core {
            return self;
        }
        self.profile = profile;
        let (mut tables, columns) = hand_written_rows(profile);
        let heads = tables::azure_monitor_heads();
        if profile == Dialect::Sentinel {
            let known: HashSet<String> = tables.iter().map(|t| t.name.clone()).collect();
            for head in heads {
                if !known.contains(&head.name) {
                    tables.push(TableRow {
                        name: head.name.clone(),
                        profile: Some("sentinel".into()),
                        category: head.categories.first().cloned(),
                        docs: (!head.docs.is_empty()).then(|| head.docs.clone()),
                        citation: Some(head.citation.to_string()),
                        documented: false,
                        declared: false,
                    });
                }
            }
        }
        // A table the reference lists columns of is documented; its columns are read when asked for.
        let by_name: HashMap<&str, &tables::AzureMonitorHead> = heads
            .iter()
            .map(|head| (head.name.as_str(), head))
            .collect();
        let mut lazy = Vec::with_capacity(tables.len());
        for row in &mut tables {
            let at = by_name.get(row.name.as_str()).and_then(|head| {
                let at = head.columns?;
                row.documented = true;
                if row.citation.is_none() {
                    row.citation = Some(head.citation.to_string());
                }
                Some((at, Arc::clone(&head.citation)))
            });
            lazy.push(Lazy {
                at,
                rows: OnceLock::new(),
            });
        }
        self.tables = tables;
        self.hand_len = columns.len();
        self.columns = columns;
        self.lazy = lazy;
        // A dialect's own functions are its alone: a catalog moved from one
        // dialect to another keeps Kusto's and takes the new dialect's.
        self.functions.retain(|f| f.profile.is_none());
        if profile == Dialect::Defender {
            self.functions.extend(defender_functions().iter().cloned());
        }
        self.reindex();
        self
    }

    /// The columns of `tables[i]` that follow its hand-written ones: the reference's, which it
    /// does not have among them, in the reference's order, and an advanced hunting table's time
    /// column (the Log Analytics copies the reference describes do not list it, yet queries over
    /// them use it). Built from the reference the first time they are asked for.
    fn reference_columns(&self, i: usize) -> &[ColumnRow] {
        let Some(lazy) = self.lazy.get(i) else {
            return &[];
        };
        lazy.rows.get_or_init(|| self.build_reference_columns(i))
    }

    fn build_reference_columns(&self, i: usize) -> Vec<ColumnRow> {
        let (Some(row), Some(lazy)) = (self.tables.get(i), self.lazy.get(i)) else {
            return Vec::new();
        };
        let profile_name = match self.profile {
            Dialect::Defender => "defender",
            _ => "sentinel",
        };
        // The names the table's hand-written columns have, which the reference does not repeat.
        let hand: HashSet<&str> = self
            .column_index
            .get(&row.name.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .filter(|&&j| j < self.hand_len)
            .filter_map(|&j| self.columns.get(j))
            .filter(|column| *column.table == *row.name)
            .map(|column| &*column.name)
            .collect();
        // One allocation each, shared by the table's columns (#1071).
        let table: Arc<str> = Arc::from(row.name.as_str());
        let profile_shared: Arc<str> = Arc::from(profile_name);
        let mut rows: Vec<ColumnRow> = Vec::new();
        let mut at: HashMap<Arc<str>, usize> = HashMap::new();
        if let Some((columns_at, citation)) = &lazy.at {
            for column in tables::azure_monitor_columns(*columns_at) {
                if hand.contains(&*column.name) {
                    continue;
                }
                // The reference describes the Log Analytics copy of an
                // advanced hunting table: its standard columns
                // (`TimeGenerated`, `TenantId`, `Type`, `_BilledSize`, ...)
                // are the workspace's, not advanced hunting's (#1885).
                if self.profile == Dialect::Defender
                    && tables::STANDARD_COLUMNS
                        .iter()
                        .any(|(name, _)| *name == &*column.name)
                {
                    continue;
                }
                if let Some(&j) = at.get(&column.name) {
                    // Listed twice, differently: neither is trusted for type checks.
                    if let Some(earlier) = rows.get_mut(j)
                        && earlier.type_name.as_deref() != Some(&*column.type_name)
                    {
                        earlier.type_name = None;
                    }
                    continue;
                }
                at.insert(Arc::clone(&column.name), rows.len());
                rows.push(ColumnRow {
                    table: Arc::clone(&table),
                    profile: Some(Arc::clone(&profile_shared)),
                    name: column.name.clone(),
                    type_name: Some(column.type_name.clone()),
                    docs: column.description.clone(),
                    citation: Some(Arc::clone(citation)),
                    from_reference: true,
                    declared: false,
                });
            }
        }
        if row.profile.as_deref() == Some("defender")
            && !hand.contains("Timestamp")
            && !at.contains_key("Timestamp")
        {
            rows.push(ColumnRow {
                table,
                profile: Some(Arc::from("defender")),
                name: "Timestamp".into(),
                type_name: Some(tables::kusto_type("datetime")),
                docs: Some(Arc::from("Event time in advanced hunting.")),
                citation: row.citation.as_deref().map(Arc::from),
                from_reference: false,
                declared: false,
            });
        }
        rows
    }

    /// The position in `tables` of the table `lower` (lower-cased) names.
    fn table_by_lower(&self, lower: &str) -> Option<usize> {
        let index = self.memo.table_lower.get_or_init(|| {
            let mut index = HashMap::with_capacity(self.tables.len());
            for (i, table) in self.tables.iter().enumerate() {
                index.entry(table.name.to_ascii_lowercase()).or_insert(i);
            }
            index
        });
        index.get(lower).copied()
    }

    fn reindex(&mut self) {
        self.memo = Memo::default();
        self.table_index = self
            .tables
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i))
            .collect();
        self.column_index.clear();
        for (i, c) in self.columns.iter().enumerate() {
            self.column_index
                .entry(c.table.to_ascii_lowercase())
                .or_default()
                .push(i);
        }
    }

    /// An ASIM parser the profile knows (`_Im_NetworkSession`,
    /// `imAuthentication`, `ASimDns`). Only Sentinel workspaces have them.
    pub fn asim_parser(&self, name: &str) -> Option<&'static tables::AsimParser> {
        if self.profile != Dialect::Sentinel {
            return None;
        }
        tables::asim().parser(name)
    }

    /// The function `name` (exactly, as Kusto's names are case-sensitive) when another
    /// dialect has it and this one does not: under Sentinel, one of advanced hunting's own
    /// ([`defender_functions`]). `None` under Core, which has no product, and under Defender.
    pub fn unavailable_function(&self, name: &str) -> Option<&'static FunctionRow> {
        if self.profile != Dialect::Sentinel {
            return None;
        }
        defender_functions().iter().find(|f| f.name == name)
    }

    /// Parsed once per profile for the process. `core()` still reparses for tests.
    pub fn cached(profile: Dialect) -> &'static Self {
        match profile {
            Dialect::Core => {
                static CORE: OnceLock<Catalog> = OnceLock::new();
                CORE.get_or_init(Self::core)
            }
            Dialect::Sentinel => {
                static SENTINEL: OnceLock<Catalog> = OnceLock::new();
                SENTINEL.get_or_init(|| Self::core().with_profile(Dialect::Sentinel))
            }
            Dialect::Defender => {
                static DEFENDER: OnceLock<Catalog> = OnceLock::new();
                DEFENDER.get_or_init(|| Self::core().with_profile(Dialect::Defender))
            }
        }
    }

    /// The profile's catalog ([`Catalog::cached`]) with the columns the
    /// workspace lists for its tables in `visibility.toml` (#146), for a
    /// query whose text is `source`: what every query check, hover and
    /// completion reads. Without declared columns for the profile's platform
    /// it is the cached catalog itself; with them, a copy built once per set
    /// of declarations ([`Catalog::with_declared_columns`]), the four most
    /// recently used kept. A name the query reads that is in neither, but
    /// that a declared pattern with columns matches (`Vendor*_CL`), gets a
    /// copy of that copy with the name's table added, the two most recent
    /// kept. `Core` has no tables and takes none.
    pub fn for_workspace(profile: Dialect, source: &str) -> CatalogRef {
        let bundled = Self::cached(profile);
        if profile == Dialect::Core {
            return CatalogRef::Bundled(bundled);
        }
        let datasets = opentide_core::datasets::current();
        let platform = profile.platform();
        let declared: Vec<DeclaredSource> =
            datasets.sources_with_columns(platform).cloned().collect();
        if declared.is_empty() {
            return CatalogRef::Bundled(bundled);
        }
        let exact: Vec<String> = datasets
            .names(platform)
            .iter()
            .filter(|n| !n.contains('*'))
            .cloned()
            .collect();
        // What a catalog is built from: the sources with columns and every
        // declared name, which a pattern's tables are matched against.
        type Key = (Vec<DeclaredSource>, Vec<String>);
        type Cache = Mutex<Recent<Key, Arc<Catalog>>>;
        type QueryCache = Mutex<Recent<(Key, Vec<String>), Arc<Catalog>>>;
        static SENTINEL: OnceLock<Cache> = OnceLock::new();
        static DEFENDER: OnceLock<Cache> = OnceLock::new();
        static SENTINEL_QUERY: OnceLock<QueryCache> = OnceLock::new();
        static DEFENDER_QUERY: OnceLock<QueryCache> = OnceLock::new();
        let (cache, query_cache) = match profile {
            Dialect::Defender => (&DEFENDER, &DEFENDER_QUERY),
            _ => (&SENTINEL, &SENTINEL_QUERY),
        };
        let cache = cache.get_or_init(Default::default);
        let key = (declared, exact);
        let workspace = Recent::get_or_build(cache, RECENT_CATALOGS, &key, || {
            bundled.with_declared_columns(&key.0, &key.1)
        });
        let declared = &key.0;
        // Names the query reads that only a declared pattern knows.
        let patterns: Vec<&DeclaredSource> =
            declared.iter().filter(|s| s.name.contains('*')).collect();
        let mut extra: Vec<String> = identifiers(source)
            .filter(|word| workspace.table(word).is_none())
            .filter(|word| {
                patterns
                    .iter()
                    .any(|p| opentide_core::datasets::glob_matches(&p.name, word))
            })
            .map(str::to_string)
            .collect();
        if extra.is_empty() {
            return CatalogRef::Declared(workspace);
        }
        extra.sort();
        extra.dedup();
        let query_cache = query_cache.get_or_init(Default::default);
        let query_key = (key.clone(), extra);
        let catalog = Recent::get_or_build(query_cache, RECENT_QUERY_CATALOGS, &query_key, || {
            let mut catalog = (*workspace).clone();
            let targets = declared_targets(&patterns, query_key.1.iter().map(String::as_str));
            catalog.apply_declared(targets);
            catalog
        });
        CatalogRef::Declared(catalog)
    }

    /// This catalog with the tables and columns `sources` declare, for
    /// every table each names: its own name, or for a pattern (`Vendor*_CL`)
    /// each catalog table and each of `declared` (the platform's other
    /// declared names) it matches. A declared table the catalog lacks is
    /// added; one it has keeps its columns and gains the declared ones. A
    /// declared column named like a catalog column replaces its type, and
    /// its description when it has one. Where several log sources give a
    /// table columns, an exact name's win over a pattern's, and an earlier
    /// pattern's over a later one's. The table's columns are then checked as
    /// a documented table's: a near miss of one is `kql_unknown_column`.
    pub fn with_declared_columns(&self, sources: &[DeclaredSource], declared: &[String]) -> Self {
        let mut catalog = self.clone();
        let exact: Vec<&DeclaredSource> =
            sources.iter().filter(|s| !s.name.contains('*')).collect();
        let patterns: Vec<&DeclaredSource> =
            sources.iter().filter(|s| s.name.contains('*')).collect();
        let mut targets: BTreeMap<String, Vec<&DeclaredSource>> = BTreeMap::new();
        for source in exact {
            targets.entry(source.name.clone()).or_default().push(source);
        }
        let names = self
            .tables
            .iter()
            .map(|t| t.name.as_str())
            .chain(declared.iter().map(String::as_str));
        for (table, matched) in declared_targets(&patterns, names) {
            targets.entry(table).or_default().extend(matched);
        }
        catalog.apply_declared(targets);
        catalog
    }

    /// Give each table the columns of its log sources, in order: the first
    /// to declare a column decides its type and description.
    fn apply_declared(&mut self, targets: BTreeMap<String, Vec<&DeclaredSource>>) {
        self.memo = Memo::default();
        let profile_name = match self.profile {
            Dialect::Defender => "defender",
            _ => "sentinel",
        };
        for (table, sources) in targets {
            let table = table.as_str();
            if sources.iter().all(|s| s.columns.is_empty()) {
                continue;
            }
            match self.table_index.get(table) {
                Some(&i) => {
                    let row = &mut self.tables[i];
                    row.documented = true;
                    row.declared = true;
                }
                None => {
                    self.table_index
                        .insert(table.to_string(), self.tables.len());
                    self.tables.push(TableRow {
                        name: table.to_string(),
                        profile: Some(profile_name.into()),
                        category: None,
                        docs: sources.iter().find_map(|s| s.description.clone()),
                        citation: None,
                        documented: true,
                        declared: true,
                    });
                    // A table the workspace names has no reference columns to read.
                    self.lazy.push(Lazy {
                        at: None,
                        rows: OnceLock::from(Vec::new()),
                    });
                }
            }
            let lower = table.to_ascii_lowercase();
            // The reference's columns of the table, to find the ones a source declares among them.
            if let Some(i) = self.table_index.get(table).copied() {
                let _ = self.reference_columns(i);
            }
            for column in sources.iter().flat_map(|s| s.columns.iter()) {
                let own = |this: &Self, wanted_declared: bool| -> Option<usize> {
                    this.column_index.get(&lower).and_then(|ids| {
                        ids.iter().copied().find(|&i| {
                            (i >= this.hand_len) == wanted_declared
                                && *this.columns[i].table == *table
                                && *this.columns[i].name == *column.name
                        })
                    })
                };
                let in_reference = self.table_index.get(table).copied().and_then(|i| {
                    let rows = self.lazy.get(i)?.rows.get()?;
                    rows.iter()
                        .position(|row| *row.name == *column.name)
                        .map(|position| (i, position))
                });
                let existing = own(self, false)
                    .map(|i| (None, i))
                    .or_else(|| in_reference.map(|(t, p)| (Some(t), p)))
                    .or_else(|| own(self, true).map(|i| (None, i)));
                let declared_before = match existing {
                    Some((None, i)) => self.columns[i].declared,
                    Some((Some(t), p)) => self
                        .lazy
                        .get(t)
                        .and_then(|lazy| lazy.rows.get())
                        .is_some_and(|rows| rows[p].declared),
                    None => false,
                };
                match existing {
                    // An earlier log source declared it already.
                    Some(_) if declared_before => {}
                    Some((place, i)) => {
                        let row = match place {
                            None => &mut self.columns[i],
                            Some(t) => {
                                match self.lazy.get_mut(t).and_then(|lazy| lazy.rows.get_mut()) {
                                    Some(rows) => &mut rows[i],
                                    None => continue,
                                }
                            }
                        };
                        row.type_name = column.type_name.as_deref().map(tables::kusto_type);
                        if let Some(description) = &column.description {
                            row.docs = Some(Arc::from(description.as_str()));
                            row.citation = None;
                        }
                        row.declared = true;
                    }
                    None => {
                        self.column_index
                            .entry(lower.clone())
                            .or_default()
                            .push(self.columns.len());
                        self.columns.push(ColumnRow {
                            table: Arc::from(table),
                            profile: Some(Arc::from(profile_name)),
                            name: Arc::from(column.name.as_str()),
                            type_name: column.type_name.as_deref().map(tables::kusto_type),
                            docs: column.description.as_deref().map(Arc::from),
                            citation: None,
                            from_reference: false,
                            declared: true,
                        });
                    }
                }
            }
        }
    }

    pub fn operator(&self, name: &str) -> Option<&OperatorRow> {
        self.by_name(0, &self.operators, |o| &o.name, name)
    }

    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        self.by_name(1, &self.functions, |f| &f.name, name)
    }

    /// The first of `rows` whose name is `name`, ASCII case ignored, looked
    /// up in the index of `rows` this catalog builds on first use (its memo's
    /// `names[slot]`): a scan of the hundreds of functions for each name a
    /// query uses was a tenth of its analysis.
    fn by_name<'a, T>(
        &self,
        slot: usize,
        rows: &'a [T],
        name_of: impl Fn(&T) -> &String,
        name: &str,
    ) -> Option<&'a T> {
        let index = self.memo.names.get(slot)?.get_or_init(|| {
            let mut by_name = HashMap::with_capacity(rows.len());
            for (i, row) in rows.iter().enumerate() {
                by_name
                    .entry(name_of(row).to_ascii_lowercase())
                    .or_insert(i);
            }
            by_name
        });
        // Most names are lower case already: no copy to look them up.
        let found = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            index.get(&name.to_ascii_lowercase())
        } else {
            index.get(name)
        };
        found.and_then(|&i| rows.get(i))
    }

    pub fn table(&self, name: &str) -> Option<&TableRow> {
        self.table_index.get(name).map(|&i| &self.tables[i])
    }

    pub fn scalar_operator(&self, name: &str) -> Option<&ScalarOperatorRow> {
        self.by_name(2, &self.scalar_operators, |o| &o.name, name)
    }

    pub fn plugin(&self, name: &str) -> Option<&PluginRow> {
        self.by_name(3, &self.plugins, |p| &p.name, name)
    }

    /// The catalogued table `name` most likely means
    /// ([`opentide_core::suggest`]).
    pub fn suggest_table(&self, name: &str) -> Option<String> {
        // The table names, lower-cased and folded once per catalog:
        // preparing the catalog's hundreds of names for each unknown table
        // was a third of a Sentinel query's analysis.
        let prepared = self
            .memo
            .table_names
            .get_or_init(|| suggest::Candidates::new(self.tables.iter().map(|t| t.name.as_str())));
        prepared
            .closest(name)
            .and_then(|i| self.tables.get(i))
            .map(|t| t.name.clone())
    }

    /// [`Catalog::suggest_table`] among the tables a query can write bare. A
    /// declared log source with columns is a catalog row named after it,
    /// spaces included, which a rename must never offer: the best bare name
    /// wins instead.
    fn suggest_bare_table(&self, name: &str) -> Option<String> {
        self.near_bare_table(name, suggest::max_edits(name.chars().count()))
    }

    /// [`Catalog::suggest_bare_table`] within `edits` edits.
    fn near_bare_table(&self, name: &str, edits: usize) -> Option<String> {
        let prepared = self
            .memo
            .table_names
            .get_or_init(|| suggest::Candidates::new(self.tables.iter().map(|t| t.name.as_str())));
        prepared
            .ranked(name, edits, self.tables.len())
            .into_iter()
            .filter_map(|i| self.tables.get(i))
            .find(|t| is_bare_identifier(&t.name))
            .map(|t| t.name.clone())
    }

    pub fn operator_names(&self) -> Vec<String> {
        self.operators.iter().map(|o| o.name.clone()).collect()
    }

    pub fn function_names(&self) -> Vec<String> {
        self.functions.iter().map(|f| f.name.clone()).collect()
    }

    /// The columns of `table`, ASCII case ignored: the hand-written ones, the reference's (read
    /// the first time a table's are asked for) and the ones a workspace declares, in that order.
    pub fn columns_for_table(&self, table: &str) -> Vec<&ColumnRow> {
        let lower = table.to_ascii_lowercase();
        let own: &[usize] = self.column_index.get(&lower).map_or(&[], Vec::as_slice);
        let mut rows: Vec<&ColumnRow> = own
            .iter()
            .filter(|&&i| i < self.hand_len)
            .filter_map(|&i| self.columns.get(i))
            .collect();
        if let Some(i) = self.table_by_lower(&lower) {
            rows.extend(self.reference_columns(i));
        }
        rows.extend(
            own.iter()
                .filter(|&&i| i >= self.hand_len)
                .filter_map(|&i| self.columns.get(i)),
        );
        rows
    }

    /// The catalog tables `source` names, in order of first mention.
    pub fn mentioned_tables(&self, source: &str) -> Vec<&TableRow> {
        let mut seen = BTreeSet::new();
        identifiers(source)
            .filter_map(|word| self.table(word))
            .filter(|t| seen.insert(t.name.as_str()))
            .collect()
    }

    pub fn resolve_column(&self, source: &str, name: &str) -> Option<&ColumnRow> {
        self.resolve_column_among(&self.mentioned_tables(source), name)
    }

    /// [`Catalog::resolve_column`] with the tables the query names already
    /// found: a caller that resolves many names scans the query once.
    fn resolve_column_among(&self, mentioned: &[&TableRow], name: &str) -> Option<&ColumnRow> {
        if let Some(col) = mentioned.iter().find_map(|table| {
            self.columns_for_table(&table.name)
                .into_iter()
                .find(|c| *c.name == *name)
        }) {
            return Some(col);
        }
        // A column of a table the query does not name: only the hand-written
        // catalog's, not every column of every table in the reference.
        self.columns
            .iter()
            .find(|c| *c.name == *name && c.hand_written())
    }

    /// The names of the hand-written catalog's columns. Finding them reads
    /// every column of the catalog, tens of thousands with the reference's:
    /// they are found once per catalog (its memo), not once per query (a
    /// quarter of a short query's analysis).
    fn hand_written_column_names(&self) -> &HashSet<Box<str>> {
        self.memo.hand_written.get_or_init(|| {
            self.columns
                .iter()
                .filter(|c| c.hand_written())
                .map(|c| Box::from(&*c.name))
                .collect()
        })
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

/// The identifier-shaped words of `source` (`[A-Za-z_][A-Za-z0-9_]*`).
fn identifiers(source: &str) -> impl Iterator<Item = &str> {
    source
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| {
            w.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        })
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

/// The HIR of `source`: its `let`s, its first source and its operators.
pub fn lower(source: &str) -> Hir {
    let parsed = parser::parse_once(source);
    diagnose::lower(&SyntaxNode::new_root(parsed.green), source)
}

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub hir: Hir,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str, profile: Dialect) -> AnalyzeResult {
    let catalog = Catalog::for_workspace(profile, source);
    analyze_with_catalog(source, &catalog)
}

/// The Kusto Query Language (KQL) [`QueryEngine`](opentide_highlight::QueryEngine) (#1953):
/// [`analyze`] behind the shared interface.
///
/// The dialect is the platform's ([`Dialect::for_platform`]): a `.kql` file
/// reads as Microsoft Sentinel's, the default. A rule's query and a search
/// get their [`Profile`]'s findings ([`apply_profile`]); a file gets none.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine;

impl opentide_highlight::QueryEngine for Engine {
    fn language(&self) -> opentide_core::LanguageId {
        opentide_core::LanguageId::Kql
    }

    fn analyze_for(
        &self,
        source: &str,
        setting: &opentide_highlight::Setting<'_>,
    ) -> opentide_highlight::AnalyzeResult {
        let dialect = Dialect::for_platform(setting.platform);
        let mut r = analyze(source, dialect);
        let profile = match setting.profile {
            opentide_highlight::Profile::File => None,
            opentide_highlight::Profile::Search => Some(Profile::Search),
            opentide_highlight::Profile::Rule => Some(Profile::Rule),
        };
        if let Some(profile) = profile {
            apply_profile(source, dialect, profile, &mut r.diagnostics);
        }
        opentide_highlight::AnalyzeResult {
            diagnostics: r.diagnostics,
            tokens: r.tokens,
        }
    }

    fn hover(
        &self,
        source: &str,
        offset: usize,
        setting: &opentide_highlight::Setting<'_>,
    ) -> Option<String> {
        hover(source, offset, Dialect::for_platform(setting.platform))
    }

    fn completions(
        &self,
        source: &str,
        offset: usize,
        setting: &opentide_highlight::Setting<'_>,
    ) -> Vec<opentide_core::CompletionItem> {
        completions(source, offset, Dialect::for_platform(setting.platform))
    }

    fn signature_help(
        &self,
        source: &str,
        offset: usize,
        setting: &opentide_highlight::Setting<'_>,
    ) -> Option<opentide_core::SignatureHelp> {
        signature_help(source, offset, Dialect::for_platform(setting.platform))
    }
}

/// The columns at every operator of a query, with the references and
/// definitions the column pass found (#112). Empty for a query that does not
/// parse at all.
pub fn columns(source: &str, profile: Dialect) -> schema::Analysis {
    let catalog = Catalog::for_workspace(profile, source);
    std::rc::Rc::unwrap_or_clone(diagnose::columns(source, &catalog))
}

/// Parses `source`, checks it against `catalog` and highlights it: every
/// diagnostic, the HIR and the highlight tokens, from one parse.
pub fn analyze_with_catalog(source: &str, catalog: &Catalog) -> AnalyzeResult {
    let analysis = diagnose::analyze(source, catalog);
    AnalyzeResult {
        diagnostics: analysis.diagnostics,
        hir: analysis.hir,
        tokens: analysis.tokens,
    }
}

/// Type names that begin a typed scalar literal, `datetime(2024-01-01)`, as
/// Kusto's lexer reads them (the `typed_literal` token in grammar.js).
const TYPED_LITERAL_TYPES: &[&str] = &[
    "bool", "date", "datetime", "decimal", "double", "guid", "int", "int32", "int64", "long",
    "real", "time", "timespan",
];

/// A name in the form of an ASIM parser (`_Im_Dns`, `_ASim_Dns`, `imDns`,
/// `ASimDns`, `vimDnsMicrosoftOMS`), when the catalog does not list it: a
/// workspace may deploy parsers of its own.
fn asim_shaped(name: &str) -> bool {
    if name.starts_with("_Im_") || name.starts_with("_ASim_") {
        return true;
    }
    ["im", "vim", "ASim"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
    })
}

/// The tables among `names` each pattern log source matches, with the
/// patterns that match it, in file order.
fn declared_targets<'d, 'n>(
    patterns: &[&'d DeclaredSource],
    names: impl Iterator<Item = &'n str>,
) -> BTreeMap<String, Vec<&'d DeclaredSource>> {
    let mut out: BTreeMap<String, Vec<&'d DeclaredSource>> = BTreeMap::new();
    for name in names {
        if name.contains('*') || out.contains_key(name) {
            continue;
        }
        let matched: Vec<&DeclaredSource> = patterns
            .iter()
            .copied()
            .filter(|p| opentide_core::datasets::glob_matches(&p.name, name))
            .collect();
        if !matched.is_empty() {
            out.insert(name.to_string(), matched);
        }
    }
    out
}

/// [`check_table`] on the table's name and the range to report: the part of
/// the check no parser is in.
fn check_table_named(
    table: &str,
    range: Range,
    catalog: &Catalog,
    binds: impl Fn(&str) -> bool,
    out: &mut Vec<Diagnostic>,
) {
    // `let` bindings, tabular parameters, functions the engine knows
    // (`_GetWatchlist`) and ASIM parsers are not tables.
    if table.starts_with('$')
        || binds(table)
        || catalog.asim_parser(table).is_some()
        || (catalog.profile == Dialect::Sentinel && asim_shaped(table))
        || catalog.operator(table).is_some()
        // A function of exactly this name: the first of any case, else a scan
        // for one of another case (the catalog has none).
        || catalog.function(table).is_some_and(|f| {
            f.name == table || catalog.functions.iter().any(|f| f.name == table)
        })
    {
        return;
    }
    let known = catalog.table(table).is_some();
    let platform = catalog.profile.platform();
    let datasets = opentide_core::datasets::current();
    // Without declarations, a name that starts with a lower-case letter is
    // more likely a workspace function; `_CL` still marks a custom table
    // (#149). With them, a workspace function is declared like a table, so
    // every name is checked whatever its case.
    if !known
        && !datasets.declares(platform)
        && table.starts_with(|c: char| c.is_ascii_lowercase())
        && !table.ends_with("_CL")
    {
        return;
    }
    let status = datasets.status(platform, table);
    // A near miss of a declared table, else of a catalog table. Only a name a
    // query can write bare is offered: a declared display name such as
    // `Azure Activity` is not a KQL identifier, and substituting it breaks the
    // query.
    // The declared names, read once for both lookups below.
    let declared = std::cell::OnceCell::new();
    let declared_names = || declared.get_or_init(|| datasets.names(platform));
    let suggestion_cell = std::cell::OnceCell::new();
    let suggest = || {
        suggest::closest(
            table,
            declared_names()
                .iter()
                .filter(|d| is_bare_identifier(d))
                .map(String::as_str),
        )
        .map(str::to_string)
        .or_else(|| catalog.suggest_bare_table(table))
    };
    // Looked up once: a name with no suggestion has no near miss either, so the
    // typo check below runs only when there is one.
    let suggestion = || suggestion_cell.get_or_init(suggest).clone();
    // The table within `misspelt_edits` (a match that differs only in case, `_`,
    // `-` or spaces counts), declared first, else in the catalog; bare
    // identifiers only, as for `suggest`.
    let near_miss = || {
        let edits = misspelt_edits(table);
        suggest::closest_within(
            table,
            declared_names()
                .iter()
                .filter(|d| is_bare_identifier(d))
                .map(String::as_str),
            edits,
        )
        .map(str::to_string)
        .or_else(|| catalog.near_bare_table(table, edits))
    };
    // The spec's precedence (visibility::1.0, Query checks): only a name the
    // catalog knows is "not declared"; one it does not know is unknown,
    // opted in or not, at the profile's severity.
    let mut d = match (status, known) {
        (Declaration::Declared, _) | (Declaration::Unchecked, true) => return,
        (Declaration::Undeclared, true) => Diagnostic::warning(
            codes::KQL_TABLE_NOT_DECLARED,
            format!(
                "'{table}' is not a table the workspace declares for {platform} in visibility.toml"
            ),
            range,
        ),
        (status, false) => {
            let opted_in = status == Declaration::Undeclared;
            let help = if opted_in {
                format!("; if the workspace holds it, declare it for {platform} in visibility.toml")
            } else {
                "; if the workspace holds it, declare it in visibility.toml".to_string()
            };
            match catalog.profile {
                // A Sentinel workspace holds tables no catalog lists (custom `_CL`
                // tables, every Azure Monitor connector), so a name missing here is
                // the engine's gap, not a mistake in the query.
                // A near miss of a table the workspace declares or the catalog
                // lists (`misspelt_edits`), and not a custom `_CL` table, is a
                // typo: an error under its own code.
                Dialect::Sentinel => match (!table.ends_with("_CL") && suggestion().is_some())
                    .then(near_miss)
                    .flatten()
                {
                    Some(near) => {
                        out.push(
                            Diagnostic::error(
                                codes::KQL_TABLE_MISSPELT,
                                format!("'{table}' is not a table opentide knows; did you mean '{near}'?"),
                                range,
                            )
                            .with_suggestion(near),
                        );
                        return;
                    }
                    None => Diagnostic::warning(
                        codes::KQL_UNKNOWN_TABLE,
                        format!("'{table}' is not a table opentide knows{help}"),
                        range,
                    ),
                },
                // Advanced hunting is a closed schema: an unknown table is an
                // error, and with declarations its help names them.
                Dialect::Core | Dialect::Defender if opted_in => Diagnostic::error(
                    codes::KQL_UNKNOWN_TABLE,
                    format!("unknown table '{table}'{help}"),
                    range,
                ),
                Dialect::Core | Dialect::Defender => Diagnostic::error(
                    codes::KQL_UNKNOWN_TABLE,
                    format!("unknown table '{table}'"),
                    range,
                ),
            }
        }
    };
    // A table the catalog knows is not misspelt: the fix is to declare it, not
    // to rename it into a declared name.
    if !known && let Some(s) = suggestion() {
        d = d.with_suggestion(s);
    }
    out.push(d);
}

/// The edits within which an unknown Sentinel table is a typo of a known one
/// (`kql_table_misspelt`), by the unknown name's own length: one for a name of
/// up to seven characters (`Sysmon`, a parser function, is two from `Syslog`;
/// `Device` is two from `MADevice`), two for longer ones, and never more than
/// the shared suggestion rule allows ([`suggest::max_edits`]).
fn misspelt_edits(name: &str) -> usize {
    let length = name.chars().count();
    (if length <= 7 { 1 } else { 2 }).min(suggest::max_edits(length))
}

/// Whether `name` is written bare in a KQL query: `[A-Za-z_][A-Za-z0-9_]*`.
/// Other names need the `['…']` quoting, which a suggestion does not add.
fn is_bare_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn overlay_catalog_captures(
    source: &str,
    spans: &mut [(ByteSpan, &'static str)],
    catalog: &Catalog,
) {
    // Once per query, not once per name: a long query has thousands of names,
    // and each scan reads the whole query (quadratic on the old engine).
    let mentioned = catalog.mentioned_tables(source);
    // The names still `variable` after the checks below that may be columns:
    // looked up after the loop, in one pass over the mentioned tables'
    // columns (a set of all those columns per query was a third of a short
    // query's analysis).
    let mut maybe_columns: Vec<(usize, ByteSpan)> = Vec::new();
    for (i, (span, capture)) in spans.iter_mut().enumerate() {
        let end = span.end.min(source.len());
        if span.start >= end {
            continue;
        }
        // The spans are the tree's tokens: char boundaries.
        let Some(text) = source.get(span.start..end) else {
            debug_assert!(false, "{}..{end} in {} bytes", span.start, source.len());
            continue;
        };
        if matches!(text, "dynamic" | "datatable" | "timespan" | "datetime")
            && (*capture == "function" || *capture == "function.builtin" || *capture == "variable")
        {
            *capture = "type";
        } else if (catalog.function(text).is_some() || catalog.plugin(text).is_some())
            && (*capture == "variable" || *capture == "function")
        {
            *capture = "function.builtin";
        } else if (catalog.operator(text).is_some()
            && (*capture == "variable" || *capture == "error"))
            || (catalog.is_join_kind(text) && *capture == "variable")
        {
            *capture = "keyword";
        } else if *capture == "variable" && catalog.scalar_operator(text).is_some() {
            *capture = "operator";
        } else if *capture == "variable" {
            maybe_columns.push((i, *span));
        }
    }
    if maybe_columns.is_empty() {
        return;
    }
    let text = |span: ByteSpan| {
        let text = source.get(span.start..span.end.min(source.len()));
        debug_assert!(text.is_some(), "{span:?} in {} bytes", source.len());
        text.unwrap_or_default()
    };
    let hand_written = catalog.hand_written_column_names();
    let wanted: HashSet<&str> = maybe_columns.iter().map(|&(_, span)| text(span)).collect();
    let mut columns: HashSet<&str> = wanted
        .iter()
        .copied()
        .filter(|name| hand_written.contains(*name))
        .collect();
    for table in &mentioned {
        for column in catalog.columns_for_table(&table.name) {
            if let Some(name) = wanted.get(&*column.name) {
                columns.insert(name);
            }
        }
    }
    for (i, span) in maybe_columns {
        if columns.contains(text(span)) {
            spans[i].1 = "property";
        }
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

pub fn completions(source: &str, offset: usize, profile: Dialect) -> Vec<CompletionItem> {
    // An offset inside a character (a decoded escape) completes nothing.
    let Some(before) = source.get(..offset.min(source.len())) else {
        return Vec::new();
    };
    let workspace = Catalog::for_workspace(profile, source);
    let catalog = &*workspace;
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
    if let Some(op) = last_operator(before)
        && COLUMN_OPERATORS.iter().any(|n| *n == op)
    {
        let mut seen = std::collections::BTreeSet::new();
        let mut items = Vec::new();
        let mentioned = catalog.mentioned_tables(source);
        let rows: Vec<&ColumnRow> = if mentioned.is_empty() {
            // No table named yet: the hand-written columns, not the whole
            // reference.
            catalog
                .columns
                .iter()
                .filter(|c| c.hand_written())
                .collect()
        } else {
            mentioned
                .iter()
                .flat_map(|t| catalog.columns_for_table(&t.name))
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
                    col.name.to_string(),
                    "column",
                    Some(detail),
                    col.docs.as_deref().map(str::to_owned),
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
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .filter(|f| f.deprecated.is_none())
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
            .filter(|o| o.deprecated.is_none())
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
            // `lower` is `chunk` with only ASCII letters changed: the same
            // byte offsets and char boundaries.
            let rest = chunk.get(end..);
            debug_assert!(rest.is_some(), "{end} in {chunk:?}");
            return rest.unwrap_or_default();
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
            Some("token" | "alongside") => {
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

/// Hover at byte `offset` of `source` (an LSP host converts the editor's
/// UTF-16 position once, with `opentide_core::position_to_offset`).
pub fn hover(source: &str, offset: usize, profile: Dialect) -> Option<String> {
    let offset = offset.min(source.len());
    // An offset inside a character (a decoded escape) has nothing to show.
    if !source.is_char_boundary(offset) {
        return None;
    }
    let workspace = Catalog::for_workspace(profile, source);
    let catalog = &*workspace;
    let word = word_at(source, offset)?;
    if let Some(md) = column_hover(source, offset, &workspace) {
        return Some(md);
    }
    if let Some(parser) = catalog.asim_parser(&word) {
        return Some(asim_hover(parser));
    }
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
        if t.declared {
            md.push_str("\n\nColumns declared in visibility.toml.");
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
        if col.declared {
            md.push_str("\n\nDeclared in visibility.toml.");
        }
        if let Some(c) = &col.citation {
            md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
        }
        return Some(md);
    }
    None
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a signature has a handful of parameters, far below u32::MAX"
)]
pub fn signature_help(source: &str, offset: usize, profile: Dialect) -> Option<SignatureHelp> {
    // An offset inside a character (a decoded escape) has nothing to show.
    let before = source.get(..offset.min(source.len()))?;
    let workspace = Catalog::for_workspace(profile, source);
    let catalog = &*workspace;
    if let Some((name, active)) = innermost_call(before)
        && let Some(mut help) = signature_for_name(catalog, &name, active)
    {
        // `f(a=1, b=` is on parameter `b`, wherever it is in the list.
        let current = before
            .rsplit([',', '('])
            .next()
            .unwrap_or_default()
            .trim_start();
        if let Some((arg, _)) = current.split_once('=') {
            let arg = arg.trim();
            if let Some(index) = help.signatures.first().and_then(|s| {
                s.parameters
                    .iter()
                    .position(|p| p.label.split(':').next().map(str::trim) == Some(arg))
            }) {
                help.active_parameter = index as u32;
            }
        }
        return Some(help);
    }
    if let Some(op_name) = last_operator(before)
        && let Some(op) = catalog.operator(&op_name)
        && let Some(sig) = op.signature.clone()
    {
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
    None
}

/// Hover for a column the query reads or defines: its name and type as the
/// pipeline has them at that point, and where it comes from.
fn column_hover(source: &str, offset: usize, catalog: &CatalogRef) -> Option<String> {
    let analysis = diagnose::columns(source, catalog);
    let column = analysis.column_at(offset)?;
    let type_name = column.type_name.as_deref().unwrap_or("unknown type");
    let mut md = format!("**{}** column (`{type_name}`)", column.name);
    match (&column.renamed_from, &column.made_by) {
        (Some(old), Some(by)) => {
            md.push_str(&format!("\n\nRenamed from `{old}` by `{}`.", by.keyword()));
        }
        (None, Some(by)) => md.push_str(&format!("\n\nMade by `{}`.", by.keyword())),
        (_, None) => match &column.origin {
            Some(schema::Origin::Asim { schema, class }) => {
                md.push_str(&format!("\n\n{class} field of the ASIM `{schema}` schema."));
                if let Some(c) = tables::asim().citation(schema) {
                    md.push_str(&format!("\n\n[ASIM {schema} schema]({c})"));
                }
            }
            origin => {
                // The origin table's own row: a column of `union A, B` or of
                // the right side of a `join` is described from its table.
                let row = match origin {
                    Some(schema::Origin::Table(table)) => catalog
                        .columns_for_table(table)
                        .into_iter()
                        .find(|c| *c.table == **table && *c.name == *column.name),
                    _ => None,
                }
                .or_else(|| catalog.resolve_column(source, &column.name));
                if let Some(row) = row {
                    md.push_str(&format!("\n\nOn `{}`.", row.table));
                    if let Some(docs) = &row.docs {
                        md.push_str(&format!(" {docs}"));
                    }
                    if row.declared {
                        md.push_str("\n\nDeclared in visibility.toml.");
                    }
                    if let Some(c) = &row.citation {
                        md.push_str(&format!("\n\n[Microsoft Learn]({c})"));
                    }
                }
            }
        },
    }
    Some(md)
}

fn asim_signature(parser: &tables::AsimParser) -> String {
    let params: Vec<String> = parser
        .params
        .iter()
        .map(|p| match &p.default {
            Some(d) => format!("{}: {} = {d}", p.name, p.type_name),
            None => format!("{}: {}", p.name, p.type_name),
        })
        .collect();
    format!("{}({})", parser.name, params.join(", "))
}

fn asim_hover(parser: &tables::AsimParser) -> String {
    let asim = tables::asim();
    let kind = if parser.unifying {
        "unifying ASIM parser"
    } else {
        "ASIM parser"
    };
    let mut md = format!(
        "**{}** ({kind}, {} schema)\n\n`{}`",
        parser.name,
        parser.schema,
        asim_signature(parser)
    );
    if let Some(columns) = asim.schemas.get(&parser.schema).map(|s| s.columns.len()) {
        md.push_str(&format!(
            "\n\nReturns rows in the ASIM {} schema ({columns} columns).",
            parser.schema
        ));
    }
    if let Some(c) = asim.citation(&parser.schema) {
        md.push_str(&format!("\n\n[ASIM {} schema]({c})", parser.schema));
    }
    md
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a signature has a handful of parameters, far below u32::MAX"
)]
fn signature_for_name(catalog: &Catalog, name: &str, active: u32) -> Option<SignatureHelp> {
    if let Some(parser) = catalog.asim_parser(name) {
        let parameters: Vec<ParameterInformation> = parser
            .params
            .iter()
            .map(|p| ParameterInformation {
                label: match &p.default {
                    Some(d) => format!("{}: {} = {d}", p.name, p.type_name),
                    None => format!("{}: {}", p.name, p.type_name),
                },
                documentation: Some(format!(
                    "Filters the rows the parser returns ({}).",
                    p.type_name
                )),
            })
            .collect();
        let active = active.min(parameters.len().saturating_sub(1) as u32);
        return Some(SignatureHelp {
            signatures: vec![SignatureInformation {
                label: asim_signature(parser),
                documentation: Some(format!(
                    "ASIM parser for the {} schema. Pass filters by name: `{}(starttime=ago(1d))`.",
                    parser.schema, parser.name
                )),
                parameters,
            }],
            active_signature: 0,
            active_parameter: active,
        });
    }
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

#[expect(
    clippy::cast_possible_truncation,
    reason = "a signature has a handful of parameters, far below u32::MAX"
)]
fn active_operator_parameter(before: &str, params: &[ParameterInformation]) -> u32 {
    let lower = before.to_ascii_lowercase();
    if lower.contains(" on ")
        && let Some(index) = params.iter().position(|param| {
            let label = param.label.to_ascii_lowercase();
            label.contains("condition") || label.contains("attribute") || label == "on"
        })
    {
        return index as u32;
    }
    if lower.contains("kind=")
        && let Some(index) = params.iter().position(|param| {
            let label = param.label.to_ascii_lowercase();
            label.contains("kind") || label.contains("flavor")
        })
    {
        return index as u32;
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
    #[expect(
        clippy::string_slice,
        reason = "`i` and `open` index ASCII bytes (name bytes or the `(`): char boundaries"
    )]
    let (name, inside) = (&before[i..name_end], &before[open + 1..]);
    let name = name.to_string();
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
    let (head, rest) = sig.split_once('(').unwrap_or(("", sig));
    // Up to the last `)`, which must come after the `(`.
    let inner = match rest.rsplit_once(')') {
        Some((inner, _)) => inner,
        None if head.contains(')') => return Vec::new(),
        None => rest,
    };
    inner
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && *p != "…")
        .map(|p| ParameterInformation {
            label: p.to_string(),
            documentation: None,
        })
        .collect()
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
        // `start` is at a `!` or a name byte that follows a byte no name
        // holds, and `j` ends a run of ASCII name bytes: char boundaries.
        let word = source.get(start..j);
        debug_assert!(word.is_some(), "{start}..{j} in {} bytes", source.len());
        word.map(str::to_string)
    }
}

/// How many catalogs built from a workspace's declarations each profile
/// keeps: runs of a few workspaces at once (#1142) find theirs instead of
/// rebuilding one another's.
const RECENT_CATALOGS: usize = 4;

/// How many copies with a query's pattern tables each profile keeps: a
/// copy is a whole catalog, and a query that reads another such name makes
/// another one.
const RECENT_QUERY_CATALOGS: usize = 2;

/// The catalogs built most recently, newest first, by what they were built
/// from.
struct Recent<K, V> {
    slots: Vec<(K, V)>,
}

impl<K, V> Default for Recent<K, V> {
    fn default() -> Self {
        Self { slots: Vec::new() }
    }
}

impl<K: PartialEq + Clone> Recent<K, Arc<Catalog>> {
    /// The catalog built from `key`, else `build`'s, kept among the `keep`
    /// most recent. The lock is not held while it builds: a run checking
    /// another workspace meanwhile finds its own. Two runs that build the
    /// same one at once keep the first. The key is copied only to keep it.
    fn get_or_build(
        cache: &Mutex<Self>,
        keep: usize,
        key: &K,
        build: impl FnOnce() -> Catalog,
    ) -> Arc<Catalog> {
        let lock = || {
            cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        if let Some(found) = lock().take(key) {
            return found;
        }
        #[cfg(test)]
        tests::BUILT.with(|built| built.set(built.get() + 1));
        let catalog = Arc::new(build());
        let mut recent = lock();
        if let Some(found) = recent.take(key) {
            return found;
        }
        recent.slots.insert(0, (key.clone(), Arc::clone(&catalog)));
        recent.slots.truncate(keep);
        catalog
    }

    /// The catalog built from `key`, moved to the front.
    fn take(&mut self, key: &K) -> Option<Arc<Catalog>> {
        let at = self.slots.iter().position(|(seen, _)| seen == key)?;
        let slot = self.slots.remove(at);
        let found = Arc::clone(&slot.1);
        self.slots.insert(0, slot);
        Some(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each product's dialect reads that product's declarations, and an
    /// unknown platform (or none) is Sentinel's (ADR 0015 §3).
    #[test]
    fn a_platform_and_its_dialect_map_both_ways() {
        for platform in ["sentinel", "microsoft_defender"] {
            assert_eq!(Dialect::for_platform(platform).platform(), platform);
        }
        assert_eq!(Dialect::for_platform(""), Dialect::Sentinel);
        assert_eq!(Dialect::for_platform("splunk"), Dialect::Sentinel);
        assert_eq!(Dialect::Core.platform(), "sentinel");
    }

    /// A profile's rows share their names with the reference's columns, and
    /// every column of a type shares that type's name (#1071): a row's own
    /// copy would cost an allocation per column again, which the equality
    /// tests, comparing texts, would not see.
    #[test]
    fn the_rows_share_the_reference_names_and_the_type_names() {
        let catalog = Catalog::cached(Dialect::Sentinel);
        let reference = tables::azure_monitor();
        // A table's reference columns are read when asked for (#1767).
        let rows = catalog.columns_for_table("SigninLogs");
        let row = rows
            .iter()
            .find(|c| c.from_reference)
            .expect("a reference column");
        let column = reference[&*row.table]
            .columns
            .iter()
            .flatten()
            .find(|c| c.name == row.name)
            .expect("its reference column");
        assert!(Arc::ptr_eq(&row.name, &column.name), "the name");
        let strings: Vec<&Arc<str>> = rows
            .iter()
            .filter_map(|c| c.type_name.as_ref())
            .filter(|t| &***t == "string")
            .take(2)
            .collect();
        assert!(Arc::ptr_eq(strings[0], strings[1]), "the type");
        assert!(Arc::ptr_eq(strings[0], &tables::kusto_type("string")));
    }

    /// The catalog as `with_profile` built it before the reference's columns were read on demand
    /// (#1767): every column of every table a row of `columns`, from the TOML read item by item
    /// and the reference decoded whole. The oracle the lazy catalog is held to.
    fn eager(profile: Dialect) -> Catalog {
        let mut catalog = Catalog::core();
        catalog.profile = profile;
        let defender: Vec<TableRow> = rows("", defender_tables(), "tables");
        let defender_columns: Vec<ColumnRow> = rows("", defender_columns(), "columns");
        let mut tables = Vec::new();
        let mut columns = Vec::new();
        if profile == Dialect::Sentinel {
            tables.extend(rows::<TableRow>("", sentinel_tables(), "tables"));
            columns.extend(rows::<ColumnRow>("", sentinel_columns(), "columns"));
        }
        for table in defender {
            if !tables.iter().any(|t: &TableRow| t.name == table.name) {
                tables.push(table);
            }
        }
        columns.extend(defender_columns);
        let reference = tables::azure_monitor();
        if profile == Dialect::Sentinel {
            for (name, table) in reference {
                if !tables.iter().any(|t| &t.name == name) {
                    tables.push(TableRow {
                        name: name.clone(),
                        profile: Some("sentinel".into()),
                        category: table.categories.first().cloned(),
                        docs: (!table.docs.is_empty()).then(|| table.docs.clone()),
                        citation: Some(table.citation.to_string()),
                        documented: false,
                        declared: false,
                    });
                }
            }
        }
        let profile_name = match profile {
            Dialect::Defender => "defender",
            _ => "sentinel",
        };
        let profile_shared: Arc<str> = Arc::from(profile_name);
        let mut hand: HashMap<(Arc<str>, Arc<str>), usize> = columns
            .iter()
            .enumerate()
            .map(|(i, c)| ((Arc::clone(&c.table), Arc::clone(&c.name)), i))
            .collect();
        for row in &mut tables {
            let Some(reference) = reference.get(&row.name) else {
                continue;
            };
            let Some(listed) = &reference.columns else {
                continue;
            };
            row.documented = true;
            if row.citation.is_none() {
                row.citation = Some(reference.citation.to_string());
            }
            let table: Arc<str> = Arc::from(row.name.as_str());
            for column in listed {
                if profile == Dialect::Defender
                    && tables::STANDARD_COLUMNS
                        .iter()
                        .any(|(name, _)| *name == &*column.name)
                {
                    continue;
                }
                let key = (Arc::clone(&table), Arc::clone(&column.name));
                if let Some(&i) = hand.get(&key) {
                    if columns[i].type_name.as_deref() != Some(&*column.type_name) {
                        columns[i].type_name = None;
                    }
                    continue;
                }
                hand.insert(key, columns.len());
                columns.push(ColumnRow {
                    table: Arc::clone(&table),
                    profile: Some(Arc::clone(&profile_shared)),
                    name: column.name.clone(),
                    type_name: Some(column.type_name.clone()),
                    docs: column.description.clone(),
                    citation: Some(Arc::clone(&reference.citation)),
                    from_reference: true,
                    declared: false,
                });
            }
        }
        for row in &tables {
            if row.profile.as_deref() == Some("defender")
                && !hand.contains_key(&(Arc::from(row.name.as_str()), Arc::from("Timestamp")))
            {
                let table: Arc<str> = Arc::from(row.name.as_str());
                hand.insert((Arc::clone(&table), Arc::from("Timestamp")), columns.len());
                columns.push(ColumnRow {
                    table,
                    profile: Some(Arc::from("defender")),
                    name: "Timestamp".into(),
                    type_name: Some(tables::kusto_type("datetime")),
                    docs: Some(Arc::from("Event time in advanced hunting.")),
                    citation: row.citation.as_deref().map(Arc::from),
                    from_reference: false,
                    declared: false,
                });
            }
        }
        catalog.lazy = tables
            .iter()
            .map(|_| Lazy {
                at: None,
                rows: OnceLock::from(Vec::new()),
            })
            .collect();
        catalog.tables = tables;
        catalog.hand_len = columns.len();
        catalog.columns = columns;
        catalog.reindex();
        catalog
    }

    /// `apply_declared` as it was before the reference's columns were read on demand: a declared
    /// column is found among all the columns, in the order they were pushed.
    fn declare_eagerly(catalog: &mut Catalog, targets: BTreeMap<String, Vec<&DeclaredSource>>) {
        let profile_name = match catalog.profile {
            Dialect::Defender => "defender",
            _ => "sentinel",
        };
        for (table, sources) in targets {
            let table = table.as_str();
            if sources.iter().all(|s| s.columns.is_empty()) {
                continue;
            }
            match catalog.table_index.get(table) {
                Some(&i) => {
                    let row = &mut catalog.tables[i];
                    row.documented = true;
                    row.declared = true;
                }
                None => {
                    catalog
                        .table_index
                        .insert(table.to_string(), catalog.tables.len());
                    catalog.tables.push(TableRow {
                        name: table.to_string(),
                        profile: Some(profile_name.into()),
                        category: None,
                        docs: sources.iter().find_map(|s| s.description.clone()),
                        citation: None,
                        documented: true,
                        declared: true,
                    });
                    catalog.lazy.push(Lazy {
                        at: None,
                        rows: OnceLock::from(Vec::new()),
                    });
                }
            }
            for column in sources.iter().flat_map(|s| s.columns.iter()) {
                let existing = catalog
                    .column_index
                    .get(&table.to_ascii_lowercase())
                    .and_then(|ids| {
                        ids.iter().copied().find(|&i| {
                            *catalog.columns[i].table == *table
                                && *catalog.columns[i].name == *column.name
                        })
                    });
                match existing {
                    Some(i) if catalog.columns[i].declared => {}
                    Some(i) => {
                        let row = &mut catalog.columns[i];
                        row.type_name = column.type_name.as_deref().map(tables::kusto_type);
                        if let Some(description) = &column.description {
                            row.docs = Some(Arc::from(description.as_str()));
                            row.citation = None;
                        }
                        row.declared = true;
                    }
                    None => {
                        catalog
                            .column_index
                            .entry(table.to_ascii_lowercase())
                            .or_default()
                            .push(catalog.columns.len());
                        catalog.columns.push(ColumnRow {
                            table: Arc::from(table),
                            profile: Some(Arc::from(profile_name)),
                            name: Arc::from(column.name.as_str()),
                            type_name: column.type_name.as_deref().map(tables::kusto_type),
                            docs: column.description.as_deref().map(Arc::from),
                            citation: None,
                            from_reference: false,
                            declared: true,
                        });
                    }
                }
            }
        }
    }

    fn declared(name: &str, columns: &[(&str, Option<&str>, Option<&str>)]) -> DeclaredSource {
        DeclaredSource {
            system: "sentinel".into(),
            name: name.into(),
            description: Some(format!("{name}'s description")),
            columns: columns
                .iter()
                .map(
                    |(column, type_name, description)| opentide_core::datasets::DeclaredColumn {
                        name: (*column).into(),
                        type_name: type_name.map(str::to_owned),
                        description: description.map(str::to_owned),
                    },
                )
                .collect(),
        }
    }

    /// Reading the reference's columns when a table's are first asked for gives, for every table,
    /// the columns the whole reference read up front gave, in the same order: with nothing
    /// declared, and with a workspace's declarations over them (a column the reference lists, one
    /// it does not, one a hand-written row has, a table the reference has no columns of, a table
    /// the workspace invents, a pattern, a column two sources declare).
    #[test]
    fn the_reference_columns_read_on_demand_are_the_ones_read_up_front() {
        let rendered = |rows: Vec<&ColumnRow>| format!("{rows:?}");
        for profile in [Dialect::Sentinel, Dialect::Defender] {
            let lazy = Catalog::core().with_profile(profile);
            let eager = eager(profile);
            assert_eq!(format!("{:?}", lazy.tables), format!("{:?}", eager.tables));
            let least = if profile == Dialect::Sentinel {
                900
            } else {
                50
            };
            assert!(lazy.tables.len() > least, "{profile:?}");
            for table in &lazy.tables {
                assert_eq!(
                    rendered(lazy.columns_for_table(&table.name)),
                    rendered(eager.columns_for_table(&table.name)),
                    "{profile:?}: {}",
                    table.name
                );
            }
            // A name that is no table, in another case.
            assert!(lazy.columns_for_table("nothing").is_empty());
            // What is scanned without a table named is the hand-written ones, each name once, as
            // the completions and the name set read them (the eager catalog also kept a
            // `Timestamp` row per advanced hunting table among them, after the hand-written
            // ones that name it: the same name, found later).
            let hand = |c: &Catalog| {
                let mut seen = HashSet::new();
                c.columns
                    .iter()
                    .filter(|c| c.hand_written() && seen.insert(c.name.clone()))
                    .map(|c| format!("{c:?}"))
                    .collect::<Vec<_>>()
            };
            assert_eq!(hand(&lazy), hand(&eager), "{profile:?}");

            let sources = [
                declared(
                    "SecurityEvent",
                    &[
                        ("IpAddress", Some("string"), Some("redeclared")),
                        ("Account", Some("dynamic"), Some("overridden")),
                        ("Computer", None, None),
                        ("NewCol_CF", Some("long"), Some("new")),
                    ],
                ),
                declared(
                    "SecurityEvent",
                    &[("Account", Some("int"), None), ("Other_CF", None, None)],
                ),
                declared(
                    "DeviceProcessEvents",
                    &[
                        ("Timestamp", Some("string"), None),
                        ("Extra_CF", Some("bool"), None),
                    ],
                ),
                declared(
                    "AzureDiagnostics",
                    &[("ResourceType_s", Some("string"), None)],
                ),
                declared("Contoso_CL", &[("Actor_s", Some("string"), Some("who"))]),
                declared("Sign*Logs", &[("Pattern_CF", Some("string"), None)]),
                declared("Device*Events", &[("Pattern2_CF", None, Some("again"))]),
            ];
            let names = ["Contoso_CL".to_owned(), "SigninLogs".to_owned()];
            // From a catalog nothing has read a table of yet, as production's is when a workspace's
            // declarations are applied to a clone of the cached one: `lazy` above has every table's
            // rows built, which the clone would inherit, and the declarations would never meet a
            // table whose rows are built after them.
            let lazy_declared = Catalog::core()
                .with_profile(profile)
                .with_declared_columns(&sources, &names);
            let mut eager_declared = eager.clone();
            let exact: Vec<&DeclaredSource> =
                sources.iter().filter(|s| !s.name.contains('*')).collect();
            let patterns: Vec<&DeclaredSource> =
                sources.iter().filter(|s| s.name.contains('*')).collect();
            let mut targets: BTreeMap<String, Vec<&DeclaredSource>> = BTreeMap::new();
            for source in exact {
                targets.entry(source.name.clone()).or_default().push(source);
            }
            let known = eager
                .tables
                .iter()
                .map(|t| t.name.as_str())
                .chain(names.iter().map(String::as_str));
            for (table, matched) in declared_targets(&patterns, known) {
                targets.entry(table).or_default().extend(matched);
            }
            declare_eagerly(&mut eager_declared, targets);
            assert_eq!(
                format!("{:?}", lazy_declared.tables),
                format!("{:?}", eager_declared.tables),
                "{profile:?}: tables with declarations"
            );
            for table in &eager_declared.tables {
                assert_eq!(
                    rendered(lazy_declared.columns_for_table(&table.name)),
                    rendered(eager_declared.columns_for_table(&table.name)),
                    "{profile:?}: with declarations: {}",
                    table.name
                );
            }
            assert_eq!(hand(&lazy_declared), hand(&eager_declared), "{profile:?}");
            // The catalog the declarations were applied to is as it was.
            assert_eq!(
                rendered(lazy.columns_for_table("SecurityEvent")),
                rendered(eager.columns_for_table("SecurityEvent"))
            );
        }
    }

    /// A Sentinel analytics rule's limits (#1915): `search *`, `union *` and
    /// a query over 10,000 characters are errors in the rule profile only, and
    /// only under Sentinel; each takes the place of the scope warning at the
    /// same place.
    #[test]
    fn sentinel_rule_profile_limits() {
        let found = |source: &str, dialect: Dialect, profile: Profile| {
            let mut diagnostics = analyze(source, dialect).diagnostics;
            apply_profile(source, dialect, profile, &mut diagnostics);
            diagnostics
                .into_iter()
                .filter(|d| {
                    d.code.starts_with("kql_rule_")
                        || d.code == codes::KQL_UNSCOPED_SEARCH
                        || d.code == codes::KQL_UNSCOPED_UNION
                })
                .map(|d| {
                    let start = opentide_core::position_to_offset(source, d.range.start);
                    let end = opentide_core::position_to_offset(source, d.range.end);
                    (
                        d.code,
                        d.severity,
                        source.get(start..end).unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let error = |code: &str, at: &str| {
            (
                code.to_owned(),
                opentide_core::Severity::Error,
                at.to_owned(),
            )
        };
        let warning = |code: &str, at: &str| {
            (
                code.to_owned(),
                opentide_core::Severity::Warning,
                at.to_owned(),
            )
        };
        let rule = Profile::Rule;
        let sentinel = Dialect::Sentinel;
        assert_eq!(
            found("search * | take 1", sentinel, rule),
            [error(codes::KQL_RULE_SEARCH_STAR, "search")]
        );
        assert_eq!(
            found("search kind=case_sensitive * | take 1", sentinel, rule),
            [error(codes::KQL_RULE_SEARCH_STAR, "search")]
        );
        assert_eq!(
            found("union * | take 1", sentinel, rule),
            [error(codes::KQL_RULE_UNION_STAR, "*")]
        );
        assert_eq!(
            found("union withsource=T * | take 1", sentinel, rule),
            [error(codes::KQL_RULE_UNION_STAR, "*")]
        );
        assert_eq!(
            found("SecurityEvent | union * | take 1", sentinel, rule),
            [error(codes::KQL_RULE_UNION_STAR, "*")]
        );
        // Not `search *` or `union *`: scoped, a pattern, or a term.
        for source in [
            "search in (SecurityEvent) * | take 1",
            "union Sec* | take 1",
            "union SecurityEvent, SigninLogs | take 1",
            "SecurityEvent | where Account == '*' | take 1",
        ] {
            assert!(
                found(source, sentinel, rule)
                    .iter()
                    .all(|(code, _, _)| !code.starts_with("kql_rule_")),
                "{source}"
            );
        }
        // An unscoped search on a term is the warning it was.
        assert_eq!(
            found("search \"x\" | take 1", sentinel, rule),
            [warning(codes::KQL_UNSCOPED_SEARCH, "search")]
        );
        // A search, and a Defender or Core rule, keep the warnings.
        for (dialect, profile) in [
            (sentinel, Profile::Search),
            (Dialect::Defender, rule),
            (Dialect::Core, rule),
        ] {
            assert_eq!(
                found("union * | take 1", dialect, profile),
                [warning(codes::KQL_UNSCOPED_UNION, "*")],
                "{dialect:?} {profile:?}"
            );
        }
        assert_eq!(Profile::default(), Profile::Search);
        // The length: at most 10,000 characters (not bytes), around blanks.
        let at = |n: usize| format!("SecurityEvent | where Account == \"{}\"", "é".repeat(n));
        let base = at(0).chars().count();
        let fits = format!("\n{}\n", at(SENTINEL_RULE_MAX_CHARS - base));
        assert!(rule_findings(&fits, sentinel, rule).is_empty());
        let over = at(SENTINEL_RULE_MAX_CHARS - base + 1);
        let long = rule_findings(&over, sentinel, rule);
        assert_eq!(long.len(), 1, "{long:?}");
        assert_eq!(long[0].code, codes::KQL_RULE_TOO_LONG);
        assert_eq!(long[0].severity, opentide_core::Severity::Error);
        assert!(
            long[0]
                .message
                .starts_with("the query is 10001 characters long")
        );
        assert!(rule_findings(&over, sentinel, Profile::Search).is_empty());
        assert!(rule_findings(&over, Dialect::Defender, rule).is_empty());
    }

    /// Advanced hunting's own functions (#1914): pre-parsed as the file reads item by item,
    /// listed by the Defender dialect only, each with its Learn page's signature.
    #[test]
    fn the_defender_functions_are_the_defender_dialects() {
        let read = rows::<FunctionRow>("defender/", defender_functions_toml(), "functions");
        assert_eq!(format!("{:?}", defender_functions()), format!("{read:?}"));
        let names: Vec<&str> = defender_functions()
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "FileProfile",
                "DeviceFromIP",
                "SeenBy",
                "AssignedIPAddresses"
            ]
        );
        for function in defender_functions() {
            assert_eq!(
                function.profile.as_deref(),
                Some("defender"),
                "{}",
                function.name
            );
            assert_eq!(
                function.kind.as_deref(),
                Some("tabular"),
                "{}",
                function.name
            );
            assert_named_signature(&function.name, function.signature.as_deref());
            assert!(
                function
                    .citation
                    .as_deref()
                    .is_some_and(|c| c.starts_with("https://learn.microsoft.com/defender-xdr/")),
                "{}",
                function.name
            );
        }
        let defender = Catalog::cached(Dialect::Defender);
        let sentinel = Catalog::cached(Dialect::Sentinel);
        let core = Catalog::cached(Dialect::Core);
        for name in names {
            assert!(defender.function(name).is_some(), "{name}");
            assert!(defender.unavailable_function(name).is_none(), "{name}");
            assert!(sentinel.function(name).is_none(), "{name}");
            assert!(sentinel.unavailable_function(name).is_some(), "{name}");
            assert!(core.function(name).is_none(), "{name}");
            assert!(core.unavailable_function(name).is_none(), "{name}");
        }
        // Kusto's names are case-sensitive: another case is not the function.
        assert!(sentinel.unavailable_function("fileprofile").is_none());
        // Kusto's own functions stay in every dialect.
        assert!(core.functions.iter().all(|f| f.profile.is_none()));
        // A catalog moved between dialects carries the new one's functions, once.
        let moved = Catalog::core()
            .with_profile(Dialect::Defender)
            .with_profile(Dialect::Sentinel);
        assert!(moved.function("FileProfile").is_none());
        let twice = Catalog::core()
            .with_profile(Dialect::Defender)
            .with_profile(Dialect::Defender);
        assert_eq!(
            twice
                .functions
                .iter()
                .filter(|f| f.name == "SeenBy")
                .count(),
            1
        );
    }

    /// Under Defender the functions get hover and signature help from their rows; under
    /// Sentinel a call to one is `kql_function_unavailable`, a warning at its name; under Core,
    /// and wherever the query names its own function so, nothing is reported (#1914).
    #[test]
    fn defender_functions_by_dialect() {
        let codes =
            |source: &str, profile: Dialect| -> Vec<(String, opentide_core::Severity, String)> {
                analyze(source, profile)
                    .diagnostics
                    .into_iter()
                    .filter(|d| d.code.starts_with("kql_") && d.code.contains("function"))
                    .map(|d| {
                        let start = opentide_core::position_to_offset(source, d.range.start);
                        let end = opentide_core::position_to_offset(source, d.range.end);
                        (
                            d.code,
                            d.severity,
                            source.get(start..end).unwrap().to_owned(),
                        )
                    })
                    .collect()
            };
        let invoked = "DeviceFileEvents\n| project SHA1\n| invoke FileProfile(SHA1, 500)";
        let sources = [
            (invoked, "FileProfile"),
            (
                "DeviceNetworkEvents | project IP = LocalIP | invoke DeviceFromIP()",
                "DeviceFromIP",
            ),
            ("DeviceInfo | take 10 | invoke SeenBy()", "SeenBy"),
            (
                "AssignedIPAddresses('host-1', ago(1d))",
                "AssignedIPAddresses",
            ),
        ];
        for (source, name) in sources {
            assert_eq!(
                codes(source, Dialect::Sentinel),
                [(
                    codes::KQL_FUNCTION_UNAVAILABLE.to_owned(),
                    opentide_core::Severity::Warning,
                    name.to_owned()
                )],
                "{source}"
            );
            assert!(codes(source, Dialect::Defender).is_empty(), "{source}");
            assert!(codes(source, Dialect::Core).is_empty(), "{source}");
        }
        // The query's own function of that name, and another case, are not reported.
        let own =
            "let FileProfile = (T:(SHA1:string)) { T };\nDeviceFileEvents | invoke FileProfile()";
        assert!(codes(own, Dialect::Sentinel).is_empty());
        // A workspace function declared as a log source, by its exact name, is
        // that function; a pattern (`Device*`, `*`) names tables, not it.
        let declared = |names: &[&str]| {
            let toml = names
                .iter()
                .map(|n| format!("[[logsources]]\nname = \"{n}\"\nsystem = \"sentinel\"\n"))
                .collect::<Vec<_>>()
                .concat();
            opentide_core::datasets::DeclaredDatasets::from_visibility(&toml).unwrap()
        };
        let probe = "DeviceNetworkEvents | project IP = LocalIP | invoke DeviceFromIP()";
        for (names, reported) in [
            (&["DeviceFromIP", "DeviceNetworkEvents"][..], false),
            (&["Device*"][..], true),
            (&["*"][..], true),
        ] {
            let _scope = opentide_core::datasets::scope_thread(Some(declared(names)));
            assert_eq!(
                codes(probe, Dialect::Sentinel)
                    .iter()
                    .any(|(code, _, _)| code == codes::KQL_FUNCTION_UNAVAILABLE),
                reported,
                "{names:?}"
            );
        }
        assert!(
            codes("SecurityEvent | invoke fileprofile()", Dialect::Sentinel)
                .iter()
                .all(|(code, _, _)| code != codes::KQL_FUNCTION_UNAVAILABLE)
        );
        let message = analyze(invoked, Dialect::Sentinel)
            .diagnostics
            .into_iter()
            .find(|d| d.code == codes::KQL_FUNCTION_UNAVAILABLE)
            .map(|d| d.message);
        assert_eq!(
            message.as_deref(),
            Some(
                "'FileProfile' is a Microsoft Defender advanced hunting function, which a \
                 Microsoft Sentinel workspace does not have"
            )
        );
        // Signature help and hover under Defender.
        let at = invoked.find("SHA1, 500").unwrap() + "SHA1, ".len();
        let help = signature_help(invoked, at, Dialect::Defender).unwrap();
        assert_eq!(help.signatures[0].label, "invoke FileProfile(x,y)");
        assert_eq!(help.active_parameter, 1);
        let labels: Vec<&str> = help.signatures[0]
            .parameters
            .iter()
            .map(|p| p.label.as_str())
            .collect();
        assert_eq!(labels, ["x", "y"]);
        let hover_at = invoked.find("FileProfile").unwrap() + 2;
        let text = hover(invoked, hover_at, Dialect::Defender).unwrap();
        assert!(text.contains("enrichment function"), "{text}");
        assert!(
            signature_help(invoked, at, Dialect::Sentinel)
                .is_none_or(|help| help.signatures[0].label != "invoke FileProfile(x,y)")
        );
        // Completion offers them under Defender only.
        let items = completions("DeviceInfo | invoke ", 20, Dialect::Defender);
        assert!(items.iter().any(|i| i.label == "SeenBy"));
        let items = completions("DeviceInfo | invoke ", 20, Dialect::Sentinel);
        assert!(!items.iter().any(|i| i.label == "SeenBy"));
    }

    /// What the build pre-parsed (`build.rs`, #1767) is what reading the TOML files item by item
    /// gives: the core rows and the hand-written rows of each profile.
    #[test]
    fn the_pre_parsed_rows_are_the_rows_read_from_the_toml() {
        fn same<T: std::fmt::Debug>(pre_parsed: &[T], read: &[T], file: &str) {
            assert!(!read.is_empty(), "{file}");
            assert_eq!(format!("{pre_parsed:?}"), format!("{read:?}"), "{file}");
        }
        let (operators, functions, scalar, plugins, types, options) = core_rows();
        same(
            &operators,
            &rows::<OperatorRow>("", operators_toml(), "operators"),
            "operators",
        );
        same(
            &functions,
            &rows::<FunctionRow>("", functions_toml(), "functions"),
            "functions",
        );
        same(
            &scalar,
            &rows::<ScalarOperatorRow>("", scalar_operators_toml(), "scalar_operators"),
            "scalar operators",
        );
        same(
            &plugins,
            &rows::<PluginRow>("", plugins_toml(), "plugins"),
            "plugins",
        );
        same(&types, &rows::<TypeRow>("", types_toml(), "types"), "types");
        same(
            &options,
            &rows::<OperatorOption>("", operator_options(), "options"),
            "options",
        );
        // A profile's hand-written rows, with the types settled against the reference: the
        // rows read from the TOML, put together as `profile_rows` does.
        let reference = tables::azure_monitor();
        for (profile, sentinel, name) in [
            (Dialect::Sentinel, true, "sentinel"),
            (Dialect::Defender, false, "defender"),
        ] {
            let (tables, columns) = rows_model::profile_rows(
                sentinel,
                (
                    rows::<TableRow>("", sentinel_tables(), "tables"),
                    rows::<ColumnRow>("", sentinel_columns(), "columns"),
                ),
                (
                    rows::<TableRow>("", defender_tables(), "tables"),
                    rows::<ColumnRow>("", defender_columns(), "columns"),
                ),
                |table, column| {
                    reference
                        .get(table)?
                        .columns
                        .as_ref()?
                        .iter()
                        .find(|c| &*c.name == column)
                        .map(|c| Arc::clone(&c.type_name))
                },
            );
            let (pre_tables, pre_columns) = hand_written_rows(profile);
            same(&pre_tables, &tables, &format!("{name} tables"));
            same(&pre_columns, &columns, &format!("{name} columns"));
            // A hand-written column the reference types differently has no type.
            assert!(
                columns.iter().any(|c| c.type_name.is_none()),
                "{name}: no column disagrees with the reference"
            );
        }
    }

    /// The core and profile catalogs read item by item are field for field
    /// the whole files (ADR 0013).
    #[test]
    fn the_catalogs_read_item_by_item_are_the_whole_files() {
        fn same<T: std::fmt::Debug>(read: &[T], whole: &[T], file: &str) {
            assert_eq!(format!("{read:?}"), format!("{whole:?}"), "{file}");
        }
        let o: OperatorsFile = toml::from_str(operators_toml()).unwrap();
        same(
            &rows::<OperatorRow>("", operators_toml(), "operators"),
            &o.operators,
            "operators",
        );
        let f: FunctionsFile = toml::from_str(functions_toml()).unwrap();
        same(
            &rows::<FunctionRow>("", functions_toml(), "functions"),
            &f.functions,
            "functions",
        );
        let t: TypesFile = toml::from_str(types_toml()).unwrap();
        same(
            &rows::<TypeRow>("", types_toml(), "types"),
            &t.types,
            "types",
        );
        let so: ScalarOperatorsFile = toml::from_str(scalar_operators_toml()).unwrap();
        same(
            &rows::<ScalarOperatorRow>("", scalar_operators_toml(), "scalar_operators"),
            &so.scalar_operators,
            "operators-scalar",
        );
        let p: PluginsFile = toml::from_str(plugins_toml()).unwrap();
        same(
            &rows::<PluginRow>("", plugins_toml(), "plugins"),
            &p.plugins,
            "plugins",
        );
        let op: OptionsFile = toml::from_str(operator_options()).unwrap();
        same(
            &rows::<OperatorOption>("", operator_options(), "options"),
            &op.options,
            "options",
        );
        for (text, name) in [
            (sentinel_tables(), "sentinel"),
            (defender_tables(), "defender"),
        ] {
            let file: TablesFile = toml::from_str(text).unwrap();
            same(&rows::<TableRow>("", text, "tables"), &file.tables, name);
        }
        for (text, name) in [
            (sentinel_columns(), "sentinel"),
            (defender_columns(), "defender"),
        ] {
            let file: ColumnsFile = toml::from_str(text).unwrap();
            same(&rows::<ColumnRow>("", text, "columns"), &file.columns, name);
        }
    }

    /// Giving a catalog a profile empties what reading it kept: Core's
    /// prepared table names (none) are not the profile's.
    #[test]
    fn a_profile_given_after_a_read_reads_its_own_tables() {
        let core = Catalog::core();
        assert_eq!(core.suggest_table("SecurityEvnt"), None);
        assert!(core.function("strlen").is_some());
        let sentinel = core.with_profile(Dialect::Sentinel);
        assert_eq!(
            sentinel.suggest_table("SecurityEvnt").as_deref(),
            Some("SecurityEvent")
        );
    }

    /// A catalog's name indexes find what a scan of its rows finds, the same
    /// row: for every operator, function, scalar operator and plugin name, in
    /// its case, upper and lower case, and names it does not have (ADR 0014,
    /// rule 2); in a profile's bundled catalog and in a copy, which builds
    /// its own.
    #[test]
    fn the_name_indexes_find_what_a_scan_finds() {
        // The row a scan finds, as its index.
        fn scan<T>(rows: &[T], name_of: impl Fn(&T) -> &String, name: &str) -> Option<usize> {
            rows.iter()
                .position(|row| name_of(row).eq_ignore_ascii_case(name))
        }
        // The row found, as its index in `rows`.
        fn index<T>(rows: &[T], found: Option<&T>) -> Option<usize> {
            found.and_then(|f| rows.iter().position(|r| std::ptr::eq(r, f)))
        }
        for profile in [Dialect::Core, Dialect::Sentinel, Dialect::Defender] {
            let bundled = Catalog::cached(profile);
            let copy = bundled.clone();
            let names: Vec<String> = bundled
                .operators
                .iter()
                .map(|o| o.name.clone())
                .chain(bundled.functions.iter().map(|f| f.name.clone()))
                .chain(bundled.scalar_operators.iter().map(|o| o.name.clone()))
                .chain(bundled.plugins.iter().map(|p| p.name.clone()))
                .chain(["", "nope", "É", "strlÉn", "\u{212a}ind"].map(String::from))
                .collect();
            let mut checked = 0;
            for catalog in [bundled, &copy] {
                for name in &names {
                    for name in [
                        name.clone(),
                        name.to_ascii_uppercase(),
                        name.to_ascii_lowercase(),
                    ] {
                        let c = catalog;
                        assert_eq!(
                            index(&c.functions, c.function(&name)),
                            scan(&c.functions, |f| &f.name, &name),
                            "function {name:?} in {profile:?}"
                        );
                        assert_eq!(
                            index(&c.operators, c.operator(&name)),
                            scan(&c.operators, |o| &o.name, &name),
                            "operator {name:?} in {profile:?}"
                        );
                        assert_eq!(
                            index(&c.scalar_operators, c.scalar_operator(&name)),
                            scan(&c.scalar_operators, |o| &o.name, &name),
                            "scalar operator {name:?} in {profile:?}"
                        );
                        assert_eq!(
                            index(&c.plugins, c.plugin(&name)),
                            scan(&c.plugins, |p| &p.name, &name),
                            "plugin {name:?} in {profile:?}"
                        );
                        checked += 1;
                    }
                }
            }
            assert!(checked > 2_000, "{checked} names in {profile:?}");
        }
    }

    thread_local! {
        /// The catalogs [`Recent::get_or_build`] built on this thread.
        pub(super) static BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// #1142: checks of two workspaces that declare columns, interleaved,
    /// as runs of both at once are: each workspace's catalog is built once
    /// and found after, where one slot per profile rebuilt it every time.
    #[test]
    fn interleaved_workspaces_each_find_their_declared_catalog() {
        let declares = |table: &str| {
            opentide_core::datasets::DeclaredDatasets::from_visibility(&format!(
                "[[logsources]]\nname = \"{table}\"\ndescription = \"x\"\nsystem = \"sentinel\"\n\
                 [logsources.columns]\nField_s = {{ type = \"string\" }}\n"
            ))
            .unwrap()
        };
        let (first, second) = (declares("FirstOne_CL"), declares("SecondOne_CL"));
        let built = || BUILT.with(std::cell::Cell::get);
        let start = built();
        for round in 0..3 {
            for (datasets, table) in [(&first, "FirstOne_CL"), (&second, "SecondOne_CL")] {
                let _scope = opentide_core::datasets::scope_thread(Some(datasets.clone()));
                let catalog = Catalog::for_workspace(Dialect::Sentinel, table);
                assert!(catalog.table(table).is_some(), "{table}, round {round}");
                assert!(
                    catalog
                        .columns_for_table(table)
                        .iter()
                        .any(|column| &*column.name == "Field_s"),
                    "{table}"
                );
            }
        }
        assert_eq!(built() - start, 2, "one build per workspace");
    }

    /// Two workspaces that declare the same pattern with columns, one of
    /// them also naming a table the pattern covers (with no columns of its
    /// own): each gets its own catalog. Keyed on the sources with columns
    /// alone, the second was served the first's, with or without the table.
    #[test]
    fn a_declared_name_without_columns_is_part_of_the_catalog_s_key() {
        let pattern = "[[logsources]]\nname = \"Vendor*_CL\"\ndescription = \"x\"\n\
                       system = \"sentinel\"\n[logsources.columns]\nField_s = { type = \"string\" }\n";
        let named = format!(
            "{pattern}[[logsources]]\nname = \"VendorFoo_CL\"\ndescription = \"x\"\nsystem = \"sentinel\"\n"
        );
        let has_foo = |visibility: &str| {
            let datasets =
                opentide_core::datasets::DeclaredDatasets::from_visibility(visibility).unwrap();
            let _scope = opentide_core::datasets::scope_thread(Some(datasets));
            Catalog::for_workspace(Dialect::Sentinel, "SecurityEvent | take 1")
                .table("VendorFoo_CL")
                .is_some()
        };
        assert!(has_foo(&named));
        assert!(!has_foo(pattern));
        assert!(has_foo(&named));
    }

    #[test]
    fn catalog_loads() {
        let c = Catalog::core().with_profile(Dialect::Sentinel);
        assert!(c.operator("where").is_some());
        assert!(c.function("ago").is_some());
        assert!(c.table("SecurityEvent").is_some());
    }

    #[test]
    fn control_command_is_unsupported() {
        let r = analyze(".show tables", Dialect::Core);
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
        let c = Catalog::cached(Dialect::Core);
        let row = c.function("hll_merge").expect("hll_merge");
        assert_eq!(row.kind.as_deref(), Some("aggregate"));
    }

    #[test]
    fn unknown_operator_is_not_silent() {
        let r = analyze("SecurityEvent | frobnicate x", Dialect::Core);
        assert!(
            r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_UNKNOWN_OPERATOR),
            "{:?}",
            r.diagnostics
        );
    }

    #[test]
    fn a_query_may_start_with_search_or_find() {
        // Valid KQL: `search` was only an operator after a pipe, so a query
        // starting with it was a parse error.
        for query in [
            "search \"mimikatz\"",
            "search in (SecurityEvent, Syslog) Account == \"a\" | take 10",
            "search kind=case_sensitive \"Mimikatz\"",
            "find in (SecurityEvent) where Account == \"a\" | project Account",
        ] {
            let r = analyze(query, Dialect::Sentinel);
            let errors: Vec<_> = r
                .diagnostics
                .iter()
                .filter(|d| d.severity == opentide_core::Severity::Error)
                .collect();
            assert!(errors.is_empty(), "{query}: {errors:?}");
        }
    }

    #[test]
    fn render_is_warning() {
        let r = analyze("SecurityEvent | render table", Dialect::Core);
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
    fn function_parameters_are_not_tables() {
        let src = "let f = (T:(TimeGenerated:datetime), InDeviceId:string) { T | where TimeGenerated > ago(1d) }; f(DeviceInfo, 'x')";
        let r = analyze(src, Dialect::Defender);
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == codes::KQL_UNKNOWN_TABLE),
            "{:?}",
            r.diagnostics
        );
    }

    /// A Sentinel table that is a near miss of a known one is a typo: an error
    /// under `kql_table_misspelt`, which suggests the table.
    #[test]
    fn near_miss_table_is_a_misspelt_error() {
        for (query, want) in [
            ("SecurityEvnt | take 1", "SecurityEvent"),
            ("SigninLog | take 1", "SigninLogs"),
            // Two edits for a name of eight characters or more, and a match that
            // differs only in case counts (zero edits).
            ("SigninLogsXY | take 1", "SigninLogs"),
            ("SIGNINLOGS | take 1", "SigninLogs"),
        ] {
            let r = analyze(query, Dialect::Sentinel);
            let d = r
                .diagnostics
                .iter()
                .find(|d| d.code == codes::KQL_TABLE_MISSPELT)
                .unwrap_or_else(|| panic!("{query}: {:?}", r.diagnostics));
            assert_eq!(d.suggestion.as_deref(), Some(want), "{query}");
            assert_eq!(d.severity, opentide_core::Severity::Error, "{query}");
            assert!(
                d.message.contains(&format!("did you mean '{want}'?")),
                "{}",
                d.message
            );
            // One finding per name, not also the unknown-table warning.
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::KQL_UNKNOWN_TABLE),
                "{query}"
            );
        }
    }

    /// The bound is the typed name's own length: `Sysmon` (a parser function)
    /// is two edits from `Syslog` and `Device` two from `MADevice`, and a
    /// short name takes one edit only, so neither is a typo.
    #[test]
    fn short_names_two_edits_away_are_not_misspelt() {
        for query in ["Sysmon | take 1", "Device | take 1"] {
            let r = analyze(query, Dialect::Sentinel);
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::KQL_TABLE_MISSPELT),
                "{query}: {:?}",
                r.diagnostics
            );
            let d = r
                .diagnostics
                .iter()
                .find(|d| d.code == codes::KQL_UNKNOWN_TABLE)
                .unwrap_or_else(|| panic!("{query}: {:?}", r.diagnostics));
            assert_eq!(d.severity, opentide_core::Severity::Warning, "{query}");
        }
    }

    /// A `let` binding named like a near miss is not a table, and a lower-case
    /// name with no declarations may be a workspace function: no finding.
    #[test]
    fn a_binding_or_lowercase_name_is_not_misspelt() {
        for query in [
            "let SigninLog = SigninLogs;\nSigninLog | take 1",
            "signinlog | take 1",
        ] {
            let r = analyze(query, Dialect::Sentinel);
            assert!(
                !r.diagnostics.iter().any(|d| {
                    d.code == codes::KQL_TABLE_MISSPELT || d.code == codes::KQL_UNKNOWN_TABLE
                }),
                "{query}: {:?}",
                r.diagnostics
            );
        }
    }

    /// Custom `_CL` tables and names three edits away stay the warning: a
    /// workspace holds tables no catalog lists.
    #[test]
    fn far_or_custom_table_stays_an_unknown_warning() {
        // `SigninLogsXYZ` is three insertions from `SigninLogs`.
        for query in ["SigninLogsXYZ | take 1", "SigninLog_CL | take 1"] {
            let r = analyze(query, Dialect::Sentinel);
            let d = r
                .diagnostics
                .iter()
                .find(|d| d.code == codes::KQL_UNKNOWN_TABLE)
                .unwrap_or_else(|| panic!("{query}: {:?}", r.diagnostics));
            assert_eq!(d.severity, opentide_core::Severity::Warning, "{query}");
            assert!(
                !r.diagnostics
                    .iter()
                    .any(|d| d.code == codes::KQL_TABLE_MISSPELT),
                "{query}"
            );
        }
    }

    #[test]
    fn unknown_table_is_a_warning_under_sentinel() {
        for query in [
            "MyCustomLog_CL | take 1",
            "VendorFirewallEvents | take 1",
            "TableNotInAnyCatalog | take 1",
        ] {
            let r = analyze(query, Dialect::Sentinel);
            let tables: Vec<_> = r
                .diagnostics
                .iter()
                .filter(|d| d.code == codes::KQL_UNKNOWN_TABLE)
                .collect();
            assert!(!tables.is_empty(), "{query}");
            for d in tables {
                assert_eq!(d.severity, opentide_core::Severity::Warning, "{query}");
                assert!(
                    d.message.contains("is not a table opentide knows")
                        && d.message.contains("visibility.toml"),
                    "{}",
                    d.message
                );
            }
            assert!(
                r.diagnostics
                    .iter()
                    .all(|d| d.severity != opentide_core::Severity::Error),
                "{query}: {:?}",
                r.diagnostics
            );
        }
    }

    #[test]
    fn unknown_table_stays_an_error_under_defender() {
        // A Log Analytics table is not an advanced hunting table.
        let r = analyze("NTANetAnalytics | take 1", Dialect::Defender);
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::KQL_UNKNOWN_TABLE)
            .expect("table diag");
        assert_eq!(d.severity, opentide_core::Severity::Error);
        assert_eq!(d.message, "unknown table 'NTANetAnalytics'");
    }

    #[test]
    fn sentinel_knows_azure_monitor_defender_xdr_tables_and_asim_parsers() {
        for query in [
            "NTANetAnalytics | take 1",
            "SentinelHealth | take 1",
            "AppServiceConsoleLogs | take 1",
            "SentinelAudit | take 1",
            "DeviceProcessEvents | take 1",
            "AzureDiagnostics | take 1",
            "ASimNetworkSessionLogs | take 1",
            "ASimNetworkSession | take 1",
            "_Im_NetworkSession | take 1",
            "imAuthentication | take 1",
            "_ASim_Dns | take 1",
        ] {
            let r = analyze(query, Dialect::Sentinel);
            assert!(r.diagnostics.is_empty(), "{query}: {:?}", r.diagnostics);
        }
        let c = Catalog::cached(Dialect::Sentinel);
        assert!(c.table("NTANetAnalytics").is_some_and(|t| t.documented));
        assert!(c.table("AzureDiagnostics").is_some_and(|t| !t.documented));
        assert!(c.table("DeviceProcessEvents").is_some_and(|t| t.documented));
        // The hand-written docs survive the merge.
        let docs = c
            .columns_for_table("DeviceProcessEvents")
            .into_iter()
            .find(|col| &*col.name == "DeviceId")
            .and_then(|col| col.docs.clone());
        assert!(docs.is_some());
        let d = Catalog::cached(Dialect::Defender);
        assert!(d.table("DeviceProcessEvents").is_some_and(|t| t.documented));
        assert!(d.table("ExposureGraphNodes").is_some_and(|t| !t.documented));
        assert!(d.asim_parser("_Im_NetworkSession").is_none());
    }

    #[test]
    fn completions_after_pipe() {
        let items = completions("SecurityEvent | ", 16, Dialect::Core);
        assert!(items.iter().any(|i| i.label == "where"));
        assert!(items.iter().any(|i| i.label == "mv-expand"));
        assert!(items.iter().any(|i| i.label == "top"));
    }

    #[test]
    fn highlight_tokens_include_keyword_and_pipe() {
        let r = analyze("SecurityEvent | take 1", Dialect::Core);
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
            let r = analyze(src, Dialect::Core);
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
        let h = hover("SecurityEvent | where EventID == 1", 16, Dialect::Core);
        assert!(h.unwrap().contains("where"));
    }

    #[test]
    fn engine_has_no_sql() {
        assert!(opentide_core::LanguageId::parse("sql").is_none());
    }

    #[test]
    fn catalog_covers_hunting_surface() {
        let c = Catalog::core().with_profile(Dialect::Sentinel);
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
        let r = analyze(src, Dialect::Core);
        let slice = |t: &opentide_highlight::HighlightToken| {
            src.get(t.span.start..t.span.end).unwrap().to_string()
        };
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
        let h = hover(src, 24, Dialect::Sentinel).expect("EventID hover");
        assert!(h.contains("EventID"), "{h}");
        assert!(h.contains("SecurityEvent"), "{h}");
        let table = hover(src, 0, Dialect::Sentinel).expect("table hover");
        assert!(
            table.contains("EventID") || table.contains("Columns"),
            "{table}"
        );
        let where_off = src.find("where ").unwrap() + 6;
        let items = completions(src, where_off, Dialect::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "EventID"),
            "{:?}",
            items.iter().map(|i| &i.label).take(20).collect::<Vec<_>>()
        );
        assert!(items.iter().any(|i| i.label == "TimeGenerated"));
        let r = analyze(src, Dialect::Sentinel);
        assert!(
            r.tokens.iter().any(|t| t.capture == "property"
                && src.get(t.span.start..t.span.end).unwrap() == "EventID"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (
                    t.capture.as_str(),
                    src.get(t.span.start..t.span.end).unwrap()
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn join_kind_signature_and_highlight() {
        let src = "SecurityEvent | join kind=inner SecurityAlert on EventID";
        let r = analyze(src, Dialect::Sentinel);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "keyword"
                    && src.get(t.span.start..t.span.end).unwrap() == "inner"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (
                    t.capture.as_str(),
                    src.get(t.span.start..t.span.end).unwrap()
                ))
                .collect::<Vec<_>>()
        );
        let eq = src.find("kind=").unwrap() + 5;
        let items = completions(src, eq, Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "leftouter"), "{items:?}");
        let help = signature_help(src, src.find("join ").unwrap() + 5, Dialect::Sentinel)
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
        let help = signature_help(ago, ago.find("ago(").unwrap() + 4, Dialect::Sentinel)
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
        let items = completions(render, render.len(), Dialect::Sentinel);
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
        let items = completions(series, series.len(), Dialect::Sentinel);
        for keyword in ["on", "from", "to", "step", "by", "default"] {
            assert!(
                items.iter().any(|i| i.label == keyword),
                "make-series missing {keyword}: {:?}",
                items.iter().map(|i| &i.label).collect::<Vec<_>>()
            );
        }

        let union = "StormEvents | union ";
        let items = completions(union, union.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "withsource="), "{items:?}");
        assert!(items.iter().any(|i| i.label == "isfuzzy="), "{items:?}");

        let search = "search ";
        let items = completions(search, search.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "kind="), "{items:?}");
        assert!(items.iter().any(|i| i.label == "in"), "{items:?}");

        let parse = "StormEvents | parse ";
        let items = completions(parse, parse.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "flags="), "{items:?}");

        let expand = "StormEvents | mv-expand ";
        let items = completions(expand, expand.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "kind="), "{items:?}");
        let kind = "StormEvents | mv-expand kind=";
        let items = completions(kind, kind.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "bag"), "{items:?}");
        assert!(items.iter().any(|i| i.label == "array"), "{items:?}");

        let join_prefix = "StormEvents | join ";
        let items = completions(join_prefix, join_prefix.len(), Dialect::Sentinel);
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
        let items = completions(named, named.len(), Dialect::Sentinel);
        assert!(
            items.iter().any(|i| i.label == "replace_source"),
            "named columnsConflict= should complete: {items:?}"
        );

        let join = "StormEvents | join kind=";
        let items = completions(join, join.len(), Dialect::Sentinel);
        assert!(items.iter().any(|i| i.label == "leftantisemi"), "{items:?}");
        assert!(
            items.iter().any(|i| i.label == "rightantisemi"),
            "{items:?}"
        );

        let unpack = "StormEvents | evaluate bag_unpack(Parsed, \"pre\", ";
        let items = completions(unpack, unpack.len(), Dialect::Sentinel);
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
        let r = analyze(src, Dialect::Core);
        assert!(
            r.tokens
                .iter()
                .any(|t| t.capture == "type"
                    && src.get(t.span.start..t.span.end).unwrap() == "dynamic"),
            "{:?}",
            r.tokens
                .iter()
                .map(|t| (
                    t.capture.as_str(),
                    src.get(t.span.start..t.span.end).unwrap()
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn compile_exclusions_are_tenant_scoped() {
        let compiled = compile_kql_query(
            "DeviceEvents | take 1",
            &[
                Exclusion {
                    tenant: Some("tenant-a".into()),
                    query: "| where Computer != \"MINE_TAIL\"".into(),
                    lets: vec![
                        ("flag".into(), LetValue::Bool(false)),
                        ("n".into(), LetValue::Number("7".into())),
                    ],
                },
                Exclusion {
                    tenant: Some("other".into()),
                    query: "| where Computer != \"FOREIGN_TAIL\"".into(),
                    lets: vec![
                        ("keep".into(), LetValue::Bool(true)),
                        ("n".into(), LetValue::Number("3".into())),
                    ],
                },
                Exclusion {
                    tenant: None,
                    query: "| where 1 == 1".into(),
                    lets: vec![("shared".into(), LetValue::String("ok".into()))],
                },
            ],
            "tenant-a",
        );
        assert!(compiled.contains("let flag = false;"));
        assert!(compiled.contains("let n = 7;"));
        assert!(compiled.contains("let shared = \"ok\";"));
        assert!(!compiled.contains("FOREIGN_TAIL"), "{compiled}");
        assert!(!compiled.contains("let keep"), "{compiled}");
        assert!(!compiled.contains("let n = 3"), "{compiled}");
        let base = compiled.find("DeviceEvents | take 1").expect("base query");
        let mine = compiled.find("MINE_TAIL").expect("matching tail");
        let shared_tail = compiled.find("| where 1 == 1").expect("global tail");
        assert!(base < mine && mine < shared_tail, "{compiled}");
    }

    #[test]
    fn operator_signature_tracks_kind_and_on() {
        let kind = "SecurityEvent | join kind=";
        let help = signature_help(kind, kind.len(), Dialect::Sentinel).expect("join kind");
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label,
            "JoinFlavor"
        );

        let on_clause = "SecurityEvent | join kind=inner AlertInfo on ";
        let help = signature_help(on_clause, on_clause.len(), Dialect::Sentinel).expect("join on");
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label, "Conditions",
            "a later `on` wins over an earlier kind=: {:?}",
            help.signatures[0].parameters
        );

        let union = "SecurityEvent | union kind=";
        let help = signature_help(union, union.len(), Dialect::Sentinel).expect("union kind");
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label,
            "kind"
        );
    }

    #[test]
    fn nested_call_commas_stay_inside_the_inner_signature() {
        let outer = "T | evaluate bag_unpack(Parsed, strcat(\"a\", \"b\"), ";
        let help = signature_help(outer, outer.len(), Dialect::Sentinel).expect("bag_unpack");
        assert!(
            help.signatures[0].label.starts_with("bag_unpack("),
            "{}",
            help.signatures[0].label
        );
        assert_eq!(
            help.signatures[0].parameters[help.active_parameter as usize].label, "columnsConflict",
            "the comma inside strcat must not advance bag_unpack: {:?}",
            help.signatures[0].parameters
        );

        let inner = "T | evaluate bag_unpack(Parsed, strcat(\"a\", ";
        let help = signature_help(inner, inner.len(), Dialect::Sentinel).expect("strcat");
        assert!(
            help.signatures[0].label.starts_with("strcat("),
            "{}",
            help.signatures[0].label
        );
    }

    #[test]
    fn an_offset_inside_a_character_is_answered_empty() {
        // A cursor inside a decoded escape (`\u00e9` in a double-quoted Tide
        // query) can reach the engine as the second byte of `\u{e9}`.
        let src = "T | where A == \"\u{e9}\" | project B";
        let inside = src.find('\u{e9}').unwrap() + 1;
        assert!(completions(src, inside, Dialect::Sentinel).is_empty());
        assert_eq!(hover(src, inside, Dialect::Sentinel), None);
        assert!(signature_help(src, inside, Dialect::Sentinel).is_none());
    }

    /// Queries with multi-byte text in every place the engine cuts: names
    /// and quoted names, hyphenated words, strings, typed literals, calls,
    /// operator options, comments and leading blanks. The tree's spans are
    /// checked in debug builds (`syntax_util::slice`).
    const MULTI_BYTE: &[&str] = &[
        "SecurityEvent | where Account has \"é😀\" | project é😀 = Account, ['é 😀'] = 1",
        "DeviceEvents | where é😀 !has 'x' and ActionType in~ ('é', \"😀\") | summarize count() by é",
        "let é = 1; T | extend x = strcat(\"é\", '😀', é) | project-away é* | parse-kv Text as (é: string)",
        "T | where x == datetime(2024-01-01) | extend d = dynamic({\"é\": \"😀\"}), t = timespan(1d) | join kind=inner (é😀) on é",
        "search \"é😀\" | take 1 // é😀 commentaire",
        "T | where ago(1d) > é😀(1, \"é\", ",
        "  é\n😀 | take 1",
        "T | sort by é😀 desc | top 3 by é asc | facet by é with (take 1)",
        "T | extend a = pro-é😀, b = é-😀, c = é😀-x | union é😀, (T | where é😀 == 1)",
        "é😀 | where é😀 > 1 | summarize arg_max(é, *) by bin(é😀, 1h) | order by é",
    ];

    #[test]
    fn multi_byte_text_is_read_whole_everywhere() {
        for query in MULTI_BYTE {
            for dialect in [Dialect::Core, Dialect::Sentinel, Dialect::Defender] {
                let result = analyze(query, dialect);
                for token in &result.tokens {
                    assert!(
                        query.get(token.span.start..token.span.end).is_some(),
                        "{query}"
                    );
                }
                let _ = columns(query, dialect);
                for (offset, _) in query.char_indices().chain([(query.len(), ' ')]) {
                    let _ = hover(query, offset, dialect);
                    let _ = completions(query, offset, dialect);
                    let _ = signature_help(query, offset, dialect);
                }
            }
            let _ = rule_findings(query, Dialect::Sentinel, Profile::Rule);
        }
    }

    #[test]
    fn helpers_read_multi_byte_text() {
        let source = "é😀 abc-d é";
        let at = source.find('b').unwrap();
        assert_eq!(word_at(source, at).as_deref(), Some("abc-d"));
        assert_eq!(word_at(source, 0), None);
        assert_eq!(word_at(source, source.len()), None);
        assert_eq!(word_at("aé", 1), None);
        assert_eq!(word_at("éa", "é".len()).as_deref(), Some("a"));
        assert_eq!(word_at("é!has", "é".len() + 1).as_deref(), Some("!has"));
        assert_eq!(
            innermost_call("T | extend x = strcat(\"é\", '😀', "),
            Some(("strcat".to_owned(), 2))
        );
        assert_eq!(innermost_call("é😀(é"), None);
        let labels = |sig: &str| -> Vec<String> {
            parameters_from_signature(sig)
                .into_iter()
                .map(|p| p.label)
                .collect()
        };
        assert_eq!(labels("f(é, 😀)"), ["é", "😀"]);
        assert_eq!(labels("f(é"), ["é"]);
        assert_eq!(labels("é, 😀"), ["é", "😀"]);
        assert!(labels(")é(x").is_empty());
        assert!(labels("é()").is_empty());
        assert_eq!(text_after_operator("T | where é😀", "where"), " é😀");
        assert_eq!(text_after_operator("T | wheré", "where"), "");
        assert_eq!(text_after_operator("T | WHERE é", "where"), " é");
        // The rule's length is counted in characters; the finding starts at
        // the first non-blank character, however wide the blanks before it.
        let long = format!(
            "\u{3000} é{}\n| take 1",
            "😀".repeat(SENTINEL_RULE_MAX_CHARS)
        );
        let found = rule_findings(&long, Dialect::Sentinel, Profile::Rule);
        let too_long = found
            .iter()
            .find(|d| d.code == codes::KQL_RULE_TOO_LONG)
            .unwrap();
        assert_eq!(too_long.range.start, opentide_core::Position::new(0, 2));
    }
}
