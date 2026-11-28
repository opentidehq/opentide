//! The data model of the Falco catalogs (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the three catalog files once and stores them pre-parsed: this file depends on `serde`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

/// One event source (`syscall`, `k8s_audit`, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub plugin: String,
    pub description: String,
}

/// What a field holds, for operator and value checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    String,
    Number,
    Bool,
    Ip,
    Other,
}

/// Whether a field takes an argument (`EPF_ARG_REQUIRED`, `EPF_ARG_ALLOWED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgRule {
    None,
    Allowed,
    Required,
}

/// One Falco field, with libsinsp's type name (`CHARBUF`, `UINT64`, `IPNET`)
/// and flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the catalog's columns: one flag per libsinsp EPF_* field flag"
)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    /// `EPF_IS_LIST`: the field extracts several values.
    pub list: bool,
    pub kind: Kind,
    /// libsinsp filter check class (`gen_event`, `thread`, ...) or plugin name.
    pub class: String,
    /// `libsinsp` or `plugin`.
    pub origin: String,
    /// Event sources the field applies to; `*` is every source.
    pub sources: Vec<String>,
    pub arg: ArgRule,
    /// `EPF_ARG_INDEX`: the argument may be a number.
    pub arg_index: bool,
    /// `EPF_ARG_KEY`: the argument may be a string.
    pub arg_key: bool,
    /// `EPF_NO_RHS`: no right-hand side field, and never one itself.
    pub no_rhs: bool,
    /// `EPF_NO_TRANSFORMER`.
    pub no_transformer: bool,
    /// `EPF_FILTER_ONLY`: not in output.
    pub filter_only: bool,
    /// `EPF_PRINT_ONLY`.
    pub print_only: bool,
    /// libsinsp's `EPF_DEPRECATED`, or deprecated by Falco's rule loader.
    pub deprecated: bool,
    /// The values libsinsp extracts, for an enumerated field (`fd.type`).
    #[serde(default)]
    pub values: Vec<String>,
    pub description: String,
}

/// A macro of the Falco default rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Macro {
    pub name: String,
    pub condition: String,
    pub source: String,
    /// The first default rules file that defines it: stable, then incubating,
    /// then sandbox.
    pub origin: String,
    /// Differing definitions in later files (`<file>: <condition>`).
    #[serde(default)]
    pub also: Vec<String>,
}

/// A list of the Falco default rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct List {
    pub name: String,
    pub items: Vec<String>,
    /// The first default rules file that defines it (see [`Macro::origin`]).
    pub origin: String,
    /// Differing definitions in later files (`<file>: [<items>]`).
    #[serde(default)]
    pub also: Vec<String>,
}

/// A rule of the Falco default rules: what a tuning (`append_to_rule`) extends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub condition: String,
    pub source: String,
    pub origin: String,
}

/// One event of the driver's event table: its category and its codes
/// (the enter and exit events, `PPME_*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub name: String,
    pub kind: String,
    pub codes: Vec<String>,
}

/// An event argument (`evt.arg.<name>`, `evt.rawarg.<name>`) and its type, as
/// libsinsp's longest-match lookup first finds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}
