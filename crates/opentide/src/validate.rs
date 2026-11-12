//! `opentide validate`'s checks and report: what
//! [`Workspace::validate`](crate::Workspace::validate) returns.
//!
//! Findings are [`Diagnostic`](crate::Diagnostic)s, the one finding type of
//! the command line, the SDKs, MCP and the language server, serialised as an
//! issue of `validate --json`.

pub use opentide_workspace::validate::{
    Check, PlatformConfigurations, PlatformFinding, QueriesMode, Report, STRICT_EXEMPT_WARNINGS,
    Stats, Summary, VALIDATION_CODES, Validation,
};
