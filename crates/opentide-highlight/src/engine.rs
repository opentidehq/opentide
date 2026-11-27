//! The interface every query-language engine implements (#1953).
//!
//! Each of the twelve query crates (`opentide-kql` … `opentide-datadog`)
//! implements [`QueryEngine`] on a struct of its own; the registry that maps
//! a [`LanguageId`] to its engine is `opentide_tide::engines`, the lowest
//! crate that depends on all of them. The trait lives here, beside
//! [`HighlightToken`], because an analysis is diagnostics and highlight
//! tokens and every query crate already builds on this crate.

use opentide_core::{Diagnostic, LanguageId};

use crate::HighlightToken;

/// What a query engine finds in one query: its diagnostics, parse error
/// included, and its highlight tokens (HighlightSpec captures).
#[derive(Debug, Clone, Default)]
pub struct AnalyzeResult {
    /// The query's diagnostics.
    pub diagnostics: Vec<Diagnostic>,
    /// The query's highlight tokens, in document order.
    pub tokens: Vec<HighlightToken>,
}

/// One query language's engine.
///
/// `Sync` so that a registry can hold the engines in a `static`.
pub trait QueryEngine: Sync {
    /// The language this engine reads.
    fn language(&self) -> LanguageId;

    /// Analyzes `source` as a file of the language on its own: the
    /// language's default profile, with no platform or workspace context.
    fn analyze(&self, source: &str) -> AnalyzeResult;
}
