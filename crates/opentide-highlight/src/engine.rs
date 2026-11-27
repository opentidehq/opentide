//! The interface every query-language engine implements (#1953).
//!
//! Each of the twelve query crates (`opentide-kql` … `opentide-datadog`)
//! implements [`QueryEngine`] on a struct of its own; the registry that maps
//! a [`LanguageId`] to its engine is defined in `opentide_tide::engines`, the
//! lowest crate that depends on all of them, and read as
//! `opentide_analysis::engines`. The trait lives here, beside
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

/// The use of a query within one product (ADR 0015 §1), chosen by where the
/// text sits and never by the platform. Each engine maps it onto its own
/// profile; an engine whose language has none ignores it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A file of the language on its own (a `.kql` or a `.yaral` file), or
    /// a query checked without a Tide object: the profile the language's
    /// specification gives a file.
    #[default]
    File,
    /// A search run by hand: a hunt's `response.procedure.searches[].query`.
    Search,
    /// A detection rule: the query of a `configurations.<platform>` block.
    Rule,
}

/// What a query is checked under besides its language (ADR 0015 §1): the
/// platform that names its dialect, its [`Profile`], and the Elastic stack
/// it runs on. The default is a file of the language with no platform.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Setting<'a> {
    /// The platform, as a `configurations` key or a hunt's `system`
    /// (`microsoft_defender`, `carbon_black_cloud`, `harfanglab`), or empty
    /// for none. It selects the dialect only (KQL, Lucene, YARA).
    pub platform: &'a str,
    /// Where the text sits.
    pub profile: Profile,
    /// The Elastic stack an ES|QL query runs on (`9.1`, `serverless`), as
    /// `opentide_esql::StackTarget::parse` reads it; `None` checks it
    /// against the newest tracked line. Other languages ignore it.
    pub stack: Option<&'a str>,
}

/// One query language's engine.
///
/// `Sync` so that a registry can hold the engines in a `static`.
pub trait QueryEngine: Sync {
    /// The language this engine reads.
    fn language(&self) -> LanguageId;

    /// Analyzes `source` under `setting`: the dialect its platform names,
    /// its profile and its stack. What only a Tide object supplies (ECS
    /// indices, a Falco block's macros and lists, an EQL rule's schedule, a
    /// Google SecOps rule's assembled sections) stays with the caller.
    fn analyze_for(&self, source: &str, setting: &Setting<'_>) -> AnalyzeResult;

    /// Analyzes `source` as a file of the language on its own: the
    /// language's default dialect and profile, with no workspace context.
    fn analyze(&self, source: &str) -> AnalyzeResult {
        self.analyze_for(source, &Setting::default())
    }
}
