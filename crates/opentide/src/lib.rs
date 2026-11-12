//! # opentide
//!
//! The Rust SDK of [opentide](https://opentide.org), spec-driven development
//! for agentic detection engineering: open a Tide workspace (threat vectors,
//! detection objectives and detection rules as YAML, with their
//! configuration), validate and lint it, read its catalogue and its ATT&CK
//! coverage, plan a deploy to the nine platforms opentide deploys to, and run
//! the `opentide` command line.
//!
//! This crate is opentide's public Rust API, and the only opentide crate with
//! a stability promise (below). The Python package and the npm packages wrap
//! it; the `opentide-*` crates it builds on are internal.
//!
//! ```
//! use opentide::validate::QueriesMode;
//!
//! let ws = opentide::Workspace::from_files(
//!     "/ws",
//!     [(
//!         "objects/rules/example.yaml",
//!         "name: Example\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n",
//!     )],
//! )?;
//! let validation = ws.validate(&opentide::ValidateOptions::default().queries(QueriesMode::Off));
//! for diagnostic in validation.report.issues.iter().chain(&validation.report.warnings) {
//!     println!("{}: {}", diagnostic.code, diagnostic.message);
//! }
//! # Ok::<(), opentide::Error>(())
//! ```
//!
//! On disk, [`Workspace::open`] takes the repository's folder. The examples
//! (`cargo run -p opentide --example validate -- <workspace>`, `catalog`,
//! `deploy_plan`) and the Rust page of the SDK documentation
//! (`docs/sdk/rust.md`) walk through the rest.
//!
//! ## Features
//!
//! | Feature | Default | What it adds |
//! |---------|:-------:|--------------|
//! | `schema` | yes | [`models`]: the Tide models, every revision, schema identifiers |
//! | `workspace` | yes | [`Workspace`]: open, [`Workspace::validate`], [`Workspace::lint`], [`Workspace::info`], [`Workspace::catalog`], [`Workspace::coverage`] |
//! | `compile` | yes | [`Workspace::deploy_plan`] and [`deploy`] |
//! | `queries` | no | The offline query engines (KQL, SPL, ES\|QL, EQL, Kibana KQL, Lucene, Falco, CQL) behind validate's and lint's queries checks |
//! | `cli` | no | `cli::main(argv)`, `cli::run_json(argv)` and the `opentide` binary (`cargo install opentide --features cli`); implies `compile` and `queries` |
//! | `lsp` | no | `lsp`: the language server, on stdio or one message at a time |
//! | `connectors` | no | [`connectors`]: the tenants a workspace configures ([`Workspace::tenants`]), and on each a query run, a live query check and a rule deploy (async, on tokio); implies `compile` |
//!
//! Without `queries`, a queries check is never skipped: validate reports one
//! `engine_unavailable` error and lint fails with that code, as the Python
//! package does when its engine does not load ([`queries`]). Turn the check
//! off ([`validate::QueriesMode::Off`]) to validate without it.
//!
//! With `connectors`, a [`connectors::Connection`] reaches one of the
//! workspace's tenants ([`Workspace::tenants`]): it runs a query, checks one
//! live and deploys a compiled rule, as `opentide query`,
//! `opentide validate query --live` and `opentide deploy` do. Its operations
//! are `async`, on tokio; [`connectors::block_on`] runs one from synchronous
//! code. A `wasm32` build takes the default features.
//!
//! ## Errors
//!
//! Every fallible operation returns [`Error`], a `#[non_exhaustive]` enum
//! whose variants each map to a stable code ([`Error::code`]). Findings
//! about the workspace are not errors: they are [`Diagnostic`]s in a report,
//! each with its code, severity and place (1-based lines, columns in Unicode
//! code points, `end_column` exclusive).
//!
//! ## Stability
//!
//! This crate follows [semantic versioning](https://semver.org) as Cargo reads
//! it: while it is `0.x`, a release that breaks the API raises the minor
//! version (0.12 to 0.13) and a patch release never does. Every item this
//! crate exports is covered, re-exported types included; the `opentide-*`
//! crates are not, and their APIs change with the engine.
//! `cargo semver-checks` runs on this crate in CI. The `connectors` feature
//! re-exports `jiff::Timestamp` ([`connectors::Timestamp`], the time of a
//! query's window): a jiff release that breaks it is a breaking release here. Structs that may gain a
//! field and enums that may gain a variant are `#[non_exhaustive]`. The
//! JSON documents ([`Document`], [`cli::run_json`] when built) follow the
//! command line's contract (`docs/cli/json-output.md`), which only grows.
//! The minimum supported Rust version is the `rust-version` of the
//! manifest; raising it is a minor release.

// The crate's page links the items of every feature; a build without `cli`
// and `connectors` (which imply every feature linked here) lacks some of them. docs.rs and
// CI's facade job document every feature, with broken links denied. An
// `allow`, not an `expect`: rustc does not run rustdoc's lints, so an
// expectation would be unfulfilled in every build but rustdoc's.
#![cfg_attr(
    not(all(feature = "cli", feature = "connectors")),
    allow(
        rustdoc::broken_intra_doc_links,
        reason = "links to the items of features this build leaves out"
    )
)]

pub mod document;
pub mod error;

#[cfg(feature = "schema")]
pub mod models;

#[cfg(feature = "workspace")]
pub mod catalog;
#[cfg(feature = "workspace")]
pub mod lint;
#[cfg(feature = "workspace")]
pub mod queries;
#[cfg(feature = "workspace")]
pub mod validate;
#[cfg(feature = "workspace")]
mod workspace;

#[cfg(feature = "compile")]
pub mod deploy;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "lsp")]
pub mod lsp;

#[cfg(feature = "connectors")]
pub mod connectors;

pub use document::Document;
pub use error::Error;

#[cfg(feature = "workspace")]
pub use opentide_workspace::{Diagnostic, Fix, Severity, TextEdit};
#[cfg(feature = "workspace")]
pub use validate::{Report, Validation};
#[cfg(feature = "workspace")]
pub use workspace::{Counts, Info, LintOptions, Options, ValidateOptions, Workspace};

#[cfg(feature = "compile")]
pub use deploy::{DeployPlan, DeployPlanOptions, Strategy};

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The Rust page of the SDK documentation, whose samples run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../../../docs/sdk/rust.md")]
pub struct RustSdkPage;

/// The crate's README, whose sample runs as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct Readme;
