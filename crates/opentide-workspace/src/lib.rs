//! Loading a Tide workspace once, in parallel, into the index the CLI, the
//! SDK, `serve`, MCP and the language server share (plan §4,
//! `opentide-workspace`; UC-2.1, #816).
//!
//! - [`root`]: where the workspace is (`--repo`, `OPENTIDE_REPO_ROOT`, the
//!   working directory, `.opentide/` or `objects/`, the git top level).
//! - [`config`]: the configuration, resolved once
//!   (`opentide_schema::configuration`) and shared immutably.
//! - [`discover`]: which files are objects (direct children of the
//!   `paths.toml` folders, `.yaml` and `.yml`, debug output left out; files in
//!   subfolders are listed as nested, #615).
//! - [`load`]: one file, read once and parsed once as YAML 1.2.
//! - [`index`]: objects by family and UUID, duplicates, load errors,
//!   references, signals and chaining.
//! - [`Workspace`]: the whole, with [`Workspace::invalidate`] for the hosts
//!   that keep it between runs; [`Registry`], the SDK's lifecycle;
//!   [`session`], workspaces kept warm between `serve`'s runs.
//!
//! - [`validate`]: every check of `opentide validate`, reported as
//!   [`Diagnostic`]s, the one finding type of the CLI, the SDK, MCP and the
//!   language server (UC-2.2).
//!
//! Every read goes through a [`FileSystem`]: [`OsFs`] on disk,
//! [`MemoryFs`] in memory. [`Stats`] counts the reads, parses and
//! configuration resolutions.
//!
//! Internal to opentide, with no stability promise: depend on the
//! [`opentide`](https://docs.rs/opentide) crate, its Rust SDK, instead.

pub mod catalogue;
pub mod config;
pub mod coverage;
pub mod diagnostic;
pub mod discover;
mod export;
pub mod fields;
pub mod fix;
pub mod fs;
pub mod index;
pub mod info;
pub mod lint;
pub mod load;
pub mod registry;
pub mod review;
pub mod root;
pub mod session;
pub mod state;
pub mod validate;
pub mod vocabularies;
pub mod watch;
mod workspace;

pub use config::{ConfigError, Configuration};
pub use diagnostic::{Diagnostic, Fix, Severity, TextEdit};
pub use fs::{FileSystem, MemoryFs, OsFs, Stamp, WriteError, WriteFs};
pub use index::{Index, Object};
pub use registry::Registry;
pub use root::RootOptions;
pub use session::{Session, SessionStats};
pub use workspace::{Change, ChangeKind, Invalidation, OpenError, Options, Stats, Workspace};
