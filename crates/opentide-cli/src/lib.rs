//! The opentide command line (plan D-3, ADR 0003): one `main(argv)` for the
//! standalone binary and the Python and npm launchers.
//!
//! This crate is the framework every command runs on (UC-3.3, #825): the
//! command tree in clap ([`tree`]), `opentide --json commands` generated from
//! it ([`catalog`]), the output modes ([`mode`]), global-flag hoisting
//! ([`hoist`]), the JSON envelope and exit codes ([`envelope`]), usage errors
//! and "did you mean" ([`usage`], [`suggest`]), logging on `tracing`
//! ([`logging`]), the crash handler and its redaction ([`crash`],
//! [`redact`]) and Ctrl-C ([`app::install_interrupt_handler`]); and the
//! renderers of every result ([`render`], UC-3.4, #826): code frames, outcome
//! lines, SARIF and Code Quality, CI sinks and progress. Commands are
//! ported onto it one by one (UC-3.5, UC-3.6); until then a command with no
//! Rust implementation is refused with `engine_not_ported`, exit 2.

pub mod app;
pub mod catalog;
pub mod crash;
pub mod env;
pub mod envelope;
pub mod hoist;
pub mod json;
pub mod logging;
pub mod mode;
pub mod redact;
pub mod render;
pub mod schemas;
pub mod style;
pub mod suggest;
pub mod tree;
mod tree_meta;
pub mod usage;

pub use app::{Host, main, run};
