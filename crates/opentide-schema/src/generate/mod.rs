//! The artifacts generated from the model (UC-1.8, #814; plan D-2): what
//! `opentide generate` writes into a workspace and what is committed for
//! editors, from the Rust model instead of Pydantic, byte for byte as the
//! oracle writes them.
//!
//! - [`json`]: documents with their keys in insertion order, written as
//!   Python's `json.dumps(indent=4)` writes them;
//! - [`annotate`]: the editor annotations of every generated schema
//!   (`schema_annotations.py`);
//! - [`router`]: `opentide.schema.json` (`router_schema.py`);
//! - [`models`]: each model's field order, which the schemas schemars
//!   derives do not keep;
//! - [`template`]: YAML skeletons (`pydantic_skeleton.py`);
//! - [`snippets`]: VS Code snippets (`vscode_snippets.py`);
//! - [`workspace`]: the files of the `templates` and `snippets` phases and
//!   the router, from a workspace's resolved configuration.
//!
//! The module is I/O-free: hosts (`cargo xtask codegen`, the CLI) write the
//! files.

pub mod annotate;
pub mod json;
pub mod models;
pub mod router;
pub mod snippets;
pub mod template;
pub mod workspace;

#[cfg(test)]
mod tests;
