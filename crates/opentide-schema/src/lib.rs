//! The Tide model as Rust code (plan D-2; ADR
//! `docs/internal/adr/0001-tide-model-as-rust-code.md`).
//!
//! Each model is a plain struct with one derive per concern:
//!
//! - `serde::{Deserialize, Serialize}`: the shape, the field order (which is
//!   also the template and serialisation order) and `deny_unknown_fields`
//!   where Pydantic has `extra="forbid"`;
//! - `garde::Validate`, with the [`Pins`] context: constraints and custom
//!   validators;
//! - `schemars::JsonSchema` (JSON Schema 2020-12): the schema, with the
//!   `tide.*` metadata keys ([`keys`]) as `#[schemars(extend(...))]`;
//! - `#[pyclass(frozen, get_all)]` behind the `python` feature: the Python
//!   class.
//!
//! Errors are [`SchemaError`]s, mapped to the CLI's diagnostic codes.
//!
//! This is the skeleton (UC-1.1, #807): the conventions, the context and the
//! error type, with [`sample`] as their worked example. The Tide models arrive
//! with UC-1.3 (#809) onwards. The crate is I/O-free and internal: the
//! `opentide` facade (UC-5.1, #836) is the public API.

pub mod error;
pub mod keys;
pub mod pins;
mod revision;
pub mod sample;

pub use error::{ErrorKind, PathSegment, SchemaError, Surface};
pub use pins::Pins;
