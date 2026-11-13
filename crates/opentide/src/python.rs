//! The Tide models as Python classes (`python` feature, UC-1.9, #815): the
//! PyO3 glue a Python extension compiles in to expose
//! [`models`] as `opentide._native.models`.
//!
//! The Python package is the one host of this surface; it is behind its own
//! feature because it brings PyO3.

pub use opentide_schema::python::{models, register};
