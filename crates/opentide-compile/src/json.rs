//! The ordered JSON value of the engine: [`opentide_core::json::Json`], whose
//! objects keep their keys in insertion order. A request body is built key by
//! key and is sent and printed in that order; `serde_json::Value` sorts its
//! keys unless the workspace turns on `preserve_order` for every crate at once.

pub use opentide_core::json::{Json, Object};
