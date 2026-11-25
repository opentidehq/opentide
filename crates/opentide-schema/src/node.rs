//! The YAML node tree a model is converted from (UC-1.2, #808): opentide-core's
//! [`opentide_core::node`], the one YAML reader of the workspace (#850),
//! re-exported here with the writer, [`to_yaml`].
//!
//! What this reads differently from the oracle (opentide 0.23.0, PyYAML's YAML
//! 1.1 loader) is the table in `crates/opentide-schema/YAML.md`, generated and
//! checked by `tests/yaml_table.rs` from `tests/oracle/yaml_cases.toml`.

mod dump;

pub use dump::{DumpError, double_quoted, to_yaml};
pub use opentide_core::node::*;
