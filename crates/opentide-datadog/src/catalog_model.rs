//! The data model of the Datadog attribute catalogue (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the model) and by its build script (`#[path]`), which
//! parses the catalogue once and stores it pre-parsed: this file depends on `serde` and on
//! nothing else of the crate.

use serde::{Deserialize, Serialize};

/// One reserved or standard attribute, as Datadog's "Default Standard Attributes" table lists
/// it: facts only, no description (`data/catalogs/datadog/NOTICE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    /// The path, without `@`: `network.client.ip`; a reserved attribute's bare name: `host`.
    pub name: String,
    /// `string`, `number`, `integer`, `boolean` or `object`.
    #[serde(rename = "type")]
    pub ty: String,
    /// The table's grouping: `Reserved`, `Network communications`, `Events`, ...
    pub domain: String,
    /// The products that set it: `logs`, `apm`, `rum`.
    pub products: Vec<String>,
}
