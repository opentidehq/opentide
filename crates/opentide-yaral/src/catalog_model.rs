//! The data model of the YARA-L catalogues (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the two catalogue files once and stores them pre-parsed: this file depends on `serde`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, rename = "enum")]
    pub is_enum: bool,
    #[serde(default)]
    pub repeated: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub doc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub name: String,
    #[serde(default)]
    pub doc: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumRow {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roots {
    pub event: String,
    pub entity: String,
    pub detection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub signature: String,
    pub min_args: usize,
    #[serde(default)]
    pub max_args: Option<usize>,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub availability: Vec<String>,
    #[serde(default)]
    pub aggregation: bool,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub url: String,
}
