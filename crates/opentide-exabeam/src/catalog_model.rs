//! The data model of the Exabeam catalogue (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the two catalogue files once and stores them pre-parsed: this file depends on `serde`
//! and on nothing else of the crate.

use serde::{Deserialize, Serialize};

/// One field (`src_ip`, `activity_type`, `approxLogTime`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// The CIM type: `string`, `integer`, `number`, `boolean`, `datetime`,
    /// `ipv4/ipv6`, `array`, `hexadecimal`, `email`, `json`.
    #[serde(rename = "type")]
    pub ty: String,
    pub description: String,
    /// A platform field the CIM table does not list.
    #[serde(default)]
    pub platform: bool,
}

/// A field-name prefix that is never unknown (`c_`, `m_`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefix {
    pub prefix: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// An activity type, `<subject>-<activity>` (`process-create`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityType {
    pub name: String,
    pub subject: String,
    pub activity: String,
    #[serde(default)]
    pub pretty_name: String,
    #[serde(default)]
    pub outcomes: Vec<String>,
}
