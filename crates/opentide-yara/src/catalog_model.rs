//! The data model of the YARA catalogs (#1743).
//!
//! Shared by the crate (`catalog.rs` reads the models) and by its build script (`#[path]`), which
//! parses the two catalog files once and stores them pre-parsed: this file depends on `serde` and
//! on nothing else of the crate.

use serde::{Deserialize, Serialize};

/// Whether the platform takes syntax only YARA-X has (`with`, digit
/// separators, float meta values, `\"\"\"` strings, booleans in `of` tuples, hex or octal
/// jump bounds, `.len()`). While `Refused`, using it is the error
/// `yara_x_only_syntax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YaraXSyntax {
    /// YARA-X's syntax is the language: a raw `.yar` file.
    #[default]
    Allowed,
    /// The platform's engine is not known to take it: the profile's start.
    Refused,
}

/// A scalar type, or the shape of a module member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Integer,
    Float,
    String,
    Boolean,
    Regexp,
    Struct,
    Array,
    Dict,
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overload {
    /// One letter per argument: `i`, `f`, `s`, `r`, `b` (`?` a structure).
    pub args: String,
    pub ret: String,
    #[serde(default)]
    pub doc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub module: String,
    /// `sections[].name`: `[]` is an array element, `{}` a dictionary value.
    pub path: String,
    pub kind: Kind,
    #[serde(default)]
    pub element: Option<Kind>,
    #[serde(default)]
    pub doc: Option<String>,
    #[serde(default, rename = "overload")]
    pub overloads: Vec<Overload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    /// `allowed` or `refused`: whether YARA-X-only syntax is taken. Any
    /// other value fails the catalog's load (and its tests), never a silent
    /// `refused`.
    pub yara_x_syntax: YaraXSyntax,
    pub ascii_only: bool,
    #[serde(default)]
    pub max_characters: Option<usize>,
    pub confirmed_modules: Vec<String>,
    pub recommended_meta: Vec<String>,
    #[serde(default)]
    pub context_values: Vec<String>,
}
