//! The JSON Schemas of the commands' `--json` documents, for `opentide commands`.
//!
//! Each command's `output_schema` is a `$ref` into `$defs`. Until a command's
//! typed result is Rust (its port, UC-3.5 and UC-3.6, derives it with
//! schemars), its schema is the one the Python models generate, kept in
//! `data/output-schemas.json` (first generated from the Python CLI's
//! `opentide --json commands`): a command whose document changes edits it,
//! and the `commands` snapshots (`tests/cli_snapshots/commands/`) show it.

use crate::json::Json;
use std::sync::OnceLock;

/// The schemas file, as text.
pub const SOURCE: &str = include_str!("../data/output-schemas.json");

/// The schemas: each command's `output_schema`, and the shared `$defs`.
pub struct Schemas {
    by_path: Vec<(String, Json)>,
    defs: Json,
}

impl Schemas {
    /// The schemas compiled into the binary, parsed once.
    pub fn load() -> &'static Schemas {
        static SCHEMAS: OnceLock<Schemas> = OnceLock::new();
        SCHEMAS.get_or_init(|| Schemas::parse(SOURCE))
    }

    /// Schemas from a generated file's text; empty when it does not parse.
    pub fn parse(text: &str) -> Schemas {
        let document = Json::parse(text).unwrap_or(Json::Null);
        let by_path = match document.get("output_schemas") {
            Some(Json::Object(members)) => members.clone(),
            _ => Vec::new(),
        };
        let defs = document
            .get("$defs")
            .cloned()
            .unwrap_or(Json::Object(Vec::new()));
        Schemas { by_path, defs }
    }

    /// The `output_schema` of the command at `path`, `null` when it has none.
    pub fn output_schema(&self, path: &str) -> Json {
        self.by_path
            .iter()
            .find(|(p, _)| p == path)
            .map_or(Json::Null, |(_, schema)| schema.clone())
    }

    /// `$defs`.
    pub fn defs(&self) -> Json {
        self.defs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_schemas_parse_and_fall_back_to_null() {
        let schemas = Schemas::load();
        assert!(matches!(schemas.output_schema("validate"), Json::Object(_)));
        assert_eq!(schemas.output_schema("no such"), Json::Null);
        let empty = Schemas::parse("not json");
        assert_eq!(empty.defs(), Json::Object(Vec::new()));
    }
}
