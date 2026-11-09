//! `data/output-schemas.json` is generated from the oracle's catalogue
//! (`tests/golden/cases/commands/json/none/default/stdout`): each command's
//! `output_schema`, then `$defs`. `OPENTIDE_CLI_BLESS=1` rewrites it.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: an unreadable recording is a failure"
)]

use opentide_cli::json::{Json, document_text};
use std::path::Path;

fn generated() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let recording = std::fs::read_to_string(
        root.join("../../tests/golden/cases/commands/json/none/default/stdout"),
    )
    .unwrap();
    let catalogue = Json::parse(&recording).unwrap();
    let Some(Json::Array(commands)) = catalogue.get("commands") else {
        panic!("no commands in the recording")
    };
    let schemas: Vec<(String, Json)> = commands
        .iter()
        .map(|command| {
            let Some(Json::Str(path)) = command.get("path") else {
                panic!("a command without a path")
            };
            (
                path.clone(),
                command.get("output_schema").cloned().unwrap_or(Json::Null),
            )
        })
        .collect();
    let document = Json::object([
        ("output_schemas", Json::Object(schemas)),
        ("$defs", catalogue.get("$defs").cloned().unwrap()),
    ]);
    document_text(&document, true)
}

#[test]
fn framework_schemas_are_the_oracles() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/output-schemas.json");
    let expected = generated();
    if std::env::var_os("OPENTIDE_CLI_BLESS").is_some() {
        std::fs::write(&path, &expected).unwrap();
    }
    // A Windows checkout may turn the file's line endings into CRLF.
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n")
            == expected,
        "data/output-schemas.json is stale: OPENTIDE_CLI_BLESS=1 cargo nextest run -p opentide-cli framework_schemas"
    );
}
