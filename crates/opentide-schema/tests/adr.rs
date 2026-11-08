//! The ADR's metadata-key table and `keys::ALL` list the same 23 keys, each
//! row with its attribute and an example (issue #807, acceptance criteria).

use std::path::Path;

use opentide_schema::keys;

fn adr() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/internal/adr/0001-tide-model-as-rust-code.md");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The rows of the table whose header starts with `| # | Key |`.
fn key_rows(text: &str) -> Vec<Vec<String>> {
    let mut lines = text
        .lines()
        .skip_while(|line| !line.starts_with("| # | Key |"));
    assert!(lines.next().is_some(), "the ADR has no `| # | Key |` table");
    lines
        .skip(1)
        .take_while(|line| line.starts_with('|'))
        .map(|line| {
            line.trim_matches('|')
                .split(" | ")
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        .collect()
}

#[test]
fn the_table_lists_every_key_once_with_attribute_and_example() {
    let rows = key_rows(&adr());
    assert_eq!(rows.len(), 23, "rows: {rows:#?}");
    for (index, (row, key)) in rows.iter().zip(keys::ALL).enumerate() {
        assert_eq!(row.len(), 6, "row {}: {row:?}", index + 1);
        assert_eq!(row[0], (index + 1).to_string());
        assert_eq!(row[1], format!("`{}`", key.name), "row {}", index + 1);
        let origin = format!("{:?}", key.origin);
        assert_eq!(row[2], origin, "row {}", index + 1);
        for (column, cell) in ["attribute", "example"].iter().zip([&row[3], &row[4]]) {
            assert!(
                cell.contains('`'),
                "row {} ({}) has no {column}",
                index + 1,
                key.name
            );
        }
    }
}
