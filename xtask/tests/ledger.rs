//! The repository's approved-diffs ledger, `tests/golden/APPROVED_DIFFS.toml`,
//! follows its schema and cites entries `CHANGELOG.md` holds: the check
//! `cargo xtask compare --check-ledger` runs, on every CI run.

use std::path::Path;

#[test]
fn the_repository_ledger_is_valid() -> anyhow::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("xtask has a parent folder"))?;
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md"))?;
    xtask::compare::read_ledger(&root.join(xtask::compare::LEDGER), &changelog)?;
    Ok(())
}
