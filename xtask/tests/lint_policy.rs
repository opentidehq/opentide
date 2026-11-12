//! The workspace's lint policy (root `Cargo.toml`, `[workspace.lints]`) holds
//! for every member.
//!
//! `unsafe_code = "forbid"` cannot be relaxed inside a crate, so a crate that
//! needs `unsafe` cannot inherit the table: it copies it with
//! `unsafe_code = "deny"` and allows `unsafe` at each site with a reason.
//! These tests keep that list of crates explicit, and each copy equal to the
//! table in everything else, so that leaving `forbid` never also drops a lint.

use std::error::Error;
use std::path::PathBuf;
use toml::{Table, Value};

/// The members that may contain `unsafe`, and why. Keep it minimal: FFI and
/// the symbols a binding must export, nothing else.
const UNSAFE_CRATES: &[(&str, &str)] = &[
    (
        "crates/opentide-syntax",
        "the tree-sitter FFI: each grammar's C entry point and LanguageFn::from_raw",
    ),
    (
        "crates/opentide-wasm",
        "the wasm32 libc shims: #[unsafe(no_mangle)] syscall symbols",
    ),
    (
        "bindings/node",
        "napi-derive's registration: each #[napi] item expands to a `ctor` static \
         constructor carrying #[allow(unsafe_code)], which forbid refuses; no unsafe of its own",
    ),
];

type TestResult = Result<(), Box<dyn Error>>;

fn read_manifest(relative: &str) -> Result<Table, Box<dyn Error>> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join(relative);
    let text =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(text.parse::<Table>()?)
}

fn workspace() -> Result<Table, Box<dyn Error>> {
    match read_manifest("Cargo.toml")?.remove("workspace") {
        Some(Value::Table(workspace)) => Ok(workspace),
        _ => Err("the root Cargo.toml has no [workspace]".into()),
    }
}

fn members(workspace: &Table) -> Vec<String> {
    workspace
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// The workspace's lint table with `unsafe_code` set to `level`.
fn workspace_lints_with_unsafe(workspace: &Table, level: &str) -> Result<Table, Box<dyn Error>> {
    let mut lints = workspace
        .get("lints")
        .and_then(Value::as_table)
        .cloned()
        .ok_or("the root Cargo.toml has no [workspace.lints]")?;
    let rust = lints
        .get_mut("rust")
        .and_then(Value::as_table_mut)
        .ok_or("[workspace.lints] has no rust table")?;
    rust.insert("unsafe_code".into(), Value::String(level.into()));
    Ok(lints)
}

#[test]
fn the_workspace_forbids_unsafe_code() -> TestResult {
    let workspace = workspace()?;
    let rust = workspace
        .get("lints")
        .and_then(|lints| lints.get("rust"))
        .ok_or("no [workspace.lints.rust]")?;
    assert_eq!(
        rust.get("unsafe_code"),
        Some(&Value::String("forbid".into()))
    );
    Ok(())
}

#[test]
fn every_unsafe_block_is_documented_and_does_one_thing() -> TestResult {
    // The policy docs/internal/unsafe.md states: a `// SAFETY:` comment on
    // each block, one unsafe operation per block.
    let workspace = workspace()?;
    let clippy = workspace
        .get("lints")
        .and_then(|lints| lints.get("clippy"))
        .ok_or("no [workspace.lints.clippy]")?;
    for lint in [
        "undocumented_unsafe_blocks",
        "multiple_unsafe_ops_per_block",
    ] {
        assert_eq!(
            clippy.get(lint),
            Some(&Value::String("deny".into())),
            "clippy::{lint} must be denied"
        );
    }
    Ok(())
}

#[test]
fn every_member_inherits_the_workspace_lints_unless_it_needs_unsafe() -> TestResult {
    let workspace = workspace()?;
    let members = members(&workspace);
    assert!(members.len() > 10, "{members:?}");
    for member in &members {
        let manifest = read_manifest(&format!("{member}/Cargo.toml"))?;
        let lints = manifest.get("lints");
        if UNSAFE_CRATES.iter().any(|(name, _)| name == member) {
            assert!(
                lints.and_then(|lints| lints.get("workspace")).is_none(),
                "{member} needs unsafe: it copies the lints instead of inheriting forbid"
            );
        } else {
            let mut inherit = Table::new();
            inherit.insert("workspace".into(), Value::Boolean(true));
            assert_eq!(
                lints,
                Some(&Value::Table(inherit)),
                "{member}: `[lints] workspace = true`, and nothing else. A crate that needs \
                 unsafe joins UNSAFE_CRATES here, with its reason"
            );
        }
    }
    Ok(())
}

#[test]
fn each_unsafe_crate_copies_the_workspace_lints_with_unsafe_denied() -> TestResult {
    let workspace = workspace()?;
    let expected = workspace_lints_with_unsafe(&workspace, "deny")?;
    let members = members(&workspace);
    for (member, why) in UNSAFE_CRATES {
        assert!(
            members.iter().any(|m| m == member),
            "{member} is not a member"
        );
        let manifest = read_manifest(&format!("{member}/Cargo.toml"))?;
        assert_eq!(
            manifest.get("lints"),
            Some(&Value::Table(expected.clone())),
            "{member} ({why}): its [lints] must be the workspace's with unsafe_code = \"deny\""
        );
    }
    Ok(())
}
