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
const UNSAFE_CRATES: &[(&str, &str)] = &[(
    "bindings/node",
    "napi-derive's registration: each #[napi] item expands to a `ctor` static \
         constructor carrying #[allow(unsafe_code)], which forbid refuses; no unsafe of its own",
)];

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

/// The words a `too_many_lines` suppression's reason uses to defer the split
/// ("split when next touched", "split when next reread", ...), matched without
/// regard to case: the workspace's long functions were kept whole with such a
/// reason when the lint was enforced, and it says nothing about the function
/// (#1959).
const DEFERRED: &str = "split when next";

/// The functions that still carry the deferred reason, one `path function`
/// per line: the list only shrinks.
const DEFERRED_LIST: &str = "xtask/too_many_lines.txt";

/// Every `.rs` file under `dir`, but in build outputs and hidden directories.
fn rust_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !name.starts_with('.') && name != "target" && name != "node_modules" {
                rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// `path function` for each suppression whose reason defers the split.
fn deferred_sites(root: &std::path::Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files = Vec::new();
    for top in ["bindings", "crates", "fuzz", "xtask"] {
        rust_files(&root.join(top), &mut files)?;
    }
    let mut sites = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "xtask/tests/lint_policy.rs" {
            continue;
        }
        sites.extend(deferred_in(&relative, &std::fs::read_to_string(&file)?)?);
    }
    sites.sort();
    Ok(sites)
}

/// `path function` for each deferred reason in one file's `text`. The function
/// is the first `fn` after the reason, outside comments; for an inner
/// attribute (`#![expect(...)]`) that is the first `fn` of the module, a key
/// that is as stable as an outer attribute's. A string broken with a `\`
/// continuation is joined first, so the reason is matched whole.
fn deferred_in(relative: &str, text: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let function = regex::Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")?;
    let continuation = regex::Regex::new(r"\\\r?\n[ \t]*")?;
    let deferred = regex::Regex::new(&format!("(?i){}", regex::escape(DEFERRED)))?;
    let joined = continuation.replace_all(text, "");
    let lines: Vec<&str> = joined.lines().collect();
    let mut sites = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if !deferred.is_match(line) {
            continue;
        }
        let name = lines[at..]
            .iter()
            .filter(|line| !line.trim_start().starts_with("//"))
            .find_map(|line| function.captures(line))
            .map_or("?", |found| found.get(1).map_or("?", |m| m.as_str()));
        sites.push(format!("{relative} {name}"));
    }
    Ok(sites)
}

#[test]
fn every_wording_of_the_deferral_is_found() -> TestResult {
    let planted = [
        (
            "#[expect(clippy::too_many_lines, reason = \"kept whole; split when next reread\")]\n\
             pub fn reread() {}\n",
            "reread",
        ),
        (
            "#[allow(clippy::too_many_lines, reason = \"Split When Next touched\")]\nfn upper() {}\n",
            "upper",
        ),
        (
            "#[expect(\n    clippy::too_many_lines,\n    reason = \"kept whole; split when next \\\n        touched\"\n)]\nfn continued() {}\n",
            "continued",
        ),
    ];
    for (text, name) in planted {
        assert_eq!(
            deferred_in("crates/x/src/lib.rs", text)?,
            vec![format!("crates/x/src/lib.rs {name}")],
            "{text}"
        );
    }
    assert!(
        deferred_in(
            "crates/x/src/lib.rs",
            "#[expect(clippy::too_many_lines, reason = \"one table\")]\nfn table() {}\n"
        )?
        .is_empty()
    );
    Ok(())
}

#[test]
fn no_new_too_many_lines_suppression_defers_its_split() -> TestResult {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
    let found = deferred_sites(&root)?;
    let listed_text = std::fs::read_to_string(root.join(DEFERRED_LIST))?;
    let mut listed: Vec<String> = listed_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    listed.sort();
    let mut new = found.clone();
    for site in &listed {
        if let Some(at) = new.iter().position(|other| other == site) {
            new.remove(at);
        }
    }
    let mut gone = listed.clone();
    for site in &found {
        if let Some(at) = gone.iter().position(|other| other == site) {
            gone.remove(at);
        }
    }
    assert!(
        new.is_empty(),
        "a `too_many_lines` suppression whose reason says \"{DEFERRED}\" is not in \
         {DEFERRED_LIST}: split the function, or give the reason it is long \
         (#1959):\n{}",
        new.join("\n")
    );
    assert!(
        gone.is_empty(),
        "{DEFERRED_LIST} lists functions that no longer defer their split: take \
         them off the list:\n{}",
        gone.join("\n")
    );
    Ok(())
}
