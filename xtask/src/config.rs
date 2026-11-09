//! `cargo xtask config diff --against python` (UC-1.5, #811): every fixture
//! and generated workspace's configuration resolved by
//! `opentide_schema::configuration::resolve`, serialised to JSON, and its
//! `validate --check configuration` findings, against the oracle's
//! `resolve_configurations` and `workspace_configuration_issues`
//! (`xtask/oracle/config_resolve.py`, run with the oracle's interpreter).
//!
//! The workspaces:
//!
//! - fixtures: `tests/golden/fixtures/vscode-workspace`,
//!   `crates/testdata/conformance/lint-toml`, every golden case workspace
//!   with a configuration folder, `tests/fixtures/generation/configurations`
//!   as a workspace's folder, and a child workspace under the vscode fixture
//!   (a parent instance);
//! - generated: the heavy workspace (`corpus generate`) in each layout, and
//!   the combined fault workspace (`corpus faults --out`), whose
//!   configuration carries the non-isolated configuration faults.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value as Json, json};

use crate::corpus::cli::{
    Scratch, check_oracle_version, load_catalogue, materialise, oracle_bin, read_folder, repo_root,
    write_workspace,
};
use crate::corpus::generate::{self, Counts, Layout, Options};
use opentide_schema::configuration::resolve::{Instance, ResolveError, resolve};

/// The usage of `cargo xtask config`.
pub const USAGE: &str = "\
usage: cargo xtask config diff --against python [--oracle BIN]
                               [--corpus all|fixtures|generated] [--keep DIR]

  compare each workspace's resolved configuration (as JSON) and its
  `validate --check configuration` findings with the oracle's; a
  workspace whose resolution stops compares the error's code and message
  (the code only for `config_parse`, whose message is the TOML crate's).
  The oracle is BIN, else $OPENTIDE_ORACLE, else `opentide` on PATH; its
  interpreter is the `python` beside it.
";

/// Runs `config <args>`; the process exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, options)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    if command == "help" || command == "--help" {
        print!("{USAGE}");
        return Ok(0);
    }
    if command != "diff" {
        bail!("unknown command `{command}`\n\n{USAGE}");
    }
    let mut against = None;
    let mut oracle = None;
    let mut corpus = "all".to_owned();
    let mut keep = None;
    let mut args = options.iter();
    while let Some(arg) = args.next() {
        let next = |args: &mut std::slice::Iter<'_, String>| {
            args.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--against" => against = Some(next(&mut args)?),
            "--oracle" => oracle = Some(next(&mut args)?),
            "--corpus" => corpus = next(&mut args)?,
            "--keep" => keep = Some(PathBuf::from(next(&mut args)?)),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    if against.as_deref() != Some("python") {
        bail!("--against python is required\n\n{USAGE}");
    }
    let (fixtures, generated) = match corpus.as_str() {
        "all" => (true, true),
        "fixtures" => (true, false),
        "generated" => (false, true),
        other => bail!("--corpus `{other}` is not all, fixtures or generated"),
    };
    let bin = oracle_bin(oracle.as_deref());
    let catalogue = load_catalogue(&repo_root().join("tests/corpora/faults.toml"))?;
    check_oracle_version(&bin, &catalogue.oracle)?;
    let python = bin.with_file_name("python");
    let scratch = keep.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("opentide-config-diff-{}", std::process::id()))
    });
    let scratch = std::path::absolute(&scratch)?;
    if scratch.exists() {
        bail!(
            "{} exists; remove it or name another --keep",
            scratch.display()
        );
    }
    std::fs::create_dir_all(&scratch)?;
    let guard = Scratch {
        path: scratch.clone(),
        keep: keep.is_some(),
    };
    let mut workspaces = Vec::new();
    if fixtures {
        workspaces.extend(fixture_workspaces(&scratch)?);
    }
    if generated {
        workspaces.extend(generated_workspaces(&scratch, &catalogue)?);
    }
    let oracle_results = run_oracle_script(&python, &workspaces)?;
    let mut failed = 0usize;
    for workspace in &workspaces {
        let key = workspace.to_string_lossy().into_owned();
        let oracle = oracle_results
            .get(&key)
            .with_context(|| format!("the oracle printed nothing for {key}"))?;
        let rust = rust_result(workspace)?;
        let (oracle, rust) = comparable(oracle, &rust);
        let shown = workspace.strip_prefix(&scratch).unwrap_or(workspace);
        let shown = shown.strip_prefix(repo_root()).unwrap_or(shown);
        if oracle == rust {
            let issues = rust
                .get("issues")
                .and_then(Json::as_array)
                .map_or(0, Vec::len);
            println!("ok   {:<72} {issues} finding(s)", shown.display());
        } else {
            failed += 1;
            println!(
                "FAIL {}\n       oracle: {}\n       rust:   {}",
                shown.display(),
                serde_json::to_string(&oracle)?,
                serde_json::to_string(&rust)?
            );
        }
    }
    drop(guard);
    println!(
        "config diff --against python: {} workspaces, {} equal, {failed} differ",
        workspaces.len(),
        workspaces.len() - failed
    );
    Ok(u8::from(failed > 0))
}

/// `config_parse`'s message is the TOML crate's (an approved difference,
/// `config_cases.toml` `toml-parse-message`): only its code is compared.
fn comparable(oracle: &Json, rust: &Json) -> (Json, Json) {
    let parse = |value: &Json| value.pointer("/error/code") == Some(&json!("config_parse"));
    if parse(oracle) && parse(rust) {
        return (
            json!({"error": {"code": "config_parse"}}),
            json!({"error": {"code": "config_parse"}}),
        );
    }
    (oracle.clone(), rust.clone())
}

fn rust_result(workspace: &Path) -> Result<Json> {
    let own_dir = workspace.join(".opentide").join("configurations");
    let own = read_folder(&own_dir, &own_dir.to_string_lossy())?;
    let parent_dir = workspace
        .parent()
        .map(|parent| parent.join(".opentide").join("configurations"));
    let parent = match &parent_dir {
        Some(dir) if *dir != own_dir => read_folder(dir, &dir.to_string_lossy())?,
        _ => None,
    };
    Ok(
        match resolve(&Instance {
            workspace: own.as_ref(),
            overlay: None,
            parent: parent.as_ref(),
            // The oracle runs without OPENTIDE_TIDE_WORKSPACE.
            skip_parent: false,
        }) {
            Ok(resolved) => json!({
                "resolved": resolved.to_json(),
                "issues": resolved.issues().iter().map(|finding| json!({
                    "code": finding.code,
                    "severity": finding.severity.as_str(),
                    "field_path": finding.field_path,
                    "message": finding.message,
                })).collect::<Vec<_>>(),
            }),
            Err(error) => {
                let message = match &error {
                    ResolveError::Parse { message, .. }
                    | ResolveError::Retired { message, .. }
                    | ResolveError::Proxy(message) => message.clone(),
                };
                json!({"error": {"code": error.code(), "message": message}})
            }
        },
    )
}

fn run_oracle_script(python: &Path, workspaces: &[PathBuf]) -> Result<BTreeMap<String, Json>> {
    let script = repo_root().join("xtask/oracle/config_resolve.py");
    let mut results = BTreeMap::new();
    for chunk in workspaces.chunks(64) {
        let output = Command::new(python)
            .arg("-I")
            .arg(&script)
            .args(chunk)
            .env_remove("OPENTIDE_TIDE_WORKSPACE")
            .output()
            .with_context(|| format!("cannot run {}", python.display()))?;
        if !output.status.success() {
            bail!(
                "{} {} failed: {}",
                python.display(),
                script.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let document: BTreeMap<String, Json> = serde_json::from_slice(&output.stdout)
            .context("the oracle script printed no JSON object")?;
        results.extend(document);
    }
    Ok(results)
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Every golden case workspace with a configuration folder, the fixtures,
/// and the workspaces made from fixtures under `scratch`.
fn fixture_workspaces(scratch: &Path) -> Result<Vec<PathBuf>> {
    let root = repo_root();
    let mut found = vec![
        root.join("tests/golden/fixtures/vscode-workspace"),
        root.join("crates/testdata/conformance/lint-toml"),
    ];
    let mut stack = vec![root.join("tests/golden/cases")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            if path.join(".opentide").join("configurations").is_dir() {
                found.push(path.clone());
            }
            if entry.file_name() != ".opentide" {
                stack.push(path);
            }
        }
    }
    // The generation fixtures' folder, as a workspace's own.
    let generation = scratch.join("fixtures/generation");
    copy_tree(
        &root.join("tests/fixtures/generation/configurations"),
        &generation.join(".opentide/configurations"),
    )?;
    found.push(generation);
    // A child workspace whose parent instance is the vscode fixture's.
    let parent = scratch.join("fixtures/parent");
    copy_tree(
        &root.join("tests/golden/fixtures/vscode-workspace/.opentide"),
        &parent.join(".opentide"),
    )?;
    let child = parent.join("child/.opentide/configurations");
    std::fs::create_dir_all(child.join("platforms"))?;
    std::fs::write(
        child.join("deployment.toml"),
        "default_responders = \"child\"\n[promotion]\nenabled = false\n",
    )?;
    std::fs::write(
        child.join("platforms/splunk.toml"),
        "[platform]\nenabled = true\n",
    )?;
    found.push(parent.join("child"));
    found.sort();
    found.dedup();
    Ok(found)
}

/// The heavy workspace in each layout and the combined fault workspace,
/// written under `scratch`.
fn generated_workspaces(
    scratch: &Path,
    catalogue: &crate::corpus::faults::Catalogue,
) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for (name, layout) in [
        ("standard", Layout::Standard),
        ("explicit", Layout::Explicit),
        ("custom", Layout::Custom),
    ] {
        let options = Options {
            seed: 1,
            counts: Counts {
                threats: 3,
                objectives: 3,
                rules: 5,
            },
            layout,
        };
        let dir = scratch.join("generated").join(name);
        write_workspace(&generate::generate(&options), &dir)?;
        found.push(dir);
    }
    let combined = scratch.join("generated").join("faults");
    materialise(catalogue, &combined)?;
    found.push(combined);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn usage_errors_are_refused() {
        assert!(run(&[]).is_err());
        assert!(run(&args(&["bogus"])).is_err());
        assert!(run(&args(&["diff"])).is_err(), "no --against");
        assert!(run(&args(&["diff", "--against", "rust"])).is_err());
        assert!(run(&args(&["diff", "--against", "python", "--corpus", "x"])).is_err());
        assert!(run(&args(&["diff", "--against", "python", "--bogus"])).is_err());
        assert!(
            run(&args(&[
                "diff",
                "--against",
                "python",
                "--oracle",
                "/nonexistent/opentide"
            ]))
            .is_err()
        );
        assert_eq!(run(&args(&["help"])).unwrap(), 0);
    }

    #[test]
    fn a_parse_error_compares_by_code() {
        let oracle = json!({"error": {"code": "config_parse", "message": "Invalid value"}});
        let rust = json!({"error": {"code": "config_parse", "message": "expected `=`"}});
        let (oracle, rust) = comparable(&oracle, &rust);
        assert_eq!(oracle, rust);
        let other = json!({"error": {"code": "retired_configuration_file", "message": "a"}});
        let (oracle, rust) = comparable(
            &other,
            &json!({"error": {"code": "retired_configuration_file", "message": "b"}}),
        );
        assert_ne!(oracle, rust);
    }

    #[test]
    fn a_workspace_without_configuration_resolves_to_the_bundled_files() {
        let dir =
            std::env::temp_dir().join(format!("opentide-config-diff-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = rust_result(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(result["resolved"]["platforms"]["splunk"].is_object());
        assert_eq!(result["issues"], json!([]));
    }
}
