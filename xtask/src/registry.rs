//! `cargo xtask registry diff --against python` (UC-2.1, #816): every
//! corpus loaded by `opentide-workspace` and its index, exported as JSON
//! (`Index::to_json`), against the Python registry's
//! (`xtask/oracle/registry_export.py`, run with the oracle's interpreter):
//! objects, UUIDs, types, paths, bodies, signals, load errors, duplicates,
//! nested files, references and chaining.
//!
//! The corpora:
//!
//! - fixtures: every fixture of `tests/golden/cases.toml`, and `edges`, a
//!   workspace written here with one file per loading rule (below);
//! - generated: the heavy workspace (seed 20261107) and the generator's three
//!   layouts;
//! - faults: the fault catalogue's base with each kind applied on its own.
//!
//! A difference is a failure unless an approved rule ([`APPROVED`]) explains
//! it; every rule says why, with its CHANGELOG entry, and a rule that
//! explains nothing on `--corpus all` is stale and fails the run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::{Value as Json, json};

use crate::corpus::cli::{
    Scratch, check_oracle_version, load_catalogue, oracle_bin, repo_root, write_workspace,
};
use crate::corpus::faults;
use crate::corpus::generate::{self, Counts, Layout, Options};
use opentide_workspace::{OsFs, RootOptions, Workspace};

/// The usage of `cargo xtask registry`.
pub const USAGE: &str = "\
usage: cargo xtask registry diff --against python [--oracle BIN]
                                 [--corpus all|fixtures|generated|faults]
                                 [--keep DIR] [--show-approved]

  load every corpus with opentide-workspace and compare its index, as
  JSON (objects, UUIDs, types, paths, bodies, signals, load errors,
  duplicates, nested files, references, chaining), with the Python
  registry's. The oracle is BIN, else $OPENTIDE_ORACLE, else `opentide`
  on PATH; its interpreter is the `python` beside it. --show-approved
  prints each approved difference too.
";

/// The seed of the heavy workspace (`corpus generate`, `bench`).
const HEAVY_SEED: u64 = 20_261_107;

/// An approved class of difference: where it applies, and why.
pub struct Approved {
    /// The rule's id, printed with each difference it explains.
    pub id: &'static str,
    /// Why the Rust result is right.
    pub reason: &'static str,
    /// The bold lead of its CHANGELOG.md entry.
    pub changelog: &'static str,
    /// Whether it explains the difference at `pointer` between the oracle's
    /// value and the Rust value.
    pub applies: fn(pointer: &str, oracle: &Json, rust: &Json) -> bool,
}

/// The approved differences.
pub const APPROVED: &[Approved] = &[
    Approved {
        id: "yaml-error-text",
        reason: "a file that is not YAML is reported in the words of the YAML 1.2 parser \
                 (saphyr) with its line and column, where the oracle quoted PyYAML; the code \
                 (`yaml_parse`), the file and its family are the same",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_error_text,
    },
    Approved {
        id: "yaml-1-2-scalars",
        reason: "objects are read as YAML 1.2 (the saphyr crate): `yes`, `no`, `on`, `off` are \
                 text, and a date or timestamp stays as written, where PyYAML (YAML 1.1) \
                 read a boolean or rewrote the timestamp in ISO form",
        changelog: "**Tide objects are read as YAML 1.2**",
        applies: yaml_1_2_scalar,
    },
];

fn last_segment(pointer: &str) -> &str {
    pointer.rsplit('/').next().unwrap_or("")
}

/// `/load_errors/N/error` or `.../message` of a YAML error on both sides.
fn yaml_error_text(pointer: &str, oracle: &Json, rust: &Json) -> bool {
    if !pointer.starts_with("/load_errors/")
        || !matches!(last_segment(pointer), "error" | "message")
    {
        return false;
    }
    let (Some(oracle), Some(rust)) = (oracle.as_str(), rust.as_str()) else {
        return false;
    };
    // Opentide's own texts never differ: only the parser's.
    let own = |text: &str| {
        text.contains("expected a mapping at the top of the file")
            || text.contains("is not UTF-8 text")
            || text.contains("has no uuid")
    };
    // The same place: the Rust line is the line the oracle names, or the
    // line where the construct it names starts (`... that starts at line 51`,
    // where saphyr points); only the words, and the column, differ.
    let lines = |text: &str| -> Vec<String> {
        text.split("line ")
            .skip(1)
            .filter_map(|rest| rest.split(',').next())
            .map(str::to_owned)
            .collect()
    };
    let rust_line = rust
        .rfind(" at line ")
        .and_then(|at| lines(&rust[at..]).into_iter().next());
    !own(oracle) && !own(rust) && rust_line.is_some_and(|line| lines(oracle).contains(&line))
}

/// YAML 1.1's readings of a plain scalar that YAML 1.2 keeps as text.
fn yaml_1_1_reading(text: &str) -> Option<Json> {
    match text {
        "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => return Some(json!(true)),
        "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => return Some(json!(false)),
        _ => {}
    }
    // A timestamp: `2026-01-01 10:00:00`, `2026-01-01t10:00:00.5+01:00`.
    let bytes = text.as_bytes();
    let is_date = bytes.len() > 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && text
            .get(..4)
            .is_some_and(|y| y.bytes().all(|b| b.is_ascii_digit()));
    if is_date {
        let (date, time) = text.split_at(10);
        let time = time.trim_start_matches([' ', '\t', 'T', 't']);
        let time = time.replace(' ', "");
        let time = time
            .strip_suffix('Z')
            .or_else(|| time.strip_suffix('z'))
            .map_or(time.clone(), |t| format!("{t}Z"));
        return Some(json!(format!("{date}T{time}")));
    }
    None
}

fn yaml_1_2_scalar(pointer: &str, oracle: &Json, rust: &Json) -> bool {
    if !(pointer.starts_with("/bodies/") || pointer.starts_with("/signals/")) {
        return false;
    }
    let Some(text) = rust.as_str() else {
        return false;
    };
    match yaml_1_1_reading(text) {
        Some(Json::Bool(flag)) => oracle == &Json::Bool(flag),
        // The oracle's ISO text: same date and time, normalised separators.
        Some(Json::String(iso)) => oracle.as_str().is_some_and(|o| {
            o.replace("+00:00", "Z") == iso || o.starts_with(iso.trim_end_matches('Z'))
        }),
        _ => false,
    }
}

/// An approved difference that spans the whole index: a file the oracle
/// refused for an impossible unquoted date (PyYAML reads `2026-02-30` as a
/// timestamp and fails) is an object in Rust, where YAML 1.2 reads it as
/// text and the `reviewed` field's own check reports it (UC-1.3,
/// `yaml-1-2-dates`): (id, reason, CHANGELOG lead).
pub const INVALID_DATES: (&str, &str, &str) = (
    "yaml-1-2-dates",
    "an unquoted impossible date is text in YAML 1.2, so the file loads and the field's \
     check reports it (schema_validation), where PyYAML refused the whole file (yaml_parse)",
    "**Tide objects are read as YAML 1.2**",
);

/// Takes out of both sides each file the oracle refused for an impossible
/// date and Rust indexed, with everything the object brings (its UUID, body,
/// file, references, signals, chaining); returns how many.
pub fn reconcile_invalid_dates(oracle: &mut Json, rust: &mut Json) -> usize {
    let refused: Vec<(usize, String)> = oracle
        .get("load_errors")
        .and_then(Json::as_array)
        .map(|errors| {
            errors
                .iter()
                .enumerate()
                .filter(|(_, error)| {
                    error["error"]
                        .as_str()
                        .is_some_and(|text| text.contains("is not a valid date"))
                })
                .filter_map(|(at, error)| Some((at, error["path"].as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let mut reconciled = 0;
    for (at, path) in refused.into_iter().rev() {
        let uuids: Vec<String> = rust["file_paths"]
            .as_object()
            .map(|paths| {
                paths
                    .iter()
                    .filter(|(_, file)| file.as_str() == Some(path.as_str()))
                    .map(|(uuid, _)| uuid.clone())
                    .collect()
            })
            .unwrap_or_default();
        if uuids.is_empty() {
            continue;
        }
        for uuid in &uuids {
            if let Some(families) = rust["objects"].as_object_mut() {
                for members in families.values_mut() {
                    if let Some(list) = members.as_array_mut() {
                        list.retain(|member| member.as_str() != Some(uuid));
                    }
                }
            }
            if let Some(bodies) = rust["bodies"].as_object_mut() {
                for members in bodies.values_mut() {
                    if let Some(map) = members.as_object_mut() {
                        map.remove(uuid);
                    }
                }
            }
            for key in ["files", "file_paths", "chaining"] {
                if let Some(map) = rust[key].as_object_mut() {
                    map.remove(uuid);
                }
            }
            if let Some(signals) = rust["signals"].as_object_mut() {
                signals.retain(|_, signal| signal["owner"].as_str() != Some(uuid));
            }
            if let Some(references) = rust["references"].as_array_mut() {
                references.retain(|reference| reference[0].as_str() != Some(uuid));
            }
        }
        if let Some(errors) = oracle["load_errors"].as_array_mut() {
            errors.remove(at);
        }
        reconciled += 1;
    }
    reconciled
}

/// Runs `registry <args>`; the process exit status.
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
    let mut show_approved = false;
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
            "--show-approved" => show_approved = true,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    if against.as_deref() != Some("python") {
        bail!("--against python is required\n\n{USAGE}");
    }
    let (fixtures, generated, fault_kinds) = match corpus.as_str() {
        "all" => (true, true, true),
        "fixtures" => (true, false, false),
        "generated" => (false, true, false),
        "faults" => (false, false, true),
        other => bail!("--corpus `{other}` is not all, fixtures, generated or faults"),
    };
    let bin = oracle_bin(oracle.as_deref());
    let catalogue = load_catalogue(&repo_root().join("tests/corpora/faults.toml"))?;
    check_oracle_version(&bin, &catalogue.oracle)?;
    let python = bin.with_file_name("python");
    let scratch = keep.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("opentide-registry-diff-{}", std::process::id()))
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
        workspaces.extend(generated_workspaces(&scratch)?);
    }
    if fault_kinds {
        workspaces.extend(fault_workspaces(&scratch, &catalogue)?);
    }
    let oracle_results = run_oracle_script(&python, &workspaces)?;
    let mut failed = 0usize;
    let mut used: BTreeMap<&'static str, usize> = BTreeMap::new();
    for workspace in &workspaces {
        let key = workspace.to_string_lossy().into_owned();
        let oracle = oracle_results
            .get(&key)
            .with_context(|| format!("the oracle printed nothing for {key}"))?;
        let mut oracle = oracle.clone();
        let mut rust = rust_result(workspace);
        let dates = reconcile_invalid_dates(&mut oracle, &mut rust);
        if dates > 0 {
            *used.entry(INVALID_DATES.0).or_default() += dates;
        }
        let oracle = &oracle;
        let shown = workspace.strip_prefix(&scratch).unwrap_or(workspace);
        let mut differences = Vec::new();
        diff("", oracle, &rust, &mut differences);
        let mut unexplained = Vec::new();
        for (pointer, oracle, rust) in differences {
            match APPROVED
                .iter()
                .find(|rule| (rule.applies)(&pointer, &oracle, &rust))
            {
                Some(rule) => {
                    *used.entry(rule.id).or_default() += 1;
                    if show_approved {
                        println!(
                            "     approved {} at {} {pointer}\n         oracle: {oracle}\n         rust:   {rust}",
                            rule.id,
                            shown.display()
                        );
                    }
                }
                None => unexplained.push((pointer, oracle, rust)),
            }
        }
        let objects = rust
            .get("objects")
            .and_then(Json::as_object)
            .map_or(0, |families| {
                families
                    .values()
                    .filter_map(Json::as_array)
                    .map(Vec::len)
                    .sum()
            });
        let errors = rust
            .get("load_errors")
            .and_then(Json::as_array)
            .map_or(0, Vec::len);
        if unexplained.is_empty() {
            println!(
                "ok   {:<60} {objects} object(s), {errors} load error(s)",
                shown.display()
            );
        } else {
            failed += 1;
            println!(
                "FAIL {} ({} difference(s))",
                shown.display(),
                unexplained.len()
            );
            for (pointer, oracle, rust) in unexplained.iter().take(20) {
                println!(
                    "       {pointer}\n         oracle: {}\n         rust:   {}",
                    serde_json::to_string(oracle)?,
                    serde_json::to_string(rust)?
                );
            }
        }
    }
    drop(guard);
    println!(
        "approved {:<22} {} file(s): {}",
        INVALID_DATES.0,
        used.get(INVALID_DATES.0).copied().unwrap_or(0),
        INVALID_DATES.2
    );
    for rule in APPROVED {
        println!(
            "approved {:<22} {} difference(s): {}",
            rule.id,
            used.get(rule.id).copied().unwrap_or(0),
            rule.changelog
        );
    }
    let stale: Vec<&str> = APPROVED
        .iter()
        .map(|rule| rule.id)
        .chain([INVALID_DATES.0])
        .filter(|id| !used.contains_key(id))
        .collect();
    if corpus == "all" && !stale.is_empty() {
        println!(
            "stale approved rule(s), explaining nothing: {}",
            stale.join(", ")
        );
        failed += 1;
    }
    println!(
        "registry diff --against python: {} workspaces, {} equal, {failed} differ",
        workspaces.len(),
        workspaces.len().saturating_sub(failed)
    );
    Ok(u8::from(failed > 0))
}

/// Every difference between `oracle` and `rust`, by JSON pointer: object
/// keys compared as sets, arrays position by position.
pub fn diff(pointer: &str, oracle: &Json, rust: &Json, out: &mut Vec<(String, Json, Json)>) {
    match (oracle, rust) {
        (Json::Object(a), Json::Object(b)) => {
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => diff(&child, x, y, out),
                    (x, y) => out.push((
                        child,
                        x.cloned().unwrap_or(json!("(absent)")),
                        y.cloned().unwrap_or(json!("(absent)")),
                    )),
                }
            }
        }
        (Json::Array(a), Json::Array(b)) if a.len() == b.len() => {
            for (index, (x, y)) in a.iter().zip(b).enumerate() {
                diff(&format!("{pointer}/{index}"), x, y, out);
            }
        }
        _ if oracle == rust => {}
        _ => out.push((pointer.to_owned(), oracle.clone(), rust.clone())),
    }
}

/// The Rust index of `workspace`, as `registry_export.py` writes the
/// oracle's: `--repo` and the working directory are the workspace.
pub fn rust_result(workspace: &Path) -> Json {
    let options = opentide_workspace::Options {
        roots: RootOptions {
            repo: Some(workspace.to_path_buf()),
            cwd: workspace.to_path_buf(),
            ..RootOptions::default()
        },
    };
    match Workspace::open(Arc::new(OsFs), options) {
        Ok(loaded) => loaded.index().to_json(loaded.root()),
        Err(error) => json!({"error": {"code": error.code()}}),
    }
}

fn run_oracle_script(python: &Path, workspaces: &[PathBuf]) -> Result<BTreeMap<String, Json>> {
    let script = repo_root().join("xtask/oracle/registry_export.py");
    let mut results = BTreeMap::new();
    for chunk in workspaces.chunks(32) {
        let output = Command::new(python)
            .arg("-I")
            .arg(&script)
            .args(chunk)
            .env_remove("OPENTIDE_TIDE_WORKSPACE")
            .env_remove("OPENTIDE_REPO_ROOT")
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

/// The `edges` workspace: one file per loading rule.
pub const EDGES: &[(&str, &[u8])] = &[
    ("objects/threats/t1.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  name: T1\nthreat:\n  chaining:\n    - relation: precedes\n      vector: 00000000-0000-4000-8000-000000000002\n    - relation: precedes\n      vector: 00000000-0000-4000-8000-000000000002\n    - relation: ''\n      vector: x\n    - vector: no-relation\n    - text\n"),
    ("objects/threats/t2.yml", b"\xef\xbb\xbfmetadata:\n  uuid: 00000000-0000-4000-8000-000000000002\n  name: T2 with a BOM, .yml\n"),
    ("objects/threats/t1-copy.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000001\n  name: duplicate of T1, read after it\n"),
    ("objects/threats/top-level-uuid.yaml", b"uuid: 00000000-0000-4000-8000-000000000003\nmetadata:\n  uuid: 00000000-0000-4000-8000-00000000ffff\n"),
    ("objects/threats/empty-uuid.yaml", b"uuid: ''\nmetadata:\n  uuid: 00000000-0000-4000-8000-000000000004\n"),
    ("objects/threats/no-uuid.yaml", b"metadata:\n  name: nothing\n"),
    ("objects/threats/list-uuid.yaml", b"metadata:\n  uuid: []\n"),
    ("objects/threats/int-uuid.yaml", b"metadata:\n  uuid: 12345\n"),
    ("objects/threats/empty.yaml", b""),
    ("objects/threats/comment.yaml", b"# nothing but a comment\n"),
    ("objects/threats/list.yaml", b"- a\n- b\n"),
    ("objects/threats/text.yaml", b"just text\n"),
    ("objects/threats/number.yaml", b"42\n"),
    ("objects/threats/latin1.yaml", b"metadata:\n  name: caf\xe9\n"),
    ("objects/threats/bom-latin1.yaml", b"\xef\xbb\xbfname: \xff\n"),
    ("objects/threats/syntax.yaml", b"metadata: [unclosed\n"),
    ("objects/threats/duplicate-key.yaml", b"metadata:\n  uuid: a\n  uuid: b\n"),
    ("objects/threats/tab.yaml", b"metadata:\n\tuuid: x\n"),
    ("objects/threats/UPPER.YAML", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000aa\n"),
    ("objects/threats/scratch.debug.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000ab\n"),
    ("objects/threats/scratch.debug.yml", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000ac\n"),
    ("objects/threats/notes.md", b"not an object\n"),
    ("objects/threats/team/nested.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000ad\n"),
    ("objects/threats/team/deeper/nested.yml", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000ae\n"),
    ("objects/threats/.hidden/h.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-0000000000af\n"),
    ("objects/objectives/o1.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000101\nobjective:\n  threats:\n    - 00000000-0000-4000-8000-000000000001\n    - 99999999-0000-4000-8000-000000000000\n    - 7\n  signals:\n    - uuid: 00000000-0000-4000-8000-000000000201\n      name: s1\n    - uuid: 00000000-0000-4000-8000-000000000201\n      name: s1 again in the same objective\n    - uuid: ''\n    - name: no uuid\n    - plain text\n    - uuid: 00000000-0000-4000-8000-000000000202\n      parent: 00000000-0000-4000-8000-000000000201\n      owner: written by hand\n"),
    ("objects/objectives/o2.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000102\nobjective:\n  signals:\n    - uuid: 00000000-0000-4000-8000-000000000201\n      name: s1 in another objective\n    - uuid: 00000000-0000-4000-8000-000000000203\n"),
    ("objects/objectives/o3.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000103\nobjective: null\n"),
    ("objects/objectives/o4.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000104\nobjective:\n  threats: []\n  signals: not a list\n"),
    ("objects/rules/r1.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000301\ndetection_model: 00000000-0000-4000-8000-000000000101\n"),
    ("objects/rules/r2.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000302\ndetection_model: 00000000-0000-4000-8000-000000000201\n"),
    ("objects/rules/r3.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000303\ndetection_model: [a, b]\n"),
    ("objects/rules/r4.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000304\ndetection_model: ''\n"),
    ("objects/rules/r5.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000101\nname: a rule with an objective's UUID\n"),
    ("objects/rules/r6.yaml", b"metadata:\n  uuid: 00000000-0000-4000-8000-000000000306\n  created: 2026-01-02\n  modified: 2026-01-02 10:30:00\n  flag: yes\n  float: 1.5\n  inf: .inf\n  nested: {a: [1, 2, {b: null}]}\n"),
];

fn write_edges(dir: &Path) -> Result<()> {
    for (path, bytes) in EDGES {
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, bytes)?;
    }
    std::fs::create_dir_all(dir.join(".opentide"))?;
    // A folder named like an object is not one.
    std::fs::create_dir_all(dir.join("objects/rules/folder.yaml"))?;
    Ok(())
}

/// Every fixture of `tests/golden/cases.toml`, `edges`, and a workspace whose
/// `paths.toml` moves its folders, under `scratch`.
fn fixture_workspaces(scratch: &Path) -> Result<Vec<PathBuf>> {
    let root = repo_root();
    let spec = crate::golden::case::Spec::parse(&std::fs::read_to_string(
        root.join("tests/golden/cases.toml"),
    )?)?;
    let mut found = Vec::new();
    for (name, fixture) in &spec.fixtures {
        let dir = scratch.join("fixtures").join(name);
        std::fs::create_dir_all(&dir)?;
        fixture
            .materialise(&root, &dir)
            .with_context(|| format!("materialise {name}"))?;
        found.push(dir);
    }
    let edges = scratch.join("fixtures").join("edges");
    write_edges(&edges)?;
    found.push(edges);
    // A child workspace: its folders come from the parent instance's paths.toml.
    let parent = scratch.join("fixtures").join("parent");
    std::fs::create_dir_all(parent.join(".opentide/configurations"))?;
    std::fs::write(
        parent.join(".opentide/configurations/paths.toml"),
        "[paths.objects]\nrule = \"detections/\"\nthreat = \"missing/\"\n",
    )?;
    let child = parent.join("child");
    write_edges(&child)?;
    std::fs::create_dir_all(child.join("detections"))?;
    std::fs::write(
        child.join("detections/d.yaml"),
        "metadata:\n  uuid: 00000000-0000-4000-8000-000000000401\n",
    )?;
    found.push(child);
    // A paths.toml that does not fit its model stops the load.
    let broken = scratch.join("fixtures").join("broken-paths");
    std::fs::create_dir_all(broken.join(".opentide/configurations"))?;
    std::fs::write(
        broken.join(".opentide/configurations/paths.toml"),
        "[paths.objects]\nrule = 5\n",
    )?;
    found.push(broken);
    Ok(found)
}

/// The heavy workspace and the generator's three layouts, under `scratch`.
fn generated_workspaces(scratch: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let heavy = scratch.join("generated").join("heavy");
    write_workspace(&generate::generate(&Options::new(HEAVY_SEED)), &heavy)?;
    found.push(heavy);
    for (name, layout) in [
        ("standard", Layout::Standard),
        ("explicit", Layout::Explicit),
        ("custom", Layout::Custom),
    ] {
        let options = Options {
            seed: 1,
            counts: Counts {
                threats: 20,
                objectives: 20,
                rules: 30,
            },
            layout,
        };
        let dir = scratch.join("generated").join(name);
        write_workspace(&generate::generate(&options), &dir)?;
        found.push(dir);
    }
    Ok(found)
}

/// The fault catalogue's base with each kind applied alone, under `scratch`.
fn fault_workspaces(scratch: &Path, catalogue: &faults::Catalogue) -> Result<Vec<PathBuf>> {
    let base = generate::generate(&catalogue.base.options()?);
    let mut found = Vec::new();
    for kind in &catalogue.kinds {
        let mut workspace = base.clone();
        let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
        faults::apply(&mut workspace, kind, &targets)?;
        let dir = scratch.join("faults").join(&kind.id);
        write_workspace(&workspace, &dir)?;
        found.push(dir);
    }
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
        assert!(run(&args(&["diff", "--keep"])).is_err());
        assert_eq!(run(&args(&["help"])).unwrap(), 0);
    }

    #[test]
    fn differences_are_found_by_pointer() {
        let mut out = Vec::new();
        diff(
            "",
            &json!({"a": [1, 2], "b": {"c": "x"}, "only": 1, "list": [1]}),
            &json!({"a": [1, 3], "b": {"c": "x"}, "list": [1, 2]}),
            &mut out,
        );
        assert_eq!(
            out,
            [
                ("/a/1".to_owned(), json!(2), json!(3)),
                ("/list".to_owned(), json!([1]), json!([1, 2])),
                ("/only".to_owned(), json!(1), json!("(absent)")),
            ]
        );
    }

    #[test]
    fn approved_rules_apply_only_where_they_say() {
        let rule = |id: &str| APPROVED.iter().find(|rule| rule.id == id).unwrap();
        let yaml = rule("yaml-error-text");
        assert!((yaml.applies)(
            "/load_errors/0/error",
            &json!("did not find expected ',' or ']' at line 2, column 1 (while parsing)"),
            &json!("while parsing a flow sequence, expected ',' or ']' at line 2, column 1"),
        ));
        assert!(!(yaml.applies)(
            "/load_errors/0/error",
            &json!("did not find expected ',' or ']' at line 3, column 1"),
            &json!("while parsing a flow sequence, expected ',' or ']' at line 2, column 1"),
        ));
        assert!((yaml.applies)(
            "/load_errors/0/error",
            &json!(
                "found a tab at line 52, column 1 (while scanning a plain scalar that starts at line 51, column 18)"
            ),
            &json!("while scanning a plain scalar, found a tab at line 51, column 18"),
        ));
        assert!(!(yaml.applies)(
            "/load_errors/0/error",
            &json!("expected a mapping at the top of the file, found a list"),
            &json!("x at line 1, column 1"),
        ));
        assert!(!(yaml.applies)(
            "/bodies/x",
            &json!("a"),
            &json!("b at line 1")
        ));
        let scalar = rule("yaml-1-2-scalars");
        assert!((scalar.applies)(
            "/bodies/rule/x/flag",
            &json!(true),
            &json!("yes")
        ));
        assert!((scalar.applies)(
            "/bodies/rule/x/off",
            &json!(false),
            &json!("off")
        ));
        assert!(!(scalar.applies)(
            "/bodies/rule/x/flag",
            &json!(false),
            &json!("yes")
        ));
        assert!((scalar.applies)(
            "/signals/x/modified",
            &json!("2026-01-02T10:30:00"),
            &json!("2026-01-02 10:30:00"),
        ));
        assert!(
            (scalar.applies)(
                "/bodies/rule/x/modified",
                &json!("2026-01-02T10:30:00Z"),
                &json!("2026-01-02 10:30:00 +00:00"),
            ) || (scalar.applies)(
                "/bodies/rule/x/modified",
                &json!("2026-01-02T10:30:00+00:00"),
                &json!("2026-01-02 10:30:00+00:00"),
            )
        );
        assert!(!(scalar.applies)(
            "/load_errors/0/error",
            &json!(true),
            &json!("yes")
        ));
        assert!(!(scalar.applies)("/bodies/x", &json!("a"), &json!("b")));
    }

    #[test]
    fn the_rust_side_of_the_edges_workspace() {
        let dir = tempfile::tempdir().unwrap();
        write_edges(dir.path()).unwrap();
        let result = rust_result(&std::fs::canonicalize(dir.path()).unwrap());
        assert_eq!(
            result["objects"]["threat"],
            json!([
                "00000000-0000-4000-8000-000000000004",
                "12345",
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                "00000000-0000-4000-8000-000000000003"
            ])
        );
        assert_eq!(result["nested"].as_array().unwrap().len(), 3);
        assert_eq!(
            result["duplicates"][0]["path"],
            "objects/threats/t1-copy.yaml"
        );
        assert_eq!(
            result["duplicates"][0]["message"],
            "UUID 00000000-0000-4000-8000-000000000001 is also used by objects/threats/t1.yaml"
        );
    }
}
