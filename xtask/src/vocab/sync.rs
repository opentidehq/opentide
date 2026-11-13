//! `cargo xtask vocab sync [--check]`: the bundled vocabularies and schema
//! pins against `opentidehq/specifications`, and the lockfile that records
//! them (`data/specifications.lock.json`).
//!
//! With a specifications checkout (`OPENTIDE_SPECIFICATIONS_ROOT`, else
//! `../specifications`), `--check` fails when a bundled `*.vocab.toml` differs
//! from its source byte for byte, when a pin table differs from its source
//! table by table (comments and layout do not count), or when the lockfile
//! does not record them; without `--check` it copies the sources over the
//! bundle and rewrites the lockfile. Without a checkout, `--check` compares the
//! lockfile with the bundle alone, and a sync writes a baseline lockfile.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::golden::blob::sha256_hex;

/// The variable naming the specifications checkout.
pub const SPECIFICATIONS_ENV: &str = "OPENTIDE_SPECIFICATIONS_ROOT";
/// The `specifications_git_sha` of a lockfile written without a checkout.
pub const BASELINE_SHA: &str = "baseline-bundled-state";
/// Lockfile keys that record provenance only: `--check` ignores them.
const PROVENANCE_KEYS: [&str; 1] = ["specifications_git_sha"];

/// `[schema::M.m]` → field path → `vocabulary::M.m`.
pub type PinTables = BTreeMap<String, BTreeMap<String, String>>;

/// The places a sync reads and writes.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `specifications/vocabularies`.
    pub source_vocabularies: PathBuf,
    /// `src/opentide/data/vocabulary`.
    pub target_vocabularies: PathBuf,
    /// `specifications/schemas/pins`.
    pub source_pins: PathBuf,
    /// `src/opentide/data/pins`.
    pub target_pins: PathBuf,
    /// `data/specifications.lock.json`.
    pub lockfile: PathBuf,
    /// The specifications checkout.
    pub specifications: PathBuf,
}

impl Paths {
    /// The paths of the repository at `repo`, with the checkout at
    /// `specifications`.
    pub fn new(repo: &Path, specifications: &Path) -> Self {
        Self {
            source_vocabularies: specifications.join("vocabularies"),
            target_vocabularies: repo.join("src/opentide/data/vocabulary"),
            source_pins: specifications.join("schemas/pins"),
            target_pins: repo.join("src/opentide/data/pins"),
            lockfile: repo.join("data/specifications.lock.json"),
            specifications: specifications.to_path_buf(),
        }
    }
}

/// The files of `dir` whose name ends with `suffix`, by name; none when the
/// directory does not exist.
pub fn list(dir: &Path, suffix: &str) -> Result<BTreeMap<String, PathBuf>> {
    let mut files = BTreeMap::new();
    if !dir.is_dir() {
        return Ok(files);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_file() && name.ends_with(suffix) {
            files.insert(name, entry.path());
        }
    }
    Ok(files)
}

/// The digest of a set of vocabulary files: SHA-256 over each name and its
/// bytes, each followed by a NUL, in name order.
pub fn vocabulary_digest(files: &BTreeMap<String, PathBuf>) -> Result<String> {
    let mut bytes = Vec::new();
    for (name, path) in files {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend(fs::read(path).with_context(|| format!("read {}", path.display()))?);
        bytes.push(0);
    }
    Ok(sha256_hex(&bytes))
}

/// The pin tables of one file: each top-level table, with its values as text.
pub fn pin_tables(path: &Path) -> Result<PinTables> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let document: toml::Table =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(document
        .into_iter()
        .filter_map(|(section, value)| match value {
            toml::Value::Table(table) => Some((
                section,
                table
                    .into_iter()
                    .map(|(key, value)| {
                        let text = match value {
                            toml::Value::String(text) => text,
                            other => other.to_string(),
                        };
                        (key, text)
                    })
                    .collect(),
            )),
            _ => None,
        })
        .collect())
}

/// The digest of a set of pin files' tables: SHA-256 of their JSON, keys
/// sorted, in the lockfile's canonical form ([`canonical_json`]).
pub fn pins_digest(files: &BTreeMap<String, PathBuf>) -> Result<String> {
    let mut tables = BTreeMap::new();
    for (name, path) in files {
        tables.insert(name.clone(), pin_tables(path)?);
    }
    let value = serde_json::to_value(tables)?;
    Ok(sha256_hex(canonical_json(&value).as_bytes()))
}

/// JSON with object keys sorted, `", "` between items and `": "` after keys,
/// and every non-ASCII character escaped as `\uXXXX` (UTF-16): the form the
/// lockfile's `bundled_pins_sha256` digests, kept so a lockfile written
/// before this tool still checks.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (n, key) in keys.into_iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                write_string(key, out);
                out.push_str(": ");
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// The lockfile's content.
pub fn lock_payload(
    sha: &str,
    vocabulary_digest: &str,
    vocabularies: &BTreeMap<String, PathBuf>,
    pins_digest: &str,
    pins: &BTreeMap<String, PathBuf>,
) -> Value {
    json!({
        "lock_version": 2,
        "specifications_repo": "opentidehq/specifications",
        "specifications_git_sha": sha,
        "source_glob": "vocabularies/*.vocab.toml",
        "bundled_vocabulary_sha256": vocabulary_digest,
        "managed_files": vocabularies.keys().collect::<Vec<_>>(),
        "pins_source_glob": "schemas/pins/*.toml",
        "bundled_pins_sha256": pins_digest,
        "managed_pin_files": pins.keys().collect::<Vec<_>>(),
    })
}

/// The lockfile as written: two-space indents, keys sorted, a final newline.
pub fn lock_text(payload: &Value) -> Result<String> {
    // Sorted through a BTreeMap, whatever serde_json's map preserves.
    let sorted: BTreeMap<String, Value> = payload
        .as_object()
        .context("the lockfile is an object")?
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(serde_json::to_string_pretty(&sorted)? + "\n")
}

/// Whether two lockfiles agree on everything but provenance.
pub fn lock_matches(current: Option<&Value>, expected: &Value) -> bool {
    let content = |lock: &Value| -> Option<BTreeMap<String, Value>> {
        Some(
            lock.as_object()?
                .iter()
                .filter(|(key, _)| !PROVENANCE_KEYS.contains(&key.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    };
    current.and_then(content).is_some() && current.and_then(content) == content(expected)
}

/// How bundled pin tables (`target`) differ from the specifications'
/// (`source`), one line per difference.
pub fn diff_pin_tables(source: &PinTables, target: &PinTables) -> Vec<String> {
    let mut problems = Vec::new();
    for section in source.keys().filter(|s| !target.contains_key(*s)) {
        problems.push(format!(
            "[{section}] schema revision missing in bundled pins"
        ));
    }
    for section in target.keys().filter(|s| !source.contains_key(*s)) {
        problems.push(format!("[{section}] schema revision not in specifications"));
    }
    for (section, expected) in source {
        let Some(actual) = target.get(section) else {
            continue;
        };
        let keys: std::collections::BTreeSet<&String> =
            expected.keys().chain(actual.keys()).collect();
        for key in keys {
            match (expected.get(key), actual.get(key)) {
                (Some(want), None) => problems.push(format!(
                    "[{section}] {key}: missing (specifications pins {want})"
                )),
                (None, Some(have)) => problems.push(format!(
                    "[{section}] {key}: not in specifications (bundled pins {have})"
                )),
                (Some(want), Some(have)) if want != have => problems.push(format!(
                    "[{section}] {key}: bundled {have}, specifications {want}"
                )),
                _ => {}
            }
        }
    }
    problems
}

/// Files missing from, extra in, or different in the bundle.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drift {
    /// In the source, not in the bundle.
    pub missing: Vec<String>,
    /// In the bundle, not in the source.
    pub extra: Vec<String>,
    /// In both, different, each with what differs (empty for a vocabulary,
    /// which is compared byte for byte).
    pub changed: BTreeMap<String, Vec<String>>,
}

impl Drift {
    /// Whether anything differs.
    pub fn any(&self) -> bool {
        !(self.missing.is_empty() && self.extra.is_empty() && self.changed.is_empty())
    }

    fn report(&self, what: &str, out: &mut String) {
        if !self.any() {
            return;
        }
        let _ = writeln!(out, "{what} drift detected:");
        for name in &self.missing {
            let _ = writeln!(out, "  missing in the bundle: {name}");
        }
        for name in &self.extra {
            let _ = writeln!(out, "  not in specifications: {name}");
        }
        for (name, problems) in &self.changed {
            let _ = writeln!(out, "  differs: {name}");
            for problem in problems {
                let _ = writeln!(out, "    - {problem}");
            }
        }
    }
}

fn vocabulary_drift(
    source: &BTreeMap<String, PathBuf>,
    target: &BTreeMap<String, PathBuf>,
) -> Result<Drift> {
    let mut drift = Drift {
        missing: source
            .keys()
            .filter(|n| !target.contains_key(*n))
            .cloned()
            .collect(),
        extra: target
            .keys()
            .filter(|n| !source.contains_key(*n))
            .cloned()
            .collect(),
        changed: BTreeMap::new(),
    };
    for (name, path) in source {
        if let Some(bundled) = target.get(name)
            && fs::read(path)? != fs::read(bundled)?
        {
            drift.changed.insert(name.clone(), Vec::new());
        }
    }
    Ok(drift)
}

fn pin_drift(
    source: &BTreeMap<String, PathBuf>,
    target: &BTreeMap<String, PathBuf>,
) -> Result<Drift> {
    let mut drift = Drift {
        missing: source
            .keys()
            .filter(|n| !target.contains_key(*n))
            .cloned()
            .collect(),
        extra: target
            .keys()
            .filter(|n| !source.contains_key(*n))
            .cloned()
            .collect(),
        changed: BTreeMap::new(),
    };
    for (name, path) in source {
        if let Some(bundled) = target.get(name) {
            let problems = diff_pin_tables(&pin_tables(path)?, &pin_tables(bundled)?);
            if !problems.is_empty() {
                drift.changed.insert(name.clone(), problems);
            }
        }
    }
    Ok(drift)
}

/// The git commit of the checkout at `root`, if it is one.
fn git_sha(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    let sha = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !sha.is_empty()).then_some(sha)
}

fn read_lock(path: &Path) -> Result<Option<Value>> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text)
        .map(Some)
        .with_context(|| format!("invalid lockfile JSON: {}", path.display()))
}

/// Runs the sync, or with `check` the check, printing what it finds into
/// `out`. Whether it passed.
pub fn run(paths: &Paths, check: bool, out: &mut String) -> Result<bool> {
    let source = list(&paths.source_vocabularies, ".vocab.toml")?;
    let target = list(&paths.target_vocabularies, ".vocab.toml")?;
    let target_pins = list(&paths.target_pins, ".toml")?;
    let current = read_lock(&paths.lockfile)?;

    if source.is_empty() {
        let _ = writeln!(
            out,
            "Specifications source not found at {} (set {SPECIFICATIONS_ENV} to override).",
            paths.source_vocabularies.display()
        );
        let payload = lock_payload(
            BASELINE_SHA,
            &vocabulary_digest(&target)?,
            &target,
            &pins_digest(&target_pins)?,
            &target_pins,
        );
        if check {
            if lock_matches(current.as_ref(), &payload) {
                let _ = writeln!(
                    out,
                    "Vocabulary lockfile matches bundled vocabularies and pins."
                );
                return Ok(true);
            }
            let _ = writeln!(
                out,
                "Bundled vocabulary or pin lockfile drift detected.\nExpected lockfile at: {}",
                paths.lockfile.display()
            );
            return Ok(false);
        }
        write_lock(&paths.lockfile, &payload)?;
        let _ = writeln!(
            out,
            "Wrote baseline lockfile from bundled state: {}",
            paths.lockfile.display()
        );
        return Ok(true);
    }

    let source_pins = list(&paths.source_pins, ".toml")?;
    if source_pins.is_empty() {
        // Syncing against an empty pin directory would delete every bundled pin.
        bail!(
            "specifications schema pins not found at {}",
            paths.source_pins.display()
        );
    }
    let vocabularies = vocabulary_drift(&source, &target)?;
    let pins = pin_drift(&source_pins, &target_pins)?;
    let sha = git_sha(&paths.specifications).unwrap_or_else(|| BASELINE_SHA.to_owned());
    let payload = lock_payload(
        &sha,
        &vocabulary_digest(&source)?,
        &source,
        &pins_digest(&source_pins)?,
        &source_pins,
    );
    if check {
        if vocabularies.any() || pins.any() {
            vocabularies.report("Vocabulary", out);
            pins.report("Pin", out);
            let _ = writeln!(out, "help: cargo xtask vocab sync");
            return Ok(false);
        }
        if !lock_matches(current.as_ref(), &payload) {
            let _ = writeln!(
                out,
                "Lockfile drift detected. Re-run `cargo xtask vocab sync` to update:\n  {}",
                paths.lockfile.display()
            );
            return Ok(false);
        }
        let _ = writeln!(
            out,
            "Vocabulary sync check passed (source, pins and lockfile are in sync)."
        );
        return Ok(true);
    }

    copy_over(&source, &paths.target_vocabularies, &vocabularies, out)?;
    copy_over(&source_pins, &paths.target_pins, &pins, out)?;
    write_lock(&paths.lockfile, &payload)?;
    let _ = writeln!(out, "Wrote lockfile: {}", paths.lockfile.display());
    Ok(true)
}

fn copy_over(
    source: &BTreeMap<String, PathBuf>,
    dir: &Path,
    drift: &Drift,
    out: &mut String,
) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    for name in drift.missing.iter().chain(drift.changed.keys()) {
        fs::copy(&source[name], dir.join(name)).with_context(|| format!("copy {name}"))?;
        let _ = writeln!(out, "Updated {}", dir.join(name).display());
    }
    for name in &drift.extra {
        fs::remove_file(dir.join(name)).with_context(|| format!("remove {name}"))?;
        let _ = writeln!(out, "Removed {}", dir.join(name).display());
    }
    Ok(())
}

fn write_lock(path: &Path, payload: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, lock_text(payload)?).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_is_the_lockfile_digest_form() {
        let value = json!({"b": {"y": "1", "x": "é"}, "a": [1, "\n"]});
        assert_eq!(
            canonical_json(&value),
            r#"{"a": [1, "\n"], "b": {"x": "\u00e9", "y": "1"}}"#
        );
        assert_eq!(canonical_json(&json!("😀")), r#""\ud83d\ude00""#);
    }

    #[test]
    fn the_committed_lockfile_matches_the_bundle() {
        // The repository's own state: what `--check` without a checkout
        // compares (CI runs it with one, `ci.yml`).
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let paths = Paths::new(&repo, &repo.join("no-specifications-here"));
        let mut out = String::new();
        assert!(run(&paths, true, &mut out).unwrap(), "{out}");
    }

    fn write(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn sync_then_check_against_a_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let spec = dir.path().join("specifications");
        write(
            &spec.join("vocabularies/tlp.vocab.toml"),
            "name = \"TLP\"\n",
        );
        write(
            &spec.join("schemas/pins/rule.toml"),
            "# comment\n[\"rule::1.0\"]\n\"severity\" = \"alert_severity::1.0\"\n",
        );
        write(
            &repo.join("src/opentide/data/vocabulary/old.vocab.toml"),
            "x\n",
        );
        write(
            &repo.join("src/opentide/data/pins/rule.toml"),
            "[\"rule::1.0\"]\nseverity = \"alert_severity::1.1\"\n",
        );
        let paths = Paths::new(&repo, &spec);

        let mut out = String::new();
        assert!(!run(&paths, true, &mut out).unwrap());
        assert!(
            out.contains("missing in the bundle: tlp.vocab.toml"),
            "{out}"
        );
        assert!(
            out.contains("not in specifications: old.vocab.toml"),
            "{out}"
        );
        assert!(
            out.contains("[rule::1.0] severity: bundled alert_severity::1.1, specifications alert_severity::1.0"),
            "{out}"
        );

        let mut out = String::new();
        assert!(run(&paths, false, &mut out).unwrap(), "{out}");
        let mut out = String::new();
        assert!(run(&paths, true, &mut out).unwrap(), "{out}");
        assert!(
            !repo
                .join("src/opentide/data/vocabulary/old.vocab.toml")
                .exists()
        );

        // Pins that differ only in layout and comments still check.
        write(
            &repo.join("src/opentide/data/pins/rule.toml"),
            "[\"rule::1.0\"]\nseverity = \"alert_severity::1.0\"\n",
        );
        let mut out = String::new();
        assert!(run(&paths, true, &mut out).unwrap(), "{out}");

        // A lockfile edited by hand fails; provenance alone does not.
        let lock = repo.join("data/specifications.lock.json");
        let text = fs::read_to_string(&lock).unwrap();
        fs::write(
            &lock,
            text.replace("\"lock_version\": 2", "\"lock_version\": 3"),
        )
        .unwrap();
        let mut out = String::new();
        assert!(!run(&paths, true, &mut out).unwrap());
        assert!(out.contains("Lockfile drift"), "{out}");
    }

    #[test]
    fn an_empty_pin_source_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let spec = dir.path().join("specifications");
        write(&spec.join("vocabularies/tlp.vocab.toml"), "x\n");
        let paths = Paths::new(&dir.path().join("repo"), &spec);
        assert!(run(&paths, false, &mut String::new()).is_err());
    }

    #[test]
    fn lockfile_comparison_ignores_provenance() {
        let a = json!({"lock_version": 2, "specifications_git_sha": "abc"});
        let b = json!({"lock_version": 2, "specifications_git_sha": "def"});
        assert!(lock_matches(Some(&a), &b));
        assert!(!lock_matches(None, &b));
        assert!(!lock_matches(Some(&json!({"lock_version": 3})), &b));
    }
}
