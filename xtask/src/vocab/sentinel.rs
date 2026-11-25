//! `cargo xtask vocab sentinel-attack [--check] [--stix-dir DIR]`: the ATT&CK
//! ids Microsoft Sentinel accepts (`src/opentide/data/sentinel/attack-v18.json`,
//! read by `opentide_schema::vocab::sentinel`), generated from MITRE's STIX
//! bundles of ATT&CK 18.1 and of the release the `att&ck` vocabulary pins.
//!
//! Every technique and sub-technique of the Enterprise, Mobile and ICS
//! matrices that is neither revoked nor deprecated, a sub-technique's name
//! prefixed with its parent's; the ids ATT&CK retired before v18, each with
//! the v18 ids that replaced it; and the newer release's ids that v18 lacks,
//! each with the v18 ids it replaced. Revocations are followed through every
//! hop, so an id revoked twice still names its v18 counterpart.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use opentide_schema::vocab::sentinel::{Later, Newer, Retired, SentinelAttack};
use serde_json::Value;

/// The ATT&CK release Sentinel is aligned to.
pub const RELEASE: &str = "18.1";
/// The matrices.
pub const DOMAINS: [&str; 3] = ["enterprise", "mobile", "ics"];
/// Where a bundle is downloaded from.
pub const SOURCE: &str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack-{release}.json";
/// What writes the file.
pub const GENERATOR: &str = "cargo xtask vocab sentinel-attack";

/// One release's techniques across the three matrices.
#[derive(Debug, Default)]
pub struct Release {
    /// Active ids to their names, a sub-technique's prefixed with its parent's.
    pub names: BTreeMap<String, String>,
    /// Revoked or deprecated ids to their names.
    pub retired: BTreeMap<String, String>,
    /// Each revoked id to the ids its revoked-by relationships name.
    pub revoked_by: BTreeMap<String, BTreeSet<String>>,
}

impl Release {
    /// The active ids `id` was revoked in favour of, through every hop, sorted.
    pub fn successors(&self, id: &str) -> Vec<String> {
        let mut found = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut todo = vec![id.to_owned()];
        while let Some(current) = todo.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if current != id && self.names.contains_key(&current) {
                found.insert(current);
                continue;
            }
            if let Some(next) = self.revoked_by.get(&current) {
                todo.extend(next.iter().cloned());
            }
        }
        found.into_iter().collect()
    }

    /// Reads the bundles of one release, `bundles` being each matrix's STIX
    /// objects.
    pub fn from_objects<'a>(bundles: impl IntoIterator<Item = &'a [Value]>) -> Self {
        let mut release = Self::default();
        let mut by_stix: BTreeMap<String, String> = BTreeMap::new();
        let mut relationships: Vec<(String, String)> = Vec::new();
        let mut raw: IndexMap<String, String> = IndexMap::new();
        for objects in bundles {
            for object in objects {
                let kind = object.get("type").and_then(Value::as_str);
                if kind == Some("relationship")
                    && object.get("relationship_type").and_then(Value::as_str) == Some("revoked-by")
                {
                    if let (Some(source), Some(target)) = (
                        object.get("source_ref").and_then(Value::as_str),
                        object.get("target_ref").and_then(Value::as_str),
                    ) {
                        relationships.push((source.to_owned(), target.to_owned()));
                    }
                    continue;
                }
                if kind != Some("attack-pattern") {
                    continue;
                }
                let Some(id) = mitre_id(object).filter(|id| is_technique_id(id)) else {
                    continue;
                };
                if let Some(stix) = object.get("id").and_then(Value::as_str) {
                    by_stix.insert(stix.to_owned(), id.clone());
                }
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                let flag = |key: &str| object.get(key).and_then(Value::as_bool) == Some(true);
                if flag("revoked") || flag("x_mitre_deprecated") {
                    release.retired.entry(id).or_insert(name);
                } else {
                    raw.entry(id).or_insert(name);
                }
            }
        }
        for (id, name) in &raw {
            let name = match id.split_once('.') {
                Some((parent, _)) if raw.contains_key(parent) => format!("{}: {name}", raw[parent]),
                _ => name.clone(),
            };
            release.names.insert(id.clone(), name);
        }
        // An id can be active in one matrix and retired in another: active wins.
        release
            .retired
            .retain(|id, _| !release.names.contains_key(id));
        for (source, target) in relationships {
            if let (Some(source), Some(target)) = (by_stix.get(&source), by_stix.get(&target)) {
                release
                    .revoked_by
                    .entry(source.clone())
                    .or_default()
                    .insert(target.clone());
            }
        }
        release
    }
}

/// `T1234` or `T1234.567`.
fn is_technique_id(id: &str) -> bool {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    match id.strip_prefix('T') {
        Some(rest) => match rest.split_once('.') {
            Some((technique, sub)) => digits(technique, 4) && digits(sub, 3),
            None => digits(rest, 4),
        },
        None => false,
    }
}

/// The object's ATT&CK id: its `mitre-attack` external reference's.
fn mitre_id(object: &Value) -> Option<String> {
    object
        .get("external_references")?
        .as_array()?
        .iter()
        .find_map(|reference| {
            (reference.get("source_name")?.as_str()? == "mitre-attack")
                .then(|| reference.get("external_id")?.as_str())
                .flatten()
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
        })
}

/// The STIX objects of a bundle document: a list, or a `bundle` with
/// `objects`.
pub fn objects(document: Value) -> Result<Vec<Value>> {
    match document {
        Value::Array(objects) => Ok(objects),
        Value::Object(mut map) => match map.remove("objects") {
            Some(Value::Array(objects)) => Ok(objects),
            _ => bail!("unrecognised STIX bundle format"),
        },
        _ => bail!("unrecognised STIX bundle format"),
    }
}

/// The list, from ATT&CK 18.1 (`v18`) and the vocabulary's release (`later`).
pub fn document(v18: &Release, later: &Release, later_release: &str) -> SentinelAttack {
    let mut replaces: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for old in v18.names.keys() {
        for new in later.successors(old) {
            replaces.entry(new).or_default().insert(old.clone());
        }
    }
    SentinelAttack {
        attack: RELEASE.to_owned(),
        domains: DOMAINS.iter().map(|d| (*d).to_owned()).collect(),
        source: SOURCE.replace("{release}", RELEASE),
        generator: GENERATOR.to_owned(),
        techniques: v18
            .names
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        retired: v18
            .retired
            .iter()
            .map(|(id, name)| {
                let replaced_by = v18
                    .successors(id)
                    .into_iter()
                    .filter(|new| v18.names.contains_key(new))
                    .collect();
                (
                    id.clone(),
                    Retired {
                        name: name.clone(),
                        replaced_by,
                    },
                )
            })
            .collect(),
        later: Later {
            attack: later_release.to_owned(),
            techniques: later
                .names
                .iter()
                .filter(|(id, _)| !v18.names.contains_key(*id))
                .map(|(id, name)| {
                    (
                        id.clone(),
                        Newer {
                            name: name.clone(),
                            replaces: replaces
                                .get(id)
                                .map(|set| set.iter().cloned().collect())
                                .unwrap_or_default(),
                        },
                    )
                })
                .collect(),
        },
    }
}

/// The file's text: one-space indents, UTF-8 as is, a final newline.
pub fn text(list: &SentinelAttack) -> Result<String> {
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    serde::Serialize::serialize(list, &mut serializer)?;
    Ok(String::from_utf8(bytes)? + "\n")
}

fn bundle_path(dir: &Path, domain: &str, release: &str) -> PathBuf {
    dir.join(format!("{domain}-attack"))
        .join(format!("{domain}-attack-{release}.json"))
}

fn load_release(dir: &Path, release: &str) -> Result<Release> {
    let mut bundles = Vec::new();
    for domain in DOMAINS {
        let path = bundle_path(dir, domain, release);
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let document: Value =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        bundles.push(objects(document).with_context(|| path.display().to_string())?);
    }
    Ok(Release::from_objects(bundles.iter().map(Vec::as_slice)))
}

/// curl's options for a bundle: HTTPS only, redirects included (the bundles
/// become committed package data), TLS 1.2 or later, failing on an HTTP error.
const CURL: [&str; 11] = [
    "--fail",
    "--silent",
    "--show-error",
    "--location",
    "--proto",
    "=https",
    "--proto-redir",
    "=https",
    "--tlsv1.2",
    "--max-time",
    "300",
];

fn download(dir: &Path, releases: &[&str]) -> Result<()> {
    for release in releases {
        for domain in DOMAINS {
            let url = SOURCE
                .replace("{domain}", domain)
                .replace("{release}", release);
            let path = bundle_path(dir, domain, release);
            fs::create_dir_all(path.parent().context("a bundle path has a parent")?)?;
            let status = Command::new("curl")
                .args(CURL)
                .arg("--output")
                .arg(&path)
                .arg(&url)
                .status()
                .context("run curl to download the STIX bundles (or pass --stix-dir)")?;
            ensure!(status.success(), "download {url} failed ({status})");
        }
    }
    Ok(())
}

/// The ATT&CK release the `att&ck` vocabulary at `path` was built from
/// (its `source_version`): the `later` table's.
pub fn vocabulary_release(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let vocabulary = opentide_schema::vocab::Vocabulary::from_file("att&ck.vocab.toml", &text)?;
    Ok(vocabulary
        .metadata
        .extra
        .get("source_version")
        .and_then(toml::Value::as_str)
        .context("att&ck.vocab.toml has no source_version")?
        .to_owned())
}

/// The list from the bundles in `stix_dir` (`{domain}-attack/{domain}-attack-{release}.json`).
pub fn generate(stix_dir: &Path, later_release: &str) -> Result<SentinelAttack> {
    Ok(document(
        &load_release(stix_dir, RELEASE)?,
        &load_release(stix_dir, later_release)?,
        later_release,
    ))
}

/// Writes `output`, or with `check` compares it, from the bundles in
/// `stix_dir` (downloaded when `None`). Whether it passed.
pub fn run(vocabulary: &Path, output: &Path, stix_dir: Option<&Path>, check: bool) -> Result<bool> {
    let later_release = vocabulary_release(vocabulary)?;
    let scratch;
    let dir = match stix_dir {
        Some(dir) => dir.to_path_buf(),
        None => {
            scratch = tempfile::tempdir()?;
            download(scratch.path(), &[RELEASE, &later_release])?;
            scratch.path().to_path_buf()
        }
    };
    let list = generate(&dir, &later_release)?;
    let expected = text(&list)?;
    // A missing file is stale; one that cannot be read is an error, not stale.
    let current = match fs::read_to_string(output) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", output.display()));
        }
    };
    if check {
        if current == expected {
            println!("{} is current", output.display());
            return Ok(true);
        }
        eprintln!("error: {} is stale", output.display());
        eprintln!("  help: cargo xtask vocab sentinel-attack");
        return Ok(false);
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, &expected).with_context(|| format!("write {}", output.display()))?;
    println!(
        "wrote {} ({} ids, ATT&CK {RELEASE})",
        output.display(),
        list.techniques.len()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn technique(id: &str, name: &str, flag: Option<&str>) -> Value {
        let mut object = json!({
            "type": "attack-pattern",
            "id": format!("attack-pattern--{id}"),
            "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": id}],
        });
        if let Some(flag) = flag {
            object[flag] = json!(true);
        }
        object
    }

    fn revoked_by(old: &str, new: &str) -> Value {
        json!({
            "type": "relationship",
            "relationship_type": "revoked-by",
            "source_ref": format!("attack-pattern--{old}"),
            "target_ref": format!("attack-pattern--{new}"),
        })
    }

    fn write(stix: &Path, release: &str, objects: &[Value]) {
        for domain in DOMAINS {
            let path = bundle_path(stix, domain, release);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let bundle = if domain == "enterprise" {
                objects.to_vec()
            } else {
                Vec::new()
            };
            fs::write(
                path,
                json!({"type": "bundle", "objects": bundle}).to_string(),
            )
            .unwrap();
        }
    }

    /// Synthetic bundles: ATT&CK 18.1 and a later 20.0.
    fn stix() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "18.1",
            &[
                technique("T1556", "Modify Authentication Process", None),
                technique("T1556.009", "Conditional Access Policies", None),
                technique("T1059", "Command and Scripting Interpreter", None),
                technique("T1059.001", "PowerShell", None),
                technique("T1562", "Impair Defenses", None),
                // Retired before v18: one revoked (twice over), one deprecated.
                technique("T1086", "PowerShell", Some("revoked")),
                technique("T1999", "Old PowerShell", Some("revoked")),
                revoked_by("T1086", "T1999"),
                revoked_by("T1999", "T1059.001"),
                technique("T1064", "Scripting", Some("x_mitre_deprecated")),
                json!({"type": "x-mitre-tactic", "id": "x-mitre-tactic--1"}),
            ],
        );
        write(
            dir.path(),
            "20.0",
            &[
                technique("T1556", "Modify Authentication Process", None),
                technique("T1556.009", "Conditional Access Policies", None),
                technique("T1059", "Command and Scripting Interpreter", None),
                technique("T1059.001", "PowerShell", None),
                // T1562 revoked by an intermediate id, itself revoked by T1685.
                technique("T1562", "Impair Defenses", Some("revoked")),
                technique("T1680", "Interim", Some("revoked")),
                technique("T1685", "Disable or Modify Tools", None),
                revoked_by("T1562", "T1680"),
                revoked_by("T1680", "T1685"),
                technique("T1696", "Anti-Automation Evasion", None),
            ],
        );
        dir
    }

    fn pairs<'a>(
        map: impl IntoIterator<Item = (&'a String, &'a String)>,
    ) -> Vec<(&'a str, &'a str)> {
        map.into_iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    #[test]
    fn techniques_are_the_active_v18_ids_with_parent_prefixed_names() {
        let stix = stix();
        let list = generate(stix.path(), "20.0").unwrap();
        assert_eq!(
            pairs(&list.techniques),
            [
                ("T1059", "Command and Scripting Interpreter"),
                ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
                ("T1556", "Modify Authentication Process"),
                (
                    "T1556.009",
                    "Modify Authentication Process: Conditional Access Policies"
                ),
                ("T1562", "Impair Defenses"),
            ]
        );
    }

    #[test]
    fn a_later_id_names_the_v18_id_through_every_revocation() {
        let stix = stix();
        let later = generate(stix.path(), "20.0").unwrap().later;
        assert_eq!(later.attack, "20.0");
        let rows: Vec<(&str, &str, Vec<String>)> = later
            .techniques
            .iter()
            .map(|(id, n)| (id.as_str(), n.name.as_str(), n.replaces.clone()))
            .collect();
        assert_eq!(
            rows,
            [
                ("T1685", "Disable or Modify Tools", vec!["T1562".to_owned()]),
                ("T1696", "Anti-Automation Evasion", vec![]),
            ]
        );
    }

    #[test]
    fn retired_ids_name_their_v18_replacement_or_none() {
        let stix = stix();
        let retired = generate(stix.path(), "20.0").unwrap().retired;
        let rows: Vec<(&str, &str, Vec<String>)> = retired
            .iter()
            .map(|(id, r)| (id.as_str(), r.name.as_str(), r.replaced_by.clone()))
            .collect();
        assert_eq!(
            rows,
            [
                ("T1064", "Scripting", vec![]),
                ("T1086", "PowerShell", vec!["T1059.001".to_owned()]),
                ("T1999", "Old PowerShell", vec!["T1059.001".to_owned()]),
            ]
        );
    }

    #[test]
    fn check_reports_a_stale_file_and_accepts_a_current_one() {
        let stix = stix();
        let dir = tempfile::tempdir().unwrap();
        let vocabulary = dir.path().join("att&ck.vocab.toml");
        fs::write(
            &vocabulary,
            "name = \"ATT&CK\"\nfield = \"att&ck\"\nsource_version = \"20.0\"\n",
        )
        .unwrap();
        let output = dir.path().join("out/attack-v18.json");
        assert!(!run(&vocabulary, &output, Some(stix.path()), true).unwrap());
        assert!(run(&vocabulary, &output, Some(stix.path()), false).unwrap());
        assert!(run(&vocabulary, &output, Some(stix.path()), true).unwrap());
        let text = fs::read_to_string(&output).unwrap();
        assert!(text.starts_with("{\n \"attack\": \"18.1\",\n \"domains\": [\n  \"enterprise\""));
    }

    #[test]
    fn an_unreadable_output_is_an_error_not_stale() {
        let stix = stix();
        let dir = tempfile::tempdir().unwrap();
        let vocabulary = dir.path().join("att&ck.vocab.toml");
        fs::write(
            &vocabulary,
            "name = \"ATT&CK\"\nfield = \"att&ck\"\nsource_version = \"20.0\"\n",
        )
        .unwrap();
        let binary = dir.path().join("binary.json");
        fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
        let error = run(&vocabulary, &binary, Some(stix.path()), true).unwrap_err();
        assert!(format!("{error:#}").contains("binary.json"), "{error:#}");
        // A directory where the file should be.
        let error = run(&vocabulary, dir.path(), Some(stix.path()), true).unwrap_err();
        assert!(format!("{error:#}").starts_with("read "), "{error:#}");
    }

    #[test]
    fn bundles_download_over_https_only() {
        let args = CURL.join(" ");
        assert!(args.contains("--proto =https"), "{args}");
        assert!(args.contains("--proto-redir =https"), "{args}");
        assert!(args.contains("--tlsv1.2"), "{args}");
        assert!(args.contains("--fail"), "{args}");
    }

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    #[test]
    fn the_later_release_is_the_vocabulary_s() {
        let committed: SentinelAttack = serde_json::from_str(
            &fs::read_to_string(repo().join("src/opentide/data/sentinel/attack-v18.json")).unwrap(),
        )
        .unwrap();
        let release =
            vocabulary_release(&repo().join("src/opentide/data/vocabulary/att&ck.vocab.toml"))
                .unwrap();
        assert_eq!(committed.later.attack, release);
    }

    #[test]
    fn the_bundled_list_round_trips() {
        // The committed file is exactly what `text` writes for its content.
        let committed =
            fs::read_to_string(repo().join("src/opentide/data/sentinel/attack-v18.json")).unwrap();
        let list: SentinelAttack = serde_json::from_str(&committed).unwrap();
        assert_eq!(list.generator, GENERATOR);
        assert_eq!(text(&list).unwrap(), committed);
    }

    #[test]
    fn ids_and_bundle_formats() {
        assert!(is_technique_id("T1059"));
        assert!(is_technique_id("T1059.001"));
        assert!(!is_technique_id("T105"));
        assert!(!is_technique_id("TA0001"));
        assert!(!is_technique_id("T1059.01"));
        assert_eq!(objects(json!([{"a": 1}])).unwrap().len(), 1);
        assert_eq!(
            objects(json!({"type": "bundle", "objects": []}))
                .unwrap()
                .len(),
            0
        );
        assert!(objects(json!({"type": "bundle"})).is_err());
        assert!(objects(json!(3)).is_err());
    }
}
