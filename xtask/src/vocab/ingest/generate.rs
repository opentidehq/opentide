//! The five vocabularies the ingest regenerates, from the STIX bundles and
//! the MISP galaxy (`opentide.vocabulary.generate_attack` and
//! `generate_actors`): `att&ck`, `att&ck.groups`, `mitigations` and
//! `datasources` from ATT&CK, `actors` from ATT&CK's groups and MISP.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::lifecycle::{Lifecycle, merge};
use super::stix;
use super::value::{Table, Value, parse_json, parse_toml, text, to_toml, truthy};

/// The file name suffix of a vocabulary.
pub const VOCAB_SUFFIX: &str = ".vocab.toml";

/// One vocabulary's merge.
#[derive(Debug, Clone)]
pub struct Generated {
    /// The vocabulary (`att&ck`).
    pub field: String,
    /// The merge.
    pub lifecycle: Lifecycle,
    /// The document to write, keys merged and provenance stamped.
    pub document: Table,
    /// Where it goes.
    pub path: PathBuf,
}

/// One generator's run: `attack` or `actors`.
#[derive(Debug, Clone)]
pub struct Report {
    /// Each vocabulary's merge, in the order the generator writes them.
    pub vocabularies: Vec<Generated>,
    /// Whether the source's provenance (ATT&CK release, MISP digest) moved.
    pub source_changed: bool,
}

impl Report {
    /// Whether anything would change.
    pub fn dirty(&self) -> bool {
        self.source_changed || self.vocabularies.iter().any(|v| v.lifecycle.dirty())
    }

    /// Each vocabulary's new contract, by field.
    pub fn new_contracts(&self) -> Vec<(String, String)> {
        self.vocabularies
            .iter()
            .filter_map(|v| {
                v.lifecycle
                    .new_contract()
                    .map(|contract| (v.field.clone(), contract.to_owned()))
            })
            .collect()
    }

    /// Writes every document.
    pub fn write(&self) -> Result<()> {
        for vocabulary in &self.vocabularies {
            write_vocab_file(&vocabulary.path, &vocabulary.document)?;
        }
        Ok(())
    }
}

/// What the generators read besides the vocabularies.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The STIX bundles: `enterprise-attack.json`, `mobile-attack.json`,
    /// `ics-attack.json`, and `manifest.json` from the fetch.
    pub stix_dir: PathBuf,
    /// The MISP galaxy, when there is one: its URL and its bytes.
    pub misp: Option<(String, Vec<u8>)>,
    /// Every timestamp the run writes where the manifest gives none
    /// (`utc_now_iso()`).
    pub now: String,
}

/// A vocabulary's field: its file name without `.vocab.toml`.
pub fn field_of(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    match name.strip_suffix(VOCAB_SUFFIX) {
        Some(field) => Ok(field.to_owned()),
        None => bail!("Not a vocabulary file: {}", path.display()),
    }
}

/// Reads a vocabulary (`read_vocab_document`): a non-empty table whose
/// `field` is its file name's.
pub fn read_vocab_document(path: &Path) -> Result<Table> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Could not read vocabulary TOML {}", path.display()))?;
    let document = parse_toml(&text)
        .with_context(|| format!("Could not read vocabulary TOML {}", path.display()))?;
    if document.is_empty() {
        bail!("Empty vocabulary TOML file: {}", path.display());
    }
    let expected = field_of(path)?;
    if document.get("field").and_then(Value::as_str) != Some(expected.as_str()) {
        bail!(
            "Vocabulary field {} does not match filename '{expected}' in {}",
            document
                .get("field")
                .map_or_else(|| "(none)".to_owned(), Value::to_string),
            path.display()
        );
    }
    Ok(document)
}

/// Writes a vocabulary (`write_vocab_file`).
pub fn write_vocab_file(path: &Path, document: &Table) -> Result<()> {
    let Some(field) = document.get("field") else {
        bail!("Cannot write vocabulary without field: {}", path.display());
    };
    if let Ok(expected) = field_of(path)
        && field.as_str() != Some(expected.as_str())
    {
        bail!(
            "Vocabulary field {field} does not match path '{}'",
            path.display()
        );
    }
    fs::write(path, to_toml(document)?).with_context(|| format!("write {}", path.display()))
}

/// The vocabulary a generator starts from (`_load_template`), `keys`
/// defaulted to an empty list.
fn template(vocab_dir: &Path, field: &str) -> Result<Table> {
    let path = vocab_dir.join(format!("{field}{VOCAB_SUFFIX}"));
    if !path.is_file() {
        bail!("No vocabulary template for field '{field}'");
    }
    let mut document = read_vocab_document(&path)?;
    if !document.contains_key("keys") {
        document.insert("keys".to_owned(), Value::Array(Vec::new()));
    }
    Ok(document)
}

/// A document's `[[keys]]` tables.
pub fn keys_of(document: &Table) -> Vec<Table> {
    document
        .get("keys")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_object)
        .cloned()
        .collect()
}

/// Replaces a document's `[[keys]]` with a merge's.
pub fn set_keys(document: &mut Table, lifecycle: &Lifecycle) {
    document.insert(
        "keys".to_owned(),
        Value::Array(lifecycle.keys.iter().cloned().map(Value::Object).collect()),
    );
}

/// The fetch's `manifest.json`, an empty table when there is none.
fn manifest(stix_dir: &Path) -> Result<Table> {
    let path = stix_dir.join("manifest.json");
    if !path.is_file() {
        return Ok(Table::new());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    match parse_json(&bytes).with_context(|| format!("parse {}", path.display()))? {
        Value::Object(table) => Ok(table),
        _ => bail!("{} is not an object", path.display()),
    }
}

/// The bundles in `stix_dir`, each read once.
struct Bundles {
    enterprise: Vec<Value>,
    mobile: Option<Vec<Value>>,
    ics: Option<Vec<Value>>,
}

impl Bundles {
    fn load(stix_dir: &Path) -> Result<Self> {
        let enterprise = stix_dir.join("enterprise-attack.json");
        if !enterprise.is_file() {
            bail!(
                "STIX bundle not found: {}. Fetch it first (without --no-fetch).",
                enterprise.display()
            );
        }
        let optional = |name: &str| -> Result<Option<Vec<Value>>> {
            let path = stix_dir.join(name);
            if path.is_file() {
                Ok(Some(stix::load_bundle(&path)?))
            } else {
                Ok(None)
            }
        };
        Ok(Self {
            enterprise: stix::load_bundle(&enterprise)?,
            mobile: optional("mobile-attack.json")?,
            ics: optional("ics-attack.json")?,
        })
    }

    /// The present bundles in `order`, each with its prefix.
    fn ordered<'a>(&'a self, order: [(&str, &'a str); 3]) -> Vec<(&'a [Value], &'a str)> {
        order
            .into_iter()
            .filter_map(|(which, prefix)| {
                let objects = match which {
                    "enterprise" => Some(&self.enterprise),
                    "mobile" => self.mobile.as_ref(),
                    _ => self.ics.as_ref(),
                };
                objects.map(|objects| (objects.as_slice(), prefix))
            })
            .collect()
    }
}

/// `_stamp_source`.
fn stamp_source(document: &mut Table, manifest: &Table, now: &str) {
    document.remove("version");
    document.insert("source".to_owned(), Value::from("mitre-attack"));
    document.insert(
        "source_version".to_owned(),
        manifest
            .get("version")
            .cloned()
            .unwrap_or_else(|| Value::from("unknown")),
    );
    document.insert(
        "source_fetched_at".to_owned(),
        manifest
            .get("fetched_at")
            .filter(|value| truthy(value))
            .cloned()
            .unwrap_or_else(|| Value::from(now)),
    );
}

/// One ATT&CK vocabulary: its template, keyed by `key`, merged with
/// `upstream` and stamped.
fn attack_vocabulary(
    vocab_dir: &Path,
    field: &str,
    key: &str,
    document: Table,
    upstream: &[Table],
    manifest: &Table,
    now: &str,
) -> Result<Generated> {
    let mut document = document;
    let lifecycle = merge(&keys_of(&document), upstream, key)?;
    set_keys(&mut document, &lifecycle);
    stamp_source(&mut document, manifest, now);
    Ok(Generated {
        field: field.to_owned(),
        lifecycle,
        document,
        path: vocab_dir.join(format!("{field}{VOCAB_SUFFIX}")),
    })
}

fn keyed_template(vocab_dir: &Path, field: &str, key: &str) -> Result<Table> {
    let mut document = template(vocab_dir, field)?;
    document.insert("key".to_owned(), Value::from(key));
    document.remove("model");
    Ok(document)
}

/// `generate_attack_vocabs`: `att&ck`, `att&ck.groups`, `mitigations` and
/// `datasources`, in that order.
pub fn attack(vocab_dir: &Path, inputs: &Inputs) -> Result<Report> {
    let manifest = manifest(&inputs.stix_dir)?;
    let bundles = Bundles::load(&inputs.stix_dir)?;
    let now = inputs.now.as_str();
    let mut vocabularies = Vec::new();

    let mut techniques = template(vocab_dir, "att&ck")?;
    let previous_source = techniques.get("source_version").cloned();
    techniques.insert("key".to_owned(), Value::from("id"));
    techniques.remove("model");
    // The header lists the Enterprise matrix's tactics, so it follows
    // ATT&CK's renames (v19: Defense Evasion became Stealth).
    let matrix = stix::matrix_tactics(&bundles.enterprise)?;
    if !matrix.is_empty() {
        techniques.insert(
            "stages".to_owned(),
            Value::Array(matrix.into_iter().map(Value::String).collect()),
        );
    }
    let upstream = stix::merged_techniques(&bundles.ordered([
        ("enterprise", ""),
        ("mobile", "Mobile"),
        ("ics", "Industrial"),
    ]))?;
    vocabularies.push(attack_vocabulary(
        vocab_dir, "att&ck", "id", techniques, &upstream, &manifest, now,
    )?);

    // The catalog of MITRE groups; live threat objects reach G-ids through
    // `actors`, which takes the same intrusion sets.
    let mut upstream = Vec::new();
    for (objects, prefix) in
        bundles.ordered([("enterprise", ""), ("ics", "ICS"), ("mobile", "Mobile")])
    {
        upstream.extend(stix::groups(objects, prefix)?);
    }
    let groups = keyed_template(vocab_dir, "att&ck.groups", "id")?;
    vocabularies.push(attack_vocabulary(
        vocab_dir,
        "att&ck.groups",
        "id",
        groups,
        &upstream,
        &manifest,
        now,
    )?);

    let mut upstream = Vec::new();
    for (objects, prefix) in bundles.ordered([
        ("enterprise", ""),
        ("mobile", "Mobile"),
        ("ics", "Industrial"),
    ]) {
        upstream.extend(stix::mitigations(objects, prefix)?);
    }
    let mitigations = keyed_template(vocab_dir, "mitigations", "name")?;
    vocabularies.push(attack_vocabulary(
        vocab_dir,
        "mitigations",
        "name",
        mitigations,
        &upstream,
        &manifest,
        now,
    )?);

    let upstream = stix::datasources(&bundles.enterprise)?;
    let datasources = keyed_template(vocab_dir, "datasources", "name")?;
    vocabularies.push(attack_vocabulary(
        vocab_dir,
        "datasources",
        "name",
        datasources,
        &upstream,
        &manifest,
        now,
    )?);

    let release = match manifest.get("version") {
        Some(value) => text(value)?,
        None => "unknown".to_owned(),
    };
    let previous = match previous_source.filter(truthy) {
        Some(value) => text(&value)?,
        None => String::new(),
    };
    Ok(Report {
        vocabularies,
        source_changed: previous != release,
    })
}

/// The MISP galaxy's actors (`_load_misp_galaxy`) and its provenance keys.
fn misp_actors(url: &str, raw: &[u8]) -> Result<(Vec<Table>, Table)> {
    let galaxy = parse_json(raw).context("parse the MISP galaxy")?;
    let mut actors = Vec::new();
    let values = galaxy
        .get("values")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for actor in values {
        let mut entry = Table::new();
        entry.insert(
            "id".to_owned(),
            actor
                .get("uuid")
                .context("a MISP actor without uuid")?
                .clone(),
        );
        entry.insert(
            "name".to_owned(),
            actor
                .get("value")
                .context("a MISP actor without value")?
                .clone(),
        );
        entry.insert(
            "description".to_owned(),
            actor
                .get("description")
                .filter(|value| truthy(value))
                .cloned()
                .unwrap_or_else(|| Value::from("")),
        );
        entry.insert("tide.vocab.stages".to_owned(), Value::from("misp"));
        if let Some(synonyms) = actor
            .get("meta")
            .and_then(|meta| meta.get("synonyms"))
            .filter(|value| truthy(value))
        {
            entry.insert("alias".to_owned(), synonyms.clone());
        }
        actors.push(entry);
    }
    let mut provenance = Table::new();
    provenance.insert("source_misp_url".to_owned(), Value::from(url));
    provenance.insert(
        "source_misp_sha256".to_owned(),
        Value::from(crate::golden::blob::sha256_hex(raw)),
    );
    Ok((actors, provenance))
}

/// `generate_actors_vocabs`: `actors` from ATT&CK's groups (each bundle's,
/// prefixed `[Enterprise]`, `[ICS]`, `[Mobile]`) and the MISP galaxy.
pub fn actors(vocab_dir: &Path, inputs: &Inputs) -> Result<Report> {
    let path = vocab_dir.join(format!("actors{VOCAB_SUFFIX}"));
    let mut document = read_vocab_document(&path)?;
    document.insert("key".to_owned(), Value::from("id"));
    document.remove("model");

    let mut actors = Vec::new();
    for (name, prefix) in [
        ("enterprise-attack.json", "Enterprise"),
        ("ics-attack.json", "ICS"),
        ("mobile-attack.json", "Mobile"),
    ] {
        let bundle = inputs.stix_dir.join(name);
        if bundle.is_file() {
            for mut group in stix::groups(&stix::load_bundle(&bundle)?, prefix)? {
                group.insert("tide.vocab.stages".to_owned(), Value::from("att&ck"));
                actors.push(group);
            }
        }
    }
    let mut provenance = Table::new();
    if let Some((url, raw)) = &inputs.misp {
        let (misp, misp_provenance) = misp_actors(url, raw)?;
        actors.extend(misp);
        provenance = misp_provenance;
    }

    let previous_misp = document.get("source_misp_sha256").cloned();
    let previous_attack = document.get("source_version").cloned();
    let lifecycle = merge(&keys_of(&document), &actors, "id")?;
    set_keys(&mut document, &lifecycle);
    document.remove("version");
    let manifest_path = inputs.stix_dir.join("manifest.json");
    if manifest_path.is_file() {
        let manifest = manifest(&inputs.stix_dir)?;
        document.insert(
            "source_version".to_owned(),
            Value::from(match manifest.get("version") {
                Some(value) => text(value)?,
                None => "unknown".to_owned(),
            }),
        );
        document.insert(
            "source_fetched_at".to_owned(),
            manifest
                .get("fetched_at")
                .cloned()
                .unwrap_or_else(|| Value::from("")),
        );
    } else {
        document.insert(
            "source_fetched_at".to_owned(),
            Value::from(inputs.now.as_str()),
        );
    }
    document.insert("source".to_owned(), Value::from("mitre-attack+misp"));
    document.insert("generated_at".to_owned(), Value::from(inputs.now.as_str()));
    for (key, value) in &provenance {
        document.insert(key.clone(), value.clone());
    }

    let text_of = |value: Option<Value>| -> Result<String> {
        match value.filter(truthy) {
            Some(value) => text(&value),
            None => Ok(String::new()),
        }
    };
    let release = match document.get("source_version") {
        Some(value) => text(value)?,
        None => "unknown".to_owned(),
    };
    let mut source_changed = text_of(previous_attack)? != release;
    if let Some(digest) = provenance.get("source_misp_sha256").and_then(Value::as_str)
        && !digest.is_empty()
        && text_of(previous_misp)? != digest
    {
        source_changed = true;
    }
    Ok(Report {
        vocabularies: vec![Generated {
            field: "actors".to_owned(),
            lifecycle,
            document,
            path,
        }],
        source_changed,
    })
}
