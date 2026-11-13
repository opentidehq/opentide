//! `cargo xtask vocab ingest [--check|--apply]`: the weekly ATT&CK and MISP
//! ingest (`.github/workflows/vocab-upstream.yml`), ported from the Python
//! package's `opentide.vocabulary.sync_upstream` (removed in UC-6.2, #841).
//!
//! It fetches the latest MITRE ATT&CK STIX release ([`fetch_stix`]) and the
//! MISP threat-actor galaxy, merges them into the specifications checkout's
//! `att&ck`, `att&ck.groups`, `mitigations`, `datasources` and `actors`
//! vocabularies with RFC 0003 per-key versions ([`lifecycle`]), and with
//! `--apply` writes them and syncs the bundle (`vocab sync`). Schema pins
//! never move: a new key opens a minor contract that the run reports as
//! unpinned.
//!
//! The vocabularies it writes hold the same data as the Python ingest's from
//! the same inputs (`scripts/vocabulary/README.md` records the comparison);
//! their layout is the `toml` crate's ([`value::to_toml`]). `[[keys]]` keep
//! the merge order, which is data; the order of keys inside a table is not,
//! and comes out sorted.

pub mod generate;
pub mod lifecycle;
pub mod stix;
pub mod value;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;

use self::generate::{Inputs, Report};
use self::value::{Table, Value, parse_json, parse_toml, text};

/// The variable naming the STIX directory (`OPENTIDE_ATTACK_STIX_DIR`).
pub const STIX_DIR_ENV: &str = "OPENTIDE_ATTACK_STIX_DIR";
/// The latest ATT&CK STIX release, from GitHub's API.
pub const GITHUB_API: &str =
    "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/latest";
/// Each bundle's key in the manifest and its file in the release.
pub const BUNDLE_FILES: [(&str, &str); 3] = [
    ("enterprise", "enterprise-attack.json"),
    ("mobile", "mobile-attack.json"),
    ("ics", "ics-attack.json"),
];
/// The schema families whose pin files name vocabulary contracts.
const PIN_FAMILIES: [&str; 3] = ["threat", "objective", "rule"];

/// What a run does.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Compute without writing; dirty is a failure (also the default).
    pub check: bool,
    /// Write the vocabularies and sync the bundle.
    pub apply: bool,
    /// Read the STIX bundles already in the STIX directory.
    pub no_fetch: bool,
    /// The STIX directory; else `$OPENTIDE_ATTACK_STIX_DIR`, else a scratch
    /// directory for the fetch.
    pub stix_dir: Option<PathBuf>,
    /// The MISP galaxy; else the bundled `resources.toml`'s
    /// `misp.galaxies.threat_actors`. `file://` reads a local file.
    pub misp_url: Option<String>,
    /// The specifications checkout; else `$OPENTIDE_SPECIFICATIONS_ROOT`,
    /// else `../specifications`.
    pub specifications: Option<PathBuf>,
    /// The time to write where the run would read the clock (`2026-11-13T00:00:00.000Z`),
    /// for a reproducible run.
    pub now: Option<String>,
}

/// Parses `vocab ingest`'s options.
pub fn parse(args: &[String]) -> Result<Options> {
    let mut options = Options::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .cloned()
                .with_context(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--check" => options.check = true,
            "--apply" => options.apply = true,
            "--no-fetch" => options.no_fetch = true,
            "--stix-dir" => options.stix_dir = Some(PathBuf::from(value("--stix-dir")?)),
            "--misp-url" => options.misp_url = Some(value("--misp-url")?),
            "--specifications" => {
                options.specifications = Some(PathBuf::from(value("--specifications")?));
            }
            "--now" => options.now = Some(value("--now")?),
            other => bail!("unknown option `{other}`\n\n{}", super::USAGE),
        }
    }
    ensure!(
        !(options.check && options.apply),
        "use either --check or --apply, not both"
    );
    Ok(options)
}

/// The ingest's result.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// `att&ck`, `att&ck.groups`, `mitigations`, `datasources`.
    pub attack: Report,
    /// `actors`.
    pub actors: Report,
    /// The contracts new keys opened, for vocabularies a schema pin file
    /// names, by field.
    pub new_contracts: BTreeMap<String, String>,
}

impl SyncReport {
    /// Whether the vocabularies would change.
    pub fn dirty(&self) -> bool {
        self.attack.dirty() || self.actors.dirty()
    }

    /// The summary the run prints (`SyncReport.summary_lines`).
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for (name, report) in [("attack", &self.attack), ("actors", &self.actors)] {
            let _ = writeln!(out, "{name}:");
            for vocabulary in &report.vocabularies {
                let lifecycle = &vocabulary.lifecycle;
                let _ = writeln!(
                    out,
                    "  {}: {} keys (+{} ~{} -{} backfill={})",
                    vocabulary.field,
                    lifecycle.keys.len(),
                    lifecycle.added.len(),
                    lifecycle.updated.len(),
                    lifecycle.removed.len(),
                    lifecycle.backfilled.len()
                );
                if let Some(contract) = lifecycle.new_contract() {
                    let _ = writeln!(out, "    new contract {}::{contract}", vocabulary.field);
                }
            }
            if report.source_changed {
                let _ = writeln!(out, "  source provenance changed ({name})");
            }
        }
        if !self.new_contracts.is_empty() {
            let opened = self
                .new_contracts
                .iter()
                .map(|(field, version)| format!("{field}::{version}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "unpinned contracts: {opened} (adopting one is a new schema revision)"
            );
        }
        out
    }
}

fn pin_assignment() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        Regex::new(r#"^[ \t]*"[^"]+"[ \t]*=[ \t]*"([^"]+)::\d+\.\d+"[ \t]*$"#)
            .expect("the pin assignment pattern compiles")
    })
}

/// The vocabulary fields a pin file's contents name as `"field::M.m"`
/// values (`vocab_fields_in_pin_contents`).
pub fn pinned_fields(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| pin_assignment().captures(line.trim_end_matches('\r')))
        .filter_map(|captures| captures.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

/// The vocabulary fields the `threat`, `objective` and `rule` pin files of
/// `dirs` name.
pub fn pinned_fields_in(dirs: &[PathBuf]) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    for dir in dirs.iter().filter(|dir| dir.is_dir()) {
        for family in PIN_FAMILIES {
            let path = dir.join(format!("{family}.toml"));
            if path.is_file() {
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("read {}", path.display()))?;
                fields.extend(pinned_fields(&text));
            }
        }
    }
    fields.sort();
    fields.dedup();
    Ok(fields)
}

/// The new contracts of vocabularies a pin file names; every one when no
/// pin file names any (`_schema_pinned_versions`).
fn schema_pinned(
    new_contracts: BTreeMap<String, String>,
    pinned: &[String],
) -> BTreeMap<String, String> {
    if pinned.is_empty() {
        return new_contracts;
    }
    new_contracts
        .into_iter()
        .filter(|(field, _)| pinned.contains(field))
        .collect()
}

/// Runs the generators on the vocabularies of `specifications`; pins are read
/// from it and from the bundle at `bundled_pins`.
pub fn compute(specifications: &Path, bundled_pins: &Path, inputs: &Inputs) -> Result<SyncReport> {
    let vocab_dir = specifications.join("vocabularies");
    let attack = generate::attack(&vocab_dir, inputs)?;
    let actors = generate::actors(&vocab_dir, inputs)?;
    let mut new_contracts: BTreeMap<String, String> = attack.new_contracts().into_iter().collect();
    new_contracts.extend(actors.new_contracts());
    let pinned = pinned_fields_in(&[
        specifications.join("schemas/pins"),
        bundled_pins.to_path_buf(),
    ])?;
    Ok(SyncReport {
        attack,
        actors,
        new_contracts: schema_pinned(new_contracts, &pinned),
    })
}

/// `utc_now_iso()`: UTC, milliseconds, a `Z`.
pub fn utc_now_iso() -> Result<String> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format_utc(since.as_secs(), since.subsec_millis()))
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for `seconds` after the epoch.
pub fn format_utc(seconds: u64, millis: u32) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rest = seconds % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// curl's options: HTTPS only, redirects followed, TLS 1.2 or later, failing
/// on an HTTP error.
const CURL: [&str; 9] = [
    "--fail",
    "--silent",
    "--show-error",
    "--location",
    "--proto",
    "=https",
    "--proto-redir",
    "=https",
    "--tlsv1.2",
];

/// Downloads `url` with curl ([`CURL`]'s options and `options`, such as
/// `--max-time 120`), into `output` when given, else returning the bytes.
/// `vocab ingest` and `vocab malapi` fetch through it.
pub fn curl(url: &str, options: &[&str], output: Option<&Path>) -> Result<Vec<u8>> {
    let mut command = Command::new("curl");
    command.args(CURL).args(options);
    if let Some(path) = output {
        command.arg("--output").arg(path);
    }
    let result = command
        .arg(url)
        .output()
        .context("run curl to download the vocabularies' sources")?;
    ensure!(
        result.status.success(),
        "download {url} failed ({}): {}",
        result.status,
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(result.stdout)
}

/// A URL's bytes: `file://` read from disk, anything else over HTTPS.
pub fn read_url(url: &str) -> Result<Vec<u8>> {
    match url.strip_prefix("file://") {
        Some(path) => fs::read(path).with_context(|| format!("read {path}")),
        None => curl(url, &["--max-time", "120"], None),
    }
}

/// The release version of an attack-stix-data tag (`ATT&CK-v18.1` → `18.1`).
pub fn release_version(tag: &str) -> &str {
    ["ATT&CK-v", "ATT&CK-V", "v"]
        .iter()
        .find_map(|prefix| tag.strip_prefix(prefix))
        .unwrap_or(tag)
}

/// One bundle of a release: its manifest key, file name and download URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSource {
    /// `enterprise`, `mobile` or `ics`.
    pub key: &'static str,
    /// `enterprise-attack.json`.
    pub file: &'static str,
    /// The release asset's `browser_download_url`, else the release's
    /// download URL for the file.
    pub url: String,
}

/// The tag of a GitHub release document and where each bundle downloads
/// from (`fetch_latest_attack_stix`).
pub fn bundle_sources(release: &Value) -> Result<(String, Vec<BundleSource>)> {
    let tag = match release.get("tag_name") {
        Some(value) => text(value)?,
        None => "unknown".to_owned(),
    };
    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut sources = Vec::new();
    for (key, file) in BUNDLE_FILES {
        let url = match assets
            .iter()
            .find(|asset| asset.get("name").and_then(Value::as_str) == Some(file))
        {
            Some(asset) => asset
                .get("browser_download_url")
                .context("a release asset without browser_download_url")
                .and_then(text)?,
            None => format!(
                "https://github.com/mitre-attack/attack-stix-data/releases/download/{tag}/{file}"
            ),
        };
        sources.push(BundleSource { key, file, url });
    }
    Ok((tag, sources))
}

/// The `manifest.json` of a fetch: release version, tag, time, bundles.
pub fn manifest_of(tag: &str, sources: &[BundleSource], now: &str) -> Table {
    let mut bundles = Table::new();
    for source in sources {
        let mut bundle = Table::new();
        bundle.insert("path".to_owned(), Value::from(source.file));
        bundle.insert("url".to_owned(), Value::from(source.url.clone()));
        bundles.insert(source.key.to_owned(), Value::Object(bundle));
    }
    let mut manifest = Table::new();
    manifest.insert("version".to_owned(), Value::from(release_version(tag)));
    manifest.insert("tag".to_owned(), Value::from(tag));
    manifest.insert("fetched_at".to_owned(), Value::from(now));
    manifest.insert("bundles".to_owned(), Value::Object(bundles));
    manifest
}

/// The text of a manifest: pretty JSON with a final newline.
pub fn manifest_text(manifest: &Table) -> Result<String> {
    Ok(serde_json::to_string_pretty(manifest)? + "\n")
}

/// Downloads the latest ATT&CK STIX bundles into `dir` and writes its
/// `manifest.json` (`fetch_latest_attack_stix`).
pub fn fetch_stix(dir: &Path, now: &str) -> Result<Table> {
    let release = parse_json(&curl(
        GITHUB_API,
        &[
            "--max-time",
            "120",
            "--header",
            "Accept: application/vnd.github+json",
        ],
        None,
    )?)
    .context("parse the latest attack-stix-data release")?;
    let (tag, sources) = bundle_sources(&release)?;
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    for source in &sources {
        curl(
            &source.url,
            &["--max-time", "300"],
            Some(&dir.join(source.file)),
        )?;
    }
    let manifest = manifest_of(&tag, &sources, now);
    let path = dir.join("manifest.json");
    fs::write(&path, manifest_text(&manifest)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(manifest)
}

/// The MISP galaxy URL in the bundled `resources.toml`.
pub fn default_misp_url(repo: &Path) -> Result<Option<String>> {
    let path = repo.join("src/opentide/data/configurations/resources.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let resources = parse_toml(&text)?;
    Ok(resources
        .get("misp")
        .and_then(|misp| misp.get("galaxies"))
        .and_then(|galaxies| galaxies.get("threat_actors"))
        .and_then(Value::as_str)
        .map(str::to_owned))
}

/// The specifications checkout a run writes into: `given`, else
/// `$OPENTIDE_SPECIFICATIONS_ROOT`, else `../specifications` beside `repo`;
/// it must exist.
pub fn specifications_root(repo: &Path, given: Option<&Path>) -> Result<PathBuf> {
    let specifications = given
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os(super::sync::SPECIFICATIONS_ENV).map(PathBuf::from))
        .unwrap_or_else(|| repo.join("../specifications"));
    dunce::canonicalize(&specifications)
        .with_context(|| format!("the specifications checkout {}", specifications.display()))
}

/// Runs `cargo xtask vocab ingest` for the repository at `repo`. Whether it
/// passed: with `--apply` always (once written); otherwise when nothing would
/// change.
pub fn run(repo: &Path, options: &Options) -> Result<bool> {
    let specifications = specifications_root(repo, options.specifications.as_deref())?;
    let now = match &options.now {
        Some(now) => now.clone(),
        None => utc_now_iso()?,
    };
    let scratch;
    let stix_dir = match options
        .stix_dir
        .clone()
        .or_else(|| std::env::var_os(STIX_DIR_ENV).map(PathBuf::from))
    {
        Some(dir) => dir,
        None if options.no_fetch => bail!("--no-fetch needs --stix-dir or ${STIX_DIR_ENV}"),
        None => {
            scratch = tempfile::tempdir()?;
            scratch.path().to_path_buf()
        }
    };
    if !options.no_fetch {
        let manifest = fetch_stix(&stix_dir, &now)?;
        eprintln!(
            "fetched ATT&CK STIX {} into {}",
            manifest
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            stix_dir.display()
        );
    }
    let misp_url = match &options.misp_url {
        Some(url) => Some(url.clone()),
        None => default_misp_url(repo)?,
    };
    let misp = match misp_url.filter(|url| !url.is_empty()) {
        Some(url) => {
            let raw = read_url(&url)?;
            Some((url, raw))
        }
        None => None,
    };
    let inputs = Inputs {
        stix_dir,
        misp,
        now,
    };
    let report = compute(
        &specifications,
        &repo.join("src/opentide/data/pins"),
        &inputs,
    )?;
    print!("{}", report.summary());
    if options.apply {
        if report.dirty() {
            report.attack.write()?;
            report.actors.write()?;
            let mut out = String::new();
            let synced = super::sync::run(
                &super::sync::Paths::new(repo, &specifications),
                false,
                &mut out,
            )?;
            eprint!("{out}");
            ensure!(synced, "the bundle sync failed");
            println!("wrote");
        } else {
            println!("no changes to write");
        }
        return Ok(true);
    }
    if report.dirty() {
        println!("Upstream vocabulary ingest would change files. Re-run with --apply.");
        return Ok(false);
    }
    println!("Already up to date.");
    Ok(true)
}

#[cfg(test)]
mod tests;
