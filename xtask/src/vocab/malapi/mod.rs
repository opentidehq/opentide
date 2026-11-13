//! `cargo xtask vocab malapi [--check|--apply]`: the MalAPI vocabulary from
//! [malapi.io](https://malapi.io), ported from the Python
//! `scripts/vocabulary/generate_malapi.py` (last at
//! `ca32f5558d95fd77d5550084ee0f9d0681397fdc`).
//!
//! It reads the front page's attack categories and API names, then each
//! API's page ([`page`]), and merges the keys into the specifications
//! checkout's `malapi.vocab.toml` with the ingest's RFC 0003 per-key rules
//! ([`super::ingest::lifecycle`]). The site answers 429 after a short burst
//! and then serves about a page a minute, so the pages are fetched one at a
//! time, [`DEFAULT_DELAY`] apart, with curl's retries on 429 and 5xx.
//! `--html-dir` reads saved pages instead (`index.html`,
//! `winapi/<API>.html`), for tests and reproducible runs.
//!
//! A run that stops part-way (the site gives up, a saved page is missing)
//! carries the existing keys of the APIs it never reached over unchanged, so
//! they are not marked removed. With `--apply` it writes that partial merge,
//! leaves the bundle alone and exits 1; a `--check` cannot conclude and
//! exits 2.

pub mod page;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};

use self::page::{FrontPage, MALAPI_URL, api_page, front_page, valid_api};
use super::ingest::generate::{
    Generated, VOCAB_SUFFIX, keys_of, read_vocab_document, set_keys, write_vocab_file,
};
use super::ingest::lifecycle::{identity, merge};
use super::ingest::value::{Table, Value, truthy};
use super::ingest::{curl, specifications_root, utc_now_iso};

/// The vocabulary's field.
pub const FIELD: &str = "malapi";
/// The pause before each API page: about the one page a minute the site
/// serves once its burst allowance is spent.
pub const DEFAULT_DELAY: Duration = Duration::from_secs(60);
/// The `source` provenance a written vocabulary records.
pub const SOURCE: &str = "malapi.io";

/// What a run does.
#[derive(Debug, Clone)]
pub struct Options {
    /// Compute without writing; dirty is a failure (also the default).
    pub check: bool,
    /// Write the vocabulary and sync the bundle.
    pub apply: bool,
    /// The specifications checkout; else `$OPENTIDE_SPECIFICATIONS_ROOT`,
    /// else `../specifications`.
    pub specifications: Option<PathBuf>,
    /// Saved pages to read instead of fetching.
    pub html_dir: Option<PathBuf>,
    /// The pause before each API page fetched.
    pub delay: Duration,
    /// The time to record as `source_fetched_at`, for a reproducible run.
    pub now: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            check: false,
            apply: false,
            specifications: None,
            html_dir: None,
            delay: DEFAULT_DELAY,
            now: None,
        }
    }
}

/// Parses `vocab malapi`'s options.
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
            "--specifications" => {
                options.specifications = Some(PathBuf::from(value("--specifications")?));
            }
            "--html-dir" => options.html_dir = Some(PathBuf::from(value("--html-dir")?)),
            "--delay" => options.delay = parse_delay(&value("--delay")?)?,
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

/// `--delay`'s seconds: a non-negative number, fractions allowed.
fn parse_delay(seconds: &str) -> Result<Duration> {
    let parsed: f64 = seconds
        .parse()
        .ok()
        .filter(|value: &f64| value.is_finite() && *value >= 0.0)
        .with_context(|| format!("--delay {seconds}: expected a number of seconds"))?;
    Duration::try_from_secs_f64(parsed).with_context(|| format!("--delay {seconds}"))
}

/// Where the pages come from.
#[derive(Debug, Clone)]
pub enum Pages {
    /// malapi.io, `delay` before each API page.
    Live {
        /// The pause before each API page.
        delay: Duration,
    },
    /// Saved pages: `index.html` and `winapi/<API>.html`.
    Saved(PathBuf),
}

impl Pages {
    /// The front page.
    fn front(&self) -> Result<String> {
        match self {
            Self::Live { .. } => fetch(MALAPI_URL),
            Self::Saved(dir) => read(&dir.join("index.html")),
        }
    }

    /// An API's page. An error is a fetch that failed: the run stops there.
    fn api(&self, api: &str) -> Result<String> {
        match self {
            Self::Live { delay } => {
                std::thread::sleep(*delay);
                fetch(&format!("{MALAPI_URL}/winapi/{api}"))
            }
            Self::Saved(dir) => read(&dir.join("winapi").join(format!("{api}.html"))),
        }
    }
}

/// A page from the site: curl, HTTPS only, retrying 429s and server errors
/// with its doubling backoff.
fn fetch(url: &str) -> Result<String> {
    let bytes = curl(
        url,
        &["--max-time", "30", "--retry", "10", "--retry-connrefused"],
        None,
    )?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A saved page.
fn read(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// What the site gave.
#[derive(Debug, Clone)]
pub struct Scrape {
    /// The attack categories.
    pub stages: Vec<Table>,
    /// One key per API page read.
    pub keys: Vec<Table>,
    /// Every API the front page lists.
    pub apis: Vec<String>,
    /// The APIs not reached when the run stopped part-way, in order.
    pub unfetched: Vec<String>,
}

/// Reads the front page, then each API's page until one cannot be fetched.
/// A page that does not parse is an error.
pub fn scrape(pages: &Pages) -> Result<Scrape> {
    let FrontPage { stages, apis } = front_page(&pages.front()?)?;
    let mut keys = Vec::new();
    let mut unfetched = Vec::new();
    for (index, api) in apis.iter().enumerate() {
        debug_assert!(valid_api(api), "front_page() only returns identifiers");
        eprintln!("[{}/{}] {api}", index + 1, apis.len());
        match pages.api(api) {
            Ok(html) => keys.push(api_page(api, &html)?),
            Err(error) => {
                eprintln!("malapi: stopped at {api}: {error:#}");
                unfetched = apis[index..].to_vec();
                break;
            }
        }
    }
    Ok(Scrape {
        stages,
        keys,
        apis,
        unfetched,
    })
}

/// The merge of a scrape into the vocabulary.
#[derive(Debug, Clone)]
pub struct Report {
    /// The merged document, its path and the lifecycle.
    pub vocabulary: Generated,
    /// Whether the attack categories changed.
    pub stages_changed: bool,
    /// The APIs the front page lists.
    pub apis: usize,
    /// The APIs not reached.
    pub unfetched: Vec<String>,
}

impl Report {
    /// Whether the vocabulary would change.
    pub fn dirty(&self) -> bool {
        self.stages_changed || self.vocabulary.lifecycle.dirty()
    }

    /// The summary the run prints.
    pub fn summary(&self) -> String {
        let lifecycle = &self.vocabulary.lifecycle;
        let mut out = format!(
            "{FIELD}: {} keys (+{} ~{} -{} backfill={})\n",
            lifecycle.keys.len(),
            lifecycle.added.len(),
            lifecycle.updated.len(),
            lifecycle.removed.len(),
            lifecycle.backfilled.len()
        );
        if let Some(contract) = lifecycle.new_contract() {
            let _ = writeln!(
                out,
                "  new contract {FIELD}::{contract} (adopting it is a new schema revision)"
            );
        }
        if self.stages_changed {
            let _ = writeln!(out, "  attack categories changed");
        }
        if !self.unfetched.is_empty() {
            let _ = writeln!(
                out,
                "  {} of {} APIs not fetched, their keys carried over unchanged",
                self.unfetched.len(),
                self.apis
            );
        }
        out
    }
}

/// Merges `scrape` into the vocabulary `existing` (at `path`): the scraped
/// keys, and the live existing keys of the APIs not reached, through the
/// lifecycle merge; the scraped categories as `stages`; the provenance
/// stamped with `now`.
pub fn build(existing: Table, path: PathBuf, scrape: Scrape, now: &str) -> Result<Report> {
    let existing_keys = keys_of(&existing);
    let mut upstream = scrape.keys;
    for key in &existing_keys {
        if let Some(name) = identity(key, "name")?
            && scrape.unfetched.contains(&name)
            && !key.get("removed").is_some_and(truthy)
        {
            upstream.push(key.clone());
        }
    }
    let lifecycle = merge(&existing_keys, &upstream, "name")?;
    let stages = Value::Array(scrape.stages.into_iter().map(Value::Object).collect());
    let mut document = existing;
    let stages_changed = document.get("stages") != Some(&stages);
    document.insert("stages".to_owned(), stages);
    set_keys(&mut document, &lifecycle);
    document.insert("source".to_owned(), Value::from(SOURCE));
    document.insert("source_fetched_at".to_owned(), Value::from(now));
    Ok(Report {
        vocabulary: Generated {
            field: FIELD.to_owned(),
            lifecycle,
            document,
            path,
        },
        stages_changed,
        apis: scrape.apis.len(),
        unfetched: scrape.unfetched,
    })
}

/// Runs `cargo xtask vocab malapi` for the repository at `repo`. Whether it
/// passed: with `--apply` once written in full; otherwise when nothing would
/// change.
pub fn run(repo: &Path, options: &Options) -> Result<bool> {
    let specifications = specifications_root(repo, options.specifications.as_deref())?;
    let path = specifications
        .join("vocabularies")
        .join(format!("{FIELD}{VOCAB_SUFFIX}"));
    let existing = read_vocab_document(&path)?;
    let now = match &options.now {
        Some(now) => now.clone(),
        None => utc_now_iso()?,
    };
    let pages = match &options.html_dir {
        Some(dir) => Pages::Saved(dir.clone()),
        None => Pages::Live {
            delay: options.delay,
        },
    };
    let report = build(existing, path, scrape(&pages)?, &now)?;
    print!("{}", report.summary());

    if !report.unfetched.is_empty() {
        if !options.apply {
            bail!(
                "{} of {} APIs not fetched: the check could not run",
                report.unfetched.len(),
                report.apis
            );
        }
        write_vocab_file(&report.vocabulary.path, &report.vocabulary.document)?;
        eprintln!(
            "malapi: {} of {} APIs not fetched, their entries left as they were in {}; \
             bundle not synced, rerun to finish",
            report.unfetched.len(),
            report.apis,
            report.vocabulary.path.display()
        );
        return Ok(false);
    }
    if options.apply {
        if report.dirty() {
            write_vocab_file(&report.vocabulary.path, &report.vocabulary.document)?;
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
        println!("The MalAPI vocabulary would change. Re-run with --apply.");
        return Ok(false);
    }
    println!("Already up to date.");
    Ok(true)
}

#[cfg(test)]
mod tests;
