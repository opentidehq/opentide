//! `opentide generate docs` (UC-3.2b, #915): a Markdown page per rule,
//! objective and threat, the folders' index pages and the root README
//! (`documentation/`).
//!
//! - [`catalog`]: the objects read into their models, sorted by name, each with
//!   a unique page slug; the relations the pages show (the flat relation walk,
//!   active rules, coverage and chaining graphs).
//! - [`render`]: each page's sections, from the models; [`page`]: the one
//!   layout every page shares (breadcrumb, title, subtitle, overview,
//!   contents line, sections, Metadata last) and its Markdown primitives;
//!   [`text`]: cells, code spans, first sentences.
//! - [`facts`]: where a rule deploys (statuses, runs, tenants, remote ids),
//!   by deploy's own rules; [`settings`]: every setting of a platform block
//!   by YAML path, described from the block models' schema; [`platforms`]:
//!   platform labels and the languages of their code settings.
//! - [`flavor`]: what GitHub, GitLab, Azure DevOps and plain Markdown change.
//! - [`diagrams`]: the diagrams pages show (coverage, deployment map,
//!   chaining, kill-chain maps, the threat landscape), built as a model that
//!   [`mermaid`] writes within each flavour's Mermaid; [`vocab`]: vocabulary
//!   labels; [`cve`]: CVE links.
//! - [`inflight`]: the open pull requests' objects, overlaid on the index for
//!   the run (the inflight preview).
//! - [`changed`]: `--changed`, the objects git reports as changed against the
//!   default branch.
//!
//! Rendering is pure: [`pages`] and [`index_pages`] return [`Output`]s;
//! [`stale_pages`] reads the output folders for pages no object writes any
//! more, and the command line writes and removes (`generate/files.rs`).

pub mod catalog;
pub mod changed;
pub mod cve;
pub mod diagrams;
pub mod facts;
pub mod flavor;
pub mod inflight;
pub mod mermaid;
pub mod page;
pub mod platforms;
pub mod render;
pub mod settings;
pub mod text;
pub mod vocab;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use opentide_schema::FromNode;
use opentide_schema::configuration::models::{
    DocumentationConfiguration, FlavorChoice, RelationsDirection,
};
use opentide_schema::configuration::resolve::Resolved;
use opentide_schema::from_node::Context;
use rayon::prelude::*;

use self::catalog::{Direction, Model, Record, Scope};
use self::cve::CveLinks;
use self::flavor::Flavor;
use self::render::{FOLDER_TITLES, Pages};
use super::{Cause, Output, PhaseError};

/// What a run reads from `documentation.toml`, the command line and the
/// environment (`DocumentationSettings`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the switches of documentation.toml, one field each"
)]
pub struct Settings {
    /// The folder the pages go to.
    pub output: PathBuf,
    /// The Markdown flavour.
    pub flavor: Flavor,
    /// Index pages in each folder and a root README.
    pub folder_index_pages: bool,
    /// GitLab pages named and linked by UUID.
    pub uuid_permalinks: bool,
    /// Which relations a page shows.
    pub direction: Direction,
    /// Index pages count each object's relations.
    pub relation_counts: bool,
    /// Index entries carry their family's icon.
    pub icons: bool,
    /// Where CVE links point.
    pub cve: CveLinks,
    /// `[cve] retrieve_details`: a CVE section is a table of each record's
    /// details, from [`Settings::cve_source`].
    pub cve_details: bool,
    /// Where those details come from (the host's lookup).
    pub cve_source: cve::CveSource,
}

/// Where the flavour comes from when `--flavor` does not say.
#[derive(Debug, Clone, Default)]
pub struct FlavorHints {
    /// `TF_BUILD` is set: Azure Pipelines.
    pub azure: bool,
    /// `GITHUB_ACTIONS` is set.
    pub github: bool,
    /// `GITLAB_CI` is set.
    pub gitlab: bool,
    /// The repository's `origin` URL.
    pub origin: Option<String>,
}

impl FlavorHints {
    /// The hints of an environment, and the `origin` URL of the checkout.
    pub fn new(env: &dyn Fn(&str) -> Option<String>, origin: Option<String>) -> Self {
        let set = |name: &str| env(name).is_some_and(|value| !value.is_empty());
        Self {
            azure: set("TF_BUILD"),
            github: set("GITHUB_ACTIONS"),
            gitlab: set("GITLAB_CI"),
            origin,
        }
    }
}

/// The flavour of the forge hosting `url` (`_flavor_for_host`).
pub fn flavor_for_url(url: &str) -> Option<Flavor> {
    let host = if let Some((_, rest)) = url.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit('@').next().unwrap_or_default();
        let host = if authority.starts_with('[') {
            authority
                .split(']')
                .next()
                .unwrap_or_default()
                .trim_start_matches('[')
        } else {
            authority.split(':').next().unwrap_or_default()
        };
        host.to_lowercase()
    } else {
        let head = url.split(':').next().unwrap_or_default();
        head.rsplit('@').next().unwrap_or_default().to_lowercase()
    };
    if host == "dev.azure.com" || host == "ssh.dev.azure.com" || host.ends_with(".visualstudio.com")
    {
        return Some(Flavor::AzureDevops);
    }
    if host.contains("github") {
        return Some(Flavor::Github);
    }
    if host.contains("gitlab") {
        return Some(Flavor::Gitlab);
    }
    None
}

impl Settings {
    /// The settings from `--output` and `--flavor` first, then
    /// `documentation.toml`; a relative output folder is under `root`, the
    /// repository root (`get_repo_root()`).
    ///
    /// # Errors
    ///
    /// `--flavor` names no flavour, or `documentation.toml` does not match
    /// its model.
    pub fn resolve(
        resolved: &Resolved,
        root: &Path,
        output: Option<&str>,
        flavor: Option<&str>,
        hints: &FlavorHints,
    ) -> Result<Self, PhaseError> {
        let docs = match resolved.get("documentation") {
            Some(node) => {
                let mut cx = Context::new();
                let model = DocumentationConfiguration::from_node(node, &mut cx);
                let errors = cx.into_errors();
                match model {
                    Some(model) if errors.is_empty() => Some(model),
                    _ => {
                        let first = errors
                            .first()
                            .map(|error| {
                                format!("{}: {}", error.field_path().join("."), error.message)
                            })
                            .unwrap_or_default();
                        return Err(PhaseError::new(format!(
                            "ConfigurationError: documentation.toml is invalid: {first}"
                        )));
                    }
                }
            }
            None => None,
        };
        let configured = docs
            .as_ref()
            .and_then(|docs| docs.output.clone())
            .filter(|output| !output.is_empty())
            .unwrap_or_else(|| "docs".to_owned());
        let output = PathBuf::from(output.unwrap_or(&configured));
        let output = if output.is_absolute() {
            output
        } else {
            root.join(output)
        };
        let default = docs.as_ref().map_or(Flavor::Generic, |docs| {
            let flavor = match &docs.flavor {
                FlavorChoice::Name(flavor) => *flavor,
                FlavorChoice::Settings(settings) => settings.default,
            };
            Flavor::from_name(
                &serde_json::to_value(flavor)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            )
            .unwrap_or(Flavor::Generic)
        });
        let flavor = match flavor.filter(|name| !name.is_empty()) {
            Some(name) => Flavor::from_name(name).ok_or_else(|| {
                PhaseError::new(format!(
                    "ValueError: '{}' is not a valid DocumentFlavor",
                    name.replace('-', "_")
                ))
            })?,
            None if hints.azure => Flavor::AzureDevops,
            None if hints.github => Flavor::Github,
            None if hints.gitlab => Flavor::Gitlab,
            None => hints
                .origin
                .as_deref()
                .and_then(flavor_for_url)
                .unwrap_or(default),
        };
        let direction = docs.as_ref().map_or(Direction::Both, |docs| {
            match docs.diagrams.relations_direction {
                RelationsDirection::Upstream => Direction::Upstream,
                RelationsDirection::Downstream => Direction::Downstream,
                RelationsDirection::Both => Direction::Both,
            }
        });
        Ok(Self {
            output,
            flavor,
            folder_index_pages: docs.as_ref().is_none_or(|docs| docs.folder_index_pages),
            uuid_permalinks: flavor == Flavor::Gitlab
                && docs
                    .as_ref()
                    .is_some_and(|docs| docs.gitlab.uuid_permalinks),
            direction,
            relation_counts: docs.as_ref().is_none_or(|docs| docs.index.relation_counts),
            icons: docs.as_ref().is_some_and(|docs| docs.index.icons),
            cve: docs.as_ref().map_or_else(CveLinks::default, |docs| {
                CveLinks::new(Some(&docs.cve.base_url), Some(&docs.cve.default_db_link))
            }),
            cve_details: docs.as_ref().is_none_or(|docs| docs.cve.retrieve_details),
            cve_source: cve::CveSource::default(),
        })
    }

    /// The folder of a scope's pages.
    pub fn folder(&self, scope: Scope) -> PathBuf {
        self.output.join(scope.folder())
    }
}

/// How many pages of each family a run wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Rule pages.
    pub rules: usize,
    /// Objective pages.
    pub objectives: usize,
    /// Threat pages.
    pub threats: usize,
}

impl Counts {
    fn add(&mut self, scope: Scope) {
        match scope {
            Scope::Rules => self.rules += 1,
            Scope::Objectives => self.objectives += 1,
            Scope::Threats => self.threats += 1,
        }
    }
}

/// A page's text as it is written: without trailing blanks, one newline at
/// the end (`write_page`).
fn page(text: &str) -> String {
    let mut text = text.trim_end().to_owned();
    text.push('\n');
    text
}

/// The pages of the objects of `scopes`, in parallel, and how many of each;
/// only the objects of `targets` when given. Threats, objectives, then rules,
/// each by name, as the oracle writes them.
///
/// # Errors
///
/// A page failed to render, named by its object.
pub fn pages(
    pages: &Pages<'_, '_>,
    scopes: &[Scope],
    targets: Option<&std::collections::BTreeSet<String>>,
) -> Result<(Vec<Output>, Counts), PhaseError> {
    let jobs = page_records(pages, scopes, targets);
    let rendered: Vec<Result<Output, PhaseError>> = jobs
        .par_iter()
        .map(|record| {
            let text = match record.scope {
                Scope::Rules => pages.rule(record),
                Scope::Objectives => pages.objective(record),
                Scope::Threats => pages.threat(record),
            }
            .map_err(|error| PhaseError::rendering(&record.uuid, &Cause::Other(error)))?;
            let path = pages
                .settings
                .folder(record.scope)
                .join(pages.filename(record));
            Ok(Output::text(path, page(&text)))
        })
        .collect();
    let mut outputs = Vec::with_capacity(rendered.len());
    let mut counts = Counts::default();
    for (record, output) in jobs.iter().zip(rendered) {
        outputs.push(output?);
        counts.add(record.scope);
    }
    Ok((outputs, counts))
}

/// The objects whose pages a run of `scopes` writes (only those of `targets`
/// when given): threats, objectives, then rules, each by name.
fn page_records<'c>(
    pages: &Pages<'c, '_>,
    scopes: &[Scope],
    targets: Option<&std::collections::BTreeSet<String>>,
) -> Vec<&'c Record> {
    let mut records = Vec::new();
    for scope in [Scope::Threats, Scope::Objectives, Scope::Rules] {
        if !scopes.contains(&scope) {
            continue;
        }
        for record in pages.catalog.records(scope) {
            if targets.is_some_and(|targets| !targets.contains(&record.uuid)) {
                continue;
            }
            records.push(record);
        }
    }
    records
}

/// The names of the threats whose pages, in a run of `scopes` (only the
/// objects of `targets` when given), need the details of their CVEs: with
/// `[cve] retrieve_details` on, each identifier's record is asked of the
/// host's [`cve::CveSource`] and the page is a table of them. Empty when the
/// setting is off: the pages then list each identifier as a link.
pub fn cve_details_needed(
    pages: &Pages<'_, '_>,
    scopes: &[Scope],
    targets: Option<&std::collections::BTreeSet<String>>,
) -> Vec<String> {
    if !pages.settings.cve_details {
        return Vec::new();
    }
    page_records(pages, scopes, targets)
        .into_iter()
        .filter(|record| match &record.model {
            Model::Threat(threat) => {
                !cve::identifiers(threat.threat.cve.as_deref().unwrap_or_default()).is_empty()
            }
            _ => false,
        })
        .map(|record| record.name.clone())
        .collect()
}

/// The folders' index pages, GitLab's `.order` files and the root README,
/// when `folder_index_pages` is on (`write_index`).
///
/// # Errors
///
/// A relation count failed, named by its object.
pub fn index_pages(pages: &Pages<'_, '_>) -> Result<Vec<Output>, PhaseError> {
    let settings = pages.settings;
    if !settings.folder_index_pages {
        return Ok(Vec::new());
    }
    let mut outputs = Vec::new();
    for (scope, title) in FOLDER_TITLES {
        let text = pages.folder_index(scope, title).map_err(|(uuid, error)| {
            if uuid.is_empty() {
                PhaseError::new(error)
            } else {
                PhaseError::new(format!("{error} while rendering {uuid}"))
            }
        })?;
        let folder = settings.folder(scope);
        outputs.push(Output::text(folder.join("README.md"), page(&text)));
        if settings.flavor == Flavor::Gitlab {
            outputs.push(Output::text(folder.join(".order"), pages.order(scope)));
        }
    }
    let root = pages.root_index().map_err(PhaseError::new)?;
    outputs.push(Output::text(settings.output.join("README.md"), page(&root)));
    Ok(outputs)
}

/// Whether `text` reads like an object page this command wrote: a Metadata
/// table whose first row is the UUID (`is_generated_page`).
pub fn is_generated_page(text: &str) -> bool {
    text.contains("## Metadata\n")
        && text.lines().any(|line| {
            line.strip_prefix("| UUID | `")
                .and_then(|rest| rest.strip_suffix("` |"))
                .is_some_and(|uuid| !uuid.is_empty() && !uuid.contains('`'))
        })
}

/// The pages in the folders of `scopes` no object writes any more: `*.md`
/// files directly in the folder, not `README.md`, that read as generated
/// pages (`prune_stale_pages`), sorted.
pub fn stale_pages(pages: &Pages<'_, '_>, scopes: &[Scope]) -> Vec<PathBuf> {
    let mut stale = Vec::new();
    for scope in Scope::ALL {
        if !scopes.contains(&scope) {
            continue;
        }
        let folder = pages.settings.folder(scope);
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        let live: HashSet<String> = pages
            .catalog
            .records(scope)
            .iter()
            .map(|record| pages.filename(record))
            .collect();
        let live_files: HashSet<(u64, u64)> = live
            .iter()
            .filter_map(|name| file_id(&folder.join(name)))
            .collect();
        let mut found: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
            .collect();
        found.sort();
        for path in found {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if live.contains(&name) || name == "README.md" {
                continue;
            }
            if file_id(&path).is_some_and(|id| live_files.contains(&id)) {
                continue;
            }
            let generated =
                std::fs::read_to_string(&path).is_ok_and(|text| is_generated_page(&text));
            if generated {
                stale.push(path);
            }
        }
    }
    stale
}

/// A file's device and inode, so a page under another spelling of a live
/// page's name on a case-insensitive file system is not removed.
#[cfg(unix)]
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .map(|meta| (meta.dev(), meta.ino()))
}

/// Without inode numbers, a live page is matched by its name alone.
#[cfg(not(unix))]
fn file_id(_path: &Path) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_hosts() {
        assert_eq!(
            flavor_for_url("git@github.com:org/repo.git"),
            Some(Flavor::Github)
        );
        assert_eq!(
            flavor_for_url("https://user@gitlab.example.org:8443/x"),
            Some(Flavor::Gitlab)
        );
        assert_eq!(
            flavor_for_url("https://dev.azure.com/org/p/_git/r"),
            Some(Flavor::AzureDevops)
        );
        assert_eq!(
            flavor_for_url("https://org.visualstudio.com/p"),
            Some(Flavor::AzureDevops)
        );
        assert_eq!(flavor_for_url("https://example.org/x"), None);
    }

    #[test]
    fn generated_pages() {
        assert!(is_generated_page("# X\n\n## Metadata\n| UUID | `u` |\n"));
        assert!(!is_generated_page("# X\n\n## Metadata\n| UUID | u |\n"));
        assert!(!is_generated_page("| UUID | `u` |\n"));
    }

    #[test]
    fn pages_end_with_one_newline() {
        assert_eq!(page("a\n\n \n"), "a\n");
        assert_eq!(page("a"), "a\n");
    }
}
