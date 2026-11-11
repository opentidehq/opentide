//! `opentide setup skills discover` and `setup skills show` (UC-4.1, #831):
//! the opentidehq/skills catalogue, fetched with the connectors' HTTP client.
//!
//! The catalogue is `manifest.json` on the skills repository's `main`
//! branch, read from raw.githubusercontent.com through the proxy and CA
//! bundle the environment names, as the Python CLI's `skills_registry` reads
//! it with `urllib`. It is never taken from anywhere else: a manifest that
//! names another repository or a ref that would climb out of it is read as
//! the default. The four authoring skills that ship with opentide are listed
//! whatever the remote catalogue says.

use std::path::{Path, PathBuf};
use std::time::Duration;

use opentide_connectors::{Environment, HttpClient, HttpSettings, TenantLabel};
use tokio_util::sync::CancellationToken;

use crate::commands::{Block, Report};
use crate::env::Env;
use crate::envelope::NextAction;
use crate::json::Json;
use crate::render::text::{Style, Text};

/// The only catalogue opentide reads.
pub const DEFAULT_SOURCE: &str = "opentidehq/skills";
/// Its branch.
pub const DEFAULT_REF: &str = "main";
/// Where its files are read.
pub const RAW_HOST: &str = "raw.githubusercontent.com";
/// `urllib.request.urlopen(..., timeout=15)`.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// Characters of a description `discover` shows; `show` prints all of it.
const DESCRIPTION_WIDTH: usize = 80;

/// One skill of the catalogue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its title.
    pub name: String,
    /// What `--install` takes, and its folder under `.agents/skills/`.
    pub slug: String,
    /// One paragraph.
    pub description: String,
}

impl Entry {
    fn new(name: &str, slug: &str, description: &str) -> Self {
        Self {
            name: name.to_owned(),
            slug: slug.to_owned(),
            description: description.to_owned(),
        }
    }

    /// The entry as the documents list it.
    fn json(&self, installed: bool) -> Json {
        Json::object([
            ("name", Json::str(&self.name)),
            ("slug", Json::str(&self.slug)),
            ("description", Json::str(&self.description)),
            ("installed", Json::Bool(installed)),
            ("path", Json::str(format!(".agents/skills/{}/", self.slug))),
        ])
    }
}

/// The authoring skills that ship inside the package
/// (`data/setup/skills/authoring/<slug>/`), nameable and listed whatever
/// the remote catalogue lists (`BUNDLED_AUTHORING_ENTRIES`).
pub fn bundled() -> Vec<Entry> {
    vec![
        Entry::new(
            "Detection engineering",
            "detection-engineering",
            "opentide's three object families: threats, objectives and rules.",
        ),
        Entry::new(
            "Detection objectives",
            "opentide-detection-objective",
            "Author objectives as objective::1.0 YAML under objects/objectives/.",
        ),
        Entry::new(
            "Detection rules",
            "opentide-detection-rule",
            "Author rules as rule::1.1 YAML under objects/rules/.",
        ),
        Entry::new(
            "Threats",
            "opentide-threat-vector",
            "Author threats as threat::1.0 YAML under objects/threats/.",
        ),
    ]
}

/// The catalogue as loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Always [`DEFAULT_SOURCE`].
    pub source: String,
    /// The ref the manifest names, when it stays in the repository.
    pub git_ref: String,
    /// The remote entries, then the bundled ones it does not list.
    pub entries: Vec<Entry>,
    /// `--refresh` was given.
    pub refreshed: bool,
}

/// How a command reaches the network.
#[derive(Clone, Copy)]
pub struct Network<'a> {
    /// The run's environment: proxies, CA bundles.
    pub env: &'a Env,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
    /// Whether Ctrl-C was pressed.
    pub interrupted: &'a (dyn Fn() -> bool + Sync),
}

impl std::fmt::Debug for Network<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("proxy", &self.proxy.map(|_| "***"))
            .finish_non_exhaustive()
    }
}

/// Whether `ref` is made of plain segments that cannot climb out of the
/// repository (`ref_is_contained`).
pub fn ref_is_contained(git_ref: &str) -> bool {
    git_ref.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    })
}

/// Whether `slug` is one directory name under `.agents/skills`
/// (`slug_is_contained`).
pub fn slug_is_contained(slug: &str) -> bool {
    let mut chars = slug.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// A JSON value as Python's `str()` writes it, for the manifest's fields.
fn text_of(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "None".to_owned(),
        serde_json::Value::Bool(true) => "True".to_owned(),
        serde_json::Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// Python's truthiness of a manifest value.
fn truthy(value: Option<&serde_json::Value>) -> bool {
    match value {
        None | Some(serde_json::Value::Null | serde_json::Value::Bool(false)) => false,
        Some(serde_json::Value::String(text)) => !text.is_empty(),
        Some(serde_json::Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(serde_json::Value::Array(items)) => !items.is_empty(),
        Some(serde_json::Value::Object(map)) => !map.is_empty(),
        Some(serde_json::Value::Bool(true)) => true,
    }
}

/// The catalogue a manifest document describes (`_parse_manifest`), the
/// bundled skills it does not list added.
pub fn parse_manifest(
    data: &serde_json::Map<String, serde_json::Value>,
    refreshed: bool,
) -> Manifest {
    let source = data
        .get("source")
        .filter(|value| truthy(Some(value)))
        .map_or_else(|| DEFAULT_SOURCE.to_owned(), text_of);
    if source.trim().to_lowercase() != DEFAULT_SOURCE {
        tracing::warn!(
            source = source.trim(),
            fallback = DEFAULT_SOURCE,
            "skills_manifest_source_rejected"
        );
    }
    let raw_ref = data
        .get("ref")
        .filter(|value| truthy(Some(value)))
        .map_or_else(|| DEFAULT_REF.to_owned(), text_of);
    let trimmed = raw_ref.trim();
    let git_ref = if trimmed.is_empty() {
        DEFAULT_REF.to_owned()
    } else if ref_is_contained(trimmed) {
        trimmed.to_owned()
    } else {
        tracing::warn!(
            "ref" = trimmed,
            fallback = DEFAULT_REF,
            "skills_manifest_ref_rejected"
        );
        DEFAULT_REF.to_owned()
    };
    let mut entries: Vec<Entry> = Vec::new();
    let items = data
        .get("skills")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for item in items {
        let Some(item) = item.as_object() else {
            continue;
        };
        let raw = if truthy(item.get("slug")) {
            item.get("slug").map(text_of).unwrap_or_default()
        } else {
            item.get("name").map(text_of).unwrap_or_default()
        };
        let slug = raw.trim().to_owned();
        if !slug_is_contained(&slug) {
            if !slug.is_empty() {
                tracing::warn!(slug = slug.as_str(), "skills_manifest_slug_rejected");
            }
            continue;
        }
        let name = item.get("name").map_or_else(|| slug.clone(), text_of);
        let description = item.get("description").map(text_of).unwrap_or_default();
        entries.push(Entry {
            name,
            slug,
            description,
        });
    }
    for entry in bundled() {
        if !entries.iter().any(|known| known.slug == entry.slug) {
            entries.push(entry);
        }
    }
    Manifest {
        source: DEFAULT_SOURCE.to_owned(),
        git_ref,
        entries,
        refreshed,
    }
}

/// The message of a catalogue that could not be read.
pub fn unavailable() -> String {
    format!(
        "Could not fetch skills catalogue from {DEFAULT_SOURCE}@{DEFAULT_REF}. \
         Check network access and that the skills repository is publicly reachable."
    )
}

/// The bytes of `path` in the skills repository at `git_ref`, or `None`
/// when they cannot be read: any transport failure or an answer that is not
/// 2xx (`fetch_github_bytes`).
pub fn fetch_file(path: &str, git_ref: &str, network: Network<'_>) -> Option<Vec<u8>> {
    if !ref_is_contained(git_ref) || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
        tracing::warn!(
            source = DEFAULT_SOURCE,
            path,
            "skills_download_url_rejected"
        );
        return None;
    }
    let url = format!("https://{RAW_HOST}/{DEFAULT_SOURCE}/{git_ref}/{path}");
    let environment = Environment::from_pairs(network.env.iter());
    let settings = HttpSettings {
        timeout: TIMEOUT,
        ..HttpSettings::default()
    };
    let label = TenantLabel::new("skills", DEFAULT_SOURCE);
    let client = HttpClient::new(&label, &settings, &environment, network.proxy).ok()?;
    let interrupted = network.interrupted;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                opentide_connectors::runtime::block_on(async {
                    let cancel = CancellationToken::new();
                    let work = async {
                        let request = client.request(reqwest::Method::GET, &url).build().ok()?;
                        let answer = client.send(request, &cancel).await.ok()?;
                        if !answer.status().is_success() {
                            return None;
                        }
                        client.bytes(answer, &cancel).await.ok()
                    };
                    // Ctrl-C stops the fetch.
                    let watch = async {
                        while !interrupted() {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        cancel.cancel();
                    };
                    tokio::select! {
                        body = work => body,
                        () = watch => None,
                    }
                })
                .ok()
                .flatten()
            })
            .join()
            .ok()
            .flatten()
    })
}

/// The live catalogue (`load_manifest`); never a packaged copy.
pub fn load(refresh: bool, network: Network<'_>) -> Result<Manifest, String> {
    let parsed = fetch_file("manifest.json", DEFAULT_REF, network)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    match parsed {
        Some(serde_json::Value::Object(data)) => Ok(parse_manifest(&data, refresh)),
        _ => {
            tracing::error!(
                source = DEFAULT_SOURCE,
                "ref" = DEFAULT_REF,
                "skills_manifest_remote_unavailable"
            );
            Err(unavailable())
        }
    }
}

/// The slugs installed under `repo/.agents/skills/` (a folder with a `SKILL.md`).
pub fn installed(repo: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(repo.join(".agents").join("skills")) else {
        return Vec::new();
    };
    let mut slugs: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir() && entry.path().join("SKILL.md").is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    slugs.sort();
    slugs
}

/// `discover`'s arguments.
#[derive(Clone, Debug, Default)]
pub struct DiscoverArgs {
    /// The repository.
    pub repo: PathBuf,
    /// `--query`.
    pub query: Option<String>,
    /// `--installed`.
    pub installed_only: bool,
    /// `--refresh`.
    pub refresh: bool,
}

/// A count as JSON.
fn count(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

/// The source as documents name it: `opentidehq/skills@main`.
fn source_of(manifest: &Manifest) -> String {
    format!("{}@{}", manifest.source, manifest.git_ref)
}

/// *text* cut at the last word that fits in *width*, then the ellipsis (`_shorten`).
pub fn shorten(text: &str, width: usize, ellipsis: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text;
    }
    let take = (width + 1).saturating_sub(ellipsis.chars().count());
    let cut: String = chars[..take.min(chars.len())].iter().collect();
    let kept = match cut.rfind(' ') {
        Some(at) if at > 0 => cut[..at].to_owned(),
        _ => {
            let mut all: Vec<char> = cut.chars().collect();
            all.pop();
            all.into_iter().collect()
        }
    };
    let trimmed = kept.trim_end_matches([' ', ',', ';', ':', '.', '—', '-']);
    format!("{trimmed}{ellipsis}")
}

/// `opentide setup skills discover`.
pub fn discover(args: &DiscoverArgs, network: Network<'_>, width: usize) -> Report {
    let command = "setup skills discover";
    let manifest = match load(args.refresh, network) {
        Ok(manifest) => manifest,
        Err(message) => return Report::error(command, message),
    };
    let installed = installed(&args.repo);
    let query = args
        .query
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let kept: Vec<&Entry> = manifest
        .entries
        .iter()
        .filter(|entry| !args.installed_only || installed.contains(&entry.slug))
        .filter(|entry| {
            query.is_empty()
                || entry.name.to_lowercase().contains(&query)
                || entry.slug.to_lowercase().contains(&query)
                || entry.description.to_lowercase().contains(&query)
        })
        .collect();
    let installed_count = kept
        .iter()
        .filter(|entry| installed.contains(&entry.slug))
        .count();
    let source = source_of(&manifest);
    let mut report = Report::completed(
        command,
        vec![
            ("source".into(), Json::str(&source)),
            ("manifest_source".into(), Json::str("remote")),
            ("manifest_refreshed".into(), Json::Bool(manifest.refreshed)),
            (
                "skills".into(),
                Json::Array(
                    kept.iter()
                        .map(|entry| entry.json(installed.contains(&entry.slug)))
                        .collect(),
                ),
            ),
            ("count".into(), count(kept.len())),
        ],
    );
    report.outcome.summary = vec![
        ("skills".into(), count(kept.len())),
        ("installed".into(), count(installed_count)),
    ];
    let noun = if kept.len() == 1 { "skill" } else { "skills" };
    let counted = match args.query.as_deref() {
        Some(query) if !query.is_empty() => format!("{} {noun} match '{query}'", kept.len()),
        _ => format!("{} {noun} available", kept.len()),
    };
    let separator = format!(" {} ", crate::render::glyphs::SEPARATOR);
    report.outcome_line =
        Some([counted, format!("{installed_count} installed"), source].join(&separator));
    if !kept.is_empty() {
        let slug_width = kept
            .iter()
            .map(|entry| crate::render::text::cell_len(&entry.slug))
            .max()
            .unwrap_or(0);
        let any_installed = installed_count > 0;
        let room = width
            .saturating_sub(slug_width + 2)
            .saturating_sub(if any_installed {
                "installed".len() + 2
            } else {
                0
            });
        let column = room.clamp(20, DESCRIPTION_WIDTH).max(20);
        let rows: Vec<Vec<Text>> = kept
            .iter()
            .map(|entry| {
                vec![
                    Text::styled(&entry.slug, &Style::new("bold")),
                    if installed.contains(&entry.slug) {
                        Text::styled("installed", &Style::new("green"))
                    } else {
                        Text::default()
                    },
                    Text::styled(
                        &shorten(&entry.description, column, "…"),
                        &Style::new("dim"),
                    ),
                ]
            })
            .collect();
        report
            .body
            .push(Block::Lines(crate::render::table::columns(&rows, 2, &[])));
    }
    report
}

/// `opentide setup skills show <name>`.
pub fn show(name: &str, repo: &Path, refresh: bool, network: Network<'_>, json: bool) -> Report {
    let command = "setup skills show";
    let manifest = match load(refresh, network) {
        Ok(manifest) => manifest,
        Err(message) => return Report::error(command, message),
    };
    let source = source_of(&manifest);
    let needle = name.trim().to_lowercase();
    let Some(entry) = manifest
        .entries
        .iter()
        .find(|entry| entry.slug.to_lowercase() == needle || entry.name.to_lowercase() == needle)
    else {
        let message = format!("skill not found: {name}");
        let mut report = Report::error(command, message.clone());
        if json {
            // The document carries the catalogue's keys after the error.
            report.outcome.data = vec![
                ("error".into(), Json::str(&message)),
                ("source".into(), Json::str(&source)),
                ("manifest_source".into(), Json::str("remote")),
                ("manifest_refreshed".into(), Json::Bool(manifest.refreshed)),
            ];
        }
        return report;
    };
    let is_installed = installed(repo).contains(&entry.slug);
    let hint = format!(
        "opentide setup skills --install {} --generic --yes",
        entry.slug
    );
    let mut report = Report::completed(
        command,
        vec![
            ("source".into(), Json::str(&source)),
            ("manifest_source".into(), Json::str("remote")),
            ("manifest_refreshed".into(), Json::Bool(manifest.refreshed)),
            ("skill".into(), entry.json(is_installed)),
            ("install_hint".into(), Json::str(&hint)),
        ],
    );
    let mut title = Text::styled(&entry.slug, &Style::new("bold"));
    if entry.name != entry.slug {
        // Rich lays the title's bold under the appended dim.
        title.append(&format!("  {}", entry.name), &Style::new("bold dim"));
    }
    let lines = vec![
        title,
        Text::plain(
            &entry
                .description
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        ),
        Text::styled(
            if is_installed {
                "installed"
            } else {
                "not installed"
            },
            &Style::new("dim"),
        ),
    ];
    report.body.push(Block::Lines(lines));
    if !is_installed {
        // `render_next_actions`: printed whole, wrapped only at a terminal.
        report.body.push(Block::Hanging(vec![(
            crate::render::outcome::next_action_text(&NextAction::new(&hint, "install it")),
            2,
        )]));
    }
    report.body_only = true;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(json: &str) -> Manifest {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        parse_manifest(value.as_object().unwrap(), false)
    }

    #[test]
    fn a_manifest_never_leaves_the_skills_repository() {
        let manifest = parsed(
            r#"{"source": "evil/skills", "ref": "../../other", "skills": [
                {"slug": "good-one", "name": "Good", "description": "d"},
                {"slug": "../escape", "name": "Bad"},
                {"name": "named-only"},
                {"slug": "", "name": ""},
                "not an object"
            ]}"#,
        );
        assert_eq!(manifest.source, DEFAULT_SOURCE);
        assert_eq!(manifest.git_ref, DEFAULT_REF);
        let slugs: Vec<&str> = manifest.entries.iter().map(|e| e.slug.as_str()).collect();
        assert_eq!(
            slugs,
            [
                "good-one",
                "named-only",
                "detection-engineering",
                "opentide-detection-objective",
                "opentide-detection-rule",
                "opentide-threat-vector"
            ]
        );
        // The case-insensitive spelling of the repository is the repository.
        assert_eq!(
            parsed(r#"{"source": "OpenTideHQ/skills", "ref": "v1.2"}"#).git_ref,
            "v1.2"
        );
    }

    #[test]
    fn the_remote_entry_wins_for_a_bundled_slug() {
        let manifest = parsed(
            r#"{"skills": [{"slug": "opentide-detection-rule", "name": "Remote", "description": "r"}]}"#,
        );
        let rule: Vec<&Entry> = manifest
            .entries
            .iter()
            .filter(|e| e.slug == "opentide-detection-rule")
            .collect();
        assert_eq!(rule.len(), 1);
        assert_eq!(rule[0].name, "Remote");
        assert_eq!(manifest.entries.len(), 4);
    }

    #[test]
    fn refs_and_slugs_are_contained() {
        assert!(ref_is_contained("main"));
        assert!(ref_is_contained("release/v1.2_x"));
        assert!(!ref_is_contained("a/../b"));
        assert!(!ref_is_contained("a//b"));
        assert!(!ref_is_contained("a?b"));
        assert!(slug_is_contained("a-b_c1"));
        assert!(!slug_is_contained("-a"));
        assert!(!slug_is_contained("a/b"));
        assert!(!slug_is_contained(""));
    }

    #[test]
    fn descriptions_are_shortened_at_a_word() {
        assert_eq!(shorten("short  text", 20, "…"), "short text");
        assert_eq!(
            shorten("Detection engineering lifecycle across the board", 30, "…"),
            "Detection engineering…"
        );
        assert_eq!(shorten("Abcdefghijklmnopqrstuvwxyz", 10, "…"), "Abcdefghi…");
        assert_eq!(shorten("one two, three", 9, "…"), "one two…");
    }

    #[test]
    fn a_file_outside_the_repository_is_never_fetched() {
        let env = Env::from_pairs([("HTTPS_PROXY", "http://127.0.0.1:9")]);
        let never = || false;
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        assert_eq!(fetch_file("../secrets", DEFAULT_REF, network), None);
        assert_eq!(fetch_file("manifest.json", "../main", network), None);
        // Refused by the proxy the environment names: no catalogue.
        assert_eq!(load(false, network).unwrap_err(), unavailable());
    }

    /// The skills repository's raw host, answered by a local stand-in through
    /// the recording proxy (nothing is recorded or written): each request's
    /// path gets the status and body *answers* name for it, else a 404.
    struct Catalogue {
        _proxy: opentide_cassette::Proxy,
        _ca: tempfile::NamedTempFile,
        env: Env,
    }

    impl Catalogue {
        fn serving(answers: &[(&str, u16, &str)]) -> Self {
            use std::io::{Read as _, Write as _};
            let answers: Vec<(String, u16, String)> = answers
                .iter()
                .map(|(path, status, body)| ((*path).to_owned(), *status, (*body).to_owned()))
                .collect();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let upstream = format!("http://{}", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let mut buffer = [0u8; 8192];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                    let path = request.split_whitespace().nth(1).unwrap_or("").to_owned();
                    let (status, body) = answers
                        .iter()
                        .find(|(wanted, _, _)| *wanted == path)
                        .map_or((404, "404: Not Found".to_owned()), |(_, status, body)| {
                            (*status, body.clone())
                        });
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            let proxy = opentide_cassette::Proxy::start(
                opentide_cassette::Mode::Record {
                    routes: std::collections::BTreeMap::from([(RAW_HOST.to_owned(), upstream)]),
                },
                opentide_cassette::Redaction::default(),
            )
            .unwrap();
            let mut ca = tempfile::NamedTempFile::new().unwrap();
            ca.write_all(proxy.ca_pem().as_bytes()).unwrap();
            let env = Env::from_pairs(
                proxy
                    .client_env(ca.path().to_str().unwrap())
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            );
            Self {
                _proxy: proxy,
                _ca: ca,
                env,
            }
        }
    }

    const MANIFEST_PATH: &str = "/opentidehq/skills/main/manifest.json";
    const MANIFEST: &str = r#"{"skills": [
        {"slug": "fancy-skill", "name": "Fancy Name", "description": "Remote one"},
        {"slug": "opentide-detection-rule", "name": "Rule", "description": "Rules"}
    ]}"#;

    fn never() -> bool {
        false
    }

    fn network(env: &Env) -> Network<'_> {
        Network {
            env,
            proxy: None,
            interrupted: &never,
        }
    }

    fn data<'a>(report: &'a Report, key: &str) -> &'a Json {
        &report
            .outcome
            .data
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("no {key} in {:?}", report.outcome.data))
            .1
    }

    #[test]
    fn a_catalogue_answer_that_is_not_2xx_is_no_catalogue() {
        // The body is a manifest: only the status says it is not one.
        let served = Catalogue::serving(&[(MANIFEST_PATH, 200, MANIFEST)]);
        let manifest = load(false, network(&served.env)).unwrap();
        assert_eq!(manifest.entries[0].slug, "fancy-skill");
        for status in [404, 500, 503] {
            let failing = Catalogue::serving(&[(MANIFEST_PATH, status, MANIFEST)]);
            assert_eq!(
                load(false, network(&failing.env)).unwrap_err(),
                unavailable(),
                "{status}"
            );
            let report = discover(
                &DiscoverArgs {
                    repo: PathBuf::from("."),
                    query: None,
                    installed_only: false,
                    refresh: false,
                },
                network(&failing.env),
                80,
            );
            assert_eq!(report.outcome.exit_code, 1);
            let failure = report.outcome.failure.as_ref().unwrap();
            assert_eq!(failure.code, "command_failed");
            assert!(
                failure
                    .message
                    .starts_with("Could not fetch skills catalogue")
            );
        }
    }

    #[test]
    fn installed_skills_are_the_folders_with_a_skill_md() {
        let repo = tempfile::tempdir().unwrap();
        let skills = repo.path().join(".agents").join("skills");
        for slug in ["opentide-detection-rule", "fancy-skill", "no-skill-md"] {
            std::fs::create_dir_all(skills.join(slug)).unwrap();
        }
        std::fs::write(skills.join("opentide-detection-rule").join("SKILL.md"), "x").unwrap();
        std::fs::write(skills.join("fancy-skill").join("SKILL.md"), "x").unwrap();
        // A file named like a skill is not one.
        std::fs::write(skills.join("loose-file"), "x").unwrap();
        assert_eq!(
            installed(repo.path()),
            ["fancy-skill", "opentide-detection-rule"]
        );
        assert!(installed(&repo.path().join("missing")).is_empty());

        let served = Catalogue::serving(&[(MANIFEST_PATH, 200, MANIFEST)]);
        let report = discover(
            &DiscoverArgs {
                repo: repo.path().to_path_buf(),
                query: None,
                installed_only: true,
                refresh: false,
            },
            network(&served.env),
            80,
        );
        assert_eq!(report.outcome.exit_code, 0);
        let Json::Array(listed) = data(&report, "skills") else {
            panic!("skills is not a list")
        };
        let slugs: Vec<&Json> = listed
            .iter()
            .filter_map(|entry| entry.get("slug"))
            .collect();
        assert_eq!(
            slugs,
            [
                &Json::str("fancy-skill"),
                &Json::str("opentide-detection-rule")
            ]
        );
        assert!(
            listed
                .iter()
                .all(|entry| entry.get("installed") == Some(&Json::Bool(true)))
        );
        assert_eq!(
            report.outcome.summary,
            vec![
                ("skills".to_owned(), Json::Int(2)),
                ("installed".to_owned(), Json::Int(2))
            ]
        );

        // `show` of an installed skill says so and offers no install.
        let shown = show(
            "fancy-skill",
            repo.path(),
            false,
            network(&served.env),
            true,
        );
        assert_eq!(
            data(&shown, "skill").get("installed"),
            Some(&Json::Bool(true))
        );
        assert_eq!(
            shown.body.len(),
            1,
            "no install hint for an installed skill"
        );
        let elsewhere = tempfile::tempdir().unwrap();
        let missing = show(
            "fancy-skill",
            elsewhere.path(),
            false,
            network(&served.env),
            true,
        );
        assert_eq!(
            data(&missing, "skill").get("installed"),
            Some(&Json::Bool(false))
        );
        assert_eq!(missing.body.len(), 2);
    }

    #[test]
    fn show_finds_a_skill_by_its_display_name() {
        let served = Catalogue::serving(&[(MANIFEST_PATH, 200, MANIFEST)]);
        let repo = tempfile::tempdir().unwrap();
        for name in ["Fancy Name", " fancy name ", "FANCY-SKILL"] {
            let report = show(name, repo.path(), false, network(&served.env), true);
            assert_eq!(report.outcome.exit_code, 0, "{name}");
            assert_eq!(
                data(&report, "skill").get("slug"),
                Some(&Json::str("fancy-skill")),
                "{name}"
            );
        }
        let report = show("Fancy", repo.path(), false, network(&served.env), true);
        assert_eq!(report.outcome.exit_code, 1);
    }
}
