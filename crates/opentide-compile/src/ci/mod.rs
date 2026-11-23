//! The CI pipelines `opentide setup ci` writes (`ci/`, UC-3.2c #916): a
//! GitHub Actions workflow, a GitLab CI pipeline or an Azure Pipelines
//! definition that validates the catalogue (SARIF for code scanning, a Code
//! Quality report for GitLab, each job's summary), generates, deploys to
//! staging from a pull request and to production from the default branch,
//! writes back what the production deploy recorded, keeps the inflight
//! preview shards, and shares and documents on request.
//!
//! Each pipeline is a minijinja template (`templates/`), the shell its jobs
//! run macros of `scripts.sh.j2`; [`render`] fills it from [`Options`]. A
//! value is `[[ value ]]` in a template, since GitHub Actions writes its own
//! expressions `${{ }}`. The commands and conditions the jobs share are
//! built here once, as `ci/stages.py` and `ci/gates.py` build them.

use std::borrow::Cow;
use std::sync::LazyLock;

use indexmap::IndexMap;
use minijinja::syntax::SyntaxConfig;
use minijinja::{Environment, Value, context};

/// A CI provider (`setup ci <provider>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// GitHub Actions.
    GitHub,
    /// GitLab CI.
    GitLab,
    /// Azure Pipelines.
    Azure,
}

impl Provider {
    /// The provider by its command-line name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "github" => Some(Self::GitHub),
            "gitlab" => Some(Self::GitLab),
            "azure" => Some(Self::Azure),
            _ => None,
        }
    }

    /// Its command-line name.
    pub fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Azure => "azure",
        }
    }

    /// The file it reads, from the repository.
    pub fn path(self) -> &'static str {
        match self {
            Self::GitHub => ".github/workflows/opentide.yml",
            Self::GitLab => ".gitlab-ci.yml",
            Self::Azure => "azure-pipelines.yml",
        }
    }

    /// What the file is, as `setup` lists what it wrote.
    pub fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub Actions pipeline",
            Self::GitLab => "GitLab CI pipeline",
            Self::Azure => "Azure Pipelines pipeline",
        }
    }

    fn template(self) -> &'static str {
        match self {
            Self::GitHub => "github.yml.j2",
            Self::GitLab => "gitlab-ci.yml.j2",
            Self::Azure => "azure-pipelines.yml.j2",
        }
    }
}

/// The platforms whose queries a pipeline checks on a live tenant
/// (`QUERY_VALIDATION_PLATFORMS`), in the platform table's order.
pub fn query_validation_platforms() -> Vec<&'static str> {
    use opentide_schema::platforms::ids_where;
    ids_where(|platform| platform.live_check)
}

/// The commands of the catalogue gate, which write findings reports.
pub const GATE_COMMANDS: [&str; 2] = ["validate", "lint"];

/// Where the gate commands write their reports.
pub const REPORTS_DIR: &str = "opentide-reports";

/// The rules folder when the workspace names none (`DEFAULT_RULES_FOLDER`).
pub const DEFAULT_RULES_FOLDER: &str = "objects/rules";

/// What a pipeline is rendered from (`CiRenderOptions`).
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the switches of `setup ci`, one field each"
)]
pub struct Options {
    /// The provider.
    pub provider: Provider,
    /// The platforms the repository enables, as `configurations` keys.
    pub platforms: Vec<String>,
    /// Deploy to staging tenants from pull requests.
    pub staging: bool,
    /// Keep the inflight preview shards.
    pub inflight: bool,
    /// Share changed objects from the default branch.
    pub sharing: bool,
    /// Gate `lint` on the changed object files only.
    pub lint_changed: bool,
    /// Build and publish the explorer (GitHub Pages).
    pub explorer_pages: bool,
    /// The Python the jobs install opentide with.
    pub python_version: String,
    /// The opentide release every job installs.
    pub opentide_version: String,
    /// The branch that deploys (`$CI_DEFAULT_BRANCH` for GitLab).
    pub default_branch: String,
    /// The folder the documentation job writes (`docs`).
    pub docs_output: String,
    /// The workspace's rules folder, from the repository root.
    pub rules_folder: String,
    /// For each enabled platform that has tenants configured, the variables
    /// those tenants' credentials name in the repository's platform file
    /// ([`tenant_variables`]; a platform without tenants has no entry): the
    /// jobs that reach a tenant map them from the CI secret store
    /// ([`secret_names`]), and a query-checked platform's live check is
    /// skipped when one is unset.
    pub credentials: IndexMap<String, Vec<String>>,
    /// The variables `sharing.toml`'s destinations name ([`env_references`]):
    /// the share job maps them.
    pub sharing_credentials: Vec<String>,
    /// Azure Library variable groups the pipeline links (`--variable-group`):
    /// each is a `- group:` entry, which makes `variables:` a list. Empty on
    /// the other providers.
    pub variable_groups: Vec<String>,
}

/// Why a pipeline could not be rendered: a template that does not render,
/// which is a bug.
#[derive(Debug, thiserror::Error)]
#[error("the {provider} pipeline template does not render: {source}")]
pub struct RenderError {
    provider: &'static str,
    #[source]
    source: minijinja::Error,
}

/// The opentidehq/explorer release `--explorer-pages` builds the site from:
/// the one that reads the bundle this opentide's `generate explorer` writes
/// (#1693). The job checks out [`EXPLORER_COMMIT`], the tag's commit, so a
/// later push to the explorer, or a moved tag, never changes a user's pages.
/// Bump both together when an explorer release reads a new bundle.
pub const EXPLORER_RELEASE: &str = "v0.6.0";

/// The commit [`EXPLORER_RELEASE`] tags.
pub const EXPLORER_COMMIT: &str = "7a34f7bcb0bfc24f40d222298d5fca9f30e00e3e";

/// The pipeline `options` describe, as its file holds it.
///
/// # Errors
///
/// A template that does not render.
pub fn render(options: &Options) -> Result<String, RenderError> {
    render_in(&environment_from(&SOURCES), options)
}

/// [`render`] with the templates of `env`.
fn render_in(env: &Environment<'_>, options: &Options) -> Result<String, RenderError> {
    let provider = options.provider;
    let fail = |source| RenderError {
        provider: provider.name(),
        source,
    };
    let template = env.get_template(provider.template()).map_err(fail)?;
    let text = template.render(values(options)).map_err(fail)?;
    Ok(format!("{}\n", text.trim_end_matches('\n')))
}

/// The templates, each with LF line endings whatever the checkout wrote: the
/// pipeline is a file the user commits, so it is the same bytes on every OS
/// (a Windows checkout with `core.autocrlf` would otherwise compile CRLF
/// templates in, and the filters join their lines with LF).
static SOURCES: LazyLock<Vec<(&'static str, String)>> = LazyLock::new(|| lf_sources(&TEMPLATES));

/// `templates` with every CRLF line ending as LF.
fn lf_sources(templates: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    templates
        .iter()
        .map(|(name, source)| (*name, source.replace("\r\n", "\n")))
        .collect()
}

fn environment_from(sources: &'static [(&'static str, String)]) -> Environment<'static> {
    let mut env = Environment::new();
    if let Ok(syntax) = SyntaxConfig::builder()
        .variable_delimiters("[[", "]]")
        .build()
    {
        env.set_syntax(syntax);
    }
    env.set_trim_blocks(true);
    env.set_lstrip_blocks(true);
    env.set_keep_trailing_newline(true);
    env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
    env.add_filter("scalar", scalar);
    env.add_filter("items", |items: Vec<String>, pad: usize| -> String {
        items
            .into_iter()
            .map(|item| format!("{}- {}", " ".repeat(pad), scalar(item, pad + 2)))
            .collect::<Vec<_>>()
            .join("\n")
    });
    env.add_filter("lines", |text: String| -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    });
    for (name, source) in sources {
        // A template that does not parse fails every render, which the
        // tests of each provider catch.
        let _ = env.add_template(name, source.as_str());
    }
    env
}

const TEMPLATES: [(&str, &str); 4] = [
    ("scripts.sh.j2", include_str!("templates/scripts.sh.j2")),
    ("github.yml.j2", include_str!("templates/github.yml.j2")),
    (
        "gitlab-ci.yml.j2",
        include_str!("templates/gitlab-ci.yml.j2"),
    ),
    (
        "azure-pipelines.yml.j2",
        include_str!("templates/azure-pipelines.yml.j2"),
    ),
];

/// `text` as a YAML scalar in a block at `indent` spaces: a `|` block when it
/// spans lines, plain when YAML reads it back as the same string, double
/// quoted otherwise.
fn scalar(text: String, indent: usize) -> String {
    if text.contains('\n') {
        let indicator = if text.ends_with('\n') { "|" } else { "|-" };
        let pad = " ".repeat(indent);
        let body: Vec<String> = text
            .trim_end_matches('\n')
            .split('\n')
            .map(|line| {
                if line.is_empty() {
                    String::new()
                } else {
                    format!("{pad}{line}")
                }
            })
            .collect();
        return format!("{indicator}\n{}", body.join("\n"));
    }
    let plain = opentide_schema::node::load(&format!("k: {text}\n"))
        .ok()
        .and_then(|document| {
            document
                .root()
                .and_then(|root| root.get("k"))
                .and_then(|value| value.value.as_str().map(str::to_owned))
        })
        .is_some_and(|read| read == text);
    if plain && !text.is_empty() {
        text
    } else {
        serde_json::to_string(&text).unwrap_or(text)
    }
}

/// A shell word, quoted as `shlex.quote` quotes it.
pub fn shell_word(text: &str) -> Cow<'_, str> {
    shlex::try_quote(text).unwrap_or(Cow::Borrowed(text))
}

/// `pip install "opentide==$OPENTIDE_VERSION"`: every job installs the
/// release the pipeline's variable pins.
const PIP_INSTALL: &str = "pip install \"opentide==$OPENTIDE_VERSION\"";

/// `[skip deploy]` or the `skip-deploy` label leaves out the jobs that reach
/// a tenant, on GitHub (`github_not_skipped`).
const GITHUB_NOT_SKIPPED: &str = "!contains(github.event.head_commit.message, '[skip deploy]') && !contains(github.event.pull_request.title, '[skip deploy]') && !contains(github.event.pull_request.labels.*.name, 'skip-deploy')";

/// Exits a job's script when its commit asks to skip deploys, on Azure
/// (`azure_skip_guard`).
const AZURE_SKIP_GUARD: &str = "commit=\"${SYSTEM_PULLREQUEST_SOURCECOMMITID:-${BUILD_SOURCEVERSION:-}}\"; if [ -n \"$commit\" ] && git log -1 --format=%B \"$commit\" 2>/dev/null | grep -qF '[skip deploy]'; then echo \"[skip deploy] or the skip-deploy label: no live query check, deploy or share in this pipeline.\"; exit 0; fi";

/// Replace the workspace's configuration with the default branch's, before
/// anything sends a credential (`trusted_platform_config_commands`).
fn trusted_config(branch: &str) -> Vec<String> {
    vec![
        "rm -rf -- .opentide/configurations".to_owned(),
        format!(
            "if [ \"$(git rev-parse --is-shallow-repository)\" = true ]; then git fetch --depth=1 origin {branch}; else git fetch origin {branch}; fi"
        ),
        "if ! git cat-file -e FETCH_HEAD:.opentide/configurations 2>/dev/null; then echo \"The default branch has no .opentide/configurations yet, so no tenant is reviewed. Skipped without using platform credentials.\"; exit 0; fi".to_owned(),
        "git checkout FETCH_HEAD -- .opentide/configurations".to_owned(),
    ]
}

/// The live check of the rules a run changed, skipped (exit 2) when a
/// variable the tenants name is unset (`query_validation_command`).
fn query_check(platform: &str, variables: &[String]) -> String {
    let live = format!("opentide validate query --platform {platform} --live --changed");
    if variables.is_empty() {
        return live;
    }
    let clauses: Vec<String> = variables
        .iter()
        .map(|name| format!("[ -z \"${name}\" ]"))
        .collect();
    format!(
        "if {}; then echo skip {platform} live query validation {}; exit 2; else {live}; fi",
        clauses.join(" || "),
        variables.join(" ")
    )
}

/// [`query_check`] when the default branch's platform file declares a
/// tenant, else a note (`reviewed_query_validation_command`).
fn reviewed_query_check(platform: &str, variables: &[String]) -> String {
    let config = shell_word(&format!(
        ".opentide/configurations/platforms/{platform}.toml"
    ))
    .into_owned();
    format!(
        "if grep -qs '^[^#]*tenants' {config}; then {}; else echo \"The default branch has no {platform} tenant yet, so no tenant is reviewed. Skipped {platform} live query validation without using platform credentials.\"; fi",
        query_check(platform, variables)
    )
}

/// The catalogue gate, each command writing its report in `format`
/// (`object_validate_commands`).
fn gate(format: &str, lint_changed: bool) -> Vec<String> {
    GATE_COMMANDS
        .iter()
        .map(|command| {
            let changed = if lint_changed && *command == "lint" {
                " --changed"
            } else {
                ""
            };
            let suffix = if format == "sarif" {
                ".sarif".to_owned()
            } else {
                format!(".{format}.json")
            };
            format!(
                "opentide {command} --strict{changed} --format {format} --output {REPORTS_DIR}/{command}{suffix}"
            )
        })
        .collect()
}

/// The Code Quality merge GitLab's validate job runs in `after_script`:
/// GitLab Runner uploads one `codequality` report file, so the gate
/// commands' reports become `opentide-reports/codequality.json`. It runs on
/// the job's Python image, the release installs no module for it (#1656). A
/// report that is missing, empty or not a JSON array (its command never ran
/// or crashed) is skipped with a note, so the merged file is always a report,
/// `[]` at worst; an issue whose `fingerprint` is already in is kept once.
fn codequality_merge() -> String {
    let inputs: Vec<String> = GATE_COMMANDS
        .iter()
        .map(|command| format!("{REPORTS_DIR}/{command}.codequality.json"))
        .collect();
    format!(
        "python3 - {REPORTS_DIR}/codequality.json {} <<'PY'\n{CODEQUALITY_MERGE}PY\n",
        inputs.join(" ")
    )
}

/// [`codequality_merge`]'s Python: the output, then the reports to merge.
const CODEQUALITY_MERGE: &str = r#"import json, os, sys
output, *reports = sys.argv[1:]
issues, seen = [], set()
for path in reports:
    try:
        with open(path, encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError) as error:
        print(f"opentide codequality: {path} skipped ({error})", file=sys.stderr)
        continue
    if not isinstance(document, list):
        print(f"opentide codequality: {path} is not a Code Quality report; skipped", file=sys.stderr)
        continue
    for issue in (item for item in document if isinstance(item, dict)):
        fingerprint = issue.get("fingerprint")
        if isinstance(fingerprint, str):
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
        issues.append(issue)
os.makedirs(os.path.dirname(output), exist_ok=True)
with open(output, "w", encoding="utf-8") as stream:
    json.dump(issues, stream, indent=2, ensure_ascii=False)
    stream.write("\n")
"#;

/// The variables a step that reaches `platform`'s tenants maps from the CI
/// secret store, sorted: exactly the `$NAME`s the repository's tenants of
/// that platform name in their `setup` values ([`Options::credentials`];
/// `opentide doctor`'s credentials check reads the same `$NAME` values, from
/// the merged configuration), so a tenant gets
/// its credential in CI as it does locally and no name that no tenant uses
/// is asked for. Only a platform with no tenants configured (no entry in
/// `credentials`) falls back to the names its bundled platform file
/// references. No other platform's variable is in it (#1689). A name the CI
/// runner sets itself ([`runner_owned`]) is left out: mapping it from the
/// secret store would replace the runner's own value.
pub fn platform_secret_names(options: &Options, platform: &str) -> Vec<String> {
    if let Some(tenant_names) = options.credentials.get(platform) {
        return mappable(tenant_names.clone());
    }
    let bundled = format!("platforms/{platform}.toml");
    mappable(
        opentide_schema::configuration::bundled::FILES
            .iter()
            .filter(|(path, _)| *path == bundled)
            .flat_map(|(_, text)| references(text()))
            .collect(),
    )
}

/// The variables the deploy steps map, sorted: [`platform_secret_names`] of
/// every platform the repository enables, as a deploy reaches each of them.
/// A platform it does not enable contributes nothing.
pub fn secret_names(options: &Options) -> Vec<String> {
    let mut names: Vec<String> = options
        .platforms
        .iter()
        .chain(options.credentials.keys())
        .flat_map(|platform| platform_secret_names(options, platform))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The variables the share job maps: `sharing.toml`'s, as [`secret_names`].
pub fn sharing_names(options: &Options) -> Vec<String> {
    mappable(options.sharing_credentials.clone())
}

fn mappable(mut names: Vec<String>) -> Vec<String> {
    names.retain(|name| !runner_owned(name));
    names.sort();
    names.dedup();
    names
}

/// Whether the CI runner or the job itself sets `name` (`PATH`, `HOME`,
/// `CI`, `GITHUB_*`, `RUNNER_*`, Azure's `BUILD_*` and `SYSTEM_*`, GitLab's
/// `CI_*`, the pipeline's own `OPENTIDE_*`, ...), in any case: a pipeline
/// never maps it from the secret store, and `setup ci` warns a tenant that
/// names one.
pub fn runner_owned(name: &str) -> bool {
    const NAMES: [&str; 22] = [
        "PATH",
        "HOME",
        "SHELL",
        "USER",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "HOSTNAME",
        "TERM",
        "IFS",
        "CI",
        "TF_BUILD",
        "AZURE_HTTP_USER_AGENT",
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "GIT_DIR",
        "SSL_CERT_FILE",
    ];
    const PREFIXES: [&str; 14] = [
        "GITHUB_",
        "RUNNER_",
        "ACTIONS_",
        "CI_",
        "GITLAB_",
        "FF_",
        "AGENT_",
        "BUILD_",
        "SYSTEM_",
        "PIPELINE_",
        "RELEASE_",
        "OPENTIDE_",
        "LD_",
        "PIP_",
    ];
    let upper = name.to_ascii_uppercase();
    NAMES.contains(&upper.as_str()) || PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
}

/// The variables a configuration file's string values name as a whole
/// (`$NAME` or `${NAME}`), anywhere in it, sorted: what `sharing.toml`'s
/// destinations read from the environment. A file that is not TOML names
/// none.
pub fn env_references(text: &str) -> Vec<String> {
    fn walk(value: &toml::Value, found: &mut Vec<String>) {
        match value {
            toml::Value::String(text) => {
                if let Some(name) = crate::plan::env_reference(text) {
                    found.push(name.to_owned());
                }
            }
            toml::Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
            toml::Value::Table(table) => table.values().for_each(|item| walk(item, found)),
            _ => {}
        }
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(document) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    document.values().for_each(|value| walk(value, &mut found));
    found.sort();
    found.dedup();
    found
}

/// `$NAME` references in `text`, an upper-case letter then upper-case
/// letters, digits and `_`.
fn references(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        rest = &rest[at + 1..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if name.starts_with(|c: char| c.is_ascii_uppercase()) {
            found.push(name);
        }
    }
    found
}

/// The tenants a platform file configures. A file that is not TOML has none.
fn tenants_of(text: &str) -> Vec<toml::Value> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(document) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    match document.get("tenants") {
        Some(toml::Value::Array(items)) => items.clone(),
        Some(table @ toml::Value::Table(_)) => vec![table.clone()],
        _ => Vec::new(),
    }
}

/// Whether a platform file configures at least one tenant: then its
/// [`tenant_variables`], even none, are the credentials its jobs map.
pub fn has_tenants(text: &str) -> bool {
    !tenants_of(text).is_empty()
}

/// The variables a platform file's tenants name in their `setup` values
/// (`workspace_credential_names`): each value that is `$NAME` or `${NAME}`
/// as a whole, sorted. A file that is not TOML names none.
pub fn tenant_variables(text: &str) -> Vec<String> {
    let mut names: Vec<String> = tenants_of(text)
        .iter()
        .filter_map(|tenant| tenant.get("setup").and_then(toml::Value::as_table))
        .flat_map(|setup| setup.values())
        .filter_map(|value| value.as_str().and_then(crate::plan::env_reference))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Whether a platform file enables its platform (`discover_enabled_platforms`):
/// a `[platform]` table and an `enabled = true` line.
pub fn enables(text: &str) -> bool {
    let section = text.lines().any(|line| line.trim_end() == "[platform]");
    let enabled = text.lines().any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        key.trim_end().eq_ignore_ascii_case("enabled")
            && !key.starts_with(char::is_whitespace)
            && value.trim().eq_ignore_ascii_case("true")
    });
    section && enabled
}

/// One job-like entry of a pipeline: what it is, where it sits and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// The Azure stage it sits in; `None` where there is no stage.
    stage: Option<String>,
    /// `job`, `deployment` or `template`.
    kind: &'static str,
    name: String,
}

/// The pipeline's stages (Azure only) and its job-like entries, as `provider`
/// names them: a GitHub workflow's `jobs:` keys, a GitLab pipeline's
/// top-level job keys (hidden `.templates` and the reserved keywords left
/// out), an Azure pipeline's stages and, in each, its `job:`, `deployment:`
/// and `template:` entries. Both empty when `text` is not YAML.
fn pipeline_entries(provider: Provider, text: &str) -> (Vec<String>, Vec<Entry>) {
    use crate::Json;
    let Some(root) = opentide_schema::node::load(text)
        .ok()
        .and_then(|document| document.root().map(|root| Json::from_node(root)))
    else {
        return (Vec::new(), Vec::new());
    };
    let (mut stages, mut entries) = (Vec::new(), Vec::new());
    let plain = |name: &String| Entry {
        stage: None,
        kind: "job",
        name: name.clone(),
    };
    match provider {
        Provider::GitHub => {
            if let Some(jobs) = root.get("jobs").and_then(Json::as_object) {
                entries.extend(jobs.iter().map(|(name, _)| plain(name)));
            }
        }
        Provider::GitLab => {
            const RESERVED: [&str; 11] = [
                "stages",
                "variables",
                "default",
                "workflow",
                "include",
                "image",
                "services",
                "cache",
                "before_script",
                "after_script",
                "spec",
            ];
            if let Some(top) = root.as_object() {
                entries.extend(
                    top.iter()
                        .filter(|(name, value)| {
                            !name.starts_with('.')
                                && !RESERVED.contains(&name.as_str())
                                && value.as_object().is_some()
                        })
                        .map(|(name, _)| plain(name)),
                );
            }
        }
        Provider::Azure => {
            const KINDS: [&str; 3] = ["job", "deployment", "template"];
            let entries_of = |list: Option<&Json>, stage: Option<&str>| -> Vec<Entry> {
                list.and_then(Json::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|item| {
                        KINDS.iter().find_map(|kind| {
                            item.get(kind).and_then(Json::as_str).map(|name| Entry {
                                stage: stage.map(str::to_owned),
                                kind,
                                name: name.to_owned(),
                            })
                        })
                    })
                    .collect()
            };
            for item in root
                .get("stages")
                .and_then(Json::as_array)
                .into_iter()
                .flatten()
            {
                match item.get("stage").and_then(Json::as_str) {
                    Some(stage) => {
                        stages.push(stage.to_owned());
                        entries.extend(entries_of(item.get("jobs"), Some(stage)));
                    }
                    // A `- template:` stage list: no stage to name.
                    None => {
                        entries.extend(entries_of(Some(&Json::Array(vec![item.clone()])), None));
                    }
                }
            }
            entries.extend(entries_of(root.get("jobs"), None));
        }
    }
    (stages, entries)
}

/// What `before` holds that `after` does not, in `before`'s order, each as
/// the pipeline's own words: `job intel_sources` (GitHub, GitLab),
/// `stage Intel (job intel_sources)` for a stage that is gone with what it
/// held, `job Deploy/approve_prod` or `deployment Deploy/approve_prod` for an
/// entry of a stage that is kept. Jobs are compared as (stage, name) pairs.
/// What a regenerate removes from a pipeline someone added to.
pub fn dropped_jobs(provider: Provider, before: &str, after: &str) -> Vec<String> {
    let (kept_stages, kept) = pipeline_entries(provider, after);
    let (stages, entries) = pipeline_entries(provider, before);
    let describe = |entry: &Entry| match &entry.stage {
        Some(stage) => format!("{} {stage}/{}", entry.kind, entry.name),
        None => format!("{} {}", entry.kind, entry.name),
    };
    let mut dropped = Vec::new();
    for stage in stages.iter().filter(|stage| !kept_stages.contains(stage)) {
        let inside: Vec<String> = entries
            .iter()
            .filter(|entry| entry.stage.as_deref() == Some(stage))
            .map(|entry| format!("{} {}", entry.kind, entry.name))
            .collect();
        dropped.push(if inside.is_empty() {
            format!("stage {stage}")
        } else {
            format!("stage {stage} ({})", inside.join(", "))
        });
    }
    dropped.extend(
        entries
            .iter()
            .filter(|entry| {
                !kept.contains(entry)
                    && entry
                        .stage
                        .as_ref()
                        .is_none_or(|stage| kept_stages.contains(stage))
            })
            .map(describe),
    );
    dropped
}

/// The Library variable groups the Azure pipeline `text` links: the
/// `- group:` entries of its top-level `variables:` list, in order.
pub fn variable_groups(text: &str) -> Vec<String> {
    use crate::Json;
    opentide_schema::node::load(text)
        .ok()
        .and_then(|document| document.root().map(|root| Json::from_node(root)))
        .and_then(|root| root.get("variables").and_then(Json::as_array).cloned())
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("group").and_then(Json::as_str).map(str::to_owned))
        .collect()
}

/// The file's first lines: how to regenerate it, and every variable the jobs
/// map from the CI secret store (`names`, then the share job's).
fn header(options: &Options, names: &[String]) -> String {
    let mut listed = names.to_vec();
    listed.extend(sharing_names(options));
    let listed = mappable(listed);
    let mut header = format!(
        "# Generated by opentide — regenerate with `opentide setup ci {}`\n",
        options.provider.name()
    );
    if !options.variable_groups.is_empty() {
        // Keep the groups through a regenerate: the line is what people run.
        header.truncate(header.len() - "`\n".len());
        for group in &options.variable_groups {
            header.push_str(&format!(" --variable-group {}", shell_word(group)));
        }
        header.push_str("`\n");
    }
    // A pipeline that maps no variable asks for none (#1689).
    if !listed.is_empty() {
        header.push_str(
            "# Platform credentials are read from the environment. Set these in the CI secret store:\n",
        );
    }
    for name in listed {
        header.push_str(&format!("#   {name}\n"));
    }
    header
}

/// The template's values.
fn values(options: &Options) -> Value {
    let branch = options.default_branch.as_str();
    let quoted_branch = shell_word(branch).into_owned();
    let header_names = secret_names(options);
    let header = header(options, &header_names);
    let restore = match options.provider {
        Provider::GitLab => trusted_config("\"$CI_DEFAULT_BRANCH\""),
        _ => trusted_config(&quoted_branch),
    };
    let none = Vec::new();
    let queries: Vec<Value> = options
        .platforms
        .iter()
        .filter(|platform| query_validation_platforms().contains(&platform.as_str()))
        .map(|platform| {
            let variables = options.credentials.get(platform).unwrap_or(&none);
            context! {
                platform => platform,
                id => platform.replace('_', "-"),
                command => reviewed_query_check(platform, variables),
                secrets => platform_secret_names(options, platform),
            }
        })
        .collect();
    let docs = vec![format!(
        "opentide generate docs --output {}",
        shell_word(&options.docs_output)
    )];
    let staging_commands = if options.staging {
        vec![
            "opentide deploy --dry-run --strategy PREVIEW".to_owned(),
            "opentide deploy --strategy PREVIEW --skip-unconfigured".to_owned(),
        ]
    } else {
        Vec::new()
    };
    context! {
        header => header,
        credentials => header_names,
        sharing_credentials => sharing_names(options),
        branch => branch,
        quoted_branch => quoted_branch,
        python => options.python_version,
        version => options.opentide_version,
        variable_groups => options.variable_groups,
        version_json => serde_json::to_string(&options.opentide_version).unwrap_or_default(),
        version_entry => format!(
            "OPENTIDE_VERSION: {}",
            serde_json::to_string(&options.opentide_version).unwrap_or_default()
        ),
        pip => PIP_INSTALL,
        restore => restore,
        queries => queries,
        lint_changed => options.lint_changed,
        validate_sarif => gate("sarif", options.lint_changed),
        validate_codequality => gate("codequality", options.lint_changed),
        codequality_merge => codequality_merge(),
        gate_commands => GATE_COMMANDS,
        not_skipped => GITHUB_NOT_SKIPPED,
        skip_guard => AZURE_SKIP_GUARD,
        premerge => match options.provider {
            Provider::Azure => format!(
                "and(eq(variables['Build.Reason'], 'PullRequest'), eq(variables['System.PullRequest.TargetBranch'], 'refs/heads/{branch}'))"
            ),
            _ => format!(
                "github.event_name == 'pull_request' && github.base_ref == '{branch}'"
            ),
        },
        production => format!(
            "github.event_name == 'push' && github.ref == 'refs/heads/{branch}'"
        ),
        on_default_branch => format!("eq(variables['Build.SourceBranch'], 'refs/heads/{branch}')"),
        staging => options.staging,
        staging_commands => staging_commands,
        inflight => options.inflight,
        sharing => options.sharing,
        explorer_pages => options.explorer_pages,
        explorer_release => EXPLORER_RELEASE,
        explorer_commit => EXPLORER_COMMIT,
        docs => docs,
        docs_output => options.docs_output,
        docs_path => serde_json::to_string(&format!("{}/", options.docs_output)).unwrap_or_default(),
        docs_publish_path => serde_json::to_string(&format!("$(Build.SourcesDirectory)/{}", options.docs_output)).unwrap_or_default(),
        dry_run => "opentide deploy --dry-run --strategy RELEASE",
        deploy => "opentide deploy --strategy RELEASE --skip-unconfigured",
        rules => shell_word(&options.rules_folder).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_quoted_as_the_shell_reads_them() {
        assert_eq!(shell_word("main"), "main");
        assert_eq!(shell_word("release/v1.2"), "release/v1.2");
        assert_eq!(
            shell_word("Objects/Detection Rules"),
            "'Objects/Detection Rules'"
        );
        assert_eq!(shell_word("docs"), "docs");
    }

    #[test]
    fn scalars_are_plain_unless_yaml_reads_them_otherwise() {
        assert_eq!(scalar("0.23.0".into(), 4), "0.23.0");
        assert_eq!(scalar("1.0".into(), 4), "\"1.0\"");
        assert_eq!(scalar("0".into(), 4), "\"0\"");
        assert_eq!(scalar("a: b".into(), 4), "\"a: b\"");
        assert_eq!(scalar("x\ny\n".into(), 4), "|\n    x\n    y");
        assert_eq!(scalar("x\n\ny".into(), 2), "|-\n  x\n\n  y");
    }

    #[test]
    fn platform_files_enable_and_name_variables() {
        assert!(enables("[platform]\nenabled = true\n"));
        assert!(enables("[platform]  \nENABLED=True\n"));
        assert!(!enables("[platform]\nenabled = false\n"));
        assert!(!enables("enabled = true\n"));
        assert!(!enables("[platform]\n  enabled = true\n"));
        assert_eq!(
            tenant_variables(
                "[[tenants]]\n[tenants.setup]\na = \"$B_ONE\"\nb = \"${A_TWO}\"\nc = \"$not-a-var!\"\nd = \"$B_ONE\"\n"
            ),
            ["A_TWO", "B_ONE"]
        );
        assert_eq!(tenant_variables("[tenants.setup]\nx = \"$X\"\n"), ["X"]);
        assert!(tenant_variables("not toml [").is_empty());
        assert_eq!(references("a $AB_1 $x ${Y} $9"), ["AB_1"]);
    }

    fn options(provider: Provider) -> Options {
        Options {
            provider,
            platforms: vec!["sentinel".into(), "splunk".into()],
            staging: true,
            inflight: true,
            sharing: true,
            lint_changed: true,
            explorer_pages: true,
            python_version: "3.12".into(),
            opentide_version: "0.23.0".into(),
            default_branch: "main".into(),
            docs_output: "docs".into(),
            rules_folder: "Objects/Detection Rules".into(),
            credentials: IndexMap::from([(
                "sentinel".to_owned(),
                vec!["AZURE_CLIENT_ID".to_owned()],
            )]),
            sharing_credentials: Vec::new(),
            variable_groups: Vec::new(),
        }
    }

    /// A Library variable group makes Azure's `variables:` a list, since a
    /// map cannot hold a `- group:` entry (#1790); without one it stays a map.
    #[test]
    fn variable_groups_make_azure_variables_a_list() {
        let mut azure = options(Provider::Azure);
        let plain = render(&azure).unwrap();
        assert!(plain.contains("variables:\n  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)\n  OPENTIDE_DEFAULT_BRANCH: main\n  OPENTIDE_VERSION: \"0.23.0\"\n"), "{plain}");
        assert!(!plain.contains("- group:"), "{plain}");

        azure.variable_groups = vec!["tenants".to_owned(), "Shared secrets".to_owned()];
        let written = render(&azure).unwrap();
        let list = "variables:\n  - group: tenants\n  - group: Shared secrets\n  - name: OPENTIDE_REPO_ROOT\n    value: $(Build.SourcesDirectory)\n  - name: OPENTIDE_DEFAULT_BRANCH\n    value: main\n  - name: OPENTIDE_VERSION\n    value: \"0.23.0\"\n";
        assert!(written.contains(list), "{written}");
        assert!(
            written.starts_with("# Generated by opentide — regenerate with `opentide setup ci azure --variable-group tenants --variable-group 'Shared secrets'`\n"),
            "{written}"
        );
    }

    /// Dropped jobs are compared as (stage, name) pairs and named by kind;
    /// a Library group is read from the top-level `variables:` list only.
    #[test]
    fn dropped_jobs_are_named_by_kind_and_stage() {
        let before = "stages:\n  - stage: Deploy\n    jobs:\n      - job: keep\n      - deployment: approve_prod\n      - template: extra.yml\n  - stage: Intel\n    jobs:\n      - job: intel_sources\n";
        let after = "stages:\n  - stage: Deploy\n    jobs:\n      - job: keep\n";
        assert_eq!(
            dropped_jobs(Provider::Azure, before, after),
            [
                "stage Intel (job intel_sources)",
                "deployment Deploy/approve_prod",
                "template Deploy/extra.yml"
            ]
        );
        // The same name in another stage is another job.
        let moved = "stages:\n  - stage: Other\n    jobs:\n      - job: keep\n";
        assert_eq!(
            dropped_jobs(Provider::Azure, after, moved),
            ["stage Deploy (job keep)"]
        );
        assert_eq!(
            dropped_jobs(
                Provider::GitHub,
                "jobs:\n  a: {}\n  b: {}\n",
                "jobs:\n  a: {}\n"
            ),
            ["job b"]
        );
        assert!(dropped_jobs(Provider::GitHub, "not: [yaml", "jobs: {}\n").is_empty());

        let groups = "variables:\n  - group: a\n  - name: X\n    value: y\n  - group: b c\n";
        assert_eq!(variable_groups(groups), ["a", "b c"]);
        assert!(variable_groups("variables:\n  X: y\n").is_empty());
        // Only the top-level list counts, and only plain `- group: <name>`.
        assert!(
            variable_groups("stages:\n  - stage: A\n    variables:\n      - group: x\n").is_empty()
        );
        assert!(
            variable_groups("variables:\n  - ${{ if eq(1, 1) }}:\n    - group: x\n  - template: t.yml\n  - group: [a]\n")
                .is_empty()
        );
    }

    /// A tenant that names its own variable gets it in CI (#1655): every job
    /// that reaches a tenant maps it, on GitHub from `secrets`, on Azure from
    /// the pipeline's variables in the step's `env:`.
    #[test]
    fn the_tenants_own_variables_reach_the_jobs() {
        let mut github = options(Provider::GitHub);
        github
            .credentials
            .insert("crowdstrike".to_owned(), vec!["FALCON_SECRET".to_owned()]);
        let written = render(&github).unwrap();
        assert!(written.contains("#   FALCON_SECRET\n"), "{written}");
        let mapped = "      FALCON_SECRET: ${{ secrets.FALCON_SECRET }}\n";
        // deploy_staging and deploy_production: CrowdStrike has no live
        // query check, so no validate step maps it (#1689).
        assert_eq!(written.matches(mapped).count(), 2, "{written}");

        let mut azure = options(Provider::Azure);
        azure.credentials = github.credentials.clone();
        let written = render(&azure).unwrap();
        assert!(written.contains("#   FALCON_SECRET\n"), "{written}");
        let mapped = "            FALCON_SECRET: $(FALCON_SECRET)\n";
        // deploy_staging and deploy_production: neither query check is
        // CrowdStrike's (#1689).
        assert_eq!(written.matches(mapped).count(), 2, "{written}");
        // The sentinel query check and the two deploys.
        assert_eq!(
            written
                .matches("AZURE_CLIENT_ID: $(AZURE_CLIENT_ID)")
                .count(),
            3
        );
        // A variable the pipeline does not define is left unset, not `$(NAME)`.
        let unset = "for name; do if [ \"$(printenv \"$name\")\" = \"\\$($name)\" ]; then unset \"$name\"; fi; done";
        assert_eq!(written.matches(unset).count(), 4, "{written}");
        assert!(written.contains("set -- AZURE_CLIENT_ID "), "{written}");
    }

    /// `has_tenants` tells a configured tenant from a commented-out example:
    /// the `[[tenants]]` block `setup` writes is a comment, `tenants = []`
    /// holds none, and a single `[tenants]` table is one.
    #[test]
    fn has_tenants_reads_configured_tenants_only() {
        assert!(!has_tenants(
            "[platform]\nenabled = true\n\n# [[tenants]]\n# name = \"x\"\n"
        ));
        assert!(!has_tenants("tenants = []\n"));
        assert!(!has_tenants("not toml ["));
        assert!(has_tenants("[[tenants]]\nname = \"a\"\n"));
        assert!(has_tenants("[tenants]\nname = \"a\"\n"));
        assert!(has_tenants("\u{feff}[[tenants]]\nname = \"a\"\n"));
    }

    /// A platform whose tenants name their variables is asked for exactly
    /// those: no name only the bundled platform file references (the
    /// Sentinel file's `AZURE_SUBSCRIPTION_ID`, the Defender file's
    /// `MDE_*`) reaches the header or any job. A platform with no tenants
    /// configured keeps the bundled names.
    #[test]
    fn tenants_name_the_secrets_not_the_bundled_file() {
        let bundled = |platform: &str| {
            platform_secret_names(
                &Options {
                    credentials: IndexMap::new(),
                    ..options(Provider::GitHub)
                },
                platform,
            )
        };
        assert!(bundled("sentinel").contains(&"AZURE_SUBSCRIPTION_ID".to_owned()));
        assert!(bundled("defender_for_endpoint").contains(&"MDE_CLIENT_ID".to_owned()));

        for provider in [Provider::GitHub, Provider::GitLab, Provider::Azure] {
            let mut options = options(provider);
            options.platforms = vec!["sentinel".into(), "defender_for_endpoint".into()];
            options.credentials = IndexMap::from([
                (
                    "sentinel".to_owned(),
                    vec![
                        "AZURE_CLIENT_ID".to_owned(),
                        "RETAIL_AZURE_TENANT_ID".to_owned(),
                    ],
                ),
                // Tenants whose values are all literals name no variable.
                ("defender_for_endpoint".to_owned(), Vec::new()),
            ]);
            assert_eq!(
                secret_names(&options),
                ["AZURE_CLIENT_ID", "RETAIL_AZURE_TENANT_ID"]
            );
            let written = render(&options).unwrap();
            for name in [
                "AZURE_SUBSCRIPTION_ID",
                "AZURE_WORKSPACE_ID",
                "AZURE_CLIENT_SECRET",
                "MDE_CLIENT_ID",
                "MDE_CLIENT_SECRET",
                "MDE_TENANT_ID",
            ] {
                assert!(!written.contains(name), "{name} in {written}");
            }
            assert!(written.contains("RETAIL_AZURE_TENANT_ID"), "{written}");
        }

        // No tenants configured: the bundled names are what the platform needs.
        let mut options = options(Provider::GitHub);
        options.credentials.clear();
        assert!(secret_names(&options).contains(&"AZURE_SUBSCRIPTION_ID".to_owned()));
    }

    /// #1689: a live query check maps only its own platform's variables, the
    /// gate maps none, and a deploy maps only the enabled platforms'.
    #[test]
    fn each_step_maps_only_the_variables_its_platforms_name() {
        let mut options = options(Provider::GitHub);
        options.credentials = IndexMap::from([
            ("sentinel".to_owned(), vec!["MY_SENTINEL_SECRET".to_owned()]),
            ("splunk".to_owned(), vec!["MY_SPLUNK_TOKEN".to_owned()]),
        ]);
        options.sharing_credentials = vec!["MISP_API_KEY".to_owned()];
        // The text of the job or step that starts at `start`, up to `end`.
        let part = |written: &str, start: &str, end: &str| -> String {
            let from = written
                .find(start)
                .unwrap_or_else(|| panic!("{start}: {written}"));
            let rest = &written[from + start.len()..];
            rest[..rest.find(end).unwrap_or(rest.len())].to_owned()
        };
        // Each platform has tenants, so only the names they use are mapped,
        // not the bundled files' (`AZURE_CLIENT_SECRET`, `SPLUNK_TOKEN`).
        let sentinel = ["MY_SENTINEL_SECRET"];
        let splunk = ["MY_SPLUNK_TOKEN"];

        let written = render(&options).unwrap();
        // Elastic is not enabled: its bundled variables are neither mapped
        // nor listed.
        assert!(!written.contains("ELASTIC_PROD_API_KEY"), "{written}");
        assert!(!written.contains("AZURE_CLIENT_SECRET"), "{written}");
        assert!(!written.contains("#   SPLUNK_TOKEN\n"), "{written}");
        assert!(!written.contains("secrets.SPLUNK_TOKEN"), "{written}");
        let gate = part(&written, "\n  validate:\n", "- name: Validate sentinel");
        assert!(!gate.contains("secrets."), "{gate}");
        let checks = [
            ("- name: Validate sentinel queries", sentinel, splunk),
            ("- name: Validate splunk queries", splunk, sentinel),
        ];
        for (start, own, other) in checks {
            let step = part(&written, start, "\n      - ");
            for name in own {
                assert!(
                    step.contains(&format!("{name}: ${{{{ secrets.{name} }}}}")),
                    "{step}"
                );
            }
            for name in other.iter().chain(&["MISP_API_KEY"]) {
                assert!(!step.contains(name), "{name} in {step}");
            }
        }
        let deploy = part(&written, "\n  deploy_production:\n", "    steps:");
        for name in sentinel.iter().chain(&splunk) {
            assert!(deploy.contains(name), "{name}: {deploy}");
        }
        assert!(!deploy.contains("MISP_API_KEY"), "{deploy}");
        let share = part(&written, "\n  share:\n", "    steps:");
        assert!(share.contains("MISP_API_KEY"), "{share}");
        assert!(
            !share.contains("AZURE_") && !share.contains("SPLUNK_"),
            "{share}"
        );

        options.provider = Provider::Azure;
        let written = render(&options).unwrap();
        assert!(!written.contains("ELASTIC_PROD_API_KEY"), "{written}");
        let checks = [
            ("- job: validate_query_sentinel\n", sentinel, splunk),
            ("- job: validate_query_splunk\n", splunk, sentinel),
        ];
        for (start, own, other) in checks {
            let job = part(&written, start, "- job:");
            for name in own {
                assert!(job.contains(&format!("{name}: $({name})")), "{job}");
            }
            for name in other.iter().chain(&["MISP_API_KEY"]) {
                assert!(!job.contains(name), "{name} in {job}");
            }
        }
        let deploy = part(&written, "- job: deploy_production\n", "- stage:");
        for name in sentinel.iter().chain(&splunk) {
            assert!(
                deploy.contains(&format!("{name}: $({name})")),
                "{name}: {deploy}"
            );
        }

        // With no platform enabled, a deploy maps nothing, and GitHub writes
        // no empty `env:`, which Actions refuses.
        options.provider = Provider::GitHub;
        options.platforms.clear();
        options.credentials.clear();
        options.sharing_credentials.clear();
        let written = render(&options).unwrap();
        assert!(!written.contains("secrets.AZURE_"), "{written}");
        assert!(!written.contains("env:\n    steps:"), "{written}");
        // Nor does its header ask for secrets it does not name.
        assert!(
            !written.contains("Set these in the CI secret store"),
            "{written}"
        );
    }

    /// #1693: the explorer site is built from the explorer release this
    /// opentide records, at its commit, never from a branch.
    #[test]
    fn the_explorer_checkout_is_pinned() {
        let written = render(&options(Provider::GitHub)).unwrap();
        let checkout = written
            .split("- name: Checkout explorer\n")
            .nth(1)
            .and_then(|rest| rest.split("\n\n").next())
            .unwrap_or_default();
        assert!(
            checkout.contains("repository: opentidehq/explorer"),
            "{checkout}"
        );
        let reference = checkout
            .lines()
            .find_map(|line| line.trim().strip_prefix("ref: "))
            .unwrap_or_default();
        // A commit, which no push can move, not a branch such as `main`.
        assert_eq!(reference, EXPLORER_COMMIT, "{checkout}");
        assert_eq!(reference.len(), 40, "{checkout}");
        assert!(
            reference.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{checkout}"
        );
    }

    /// The share job maps the variables `sharing.toml` names; a name the
    /// runner sets itself is never mapped; a name YAML would read as another
    /// value is quoted as a key.
    #[test]
    fn sharing_runner_and_yaml_names() {
        assert_eq!(
            env_references(
                "[[misp]]\napi_key = \"${MISP_API_KEY}\"\nurl = \"$MISP_URL\"\n[[misp]]\napi_key = \"literal\"\nnested = { key = \"$OTHER\" }\n"
            ),
            ["MISP_API_KEY", "MISP_URL", "OTHER"]
        );
        assert!(env_references("not toml [").is_empty());
        for owned in [
            "PATH",
            "home",
            "CI",
            "GITHUB_TOKEN",
            "RUNNER_TEMP",
            "AZURE_HTTP_USER_AGENT",
            "BUILD_SOURCEVERSION",
            "CI_JOB_TOKEN",
            "OPENTIDE_VERSION",
        ] {
            assert!(runner_owned(owned), "{owned}");
        }
        for free in [
            "AZURE_CLIENT_SECRET",
            "ELASTIC_API_KEY",
            "MISP_API_KEY",
            "CIRCL_KEY",
            "PATHFINDER",
        ] {
            assert!(!runner_owned(free), "{free}");
        }

        for provider in [Provider::GitHub, Provider::Azure] {
            let mut options = options(provider);
            options.credentials.insert(
                "elastic".to_owned(),
                vec!["PATH".to_owned(), "NULL".to_owned()],
            );
            options.sharing_credentials = vec!["MISP_API_KEY".to_owned(), "HOME".to_owned()];
            let written = render(&options).unwrap();
            assert!(!written.contains(" PATH:"), "{written}");
            assert!(!written.contains(" HOME:"), "{written}");
            assert!(!written.contains("#   PATH\n"), "{written}");
            assert!(written.contains("#   MISP_API_KEY\n"), "{written}");
            assert!(written.contains("\"NULL\": $"), "{written}");
            let (job, mapped) = match provider {
                Provider::GitHub => ("\n  share:\n", "MISP_API_KEY: ${{ secrets.MISP_API_KEY }}"),
                _ => ("- job: share\n", "MISP_API_KEY: $(MISP_API_KEY)"),
            };
            let share = &written[written.find(job).unwrap()..];
            assert_eq!(written.matches(mapped).count(), 1, "{written}");
            assert!(share.contains(mapped), "{share}");
        }
    }

    /// Every job runs what the pinned release has (#1656): GitLab merges its
    /// Code Quality reports on the job's Python, not with a module the
    /// package no longer ships, and the explorer job installs the release,
    /// not opentide's source.
    #[test]
    fn jobs_run_only_what_the_release_installs() {
        let gitlab = render(&options(Provider::GitLab)).unwrap();
        assert!(!gitlab.contains("opentide.ci"), "{gitlab}");
        assert!(
            gitlab.contains(
                "python3 - opentide-reports/codequality.json opentide-reports/validate.codequality.json opentide-reports/lint.codequality.json <<'PY'"
            ),
            "{gitlab}"
        );
        assert!(gitlab.contains("codequality: opentide-reports/codequality.json"));

        let github = render(&options(Provider::GitHub)).unwrap();
        let explorer = &github[github.find("  explorer:").unwrap()..];
        for gone in [
            "pip install -e",
            "opentidehq/opentide\n",
            "GH_APP",
            "OPENTIDE_REPO_TOKEN",
        ] {
            assert!(!explorer.contains(gone), "{gone} in {explorer}");
        }
        assert!(explorer.contains("run: pip install \"opentide==$OPENTIDE_VERSION\""));
    }

    #[test]
    fn crlf_templates_write_lf_pipelines() {
        // A Windows checkout with core.autocrlf compiles CRLF templates in.
        let crlf: Vec<(&'static str, String)> = TEMPLATES
            .iter()
            .map(|(name, source)| (*name, source.replace('\n', "\r\n")))
            .collect();
        assert!(crlf.iter().all(|(_, source)| source.contains("\r\n")));
        let crlf: Vec<(&'static str, &str)> = crlf
            .iter()
            .map(|(name, source)| (*name, source.as_str()))
            .collect();
        let crlf = environment_from(Box::leak(lf_sources(&crlf).into_boxed_slice()));
        assert!(SOURCES.iter().all(|(_, source)| !source.contains('\r')));
        let lf = environment_from(&SOURCES);
        for provider in [Provider::GitHub, Provider::GitLab, Provider::Azure] {
            let options = options(provider);
            let written = render_in(&crlf, &options).unwrap();
            assert!(
                !written.contains('\r'),
                "{}: CR in the pipeline",
                provider.name()
            );
            assert_eq!(written, render_in(&lf, &options).unwrap());
            assert_eq!(written, render(&options).unwrap());
        }
    }
}
