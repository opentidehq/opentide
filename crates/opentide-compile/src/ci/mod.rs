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
/// (`QUERY_VALIDATION_PLATFORMS`).
pub const QUERY_VALIDATION_PLATFORMS: [&str; 6] = [
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "carbon_black_cloud",
    "elastic",
];

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
    /// For each query-checked platform, the variables its tenants'
    /// credentials name in the repository's platform file
    /// ([`tenant_variables`]): the live check is skipped when one is unset.
    pub credentials: IndexMap<String, Vec<String>>,
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

/// Every variable the bundled platform files reference (`$NAME`), sorted:
/// the secrets the header lists and GitHub's deploy jobs map
/// (`platform_credential_names`).
pub fn bundled_variables() -> Vec<String> {
    let mut names: Vec<String> = opentide_schema::configuration::bundled::FILES
        .iter()
        .filter(|(path, _)| path.starts_with("platforms/"))
        .flat_map(|(_, text)| references(text))
        .collect();
    names.sort();
    names.dedup();
    names
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

/// The variables a platform file's tenants name in their `setup` values
/// (`workspace_credential_names`): each value that is `$NAME` or `${NAME}`
/// as a whole, sorted. A file that is not TOML names none.
pub fn tenant_variables(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Ok(document) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let tenants = match document.get("tenants") {
        Some(toml::Value::Array(items)) => items.iter().collect(),
        Some(table @ toml::Value::Table(_)) => vec![table],
        _ => Vec::new(),
    };
    let mut names: Vec<String> = tenants
        .into_iter()
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

/// The template's values.
fn values(options: &Options) -> Value {
    let branch = options.default_branch.as_str();
    let quoted_branch = shell_word(branch).into_owned();
    let header_names = bundled_variables();
    let mut header = format!(
        "# Generated by opentide — regenerate with `opentide setup ci {}`\n\
         # Platform credentials are read from the environment. Set these in the CI secret store:\n",
        options.provider.name()
    );
    for name in &header_names {
        header.push_str(&format!("#   {name}\n"));
    }
    let restore = match options.provider {
        Provider::GitLab => trusted_config("\"$CI_DEFAULT_BRANCH\""),
        _ => trusted_config(&quoted_branch),
    };
    let none = Vec::new();
    let queries: Vec<Value> = options
        .platforms
        .iter()
        .filter(|platform| QUERY_VALIDATION_PLATFORMS.contains(&platform.as_str()))
        .map(|platform| {
            let variables = options.credentials.get(platform).unwrap_or(&none);
            context! {
                platform => platform,
                id => platform.replace('_', "-"),
                command => reviewed_query_check(platform, variables),
            }
        })
        .collect();
    let query_commands: Vec<String> = queries
        .iter()
        .filter_map(|query| query.get_attr("command").ok())
        .map(|command| command.to_string())
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
        branch => branch,
        quoted_branch => quoted_branch,
        python => options.python_version,
        version => options.opentide_version,
        version_entry => format!(
            "OPENTIDE_VERSION: {}",
            serde_json::to_string(&options.opentide_version).unwrap_or_default()
        ),
        pip => PIP_INSTALL,
        restore => restore,
        queries => if options.provider == Provider::GitHub { Value::from(query_commands) } else { Value::from(queries) },
        lint_changed => options.lint_changed,
        validate_sarif => gate("sarif", options.lint_changed),
        validate_codequality => gate("codequality", options.lint_changed),
        codequality_merge => format!(
            "python -m opentide.ci.codequality --output {REPORTS_DIR}/codequality.json {}",
            GATE_COMMANDS
                .iter()
                .map(|command| format!("{REPORTS_DIR}/{command}.codequality.json"))
                .collect::<Vec<_>>()
                .join(" ")
        ),
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
        }
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
