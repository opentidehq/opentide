//! `generate docs` (UC-3.2b, #915; the 0.26.0 redesign): every file a run
//! writes for the tide-corpus fixture, in each of the four flavours,
//! compared byte for byte with the files opentide 0.28.1 writes for it
//! (`tests/docs_0_28/<flavor>`: pages, folder indexes, GitLab's `.order`
//! files and the catalogue overview, diagrams included), and the oracle's
//! failure on the vscode fixture. The flavour a run picks from its CI and
//! `origin`, a rule with several platform blocks, a rule's tenants and
//! remote ids, and a threat's CVEs have no recording: their tests assert
//! what 0.28.x writes for them (compared with its pages on the same edits of
//! the fixture when they were written). Two departures from 0.28.1 are
//! deliberate and recorded in `quote_title` (GitLab's quoted titles) and
//! `inherited_techniques` (a rule's inherited techniques on its pages), and
//! the test of inherited techniques asserts the second one.
//!
//! When the fixture changes, record the pages again with 0.28.1 itself, not
//! by hand: in a venv with `pip install opentide==0.28.1`, lay the fixture
//! out as `common/golden.rs` does (`.opentide/configurations` and the
//! `objects/<family>` links) and run `opentide generate docs --flavor
//! <flavor> --output <dir>` in it, then copy `<dir>` over
//! `tests/docs_0_28/<flavor>`.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a broken fixture is a failure")]

#[path = "common/golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use opentide_compile::generate::Output;
use opentide_compile::generate::docs::catalog::{Catalog, Scope};
use opentide_compile::generate::docs::cve::{
    CveDetail, CveRecord, CveSource, Cvss, Epss, EpssDetail, Weakness,
};
use opentide_compile::generate::docs::facts::Environment as DeploymentFacts;
use opentide_compile::generate::docs::render::Pages;
use opentide_compile::generate::docs::vocab::Vocab;
use opentide_compile::generate::docs::{
    FlavorHints, Settings, cve_details_needed, index_pages, pages,
};
use opentide_compile::strategy::Statuses;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, RootOptions, Workspace};

fn open(fixture: &str) -> (tempfile::TempDir, Workspace) {
    open_edited(fixture, |_| {})
}

/// The fixture, edited by `edit` (given the workspace folder) before it is
/// opened.
fn open_edited(fixture: &str, edit: impl FnOnce(&Path)) -> (tempfile::TempDir, Workspace) {
    let dir = tempfile::tempdir().unwrap();
    let ws = dunce::canonicalize(dir.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    golden::fixture(fixture, &ws);
    edit(&ws);
    let options = RootOptions {
        repo: Some(ws.clone()),
        repo_root_env: Some(ws.clone()),
        tide_workspace_env: Some(ws.clone()),
        cwd: ws,
    };
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options { roots: options },
    )
    .unwrap();
    (dir, workspace)
}

/// Every file a full run writes, by path relative to the workspace.
fn render(workspace: &Workspace, flavor: Option<&str>) -> Result<BTreeMap<String, String>, String> {
    render_with(workspace, flavor, &FlavorHints::default())
}

/// The deployment facts of a workspace, as the command line reads them.
fn deployment_facts(workspace: &Workspace, catalog: &Catalog<'_>) -> DeploymentFacts {
    let config = opentide_compile::Json::from_node(&workspace.configuration().resolved.tree);
    let enabled = opentide_compile::plan::enabled(&config);
    DeploymentFacts::read(
        &config,
        &enabled,
        &opentide_workspace::OsFs,
        workspace.root(),
        catalog.rules.iter().map(|record| record.uuid.as_str()),
    )
}

fn render_with(
    workspace: &Workspace,
    flavor: Option<&str>,
    hints: &FlavorHints,
) -> Result<BTreeMap<String, String>, String> {
    render_cves(workspace, flavor, hints, None)
}

/// [`render_with`], the CVE details asked of `source` when given.
fn render_cves(
    workspace: &Workspace,
    flavor: Option<&str>,
    hints: &FlavorHints,
    source: Option<CveSource>,
) -> Result<BTreeMap<String, String>, String> {
    let resolved = &workspace.configuration().resolved;
    let mut settings = Settings::resolve(resolved, workspace.root(), None, flavor, hints)
        .map_err(|error| error.detail)?;
    if let Some(source) = source {
        settings.cve_source = source;
    }
    let catalog = Catalog::build(workspace.index(), Statuses::from_resolved(resolved))
        .map_err(|error| error.detail)?;
    let vocabularies = Vocabularies::bundled();
    let deployment = deployment_facts(workspace, &catalog);
    let pages_of = Pages {
        catalog: &catalog,
        settings: &settings,
        vocab: Vocab::new(&vocabularies),
        deployment: &deployment,
    };
    let (mut outputs, _) = pages(&pages_of, &Scope::ALL, None).map_err(|error| error.detail)?;
    outputs.extend(index_pages(&pages_of).map_err(|error| error.detail)?);
    Ok(outputs
        .into_iter()
        .map(|Output { path, bytes }| {
            (
                path.strip_prefix(workspace.root())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                String::from_utf8(bytes).unwrap(),
            )
        })
        .collect())
}

/// The files under `dir`, by path below `prefix`, recursively.
fn files_under(dir: &Path, prefix: &str, out: &mut BTreeMap<String, String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let key = format!("{prefix}/{name}");
        if path.is_dir() {
            files_under(&path, &key, out);
        } else {
            out.insert(key, std::fs::read_to_string(&path).unwrap());
        }
    }
}

/// Every file a run writes for the tide corpus in `flavor` is the one
/// opentide 0.28.1 writes (`tests/docs_0_28/<flavor>`).
fn check(flavor: &str) {
    let (_dir, workspace) = open("tide-corpus");
    let written = render(&workspace, Some(flavor)).unwrap();
    let mut expected = BTreeMap::new();
    files_under(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/docs_0_28")
            .join(flavor),
        "docs",
        &mut expected,
    );
    assert_eq!(
        written.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
        "{flavor}: the files written"
    );
    for (path, text) in &written {
        let golden = inherited_techniques(path, &quote_title(&expected[path]));
        assert_eq!(text, &golden, "{flavor}: {path}");
    }
}

/// The second deliberate difference: 0.28 listed only a rule's own
/// `techniques` on its page, overview row and rules-index row, and counted
/// only those, though a rule also covers the techniques its objective (or
/// the objective's threats) gives it. The corpus's Sysdig rule lists
/// T1059.004 and inherits T1059, which the pages now show, marked
/// `(inherited)`.
fn inherited_techniques(path: &str, page: &str) -> String {
    const OWN: &str = "[`T1059.004`](https://attack.mitre.org/techniques/T1059/004) \
                       Command and Scripting Interpreter: Unix Shell";
    const PARENT: &str = "[`T1059`](https://attack.mitre.org/techniques/T1059)";
    let page = page
        .replace("| `T1059.004` | ", "| `T1059.004`, `T1059` (inherited) | ")
        .replace(
            "\"d\":\"`T1059.004`\"",
            "\"d\":\"`T1059.004`, `T1059` (inherited)\"",
        );
    if !path.contains("sysdig-falco-rule") && !path.contains("8003-0000005d1a90") {
        return page;
    }
    let row = "| [`T1059.004`](https://attack.mitre.org/techniques/T1059/004) | Command and \
               Scripting Interpreter: Unix Shell | Execution |";
    page.replace(
        &format!("| ATT&CK | {OWN} |"),
        &format!("| ATT&CK | {OWN}<br>{PARENT} Command and Scripting Interpreter (inherited) |"),
    )
    .replace(
        row,
        &format!(
            "| {PARENT} | Command and Scripting Interpreter *(inherited)* | Execution | Adversaries \
             may abuse command and script interpreters to execute commands, scripts, or \
             binaries. |\n{row}"
        ),
    )
}

/// The one deliberate difference from 0.28's pages: GitLab wiki front
/// matter quotes the title (a YAML double-quoted scalar), which 0.28 wrote
/// bare, so a name with `: ` or ` #` broke the front matter or lost its end.
fn quote_title(page: &str) -> String {
    let Some(rest) = page.strip_prefix("---\ntitle: ") else {
        return page.to_owned();
    };
    let (title, rest) = rest.split_once('\n').unwrap();
    format!(
        "---\ntitle: {}\n{rest}",
        opentide_schema::node::double_quoted(title)
    )
}

/// GitLab wiki front matter is YAML that reads back as the object's name,
/// whatever the name holds: `: `, `#`, `[`, words YAML reads as other
/// types, quotes, a leading `-`.
#[test]
fn gitlab_front_matter_reads_back_as_the_name() {
    let names = [
        "Mimikatz: dump [x] #1",
        "yes",
        "null",
        "it's \"quoted\"",
        "- leading dash",
        "{a: b} & *alias",
    ];
    for name in names {
        let (_dir, workspace) = open_edited("tide-corpus", |ws| {
            let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
            let text = std::fs::read_to_string(&rule).unwrap();
            let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
            let at = lines
                .iter()
                .position(|line| line.starts_with("name:"))
                .unwrap();
            lines[at] = format!("name: {}", opentide_schema::node::double_quoted(name));
            std::fs::write(&rule, lines.join("\n") + "\n").unwrap();
        });
        let written = render_with(
            &workspace,
            None,
            &FlavorHints {
                gitlab: true,
                ..FlavorHints::default()
            },
        )
        .unwrap();
        let page = &written["docs/rules/00000000-0000-4000-8003-000000000001.md"];
        let yaml = page
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .unwrap()
            .0;
        let document = opentide_schema::node::load(yaml).unwrap();
        let title = document
            .root()
            .unwrap()
            .get("title")
            .unwrap()
            .value
            .as_str();
        assert_eq!(title, Some(name), "{yaml}");
    }
}

#[test]
fn every_page_is_0_28s() {
    check("generic");
}

#[test]
fn every_github_page_is_0_28s() {
    check("github");
}

#[test]
fn every_gitlab_page_is_0_28s() {
    check("gitlab");
}

#[test]
fn every_azure_devops_page_is_0_28s() {
    check("azure_devops");
}

fn append(ws: &Path, file: &str, text: &str) {
    let path = ws.join(file);
    let mut current = std::fs::read_to_string(&path).unwrap();
    current.push_str(text);
    std::fs::write(path, current).unwrap();
}

fn documentation(ws: &Path, toml: &str) {
    std::fs::write(ws.join(".opentide/configurations/documentation.toml"), toml).unwrap();
}

/// A `documentation.toml` its model refuses stops the docs phase, naming
/// the file and the first error.
#[test]
fn an_invalid_documentation_toml_names_the_file() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        documentation(ws, "output = 5\n");
    });
    let error = Settings::resolve(
        &workspace.configuration().resolved,
        workspace.root(),
        None,
        None,
        &FlavorHints::default(),
    )
    .err()
    .unwrap();
    assert!(
        error.detail.starts_with("documentation.toml is invalid: "),
        "{}",
        error.detail
    );
}

/// The flavour a run renders without `--flavor`: the CI it runs in (Azure,
/// then GitHub, then GitLab), then the host of the `origin` remote, then
/// `documentation.toml`; `--flavor` before all of them.
#[test]
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn the_flavour_comes_from_ci_then_origin_then_the_configuration() {
    use opentide_compile::generate::docs::flavor::Flavor;
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        documentation(ws, "[flavor]\ndefault = \"gitlab\"\n");
    });
    let resolved = &workspace.configuration().resolved;
    let flavor = |flavor: Option<&str>, env: &[(&str, &str)], origin: Option<&str>| {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let lookup = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let hints = FlavorHints::new(&lookup, origin.map(str::to_owned));
        Settings::resolve(resolved, workspace.root(), None, flavor, &hints)
            .unwrap()
            .flavor
    };
    assert_eq!(flavor(None, &[], None), Flavor::Gitlab);
    assert_eq!(
        flavor(None, &[("GITHUB_ACTIONS", "true")], None),
        Flavor::Github
    );
    assert_eq!(
        flavor(
            None,
            &[
                ("GITHUB_ACTIONS", "true"),
                ("GITLAB_CI", "true"),
                ("TF_BUILD", "True")
            ],
            None
        ),
        Flavor::AzureDevops
    );
    assert_eq!(
        flavor(
            None,
            &[("GITHUB_ACTIONS", "true"), ("GITLAB_CI", "true")],
            None
        ),
        Flavor::Github
    );
    // An empty variable is unset; `CI` alone names no forge.
    assert_eq!(
        flavor(
            None,
            &[("GITHUB_ACTIONS", ""), ("CI", "true")],
            Some("https://github.com/o/r.git")
        ),
        Flavor::Github
    );
    assert_eq!(
        flavor(
            None,
            &[("GITLAB_CI", "true")],
            Some("https://github.com/o/r.git")
        ),
        Flavor::Gitlab
    );
    assert_eq!(
        flavor(None, &[], Some("git@ssh.dev.azure.com:v3/org/project/repo")),
        Flavor::AzureDevops
    );
    assert_eq!(
        flavor(None, &[], Some("https://github.example.com/o/r.git")),
        Flavor::Github
    );
    // A host that names no forge leaves the configured flavour.
    assert_eq!(
        flavor(None, &[], Some("https://git.example.org/o/r.git")),
        Flavor::Gitlab
    );
    assert_eq!(
        flavor(
            Some("generic"),
            &[("TF_BUILD", "True")],
            Some("https://github.com/o/r")
        ),
        Flavor::Generic
    );
    // A flavour that is none of them is refused, naming the choices.
    let unknown = Settings::resolve(
        resolved,
        workspace.root(),
        None,
        Some("wiki"),
        &FlavorHints::default(),
    )
    .err()
    .unwrap();
    assert_eq!(
        unknown.detail,
        "unknown docs flavor `wiki` (expected generic, github, gitlab or azure_devops)"
    );
    // Without documentation.toml the default is CommonMark.
    let (_dir, plain) = open("tide-corpus");
    let settings = Settings::resolve(
        &plain.configuration().resolved,
        plain.root(),
        None,
        None,
        &FlavorHints::default(),
    )
    .unwrap();
    assert_eq!(settings.flavor, Flavor::Generic);
}

/// GitLab: each folder has a `.order` file (README, then the pages by
/// name), the index pages are `json:table` blocks, and with
/// `uuid_permalinks` (the default) a page is named by its object's UUID.
#[test]
fn gitlab_pages_are_ordered_and_named_by_uuid() {
    let (_dir, workspace) = open("tide-corpus");
    let written = render_with(
        &workspace,
        None,
        &FlavorHints {
            gitlab: true,
            ..FlavorHints::default()
        },
    )
    .unwrap();
    assert_eq!(
        written["docs/rules/.order"],
        "README\n00000000-0000-4000-8003-000000000005\n00000000-0000-4000-8003-000000000006\n\
         00000000-0000-4000-8003-000000000002\n00000000-0000-4000-8003-000000000009\n\
         00000000-0000-4000-8003-000000000007\n00000000-0000-4000-8003-000000000001\n\
         00000000-0000-4000-8003-000000000004\n00000000-0000-4000-8003-000000000003\n\
         00000000-0000-4000-8003-000000000008\n00000000-0000-4000-8003-0000005d1a90\n"
    );
    assert_eq!(
        written["docs/threats/.order"],
        "README\n00000000-0000-4000-8001-000000000001\n"
    );
    assert!(written.contains_key("docs/objectives/.order"));
    assert!(written.contains_key("docs/rules/00000000-0000-4000-8003-000000000001.md"));
    assert!(!written.contains_key("docs/rules/sentinel-kql-rule.md"));
    assert!(!written.contains_key("docs/.order"));
    let index = &written["docs/rules/README.md"];
    assert!(
        index.starts_with(
            "[Catalogue](../README)\n\n# Detection rules\n\nDetection rules: the queries \
             opentide deploys, with the status each platform block carries. 10 rules.\n\n\
             ## Status by platform\n\n| Platform | `STAGING` | Total |\n"
        ),
        "{index}"
    );
    assert!(index.contains("## All rules\n\n```json:table\n"), "{index}");
    assert!(
        index.contains(
            r#"{"a":"[Sentinel KQL Rule](00000000-0000-4000-8003-000000000001)","b":"High","c":"Microsoft Sentinel `STAGING`","d":"`T1059`","e":"`00000000-0000-4000-8003-000000000001`","f":"2"}"#
        ),
        "{index}"
    );
    let objective = &written["docs/objectives/00000000-0000-4000-8002-000000000001.md"];
    assert!(
        objective.contains(
            "| Rule | [Sentinel KQL Rule](../rules/00000000-0000-4000-8003-000000000001) | \
             Downstream |\n"
        ),
        "{objective}"
    );
    // GitLab draws its own table of contents.
    assert!(
        objective.contains("\n\n[[_TOC_]]\n\n## Composition\n"),
        "{objective}"
    );
    assert!(objective.contains("```mermaid\n"), "{objective}");

    // Without permalinks the pages keep their slugs, in GitLab's links.
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        documentation(
            ws,
            "[flavor]\ndefault = \"gitlab\"\n\n[gitlab]\nuuid_permalinks = false\n",
        );
    });
    let written = render(&workspace, None).unwrap();
    assert!(written["docs/rules/.order"].starts_with("README\ncarbon-black-lucene-rule\n"));
    assert!(written.contains_key("docs/rules/sentinel-kql-rule.md"));
    assert!(
        written["docs/objectives/credential-access-objective.md"]
            .contains("| Rule | [Sentinel KQL Rule](../rules/sentinel-kql-rule) | Downstream |\n")
    );
}

/// A rule named `README` never writes `readme.md` beside the folder's
/// `README.md`: one file where case does not count (Windows, macOS). No two
/// files a run writes differ only by case, in any flavour.
#[test]
fn no_page_shares_a_name_with_an_index_but_for_case() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
        let text = std::fs::read_to_string(&rule).unwrap();
        std::fs::write(&rule, text.replacen("Sentinel KQL Rule", "README", 1)).unwrap();
    });
    for flavor in ["generic", "github", "gitlab", "azure-devops"] {
        let written = render(&workspace, Some(flavor)).unwrap();
        let mut seen = std::collections::HashMap::new();
        for path in written.keys() {
            if let Some(other) = seen.insert(path.to_lowercase(), path) {
                panic!("{flavor}: {path} and {other} are one file on Windows and macOS");
            }
        }
        assert!(
            written["docs/rules/README.md"].contains("# Detection rules"),
            "{flavor}: the index is the folder's README"
        );
    }
    // GitLab without UUID permalinks names its pages by slug: `.order`
    // lists the page under its suffixed name, after the folder's README.
    let (_dir, slugged) = open_edited("tide-corpus", |ws| {
        let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
        let text = std::fs::read_to_string(&rule).unwrap();
        std::fs::write(&rule, text.replacen("Sentinel KQL Rule", "README", 1)).unwrap();
        documentation(
            ws,
            "[flavor]\ndefault = \"gitlab\"\n\n[gitlab]\nuuid_permalinks = false\n",
        );
    });
    let written = render(&slugged, None).unwrap();
    assert!(written.contains_key("docs/rules/readme-00000000.md"));
    let order = &written["docs/rules/.order"];
    assert!(order.starts_with("README\n"), "{order}");
    assert_eq!(
        order
            .lines()
            .filter(|line| line.eq_ignore_ascii_case("readme"))
            .count(),
        1,
        "{order}"
    );
    assert!(
        order.lines().any(|line| line == "readme-00000000"),
        "{order}"
    );
    let written = render(&workspace, Some("github")).unwrap();
    assert!(
        written.contains_key("docs/rules/readme-00000000.md"),
        "{:?}",
        written
            .keys()
            .filter(|key| key.starts_with("docs/rules/"))
            .collect::<Vec<_>>()
    );
}

/// `page`'s Markdown: without its Mermaid blocks (fenced, or Azure DevOps'
/// `::: mermaid`) and its wiki front matter, which are not Markdown.
fn without_mermaid(page: &str) -> String {
    let page = page
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .map_or(page, |(_, rest)| rest);
    let mut out = String::new();
    let mut inside = false;
    for line in page.lines() {
        if !inside && (line == "```mermaid" || line == "::: mermaid") {
            inside = true;
        } else if inside && (line == "```" || line == ":::") {
            inside = false;
        } else if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Whether `text` holds `raw` with its first character not escaped: not
/// after an odd run of backslashes.
fn unescaped(text: &str, raw: &str) -> bool {
    // Code spans (single backticks here) are not Markdown.
    let text: String = text.split('`').step_by(2).collect::<Vec<_>>().join(" ");
    text.match_indices(raw).any(|(at, _)| {
        let before = &text[..at];
        let run = before.len() - before.trim_end_matches('\\').len();
        run.is_multiple_of(2)
    })
}

/// An object's or a signal's name, a value the vocabulary lacks and a CVE
/// record's text are text on every page: they cannot open a link
/// (`[x](javascript:…)`) or raw HTML (`<b>`), in a heading, a link's text, a
/// table or an index. A `\|` in a name stays in its cell, and a code span
/// in a name renders as it did.
#[test]
fn names_are_escaped_where_they_become_markdown() {
    const RULE: &str = "Evil [x](javascript:alert(1)) <b>bold</b>";
    const SIGNAL: &str = "Signal [y](javascript:alert(2)) <i>it</i>";
    const OBJECTIVE: &str = "Pipe a\\|b [o](javascript:6) `<code>` and `C:\\x`";
    const THREAT: &str = "Threat [t](javascript:7) <u>u</u>";
    const ACTOR: &str = "Actor [a](javascript:5) <s>a</s>";
    let rename = |file: &Path, from: &str, to: &str| {
        let text = std::fs::read_to_string(file).unwrap();
        assert!(text.contains(from), "{}", file.display());
        std::fs::write(file, text.replacen(from, to, 1)).unwrap();
    };
    let quoted = opentide_schema::node::double_quoted;
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        let objects = ws.join("Objects");
        rename(
            &objects.join("Detection Rules/rule-0001-sentinel-kql.yaml"),
            "Sentinel KQL Rule",
            &quoted(RULE),
        );
        let objective = objects.join("Detection Objectives/objective-0001-credential-access.yaml");
        rename(&objective, "Suspicious logon signal", &quoted(SIGNAL));
        rename(
            &objective,
            "Credential Access Objective",
            &quoted(OBJECTIVE),
        );
        let threat = objects.join("Threat Vectors/threat-0001-simulated-actor.yaml");
        rename(&threat, "Simulated Actor", &quoted(THREAT));
        rename(
            &threat,
            "    - name: att&ck::G0006\n",
            &format!("    - name: att&ck::G0006\n    - name: {}\n", quoted(ACTOR)),
        );
        append(
            ws,
            "Objects/Threat Vectors/threat-0001-simulated-actor.yaml",
            "  cve:\n    - CVE-2023-0001\n",
        );
    });
    let source = || {
        CveSource::new(|id: &str| {
            CveDetail::Found(Box::new(CveRecord {
                identifier: id.into(),
                title: Some("Title [c](javascript:8) <em>e</em>".into()),
                severity: Some("HIGH [sev](javascript:2) <i>s</i>".into()),
                aliases: vec!["GHSA-[al](javascript:3)".into()],
                weaknesses: vec![Weakness {
                    identifier: "CWE-79".into(),
                    name: "Weak [w](javascript:4) <u>w</u>".into(),
                }],
                affected: vec!["<b>ADC</b>".into()],
                ..CveRecord::default()
            }))
        })
    };
    let names = [RULE, SIGNAL, THREAT, ACTOR];
    for flavor in ["generic", "github", "gitlab", "azure-devops"] {
        let written = render_cves(
            &workspace,
            Some(flavor),
            &FlavorHints::default(),
            Some(source()),
        )
        .unwrap();
        let mut seen = [0; 4];
        let mut code_spans = 0;
        for (path, text) in &written {
            // Mermaid labels are not Markdown: their own escaping is tested
            // with the diagrams.
            let text = &without_mermaid(text);
            for raw in [
                "[x](", "[y](", "[o](", "[t](", "[a](", "[c](", "[sev](", "[al](", "[w](", "<b>",
                "<i>", "<u>", "<s>", "<em>",
            ] {
                assert!(
                    !unescaped(text, raw),
                    "{flavor}: {path} holds an unescaped {raw:?}:\n{text}"
                );
            }
            // `a\|b`: the backslash escaped and the pipe too, so the cell
            // does not end there.
            for row in text.lines().filter(|line| line.starts_with('|')) {
                assert!(!row.contains("a\\\\|b"), "{flavor}: {path}: {row}");
            }
            for (count, name) in seen.iter_mut().zip(names) {
                let escaped = name
                    .replace('[', "\\[")
                    .replace(']', "\\]")
                    .replace('<', "\\<")
                    .replace('>', "\\>");
                *count += text.matches(&escaped).count();
            }
            code_spans += text.matches("`<code>` and `C:\\x`").count();
        }
        assert!(seen.iter().all(|count| *count > 0), "{flavor}: {seen:?}");
        assert!(
            code_spans > 1,
            "{flavor}: the code spans, kept, {code_spans} times"
        );
    }
}

/// Azure DevOps: wiki links from the wiki's root, a table of contents on
/// the index pages, and Mermaid in `::: mermaid` blocks with `graph`.
#[test]
fn azure_devops_pages_use_wiki_links_and_its_mermaid_blocks() {
    let (_dir, workspace) = open("tide-corpus");
    let written = render(&workspace, Some("azure-devops")).unwrap();
    assert!(
        !written
            .keys()
            .any(|path| Path::new(path).file_name() == Some(".order".as_ref()))
    );
    let index = &written["docs/objectives/README.md"];
    // No breadcrumb: Azure DevOps names every index page README.
    assert!(index.starts_with("# Detection objectives\n\n"), "{index}");
    assert!(
        index.contains(
            "| [Credential Access Objective](/credential-access-objective) | High | 1 | 1 | \
             `00000000-0000-4000-8002-000000000001` | 12 |\n"
        ),
        "{index}"
    );
    let objective = &written["docs/objectives/credential-access-objective.md"];
    assert!(objective.contains("::: mermaid\ngraph LR\n"), "{objective}");
    assert!(!objective.contains("classDef"), "{objective}");
    assert!(!objective.contains("```mermaid"), "{objective}");
    assert!(!objective.contains("subgraph"), "{objective}");
    assert!(
        objective.starts_with("# Credential Access Objective\n"),
        "{objective}"
    );
    assert!(
        objective.contains("| Threat | [Simulated Actor](/simulated-actor) | Upstream |\n"),
        "{objective}"
    );
    assert!(
        objective.contains(
            "| Signal | [Suspicious logon signal](/credential-access-objective#suspicious-logon-signal)"
        ),
        "{objective}"
    );
}

/// A rule with several platform blocks: a Deployment row and a status line
/// per block on its page, each status explained once; a line per platform
/// in the index, and the rules counted per platform and status.
#[test]
fn a_rule_with_several_blocks_shows_each_platform() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        append(
            ws,
            "Objects/Detection Rules/rule-0003-splunk-spl.yaml",
            "  carbon_black_cloud:\n    enabled: true\n    name: Splunk SPL Rule\n    status: STAGING\n    query: process_name:cmd.exe\n  sentinel:\n    enabled: true\n    name: Splunk SPL Rule\n    status: PRODUCTION\n    query: SecurityEvent | take 1\n    scheduling:\n      frequency: PT1H\n      lookback: PT2H\n    alert:\n      title: Splunk SPL Rule\n      suppression: false\n    grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n",
        );
    });
    let written = render(&workspace, None).unwrap();
    let index = &written["docs/rules/README.md"];
    assert!(
        index.contains(
            "| [Splunk SPL Rule](splunk-spl-rule.md) | High | Microsoft Sentinel `PRODUCTION`<br>\
             Splunk Enterprise Security `STAGING`<br>Carbon Black Cloud `STAGING` | `T1059` | \
             `00000000-0000-4000-8003-000000000003` | 2 |\n"
        ),
        "{index}"
    );
    assert!(
        index.contains(
            "| Platform | `STAGING` | `PRODUCTION` | Total |\n| --- | --- | --- | --- |\n\
             | Carbon Black Cloud | 2 | - | 2 |\n"
        ),
        "{index}"
    );
    assert!(
        index.contains("| Microsoft Sentinel | 2 | 1 | 3 |\n"),
        "{index}"
    );
    let page = &written["docs/rules/splunk-spl-rule.md"];
    assert!(
        page.contains(
            "| Microsoft Sentinel | `PRODUCTION` | RELEASE runs | no tenant configured | yes |\n\
             | Splunk Enterprise Security | `STAGING` | PREVIEW runs | no tenant configured | yes |\n\
             | Carbon Black Cloud | `STAGING` | PREVIEW runs | no tenant configured | yes |\n\n\
             - `PRODUCTION` (strategy `RELEASE`): Deployed in active production environment, \
             potentially raising alerts\n\
             - `STAGING` (strategy `PREVIEW`): Deployed in staging environment for operational \
             testing\n"
        ),
        "{page}"
    );
    assert_eq!(
        page.matches("### ").count() - page.matches("### Related").count(),
        3,
        "{page}"
    );
}

/// A deliberate departure from 0.28.1 (see `inherited_techniques`): the
/// rules of the corpus carry no `techniques` of their own but one, and inherit
/// T1059 through their detection model (one names a signal, whose objective
/// is the one that implements it). Docs, the Navigator layer and
/// `info coverage` count the same techniques: those a rule lists or inherits.
#[test]
fn docs_navigator_and_coverage_count_a_rules_inherited_techniques() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        let rules = ws.join("Objects/Detection Rules");
        for entry in std::fs::read_dir(&rules).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let mut text = text.replace("techniques:\n  - T1059.004\n", "");
            text = text.replace("techniques:\n  - T1059\n", "");
            if path.ends_with("rule-0001-sentinel-kql.yaml") {
                text = text.replace(
                    "detection_model: 00000000-0000-4000-8002-000000000001",
                    "detection_model: 00000000-0000-4000-8099-000000000001",
                );
            }
            if path.ends_with("rule-0002-defender-kql.yaml") {
                text = text.replace(
                    "detection_model:",
                    "techniques:\n  - T1021\ndetection_model:",
                );
            }
            std::fs::write(&path, text).unwrap();
        }
        let objective =
            ws.join("Objects/Detection Objectives/objective-0001-credential-access.yaml");
        let text = std::fs::read_to_string(&objective).unwrap();
        std::fs::write(
            &objective,
            text.replace("  threats:\n", "  mitre_attack:\n    - T1059\n  threats:\n"),
        )
        .unwrap();
    });
    let index = workspace.index();
    let covered: std::collections::BTreeSet<String> =
        opentide_workspace::coverage::rule_technique_index(index)
            .values()
            .flat_map(|found| found.own.iter().chain(&found.inherited).cloned())
            .collect();
    assert_eq!(
        covered,
        ["T1021", "T1059"].map(str::to_owned).into_iter().collect()
    );

    let written = render(&workspace, None).unwrap();
    assert!(
        written["docs/README.md"].contains("| ATT&CK techniques detected by rules | 2 |"),
        "{}",
        written["docs/README.md"]
    );
    let objective = written
        .iter()
        .find(|(path, _)| path.starts_with("docs/objectives/") && !path.ends_with("README.md"))
        .map(|(_, page)| page)
        .unwrap();
    assert!(!objective.contains("*No rule*"), "{objective}");
    let row = objective
        .lines()
        .find(|line| line.starts_with("| [`T1059`]"))
        .unwrap();
    assert!(row.contains("Sentinel KQL Rule"), "{row}");
    // A rule's own page shows what it inherits, marked.
    let rule = &written["docs/rules/sentinel-kql-rule.md"];
    assert!(rule.contains("`T1059`"), "{rule}");
    assert!(rule.contains("(inherited)"), "{rule}");

    let settings = opentide_compile::generate::exports::Settings::new(
        workspace.configuration(),
        workspace.root(),
    );
    let layer = opentide_compile::generate::exports::export(
        opentide_compile::generate::exports::Target::Navigator,
        index,
        &settings,
        &Vocabularies::bundled(),
    )
    .unwrap();
    let layer: serde_json::Value = serde_json::from_slice(&layer.bytes).unwrap();
    let entries: std::collections::BTreeSet<(String, String)> = layer["techniques"]
        .as_array()
        .unwrap()
        .iter()
        .map(|technique| {
            (
                technique["techniqueID"].as_str().unwrap().to_owned(),
                technique["color"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    // T1059 is a threat's and a rule's (green); T1021 is a rule's alone (blue).
    assert_eq!(
        entries,
        [("T1021", "#6baed6"), ("T1059", "#74c476")]
            .map(|(id, color)| (id.to_owned(), color.to_owned()))
            .into_iter()
            .collect()
    );
}

/// A rule's tenants: the ones its runs reach, the ones they do not and why,
/// a manual tenant left out, and the remote ids the deployment state holds,
/// for a tenant the rule no longer reaches too.
#[test]
fn a_rules_tenants_and_remote_ids() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        append(
            ws,
            ".opentide/configurations/platforms/microsoft_defender.toml",
            "\n[[tenants]]\nname = \"lab\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nx = 1\n\n\
             [[tenants]]\nname = \"prod\"\ndescription = \"Production SOC\"\n\
             strategies = [\"RELEASE\"]\n[tenants.setup]\nx = 1\n\n\
             [[tenants]]\nname = \"vip\"\nmanual = true\n[tenants.setup]\nx = 1\n",
        );
        let states = ws.join(".opentide/states/deployment");
        std::fs::create_dir_all(&states).unwrap();
        std::fs::write(
            states.join("00000000-0000-4000-8003-000000000002.json"),
            r#"{"schema": "deployment.state::1.0", "object_uuid": "00000000-0000-4000-8003-000000000002", "platforms": {"microsoft_defender": {"prod": "7002", "old": "7000"}}}"#,
        )
        .unwrap();
    });
    let page = &render(&workspace, None).unwrap()["docs/rules/defender-kql-rule.md"];
    assert!(
        page.contains(
            "| Microsoft Defender | `STAGING` | PREVIEW runs | `lab` | yes |\n\n\
             - `STAGING` (strategy `PREVIEW`): Deployed in staging environment for operational \
             testing\n\n```mermaid\n"
        ),
        "{page}"
    );
    // The deployment map: a solid line labelled with the runs that reach a
    // tenant, a dotted one to a tenant no run reaches, each remote id under
    // its tenant.
    assert!(
        page.contains(
            "    subgraph lane3[\"Tenants\"]\n        ten1[[\"lab\"]]\n        \
             ten2[[\"prod<br>id 7002\"]]\n    end\n    rul1 --> plt1\n    \
             plt1 -->|\"PREVIEW\"| ten1\n    plt1 -.-> ten2\n"
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "*Lines:* solid line = deployed, by the runs named on the line; dotted line = not \
             deployed: no run takes this status or tenant.\n\n### Tenant targeting\n\n\
             | Platform | Tenant | Reached by | Remote ID |\n| --- | --- | --- | --- |\n\
             | Microsoft Defender | `lab` | PREVIEW runs | - |\n\
             | Microsoft Defender | `prod`<br>Production SOC | no run: the tenant \
             takes RELEASE runs only | `7002` |\n\
             | Microsoft Defender | `old` | not targeted | `7000` |\n"
        ),
        "{page}"
    );
    assert!(
        page.contains("Status `STAGING` · deployed by PREVIEW runs · tenants: `lab`\n"),
        "{page}"
    );
}

/// A threat's CVEs: each identifier once by its lookup key, canonical, as a
/// link to its Vulnerability-Lookup record (`[cve] base_url`).
#[test]
fn a_threats_cves_link_to_their_records() {
    let edit = |toml: &'static str| {
        move |ws: &Path| {
            append(
                ws,
                "Objects/Threat Vectors/threat-0001-simulated-actor.yaml",
                "  cve:\n    - cve-2024-3094\n    - GCVE-0-2024-3094\n    - GHSA-AbCd-1234-zzzz\n    - gcve-1-2025-0001\n",
            );
            documentation(ws, toml);
        }
    };
    let section = "## CVE\n\nIdentifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), \
                   which aggregates CVE, GHSA, CSAF, NVD, and related feeds.\n\n";
    let (_dir, workspace) = open_edited("tide-corpus", edit("[cve]\nretrieve_details = false\n"));
    let page = &render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains(&format!(
            "{section}- [CVE-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)\n\
             - [GHSA-abcd-1234-zzzz](https://vulnerability.circl.lu/vuln/GHSA-abcd-1234-zzzz)\n\
             - [GCVE-1-2025-0001](https://vulnerability.circl.lu/vuln/GCVE-1-2025-0001)\n\n\
             ## Detection coverage\n"
        )),
        "{page}"
    );
    let (_dir, workspace) = open_edited(
        "tide-corpus",
        edit(
            "[cve]\nretrieve_details = false\nbase_url = \"https://vl.example.org/\"\n\
             default_db_link = \"\"\n",
        ),
    );
    let page = &render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains("- [CVE-2024-3094](https://vl.example.org/vuln/CVE-2024-3094)\n"),
        "{page}"
    );
    // The bundled default_db_link names the public instance's pages, ahead
    // of base_url; a query-style prefix takes the identifier as is.
    let (_dir, workspace) = open_edited(
        "tide-corpus",
        edit("[cve]\nretrieve_details = false\nbase_url = \"https://vl.example.org/\"\n"),
    );
    let page = &render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains("- [CVE-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)\n"),
        "{page}"
    );
    let (_dir, workspace) = open_edited(
        "tide-corpus",
        edit(
            "[cve]\nretrieve_details = false\n\
             default_db_link = \"https://db.example.org/lookup?id=\"\n",
        ),
    );
    let page = &render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains("- [CVE-2024-3094](https://db.example.org/lookup?id=CVE-2024-3094)\n"),
        "{page}"
    );
    // A threat without CVEs has no section.
    let (_dir, workspace) = open("tide-corpus");
    assert!(
        !render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"].contains("## CVE")
    );
}

/// With `[cve] retrieve_details` on, each record's severity, EPSS score,
/// exploitation and weakness, as opentide 0.28.1's `render_cves`,
/// `cve_overview` and `exploited_banner` write them for the same records
/// (GitHub flavour): an advisory alias beside its CVE, a severity without a
/// CVSS score, a CWE without a number, a score that rounds half to even, an
/// EPSS score that never reads as certain, a CVE exploited by SSVC alone,
/// and an identifier the instance could not be asked for.
#[test]
fn a_threats_cve_details_show_severity_epss_exploitation_and_weakness() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws: &Path| {
        append(
            ws,
            "Objects/Threat Vectors/threat-0001-simulated-actor.yaml",
            "  cve:\n    - CVE-2023-0001\n    - CVE-2023-0002\n    - CVE-2023-0003\n",
        );
    });
    let source = CveSource::new(|id: &str| match id {
        "CVE-2023-0001" => CveDetail::Found(Box::new(CveRecord {
            identifier: id.into(),
            description: Some(format!("A description {}", "that goes on ".repeat(30))),
            severity: Some("HIGH | x".into()),
            aliases: vec!["CVE-2023-0001".into(), "GHSA-aaaa-bbbb-cccc".into()],
            weaknesses: vec![
                Weakness {
                    identifier: "CWE-NOINFO".into(),
                    name: String::new(),
                },
                Weakness {
                    identifier: "CWE-79".into(),
                    name: "Cross | Site".into(),
                },
            ],
            exploitation: Some("poc".into()),
            epss: EpssDetail::Unavailable,
            ..CveRecord::default()
        })),
        "CVE-2023-0002" => CveDetail::Found(Box::new(CveRecord {
            identifier: id.into(),
            title: Some("Second.".into()),
            published: Some("2023-02-02".into()),
            page_url: "https://x.example/2".into(),
            cvss: Some(Cvss {
                version: "4.0".into(),
                score: 7.25,
                ..Cvss::default()
            }),
            exploitation: Some("Active".into()),
            affected: (0..5).map(|n| format!("p{n}")).collect(),
            epss: EpssDetail::Score(Epss {
                probability: 0.99999,
                percentile: 0.5,
                date: String::new(),
            }),
            ..CveRecord::default()
        })),
        _ => CveDetail::Unavailable,
    });
    let page = &render_cves(
        &workspace,
        Some("github"),
        &FlavorHints::default(),
        Some(source),
    )
    .unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains("\n| CVE | 3 CVEs (highest CVSS 7.2, 1 known exploited) |\n"),
        "{page}"
    );
    assert!(
        page.contains(
            "\n> [!WARNING]\n> `CVE-2023-0002` (CISA SSVC: active) is known to be exploited \
             in the wild.\n"
        ),
        "{page}"
    );
    let section = &page[page.find("## CVE\n").unwrap()..];
    let section = &section[..section.find("\n## Detection coverage").unwrap()];
    const PAGES: &str = "https://vulnerability.circl.lu/vuln/";
    let summary = format!("{} that", " that goes on".repeat(20));
    assert_eq!(
        section,
        format!(
            "## CVE\n\nIdentifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), \
             which aggregates CVE, GHSA, CSAF, NVD, and related feeds.\n\n\
             | Identifier | Severity | EPSS | Exploitation | Weakness | Published |\n\
             | --- | --- | --- | --- | --- | --- |\n\
             | [CVE-2023-0001]({PAGES}CVE-2023-0001)<br>[GHSA-aaaa-bbbb-cccc]({PAGES}GHSA-aaaa-bbbb-cccc) \
             | HIGH \\| x | - | Proof of concept<br>CISA SSVC \
             | CWE-NOINFO<br>[CWE-79](https://cwe.mitre.org/data/definitions/79.html) Cross \\| Site | - |\n\
             | [CVE-2023-0002](https://x.example/2) | **7.2**<br>CVSS 4.0 | >99.9%<br>top 50.0% \
             | **Active**<br>CISA SSVC | - | 2023-02-02 |\n\
             | [CVE-2023-0003]({PAGES}CVE-2023-0003) | - | - | - | - | Details unavailable from \
             Vulnerability-Lookup. |\n\n\
             - **CVE-2023-0001**: A description{summary}….\n\
             - **CVE-2023-0002**: Second. Affects p0, p1, p2, p3 and 1 more.\n\n\
             Vulnerability-Lookup was unreachable for at least one identifier; links still point \
             at the CIRCL record page.\n\n\
             Vulnerability-Lookup returned no EPSS score for at least one identifier; those rows \
             show none.\n\n\
             *EPSS: FIRST's probability of exploitation in the next 30 days. Exploitation: CISA's \
             Known Exploited Vulnerabilities catalog, else its SSVC assessment.*\n"
        )
    );
}

/// With `[cve] retrieve_details` on (the default), the threats whose pages
/// list CVEs need their details, which the host fetches (`CveSource`): by
/// the scopes and targets a run writes. With it off, none do.
#[test]
fn cve_details_are_needed_with_retrieve_details_on() {
    let with_cves = |toml: &'static str| {
        move |ws: &Path| {
            append(
                ws,
                "Objects/Threat Vectors/threat-0001-simulated-actor.yaml",
                "  cve:\n    - cve-2024-3094\n",
            );
            if !toml.is_empty() {
                documentation(ws, toml);
            }
        }
    };
    let needed = |workspace: &Workspace,
                  scopes: &[Scope],
                  targets: Option<&std::collections::BTreeSet<String>>| {
        let resolved = &workspace.configuration().resolved;
        let settings = Settings::resolve(
            resolved,
            workspace.root(),
            None,
            None,
            &FlavorHints::default(),
        )
        .unwrap();
        let catalog = Catalog::build(workspace.index(), Statuses::from_resolved(resolved)).unwrap();
        let vocabularies = Vocabularies::bundled();
        let deployment = deployment_facts(workspace, &catalog);
        let pages_of = Pages {
            catalog: &catalog,
            settings: &settings,
            vocab: Vocab::new(&vocabularies),
            deployment: &deployment,
        };
        cve_details_needed(&pages_of, scopes, targets)
    };
    let (_dir, workspace) = open_edited("tide-corpus", with_cves(""));
    assert_eq!(needed(&workspace, &Scope::ALL, None), ["Simulated Actor"]);
    assert_eq!(
        needed(&workspace, &[Scope::Threats], None),
        ["Simulated Actor"]
    );
    assert!(needed(&workspace, &[Scope::Rules, Scope::Objectives], None).is_empty());
    let threat: std::collections::BTreeSet<String> =
        ["00000000-0000-4000-8001-000000000001".to_owned()].into();
    let rule: std::collections::BTreeSet<String> =
        ["00000000-0000-4000-8003-000000000001".to_owned()].into();
    assert_eq!(
        needed(&workspace, &Scope::ALL, Some(&threat)),
        ["Simulated Actor"]
    );
    assert!(needed(&workspace, &Scope::ALL, Some(&rule)).is_empty());
    let (_dir, workspace) =
        open_edited("tide-corpus", with_cves("[cve]\nretrieve_details = true\n"));
    assert_eq!(needed(&workspace, &Scope::ALL, None), ["Simulated Actor"]);
    let (_dir, workspace) = open_edited(
        "tide-corpus",
        with_cves("[cve]\nretrieve_details = false\n"),
    );
    assert!(needed(&workspace, &Scope::ALL, None).is_empty());
    // Without CVEs, nothing is needed.
    let (_dir, workspace) = open("tide-corpus");
    assert!(needed(&workspace, &Scope::ALL, None).is_empty());
}
