//! `generate docs` against the oracle's recordings (UC-3.2b, #915): every
//! page and index of the tide-corpus fixture, in the generic and GitHub
//! flavours, compared with the files the oracle wrote, and the oracle's
//! failure on the vscode fixture. The GitLab and Azure DevOps flavours, the
//! flavour a run picks from its CI and `origin`, a rule with several
//! platform blocks and a threat's CVEs have no recording: their tests assert
//! what the oracle writes for them (compared with the Python engine's pages
//! on the same edits of the fixture when they were written).

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a broken fixture is a failure")]

#[path = "common/golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use opentide_compile::generate::Output;
use opentide_compile::generate::docs::catalog::{Catalog, Scope};
use opentide_compile::generate::docs::render::{Pages, Templates};
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

fn render_with(
    workspace: &Workspace,
    flavor: Option<&str>,
    hints: &FlavorHints,
) -> Result<BTreeMap<String, String>, String> {
    let resolved = &workspace.configuration().resolved;
    let settings = Settings::resolve(resolved, workspace.root(), None, flavor, hints)
        .map_err(|error| error.detail)?;
    let catalog = Catalog::build(workspace.index(), Statuses::from_resolved(resolved))
        .map_err(|error| error.detail)?;
    let vocabularies = Vocabularies::bundled();
    let templates = Templates::new();
    let pages_of = Pages {
        catalog: &catalog,
        settings: &settings,
        vocab: Vocab::new(&vocabularies),
        templates: &templates,
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

fn check(case: &str, flavor: Option<&str>) {
    let (_dir, workspace) = open("tide-corpus");
    let written = render(&workspace, flavor).unwrap();
    let (_, recorded) = golden::recorded(case);
    let recorded: BTreeMap<String, String> = recorded
        .into_iter()
        .map(|(path, bytes)| (path, String::from_utf8(bytes).unwrap()))
        .collect();
    assert_eq!(
        written.keys().collect::<Vec<_>>(),
        recorded.keys().collect::<Vec<_>>(),
        "{case}: the files written"
    );
    for (path, text) in &written {
        assert_eq!(text, &recorded[path], "{case}: {path}");
    }
}

#[test]
fn every_page_is_the_oracles() {
    check("generate.docs/json/tide-corpus/default", None);
}

#[test]
fn every_github_page_is_the_oracles() {
    check(
        "generate.docs/json/tide-corpus/output-flavor",
        Some("github"),
    );
}

#[test]
fn an_object_that_does_not_validate_fails_as_the_oracle_does() {
    let (_dir, workspace) = open("vscode");
    let error = render(&workspace, None).unwrap_err();
    let stdout =
        std::fs::read_to_string(golden::case("generate.docs/json/vscode/default").join("stdout"))
            .unwrap();
    assert!(
        stdout.contains(&format!("\"message\":\"docs: {error}\"")),
        "{error} is not the oracle's failure: {stdout}"
    );
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

/// The flavour a run renders without `--flavor`: the CI it runs in (Azure,
/// then GitHub, then GitLab), then the host of the `origin` remote, then
/// `documentation.toml`; `--flavor` before all of them.
#[test]
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
        index.starts_with("# Detection Rules\n```json:table\n"),
        "{index}"
    );
    assert!(
        index.contains(
            r#"{"a":"[Sentinel KQL Rule](00000000-0000-4000-8003-000000000001)","b":"00000000-0000-4000-8003-000000000001","c":"STAGING","d":"High","e":"2"}"#
        ),
        "{index}"
    );
    let objective = &written["docs/objectives/00000000-0000-4000-8002-000000000001.md"];
    assert!(
        objective.contains(
            "| Rule | [Sentinel KQL Rule](../rules/00000000-0000-4000-8003-000000000001) \
             (`00000000-0000-4000-8003-000000000001`) | Downstream | rule |\n"
        ),
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
        written["docs/objectives/credential-access-objective.md"].contains(
            "| Rule | [Sentinel KQL Rule](../rules/sentinel-kql-rule) \
             (`00000000-0000-4000-8003-000000000001`) | Downstream | rule |\n"
        )
    );
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
    assert!(
        index.starts_with("# Detection Objectives\n[[_TOC_]]\n"),
        "{index}"
    );
    assert!(
        index.contains(
            "| [Credential Access Objective](/credential-access-objective) | \
             00000000-0000-4000-8002-000000000001 | High | 12 |\n"
        ),
        "{index}"
    );
    let objective = &written["docs/objectives/credential-access-objective.md"];
    assert!(objective.contains("::: mermaid\ngraph TB\n"), "{objective}");
    assert!(!objective.contains("```mermaid"), "{objective}");
    assert!(!objective.contains("subgraph"), "{objective}");
    assert!(
        objective.contains(
            "| Threat | [Simulated Actor](/simulated-actor) \
             (`00000000-0000-4000-8001-000000000001`) | Upstream | threat |\n"
        ),
        "{objective}"
    );
    assert!(
        objective.contains(
            "| Signal | [Suspicious logon signal](/credential-access-objective#suspicious-logon-signal)"
        ),
        "{objective}"
    );
}

/// A rule with several platform blocks: a Status row per block on its page,
/// and each status once in the index's cell, sorted.
#[test]
fn a_rule_with_several_blocks_lists_each_status_once() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        append(
            ws,
            "Objects/Detection Rules/rule-0003-splunk-spl.yaml",
            "  carbon_black_cloud:\n    enabled: true\n    name: Splunk SPL Rule\n    status: STAGING\n    query: process_name:cmd.exe\n  sentinel:\n    enabled: true\n    name: Splunk SPL Rule\n    status: PRODUCTION\n    query: SecurityEvent | take 1\n    scheduling:\n      frequency: PT1H\n      lookback: PT2H\n    alert:\n      title: Splunk SPL Rule\n      suppression: false\n    grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n",
        );
    });
    let written = render(&workspace, None).unwrap();
    assert!(
        written["docs/rules/README.md"].contains(
            "| [Splunk SPL Rule](splunk-spl-rule.md) | 00000000-0000-4000-8003-000000000003 | \
             PRODUCTION, STAGING | High | 2 |\n"
        ),
        "{}",
        written["docs/rules/README.md"]
    );
    let page = &written["docs/rules/splunk-spl-rule.md"];
    assert!(
        page.contains(
            "| Status (sentinel) | `PRODUCTION` |\n| Status (splunk) | `STAGING` |\n\
             | Status (carbon_black_cloud) | `STAGING` |\n"
        ),
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
    let section = "## CVE\nIdentifiers link to [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu), \
                   which aggregates CVE, GHSA, CSAF, NVD, and related feeds.\n\n";
    let (_dir, workspace) = open_edited("tide-corpus", edit("[cve]\nretrieve_details = false\n"));
    let page = &render(&workspace, None).unwrap()["docs/threats/simulated-actor.md"];
    assert!(
        page.contains(&format!(
            "{section}- [CVE-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)\n\
             - [GHSA-abcd-1234-zzzz](https://vulnerability.circl.lu/vuln/GHSA-abcd-1234-zzzz)\n\
             - [GCVE-1-2025-0001](https://vulnerability.circl.lu/vuln/GCVE-1-2025-0001)\n\n\
             ## ATT&CK Techniques\n"
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

/// With `[cve] retrieve_details` on (the default), the threats whose pages
/// list CVEs need their details, which only the Python engine fetches: by
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
        let templates = Templates::new();
        let pages_of = Pages {
            catalog: &catalog,
            settings: &settings,
            vocab: Vocab::new(&vocabularies),
            templates: &templates,
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
