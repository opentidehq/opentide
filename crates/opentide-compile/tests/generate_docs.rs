//! `generate docs` (UC-3.2b, #915; the 0.26.0 redesign): every file a run
//! writes for the tide-corpus fixture, in each of the four flavours,
//! compared byte for byte with the files opentide 0.28.1 writes for it
//! (`tests/docs_0_28/<flavor>`: pages, folder indexes, GitLab's `.order`
//! files and the catalogue overview, diagrams included), and the oracle's
//! failure on the vscode fixture. The flavour a run picks from its CI and
//! `origin`, a rule with several platform blocks, a rule's tenants and
//! remote ids, and a threat's CVEs have no recording: their tests assert
//! what 0.28.x writes for them (compared with its pages on the same edits of
//! the fixture when they were written).

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
        assert_eq!(text, &expected[path], "{flavor}: {path}");
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

/// A rule's tenants: the ones its runs reach, the ones they do not and why,
/// a manual tenant left out, and the remote ids the deployment state holds,
/// for a tenant the rule no longer reaches too.
#[test]
fn a_rules_tenants_and_remote_ids() {
    let (_dir, workspace) = open_edited("tide-corpus", |ws| {
        append(
            ws,
            ".opentide/configurations/platforms/defender_for_endpoint.toml",
            "\n[[tenants]]\nname = \"lab\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\nx = 1\n\n\
             [[tenants]]\nname = \"prod\"\ndescription = \"Production SOC\"\n\
             strategies = [\"RELEASE\"]\n[tenants.setup]\nx = 1\n\n\
             [[tenants]]\nname = \"vip\"\nmanual = true\n[tenants.setup]\nx = 1\n",
        );
        let states = ws.join(".opentide/states/deployment");
        std::fs::create_dir_all(&states).unwrap();
        std::fs::write(
            states.join("00000000-0000-4000-8003-000000000002.json"),
            r#"{"schema": "deployment.state::1.0", "object_uuid": "00000000-0000-4000-8003-000000000002", "platforms": {"defender_for_endpoint": {"prod": "7002", "old": "7000"}}}"#,
        )
        .unwrap();
    });
    let page = &render(&workspace, None).unwrap()["docs/rules/defender-kql-rule.md"];
    assert!(
        page.contains(
            "| Microsoft Defender for Endpoint | `STAGING` | PREVIEW runs | `lab` | yes |\n\n\
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
             | Microsoft Defender for Endpoint | `lab` | PREVIEW runs | - |\n\
             | Microsoft Defender for Endpoint | `prod`<br>Production SOC | no run: the tenant \
             takes RELEASE runs only | `7002` |\n\
             | Microsoft Defender for Endpoint | `old` | not targeted | `7000` |\n"
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
