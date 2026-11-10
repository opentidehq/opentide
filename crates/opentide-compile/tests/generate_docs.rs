//! `generate docs` against the oracle's recordings (UC-3.2b, #915): every
//! page and index of the tide-corpus fixture, in the generic and GitHub
//! flavours, compared with the files the oracle wrote, and the oracle's
//! failure on the vscode fixture.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "a test: a broken fixture is a failure")]

#[path = "common/golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::sync::Arc;

use opentide_compile::generate::Output;
use opentide_compile::generate::docs::catalog::{Catalog, Scope};
use opentide_compile::generate::docs::render::{Pages, Templates};
use opentide_compile::generate::docs::vocab::Vocab;
use opentide_compile::generate::docs::{FlavorHints, Settings, index_pages, pages};
use opentide_compile::strategy::Statuses;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, RootOptions, Workspace};

fn open(fixture: &str) -> (tempfile::TempDir, Workspace) {
    let dir = tempfile::tempdir().unwrap();
    let ws = dunce::canonicalize(dir.path()).unwrap().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    golden::fixture(fixture, &ws);
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
    let resolved = &workspace.configuration().resolved;
    let settings = Settings::resolve(
        resolved,
        workspace.root(),
        None,
        flavor,
        &FlavorHints::default(),
    )
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
