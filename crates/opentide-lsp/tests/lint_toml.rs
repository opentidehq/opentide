//! `opentide lsp start` follows a root's `.opentide/configurations/lint.toml`
//! (#214): on disk, and as the editor's buffer while it is open.

mod common;

use common::{
    Lsp, Scratch, bin, copy_dir, file_uri, next_diagnostics, published_codes, published_for,
    repo_root,
};
use serde_json::{Value, json};
use std::process::Command;

const LINT_CODES: [&str; 5] = [
    "filename_slug",
    "filename_pattern",
    "missing_author",
    "missing_organisation",
    "recommended_field_missing",
];

fn lint_codes(codes: Vec<String>) -> Vec<String> {
    let mut codes: Vec<String> = codes
        .into_iter()
        .filter(|c| LINT_CODES.contains(&c.as_str()))
        .collect();
    codes.sort();
    codes
}

#[test]
fn the_roots_lint_toml_decides_filename_and_metadata_findings() {
    let scratch = Scratch::new("lint-toml");
    let root = &scratch.0;
    copy_dir(&repo_root().join("testdata/conformance/lint-toml"), root);
    // `T-0001.yaml`: not the slug of its name, with an author and no organisation.
    let threat = root.join("objects/threats/T-0001.yaml");
    let threat_uri = file_uri(&threat);
    let text = std::fs::read_to_string(&threat).unwrap();
    let lint_uri = file_uri(&root.join(".opentide/configurations/lint.toml"));

    let mut lsp = Lsp::spawn();
    lsp.request(
        "initialize",
        json!({ "capabilities": {}, "rootUri": file_uri(root) }),
    );
    lsp.notify("initialized", json!({}));

    // The file on disk: threat file names are free, only `author` is required.
    let on_disk = lint_codes(published_codes(
        &mut lsp,
        &threat_uri,
        "opentide-yaml",
        &text,
    ));
    assert!(on_disk.is_empty(), "{on_disk:?}");

    // The editor's buffer wins over the file: `opentide lint`'s defaults.
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": {
            "uri": lint_uri, "languageId": "toml", "version": 1, "text": "# defaults\n"
        } }),
    );
    assert_eq!(
        lint_codes(next_diagnostics(&mut lsp, &threat_uri)),
        vec!["filename_slug", "missing_organisation"]
    );

    // Closed unsaved: the file on disk applies again.
    lsp.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": lint_uri } }),
    );
    assert!(lint_codes(next_diagnostics(&mut lsp, &threat_uri)).is_empty());
}

fn initialized(params: Value) -> Lsp {
    let mut lsp = Lsp::spawn();
    lsp.request("initialize", params);
    lsp.notify("initialized", json!({}));
    lsp
}

fn replace_text(lsp: &mut Lsp, uri: &str, text: &str) {
    lsp.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": uri }, "contentChanges": [{ "text": text }] }),
    );
}

/// A `lint.toml` buffer that is not TOML yet (mid-edit) keeps the settings
/// that last parsed: no object is re-checked, only the configuration
/// documents, and the next text that parses applies.
#[test]
fn a_lint_toml_mid_edit_re_checks_no_object() {
    let scratch = Scratch::new("lint-toml-mid-edit");
    let root = &scratch.0;
    copy_dir(&repo_root().join("testdata/conformance/lint-toml"), root);
    let threat = root.join("objects/threats/T-0001.yaml");
    let threat_uri = file_uri(&threat);
    let text = std::fs::read_to_string(&threat).unwrap();
    let lint_uri = file_uri(&root.join(".opentide/configurations/lint.toml"));

    let mut lsp = initialized(json!({ "capabilities": {}, "rootUri": file_uri(root) }));
    let on_disk = lint_codes(published_codes(
        &mut lsp,
        &threat_uri,
        "opentide-yaml",
        &text,
    ));
    assert!(on_disk.is_empty(), "{on_disk:?}");
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": {
            "uri": lint_uri, "languageId": "toml", "version": 1, "text": "# defaults\n"
        } }),
    );
    assert_eq!(
        lint_codes(next_diagnostics(&mut lsp, &threat_uri)),
        vec!["filename_slug", "missing_organisation"]
    );

    replace_text(&mut lsp, &lint_uri, "[filenames\nstyle = ");
    // The batch publishes lint.toml itself and nothing else; a request in
    // the next batch is answered after anything that batch published.
    published_for(&mut lsp, &lint_uri);
    lsp.write(&json!({
        "jsonrpc": "2.0", "id": 900, "method": "textDocument/documentSymbol",
        "params": { "textDocument": { "uri": threat_uri } }
    }));
    loop {
        let message = lsp.read();
        if message["id"] == 900 {
            break;
        }
        assert_ne!(message["params"]["uri"], threat_uri.as_str(), "{message}");
    }

    replace_text(
        &mut lsp,
        &lint_uri,
        "[filenames]\nenabled = false\n[metadata]\nenabled = false\n",
    );
    assert!(lint_codes(next_diagnostics(&mut lsp, &threat_uri)).is_empty());
}

/// Two workspace folders, one with its own `lint.toml`: whichever root was
/// analysed last, each document is checked under its own root's settings.
#[test]
fn each_root_keeps_its_own_lint_toml() {
    let scratch = Scratch::new("lint-toml-two-roots");
    let (a, b) = (scratch.0.join("a"), scratch.0.join("b"));
    let fixture = repo_root().join("testdata/conformance/lint-toml/objects/threats/T-0001.yaml");
    let text = std::fs::read_to_string(&fixture).unwrap();
    let mut uris = Vec::new();
    for root in [&a, &b] {
        let threat = root.join("objects/threats/T-0001.yaml");
        std::fs::create_dir_all(threat.parent().unwrap()).unwrap();
        std::fs::write(&threat, &text).unwrap();
        uris.push(file_uri(&threat));
    }
    let configurations = a.join(".opentide/configurations");
    std::fs::create_dir_all(&configurations).unwrap();
    std::fs::write(
        configurations.join("lint.toml"),
        "[filenames]\nstyle = \"none\"\n",
    )
    .unwrap();
    let folder = |p: &std::path::Path, name: &str| json!({ "uri": file_uri(p), "name": name });
    let mut lsp = initialized(json!({
        "capabilities": { "workspace": { "workspaceFolders": true } },
        "workspaceFolders": [folder(&a, "a"), folder(&b, "b")],
    }));
    let (uri_a, uri_b) = (&uris[0], &uris[1]);
    let slug_in = |codes: Vec<String>| codes.iter().any(|c| c == "filename_slug");

    assert!(!slug_in(published_codes(
        &mut lsp,
        uri_a,
        "opentide-yaml",
        &text
    )));
    // Opening B re-checks A too (a Tide object may reference another).
    lsp.notify(
        "textDocument/didOpen",
        json!({ "textDocument": {
            "uri": uri_b, "languageId": "opentide-yaml", "version": 1, "text": text
        } }),
    );
    let both = |lsp: &mut Lsp| {
        let (mut seen_a, mut seen_b) = (None, None);
        while seen_a.is_none() || seen_b.is_none() {
            let message = lsp.read();
            if message["method"] != "textDocument/publishDiagnostics" {
                continue;
            }
            let codes: Vec<String> = message["params"]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|d| d["code"].as_str().map(str::to_string))
                .collect();
            if message["params"]["uri"] == uri_a.as_str() {
                seen_a = Some(slug_in(codes));
            } else if message["params"]["uri"] == uri_b.as_str() {
                seen_b = Some(slug_in(codes));
            }
        }
        (seen_a.unwrap(), seen_b.unwrap())
    };
    assert_eq!(both(&mut lsp), (false, true), "after opening B");
    for (round, uri) in [uri_a, uri_b, uri_a, uri_b].into_iter().enumerate() {
        replace_text(&mut lsp, uri, &format!("{text}# edit {round}\n"));
        assert_eq!(
            both(&mut lsp),
            (false, true),
            "after editing {uri} ({round})"
        );
    }
}

/// An unsaved buffer has no file name to check.
#[test]
fn an_untitled_document_gets_no_filename_finding() {
    let scratch = Scratch::new("lint-toml-untitled");
    copy_dir(
        &repo_root().join("testdata/conformance/lint-toml"),
        &scratch.0,
    );
    std::fs::remove_file(scratch.0.join(".opentide/configurations/lint.toml")).unwrap();
    let text = std::fs::read_to_string(scratch.0.join("objects/threats/T-0001.yaml")).unwrap();
    let mut lsp = initialized(json!({ "capabilities": {}, "rootUri": file_uri(&scratch.0) }));
    let codes = lint_codes(published_codes(
        &mut lsp,
        "untitled:Untitled-1",
        "opentide-yaml",
        &text,
    ));
    assert_eq!(codes, vec!["missing_organisation"]);
}

fn cli_lint_codes(dir: &std::path::Path, file: &str) -> Vec<String> {
    let out = Command::new(bin())
        .current_dir(dir)
        .args(["analyze", file])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let diagnostics: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    lint_codes(
        diagnostics
            .iter()
            .filter_map(|d| d["code"].as_str().map(str::to_string))
            .collect(),
    )
}

/// `opentide-lsp analyze` follows the workspace's `lint.toml`, as the
/// server does.
#[test]
fn cli_analyze_follows_the_workspaces_lint_toml() {
    let scratch = Scratch::new("lint-toml-cli");
    let root = &scratch.0;
    copy_dir(&repo_root().join("testdata/conformance/lint-toml"), root);
    let threats = root.join("objects/threats");
    let threat = threats.join("T-0001.yaml");
    let path = threat.to_str().unwrap();
    assert!(cli_lint_codes(root, path).is_empty());
    std::fs::remove_file(root.join(".opentide/configurations/lint.toml")).unwrap();
    let defaults = vec!["filename_slug", "missing_organisation"];
    assert_eq!(cli_lint_codes(root, path), defaults);
    // A bare file name is the file in the current directory.
    assert_eq!(cli_lint_codes(&threats, "T-0001.yaml"), defaults);
}
