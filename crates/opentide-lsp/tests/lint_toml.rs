//! `opentide lsp start` follows a root's `.opentide/configurations/lint.toml`
//! (#214): on disk, and as the editor's buffer while it is open.

mod common;

use common::{Lsp, Scratch, copy_dir, file_uri, next_diagnostics, published_codes, repo_root};
use serde_json::json;

const LINT_CODES: [&str; 4] = [
    "filename_slug",
    "filename_pattern",
    "missing_author",
    "missing_organisation",
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
