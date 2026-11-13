//! `vocab malapi` on the saved pages of `xtask/tests/malapi/` and a
//! specifications checkout of its own: no network.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::json;

use super::*;

const NOW: &str = "2026-11-13T10:00:00.000Z";

/// The saved pages: three APIs, GetDriveTypeA, IsDebuggerPresent and
/// VirtualAlloc.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/malapi")
}

fn words(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// The vocabulary the site's pages are merged into: GetDriveTypeA with an
/// older description, IsDebuggerPresent as the site has it, Gone (no longer
/// listed) and Dead (removed before).
const EXISTING: &str = r#"name = "Malicious Window API"
field = "malapi"
description = "MalAPI.io maps Windows APIs to common techniques used by malware."
reference = "https://malapi.io"
key = "name"

[[stages]]
name = "Enumeration"
description = "Functions associated with system enumeration."

[[keys]]
version = "1.0"
name = "GetDriveTypeA"
description = "GetDriveTypeA is old.\nLibrary : `Kernel32.dll`"
link = "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea"
"tide.vocab.stages" = ["Enumeration", "Anti-Debugging"]

[[keys]]
version = "1.0"
name = "Gone"
description = "Not listed any more."
link = "https://learn.microsoft.com/gone"
"tide.vocab.stages" = "Helper"

[[keys]]
version = "1.0"
name = "IsDebuggerPresent"
description = "IsDebuggerPresent checks if the current process is being debugged by a user-mode debugger."
link = "https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent"
"tide.vocab.stages" = "Anti-Debugging"

[[keys]]
version = "1.0"
name = "Dead"
description = "Removed before."
removed = "2.0"
"#;

/// A specifications checkout with the vocabulary, and a repository with an
/// empty bundle.
fn layout(root: &Path) {
    let vocabularies = root.join("specifications/vocabularies");
    fs::create_dir_all(&vocabularies).unwrap();
    fs::write(vocabularies.join("malapi.vocab.toml"), EXISTING).unwrap();
    let pins = root.join("specifications/schemas/pins");
    fs::create_dir_all(&pins).unwrap();
    fs::write(
        pins.join("threat.toml"),
        "[\"threat::1.0\"]\n\"threat.actors.name\" = \"actors::1.0\"\n",
    )
    .unwrap();
    let repo = root.join("repo");
    for dir in [
        "src/opentide/data/vocabulary",
        "src/opentide/data/pins",
        "data",
    ] {
        fs::create_dir_all(repo.join(dir)).unwrap();
    }
}

fn options(root: &Path, html_dir: &Path, check: bool, apply: bool) -> Options {
    Options {
        check,
        apply,
        specifications: Some(root.join("specifications")),
        html_dir: Some(html_dir.to_path_buf()),
        delay: Duration::ZERO,
        now: Some(NOW.to_owned()),
    }
}

fn vocabulary(root: &Path) -> PathBuf {
    root.join("specifications/vocabularies/malapi.vocab.toml")
}

fn keys_by_name(document: &Table) -> serde_json::Map<String, Value> {
    keys_of(document)
        .into_iter()
        .map(|key| (key["name"].as_str().unwrap().to_owned(), Value::Object(key)))
        .collect()
}

#[test]
fn the_front_page_lists_the_categories_and_every_linked_api_once() {
    let page = front_page(&fs::read_to_string(fixtures().join("index.html")).unwrap()).unwrap();
    assert_eq!(
        Value::Array(page.stages.into_iter().map(Value::Object).collect()),
        json!([
            {"name": "Enumeration", "description": "Functions associated with system enumeration."},
            {"name": "Anti-Debugging",
             "description": "Functions associated with anti-reverse engineering and debugging."},
            {"name": "Helper",
             "description": "Functions that are not necessarily malicious, but can aid malware."},
        ])
    );
    // Relative, absolute and trailing-slash links; the navigation's and the
    // footer's links are not APIs.
    assert_eq!(
        page.apis,
        ["GetDriveTypeA", "IsDebuggerPresent", "VirtualAlloc"]
    );
}

#[test]
fn a_front_page_that_lost_its_table_categories_or_links_is_an_error() {
    let error = |html: &str| front_page(html).unwrap_err().to_string();
    assert_eq!(
        error("<p>maintenance</p>"),
        "No main-table on https://malapi.io"
    );
    assert_eq!(
        error(r#"<table id="main-table"><tr><td>x</td></tr></table>"#),
        "No attack category on https://malapi.io"
    );
    assert!(
        error(r#"<table id="main-table"><tr><th>Helper</th></tr></table>"#)
            .contains("`Helper` has no icon title")
    );
    assert_eq!(
        error(r#"<table id="main-table"><tr><th>H<img title="h"></th></tr></table>"#),
        "No API link on https://malapi.io",
        "never an empty scrape, which would remove every key"
    );
    assert!(
        error(
            r#"<table id="main-table"><tr><th>H<img title="h"></th></tr></table>
               <a href="/winapi/x">../../etc/passwd</a>"#
        )
        .contains("is not an identifier"),
        "a name goes into a URL and a file name"
    );
}

#[test]
fn an_api_page_is_a_vocabulary_key() {
    let read = |api: &str| {
        let html = fs::read_to_string(fixtures().join(format!("winapi/{api}.html"))).unwrap();
        Value::Object(api_page(api, &html).unwrap())
    };
    assert_eq!(
        read("GetDriveTypeA"),
        json!({
            "name": "GetDriveTypeA",
            "description": "GetDriveTypeA is used to determine if a disk drive is a removable, \
                            fixed, CD-ROM, RAM disk, or network drive.\nLibrary : `Kernel32.dll`",
            "link": "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea",
            "tide.vocab.stages": ["Enumeration", "Anti-Debugging"],
        })
    );
    // One category is a string; no library, nothing appended.
    assert_eq!(
        read("IsDebuggerPresent"),
        json!({
            "name": "IsDebuggerPresent",
            "description": "IsDebuggerPresent checks if the current process is being debugged \
                            by a user-mode debugger.",
            "link": "https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent",
            "tide.vocab.stages": "Anti-Debugging",
        })
    );
}

#[test]
fn an_api_page_without_details_is_an_error() {
    let detail = |heading: &str, content: &str| {
        format!(
            r#"<div class="detail-container"><div class="heading">{heading}</div><div class="content">{content}</div></div>"#
        )
    };
    let error = |html: &str| api_page("X", html).unwrap_err().to_string();
    assert_eq!(error("<html></html>"), "Empty parsed API: X");
    assert_eq!(
        error(&detail("Description", "d")),
        "the page of X has no Function Name"
    );
    assert_eq!(
        error(&(detail("Function Name", "X") + &detail("Library", "k.dll"))),
        "the page of X names a library but has no Description"
    );
}

#[test]
fn the_merge_updates_adds_removes_and_keeps_versions() {
    let dir = tempfile::tempdir().unwrap();
    layout(dir.path());
    let path = vocabulary(dir.path());
    let report = build(
        read_vocab_document(&path).unwrap(),
        path,
        scrape(&Pages::Saved(fixtures())).unwrap(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        report.summary(),
        "malapi: 5 keys (+1 ~1 -1 backfill=0)\n  new contract malapi::1.1 (adopting it is a new \
         schema revision)\n  attack categories changed\n"
    );
    assert!(report.dirty());
    let document = &report.vocabulary.document;
    assert_eq!(document["source"], SOURCE);
    assert_eq!(document["source_fetched_at"], NOW);
    assert_eq!(document["stages"].as_array().unwrap().len(), 3);
    // The keys keep the merge order: the existing ones, then the new.
    assert_eq!(
        keys_of(document)
            .iter()
            .map(|key| key["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "GetDriveTypeA",
            "Gone",
            "IsDebuggerPresent",
            "Dead",
            "VirtualAlloc"
        ]
    );
    let keys = keys_by_name(document);
    let updated = &keys["GetDriveTypeA"];
    assert_eq!(updated["version"], "1.0", "an edit keeps the version");
    assert!(
        updated["description"]
            .as_str()
            .unwrap()
            .starts_with("GetDriveTypeA is used")
    );
    assert_eq!(
        keys["Gone"]["version"], "1.0",
        "a removed API keeps its version"
    );
    assert_eq!(keys["Gone"]["removed"], "2.0");
    assert_eq!(keys["Dead"]["removed"], "2.0");
    assert_eq!(keys["VirtualAlloc"]["version"], "1.1");
    assert_eq!(keys["VirtualAlloc"]["tide.vocab.stages"], "Helper");
}

#[test]
fn check_exits_1_on_drift_apply_writes_and_syncs_and_then_check_passes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    layout(root);
    let repo = root.join("repo");
    let before = fs::read(vocabulary(root)).unwrap();

    assert!(!run(&repo, &options(root, &fixtures(), true, false)).unwrap());
    assert_eq!(
        fs::read(vocabulary(root)).unwrap(),
        before,
        "a check writes nothing"
    );
    // The command line: exit status 1.
    let specifications = root.join("specifications");
    let fixtures = fixtures();
    let args = [
        "malapi",
        "--check",
        "--specifications",
        specifications.to_str().unwrap(),
        "--html-dir",
        fixtures.to_str().unwrap(),
        "--now",
        NOW,
    ];
    assert_eq!(super::super::main(&words(&args)), ExitCode::FAILURE);

    assert!(run(&repo, &options(root, &fixtures, false, true)).unwrap());
    let written = read_vocab_document(&vocabulary(root)).unwrap();
    assert_eq!(keys_by_name(&written)["VirtualAlloc"]["version"], "1.1");
    assert_eq!(written["source_fetched_at"], NOW);
    assert_eq!(
        fs::read_to_string(repo.join("src/opentide/data/vocabulary/malapi.vocab.toml")).unwrap(),
        fs::read_to_string(vocabulary(root)).unwrap(),
        "the bundle is synced"
    );
    assert!(repo.join("data/specifications.lock.json").is_file());

    assert!(
        run(&repo, &options(root, &fixtures, true, false)).unwrap(),
        "a second run finds nothing to do"
    );
    assert!(
        run(&repo, &options(root, &fixtures, false, true)).unwrap(),
        "no changes to write"
    );
    assert_eq!(super::super::main(&words(&args)), ExitCode::SUCCESS);
}

#[test]
fn a_run_stopped_part_way_carries_the_unreached_keys_over() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    layout(root);
    // The site gave up after GetDriveTypeA: IsDebuggerPresent's page and the
    // ones after it never came.
    let pages = root.join("pages");
    fs::create_dir_all(pages.join("winapi")).unwrap();
    for page in ["index.html", "winapi/GetDriveTypeA.html"] {
        fs::copy(fixtures().join(page), pages.join(page)).unwrap();
    }
    let repo = root.join("repo");

    let error = run(&repo, &options(root, &pages, true, false)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "2 of 3 APIs not fetched: the check could not run"
    );

    assert!(
        !run(&repo, &options(root, &pages, false, true)).unwrap(),
        "a partial apply fails"
    );
    let written = read_vocab_document(&vocabulary(root)).unwrap();
    let keys = keys_by_name(&written);
    let existing = keys_by_name(&super::super::ingest::value::parse_toml(EXISTING).unwrap());
    assert_eq!(keys["IsDebuggerPresent"], existing["IsDebuggerPresent"]);
    assert_eq!(keys["Dead"], existing["Dead"]);
    assert_eq!(keys["Gone"]["removed"], "2.0");
    assert!(!keys.contains_key("VirtualAlloc"));
    assert!(
        keys["GetDriveTypeA"]["description"]
            .as_str()
            .unwrap()
            .starts_with("GetDriveTypeA is used")
    );
    assert!(
        !repo
            .join("src/opentide/data/vocabulary/malapi.vocab.toml")
            .exists(),
        "the bundle is not synced"
    );
}

#[test]
fn a_saved_page_that_does_not_parse_stops_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    layout(root);
    let pages = root.join("pages");
    fs::create_dir_all(pages.join("winapi")).unwrap();
    fs::copy(fixtures().join("index.html"), pages.join("index.html")).unwrap();
    fs::write(pages.join("winapi/GetDriveTypeA.html"), "<p>gone</p>").unwrap();
    let error = run(&root.join("repo"), &options(root, &pages, false, true)).unwrap_err();
    assert_eq!(error.to_string(), "Empty parsed API: GetDriveTypeA");
    assert_eq!(fs::read_to_string(vocabulary(root)).unwrap(), EXISTING);
    // No front page at all.
    let empty = root.join("empty");
    fs::create_dir_all(&empty).unwrap();
    assert!(run(&root.join("repo"), &options(root, &empty, true, false)).is_err());
}

#[test]
fn the_options_are_checked() {
    assert!(parse(&words(&["--check", "--apply"])).is_err());
    assert!(parse(&words(&["--html-dir"])).is_err());
    assert!(parse(&words(&["--frobnicate"])).is_err());
    for delay in ["-1", "NaN", "inf", "soon", "1e300"] {
        assert!(parse(&words(&["--delay", delay])).is_err(), "{delay}");
    }
    let defaults = parse(&[]).unwrap();
    assert!(!defaults.check && !defaults.apply);
    assert_eq!(defaults.delay, DEFAULT_DELAY);
    let options = parse(&words(&[
        "--apply",
        "--delay",
        "2.5",
        "--html-dir",
        "pages",
        "--specifications",
        "spec",
        "--now",
        NOW,
    ]))
    .unwrap();
    assert!(options.apply);
    assert_eq!(options.delay, Duration::from_millis(2500));
    assert_eq!(options.html_dir.as_deref(), Some(Path::new("pages")));
    assert_eq!(options.specifications.as_deref(), Some(Path::new("spec")));
    assert_eq!(options.now.as_deref(), Some(NOW));
}

#[test]
fn api_names_are_identifiers() {
    assert!(valid_api("NtQueryInformationProcess"));
    assert!(valid_api("_snprintf"));
    for name in ["", "a b", "../x", "x/y", "x?y", "é"] {
        assert!(!valid_api(name), "{name}");
    }
}
