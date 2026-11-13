//! The ingest end to end on synthetic STIX bundles, a MISP galaxy file and a
//! specifications checkout of its own: no network.

use std::fs;
use std::path::Path;

use serde_json::json;

use super::*;

const NOW: &str = "2026-11-13T10:00:00.123Z";

fn reference(id: &str) -> serde_json::Value {
    json!([{"source_name": "mitre-attack", "external_id": id,
            "url": format!("https://attack.mitre.org/{id}")}])
}

/// A specifications checkout with the five vocabularies and a threat pin
/// file, and a repository with the bundled configuration and pins.
fn layout(root: &Path) {
    let vocabularies = root.join("specifications/vocabularies");
    fs::create_dir_all(&vocabularies).unwrap();
    let header = |name: &str, field: &str, key: &str| {
        format!("name = \"{name}\"\nfield = \"{field}\"\ndescription = \"d\"\nkey = \"{key}\"\n")
    };
    fs::write(
        vocabularies.join("att&ck.vocab.toml"),
        header("MITRE ATT&CK", "att&ck", "id")
            + "stages = [\n    \"Old\",\n]\nsource = \"mitre-attack\"\nsource_version = \"19.0\"\n\
               [[keys]]\nid = \"T1000\"\nname = \"Gone\"\ndescription = \"\"\nversion = \"1.0\"\n\
               [[keys]]\nid = \"T1001\"\nname = \"Kept\"\ndescription = \"old\"\nversion = \"1.1\"\n",
    )
    .unwrap();
    fs::write(
        vocabularies.join("att&ck.groups.vocab.toml"),
        header("Groups", "att&ck.groups", "id"),
    )
    .unwrap();
    fs::write(
        vocabularies.join("mitigations.vocab.toml"),
        header("Mitigations", "mitigations", "name") + "model = \"x\"\n",
    )
    .unwrap();
    fs::write(
        vocabularies.join("datasources.vocab.toml"),
        header("Data sources", "datasources", "name"),
    )
    .unwrap();
    fs::write(
        vocabularies.join("actors.vocab.toml"),
        header("Threat Actors", "actors", "id")
            + "\n[[stages]]\nid = \"misp\"\nname = \"MISP Threat Actor Galaxy\"\n\
               description = \"Threat Actors extracted from MISP Threat Actor Galaxy/Cluster\"\n\
               [[keys]]\nid = \"G0001\"\nname = \"[Enterprise] APT\"\ndescription = \"\"\n\
               \"tide.vocab.stages\" = \"att&ck\"\nversion = \"1.0\"\n",
    )
    .unwrap();
    let pins = root.join("specifications/schemas/pins");
    fs::create_dir_all(&pins).unwrap();
    fs::write(
        pins.join("threat.toml"),
        "[\"threat::1.0\"]\n\"threat.actors.name\" = \"actors::1.0\"\n\"threat.mitre_attack\" = \"att&ck::1.1\"\n",
    )
    .unwrap();

    let repo = root.join("repo");
    fs::create_dir_all(repo.join("src/opentide/data/configurations")).unwrap();
    fs::create_dir_all(repo.join("src/opentide/data/pins")).unwrap();
    fs::create_dir_all(repo.join("src/opentide/data/vocabulary")).unwrap();
    fs::create_dir_all(repo.join("data")).unwrap();
    fs::write(
        repo.join("src/opentide/data/configurations/resources.toml"),
        format!(
            "[misp.galaxies]\nthreat_actors = \"file://{}\"\n",
            root.join("galaxy.json").display()
        ),
    )
    .unwrap();

    let stix = root.join("stix");
    fs::create_dir_all(&stix).unwrap();
    let enterprise = json!({"type": "bundle", "objects": [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Stealth",
         "x_mitre_shortname": "stealth"},
        {"type": "x-mitre-matrix", "tactic_refs": ["x-mitre-tactic--1"]},
        {"type": "attack-pattern", "name": "Kept", "description": "new text",
         "external_references": reference("T1001"),
         "kill_chain_phases": [{"phase_name": "stealth"}]},
        {"type": "attack-pattern", "name": "Sub", "external_references": reference("T1001.001")},
        {"type": "intrusion-set", "name": "APT", "aliases": ["APT", "Other\u{1}"],
         "external_references": reference("G0001")},
        {"type": "course-of-action", "name": "Audit", "description": "a",
         "external_references": reference("M1047")},
        {"type": "x-mitre-data-source", "id": "ds--1", "name": "Process",
         "external_references": reference("DS0009")},
        {"type": "x-mitre-data-component", "name": "Process Creation",
         "x_mitre_data_source_ref": "ds--1", "description": "c"},
    ]});
    fs::write(stix.join("enterprise-attack.json"), enterprise.to_string()).unwrap();
    let mobile = json!([
        {"type": "attack-pattern", "name": "Phone", "external_references": reference("T1400")},
        {"type": "intrusion-set", "name": "APT", "external_references": reference("G0001")},
    ]);
    fs::write(stix.join("mobile-attack.json"), mobile.to_string()).unwrap();
    fs::write(
        stix.join("manifest.json"),
        json!({"version": "20.0", "tag": "v20.0", "fetched_at": "2026-11-02T14:23:27.420Z"})
            .to_string(),
    )
    .unwrap();
    let galaxy = json!({"values": [
        {"uuid": "7a3f-misp", "value": "Fancy", "description": "f",
         "meta": {"synonyms": ["F1", "F2"]}},
        {"uuid": "8b4e-misp", "value": "Quiet"},
    ]});
    fs::write(root.join("galaxy.json"), galaxy.to_string()).unwrap();
}

fn options(root: &Path, check: bool, apply: bool) -> Options {
    Options {
        check,
        apply,
        no_fetch: true,
        stix_dir: Some(root.join("stix")),
        misp_url: None,
        specifications: Some(root.join("specifications")),
        now: Some(NOW.to_owned()),
    }
}

#[test]
fn the_ingest_merges_every_vocabulary_and_reports_the_unpinned_contracts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    layout(root);
    let galaxy = fs::read(root.join("galaxy.json")).unwrap();
    let inputs = Inputs {
        stix_dir: root.join("stix"),
        misp: Some(("file://galaxy".to_owned(), galaxy)),
        now: NOW.to_owned(),
    };
    let report = compute(
        &root.join("specifications"),
        &root.join("repo/src/opentide/data/pins"),
        &inputs,
    )
    .unwrap();
    assert_eq!(
        report.summary(),
        "attack:\n  att&ck: 4 keys (+2 ~1 -1 backfill=0)\n    new contract att&ck::1.2\n\
         \x20 att&ck.groups: 1 keys (+1 ~0 -0 backfill=0)\n\
         \x20 mitigations: 1 keys (+1 ~0 -0 backfill=0)\n\
         \x20 datasources: 2 keys (+2 ~0 -0 backfill=0)\n\
         \x20 source provenance changed (attack)\n\
         actors:\n  actors: 3 keys (+2 ~1 -0 backfill=0)\n    new contract actors::1.1\n\
         \x20 source provenance changed (actors)\n\
         unpinned contracts: actors::1.1, att&ck::1.2 (adopting one is a new schema revision)\n"
    );
    assert!(report.dirty());

    let attack = &report.attack.vocabularies[0].document;
    let text = tomli::dump_vocab_document(attack).unwrap();
    assert_eq!(
        text,
        "name = \"MITRE ATT&CK\"\nfield = \"att&ck\"\ndescription = \"d\"\nkey = \"id\"\n\
         stages = [\n    \"Stealth\",\n]\nsource = \"mitre-attack\"\nsource_version = \"20.0\"\n\
         source_fetched_at = \"2026-11-02T14:23:27.420Z\"\n\
         [[keys]]\nid = \"T1000\"\nname = \"Gone\"\ndescription = \"\"\nversion = \"1.0\"\nremoved = \"2.0\"\n\
         [[keys]]\nid = \"T1001\"\nname = \"Kept\"\ndescription = \"new text\"\n\
         link = \"https://attack.mitre.org/T1001\"\n\"tide.vocab.stages\" = [\n    \"Stealth\",\n]\nversion = \"1.1\"\n\
         [[keys]]\nid = \"T1001.001\"\nname = \"Kept: Sub\"\ndescription = \"\"\n\
         link = \"https://attack.mitre.org/T1001.001\"\nversion = \"1.2\"\n\
         [[keys]]\nid = \"T1400\"\nname = \"Mobile : Phone\"\ndescription = \"\"\n\
         link = \"https://attack.mitre.org/T1400\"\nversion = \"1.2\"\n"
    );
    let mitigations = &report.attack.vocabularies[2].document;
    assert!(!mitigations.contains_key("model"));

    let actors = tomli::dump_vocab_document(&report.actors.vocabularies[0].document).unwrap();
    let digest = crate::golden::blob::sha256_hex(&fs::read(root.join("galaxy.json")).unwrap());
    assert!(
        actors.starts_with(&format!(
            "name = \"Threat Actors\"\nfield = \"actors\"\ndescription = \"d\"\nkey = \"id\"\n\
             source_version = \"20.0\"\nsource_fetched_at = \"2026-11-02T14:23:27.420Z\"\n\
             source = \"mitre-attack+misp\"\ngenerated_at = \"{NOW}\"\n\
             source_misp_url = \"file://galaxy\"\nsource_misp_sha256 = \"{digest}\"\n\n\
             [[stages]]\nid = \"misp\"\n"
        )),
        "{actors}"
    );
    assert!(actors.contains(
        "[[keys]]\nid = \"G0001\"\nname = \"[Enterprise] APT\"\ndescription = \"\"\n\
         link = \"https://attack.mitre.org/G0001\"\nalias = [\n    \"APT\",\n    \"Other\\u0001\",\n]\n\
         \"tide.vocab.stages\" = \"att&ck\"\nversion = \"1.0\"\n"
    ), "{actors}");
    assert!(
        !actors.contains("[Mobile]"),
        "the Enterprise entry of a repeated group wins"
    );
    assert!(actors.contains(
        "id = \"7a3f-misp\"\nname = \"Fancy\"\ndescription = \"f\"\n\"tide.vocab.stages\" = \"misp\"\n\
         alias = [\n    \"F1\",\n    \"F2\",\n]\nversion = \"1.1\"\n"
    ));
}

#[test]
fn check_writes_nothing_apply_writes_and_syncs_and_then_check_passes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    layout(root);
    let repo = root.join("repo");
    let vocabularies = root.join("specifications/vocabularies");
    let before = fs::read(vocabularies.join("att&ck.vocab.toml")).unwrap();

    assert!(!run(&repo, &options(root, true, false)).unwrap(), "dirty");
    assert_eq!(
        fs::read(vocabularies.join("att&ck.vocab.toml")).unwrap(),
        before
    );

    assert!(run(&repo, &options(root, false, true)).unwrap());
    let written = fs::read_to_string(vocabularies.join("att&ck.vocab.toml")).unwrap();
    assert!(written.contains("removed = \"2.0\""));
    assert_eq!(
        fs::read_to_string(repo.join("src/opentide/data/vocabulary/actors.vocab.toml")).unwrap(),
        fs::read_to_string(vocabularies.join("actors.vocab.toml")).unwrap(),
        "the bundle is synced"
    );
    assert!(repo.join("data/specifications.lock.json").is_file());

    assert!(
        run(&repo, &options(root, true, false)).unwrap(),
        "a second run finds nothing to do"
    );
    assert!(
        run(&repo, &options(root, false, true)).unwrap(),
        "no changes to write"
    );
}

#[test]
fn the_options_are_checked() {
    let words = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    assert!(parse(&words(&["--check", "--apply"])).is_err());
    assert!(parse(&words(&["--stix-dir"])).is_err());
    assert!(parse(&words(&["--frobnicate"])).is_err());
    let options = parse(&words(&["--apply", "--no-fetch", "--now", NOW])).unwrap();
    assert!(options.apply && options.no_fetch);
    assert_eq!(options.now.as_deref(), Some(NOW));

    let dir = tempfile::tempdir().unwrap();
    layout(dir.path());
    let mut no_dir = options_for_missing_stix(dir.path());
    no_dir.stix_dir = None;
    // SAFETY-free: the variable is read, never set, by this test.
    if std::env::var_os(STIX_DIR_ENV).is_none() {
        assert!(
            run(&dir.path().join("repo"), &no_dir).is_err(),
            "--no-fetch needs a directory"
        );
    }
}

fn options_for_missing_stix(root: &Path) -> Options {
    Options {
        no_fetch: true,
        ..options(root, true, false)
    }
}

#[test]
fn pin_files_name_vocabulary_fields() {
    assert_eq!(
        pinned_fields(
            "[\"t::1.0\"]\n  \"a.b\" = \"actors::1.2\"\r\n\"x\" = \"y\"\n\"c\"=\"att&ck::10.0\" \n"
        ),
        ["actors", "att&ck"]
    );
    let mut contracts = BTreeMap::new();
    contracts.insert("actors".to_owned(), "1.2".to_owned());
    contracts.insert("mitigations".to_owned(), "1.1".to_owned());
    assert_eq!(schema_pinned(contracts.clone(), &[]).len(), 2);
    assert_eq!(
        schema_pinned(contracts, &["actors".to_owned()])
            .into_keys()
            .collect::<Vec<_>>(),
        ["actors"]
    );
}

#[test]
fn timestamps_and_tags_are_the_old_ingests() {
    assert_eq!(format_utc(0, 0), "1970-01-01T00:00:00.000Z");
    assert_eq!(format_utc(1_793_092_207, 420), "2026-10-27T09:10:07.420Z");
    assert_eq!(format_utc(951_782_400, 5), "2000-02-29T00:00:00.005Z");
    assert_eq!(release_version("ATT&CK-v18.1"), "18.1");
    assert_eq!(release_version("v20.0"), "20.0");
    assert_eq!(release_version("20.0"), "20.0");
    assert!(utc_now_iso().unwrap().ends_with('Z'));
}

#[test]
fn a_misp_file_url_is_read_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.json");
    fs::write(&path, b"{}").unwrap();
    assert_eq!(
        read_url(&format!("file://{}", path.display())).unwrap(),
        b"{}"
    );
    assert!(read_url("file:///nonexistent/galaxy.json").is_err());
}

#[test]
fn a_release_names_its_bundles_and_the_manifest_records_them() {
    let release = value::parse_json(
        br#"{"tag_name": "v20.1", "assets": [
            {"name": "mobile-attack.json", "browser_download_url": "https://example.test/m.json"},
            {"name": "other.json", "browser_download_url": "https://example.test/o.json"}]}"#,
    )
    .unwrap();
    let (tag, sources) = bundle_sources(&release).unwrap();
    assert_eq!(tag, "v20.1");
    assert_eq!(
        sources.iter().map(|s| s.url.as_str()).collect::<Vec<_>>(),
        [
            "https://github.com/mitre-attack/attack-stix-data/releases/download/v20.1/enterprise-attack.json",
            "https://example.test/m.json",
            "https://github.com/mitre-attack/attack-stix-data/releases/download/v20.1/ics-attack.json",
        ]
    );
    let manifest = manifest_of(&tag, &sources[..1], NOW);
    assert_eq!(
        manifest_text(&manifest).unwrap(),
        "{\n  \"version\": \"20.1\",\n  \"tag\": \"v20.1\",\n  \"fetched_at\": \"2026-11-13T10:00:00.123Z\",\n  \
         \"bundles\": {\n    \"enterprise\": {\n      \"path\": \"enterprise-attack.json\",\n      \
         \"url\": \"https://github.com/mitre-attack/attack-stix-data/releases/download/v20.1/enterprise-attack.json\"\n    }\n  }\n}\n"
    );
    let (tag, _) = bundle_sources(&value::parse_json(b"{}").unwrap()).unwrap();
    assert_eq!(tag, "unknown");
}
