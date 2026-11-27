//! `opentide_schema::objects::platform::constraint_codes` covers every model
//! that reports a constraint code (#1893). It reads the crate's sources, so it
//! lives here: the library's own tests stay I/O-free
//! (`scripts/engine/check-io-free.sh`).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test]: a source that cannot be read fails the test"
)]

use opentide_schema::objects::platform::{self, graylog, microsoft_defender, sentinel};

/// Every source file of the crate, by its path from `src/`, with its text.
fn sources(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, root, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((name, std::fs::read_to_string(&path).unwrap()));
        }
    }
}

/// `constraint_codes` reads every model that reports an error typed by its
/// own code (`ErrorKind::Constraint`): `validate` fails its `schema` check on
/// those codes alone (#1893), so a model that starts reporting one adds its
/// list there, and this test names the file. Each code is one `opentide
/// explain` knows (`opentide_core::codes::ALL`), and none is listed twice.
#[test]
fn constraint_codes_read_every_model_that_reports_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &root, &mut files);
    let mut reporting: Vec<String> = files
        .into_iter()
        .filter(|(name, text)| {
            name != "error.rs"
                && !name.ends_with("tests.rs")
                && text.contains("ErrorKind::Constraint(")
        })
        .map(|(name, _)| name)
        .collect();
    reporting.sort();
    // Graylog's findings are reported by `report_finding` in `mod.rs`.
    assert_eq!(
        reporting,
        [
            "objects/platform/bitdefender/checks.rs",
            "objects/platform/datadog.rs",
            "objects/platform/exabeam.rs",
            "objects/platform/google_secops.rs",
            "objects/platform/microsoft_defender.rs",
            "objects/platform/mod.rs",
            "objects/platform/sentinel.rs",
        ],
        "a model reports a constraint code: add its codes to platform::constraint_codes"
    );
    let codes: Vec<&str> = platform::constraint_codes().collect();
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "{codes:?}");
    for code in codes {
        assert!(opentide_core::codes::ALL.contains(&code), "{code}");
    }
    for code in microsoft_defender::CONSTRAINT_CODES
        .into_iter()
        .chain(graylog::constraint_codes())
        .chain(sentinel::CONSTRAINT_CODES)
    {
        assert!(unique.contains(code), "{code}");
    }
    assert!(!unique.contains("extra_forbidden"));
}
