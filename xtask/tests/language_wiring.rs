//! Every query language is wired everywhere a language must be.
//!
//! A language is named in tables across the workspace, and most of them fail
//! quietly when one is left out: lint drops a language's findings without
//! `ENGINE_REFERENCES`, a pull request to a parser crate skips the WASM job
//! without `PARSER_CRATES`. This test walks `LanguageId::QUERY_LANGUAGES` (and
//! checks that list against the enum itself) and lists every table a language
//! is missing from, with its file. The add-language skill's checklist says
//! where each one is; this test says which ones a change forgot.

#![expect(
    clippy::expect_used,
    reason = "test helpers: a panic naming the missing file or table is how the test fails"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use opentide_core::LanguageId;
use opentide_schema::platforms::PLATFORMS;

/// The `LanguageId` variants that are not query languages, and why.
const NOT_QUERY_LANGUAGES: &[(&str, &str)] = &[
    ("TideYaml", "the Tide object files themselves"),
    ("Config", "opentide's configuration TOML"),
];

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

fn read(relative: &str) -> String {
    let path = root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The variants of `pub enum LanguageId`, as its source declares them.
fn declared_variants() -> BTreeSet<String> {
    let source = read("crates/opentide-core/src/lib.rs");
    let start = source
        .find("pub enum LanguageId {")
        .expect("opentide-core declares LanguageId");
    let body = &source[start..];
    let body = &body[..body.find("\n}").expect("the enum closes")];
    // A variant's line, without a trailing comment: `Name,`, `Name = 3,`,
    // `Name(T),` or `Name { .. },` (attributes and doc comments are skipped).
    body.lines()
        .map(|line| line.split("//").next().unwrap_or_default().trim())
        .filter(|line| !line.starts_with('#') && !line.starts_with("pub enum"))
        .filter_map(|line| {
            let name: String = line
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            name.chars()
                .next()
                .is_some_and(char::is_uppercase)
                .then_some(name)
        })
        .collect()
}

/// Query languages whose platform row is not in the registry yet, and why.
/// Every other table applies to them; only "a platform's offline_languages"
/// waits for the row. A language listed here that a platform already checks
/// offline fails `languages_awaiting_a_platform_have_none`, so the entry is
/// removed with the change that adds the row.
const AWAITING_A_PLATFORM: &[(&str, &str)] = &[];

/// Whether a variant is a query language. `LanguageId` is non-exhaustive, so
/// the `match` needs a wildcard, which panics: the test below fails until a
/// new variant is listed in `LanguageId::QUERY_LANGUAGES` or
/// `NOT_QUERY_LANGUAGES` (`declared_variants`), and a new query language
/// until it is classified here.
const fn is_query_language(id: LanguageId) -> bool {
    match id {
        LanguageId::TideYaml | LanguageId::Config => false,
        LanguageId::Kql
        | LanguageId::Spl
        | LanguageId::Esql
        | LanguageId::Eql
        | LanguageId::Kuery
        | LanguageId::Lucene
        | LanguageId::Falco
        | LanguageId::Cql
        | LanguageId::Yara
        | LanguageId::Exabeam
        | LanguageId::Yaral
        | LanguageId::Datadog => true,
        _ => panic!("classify the new LanguageId variant in is_query_language"),
    }
}

/// The text between `open` and the next `close` after it in `text`.
fn between<'t>(text: &'t str, open: &str, close: &str) -> &'t str {
    let start = text
        .find(open)
        .unwrap_or_else(|| panic!("{open:?} not found"))
        + open.len();
    let rest = &text[start..];
    &rest[..rest
        .find(close)
        .unwrap_or_else(|| panic!("{close:?} not found after {open:?}"))]
}

#[test]
fn query_languages_lists_every_variant_but_the_documents() {
    let listed: BTreeSet<String> = LanguageId::QUERY_LANGUAGES
        .iter()
        .map(|id| format!("{id:?}"))
        .chain(
            NOT_QUERY_LANGUAGES
                .iter()
                .map(|(name, _)| (*name).to_owned()),
        )
        .collect();
    assert!(
        LanguageId::QUERY_LANGUAGES
            .iter()
            .all(|id| is_query_language(*id)),
        "QUERY_LANGUAGES holds a variant is_query_language says is not a query language"
    );
    assert_eq!(
        listed,
        declared_variants(),
        "LanguageId::QUERY_LANGUAGES (crates/opentide-core/src/lib.rs) and \
         NOT_QUERY_LANGUAGES here must name every LanguageId variant once"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one check per table, each with the file it names: read top to bottom"
)]
fn every_query_language_is_wired() {
    let codes: Vec<&str> = opentide_core::codes::ALL.to_vec();
    let references: Vec<&str> = opentide_analysis::queries::ENGINE_REFERENCES
        .iter()
        .map(|(prefix, _, _)| *prefix)
        .collect();
    let schemas: serde_json::Value =
        serde_json::from_str(&read("crates/opentide-cli/data/output-schemas.json"))
            .expect("output-schemas.json is JSON");
    let schema_languages: BTreeSet<&str> = schemas
        .pointer("/$defs/QueryChecked/properties/language/enum")
        .and_then(serde_json::Value::as_array)
        .expect("QueryChecked.language is an enum")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let changes = read("scripts/ci/changes.py");
    let parser_crates = between(&changes, "PARSER_CRATES = (", ")");
    let fuzz_sh = read("scripts/engine/fuzz.sh");
    // The `case` arm that runs a language target: `kql|spl|...)`.
    let fuzz_languages: Vec<&str> = fuzz_sh
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("kql|"))
        .expect("fuzz.sh has the language targets' case arm")
        .trim_end_matches(')')
        .split('|')
        .collect();
    let fuzz_cargo = read("fuzz/Cargo.toml");
    let engine_fuzz = read(".github/workflows/engine-fuzz.yml");
    let fuzz_matrix = between(&engine_fuzz, "target: [", "]");
    let wasm_smoke = read("scripts/engine/wasm-smoke.mjs");
    let wasm_samples = between(&wasm_smoke, "const samples = {", "};");
    let throughput = read("crates/opentide-analysis/benches/throughput.rs");
    let bench_rows = between(&throughput, "const LANGUAGES: &[Language] = &[", "\n];");
    let lsp_client = read("packages/lsp-client/src/index.ts");
    let stub = read("src/opentide/_native/__init__.pyi");
    let io_free = read("scripts/engine/check-io-free.sh");
    let budgets = read("tests/bench/instructions.toml");
    let helix = read("editors/helix/languages.toml");
    let nvim = read("editors/nvim/opentide.lua");
    let zed = read("editors/zed/opentide.json");
    let stub_languages = between(&stub, "Language = Literal[", "]");

    let mut missing = Vec::new();
    for language in LanguageId::QUERY_LANGUAGES {
        let id = language.as_str();
        let krate = format!("opentide-{id}");
        let prefix = format!("{id}_");
        let mut check = |wired: bool, table: &str| {
            if !wired {
                missing.push(format!("{id}: {table}"));
            }
        };
        check(
            root()
                .join("crates")
                .join(&krate)
                .join("Cargo.toml")
                .is_file(),
            &format!("its crate, crates/{krate}"),
        );
        check(
            codes.iter().any(|code| code.starts_with(&prefix)),
            "a code in opentide_core::codes::ALL (crates/opentide-core/src/lib.rs)",
        );
        check(
            references.contains(&prefix.as_str()),
            "ENGINE_REFERENCES (crates/opentide-analysis/src/queries.rs): without it lint drops \
             its findings",
        );
        check(
            PLATFORMS
                .iter()
                .any(|platform| platform.offline_languages.contains(&id))
                || AWAITING_A_PLATFORM
                    .iter()
                    .any(|(awaiting, _)| *awaiting == id),
            "a platform's offline_languages (crates/opentide-schema/src/platforms.rs)",
        );
        check(
            schema_languages.contains(id),
            "QueryChecked.language (crates/opentide-cli/data/output-schemas.json)",
        );
        check(
            parser_crates.contains(&format!("\"{krate}\"")),
            "PARSER_CRATES (scripts/ci/changes.py): without it its pull requests skip the WASM job",
        );
        check(
            root()
                .join("fuzz/fuzz_targets")
                .join(format!("{id}.rs"))
                .is_file()
                && fuzz_cargo.contains(&format!("name = \"{id}\"")),
            "a fuzz target (fuzz/fuzz_targets/, fuzz/Cargo.toml)",
        );
        check(
            fuzz_matrix.split(',').any(|target| target.trim() == id),
            "the fuzz matrix (.github/workflows/engine-fuzz.yml)",
        );
        check(
            fuzz_languages.contains(&id),
            "the language targets of scripts/engine/fuzz.sh",
        );
        check(
            wasm_samples.contains(&format!("\n    {id}: ")),
            "a sample (scripts/engine/wasm-smoke.mjs)",
        );
        check(
            bench_rows.contains(&format!("id: LanguageId::{language:?},")),
            "a LANGUAGES row (crates/opentide-analysis/benches/throughput.rs)",
        );
        check(
            lsp_client.contains(&format!("id: \"{id}\"")),
            "a language (packages/lsp-client/src/index.ts)",
        );
        check(
            stub_languages.contains(&format!("\"{id}\"")),
            "the Python stub's Language literal (src/opentide/_native/__init__.pyi)",
        );
        check(
            io_free
                .split_whitespace()
                .any(|word| word == krate.as_str()),
            "the I/O-free crates (scripts/engine/check-io-free.sh)",
        );
        check(
            root().join("crates/testdata/corpus").join(id).is_dir(),
            "its corpus (crates/testdata/corpus/<id>/)",
        );
        check(
            root()
                .join("crates/opentide-highlight/src/keywords")
                .join(format!("{id}.rs"))
                .is_file(),
            "its KEYWORDS table (crates/opentide-highlight/src/keywords/<id>.rs)",
        );
        check(
            budgets.lines().any(|line| line.trim() == format!("[{id}]")),
            "its budgets (tests/bench/instructions.toml: cargo xtask throughput --record)",
        );
        check(
            helix.contains(&format!("name = \"{id}\"")),
            "a language (editors/helix/languages.toml)",
        );
        check(
            nvim.contains(&format!("\"{id}\"")),
            "a filetype (editors/nvim/opentide.lua)",
        );
        check(
            zed.contains(&format!("\"{id}\": {{")),
            "a language (editors/zed/opentide.json)",
        );
    }
    assert!(
        missing.is_empty(),
        "a query language is missing from these tables (the add-language skill, \
         .agents/skills/add-language/SKILL.md, says what each one needs):\n  {}",
        missing.join("\n  ")
    );
}

/// A language that waits for its platform row has none yet: once a platform
/// checks it offline, its entry in [`AWAITING_A_PLATFORM`] goes.
#[test]
fn languages_awaiting_a_platform_have_none() {
    for (id, why) in AWAITING_A_PLATFORM {
        assert!(
            LanguageId::QUERY_LANGUAGES
                .iter()
                .any(|l| l.as_str() == *id),
            "{id} is in AWAITING_A_PLATFORM but is not a query language"
        );
        assert!(!why.is_empty());
        let checked_by: Vec<&str> = PLATFORMS
            .iter()
            .filter(|platform| platform.offline_languages.contains(id))
            .map(|platform| platform.id)
            .collect();
        assert!(
            checked_by.is_empty(),
            "{id} is checked offline by {checked_by:?}: remove it from AWAITING_A_PLATFORM"
        );
    }
}

/// The registry's query files and its offline languages say the same thing:
/// each suffix `validate query` accepts for a platform is in a language the
/// platform checks offline, and each of those languages has a suffix.
#[test]
fn the_registry_s_suffixes_match_its_offline_languages() {
    let mut mismatched = Vec::new();
    for platform in PLATFORMS {
        let by_suffix: BTreeSet<&str> = platform
            .query_file_suffixes
            .iter()
            .map(|suffix| LanguageId::from_extension(suffix).map_or("?", LanguageId::as_str))
            .collect();
        let offline: BTreeSet<&str> = platform.offline_languages.iter().copied().collect();
        if by_suffix != offline {
            mismatched.push(format!(
                "{}: query_file_suffixes {:?} read as {by_suffix:?}, offline_languages {offline:?}",
                platform.id, platform.query_file_suffixes
            ));
        }
    }
    assert!(
        mismatched.is_empty(),
        "crates/opentide-schema/src/platforms.rs:\n  {}",
        mismatched.join("\n  ")
    );
}

/// The MCP manifest's `validate_query` says which platforms it checks
/// offline and which on the tenant; those lists are the registry's.
#[test]
fn the_mcp_manifest_names_the_registry_s_platforms() {
    let manifest = read("crates/opentide-cli/data/mcp/manifest.json");
    let listed = |open: &str, close: &str| -> BTreeSet<String> {
        between(&manifest, open, close)
            .split(", ")
            .map(|id| id.trim().to_owned())
            .collect()
    };
    let registry = |keep: fn(&opentide_schema::platforms::Platform) -> bool| -> BTreeSet<String> {
        PLATFORMS
            .iter()
            .filter(|platform| keep(platform))
            .map(|platform| platform.id.to_owned())
            .collect()
    };
    assert_eq!(
        listed("Offline: ", "."),
        registry(|platform| !platform.offline_languages.is_empty()),
        "validate_query's \"Offline:\" list (crates/opentide-cli/data/mcp/manifest.json) is the \
         registry's platforms with offline_languages"
    );
    assert_eq!(
        listed("Platforms: ", ";"),
        registry(|platform| platform.live_check),
        "validate_query's \"Platforms:\" list (crates/opentide-cli/data/mcp/manifest.json) is the \
         registry's platforms with live_check"
    );
}
