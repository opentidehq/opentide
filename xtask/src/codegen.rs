//! `cargo xtask codegen [--check]` (UC-1.8, #814): the artifacts generated
//! from the Rust model (`opentide_schema::generate`).
//!
//! - **Committed artifacts**: every platform block's template,
//!   `src/opentide/schemas/data/platform_templates/<platform>.template.yaml`,
//!   which the package ships and `generate snippets` falls back to, and the
//!   object templates the language server offers as snippets,
//!   `data/catalogs/tide/templates/<family>.1.0.template.yaml`: what
//!   `generate templates` writes for the bundled configuration (#814; a file
//!   there no snippet reads is stale). Without `--check` they are written;
//!   with it, a difference fails.
//! - **Golden parity** (`--check` only): each recording in
//!   `tests/golden/cases` of an `opentide generate` that exited 0 and ran
//!   the `schemas`, `templates` and `snippets` phases (a bare `generate`,
//!   or those phases named with others) holds the templates, the snippets
//!   and the router schema the oracle wrote. Recordings missing one of those
//!   phases, and of a failed run, are not compared: every bare `generate`
//!   on vscode-workspace exits 1 in the docs phase, so that fixture is
//!   compared through `generate schemas templates vocabs snippets`. In each
//!   compared case the same files, generated from the fixture's resolved
//!   configuration, must be byte-identical, and neither side may hold one
//!   the other has not.
//!
//! - **Schemas by verdict** (`--check` only; UC-1.8b, #900): the JSON
//!   Schemas of the `schemas` phase (each object revision's, and
//!   `visibility.toml`'s) in each such recording and in each recording of
//!   `opentide new` that generated them, and every configuration
//!   schema the oracle generates (`crates/opentide-schema/tests/oracle/
//!   configuration_schemas.json`, from `configuration_schemas.py`), are
//!   compared with Rust's by what they accept and refuse, not by their text
//!   ([`crate::verdict`]): every object and configuration file of the
//!   fixtures and of the fault catalogue (every kind must apply), the object
//!   and configuration tables' cases, the bundled configuration files and
//!   the comparison's own probes must get the same verdict from both, but
//!   for each approved difference (`verdict::ALLOWANCES`, which must still
//!   occur). Each compared document must accept at least one instance and
//!   refuse at least one, so a document handed the wrong kind of instance
//!   fails. The configuration router must be the same document. The text
//!   differences are listed in `tests/golden/APPROVED_DIFFS.toml`.
//! - **Editor schemas** (committed): each object revision's schema in
//!   `data/catalogs/tide/schemas/`, generated from the bundled configuration
//!   with no workspace objects, vocabulary essays shortened.
//!
//! - **Language-server catalogs** (`--check` only; UC-3.5d, #933): the
//!   `fields.json` and `deprecations.json` the `schemas` phase writes, from
//!   `opentide_schema::generate::catalog`: byte for byte as in each golden
//!   recording of `opentide generate` that wrote them (the oracle's version
//!   as the label), and the committed copy in `data/catalogs/tide/generated/`
//!   by content, its labels aside.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use opentide_schema::configuration::resolve::{Instance, resolve};
use opentide_schema::generate::configuration::{
    ROUTER_NAME, configuration_schema_name, configuration_schemas, file_keys,
};
use opentide_schema::generate::schema::{Sources, revision_schema};
use opentide_schema::generate::workspace::{
    Artifact, CORE_OBJECT_TYPES, identifiers_for_families, platform_template,
    platform_template_name, router_artifact, schema_artifacts, snippets, templates,
};
use opentide_schema::node::Node;
use opentide_schema::objects::platform::PLATFORM_CONFIG_MODELS;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{OsFs, RootOptions, Workspace};
use serde_json::Value;

use crate::corpus::cli::{read_folder, repo_root};
use crate::golden::case::Spec;
use crate::golden::recording::{Recording, recorded_ids};
use crate::golden::snapshot::{ChangeKind, Kind};
use crate::verdict::{self, Instances};

/// The usage of `cargo xtask codegen`.
pub const USAGE: &str = "usage: cargo xtask codegen [--check]

  (no option)  write the committed artifacts generated from the Rust model:
               src/opentide/schemas/data/platform_templates/*.template.yaml,
               data/catalogs/tide/schemas/<revision>.schema.json and the
               router beside them (opentide.schema.json), the language
               server's catalogs (data/catalogs/tide/generated/) and the key
               lists of highlights/queries/tide/highlights.scm
  --check      compare them instead of writing; compare what `opentide
               generate` writes (templates, snippets, the router schema) with
               each golden recording of an `opentide generate` that ran
               those phases and exited 0, byte for byte; and compare the
               JSON Schemas it writes (each revision's, visibility.toml's)
               and the configuration schemas with the oracle's by verdict on
               every corpus object, configuration file and fault; compare
               the language server's catalogs with the recordings, byte for
               byte, and with data/catalogs/tide/generated; exit 1 on a
               difference
";

/// Where the committed editor schemas live, relative to the repository.
pub const EDITOR_SCHEMAS: &str = "data/catalogs/tide/schemas";

/// The oracle's configuration schemas, written by `configuration_schemas.py`
/// with the oracle's interpreter.
pub const ORACLE_CONFIGURATION_SCHEMAS: &str =
    "crates/opentide-schema/tests/oracle/configuration_schemas.json";

/// Where the committed language-server catalogs live, relative to the
/// repository.
pub const COMMITTED_CATALOGS: &str = "data/catalogs/tide/generated";

/// Where the committed platform templates live, relative to the repository.
pub const PLATFORM_TEMPLATES: &str = "src/opentide/schemas/data/platform_templates";

/// Where the object templates the language server offers as snippets live,
/// relative to the repository (`opentide_tide::snippet`).
pub const EDITOR_TEMPLATES: &str = "data/catalogs/tide/templates";

/// The object templates the language server compiles in: what `opentide
/// generate templates` writes for the bundled configuration, by file name
/// (#814).
pub const EDITOR_TEMPLATE_NAMES: [&str; 3] = [
    "objective.1.0.template.yaml",
    "rule.1.0.template.yaml",
    "threat.1.0.template.yaml",
];

/// Runs `codegen`: `Ok(0)` passed, `Ok(1)` a difference.
pub fn run(args: &[String]) -> Result<u8> {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            "help" | "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(0);
            }
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let root = repo_root();
    let mut problems = committed(&root, check)?;
    problems.extend(engine_catalog(&root, check)?);
    let mut compared = 0;
    let mut judged = 0;
    if check {
        let (count, golden) = golden_parity(&root)?;
        compared = count;
        problems.extend(golden);
        let (count, verdicts) = schema_verdicts(&root)?;
        judged = count;
        problems.extend(verdicts);
        let (count, catalogs) = catalog_parity(&root)?;
        compared += count;
        problems.extend(catalogs);
    }
    for problem in &problems {
        eprintln!("error: {problem}");
    }
    if problems.is_empty() {
        if check {
            println!(
                "codegen: the committed artifacts are current, {compared} files of the \
                 golden recordings of `opentide generate` match byte for byte, and the \
                 schemas agree with the oracle's on {judged} verdicts"
            );
        }
        Ok(0)
    } else {
        eprintln!(
            "codegen: {} difference(s); run `cargo xtask codegen` for the committed files, \
             and fix opentide-schema's generator for a golden difference",
            problems.len()
        );
        Ok(1)
    }
}

/// The committed artifacts, by path relative to the repository.
pub fn committed_artifacts() -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for registered in PLATFORM_CONFIG_MODELS {
        let text = platform_template(registered.key)?
            .with_context(|| format!("no template for platform {}", registered.key))?;
        out.push((
            format!(
                "{PLATFORM_TEMPLATES}/{}",
                platform_template_name(registered.key)
            ),
            text,
        ));
    }
    let sources = bundled_sources()?;
    // The editor's snippets: the templates `generate templates` writes for
    // the bundled configuration, one source with the command (#814).
    let generated = templates(&sources.config).map_err(|error| anyhow::anyhow!("{error}"))?;
    for name in EDITOR_TEMPLATE_NAMES {
        let artifact = generated
            .iter()
            .find(|artifact| Path::new(&artifact.path).file_name() == Some(name.as_ref()))
            .with_context(|| format!("`generate templates` writes no {name}"))?;
        out.push((format!("{EDITOR_TEMPLATES}/{name}"), artifact.text.clone()));
    }
    for id in identifiers_for_families(&CORE_OBJECT_TYPES) {
        let identifier = id.to_string();
        let schema = revision_schema(&identifier, &sources)
            .with_context(|| format!("no schema for {identifier}"))?;
        out.push((
            format!(
                "{EDITOR_SCHEMAS}/{}",
                opentide_schema::generate::router::schema_artifact_name(&id)
            ),
            editor_reference_text(&annotated(&schema)),
        ));
    }
    Ok(out)
}

/// The sources of the committed editor schemas: the bundled configuration
/// alone, the bundled vocabularies, and empty object vocabularies (no
/// workspace objects).
fn bundled_sources() -> Result<Sources> {
    let resolved = resolve(&Instance {
        skip_parent: true,
        ..Instance::default()
    })
    .map_err(|error| anyhow::anyhow!("{}", error.message()))?;
    let mut vocabularies = Vocabularies::bundled();
    for vocabulary in opentide_workspace::vocabularies::object_vocabularies(
        &opentide_workspace::Index::default(),
        &resolved.tree,
    ) {
        vocabularies.insert(vocabulary);
    }
    Ok(Sources {
        config: Arc::new(resolved.tree),
        vocabularies: Arc::new(vocabularies),
    })
}

/// `schema` with the editor annotations `generate schemas` adds
/// (`annotate_editor_schema`).
fn annotated(schema: &schemars::Schema) -> Value {
    let mut json = opentide_schema::generate::json::Json::from(schema.as_value());
    opentide_schema::generate::annotate::annotate_editor_schema(&mut json);
    serde_json::to_value(&json).unwrap_or(Value::Null)
}

/// The longest enum whose Markdown descriptions a committed editor schema
/// keeps (`ENUM_DOC_MAX`), and the length each is cut to (`DOC_CAP`).
const ENUM_DOC_MAX: usize = 40;
const DOC_CAP: usize = 160;

/// A committed editor schema's text: two-space indentation, each enum's
/// Markdown descriptions cut to their summary, or dropped past
/// `ENUM_DOC_MAX` values (the ATT&CK and actor essays would make the
/// files tens of megabytes).
pub fn editor_reference_text(schema: &Value) -> String {
    let mut shortened = schema.clone();
    shorten_enum_docs(&mut shortened);
    let mut text = serde_json::to_string_pretty(&shortened).unwrap_or_default();
    text.push('\n');
    text
}

fn shorten_enum_docs(node: &mut Value) {
    match node {
        Value::Object(map) => {
            let long = map
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| values.len() > ENUM_DOC_MAX);
            if let Some(docs) = map.get_mut("markdownEnumDescriptions") {
                match docs {
                    Value::Array(items) if !long => {
                        for item in items.iter_mut() {
                            if let Value::String(text) = item {
                                *text = cap_doc(&short_doc(text));
                            }
                        }
                    }
                    _ => {
                        map.remove("markdownEnumDescriptions");
                    }
                }
            }
            for (key, value) in map.iter_mut() {
                if key != "markdownEnumDescriptions" {
                    shorten_enum_docs(value);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(shorten_enum_docs),
        _ => {}
    }
}

/// A dropdown's text after its last `---`, on one line.
fn short_doc(markdown: &str) -> String {
    let text = markdown.trim();
    let text = text.rsplit("---").next().unwrap_or(text).trim();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cap_doc(text: &str) -> String {
    if text.chars().count() <= DOC_CAP {
        return text.to_owned();
    }
    let cut: String = text.chars().take(DOC_CAP - 1).collect();
    format!("{}…", cut.trim_end())
}

fn committed(root: &Path, check: bool) -> Result<Vec<String>> {
    let artifacts = committed_artifacts()?;
    let mut problems = Vec::new();
    for (path, text) in &artifacts {
        let file = root.join(path);
        if check {
            match std::fs::read_to_string(&file) {
                Ok(current) if current == *text => {}
                Ok(_) => problems.push(format!("{path}: differs from what the model generates")),
                Err(_) => problems.push(format!("{path}: missing")),
            }
        } else {
            std::fs::write(&file, text).with_context(|| format!("write {}", file.display()))?;
            println!("wrote {path}");
        }
    }
    // A template of a platform the model no longer has is stale.
    let dir = root.join(PLATFORM_TEMPLATES);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    problems.extend(stale_templates(&names, &artifacts));
    let dir = root.join(EDITOR_SCHEMAS);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    problems.extend(stale_editor_schemas(&names, &artifacts));
    // A template the editor does not compile in is stale.
    let dir = root.join(EDITOR_TEMPLATES);
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !EDITOR_TEMPLATE_NAMES.contains(&name.as_str()) {
            problems.push(format!(
                "{EDITOR_TEMPLATES}/{name}: no snippet reads it; remove it"
            ));
        }
    }
    Ok(problems)
}

/// The router the engine compiles in, `opentide.schema.json` beside the
/// revision schemas: each revision's schema chosen by `metadata.schema`.
pub const ENGINE_ROUTER: &str = "data/catalogs/tide/schemas/opentide.schema.json";

/// The static highlight query of Tide objects, whose key lists come from
/// the field catalog.
pub const TIDE_HIGHLIGHTS: &str = "highlights/queries/tide/highlights.scm";

/// The files the engine compiles in that name the version they were
/// generated by (until UC-6.2, #841, a script wrote them from the Python
/// models): the language server's catalogs, the
/// router and the highlight query's key lists, generated from the Rust model
/// with the bundled configuration. Checked with that label left out; written
/// with `version` as the label.
pub fn engine_catalog_artifacts(version: &str) -> Result<Vec<(String, String)>> {
    use opentide_schema::generate::catalog::{FIELDS_FILE, catalog_texts};
    let sources = bundled_sources()?;
    let mut out = Vec::new();
    let mut fields = Value::Null;
    for (name, text) in catalog_texts(version, &sources) {
        if name == FIELDS_FILE {
            fields = serde_json::from_str(&text).context("the generated fields.json")?;
        }
        out.push((format!("{COMMITTED_CATALOGS}/{name}"), text));
    }
    let identifiers = identifiers_for_families(&CORE_OBJECT_TYPES);
    out.push((
        ENGINE_ROUTER.to_owned(),
        opentide_schema::generate::catalog::dump(&engine_router(&identifiers, version)),
    ));
    out.push((
        TIDE_HIGHLIGHTS.to_owned(),
        tide_highlights(&fields, version),
    ));
    Ok(out)
}

/// One schema that picks a revision's schema by `metadata.schema`, its keys
/// in the order the engine's copy has always had them.
fn engine_router(
    identifiers: &[opentide_schema::revisions::SchemaId],
    version: &str,
) -> opentide_schema::generate::json::Json {
    use opentide_schema::generate::json::{Json, Object};
    fn object(pairs: Vec<(&str, Json)>) -> Json {
        let mut out = Object::new();
        for (key, value) in pairs {
            out.insert(key.to_owned(), value);
        }
        Json::from(out)
    }
    let required = |key: &str| Json::from(vec![Json::from(key)]);
    let branches: Vec<Json> = identifiers
        .iter()
        .map(|id| {
            let schema = object(vec![("const", Json::from(id.to_string()))]);
            let metadata = object(vec![
                ("properties", object(vec![("schema", schema)])),
                ("required", required("schema")),
            ]);
            let condition = object(vec![
                ("properties", object(vec![("metadata", metadata)])),
                ("required", required("metadata")),
            ]);
            let target = format!(
                "./{}",
                opentide_schema::generate::router::schema_artifact_name(id)
            );
            object(vec![
                ("if", condition),
                ("then", object(vec![("$ref", Json::from(target))])),
            ])
        })
        .collect();
    object(vec![
        (
            "$schema",
            Json::from("https://json-schema.org/draft/2020-12/schema"),
        ),
        (
            "$id",
            Json::from("https://opentide.dev/schemas/opentide.schema.json"),
        ),
        ("title", Json::from("opentide Object Router")),
        (
            "description",
            Json::from(format!("Generated from opentide {version}.")),
        ),
        ("oneOf", Json::from(branches)),
    ])
}

/// The highlight query of Tide objects: every key of the field catalog
/// under its capture, `tide.property` (and `tide.keyword`, if any).
fn tide_highlights(fields: &Value, version: &str) -> String {
    let rows = fields
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let names = |capture: &str| -> std::collections::BTreeSet<String> {
        rows.iter()
            .filter(|row| row.get("capture").and_then(Value::as_str) == Some(capture))
            .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect()
    };
    let mut queries = String::new();
    for capture in ["tide.property", "tide.keyword"] {
        let names = names(capture);
        if names.is_empty() {
            continue;
        }
        let alternatives: Vec<String> = names.iter().map(|name| escape_regex(name)).collect();
        queries.push_str(&format!(
            "((block_mapping_pair\n  key: (_) @{capture})\n (#match? @{capture} \"^({})$\"))\n",
            alternatives.join("|")
        ));
    }
    format!(
        "; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto\n\
         ; the host document by opentide-highlight (not by this query).\n\
         ; Generated key lists come from catalogs/tide/generated/fields.json\n\
         ; (opentide {version}). Runtime highlighting is path-aware and does not\n\
         ; use this query. Every schema key uses tide.property so nesting does not\n\
         ; recolor the key. Capture names must stay a subset of HighlightSpec.\n\
         \n{queries}\n(comment) @comment\n"
    )
}

/// *name* with only the regex metacharacters escaped (`att&ck` stays as it is).
fn escape_regex(name: &str) -> String {
    let mut out = String::new();
    for character in name.chars() {
        if ".^$*+?()[]{}|\\".contains(character) {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

/// *text* without the line that names the version it was generated by.
fn without_label(path: &str, text: &str) -> String {
    let json = std::path::Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    let marker = if json {
        "Generated from opentide "
    } else {
        "; (opentide "
    };
    text.lines()
        .filter(|line| !line.contains(marker))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The version the written files are labelled with: this checkout's
/// opentide release (`git describe` of its `v*` tags, as hatch-vcs reads
/// it), else the workspace's.
fn label_version(root: &Path) -> String {
    std::process::Command::new("git")
        .args(["describe", "--tags", "--match", "v[0-9]*"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().trim_start_matches('v').to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned())
}

/// Writes (or, with `check`, compares) [`engine_catalog_artifacts`]; the
/// catalogs' differences are `catalog_parity`'s to report.
fn engine_catalog(root: &Path, check: bool) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for (path, text) in engine_catalog_artifacts(&label_version(root))? {
        let file = root.join(&path);
        if !check {
            std::fs::write(&file, &text).with_context(|| format!("write {}", file.display()))?;
            println!("wrote {path}");
        } else if !path.starts_with(COMMITTED_CATALOGS) {
            match std::fs::read_to_string(&file) {
                Ok(current) if without_label(&path, &current) == without_label(&path, &text) => {}
                Ok(_) => problems.push(format!("{path}: differs from what the model generates")),
                Err(_) => problems.push(format!("{path}: missing")),
            }
        }
    }
    Ok(problems)
}

/// Of the file names in the committed editor schemas' folder, each
/// revision schema no artifact is (the router, `opentide.schema.json`, is
/// [`engine_catalog_artifacts`]').
fn stale_editor_schemas(names: &[String], artifacts: &[(String, String)]) -> Vec<String> {
    let mut stale: Vec<String> = names
        .iter()
        .filter(|name| name.ends_with(".schema.json") && *name != "opentide.schema.json")
        .map(|name| format!("{EDITOR_SCHEMAS}/{name}"))
        .filter(|path| !artifacts.iter().any(|(known, _)| known == path))
        .map(|path| format!("{path}: no registered revision generates it"))
        .collect();
    stale.sort();
    stale
}

/// Of the file names in the committed templates' folder, each template no
/// artifact is: a platform the model no longer has.
fn stale_templates(names: &[String], artifacts: &[(String, String)]) -> Vec<String> {
    let mut stale: Vec<String> = names
        .iter()
        .filter(|name| name.ends_with(".template.yaml"))
        .map(|name| format!("{PLATFORM_TEMPLATES}/{name}"))
        .filter(|path| !artifacts.iter().any(|(known, _)| known == path))
        .map(|path| format!("{path}: no platform model generates it"))
        .collect();
    stale.sort();
    stale
}

/// The phases of `opentide generate` that write the files this generator
/// covers: `schemas` the router, `templates` the templates and `snippets`
/// the snippets.
const COMPARED_PHASES: [&str; 3] = ["schemas", "templates", "snippets"];

/// The phases a recording can name besides those: they write other files.
const OTHER_PHASES: [&str; 5] = ["vocabs", "docs", "explorer", "exports", "inflight"];

/// Whether a case's argv runs every phase that writes the files this
/// generator covers: a bare `opentide generate`, or phases named as words
/// after it that include all of [`COMPARED_PHASES`]. Only global flags
/// (`--json`, `--no-color`) may come with it.
fn writes_compared_phases(argv: &[String]) -> bool {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        return false;
    }
    let words: Vec<&str> = argv
        .iter()
        .skip(1)
        .map(String::as_str)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    let Some((&"generate", phases)) = words.split_first() else {
        return false;
    };
    phases.is_empty()
        || (COMPARED_PHASES.iter().all(|phase| phases.contains(phase))
            && phases
                .iter()
                .all(|phase| COMPARED_PHASES.contains(phase) || OTHER_PHASES.contains(phase)))
}

/// Whether a workspace path is one of the files this generator writes.
fn generated_here(path: &str) -> bool {
    path.starts_with(".opentide/templates/")
        || path.ends_with(".code-snippets")
        || path == ".opentide/schemas/opentide.schema.json"
}

/// What `opentide generate` writes, of the files this generator covers, in
/// the workspace at `dir`.
pub fn workspace_artifacts(dir: &Path) -> Result<Vec<Artifact>> {
    let own_dir = dir.join(".opentide").join("configurations");
    let own = read_folder(&own_dir, &own_dir.to_string_lossy())?;
    let resolved = resolve(&Instance {
        workspace: own.as_ref(),
        overlay: None,
        parent: None,
        // Generation sets OPENTIDE_TIDE_WORKSPACE: no parent instance.
        skip_parent: true,
    })
    .map_err(|error| anyhow::anyhow!("{}", error.message()))?;
    let mut artifacts = templates(&resolved.tree)?;
    let snippet = snippets(&resolved.tree, &artifacts).map_err(anyhow::Error::msg)?;
    artifacts.push(snippet);
    artifacts.push(router_artifact(&resolved.tree));
    Ok(artifacts)
}

/// The number of recorded files that matched, and the differences.
fn golden_parity(root: &Path) -> Result<(usize, Vec<String>)> {
    let golden = root.join("tests/golden");
    let spec_text = std::fs::read_to_string(golden.join("cases.toml"))
        .context("read tests/golden/cases.toml")?;
    let spec = Spec::parse(&spec_text)?;
    let cases = golden.join("cases");
    let blobs = golden.join("blobs");
    let scratch = tempfile::tempdir().context("create a scratch directory")?;
    let mut generated: BTreeMap<String, Vec<Artifact>> = BTreeMap::new();
    let mut problems = Vec::new();
    let mut compared = 0;
    for id in recorded_ids(&cases)? {
        if !id.starts_with("generate/") {
            continue;
        }
        let recording = Recording::read(&cases.join(&id), &blobs)?;
        if !writes_compared_phases(&recording.case.argv) || recording.exit_code != 0 {
            continue;
        }
        let fixture = recording.case.fixture.clone();
        if !generated.contains_key(&fixture) {
            let fixture_spec = spec
                .fixtures
                .get(&fixture)
                .with_context(|| format!("{id}: no fixture {fixture} in cases.toml"))?;
            let dir: PathBuf = scratch.path().join(&fixture);
            std::fs::create_dir_all(&dir)?;
            fixture_spec.materialise(root, &dir)?;
            generated.insert(fixture.clone(), workspace_artifacts(&dir)?);
        }
        let artifacts = &generated[&fixture];
        let mut recorded: BTreeMap<String, &[u8]> = BTreeMap::new();
        for file in &recording.files {
            let Some(path) = file.path.strip_prefix("ws/") else {
                continue;
            };
            if file.kind == Kind::File
                && file.change != ChangeKind::Deleted
                && generated_here(path)
                && let Some(contents) = &file.contents
            {
                recorded.insert(path.to_owned(), contents);
            }
        }
        compared += compare(&id, artifacts, recorded, &mut problems);
    }
    if compared == 0 && problems.is_empty() {
        problems.push("no golden recording of `opentide generate` was compared".to_owned());
    }
    Ok((compared, problems))
}

/// The sources of what `opentide generate schemas` writes in the workspace
/// at `dir`: its resolved configuration, its vocabularies and its objects'.
pub fn workspace_sources(dir: &Path) -> Result<Sources> {
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: None,
                repo_root_env: None,
                tide_workspace_env: Some(dir.to_path_buf()),
                cwd: dir.to_path_buf(),
            },
        },
    )
    .map_err(|error| anyhow::anyhow!("open {}: {error}", dir.display()))?;
    let tree: Node = workspace.configuration().resolved.tree.clone();
    let mut vocabularies = Vocabularies::bundled();
    for vocabulary in
        opentide_workspace::vocabularies::object_vocabularies(workspace.index(), &tree)
    {
        vocabularies.insert(vocabulary);
    }
    Ok(Sources {
        config: Arc::new(tree),
        vocabularies: Arc::new(vocabularies),
    })
}

/// What `opentide generate schemas` writes in the workspace at `dir`, but
/// the router: each object revision's schema and `visibility.toml`'s, from
/// the workspace's resolved configuration, its vocabularies and its objects.
pub fn workspace_schema_artifacts(dir: &Path) -> Result<Vec<Artifact>> {
    Ok(schema_artifacts(&workspace_sources(dir)?))
}

/// A catalog document without the keys that only label it.
fn unlabelled(path: &str, text: &str) -> Result<Value> {
    use opentide_schema::generate::catalog::LABEL_KEYS;
    let mut value: Value =
        serde_json::from_str(text).with_context(|| format!("{path}: not JSON"))?;
    if let Some(object) = value.as_object_mut() {
        for key in LABEL_KEYS {
            object.remove(key);
        }
    }
    Ok(value)
}

/// The language server's catalogs the `schemas` phase writes
/// (`.opentide/lsp/catalogs/generated/`): the committed copy the engine
/// compiles in (`data/catalogs/tide/generated/`) must hold what the Rust
/// generator writes from the bundled configuration, its `opentide` and
/// `generator` labels aside (`catalog_differences`); and each golden
/// recording of an `opentide generate` that wrote them must hold, byte for
/// byte, what the generator writes for the fixture with the oracle's version
/// as the label. Returns the number of files compared and the differences.
fn catalog_parity(root: &Path) -> Result<(usize, Vec<String>)> {
    use opentide_schema::generate::catalog::{CATALOG_DIR, catalog_texts};
    let mut problems = Vec::new();
    let mut compared = 0;
    let sources = bundled_sources()?;
    for (name, text) in catalog_texts("", &sources) {
        let path = format!("{COMMITTED_CATALOGS}/{name}");
        match std::fs::read_to_string(root.join(&path)) {
            Ok(current) if unlabelled(&path, &current)? == unlabelled(&path, &text)? => {
                compared += 1;
            }
            Ok(_) => problems.push(format!("{path}: differs from what the model generates")),
            Err(_) => problems.push(format!("{path}: missing")),
        }
    }

    let golden = root.join("tests/golden");
    let oracle =
        std::fs::read_to_string(golden.join("ORACLE")).context("read tests/golden/ORACLE")?;
    let version = oracle
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .context("tests/golden/ORACLE names no version")?;
    let spec_text = std::fs::read_to_string(golden.join("cases.toml"))
        .context("read tests/golden/cases.toml")?;
    let spec = Spec::parse(&spec_text)?;
    let cases = golden.join("cases");
    let blobs = golden.join("blobs");
    let scratch = tempfile::tempdir().context("create a scratch directory")?;
    let mut generated: BTreeMap<String, Vec<(&'static str, String)>> = BTreeMap::new();
    let prefix = format!("ws/{CATALOG_DIR}/");
    for id in recorded_ids(&cases)? {
        if !id.starts_with("generate/") {
            continue;
        }
        let recording = Recording::read(&cases.join(&id), &blobs)?;
        if recording.exit_code != 0 {
            continue;
        }
        let recorded: Vec<(&str, &[u8])> = recording
            .files
            .iter()
            .filter(|file| file.kind == Kind::File && file.change != ChangeKind::Deleted)
            .filter_map(|file| {
                let name = file.path.strip_prefix(&prefix)?;
                Some((name, file.contents.as_deref()?))
            })
            .collect();
        if recorded.is_empty() {
            continue;
        }
        let fixture = recording.case.fixture.clone();
        if !generated.contains_key(&fixture) {
            let fixture_spec = spec
                .fixtures
                .get(&fixture)
                .with_context(|| format!("{id}: no fixture {fixture} in cases.toml"))?;
            let dir: PathBuf = scratch.path().join(&fixture);
            std::fs::create_dir_all(&dir)?;
            fixture_spec.materialise(root, &dir)?;
            generated.insert(
                fixture.clone(),
                catalog_texts(&version, &workspace_sources(&dir)?),
            );
        }
        let ours = &generated[&fixture];
        for (name, bytes) in recorded {
            match ours.iter().find(|(known, _)| *known == name) {
                Some((_, text)) if text.as_bytes() == bytes => compared += 1,
                Some(_) => problems.push(format!(
                    "{id}: {CATALOG_DIR}/{name} differs from the oracle's"
                )),
                None => problems.push(format!(
                    "{id}: {CATALOG_DIR}/{name}: the generator writes no such file"
                )),
            }
        }
    }
    if generated.is_empty() {
        problems.push("no golden recording of `opentide generate` wrote the catalogs".to_owned());
    }
    Ok((compared, problems))
}

/// The fixtures whose object and configuration files are validated against
/// both schemas, besides the fault catalogue's.
const INSTANCE_FIXTURES: [&str; 5] = [
    "tide-corpus",
    "tide-corpus-typo",
    "vscode",
    "heavy-small",
    "fault",
];

/// Whether a recorded workspace path is a JSON Schema of the `schemas`
/// phase compared by verdict: a `*.schema.json` file the byte comparison
/// does not cover (the router).
fn judged_here(path: &str) -> bool {
    std::path::Path::new(path)
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".schema.json"))
        && path.starts_with(".opentide/")
        && !generated_here(path)
}

/// What a JSON Schema of the `schemas` phase validates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaKind {
    /// `visibility.toml` (`.opentide/schemas/visibility.schema.json`).
    Visibility,
    /// An object revision (`.opentide/schemas/rule.1.1.schema.json`).
    Object,
}

fn schema_kind(path: &str) -> SchemaKind {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.starts_with("visibility.") {
        SchemaKind::Visibility
    } else {
        SchemaKind::Object
    }
}

fn parse_json(label: &str, bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).with_context(|| format!("{label}: not JSON"))
}

/// The number of verdicts compared, and the differences: the schemas of
/// every recorded `generate` that wrote them, and the configuration
/// schemas, against the oracle's.
fn schema_verdicts(root: &Path) -> Result<(usize, Vec<String>)> {
    let golden = root.join("tests/golden");
    let spec_text = std::fs::read_to_string(golden.join("cases.toml"))
        .context("read tests/golden/cases.toml")?;
    let spec = Spec::parse(&spec_text)?;
    let scratch = tempfile::tempdir().context("create a scratch directory")?;
    let mut dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut instances = Instances::default();
    for fixture in INSTANCE_FIXTURES {
        let fixture_spec = spec
            .fixtures
            .get(fixture)
            .with_context(|| format!("no fixture {fixture} in cases.toml"))?;
        let dir = scratch.path().join(fixture);
        std::fs::create_dir_all(&dir)?;
        fixture_spec.materialise(root, &dir)?;
        instances.extend(verdict::workspace_instances(fixture, &dir)?);
        dirs.insert(fixture.to_owned(), dir);
    }
    instances.extend(verdict::fault_instances()?);
    instances.extend(verdict::configuration_case_instances(root)?);
    instances.extend(verdict::object_case_instances(root)?);
    instances.extend(verdict::probe_instances());
    let objects: Vec<&verdict::Instance> = instances.objects.iter().collect();
    let visibility: Vec<&verdict::Instance> =
        instances.configurations_of("visibility.toml").collect();

    let mut problems = Vec::new();
    let mut judged = 0;
    let mut allowed = Vec::new();
    let cases = golden.join("cases");
    let blobs = golden.join("blobs");
    let mut generated: BTreeMap<String, Vec<Artifact>> = BTreeMap::new();
    let mut done: HashSet<(String, String, u64)> = HashSet::new();
    for id in recorded_ids(&cases)? {
        // `new` runs the `schemas` phase first where the workspace has no
        // schema yet (UC-3.5d, #933), and `setup vscode` before it writes
        // the editor settings (UC-3.6c, #951): their recordings hold the
        // oracle's too.
        if !id.starts_with("generate/")
            && !id.starts_with("new.")
            && !id.starts_with("setup.vscode/")
        {
            continue;
        }
        let recording = Recording::read(&cases.join(&id), &blobs)?;
        if recording.exit_code != 0 {
            continue;
        }
        let mut recorded: BTreeMap<String, &[u8]> = BTreeMap::new();
        for file in &recording.files {
            let Some(path) = file.path.strip_prefix("ws/") else {
                continue;
            };
            if file.kind == Kind::File
                && file.change != ChangeKind::Deleted
                && judged_here(path)
                && let Some(contents) = &file.contents
            {
                recorded.insert(path.to_owned(), contents);
            }
        }
        if recorded.is_empty() {
            continue;
        }
        let fixture = recording.case.fixture.clone();
        if !dirs.contains_key(&fixture) {
            let fixture_spec = spec
                .fixtures
                .get(&fixture)
                .with_context(|| format!("{id}: no fixture {fixture} in cases.toml"))?;
            let dir = scratch.path().join(&fixture);
            std::fs::create_dir_all(&dir)?;
            fixture_spec.materialise(root, &dir)?;
            dirs.insert(fixture.clone(), dir);
        }
        if !generated.contains_key(&fixture) {
            generated.insert(
                fixture.clone(),
                workspace_schema_artifacts(&dirs[&fixture])?,
            );
        }
        let artifacts = &generated[&fixture];
        for artifact in artifacts {
            if !recorded.contains_key(&artifact.path) {
                problems.push(format!(
                    "{id}: {} is generated, the oracle did not write it",
                    artifact.path
                ));
            }
        }
        for (path, bytes) in recorded {
            let Some(artifact) = artifacts.iter().find(|artifact| artifact.path == path) else {
                problems.push(format!("{id}: the oracle wrote {path}, Rust does not"));
                continue;
            };
            let key = (fixture.clone(), path.clone(), {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                bytes.hash(&mut hasher);
                hasher.finish()
            });
            if !done.insert(key) {
                continue;
            }
            let oracle = parse_json(&format!("{id}: {path}"), bytes)?;
            let rust = parse_json(&format!("Rust's {path}"), artifact.text.as_bytes())?;
            let subjects = match schema_kind(&path) {
                SchemaKind::Visibility => &visibility,
                SchemaKind::Object => &objects,
            };
            let tally = verdict::compare(
                &format!("{id}: {path}"),
                &oracle,
                &rust,
                subjects,
                &verdict::ALLOWANCES,
                &mut problems,
            )?;
            judged += tally.compared;
            allowed.extend(tally.allowed);
        }
    }

    let oracle_path = root.join(ORACLE_CONFIGURATION_SCHEMAS);
    let oracle_text = std::fs::read_to_string(&oracle_path)
        .with_context(|| format!("read {ORACLE_CONFIGURATION_SCHEMAS}"))?;
    let oracle: Value = serde_json::from_str(&oracle_text)
        .with_context(|| format!("{ORACLE_CONFIGURATION_SCHEMAS}: not JSON"))?;
    let documents = oracle
        .get("documents")
        .and_then(Value::as_object)
        .with_context(|| format!("{ORACLE_CONFIGURATION_SCHEMAS}: no `documents`"))?;
    let tally = configuration_verdicts(
        documents,
        &configuration_schemas(),
        &instances,
        &mut problems,
    )?;
    judged += tally.compared;
    allowed.extend(tally.allowed);
    problems.extend(verdict::stale_allowances(&verdict::ALLOWANCES, &allowed));
    if judged == 0 && problems.is_empty() {
        problems.push("no schema verdict was compared".to_owned());
    }
    Ok((judged, problems))
}

/// Compares the configuration documents Rust generates (`rust`, by file
/// name) with the oracle's (`oracle`): each file only one side generates is
/// a problem, the router must be the same document, and every other schema
/// is compared by verdict on the configuration files routed to it. Returns
/// the comparisons' sum.
fn configuration_verdicts(
    oracle: &serde_json::Map<String, Value>,
    rust: &[(String, Value)],
    instances: &Instances,
    problems: &mut Vec<String>,
) -> Result<verdict::Tally> {
    let mut sum = verdict::Tally::default();
    for name in oracle.keys() {
        if !rust.iter().any(|(known, _)| known == name) {
            problems.push(format!("the oracle generates {name}, Rust does not"));
        }
    }
    for (name, document) in rust {
        let Some(expected) = oracle.get(name) else {
            problems.push(format!("Rust generates {name}, the oracle does not"));
            continue;
        };
        if name == ROUTER_NAME {
            // The router names schemas; it validates no file.
            if expected != document {
                problems.push(format!("{name}: differs from the oracle's"));
            }
            continue;
        }
        let keys: Vec<String> = file_keys()
            .into_iter()
            .filter(|key| configuration_schema_name(key) == *name)
            .collect();
        let subjects: Vec<&verdict::Instance> = instances
            .configurations
            .iter()
            .filter(|(key, _)| keys.contains(key))
            .map(|(_, instance)| instance)
            .collect();
        let tally = verdict::compare(
            name,
            expected,
            document,
            &subjects,
            &verdict::ALLOWANCES,
            problems,
        )?;
        sum.compared += tally.compared;
        sum.accepted += tally.accepted;
        sum.refused += tally.refused;
        sum.allowed.extend(tally.allowed);
    }
    Ok(sum)
}

/// Compares what Rust generates with what case `id` recorded, by path:
/// pushes a problem for each file whose bytes differ and each file only one
/// side has, and returns the number of files that matched.
fn compare(
    id: &str,
    artifacts: &[Artifact],
    mut recorded: BTreeMap<String, &[u8]>,
    problems: &mut Vec<String>,
) -> usize {
    let mut matched = 0;
    for artifact in artifacts {
        match recorded.remove(&artifact.path) {
            Some(bytes) if bytes == artifact.text.as_bytes() => matched += 1,
            Some(bytes) => problems.push(format!(
                "{id}: {} differs from the oracle's\n{}",
                artifact.path,
                crate::golden::recording::unified(&String::from_utf8_lossy(bytes), &artifact.text)
            )),
            None => problems.push(format!(
                "{id}: {} is generated, the oracle did not write it",
                artifact.path
            )),
        }
    }
    for path in recorded.keys() {
        problems.push(format!("{id}: the oracle wrote {path}, Rust does not"));
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generated_files_are_recognised() {
        assert!(generated_here(".opentide/templates/rule.1.1.template.yaml"));
        assert!(generated_here(
            ".opentide/templates/platforms/elastic.template.yaml"
        ));
        assert!(generated_here(".vscode/model-templates.code-snippets"));
        assert!(generated_here(".opentide/schemas/opentide.schema.json"));
        assert!(!generated_here(".opentide/schemas/rule.1.1.schema.json"));
        assert!(!generated_here("docs/README.md"));
    }

    #[test]
    fn only_runs_of_every_compared_phase_are_compared() {
        let argv = |args: &[&str]| -> Vec<String> {
            std::iter::once("opentide")
                .chain(args.iter().copied())
                .map(str::to_owned)
                .collect()
        };
        assert!(writes_compared_phases(&argv(&["generate"])));
        assert!(writes_compared_phases(&argv(&[
            "--json",
            "--no-color",
            "generate"
        ])));
        assert!(writes_compared_phases(&argv(&[
            "generate",
            "schemas",
            "templates",
            "vocabs",
            "snippets"
        ])));
        assert!(writes_compared_phases(&argv(&[
            "generate",
            "snippets",
            "templates",
            "schemas"
        ])));
        assert!(!writes_compared_phases(&argv(&["generate", "--help"])));
        assert!(!writes_compared_phases(&argv(&["generate", "schemas"])));
        // One compared phase missing: its files would be absent.
        assert!(!writes_compared_phases(&argv(&[
            "generate",
            "schemas",
            "templates"
        ])));
        assert!(!writes_compared_phases(&argv(&[
            "generate",
            "templates",
            "snippets",
            "vocabs"
        ])));
        // A word that is no phase: a different command or a positional.
        assert!(!writes_compared_phases(&argv(&[
            "generate",
            "schemas",
            "templates",
            "snippets",
            "x"
        ])));
        assert!(!writes_compared_phases(&argv(&[
            "generate", "docs", "--output", "x"
        ])));
        assert!(!writes_compared_phases(&argv(&["info"])));
    }

    fn artifact(path: &str, text: &str) -> Artifact {
        Artifact {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn the_comparison_reports_differing_bytes_and_files_only_one_side_has() {
        let artifacts = [
            artifact("same.yaml", "a: 1\n"),
            artifact("differs.yaml", "a: 1\n"),
            artifact("rust-only.yaml", "a: 1\n"),
        ];
        let recorded: BTreeMap<String, &[u8]> = BTreeMap::from([
            ("same.yaml".to_owned(), b"a: 1\n".as_slice()),
            ("differs.yaml".to_owned(), b"a: 2\n".as_slice()),
            ("oracle-only.yaml".to_owned(), b"a: 1\n".as_slice()),
        ]);
        let mut problems = Vec::new();
        assert_eq!(compare("case", &artifacts, recorded, &mut problems), 1);
        assert_eq!(problems.len(), 3, "{problems:#?}");
        assert!(
            problems[0].starts_with("case: differs.yaml differs from the oracle's\n"),
            "{problems:#?}"
        );
        assert!(problems[0].contains("-a: 2") && problems[0].contains("+a: 1"));
        assert_eq!(
            problems[1],
            "case: rust-only.yaml is generated, the oracle did not write it"
        );
        assert_eq!(
            problems[2],
            "case: the oracle wrote oracle-only.yaml, Rust does not"
        );
    }

    #[test]
    fn identical_files_compare_clean() {
        let artifacts = [artifact("a.yaml", "x\n"), artifact("b.json", "{}\n")];
        let recorded: BTreeMap<String, &[u8]> = BTreeMap::from([
            ("a.yaml".to_owned(), b"x\n".as_slice()),
            ("b.json".to_owned(), b"{}\n".as_slice()),
        ]);
        let mut problems = Vec::new();
        assert_eq!(compare("case", &artifacts, recorded, &mut problems), 2);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn an_extra_committed_template_is_stale() {
        let artifacts = committed_artifacts().unwrap();
        let mut names: Vec<String> = artifacts
            .iter()
            .map(|(path, _)| path.rsplit('/').next().unwrap().to_owned())
            .collect();
        assert!(stale_templates(&names, &artifacts).is_empty());
        names.push("retired.template.yaml".to_owned());
        names.push("README.md".to_owned());
        assert_eq!(
            stale_templates(&names, &artifacts),
            [format!(
                "{PLATFORM_TEMPLATES}/retired.template.yaml: no platform model generates it"
            )]
        );
    }

    #[test]
    fn every_platform_has_a_committed_template() {
        let artifacts = committed_artifacts().unwrap();
        let templates = artifacts
            .iter()
            .filter(|(path, _)| path.starts_with(PLATFORM_TEMPLATES))
            .count();
        assert_eq!(templates, PLATFORM_CONFIG_MODELS.len());
        assert!(artifacts.iter().all(|(_, text)| !text.is_empty()));
    }

    #[test]
    fn every_revision_has_a_committed_editor_schema_and_no_other() {
        let artifacts = committed_artifacts().unwrap();
        let schemas: Vec<&str> = artifacts
            .iter()
            .filter_map(|(path, _)| path.strip_prefix(&format!("{EDITOR_SCHEMAS}/")))
            .collect();
        assert_eq!(
            schemas,
            [
                "objective.1.0.schema.json",
                "rule.1.0.schema.json",
                "rule.1.1.schema.json",
                "threat.1.0.schema.json"
            ]
        );
        let names: Vec<String> = schemas
            .iter()
            .map(|name| (*name).to_owned())
            .chain([
                "opentide.schema.json".to_owned(),
                "rule.0.9.schema.json".to_owned(),
            ])
            .collect();
        assert_eq!(
            stale_editor_schemas(&names, &artifacts),
            [format!(
                "{EDITOR_SCHEMAS}/rule.0.9.schema.json: no registered revision generates it"
            )]
        );
    }

    #[test]
    fn enum_essays_are_shortened_in_the_committed_schemas() {
        let many: Vec<Value> = (0..=ENUM_DOC_MAX)
            .map(|n| Value::from(n.to_string()))
            .collect();
        let long_doc = format!(
            "### Name\n\n**Identifier**: `x`\n\n---\n\n{}",
            "word ".repeat(60)
        );
        let mut schema = serde_json::json!({
            "properties": {
                "few": {"enum": ["a"], "markdownEnumDescriptions": [long_doc]},
                "many": {"enum": many, "markdownEnumDescriptions": ["x"]},
            }
        });
        shorten_enum_docs(&mut schema);
        let few = schema["properties"]["few"]["markdownEnumDescriptions"][0]
            .as_str()
            .unwrap();
        assert_eq!(few.chars().count(), DOC_CAP);
        assert!(few.starts_with("word word") && few.ends_with('…'), "{few}");
        assert!(
            schema["properties"]["many"]
                .get("markdownEnumDescriptions")
                .is_none()
        );
        assert!(editor_reference_text(&schema).ends_with("}\n"));
    }

    fn oracle_configuration_documents() -> serde_json::Map<String, Value> {
        let text = std::fs::read_to_string(repo_root().join(ORACLE_CONFIGURATION_SCHEMAS)).unwrap();
        let oracle: Value = serde_json::from_str(&text).unwrap();
        oracle["documents"].as_object().unwrap().clone()
    }

    #[test]
    fn the_configuration_documents_agree_with_the_oracles_and_a_changed_router_does_not() {
        let oracle = oracle_configuration_documents();
        let mut instances = verdict::configuration_case_instances(&repo_root()).unwrap();
        instances.extend(verdict::probe_instances());
        let rust = configuration_schemas();
        let mut problems = Vec::new();
        let tally = configuration_verdicts(&oracle, &rust, &instances, &mut problems).unwrap();
        assert!(problems.is_empty(), "{problems:#?}");
        assert!(tally.accepted > 0 && tally.refused > 0, "{tally:?}");

        let mut changed = rust.clone();
        let router = changed
            .iter_mut()
            .find(|(name, _)| name == ROUTER_NAME)
            .map(|(_, document)| document)
            .unwrap();
        router["files"].as_object_mut().unwrap().insert(
            "extra.toml".to_owned(),
            serde_json::json!("extra.schema.json"),
        );
        let mut problems = Vec::new();
        configuration_verdicts(&oracle, &changed, &instances, &mut problems).unwrap();
        assert_eq!(
            problems,
            [format!("{ROUTER_NAME}: differs from the oracle's")]
        );

        // A document only one side generates is reported.
        let mut fewer = rust.clone();
        fewer.retain(|(name, _)| name != "sharing.schema.json");
        let mut problems = Vec::new();
        configuration_verdicts(&oracle, &fewer, &instances, &mut problems).unwrap();
        assert_eq!(
            problems,
            ["the oracle generates sharing.schema.json, Rust does not"]
        );
    }

    #[test]
    fn the_probes_get_their_verdict_from_the_schemas_rust_generates() {
        let rust = configuration_schemas();
        let artifacts = committed_artifacts().unwrap();
        let rule_1_0: Value = artifacts
            .iter()
            .find(|(path, _)| path.ends_with("/rule.1.0.schema.json"))
            .map(|(_, text)| serde_json::from_str(text).unwrap())
            .unwrap();
        for (index, (path, text, accepted)) in verdict::PROBES.iter().enumerate() {
            let mut instances = Instances::default();
            instances.add("probe", path, text);
            let (schema, instance) = if let Some(instance) = instances.objects.first() {
                (&rule_1_0, instance)
            } else {
                let (key, instance) = instances.configurations.first().unwrap();
                let name = configuration_schema_name(key);
                let schema = rust
                    .iter()
                    .find(|(known, _)| *known == name)
                    .map(|(_, schema)| schema)
                    .unwrap();
                (schema, instance)
            };
            let verdict = verdict::verdicts(schema, [instance]).unwrap().remove(0);
            assert_eq!(
                verdict.is_none(),
                *accepted,
                "probe {index} ({path}): {verdict:?}\n{text}"
            );
        }
    }

    #[test]
    fn a_visibility_schema_validates_visibility_files_and_any_other_objects() {
        assert_eq!(
            schema_kind(".opentide/schemas/visibility.1.0.schema.json"),
            SchemaKind::Visibility
        );
        assert_eq!(
            schema_kind(".opentide/schemas/visibility.schema.json"),
            SchemaKind::Visibility
        );
        assert_eq!(
            schema_kind(".opentide/schemas/rule.1.1.schema.json"),
            SchemaKind::Object
        );
        assert_eq!(
            schema_kind(".opentide/schemas/objective.1.0.schema.json"),
            SchemaKind::Object
        );
    }

    #[test]
    fn only_regex_metacharacters_are_escaped() {
        assert_eq!(escape_regex("att&ck"), "att&ck");
        assert_eq!(escape_regex("a.b"), "a\\.b");
        assert_eq!(
            escape_regex(".^$*+?()[]{}|\\"),
            "\\.\\^\\$\\*\\+\\?\\(\\)\\[\\]\\{\\}\\|\\\\"
        );
    }

    #[test]
    fn the_version_label_is_left_out_of_a_comparison_and_nothing_else() {
        let json = "{\n  \"description\": \"Generated from opentide 1.0.\",\n  \"a\": 1\n}";
        let other = "{\n  \"description\": \"Generated from opentide 2.0.\",\n  \"a\": 1\n}";
        assert_eq!(
            without_label("x/opentide.schema.json", json),
            without_label("x/opentide.schema.json", other)
        );
        assert_eq!(
            without_label("x/OPENTIDE.SCHEMA.JSON", json),
            "{\n  \"a\": 1\n}"
        );
        // A highlight query's label is its comment line; the JSON marker is
        // only a label in JSON.
        let scm = "; (opentide 1.0). Runtime\n(comment) @comment\nGenerated from opentide x";
        assert_eq!(
            without_label("highlights.scm", scm),
            "(comment) @comment\nGenerated from opentide x"
        );
    }

    #[test]
    fn the_highlight_query_lists_each_capture_s_keys_once_and_sorted() {
        let fields = serde_json::json!({"fields": [
            {"name": "title", "capture": "tide.property"},
            {"name": "a.b", "capture": "tide.property"},
            {"name": "title", "capture": "tide.property"},
            {"name": "when", "capture": "tide.keyword"},
            {"name": "plain", "capture": "other"},
            {"capture": "tide.property"},
        ]});
        let text = tide_highlights(&fields, "9.9.9");
        assert!(text.contains("; (opentide 9.9.9). Runtime"), "{text}");
        assert!(
            text.contains(
                "((block_mapping_pair\n  key: (_) @tide.property)\n \
                 (#match? @tide.property \"^(a\\.b|title)$\"))\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("(#match? @tide.keyword \"^(when)$\"))\n"),
            "{text}"
        );
        assert!(!text.contains("plain"), "{text}");
        assert!(text.ends_with("\n(comment) @comment\n"), "{text}");

        // No field catalog: no key list, the comment capture alone.
        let empty = tide_highlights(&Value::Null, "9.9.9");
        assert!(!empty.contains("block_mapping_pair"), "{empty}");
        assert!(empty.ends_with("\n\n\n(comment) @comment\n"), "{empty:?}");
    }

    #[test]
    fn the_router_picks_each_revision_by_its_metadata_schema() {
        let identifiers = identifiers_for_families(&CORE_OBJECT_TYPES);
        let router = serde_json::to_value(engine_router(&identifiers, "9.9.9")).unwrap();
        assert_eq!(router["title"], "opentide Object Router");
        assert_eq!(router["description"], "Generated from opentide 9.9.9.");
        let branches = router["oneOf"].as_array().unwrap();
        assert_eq!(branches.len(), identifiers.len());
        let rule = branches
            .iter()
            .find(|branch| {
                branch["if"]["properties"]["metadata"]["properties"]["schema"]["const"]
                    == "rule::1.1"
            })
            .unwrap();
        assert_eq!(rule["then"]["$ref"], "./rule.1.1.schema.json");
        assert_eq!(
            rule["if"]["required"],
            serde_json::json!(["metadata"]),
            "{rule}"
        );
        assert_eq!(
            rule["if"]["properties"]["metadata"]["required"],
            serde_json::json!(["schema"])
        );
    }

    #[test]
    fn the_engine_catalog_artifacts_carry_their_version_label() {
        let artifacts = engine_catalog_artifacts("9.9.9").unwrap();
        let paths: Vec<&str> = artifacts.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            paths,
            [
                format!("{COMMITTED_CATALOGS}/fields.json").as_str(),
                format!("{COMMITTED_CATALOGS}/deprecations.json").as_str(),
                ENGINE_ROUTER,
                TIDE_HIGHLIGHTS,
            ]
        );
        let text = |path: &str| &artifacts.iter().find(|(p, _)| p == path).unwrap().1;
        assert!(text(ENGINE_ROUTER).contains("Generated from opentide 9.9.9."));
        assert!(text(TIDE_HIGHLIGHTS).contains("; (opentide 9.9.9)."));
        // The key lists come from the field catalog: `metadata` is a key of
        // every object.
        assert!(
            text(TIDE_HIGHLIGHTS).contains("|metadata|"),
            "{}",
            text(TIDE_HIGHLIGHTS)
        );
    }

    /// An empty repository layout with the folders `codegen` writes into.
    fn scratch_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in [
            PLATFORM_TEMPLATES,
            EDITOR_SCHEMAS,
            COMMITTED_CATALOGS,
            "highlights/queries/tide",
        ] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        root
    }

    #[test]
    fn the_engine_catalog_is_written_then_checked_by_content_not_label() {
        let root = scratch_root();
        let root = root.path();
        assert!(engine_catalog(root, false).unwrap().is_empty());
        for (path, _) in engine_catalog_artifacts("0").unwrap() {
            assert!(root.join(&path).is_file(), "{path}");
        }
        assert!(engine_catalog(root, true).unwrap().is_empty());

        // Another version's label is no difference.
        let router = root.join(ENGINE_ROUTER);
        let text = std::fs::read_to_string(&router).unwrap();
        let relabelled: String = text
            .lines()
            .map(|line| {
                if line.contains("Generated from opentide ") {
                    "  \"description\": \"Generated from opentide 0.0.1.\","
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(relabelled, text);
        std::fs::write(&router, relabelled).unwrap();
        assert!(engine_catalog(root, true).unwrap().is_empty());

        // A changed key list is; a missing file is reported as missing. The
        // language server's catalogs are catalog_parity's to compare.
        std::fs::write(&router, text.replace("rule.1.1", "rule.9.9")).unwrap();
        std::fs::remove_file(root.join(TIDE_HIGHLIGHTS)).unwrap();
        std::fs::write(root.join(COMMITTED_CATALOGS).join("fields.json"), "{}").unwrap();
        assert_eq!(
            engine_catalog(root, true).unwrap(),
            [
                format!("{ENGINE_ROUTER}: differs from what the model generates"),
                format!("{TIDE_HIGHLIGHTS}: missing"),
            ]
        );
    }

    #[test]
    fn the_committed_artifacts_are_written_then_checked_byte_for_byte() {
        let root = scratch_root();
        let root = root.path();
        assert!(committed(root, false).unwrap().is_empty());
        assert!(committed(root, true).unwrap().is_empty());

        let artifacts = committed_artifacts().unwrap();
        let (template, _) = artifacts
            .iter()
            .find(|(path, _)| path.starts_with(PLATFORM_TEMPLATES))
            .unwrap();
        let (schema, _) = artifacts
            .iter()
            .find(|(path, _)| path.starts_with(EDITOR_SCHEMAS))
            .unwrap();
        std::fs::write(root.join(template), "changed\n").unwrap();
        std::fs::remove_file(root.join(schema)).unwrap();
        std::fs::write(
            root.join(PLATFORM_TEMPLATES).join("retired.template.yaml"),
            "",
        )
        .unwrap();
        assert_eq!(
            committed(root, true).unwrap(),
            [
                format!("{template}: differs from what the model generates"),
                format!("{schema}: missing"),
                format!(
                    "{PLATFORM_TEMPLATES}/retired.template.yaml: no platform model generates it"
                ),
            ]
        );

        // Without the folders there is nothing to check against.
        let empty = tempfile::tempdir().unwrap();
        assert!(committed(empty.path(), true).is_err());
    }

    /// `git` in `dir`, with a fixed identity and no maintenance.
    fn git(dir: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .envs(crate::payloads::git::QUIET_GIT)
            .env("GIT_AUTHOR_NAME", "golden")
            .env("GIT_AUTHOR_EMAIL", "golden@example.invalid")
            .env("GIT_COMMITTER_NAME", "golden")
            .env("GIT_COMMITTER_EMAIL", "golden@example.invalid")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    #[test]
    fn the_label_is_the_checkout_s_release_else_the_workspace_s_version() {
        let repo = tempfile::tempdir().unwrap();
        let repo = repo.path();
        git(repo, &["init", "--quiet"]);
        git(repo, &["commit", "--quiet", "--allow-empty", "-m", "first"]);
        // No release tag: git describe fails.
        assert_eq!(label_version(repo), env!("CARGO_PKG_VERSION"));
        git(repo, &["tag", "engine-v9.0.0"]);
        assert_eq!(label_version(repo), env!("CARGO_PKG_VERSION"));
        git(repo, &["tag", "v1.2.3"]);
        assert_eq!(label_version(repo), "1.2.3");
        git(
            repo,
            &["commit", "--quiet", "--allow-empty", "-m", "second"],
        );
        assert!(
            label_version(repo).starts_with("1.2.3-1-g"),
            "{}",
            label_version(repo)
        );
    }

    #[test]
    fn codegen_refuses_an_unknown_option_and_prints_its_usage() {
        assert_eq!(run(&["--help".to_owned()]).unwrap(), 0);
        let error = run(&["--write".to_owned()]).unwrap_err().to_string();
        assert!(error.starts_with("unknown option `--write`"), "{error}");
    }
}
