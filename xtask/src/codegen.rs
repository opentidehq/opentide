//! `cargo xtask codegen [--check]` (UC-1.8, #814): the artifacts generated
//! from the Rust model (`opentide_schema::generate`).
//!
//! - **Committed artifacts**: every platform block's template,
//!   `src/opentide/schemas/data/platform_templates/<platform>.template.yaml`,
//!   which the package ships and `generate snippets` falls back to. Without
//!   `--check` they are written; with it, a difference fails.
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
//!   `visibility.toml`'s) in each such recording, and every configuration
//!   schema the oracle generates (`crates/opentide-schema/tests/oracle/
//!   configuration_schemas.json`, from `configuration_schemas.py`), are
//!   compared with Rust's by what they accept and refuse, not by their text
//!   ([`crate::verdict`]): every object and configuration file of the
//!   fixtures and of the fault catalogue, the configuration table's texts and
//!   the bundled configuration files must get the same verdict from both.
//!   The configuration router must be the same document. The text
//!   differences are listed in `tests/golden/APPROVED_DIFFS.toml`.
//! - **Editor schemas** (committed): each object revision's schema in
//!   `data/catalogs/tide/schemas/`, generated from the bundled configuration
//!   with no workspace objects, vocabulary essays shortened.
//!
//! The language server's field catalog is not generated from Rust yet
//! (UC-2.6, #821).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use opentide_schema::configuration::resolve::{Instance, resolve};
use opentide_schema::generate::configuration::{
    ROUTER_NAME, configuration_router, configuration_schema_name, configuration_schemas, file_keys,
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
               src/opentide/schemas/data/platform_templates/*.template.yaml
               and data/catalogs/tide/schemas/<revision>.schema.json
  --check      compare them instead of writing; compare what `opentide
               generate` writes (templates, snippets, the router schema) with
               each golden recording of an `opentide generate` that ran
               those phases and exited 0, byte for byte; and compare the
               JSON Schemas it writes (each revision's, visibility.toml's)
               and the configuration schemas with the oracle's by verdict on
               every corpus object, configuration file and fault; exit 1 on
               a difference
";

/// Where the committed editor schemas live, relative to the repository.
pub const EDITOR_SCHEMAS: &str = "data/catalogs/tide/schemas";

/// The oracle's configuration schemas, written by `configuration_schemas.py`
/// with the oracle's interpreter.
pub const ORACLE_CONFIGURATION_SCHEMAS: &str =
    "crates/opentide-schema/tests/oracle/configuration_schemas.json";

/// Where the committed platform templates live, relative to the repository.
pub const PLATFORM_TEMPLATES: &str = "src/opentide/schemas/data/platform_templates";

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
    let mut compared = 0;
    let mut judged = 0;
    if check {
        let (count, golden) = golden_parity(&root)?;
        compared = count;
        problems.extend(golden);
        let (count, verdicts) = schema_verdicts(&root)?;
        judged = count;
        problems.extend(verdicts);
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
/// [`ENUM_DOC_MAX`] values (the ATT&CK and actor essays would make the
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
    Ok(problems)
}

/// Of the file names in the committed editor schemas' folder, each
/// revision schema no artifact is (the router, `opentide.schema.json`, is
/// written by `scripts/engine/sync_opentide_schemas.py`).
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

/// What `opentide generate schemas` writes in the workspace at `dir`, but
/// the router: each object revision's schema and `visibility.toml`'s, from
/// the workspace's resolved configuration, its vocabularies and its objects.
pub fn workspace_schema_artifacts(dir: &Path) -> Result<Vec<Artifact>> {
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
    Ok(schema_artifacts(&Sources {
        config: Arc::new(tree),
        vocabularies: Arc::new(vocabularies),
    }))
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
    let objects: Vec<&verdict::Instance> = instances.objects.iter().collect();
    let visibility: Vec<&verdict::Instance> =
        instances.configurations_of("visibility.toml").collect();

    let mut problems = Vec::new();
    let mut judged = 0;
    let cases = golden.join("cases");
    let blobs = golden.join("blobs");
    let mut generated: BTreeMap<String, Vec<Artifact>> = BTreeMap::new();
    let mut done: HashSet<(String, String, u64)> = HashSet::new();
    for id in recorded_ids(&cases)? {
        if !id.starts_with("generate/") {
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
            let subjects = if path.contains("visibility") {
                &visibility
            } else {
                &objects
            };
            judged += verdict::compare(
                &format!("{id}: {path}"),
                &oracle,
                &rust,
                subjects,
                &mut problems,
            )?;
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
    let rust_documents = configuration_schemas();
    for name in documents.keys() {
        if !rust_documents.iter().any(|(known, _)| known == name) {
            problems.push(format!("the oracle generates {name}, Rust does not"));
        }
    }
    for (name, rust) in &rust_documents {
        let Some(oracle) = documents.get(name) else {
            problems.push(format!("Rust generates {name}, the oracle does not"));
            continue;
        };
        if name == ROUTER_NAME {
            if *oracle != configuration_router() {
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
        judged += verdict::compare(name, oracle, rust, &subjects, &mut problems)?;
    }
    if judged == 0 && problems.is_empty() {
        problems.push("no schema verdict was compared".to_owned());
    }
    Ok((judged, problems))
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
            .chain(["opentide.schema.json".to_owned(), "rule.0.9.schema.json".to_owned()])
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
        let many: Vec<Value> = (0..=ENUM_DOC_MAX).map(|n| Value::from(n.to_string())).collect();
        let long_doc = format!("### Name\n\n**Identifier**: `x`\n\n---\n\n{}", "word ".repeat(60));
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
        assert!(schema["properties"]["many"].get("markdownEnumDescriptions").is_none());
        assert!(editor_reference_text(&schema).ends_with("}\n"));
    }
}
