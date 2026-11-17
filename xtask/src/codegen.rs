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
//! - **Diagnostics reference** (committed): `docs/cli/diagnostics.md`, every
//!   `opentide explain` page on one page, its prose made safe for MDX
//!   (`opentide_cli::explain::reference_markdown`).
//! - **Editor schemas** (committed): each object revision's schema in
//!   `data/catalogs/tide/schemas/`, generated from the bundled configuration
//!   with no workspace objects, vocabulary essays shortened.
//!
//! - **Language-server catalogs** (UC-3.5d, #933): the `fields.json` and
//!   `deprecations.json` the `schemas` phase writes, from
//!   `opentide_schema::generate::catalog`: the committed copy in
//!   `data/catalogs/tide/generated/` (`--check`).
//!
//! The comparisons with the oracle's recordings (`--oracle`) were retired
//! with the recordings (#1142). Engine lint runs `codegen --check`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use opentide_schema::configuration::resolve::{Instance, resolve};
use opentide_schema::generate::schema::{Sources, revision_schema};
use opentide_schema::generate::workspace::{
    CORE_OBJECT_TYPES, identifiers_for_families, platform_template, platform_template_name,
    templates,
};
use opentide_schema::objects::platform::PLATFORM_CONFIG_MODELS;
use opentide_schema::vocab::Vocabularies;
use serde_json::Value;

use crate::corpus::cli::repo_root;

/// The arguments of `cargo xtask codegen`. With no option it writes the
/// committed artifacts generated from the Rust model:
/// src/opentide/schemas/data/platform_templates/*.template.yaml,
/// data/catalogs/tide/schemas/`<revision>.schema.json` and the router beside them
/// (opentide.schema.json), the language server's catalogs
/// (data/catalogs/tide/generated/), the diagnostics reference
/// (docs/cli/diagnostics.md), and the typed AST of every .ungram grammar
/// (src/generated/ast.rs of its crate).
#[derive(Args)]
pub struct CodegenArgs {
    /// Compare them instead of writing, and the language server's catalogs with
    /// data/catalogs/tide/generated; exit 1 on a difference (CI's Engine lint)
    #[arg(long)]
    pub check: bool,
}

/// Where the committed editor schemas live, relative to the repository.
pub const EDITOR_SCHEMAS: &str = "data/catalogs/tide/schemas";

/// Where the committed language-server catalogs live, relative to the
/// repository.
pub const COMMITTED_CATALOGS: &str = "data/catalogs/tide/generated";

/// Where the committed platform templates live, relative to the repository.
pub const PLATFORM_TEMPLATES: &str = "src/opentide/schemas/data/platform_templates";

/// The diagnostics reference, every `opentide explain` page on one docs
/// page (`opentide_cli::explain::reference_markdown`), relative to the
/// repository.
pub const DIAGNOSTICS_REFERENCE: &str = "docs/cli/diagnostics.md";

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
pub fn run(args: &CodegenArgs) -> Result<u8> {
    let CodegenArgs { check } = *args;
    let root = repo_root();
    let mut problems = committed(&root, check)?;
    problems.extend(engine_catalog(&root, check)?);
    problems.extend(crate::astgen::sync(&root, check)?);
    problems.extend(crate::yara_modules::sync(&root, check)?);
    if check {
        // The committed language-server catalogs' drift from the generator.
        problems.extend(catalog_drift(&root)?.1);
    }
    for problem in &problems {
        eprintln!("error: {problem}");
    }
    if problems.is_empty() {
        if check {
            println!("codegen: the committed artifacts are current");
        }
        Ok(0)
    } else {
        eprintln!(
            "codegen: {} difference(s); run `cargo xtask codegen` for the committed files",
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
    out.push((
        DIAGNOSTICS_REFERENCE.to_owned(),
        opentide_cli::explain::reference_markdown(),
    ));
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
    let dir = root.join(EDITOR_TEMPLATES);
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    problems.extend(stale_editor_templates(&names));
    Ok(problems)
}

/// The router the engine compiles in, `opentide.schema.json` beside the
/// revision schemas: each revision's schema chosen by `metadata.schema`.
pub const ENGINE_ROUTER: &str = "data/catalogs/tide/schemas/opentide.schema.json";

/// The files the engine compiles in that name the version they were
/// generated by (until UC-6.2, #841, a script wrote them from the Python
/// models): the language server's catalogs and the
/// router, generated from the Rust model
/// with the bundled configuration. Checked with that label left out; written
/// with `version` as the label.
pub fn engine_catalog_artifacts(version: &str) -> Result<Vec<(String, String)>> {
    use opentide_schema::generate::catalog::catalog_texts;
    let sources = bundled_sources()?;
    let mut out = Vec::new();
    for (name, text) in catalog_texts(version, &sources) {
        out.push((format!("{COMMITTED_CATALOGS}/{name}"), text));
    }
    let identifiers = identifiers_for_families(&CORE_OBJECT_TYPES);
    out.push((
        ENGINE_ROUTER.to_owned(),
        opentide_schema::generate::catalog::dump(&engine_router(&identifiers, version)),
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

/// *text* without the line that names the version it was generated by.
fn without_label(path: &str, text: &str) -> String {
    let json = std::path::Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if !json {
        return text.to_owned();
    }
    text.lines()
        .filter(|line| !line.contains("Generated from opentide "))
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

/// Of the file names in the editor's templates folder, each the language
/// server does not compile in (#814).
fn stale_editor_templates(names: &[String]) -> Vec<String> {
    let mut stale: Vec<String> = names
        .iter()
        .filter(|name| !EDITOR_TEMPLATE_NAMES.contains(&name.as_str()))
        .map(|name| format!("{EDITOR_TEMPLATES}/{name}: no snippet reads it; remove it"))
        .collect();
    stale.sort();
    stale
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

/// The committed language-server catalogs' drift from what the Rust
/// generator writes for the bundled configuration, labels aside: the files
/// that match and the problems.
fn catalog_drift(root: &Path) -> Result<(usize, Vec<String>)> {
    use opentide_schema::generate::catalog::catalog_texts;
    let mut drift = Vec::new();
    let mut compared = 0;
    let sources = bundled_sources()?;
    for (name, text) in catalog_texts("", &sources) {
        let path = format!("{COMMITTED_CATALOGS}/{name}");
        match std::fs::read_to_string(root.join(&path)) {
            Ok(current) if unlabelled(&path, &current)? == unlabelled(&path, &text)? => {
                compared += 1;
            }
            Ok(_) => drift.push(format!("{path}: differs from what the model generates")),
            Err(_) => drift.push(format!("{path}: missing")),
        }
    }
    Ok((compared, drift))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{self, Instances};
    use opentide_schema::generate::configuration::{configuration_schema_name, configuration_schemas};

    #[test]
    fn an_extra_committed_template_is_stale() {
        let artifacts = committed_artifacts().unwrap();
        let mut names: Vec<String> = artifacts
            .iter()
            .filter(|(path, _)| path.starts_with(PLATFORM_TEMPLATES))
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

    /// #814: the editor's snippets are the three generated templates; any
    /// other file in their folder is stale.
    #[test]
    fn the_editor_templates_are_generated_and_an_extra_one_is_stale() {
        let artifacts = committed_artifacts().unwrap();
        let mut names: Vec<String> = artifacts
            .iter()
            .filter_map(|(path, _)| path.strip_prefix(&format!("{EDITOR_TEMPLATES}/")))
            .map(str::to_owned)
            .collect();
        assert_eq!(names, EDITOR_TEMPLATE_NAMES);
        assert!(stale_editor_templates(&names).is_empty());
        names.push("rule.1.1.template.yaml".to_owned());
        assert_eq!(
            stale_editor_templates(&names),
            [format!(
                "{EDITOR_TEMPLATES}/rule.1.1.template.yaml: no snippet reads it; remove it"
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
        // The marker is only a label in JSON.
        let text = "a\nGenerated from opentide x";
        assert_eq!(without_label("notes.md", text), text);
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
            ]
        );
        let text = |path: &str| &artifacts.iter().find(|(p, _)| p == path).unwrap().1;
        assert!(text(ENGINE_ROUTER).contains("Generated from opentide 9.9.9."));
    }

    /// An empty repository layout with the folders `codegen` writes into.
    fn scratch_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in [
            PLATFORM_TEMPLATES,
            EDITOR_TEMPLATES,
            EDITOR_SCHEMAS,
            COMMITTED_CATALOGS,
            "docs/cli",
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

        // A changed router is; a missing one is reported as missing. The
        // language server's catalogs are catalog_parity's to compare.
        std::fs::write(&router, text.replace("rule.1.1", "rule.9.9")).unwrap();
        std::fs::write(root.join(COMMITTED_CATALOGS).join("fields.json"), "{}").unwrap();
        assert_eq!(
            engine_catalog(root, true).unwrap(),
            [format!(
                "{ENGINE_ROUTER}: differs from what the model generates"
            )]
        );
        std::fs::remove_file(&router).unwrap();
        assert_eq!(
            engine_catalog(root, true).unwrap(),
            [format!("{ENGINE_ROUTER}: missing")]
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
        // A page edited by hand, or not regenerated after a page changed.
        let reference = root.join(DIAGNOSTICS_REFERENCE);
        let text = std::fs::read_to_string(&reference).unwrap();
        assert!(text.contains("&lt;=>"), "the reference is not MDX-safe");
        std::fs::write(&reference, text.replace("&lt;=>", "<=>")).unwrap();
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
                format!("{DIAGNOSTICS_REFERENCE}: differs from what the model generates"),
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
            .envs([
                ("GIT_CONFIG_COUNT", "2"),
                ("GIT_CONFIG_KEY_0", "maintenance.auto"),
                ("GIT_CONFIG_VALUE_0", "false"),
                ("GIT_CONFIG_KEY_1", "gc.auto"),
                ("GIT_CONFIG_VALUE_1", "0"),
            ])
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
    fn codegen_help_succeeds_and_an_unknown_option_is_a_usage_error() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            args: CodegenArgs,
        }
        let help = Cli::try_parse_from(["codegen", "--help"]).err().unwrap();
        assert_eq!(help.exit_code(), 0);
        let error = Cli::try_parse_from(["codegen", "--write"]).err().unwrap();
        assert_eq!(error.exit_code(), 2);
    }
}
