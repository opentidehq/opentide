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
//! The JSON Schema of each revision, the configuration schemas and the
//! language server's field catalog are not generated from Rust yet (#814).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use opentide_schema::configuration::resolve::{Instance, resolve};
use opentide_schema::generate::workspace::{
    Artifact, platform_template, platform_template_name, router_artifact, snippets, templates,
};
use opentide_schema::objects::platform::PLATFORM_CONFIG_MODELS;

use crate::corpus::cli::{read_folder, repo_root};
use crate::golden::case::Spec;
use crate::golden::recording::{Recording, recorded_ids};
use crate::golden::snapshot::{ChangeKind, Kind};

/// The usage of `cargo xtask codegen`.
pub const USAGE: &str = "usage: cargo xtask codegen [--check]

  (no option)  write the committed artifacts generated from the Rust model:
               src/opentide/schemas/data/platform_templates/*.template.yaml
  --check      compare them instead of writing, and compare what `opentide
               generate` writes (templates, snippets, the router schema) with
               each golden recording of an `opentide generate` that ran
               those phases and exited 0; exit 1 on a difference
";

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
    if check {
        let (count, golden) = golden_parity(&root)?;
        compared = count;
        problems.extend(golden);
    }
    for problem in &problems {
        eprintln!("error: {problem}");
    }
    if problems.is_empty() {
        if check {
            println!(
                "codegen: the committed artifacts are current, and {compared} files of the \
                 golden recordings of `opentide generate` match byte for byte"
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
    Ok(out)
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
    Ok(problems)
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
        assert_eq!(artifacts.len(), PLATFORM_CONFIG_MODELS.len());
        assert!(
            artifacts
                .iter()
                .all(|(path, text)| path.starts_with(PLATFORM_TEMPLATES) && !text.is_empty())
        );
    }
}
