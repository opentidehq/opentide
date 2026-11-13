//! `cargo xtask spec-fields [--specifications DIR]`: every model field's
//! description agrees with its row in the field tables of
//! `opentidehq/specifications`.
//!
//! The descriptions are the hovers editors show (the language server's
//! catalog and the generated schemas read them from the models), so they are
//! held to the specification's text. The Python check
//! (`tests/test_models/test_spec_field_descriptions.py`) read the Pydantic
//! docstrings; this one reads the Rust models' JSON Schemas
//! (`opentide_schema::generate::schema::revision_model_schema`): each
//! object revision's root and every model under `$defs` it reaches (the
//! platform blocks through `configurations`), by the Pydantic name the schema
//! keeps (`DetectionRule`, `SentinelAlert`).
//!
//! A spec table describes a model when it is the first table under a
//! `### `field` (ClassName)` heading and has a `Description` column; its
//! rows are `` | `key` | ... | description | ``. A row's text and the
//! property's `description` are compared after dropping Markdown link
//! targets, unescaping `\|`, collapsing white space and a final full stop.
//! `PlatformConfigBase` is not a model of its own here: its fields open every
//! platform block (`platform_block!`), so its rows are checked against each
//! block. Rows for a model or key the Rust schema does not have are not
//! counted; fewer than [`MIN_CHECKED`] counted rows fails, so a spec layout
//! change cannot pass for "no drift".
//!
//! Exit status: 0 no drift, 1 drift or too few rows, 2 no specifications
//! checkout (the check never passes by not running).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::Value;

/// The usage.
pub const USAGE: &str = "\
usage: cargo xtask spec-fields [--specifications DIR] [--list]

Checks every model field's description against its row in the field tables of
the specifications checkout (DIR, else $OPENTIDE_SPECIFICATIONS_ROOT, else
../specifications): specs/platforms/*.md, specs/objects/*-1.0.md and
specs/metadata.md. --list prints each row it matched with a model field.

exit status: 0 no drift, 1 drift (or fewer rows matched than the floor),
2 usage error or no checkout
";

/// The spec pages whose tables describe the models, under `specs/`.
pub const SPEC_FILES: [&str; 3] = ["platforms/*.md", "objects/*-1.0.md", "metadata.md"];

/// The object revisions whose models (and every model they reach) are
/// checked.
pub const REVISIONS: [&str; 4] = ["rule::1.0", "rule::1.1", "threat::1.0", "objective::1.0"];

/// The fewest rows that must match a model field.
pub const MIN_CHECKED: usize = 100;

/// Rows rewritten on purpose, by model and serialised key: the spec row
/// points at another spec page, or says what the spec says rather than what
/// the model enforces. The Python check's list, with the serialised names
/// (`schema` for `schema_id` and `platform_schema`).
pub const REWRITTEN: [(&str, &str); 16] = [
    ("DetectionObjective", "metadata"),
    ("DetectionRule", "metadata"),
    // The spec calls these the rule's lifecycle status and severity; deploy
    // and promotion read each platform block's status and
    // response.alert_severity.
    ("DetectionRule", "severity"),
    ("DetectionRule", "status"),
    ("ElasticActions", "respond"),
    ("ElasticRisk", "score"),
    ("ElasticThreatMatch", "filters"),
    ("ObjectiveBody", "signals"),
    ("ObjectMetadata", "schema"),
    ("PlatformConfigBase", "schema"),
    ("PlatformConfigBase", "status"),
    ("RuleResponse", "responders"),
    ("SentinelOneCondition", "cool_off"),
    ("SignalData", "logsources"),
    ("ThreatBody", "actors"),
    ("ThreatVector", "metadata"),
];

/// The spec name of the fields every platform block opens with.
pub const PLATFORM_BASE: &str = "PlatformConfigBase";

/// One row of a spec table: the model it describes, the key, the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The model (`SentinelAlert`).
    pub model: String,
    /// The serialised key (`create_incident`).
    pub key: String,
    /// The description cell as written.
    pub description: String,
    /// Where it is: `platforms/sentinel-1.0.md`.
    pub source: String,
}

fn heading() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        Regex::new(r"^#{2,4} .*\((\w+)\)\s*$").expect("the heading pattern compiles")
    })
}

fn row() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        Regex::new(r"^\|\s*`(\w+)`\s*\|").expect("the row pattern compiles")
    })
}

fn link() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        Regex::new(r"\[([^\]]+)\]\([^)]*\)").expect("the link pattern compiles")
    })
}

/// The last cell of a table row: the text after the last `|` that is not
/// escaped, once the row's outer pipes are dropped.
fn last_cell(line: &str) -> &str {
    let inner = line.trim().trim_matches('|');
    let bytes = inner.as_bytes();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'|' && (index == 0 || bytes[index - 1] != b'\\') {
            start = index + 1;
        }
    }
    &inner[start..]
}

/// The rows of one spec page that describe a model.
pub fn rows(text: &str, source: &str) -> Vec<Row> {
    let mut found = Vec::new();
    let mut model: Option<String> = None;
    let mut in_table = false;
    for line in text.lines() {
        if line.starts_with('#') {
            model = heading()
                .captures(line)
                .and_then(|captures| captures.get(1))
                .map(|m| m.as_str().to_owned());
        } else if line.starts_with('|') {
            // Only the first table under a heading describes its model; a
            // table without a description column describes none.
            if !in_table && !line.trim_end().ends_with("Description |") {
                model = None;
            }
            in_table = true;
            if let Some(name) = &model
                && let Some(captures) = row().captures(line)
                && let Some(key) = captures.get(1)
            {
                found.push(Row {
                    model: name.clone(),
                    key: key.as_str().to_owned(),
                    description: last_cell(line).to_owned(),
                    source: source.to_owned(),
                });
            }
        } else if in_table {
            in_table = false;
            model = None;
        }
    }
    found
}

/// A description as compared: link targets dropped, `\|` unescaped, white
/// space collapsed, no final full stop.
pub fn normalise(text: &str) -> String {
    let text = link().replace_all(text, "$1").replace("\\|", "|");
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim_end_matches('.').to_owned()
}

/// Every model the revisions reach, by name, each with its properties'
/// descriptions (`None` for a property without one). A name met in two
/// revisions with different properties keeps both.
pub type Models = BTreeMap<String, Vec<BTreeMap<String, Option<String>>>>;

fn properties_of(schema: &Value) -> Option<BTreeMap<String, Option<String>>> {
    let properties = schema.get("properties")?.as_object()?;
    Some(
        properties
            .iter()
            .map(|(key, property)| {
                (
                    key.clone(),
                    property
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            })
            .collect(),
    )
}

fn add(models: &mut Models, name: &str, schema: &Value) {
    if let Some(properties) = properties_of(schema) {
        let entry = models.entry(name.to_owned()).or_default();
        if !entry.contains(&properties) {
            entry.push(properties);
        }
    }
}

/// The models of `schemas`, each a revision's model schema.
pub fn models_of(schemas: &[Value]) -> Models {
    let mut models = Models::new();
    for schema in schemas {
        if let Some(title) = schema.get("title").and_then(Value::as_str) {
            add(&mut models, title, schema);
        }
        if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
            for (name, def) in defs {
                add(&mut models, name, def);
            }
        }
    }
    models
}

/// The models of [`REVISIONS`].
pub fn models() -> Result<Models> {
    let mut schemas = Vec::new();
    for identifier in REVISIONS {
        let schema = opentide_schema::generate::schema::revision_model_schema(identifier)
            .with_context(|| format!("no model schema for {identifier}"))?;
        schemas.push(schema.as_value().clone());
    }
    Ok(models_of(&schemas))
}

/// The platform blocks: the models whose properties open with every one of
/// `PlatformConfigBase`'s fields, found as the models named `*Config` that
/// have a `schema` and a `status`.
fn platform_blocks(models: &Models) -> Vec<&str> {
    models
        .iter()
        .filter(|(name, variants)| {
            name.ends_with("Config")
                && variants.iter().any(|properties| {
                    properties.contains_key("schema") && properties.contains_key("status")
                })
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// What the check found.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Rows that matched a model field.
    pub checked: usize,
    /// Each matched row: `Model key`.
    pub rows: Vec<String>,
    /// Each difference: `Model.key (source): spec "…" != model "…"`.
    pub drift: Vec<String>,
}

/// Holds `rows` to `models`.
pub fn check(rows: &[Row], models: &Models) -> Outcome {
    let rewritten: BTreeSet<(&str, &str)> = REWRITTEN.iter().copied().collect();
    let blocks = platform_blocks(models);
    let mut outcome = Outcome::default();
    for row in rows {
        if rewritten.contains(&(row.model.as_str(), row.key.as_str())) {
            continue;
        }
        let names: Vec<&str> = if row.model == PLATFORM_BASE {
            blocks.clone()
        } else {
            vec![row.model.as_str()]
        };
        let mut matched = false;
        let expected = normalise(&row.description);
        for name in names {
            for properties in models.get(name).into_iter().flatten() {
                let Some(description) = properties.get(&row.key) else {
                    continue;
                };
                matched = true;
                let actual = description.as_deref().unwrap_or("");
                if normalise(actual) != expected {
                    outcome.drift.push(format!(
                        "{name}.{} ({}): spec {:?} != model {actual:?}",
                        row.key, row.source, row.description
                    ));
                }
            }
        }
        if matched {
            outcome.checked += 1;
            outcome.rows.push(format!("{} {}", row.model, row.key));
        }
    }
    outcome.drift.dedup();
    outcome
}

/// Expands `SPEC_FILES` under `specs`, each pattern's files sorted.
fn spec_files(specs: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for pattern in SPEC_FILES {
        let full = specs.join(pattern);
        let mut matched: Vec<PathBuf> = glob::glob(&full.to_string_lossy())
            .with_context(|| format!("the pattern {pattern}"))?
            .collect::<Result<_, _>>()?;
        matched.sort();
        files.extend(matched);
    }
    Ok(files)
}

/// Runs the check against the checkout at `specifications`. Whether it
/// passed; an error when there is no checkout.
pub fn run(specifications: &Path, list: bool, out: &mut String) -> Result<bool> {
    let specs = specifications.join("specs");
    if !specs.is_dir() {
        bail!(
            "no specifications checkout at {} (set $OPENTIDE_SPECIFICATIONS_ROOT or pass --specifications)",
            specifications.display()
        );
    }
    let mut all = Vec::new();
    for path in spec_files(&specs)? {
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let source = path
            .strip_prefix(&specs)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        all.extend(rows(&text, &source));
    }
    let outcome = check(&all, &models()?);
    if list {
        for row in &outcome.rows {
            out.push_str(&format!("row: {row}\n"));
        }
    }
    for drift in &outcome.drift {
        out.push_str(&format!("drift: {drift}\n"));
    }
    if outcome.checked < MIN_CHECKED {
        out.push_str(&format!(
            "error: only {} spec rows matched a model field (at least {MIN_CHECKED} expected): \
             has the specifications' table layout changed?\n",
            outcome.checked
        ));
        return Ok(false);
    }
    if outcome.drift.is_empty() {
        out.push_str(&format!(
            "{} spec rows match their model field descriptions\n",
            outcome.checked
        ));
        return Ok(true);
    }
    out.push_str(&format!(
        "error: {} of {} spec rows differ from the model's description; change the model's doc \
         (crates/opentide-schema/src/objects/) or the spec, or list a deliberate rewrite in \
         xtask/src/spec_fields.rs (REWRITTEN)\n",
        outcome.drift.len(),
        outcome.checked
    ));
    Ok(false)
}

/// `cargo xtask spec-fields ARGS`.
pub fn main(args: &[String]) -> ExitCode {
    let mut specifications = None;
    let mut list = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--specifications" => match args.next() {
                Some(dir) => specifications = Some(PathBuf::from(dir)),
                None => {
                    eprint!("xtask spec-fields: --specifications needs a directory\n\n{USAGE}");
                    return ExitCode::from(2);
                }
            },
            "--list" => list = true,
            "help" | "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprint!("xtask spec-fields: unknown option `{other}`\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let specifications = specifications
        .or_else(|| std::env::var_os(crate::vocab::sync::SPECIFICATIONS_ENV).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("../specifications"));
    let mut out = String::new();
    let result = run(&specifications, list, &mut out);
    print!("{out}");
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xtask spec-fields: {error:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PAGE: &str = "\
# Sentinel

### `alert` (SentinelAlert)

| Key | Type | Description |
|-----|------|-------------|
| `title` | string | The alert's [title](https://example.test/t). |
| `severity` | string | One of `High` \\| `Low` |
| not a key | x | ignored |

| Key | Description |
|-----|-------------|
| `nested` | A second table under the heading describes another object |

### `other` (SentinelOther)

| Key | Type |
|-----|------|
| `x` | no description column |

## `base` (PlatformConfigBase)

| Key | Description |
|-----|-------------|
| `description` | What the block does |
";

    #[test]
    fn rows_are_the_first_described_table_under_a_model_heading() {
        let found = rows(PAGE, "platforms/sentinel-1.0.md");
        let keys: Vec<_> = found
            .iter()
            .map(|r| (r.model.as_str(), r.key.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                ("SentinelAlert", "title"),
                ("SentinelAlert", "severity"),
                ("PlatformConfigBase", "description")
            ]
        );
        assert_eq!(found[1].description, " One of `High` \\| `Low` ");
    }

    #[test]
    fn descriptions_are_compared_without_links_escapes_spacing_or_a_final_stop() {
        assert_eq!(
            normalise(" The alert's [title](https://example.test/t).  "),
            "The alert's title"
        );
        assert_eq!(
            normalise("One of `High` \\| `Low`"),
            "One of `High` | `Low`"
        );
        assert_eq!(normalise("a\n  b..."), "a b");
    }

    fn models_fixture(title: &str) -> Models {
        models_of(&[json!({
            "title": "DetectionRule",
            "properties": {"name": {"description": "The rule's name."}},
            "$defs": {
                "SentinelAlert": {"properties": {
                    "title": {"description": "The alert's title"},
                    "severity": {"description": "One of `High` | `Low`."}
                }},
                "SentinelConfig": {"properties": {
                    "schema": {}, "status": {}, "description": {"description": "What the block does"}
                }},
                "SplunkConfig": {"properties": {
                    "schema": {}, "status": {}, "description": {"description": title}
                }},
                "Severity": {"enum": ["a"]}
            }
        })])
    }

    #[test]
    fn matching_rows_pass_and_the_base_rows_hold_every_platform_block() {
        let found = rows(PAGE, "platforms/sentinel-1.0.md");
        let outcome = check(&found, &models_fixture("What the block does."));
        assert_eq!(outcome.checked, 3);
        assert!(outcome.drift.is_empty(), "{:?}", outcome.drift);

        let outcome = check(&found, &models_fixture("Something else"));
        assert_eq!(outcome.drift.len(), 1, "{:?}", outcome.drift);
        assert!(outcome.drift[0].starts_with("SplunkConfig.description"));
    }

    #[test]
    fn rewritten_rows_and_unknown_models_are_not_counted() {
        let rows = [
            Row {
                model: "DetectionRule".into(),
                key: "status".into(),
                description: "anything".into(),
                source: "s".into(),
            },
            Row {
                model: "Unknown".into(),
                key: "x".into(),
                description: "y".into(),
                source: "s".into(),
            },
            Row {
                model: "DetectionRule".into(),
                key: "missing".into(),
                description: "y".into(),
                source: "s".into(),
            },
        ];
        let outcome = check(&rows, &models_fixture(""));
        assert_eq!(outcome.checked, 0);
        assert!(outcome.drift.is_empty());
    }

    #[test]
    fn no_checkout_is_an_error_and_a_sparse_one_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut out = String::new();
        assert!(run(&dir.path().join("absent"), false, &mut out).is_err());
        fs::create_dir_all(dir.path().join("specs/platforms")).unwrap();
        fs::write(dir.path().join("specs/platforms/sentinel-1.0.md"), PAGE).unwrap();
        assert!(!run(dir.path(), true, &mut out).unwrap());
        // The page's rows name real models whose descriptions differ: drift,
        // and too few rows for the floor.
        assert!(out.contains("row: SentinelAlert title\n"), "{out}");
        assert!(
            out.contains("drift: SentinelAlert.title (platforms/sentinel-1.0.md)"),
            "{out}"
        );
        assert!(out.contains("only 2 spec rows matched"), "{out}");
    }

    #[test]
    fn the_rust_models_name_every_spec_model_they_hold() {
        let models = models().unwrap();
        for name in [
            "DetectionRule",
            "DetectionRule_v1_1",
            "ThreatVector",
            "DetectionObjective",
            "ObjectMetadata",
            "SentinelAlert",
            "ElasticActions",
            "SysdigMacro",
        ] {
            assert!(
                models.contains_key(name),
                "{name}: {:?}",
                models.keys().collect::<Vec<_>>()
            );
        }
        assert!(
            platform_blocks(&models).len() >= 9,
            "{:?}",
            platform_blocks(&models)
        );
    }
}
