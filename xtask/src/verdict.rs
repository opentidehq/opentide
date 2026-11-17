//! JSON Schema verdicts (UC-1.8b, #900): what a schema Rust generates
//! accepts and refuses, never its text, for the documents an editor
//! validates (an object file's YAML read as YAML 1.2, a configuration file's
//! TOML, each as JSON; a file that does not parse is no instance).
//!
//! What is left of the comparison with the oracle's schemas, retired with
//! the oracle (#1142): the probes, each with the verdict the generated
//! schemas must give it, checked by codegen's tests.

use anyhow::Result;
use opentide_schema::configuration::checks::file_key;
use opentide_schema::configuration::merge::to_json;
use serde_json::Value;

/// One document validated against both schemas.
#[derive(Debug, Clone)]
pub struct Instance {
    /// Where it comes from, for messages: `<source>:<path>`.
    pub label: String,
    /// The document, as JSON.
    pub value: Value,
}

/// The documents of a corpus: object files, and configuration files by
/// their router key (`deployment.toml`, `platforms/sentinel.toml`).
#[derive(Debug, Default, Clone)]
pub struct Instances {
    /// Object files.
    pub objects: Vec<Instance>,
    /// Configuration files, each with its router key.
    pub configurations: Vec<(String, Instance)>,
}

impl Instances {
    /// The configuration files routed to `key`.
    pub fn configurations_of<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Instance> {
        self.configurations
            .iter()
            .filter(move |(known, _)| known == key)
            .map(|(_, instance)| instance)
    }

    /// Adds a file by its path relative to the workspace and its text: an
    /// object file under no dot folder, or a configuration file under
    /// `.opentide/configurations/`.
    pub fn add(&mut self, source: &str, path: &str, text: &str) {
        let label = format!("{source}:{path}");
        let path = path.replace('\\', "/");
        if let Some(relative) = path.strip_prefix(".opentide/configurations/") {
            if let (Some(key), Some(value)) = (file_key(relative), toml_instance(text)) {
                self.configurations.push((key, Instance { label, value }));
            }
            return;
        }
        let hidden = path.split('/').any(|part| part.starts_with('.'));
        let yaml = std::path::Path::new(&path)
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml");
        if yaml
            && !hidden
            && let Some(value) = yaml_instance(text)
        {
            self.objects.push(Instance { label, value });
        }
    }
}

/// A YAML document as JSON, when it parses to a mapping.
pub fn yaml_instance(text: &str) -> Option<Value> {
    let document = opentide_schema::node::load(text).ok()?;
    let root = document.root()?;
    let value = to_json(root);
    value.is_object().then_some(value)
}

/// A TOML document as JSON, when it parses.
pub fn toml_instance(text: &str) -> Option<Value> {
    let node = opentide_schema::configuration::toml::parse(text).ok()?;
    Some(to_json(&node))
}

/// Documents written for the comparison itself, each with the verdict both
/// schemas must give it (`true`: accepted). They keep every compared
/// document non-vacuous (a minimal `rule::1.0` object, which a workspace
/// whose rules reference its own objectives still accepts; a file of a
/// platform opentide has no model for) and sit on either side of each
/// hand-written constraint (`exclusiveMinimum`, `minLength`, `pattern`), so
/// a schema that moves a boundary gets a different verdict from the
/// oracle's.
pub const PROBES: [(&str, &str, bool); 12] = [
    (
        "rule-1.0-minimal.yaml",
        "name: Probe\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000aa\n  schema: rule::1.0\n  \
         version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\n\
         description: d\nresponse: null\nconfigurations: null\n",
        true,
    ),
    (
        ".opentide/configurations/platforms/plugin.toml",
        "[platform]\nenabled = true\nname = \"Plugin\"\n[[tenants]]\nname = \"prod\"\n",
        true,
    ),
    (
        ".opentide/configurations/platforms/plugin.toml",
        "[[tenants]]\nname = \"\"\n",
        false,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = 0.1\n",
        true,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = 0\n",
        false,
    ),
    (
        ".opentide/configurations/documentation.toml",
        "[cve]\ntimeout = -1.5\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        true,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"Prod\"\nurl = \"https://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
    (
        ".opentide/configurations/sharing.toml",
        "[[misp]]\nname = \"prod\"\nurl = \"ftp://misp.example\"\n\
         api_key = \"${MISP_KEY}\"\nmax_tlp = \"amber\"\n",
        false,
    ),
];

/// A compiled schema, or why it does not compile.
fn compile(schema: &Value) -> Result<jsonschema::Validator> {
    jsonschema::validator_for(schema).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Why a schema refuses an instance: the first error and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The validator's message.
    pub message: String,
    /// The JSON pointer of the refused value (`/references`).
    pub at: String,
}

/// Each instance's verdict under `schema`: `None` when it is accepted,
/// else the first reason it is refused.
pub fn verdicts<'a>(
    schema: &Value,
    instances: impl IntoIterator<Item = &'a Instance>,
) -> Result<Vec<Option<Refusal>>> {
    let validator = compile(schema)?;
    Ok(instances
        .into_iter()
        .map(|instance| {
            validator
                .iter_errors(&instance.value)
                .next()
                .map(|error| Refusal {
                    message: error.to_string(),
                    at: error.instance_path().to_string(),
                })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_routed_by_what_they_are() {
        let mut instances = Instances::default();
        instances.add("w", "objects/rules/a.yaml", "name: a\n");
        instances.add("w", "objects/rules/b.yml", "- not a mapping\n");
        instances.add("w", ".opentide/configurations/deployment.toml", "x = 1\n");
        instances.add(
            "w",
            ".opentide/configurations/platforms/sentinel.toml",
            "[platform]\n",
        );
        instances.add(
            "w",
            ".opentide/configurations/platforms/plugin.toml",
            "a = 1\n",
        );
        instances.add("w", ".opentide/configurations/lint.toml", "a = 1\n");
        instances.add("w", ".vscode/settings.yaml", "a: 1\n");
        instances.add("w", "README.md", "# x\n");
        assert_eq!(instances.objects.len(), 1);
        assert_eq!(instances.objects[0].label, "w:objects/rules/a.yaml");
        let keys: Vec<&str> = instances
            .configurations
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "deployment.toml",
                "platforms/sentinel.toml",
                "platforms/*.toml"
            ]
        );
        assert_eq!(instances.configurations_of("deployment.toml").count(), 1);
    }
}
