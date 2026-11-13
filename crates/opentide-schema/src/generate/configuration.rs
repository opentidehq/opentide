//! The JSON Schema of each configuration TOML file and the router keyed by
//! file name (`configuration_schemas.py`; UC-1.8b, #900), from the
//! configuration models' derived [`JsonSchema`] (schemars), never from a
//! hand-written schema.
//!
//! Each schema is the model's schemars schema (draft 2020-12) with every
//! `tide.*` keyword stripped ([`super::schema::StripFrameworkKeywords`]) and
//! its `title` set to the router key it serves. The router maps a path under
//! `.opentide/configurations/` to its schema file, since a TOML file is
//! routed by its name rather than by a key inside it.
//!
//! The documents accept and refuse what the oracle's do (`cargo xtask
//! codegen --check` validates every configuration file of the corpora
//! against both); their text differs as `tests/golden/APPROVED_DIFFS.toml`
//! records (`configuration-schema-text`).

use schemars::generate::SchemaSettings;
use schemars::transform::Transform;
use schemars::{JsonSchema, Schema};
use serde_json::{Map, Value, json};

use crate::configuration::checks::{FILE_MODELS, GENERIC_PLATFORM_FILE};
use crate::configuration::models::{
    BitdefenderConfiguration, CarbonBlackCloudConfiguration, CrowdstrikeConfiguration,
    DefenderForEndpointConfiguration, DeploymentConfiguration, DocumentationConfiguration,
    ElasticConfiguration, GoogleSecopsConfiguration, GraylogConfiguration, HarfangLabConfiguration,
    PLATFORMS, PathsConfiguration, PlatformConfiguration, SentinelConfiguration,
    SentinelOneConfiguration, SharingConfiguration, SplunkConfiguration, SysdigConfiguration,
    VisibilityConfig,
};

use super::schema::StripFrameworkKeywords;

/// The dialect every configuration schema declares.
pub const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The router's file name.
pub const ROUTER_NAME: &str = "configurations.router.json";

/// The router's title.
pub const ROUTER_TITLE: &str = "opentide Configuration Router";

/// The schema identifier `visibility.toml` declares (`visibility::1.0`).
pub const VISIBILITY_SCHEMA_ID: &str = "visibility::1.0";

/// The MISP connector's schema identifier (`MISP_SCHEMA_ID`).
pub const MISP_SCHEMA_ID: &str = "sharing::misp::1.0";

/// Every router key with a model, in the oracle's order
/// (`configuration_files`): the files with a model of their own, each
/// platform's file, then the generic platform file.
pub fn file_keys() -> Vec<String> {
    let mut keys: Vec<String> = FILE_MODELS.iter().map(|&key| key.to_owned()).collect();
    keys.extend(PLATFORMS.iter().map(|id| format!("platforms/{id}.toml")));
    keys.push(GENERIC_PLATFORM_FILE.to_owned());
    keys
}

/// The schema file name of a router key: `platforms/sentinel.toml` is
/// written as `platforms.sentinel.schema.json`, the generic platform file as
/// `platforms.schema.json`.
pub fn configuration_schema_name(file_key: &str) -> String {
    if file_key == GENERIC_PLATFORM_FILE {
        return "platforms.schema.json".to_owned();
    }
    let stem = file_key.strip_suffix(".toml").unwrap_or(file_key);
    format!("{}.schema.json", stem.replace('/', "."))
}

/// The schemars schema of `T`, draft 2020-12.
pub fn model_schema<T: JsonSchema>() -> Schema {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
}

/// The derived schema of the model behind `file_key`, or `None` for a key
/// that names none.
fn raw(file_key: &str) -> Option<Schema> {
    Some(match file_key {
        "paths.toml" => model_schema::<PathsConfiguration>(),
        "deployment.toml" => model_schema::<DeploymentConfiguration>(),
        "visibility.toml" => model_schema::<VisibilityConfig>(),
        "documentation.toml" => model_schema::<DocumentationConfiguration>(),
        "sharing.toml" => model_schema::<SharingConfiguration>(),
        "platforms/sentinel.toml" => model_schema::<SentinelConfiguration>(),
        "platforms/splunk.toml" => model_schema::<SplunkConfiguration>(),
        "platforms/carbon_black_cloud.toml" => model_schema::<CarbonBlackCloudConfiguration>(),
        "platforms/sentinel_one.toml" => model_schema::<SentinelOneConfiguration>(),
        "platforms/defender_for_endpoint.toml" => {
            model_schema::<DefenderForEndpointConfiguration>()
        }
        "platforms/crowdstrike.toml" => model_schema::<CrowdstrikeConfiguration>(),
        "platforms/harfanglab.toml" => model_schema::<HarfangLabConfiguration>(),
        "platforms/elastic.toml" => model_schema::<ElasticConfiguration>(),
        "platforms/sysdig.toml" => model_schema::<SysdigConfiguration>(),
        "platforms/bitdefender.toml" => model_schema::<BitdefenderConfiguration>(),
        "platforms/google_secops.toml" => model_schema::<GoogleSecopsConfiguration>(),
        "platforms/graylog.toml" => model_schema::<GraylogConfiguration>(),
        GENERIC_PLATFORM_FILE => model_schema::<PlatformConfiguration>(),
        _ => return None,
    })
}

/// The JSON Schema of one configuration file (`generate_configuration_schema`),
/// or `None` for a key that names no model.
pub fn configuration_schema(file_key: &str) -> Option<Value> {
    let mut schema = raw(file_key)?;
    StripFrameworkKeywords.transform(&mut schema);
    let title = if file_key == GENERIC_PLATFORM_FILE {
        "platforms/<id>.toml"
    } else {
        file_key
    };
    schema.insert("$schema".to_owned(), JSON_SCHEMA_DIALECT.into());
    schema.insert("title".to_owned(), title.into());
    Some(schema.to_value())
}

fn router_entry(file_key: &str) -> Value {
    let mut entry = Map::new();
    entry.insert(
        "schema".to_owned(),
        configuration_schema_name(file_key).into(),
    );
    let sharing = file_key == "sharing.toml";
    entry.insert(
        "merge".to_owned(),
        if sharing { "by-name" } else { "deep" }.into(),
    );
    if file_key == "visibility.toml" {
        entry.insert("schema_id".to_owned(), VISIBILITY_SCHEMA_ID.into());
    }
    if sharing {
        entry.insert("connectors".to_owned(), json!({"misp": MISP_SCHEMA_ID}));
    }
    Value::Object(entry)
}

/// The router: each configuration file name mapped to its schema file
/// (`build_configuration_router`).
pub fn configuration_router() -> Value {
    let files: Map<String, Value> = file_keys()
        .into_iter()
        .map(|key| {
            let entry = router_entry(&key);
            (key, entry)
        })
        .collect();
    json!({
        "title": ROUTER_TITLE,
        "description": "Maps a file under .opentide/configurations/ to the JSON Schema that \
            validates it. A file is a partial override: required keys apply to the merge of the \
            bundled file, the workspace file and the parent instance. platforms/*.toml matches \
            a platform file without a dedicated entry.",
        "files": files,
    })
}

/// Every configuration schema and the router, by output file name, in the
/// oracle's order (`generate_configuration_schemas`).
pub fn configuration_schemas() -> Vec<(String, Value)> {
    let mut documents: Vec<(String, Value)> = Vec::new();
    for key in file_keys() {
        let name = configuration_schema_name(&key);
        if documents.iter().any(|(known, _)| *known == name) {
            continue;
        }
        if let Some(schema) = configuration_schema(&key) {
            documents.push((name, schema));
        }
    }
    documents.push((ROUTER_NAME.to_owned(), configuration_router()));
    documents
}

/// A configuration document's text: two-space indentation and a final
/// newline (`render_schema`). Keys are in `serde_json`'s order.
pub fn render(document: &Value) -> String {
    let mut text = serde_json::to_string_pretty(document).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_router_key_has_a_schema_and_a_file_name() {
        let keys = file_keys();
        assert_eq!(keys.len(), FILE_MODELS.len() + PLATFORMS.len() + 1);
        for key in &keys {
            let schema = configuration_schema(key).unwrap();
            assert_eq!(schema["$schema"], JSON_SCHEMA_DIALECT, "{key}");
            assert!(schema["title"].is_string(), "{key}");
        }
        assert_eq!(
            configuration_schema_name("platforms/sentinel.toml"),
            "platforms.sentinel.schema.json"
        );
        assert_eq!(
            configuration_schema_name(GENERIC_PLATFORM_FILE),
            "platforms.schema.json"
        );
        assert_eq!(
            configuration_schema(GENERIC_PLATFORM_FILE).unwrap()["title"],
            "platforms/<id>.toml"
        );
        assert!(configuration_schema("lint.toml").is_none());
    }

    #[test]
    fn the_router_names_each_file_its_schema_and_merge() {
        let router = configuration_router();
        let files = router["files"].as_object().unwrap();
        assert_eq!(files.len(), FILE_MODELS.len() + PLATFORMS.len() + 1);
        assert_eq!(files["sharing.toml"]["merge"], "by-name");
        assert_eq!(files["sharing.toml"]["connectors"]["misp"], MISP_SCHEMA_ID);
        assert_eq!(files["visibility.toml"]["schema_id"], VISIBILITY_SCHEMA_ID);
        assert_eq!(files["deployment.toml"]["merge"], "deep");
        assert!(files["deployment.toml"].get("schema_id").is_none());
        assert_eq!(files["platforms/*.toml"]["schema"], "platforms.schema.json");
        let names: Vec<String> = configuration_schemas()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names.len(), FILE_MODELS.len() + PLATFORMS.len() + 2);
        assert_eq!(names.last().map(String::as_str), Some(ROUTER_NAME));
    }

    #[test]
    fn closed_models_are_closed_and_constraints_are_kept() {
        let deployment = configuration_schema("deployment.toml").unwrap();
        assert_eq!(deployment["additionalProperties"], false);
        let text = serde_json::to_string(&deployment).unwrap();
        assert!(text.contains("\"minItems\":1"), "{text}");
        assert!(!text.contains("tide."), "{text}");
    }
}
