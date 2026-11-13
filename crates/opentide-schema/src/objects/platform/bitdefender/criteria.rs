//! The GravityZone criteria catalogue (bitdefender-1.0, Criteria catalogue):
//! `data/catalogs/bitdefender/criteria.toml`, the one data source for the
//! fields, enum values, relations, sensors and pairing rules of a Basic rule.
//! The model's checks read it here, and the editor's criteria completion and
//! hover read the same file, so `opentide validate` and the editor check a
//! block alike. The catalogue is facts read from Bitdefender's "Detection and
//! exclusion criteria for Basic rules"; see the `NOTICE` beside it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

/// The catalogue as the TOML file holds it.
#[derive(Debug, Clone, Deserialize)]
pub struct Criteria {
    /// The page the facts were read from.
    pub source: String,
    /// When it was read.
    pub fetched: String,
    /// Full registry hive names and the short names GravityZone matches.
    #[serde(default)]
    pub registry_hives: BTreeMap<String, String>,
    /// The alert criterion (`detection` in `criteriaList`, `alert` in the block).
    pub alert: AlertRow,
    /// Rules over a whole criteria list.
    #[serde(default)]
    pub rules: Vec<RuleRow>,
    /// The targets, in the page's order.
    pub targets: Vec<TargetRow>,
    /// The fields, in the page's order.
    pub fields: Vec<FieldRow>,
}

/// The alert criterion.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertRow {
    /// Its API field (`detection`).
    pub field: String,
    /// Its Control Center label.
    pub label: String,
    /// The sensor that evaluates it.
    pub availability: String,
    /// The relations it takes.
    pub relations: Vec<String>,
}

/// A rule over a whole criteria list.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleRow {
    /// `no_sensor_mix`, `one_resource`, or `alert_or_operation`.
    pub kind: String,
    /// The target it applies to; every target when absent.
    pub target: Option<String>,
    /// The operation field it is about; any `*.Operation` field when absent.
    pub field: Option<String>,
    /// `xdr` (rules an XDR sensor evaluates) or `all`.
    pub scope: Option<String>,
    /// Whether the rule needs one of `alert` and the operation, or only refuses both.
    pub require: Option<bool>,
    /// `one_resource`: the targets it applies to.
    #[serde(default)]
    pub targets: Vec<String>,
}

/// A target.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetRow {
    /// Its API name (`process`, `user connection`).
    pub name: String,
    /// Whether a detection rule may use it.
    pub detection: bool,
    /// Whether an exclusion rule may use it.
    pub exclusion: bool,
    /// bitdefender-1.0 states its field list: an unknown field is an error.
    pub closed: bool,
}

/// A field of a target.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldRow {
    /// Its API name (`Process.CommandLine`).
    pub name: String,
    /// Its target.
    pub target: String,
    /// Its Control Center label.
    pub label: String,
    /// The sensor that evaluates it in a detection rule: `edr`, `xdr` or `both`.
    pub availability: String,
    /// The sensor in an exclusion rule, when it differs.
    pub exclusion_availability: Option<String>,
    /// Whether a detection rule may use it.
    pub detection: bool,
    /// Whether an exclusion rule may use it.
    pub exclusion: bool,
    /// The relations it takes.
    pub relations: Vec<String>,
    /// `string`, `hash`, `ip`, `email`, `port`, or `enum`.
    pub kind: String,
    /// A port's lowest value.
    pub minimum: Option<i64>,
    /// A port's highest value.
    pub maximum: Option<i64>,
    /// The XDR resource the field is about (one per connection rule).
    pub resource: Option<String>,
    /// One of these must also be a criterion of the rule.
    #[serde(default)]
    pub requires_any: Vec<String>,
    /// The same, in a detection rule, where `detection` is the block's `alert`.
    #[serde(default)]
    pub detection_requires_any: Vec<String>,
    /// Fields that may not be criteria of the same rule.
    #[serde(default)]
    pub incompatible: Vec<String>,
    /// An enum's values.
    #[serde(default)]
    pub values: Vec<ValueRow>,
}

/// An enum value of a field.
#[derive(Debug, Clone, Deserialize)]
pub struct ValueRow {
    /// The value.
    pub name: String,
    /// The sensor that evaluates it; the field's when absent.
    pub availability: Option<String>,
    /// Fields that may not be criteria of a rule using that value.
    #[serde(default)]
    pub incompatible: Vec<String>,
}

impl Criteria {
    /// The target called `name`.
    pub fn target(&self, name: &str) -> Option<&TargetRow> {
        self.targets.iter().find(|target| target.name == name)
    }

    /// The detection field called `name` (the checks read detection fields only).
    pub fn field(&self, name: &str) -> Option<&FieldRow> {
        self.fields
            .iter()
            .filter(|field| field.detection)
            .find(|field| field.name == name)
    }

    /// The fields of `target` a detection rule can use, in page order.
    pub fn detection_fields<'a>(&'a self, target: &'a str) -> impl Iterator<Item = &'a FieldRow> {
        self.fields
            .iter()
            .filter(move |field| field.target == target && field.detection)
    }

    /// Whether a detection rule may use `target`.
    pub fn is_detection_target(&self, target: &str) -> bool {
        self.target(target).is_some_and(|row| row.detection)
    }

    /// Whether bitdefender-1.0 states `target`'s field list.
    pub fn is_closed_target(&self, target: &str) -> bool {
        self.target(target).is_some_and(|row| row.closed)
    }

    /// The targets with one XDR resource per rule (`one_resource`).
    pub fn one_resource_targets(&self) -> BTreeSet<&str> {
        self.rules
            .iter()
            .filter(|rule| rule.kind == "one_resource")
            .flat_map(|rule| rule.targets.iter().map(String::as_str))
            .collect()
    }

    /// The `alert_or_operation` rules, in the catalogue's order.
    pub fn alert_or_operation(&self) -> impl Iterator<Item = &RuleRow> {
        self.rules
            .iter()
            .filter(|rule| rule.kind == "alert_or_operation")
    }
}

impl FieldRow {
    /// The enum value called `name`.
    pub fn value(&self, name: &str) -> Option<&ValueRow> {
        self.values.iter().find(|value| value.name == name)
    }

    /// The sensor that evaluates the enum value `name`: its own, else the field's.
    pub fn value_availability<'a>(&'a self, name: &str) -> &'a str {
        self.value(name)
            .and_then(|value| value.availability.as_deref())
            .unwrap_or(&self.availability)
    }
}

/// The catalogue the crate compiles in.
pub const SOURCE: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/data/catalogs/bitdefender/criteria.toml"
));

/// The bundled catalogue, parsed once per process. The file is checked by
/// this crate's tests, so it parses; were it not to, every check would read
/// an empty catalogue rather than panic.
pub fn criteria() -> &'static Criteria {
    static CATALOG: OnceLock<Criteria> = OnceLock::new();
    CATALOG.get_or_init(|| {
        toml::from_str(SOURCE).unwrap_or_else(|_| Criteria {
            source: String::new(),
            fetched: String::new(),
            registry_hives: BTreeMap::new(),
            alert: AlertRow {
                field: "detection".to_owned(),
                label: String::new(),
                availability: "both".to_owned(),
                relations: Vec::new(),
            },
            rules: Vec::new(),
            targets: Vec::new(),
            fields: Vec::new(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_catalogue_parses() {
        let parsed: Criteria = toml::from_str(SOURCE).expect("criteria.toml parses");
        assert_eq!(parsed.alert.field, "detection");
        assert_eq!(parsed.targets.len(), 25);
        assert!(parsed.fields.len() > 250);
        let catalogue = criteria();
        assert!(catalogue.is_closed_target("process"));
        assert!(catalogue.is_detection_target("user connection"));
        assert!(!catalogue.is_closed_target("user connection"));
        assert!(!catalogue.is_detection_target("flow"));
        assert_eq!(
            catalogue.one_resource_targets(),
            BTreeSet::from(["connection", "user connection"])
        );
        assert_eq!(catalogue.alert_or_operation().count(), 20);
        assert_eq!(
            catalogue.field("Process.Name").map(|f| f.target.as_str()),
            Some("process")
        );
        assert_eq!(catalogue.detection_fields("registry").count(), 9);
        assert_eq!(catalogue.registry_hives["HKEY_LOCAL_MACHINE"], "HKLM");
    }
}
