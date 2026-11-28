//! A tenant: its name, its HTTP settings and its credentials, read from its
//! `setup` table (`configurations/platforms/<platform>.toml`).
//!
//! Each tenant is read on its own, so two tenants of one platform with
//! different `ssl` settings get different clients (#742: the first tenant's
//! settings used to apply to all).

use std::collections::BTreeMap;

use opentide_schema::platforms::{PlatformId, PlatformKey};

use crate::credentials::{self, Credential, Mode, Origin};
use crate::error::ConnectorError;
use crate::http::HttpSettings;
use crate::{Environment, Secret};

/// The words a tenant's `ssl` takes, as `SSL_TRUE_WORDS` and
/// `SSL_FALSE_WORDS` in the configuration models.
pub const SSL_TRUE_WORDS: [&str; 4] = ["true", "yes", "on", "1"];
/// See [`SSL_TRUE_WORDS`].
pub const SSL_FALSE_WORDS: [&str; 4] = ["false", "no", "off", "0"];

/// Which tenant a message or an event is about.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantLabel {
    /// The platform's identifier (`sentinel`, `elastic`).
    pub platform: String,
    /// The tenant's name.
    pub tenant: String,
}

impl TenantLabel {
    /// The label of *tenant* on *platform*.
    pub fn new(platform: impl Into<String>, tenant: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            tenant: tenant.into(),
        }
    }
}

/// One tenant, ready for a client.
#[derive(Clone, Debug)]
pub struct Tenant {
    /// Its platform and name.
    pub label: TenantLabel,
    /// Its HTTP settings.
    pub http: HttpSettings,
    /// Its setup values, resolved; secrets print as `***`.
    pub setup: BTreeMap<String, Credential>,
    /// The variables read the 0.21.0 way, to warn about once.
    pub legacy_variables: Vec<String>,
    /// The setup's lists of strings (Elastic's `index`, Sysdig's
    /// `policies`), as written: they name no credential.
    pub lists: BTreeMap<String, Vec<String>>,
    /// The setup's tables of strings (Graylog's `stream_ids`), as written,
    /// in file order: they name no credential.
    pub tables: BTreeMap<String, Vec<(String, String)>>,
}

impl Tenant {
    /// The tenant *name* of *platform* from its `setup` table.
    ///
    /// `ssl` is read as a boolean, a boolean word, or a `$NAME` whose value is one; an unset
    /// `$NAME` is refused before anything is sent. Every other string value
    /// is resolved as a credential in *mode*. *defaults* are the platform's
    /// timeout and retries: no tenant key sets them.
    pub fn from_setup(
        platform: &str,
        name: &str,
        setup: &toml::Table,
        env: &Environment,
        mode: Mode,
        defaults: &HttpSettings,
    ) -> Result<Self, ConnectorError> {
        let label = TenantLabel::new(platform, name);
        let setup_error = |message: String| ConnectorError::Setup {
            platform: platform.to_owned(),
            tenant: name.to_owned(),
            message,
        };
        // A setup key a platform removed (HarfangLab's `type`,
        // platform-harfanglab 1.6) fails the tenant before anything is
        // resolved, with the message `validate` reports at the key.
        if platform == "harfanglab"
            && let Some((key, message)) =
                opentide_schema::configuration::models::REMOVED_HARFANGLAB_KEYS
                    .iter()
                    .find(|(key, _)| setup.contains_key(*key))
        {
            return Err(setup_error(format!("{key}: {message}")));
        }
        let mut http = defaults.clone();
        if let Some(value) = setup.get("ssl") {
            http.tls.verify = ssl(value, env, mode).map_err(setup_error)?;
        }
        let mut values = BTreeMap::new();
        let mut legacy_variables = Vec::new();
        let mut lists = BTreeMap::new();
        let mut tables = BTreeMap::new();
        for (key, value) in setup {
            if key == "ssl" {
                continue;
            }
            let text = match value {
                toml::Value::Array(items) => {
                    let texts: Vec<String> = items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect();
                    lists.insert(key.clone(), texts);
                    continue;
                }
                toml::Value::Table(entries) => {
                    let texts: Vec<(String, String)> = entries
                        .iter()
                        .filter_map(|(name, item)| {
                            item.as_str().map(|text| (name.clone(), text.to_owned()))
                        })
                        .collect();
                    tables.insert(key.clone(), texts);
                    continue;
                }
                toml::Value::String(text) => text.clone(),
                toml::Value::Integer(_) | toml::Value::Float(_) | toml::Value::Boolean(_) => {
                    value.to_string()
                }
                toml::Value::Datetime(_) => continue,
            };
            let resolved = credentials::resolve(
                &text,
                env,
                mode,
                Origin {
                    platform,
                    tenant: name,
                    key,
                },
            )?;
            if let Some(variable) = resolved.legacy_variable {
                legacy_variables.push(variable);
            }
            values.insert(key.clone(), resolved.credential);
        }
        Ok(Self {
            label,
            http,
            setup: values,
            legacy_variables,
            lists,
            tables,
        })
    }

    /// A setup value's secret, or the error a command that sends reports
    /// when it is missing or a placeholder.
    pub fn secret(&self, key: &str) -> Result<&Secret, ConnectorError> {
        match self.setup.get(key) {
            Some(Credential::Value(secret)) => Ok(secret),
            Some(Credential::Placeholder { variable }) => Err(ConnectorError::MissingCredential {
                platform: self.label.platform.clone(),
                tenant: self.label.tenant.clone(),
                key: key.to_owned(),
                variable: variable.clone(),
            }),
            None => Err(ConnectorError::Setup {
                platform: self.label.platform.clone(),
                tenant: self.label.tenant.clone(),
                message: format!("{key} is missing"),
            }),
        }
    }

    /// The setup's list *key* (`index`), empty when it has none.
    pub fn list(&self, key: &str) -> &[String] {
        self.lists.get(key).map_or(&[], Vec::as_slice)
    }

    /// The setup's table *key* (`stream_ids`), empty when it has none.
    pub fn table(&self, key: &str) -> &[(String, String)] {
        self.tables.get(key).map_or(&[], Vec::as_slice)
    }

    /// Every resolved secret of this tenant, for a redactor.
    pub fn secrets(&self) -> impl Iterator<Item = &Secret> {
        self.setup.values().filter_map(Credential::secret)
    }
}

/// The tenants *config* (a workspace's resolved configuration, as
/// `opentide_compile::Json`) lists for *platform*, in file order: each one's
/// `name` and its `setup` table, ready for [`Tenant::from_setup`]. A setup
/// value with no TOML form (a null) is left out, as the loader leaves it out
/// of the strings it resolves; a table is kept for [`Tenant::tables`].
pub fn configured(config: &opentide_compile::Json, platform: &str) -> Vec<(String, toml::Table)> {
    opentide_compile::plan::tenants(config, &PlatformKey::new(platform))
        .into_iter()
        .map(|tenant| {
            let setup = tenant
                .get("setup")
                .and_then(opentide_compile::Json::as_object)
                .map(|setup| {
                    setup
                        .iter()
                        .filter_map(|(key, value)| {
                            toml_value(value).map(|value| (key.clone(), value))
                        })
                        .collect()
                })
                .unwrap_or_default();
            (
                opentide_compile::deploy::tenant_name(tenant).to_owned(),
                setup,
            )
        })
        .collect()
}

/// A setup value as `toml` holds it, for [`Tenant::from_setup`]: a table
/// (Graylog's `stream_ids`) is kept, for [`Tenant::table`]; a null, which
/// TOML cannot hold, is left out, in a table or a list too.
pub fn toml_value(value: &opentide_compile::Json) -> Option<toml::Value> {
    use opentide_compile::Json as J;
    Some(match value {
        J::Str(text) => toml::Value::String(text.clone()),
        J::Int(number) => toml::Value::Integer(*number),
        // TOML has no integer beyond i64: the nearest float, as before.
        #[expect(
            clippy::cast_precision_loss,
            reason = "only an integer beyond i64 is approximated"
        )]
        J::UInt(number) => toml::Value::Float(*number as f64),
        J::Float(number) => toml::Value::Float(*number),
        J::Bool(flag) => toml::Value::Boolean(*flag),
        J::Array(items) => toml::Value::Array(items.iter().filter_map(toml_value).collect()),
        J::Object(entries) => toml::Value::Table(
            entries
                .iter()
                .filter_map(|(key, value)| toml_value(value).map(|value| (key.clone(), value)))
                .collect(),
        ),
        J::Null => return None,
    })
}

/// A tenant's `ssl` as the verify flag.
fn ssl(value: &toml::Value, env: &Environment, mode: Mode) -> Result<bool, String> {
    let word = |text: &str| {
        let lowered = text.trim().to_lowercase();
        if SSL_TRUE_WORDS.contains(&lowered.as_str()) {
            Some(true)
        } else if SSL_FALSE_WORDS.contains(&lowered.as_str()) {
            Some(false)
        } else {
            None
        }
    };
    match value {
        toml::Value::Boolean(flag) => Ok(*flag),
        toml::Value::String(text) => {
            if let Some(variable) = opentide_workspace::info::env_reference(text) {
                return match env.raw(variable) {
                    Some(found) => word(found).ok_or_else(|| {
                        format!("ssl must be true or false, got {found:?} from {variable}")
                    }),
                    // A run that sends nothing keeps verifying.
                    None if mode == Mode::Counting => Ok(true),
                    None => Err(format!(
                        "ssl is unset ({text}). Set that environment variable to true or false."
                    )),
                };
            }
            word(text).ok_or_else(|| format!("ssl must be true or false, got {text:?}"))
        }
        other => Err(format!("ssl must be true or false, got {other}")),
    }
}

/// Microsoft Graph, which Microsoft Defender's tenants are reached through.
const GRAPH_HOST: &str = "https://graph.microsoft.com";
/// CrowdStrike's API in its default cloud (US-1).
const CROWDSTRIKE_HOST: &str = "https://api.crowdstrike.com";
/// The Log Analytics API, which Microsoft Sentinel's queries run on.
const LOG_ANALYTICS_HOST: &str = "https://api.loganalytics.io";

/// The address a transport failure is reported at for a tenant of *platform*
/// configured without a URL (`_DEFAULT_HOSTS`), or `None` for a platform
/// whose tenants name their own.
pub const fn default_host(platform: PlatformId) -> Option<&'static str> {
    match platform {
        PlatformId::MicrosoftDefender => Some(GRAPH_HOST),
        PlatformId::Crowdstrike => Some(CROWDSTRIKE_HOST),
        PlatformId::Sentinel => Some(LOG_ANALYTICS_HOST),
        PlatformId::Splunk
        | PlatformId::SentinelOne
        | PlatformId::Harfanglab
        | PlatformId::CarbonBlackCloud
        | PlatformId::Elastic
        | PlatformId::Sysdig
        | PlatformId::Bitdefender
        | PlatformId::Graylog
        | PlatformId::Exabeam
        | PlatformId::GoogleSecops
        | PlatformId::Datadog => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cloud_platforms_have_a_default_host() {
        assert_eq!(
            default_host(PlatformId::MicrosoftDefender),
            Some("https://graph.microsoft.com")
        );
        assert_eq!(
            default_host(PlatformId::Crowdstrike),
            Some("https://api.crowdstrike.com")
        );
        assert_eq!(
            default_host(PlatformId::Sentinel),
            Some("https://api.loganalytics.io")
        );
        assert_eq!(default_host(PlatformId::Elastic), None);
    }

    #[test]
    fn an_integer_beyond_i64_is_the_nearest_float_in_a_setup_value() {
        use opentide_compile::Json as J;
        // TOML integers are signed 64-bit: u64::MAX is 2^64 as the nearest float.
        let Some(toml::Value::Float(float)) = toml_value(&J::UInt(u64::MAX)) else {
            panic!("a UInt is a TOML float");
        };
        assert_eq!(float.to_bits(), 2f64.powi(64).to_bits());
        // An integer that fits keeps its digits.
        assert_eq!(
            toml_value(&J::Int(i64::MAX)),
            Some(toml::Value::Integer(i64::MAX))
        );
    }
}
