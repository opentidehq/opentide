//! Platform plugins on the command line (UC-4.5, #835).
//!
//! The Python binding (`opentide._native`) installs the run's
//! [`PluginHost`] ([`set_host`]) before it runs the command line: the
//! platforms the `opentide.platforms` entry points add, called through PyO3.
//! [`registry`] is the built-in platforms and those plugins, which `query`,
//! `validate query --live` and `deploy` reach through the connectors' traits,
//! and [`configurations`] is the check `validate` runs on a plugin's block of
//! a rule's `configurations`.
//!
//! The native binary and the npm package install no host: a workspace that
//! enables a platform that is not built in is told so ([`workspace_warnings`],
//! [`opentide_connectors::plugin::unavailable`]).

use std::sync::OnceLock;

use opentide_connectors::connector::ConfigurationFinding;
use opentide_connectors::plugin::{self, PluginError, PluginHost};
use opentide_connectors::{ConnectorError, Registry};
use opentide_schema::node::Node;
use opentide_workspace::validate::{PlatformConfigurations, PlatformFinding};

static HOST: OnceLock<Box<dyn PluginHost>> = OnceLock::new();
/// The plugins' identifiers and the plugins that failed, read once.
static LOADED: OnceLock<(Vec<String>, Vec<PluginError>)> = OnceLock::new();

/// Installs the run's plugin host; a second call keeps the first.
pub fn set_host(host: Box<dyn PluginHost>) {
    let _ignored = HOST.set(host);
}

/// Whether a host is installed: the command line runs inside the Python
/// package.
pub fn hosted() -> bool {
    HOST.get().is_some()
}

/// The built-in platforms, reading the command's `environment` (Google
/// SecOps's Application Default Credentials), then the plugins. Built fresh
/// for each caller, as [`opentide_connectors::builtin_with`] is: a
/// connector's state (a token) never outlives the command that made it; the
/// host keeps the plugins it loaded.
pub fn registry(environment: &opentide_connectors::Environment) -> Registry {
    plugin::with_plugins(HOST.get().map(AsRef::as_ref), environment).0
}

fn loaded() -> &'static (Vec<String>, Vec<PluginError>) {
    LOADED.get_or_init(|| {
        // Only the plugins' identifiers are read: no environment.
        let (registry, errors) = plugin::with_plugins(
            HOST.get().map(AsRef::as_ref),
            &opentide_connectors::Environment::default(),
        );
        let ids = registry
            .ids()
            .into_iter()
            .filter(|id| {
                registry
                    .get(id)
                    .is_some_and(opentide_connectors::Platform::is_plugin)
            })
            .map(str::to_owned)
            .collect();
        (ids, errors)
    })
}

/// The plugins that could not be loaded or registered.
pub fn errors() -> &'static [PluginError] {
    &loaded().1
}

/// Whether *platform* is a plugin platform this run can reach. Built-in
/// names never load the plugins.
pub fn is_plugin(platform: &str) -> bool {
    !plugin::is_builtin(platform) && hosted() && loaded().0.iter().any(|id| id == platform)
}

/// The plugin platforms' identifiers, in registration order.
pub fn plugin_ids() -> Vec<String> {
    if !hosted() {
        return Vec::new();
    }
    loaded().0.clone()
}

/// The check `validate` runs on plugin blocks; `None` without a host.
pub fn configurations() -> Option<&'static dyn PlatformConfigurations> {
    hosted().then_some(&PluginBlocks as &dyn PlatformConfigurations)
}

/// The plugins' own checks of their blocks.
struct PluginBlocks;

impl PlatformConfigurations for PluginBlocks {
    fn platforms(&self) -> Vec<String> {
        plugin_ids()
    }

    fn check(&self, platform: &str, block: &serde_json::Value) -> Vec<PlatformFinding> {
        // A block's check reads no tenant and no credential.
        let registry = registry(&opentide_connectors::Environment::default());
        let Some(check) = registry
            .get(platform)
            .and_then(opentide_connectors::Platform::configuration_check)
        else {
            return Vec::new();
        };
        match check.check(block) {
            Ok(found) => found.into_iter().map(finding).collect(),
            Err(error) => vec![PlatformFinding::new(
                Vec::new(),
                format!("the plugin could not check this block: {}", reason(&error)),
                false,
            )],
        }
    }
}

fn finding(found: ConfigurationFinding) -> PlatformFinding {
    PlatformFinding::new(found.path, found.message, found.warning)
}

/// An error's text without the platform and tenant a tenant error names.
fn reason(error: &ConnectorError) -> String {
    match error {
        ConnectorError::Crashed { message, .. } | ConnectorError::Refused { message, .. } => {
            message.clone()
        }
        other => other.to_string(),
    }
}

/// The platforms the workspace enables (`[platform] enabled = true`) that
/// are not built in, in the configuration's order.
pub fn enabled_outside_builtin(platforms: Option<&Node>) -> Vec<String> {
    opentide_schema::configuration::resolve::enabled_platform_ids(platforms)
        .into_iter()
        .filter(|id| !plugin::is_builtin(id))
        .collect()
}

/// What a run says about the workspace's plugin platforms, as `warning:`
/// lines: each enabled platform this command line cannot reach (no host, or
/// no installed plugin provides it), then each plugin that failed to load.
pub fn workspace_warnings(platforms: Option<&Node>) -> Vec<String> {
    let enabled = enabled_outside_builtin(platforms);
    if enabled.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = enabled
        .iter()
        .filter(|id| !is_plugin(id))
        .map(|id| {
            if hosted() {
                format!(
                    "{id} is enabled, but no installed {} plugin provides it",
                    plugin::ENTRY_POINT_GROUP
                )
            } else {
                plugin::unavailable(id)
            }
        })
        .collect();
    if hosted() {
        lines.extend(
            errors()
                .iter()
                .filter(|error| enabled.contains(&error.platform))
                .map(ToString::to_string),
        );
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platforms(text: &str) -> Node {
        let parsed = opentide_schema::node::load(text).expect("parsed");
        parsed.root().expect("a root").as_ref().clone()
    }

    #[test]
    fn enabled_platforms_outside_the_builtin_ones_are_named_without_a_host() {
        let node = platforms(
            "acme:\n  platform:\n    enabled: true\nsentinel:\n  platform:\n    enabled: true\n\
             other:\n  platform:\n    enabled: false\n",
        );
        assert_eq!(enabled_outside_builtin(Some(&node)), ["acme"]);
        assert!(enabled_outside_builtin(None).is_empty());
        let lines = workspace_warnings(Some(&node));
        assert_eq!(lines, [plugin::unavailable("acme")]);
        assert!(!is_plugin("acme"));
        assert!(plugin_ids().is_empty());
        assert!(configurations().is_none());
    }

    #[test]
    fn a_failed_check_is_one_finding_on_the_block() {
        let error = ConnectorError::Crashed {
            platform: "acme".into(),
            tenant: String::new(),
            message: "ValueError: boom".into(),
        };
        assert_eq!(reason(&error), "ValueError: boom");
        assert_eq!(
            reason(&ConnectorError::Cancelled),
            ConnectorError::Cancelled.to_string()
        );
        let found = finding(ConfigurationFinding {
            path: vec!["query".into()],
            message: "Field required".into(),
            warning: true,
        });
        assert_eq!(found.field_path, ["query"]);
        assert!(found.warning);
        assert!(
            PluginBlocks
                .check("acme", &serde_json::json!({}))
                .is_empty()
        );
    }
}
