//! Platform plugins (UC-4.5, #835): platforms a Python package adds through
//! the `opentide.platforms` entry-point group.
//!
//! The Rust core cannot import Python, so a host that can supplies them: a
//! [`PluginHost`]. The Python binding (`opentide._native`) is the one host:
//! it discovers the entry points through the SDK layer (`opentide.plugins`)
//! and wraps each plugin as a [`Platform`], whose [`Deployer`],
//! [`LiveValidator`], [`QueryRunner`] and [`ConfigurationCheck`] call the
//! plugin through PyO3, taking the GIL for the call alone. The native binary
//! and the npm package have no host: [`unavailable`] is what they say about
//! a platform the workspace enables that is not built in.
//!
//! [`Deployer`]: crate::connector::Deployer
//! [`LiveValidator`]: crate::connector::LiveValidator
//! [`QueryRunner`]: crate::connector::QueryRunner
//! [`ConfigurationCheck`]: crate::connector::ConfigurationCheck

use crate::connector::{Platform, Registry};

/// The entry-point group plugins register in.
pub const ENTRY_POINT_GROUP: &str = "opentide.platforms";

/// A plugin that could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginError {
    /// The entry point's name: the platform's identifier.
    pub platform: String,
    /// Why.
    pub message: String,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "platform plugin {} could not be loaded: {}",
            self.platform, self.message
        )
    }
}

/// What supplies the plugin platforms of a run: the Python binding.
pub trait PluginHost: Send + Sync {
    /// Every plugin installed, each as a platform, or why it could not be
    /// loaded. A plugin whose identifier is a built-in platform's is never
    /// returned: [`with_plugins`] refuses it.
    fn platforms(&self) -> Vec<Result<Box<dyn Platform>, PluginError>>;
}

/// The built-in platforms, then *host*'s plugins, with the plugins that could
/// not be loaded or registered (a plugin cannot replace a built-in platform,
/// nor another plugin).
pub fn with_plugins(host: Option<&dyn PluginHost>) -> (Registry, Vec<PluginError>) {
    let mut registry = crate::builtin();
    let mut errors = Vec::new();
    let Some(host) = host else {
        return (registry, errors);
    };
    for platform in host.platforms() {
        match platform {
            Ok(platform) => {
                let id = platform.id().to_owned();
                if let Err(message) = registry.register(platform) {
                    errors.push(PluginError {
                        platform: id,
                        message,
                    });
                }
            }
            Err(error) => errors.push(error),
        }
    }
    (registry, errors)
}

/// Whether *id* names one of the built-in platforms.
pub fn is_builtin(id: &str) -> bool {
    opentide_schema::platforms::is_builtin(id)
}

/// The identifiers of the built-in platforms, in [`crate::builtin`]'s order
/// ([`opentide_schema::platforms::Order::Connector`]).
pub const BUILTIN: [&str; opentide_schema::platforms::COUNT] =
    opentide_schema::platforms::ordered(opentide_schema::platforms::Order::Connector);

/// What a command line without a plugin host (the native binary, the npm
/// package) says about *platform*, a platform the workspace enables that is
/// not built in.
pub fn unavailable(platform: &str) -> String {
    format!(
        "{platform} is not a built-in platform: if it is a platform plugin (an \
         {ENTRY_POINT_GROUP} entry point), it loads only when opentide runs from its Python \
         package (pip install opentide, then opentide ...); this command \
         line cannot check its configuration or reach its tenants"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::ConfigurationCheck;

    struct Fake(&'static str);

    impl Platform for Fake {
        fn id(&self) -> &str {
            self.0
        }
        fn is_plugin(&self) -> bool {
            true
        }
    }

    struct Host;

    impl PluginHost for Host {
        fn platforms(&self) -> Vec<Result<Box<dyn Platform>, PluginError>> {
            vec![
                Ok(Box::new(Fake("acme"))),
                Ok(Box::new(Fake("sentinel"))),
                Ok(Box::new(Fake("acme"))),
                Err(PluginError {
                    platform: "broken".into(),
                    message: "ImportError: no module named broken".into(),
                }),
            ]
        }
    }

    #[test]
    fn plugins_follow_the_builtin_platforms_and_cannot_replace_one() {
        let (registry, errors) = with_plugins(Some(&Host));
        let ids = registry.ids();
        assert_eq!(ids.len(), 10);
        assert_eq!(ids[..9], BUILTIN);
        assert_eq!(ids[9], "acme");
        let acme = registry.get("acme").expect("registered");
        assert!(acme.is_plugin());
        assert!(acme.deployer().is_none() && acme.configuration_check().is_none());
        assert!(!registry.get("sentinel").expect("built in").is_plugin());
        let failed: Vec<(&str, &str)> = errors
            .iter()
            .map(|error| (error.platform.as_str(), error.message.as_str()))
            .collect();
        assert_eq!(
            failed,
            [
                ("sentinel", "platform sentinel is already registered"),
                ("acme", "platform acme is already registered"),
                ("broken", "ImportError: no module named broken"),
            ]
        );
        assert_eq!(
            errors[2].to_string(),
            "platform plugin broken could not be loaded: ImportError: no module named broken"
        );
    }

    #[test]
    fn without_a_host_the_registry_is_the_builtin_one() {
        let (registry, errors) = with_plugins(None);
        assert_eq!(registry.ids(), BUILTIN);
        assert!(errors.is_empty());
        assert!(BUILTIN.iter().all(|id| is_builtin(id)));
        assert!(!is_builtin("acme"));
    }

    #[test]
    fn the_message_without_a_host_names_the_platform_and_the_way_out() {
        let message = unavailable("acme");
        assert!(message.starts_with("acme is not a built-in platform"));
        assert!(message.contains("opentide.platforms entry point"));
        assert!(message.contains("pip install opentide, then opentide"));
    }

    struct Checked;

    impl ConfigurationCheck for Checked {
        fn check(
            &self,
            block: &serde_json::Value,
        ) -> Result<Vec<crate::connector::ConfigurationFinding>, crate::ConnectorError> {
            Ok(block
                .as_object()
                .into_iter()
                .flat_map(|map| map.keys())
                .map(|key| crate::connector::ConfigurationFinding {
                    path: vec![key.clone()],
                    message: "unexpected".into(),
                    warning: false,
                })
                .collect())
        }
    }

    #[test]
    fn a_configuration_check_reports_paths_inside_the_block() {
        let found = Checked
            .check(&serde_json::json!({"query": 1}))
            .expect("checked");
        assert_eq!(found[0].path, ["query"]);
    }
}
