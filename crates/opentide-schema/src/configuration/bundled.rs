//! The bundled configuration files (`src/opentide/data/configurations/`),
//! compiled in: the first layer every workspace's configuration merges onto.
//! `tests/configuration.rs` checks that this list is the folder's.

/// Every bundled `.toml` file, by its path relative to the folder, in the
/// order the oracle reads them (sorted by name, the `platforms/` folder in
/// its place).
pub const FILES: [(&str, &str); 18] = [
    (
        "deployment.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/deployment.toml"
        )),
    ),
    (
        "documentation.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/documentation.toml"
        )),
    ),
    (
        "lint.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/lint.toml"
        )),
    ),
    (
        "paths.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/paths.toml"
        )),
    ),
    (
        "platforms/carbon_black_cloud.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/carbon_black_cloud.toml"
        )),
    ),
    (
        "platforms/crowdstrike.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/crowdstrike.toml"
        )),
    ),
    (
        "platforms/defender_for_endpoint.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/defender_for_endpoint.toml"
        )),
    ),
    (
        "platforms/elastic.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/elastic.toml"
        )),
    ),
    (
        "platforms/exabeam.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/exabeam.toml"
        )),
    ),
    (
        "platforms/google_secops.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/google_secops.toml"
        )),
    ),
    (
        "platforms/harfanglab.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/harfanglab.toml"
        )),
    ),
    (
        "platforms/sentinel.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/sentinel.toml"
        )),
    ),
    (
        "platforms/sentinel_one.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/sentinel_one.toml"
        )),
    ),
    (
        "platforms/splunk.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/splunk.toml"
        )),
    ),
    (
        "platforms/sysdig.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/platforms/sysdig.toml"
        )),
    ),
    (
        "resources.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/resources.toml"
        )),
    ),
    (
        "sharing.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/sharing.toml"
        )),
    ),
    (
        "visibility.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/configurations/visibility.toml"
        )),
    ),
];

/// The bundled `tlp` vocabulary, whose names `max_tlp` must be.
pub const TLP_VOCABULARY: &str = include_str!(concat!(
    env!("OPENTIDE_ASSETS"),
    "/src/opentide/data/vocabulary/tlp.vocab.toml"
));

/// The text of the bundled file at `relative` (`deployment.toml`,
/// `platforms/splunk.toml`), if one ships.
pub fn text(relative: &str) -> Option<&'static str> {
    FILES
        .iter()
        .find(|(path, _)| *path == relative)
        .map(|(_, text)| *text)
}

/// The bundled document for a router key (`platforms/*.toml` has none), or
/// an empty table (`bundled_layer`).
pub fn layer(file_key: &str) -> crate::node::Node {
    if file_key.contains('*') {
        return super::merge::empty();
    }
    text(file_key)
        .and_then(|text| super::toml::parse(text).ok())
        .unwrap_or_else(super::merge::empty)
}

/// The `tlp` names of the bundled vocabulary, in its order; the `TlpName`
/// values when it holds none (`_tlp_names`).
pub fn tlp_names() -> Vec<String> {
    let names: Vec<String> = super::toml::parse(TLP_VOCABULARY)
        .ok()
        .and_then(|document| {
            let crate::node::Value::Seq(keys) = &document.get("keys")?.value else {
                return None;
            };
            Some(
                keys.iter()
                    .filter_map(|key| match &key.get("name")?.value {
                        crate::node::Value::Str(name) if !name.is_empty() => Some(name.clone()),
                        crate::node::Value::Int(number) => Some(number.to_string()),
                        _ => None,
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    if names.is_empty() {
        super::models::TLP_ORDER
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        names
    }
}
