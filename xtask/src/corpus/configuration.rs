//! The fault kinds of `tests/corpora/faults.toml` whose findings are about
//! configuration files (UC-1.5, #811), which the conformance suite lays out
//! one workspace each (`cargo xtask conformance`).

/// The configuration fault kinds of `tests/corpora/faults.toml`, each with
/// what it exercises. The `config-enum-*` kinds and `platform-not-enabled`
/// are findings on rules (UC-2.x), not on configuration files.
pub const CONFIGURATION: &[(&str, &str)] = &[
    (
        "config-unknown-key-platform",
        "an unknown key in [platform]",
    ),
    ("config-missing-field-tenant", "a tenant without its name"),
    (
        "config-schema-validation-platform",
        "a platform name that is not a string",
    ),
    (
        "config-promotion-target-unknown",
        "a promotion target no status has",
    ),
    (
        "config-unknown-key-deployment",
        "five unknown keys in deployment.toml",
    ),
    ("config-retired-file", "global.toml stops every command"),
    (
        "config-parse-visibility",
        "visibility.toml that is not TOML",
    ),
    (
        "gap-extra-configuration-file",
        "a .toml opentide does not read",
    ),
    (
        "config-asset-unknown",
        "log sources naming undeclared assets",
    ),
    ("sharing-api-key-literal", "literal MISP keys"),
    ("sharing-duplicate-name", "five blocks of one name"),
    ("sharing-name-invalid", "block names that are not slugs"),
    (
        "sharing-max-tlp-unknown",
        "a max_tlp that is not a tlp name",
    ),
    ("sharing-url-invalid", "ftp URLs"),
    (
        "sharing-invalid-value",
        "a verify_ssl that is not a boolean",
    ),
    (
        "sharing-object-type-unknown",
        "an object type that is not a family",
    ),
    (
        "sharing-organisation-uuid-invalid",
        "organisation UUIDs that are not UUIDs",
    ),
    (
        "sharing-rule-status-unknown",
        "rule statuses deployment.toml lacks",
    ),
    ("sharing-unknown-key", "unknown block keys"),
    ("sharing-missing-field", "blocks missing required keys"),
    ("sharing-unknown-connector", "another connector's array"),
    (
        "gap-sharing-dollar-variable",
        "$NAME is a literal key in sharing.toml",
    ),
    ("sharing-config-parse", "sharing.toml that is not TOML"),
    ("sharing-directory", "configurations/sharing/"),
];
