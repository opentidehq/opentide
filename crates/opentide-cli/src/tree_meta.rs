//! What the catalogue (`opentide --json commands`) says about an argument that
//! clap's model of it cannot: the negative flag of a pair, and a default that
//! is not the one clap holds. `tests/framework_catalog.rs` checks that every
//! row names an argument of [`crate::tree`].

/// `(command path, option id, negative option id, negative flag)`: the
/// option's `secondary_flags`. The negative option is its own clap argument,
/// which the catalogue folds into the positive one.
pub(crate) const SECONDARY: &[(&str, &str, &str, &str)] = &[
    (
        "generate extract elastic",
        "include_prebuilt",
        "custom_only",
        "--custom-only",
    ),
    (
        "deploy",
        "keep_deprecated",
        "drop_deprecated",
        "--drop-deprecated",
    ),
    ("share", "publish", "no_publish", "--no-publish"),
    ("share push", "publish", "no_publish", "--no-publish"),
    ("setup", "staging", "no_staging", "--no-staging"),
    ("setup", "inflight", "no_inflight", "--no-inflight"),
    ("setup", "sharing", "no_sharing", "--no-sharing"),
    ("setup", "lint_changed", "lint_all", "--lint-all"),
    ("setup", "promotion", "no_promotion", "--no-promotion"),
    (
        "setup",
        "explorer_pages",
        "no_explorer_pages",
        "--no-explorer-pages",
    ),
    ("setup ci", "staging", "no_staging", "--no-staging"),
    ("setup ci", "inflight", "no_inflight", "--no-inflight"),
    ("setup ci", "sharing", "no_sharing", "--no-sharing"),
    ("setup ci", "lint_changed", "lint_all", "--lint-all"),
    ("setup ci", "promotion", "no_promotion", "--no-promotion"),
    (
        "setup ci",
        "explorer_pages",
        "no_explorer_pages",
        "--no-explorer-pages",
    ),
    ("setup hooks", "install", "no_install", "--no-install"),
];

/// `(command path, argument id, default as JSON)`: a default other than the
/// one clap holds: `null` and `true` for a flag pair the command resolves
/// itself, `[]` for a repeatable option whose default is the empty list
/// rather than none.
pub(crate) const DEFAULTS: &[(&str, &str, &str)] = &[
    ("lint", "check", "[]"),
    ("deploy", "keep_deprecated", "null"),
    ("share", "publish", "null"),
    ("share push", "publish", "null"),
    ("setup", "platform", "[]"),
    ("setup", "staging", "true"),
    ("setup", "inflight", "true"),
    ("setup", "promotion", "null"),
    ("setup", "mcp", "[]"),
    ("setup", "skills", "[]"),
    ("setup repo", "platform", "[]"),
    ("setup ci", "staging", "true"),
    ("setup ci", "inflight", "true"),
    ("setup ci", "promotion", "null"),
    ("setup hooks", "install", "true"),
    ("setup skills", "install", "[]"),
];
/// `(command path, argument id, choices)`: an argument whose value the
/// command checks itself, with its own message and suggestion (`info`'s
/// section), so clap holds no choices for it; the catalogue lists them.
pub(crate) const CHOICES: &[(&str, &str, &[&str])] =
    &[("info", "section", &crate::commands::info::SECTIONS)];

/// The catalogue's choices for `id` in the command at `path`, when the
/// command checks them itself.
pub(crate) fn choices(path: &str, id: &str) -> Option<Vec<String>> {
    CHOICES
        .iter()
        .find(|(p, arg, _)| *p == path && *arg == id)
        .map(|(_, _, values)| values.iter().map(|v| (*v).to_owned()).collect())
}

/// Environment variables a root option reads itself, not through clap:
/// `--debug` reads `OPENTIDE_DEBUG` (and `DEBUG` when it is a boolean), so
/// that `DEBUG='*'` cannot fail every command.
pub(crate) const CALLBACK_ENVVARS: &[(&str, &str)] = &[("debug", "OPENTIDE_DEBUG")];

/// Root options that say nothing about a command: left out of the catalogue.
pub(crate) const PLUMBING: &[&str] = &["help", "install_completion", "show_completion"];

/// The negative option of `id` in the command at `path`, if it has one.
pub(crate) fn secondary(path: &str, id: &str) -> Option<(&'static str, &'static str)> {
    SECONDARY
        .iter()
        .find(|(p, primary, _, _)| *p == path && *primary == id)
        .map(|(_, _, secondary, flag)| (*secondary, *flag))
}

/// Whether `id` is the negative option of a pair in the command at `path`.
pub(crate) fn is_secondary(path: &str, id: &str) -> bool {
    SECONDARY
        .iter()
        .any(|(p, _, secondary, _)| *p == path && *secondary == id)
}

/// The catalogue's default for `id` in the command at `path`, when clap's is not it.
pub(crate) fn default(path: &str, id: &str) -> Option<&'static str> {
    DEFAULTS
        .iter()
        .find(|(p, arg, _)| *p == path && *arg == id)
        .map(|(_, _, value)| *value)
}
