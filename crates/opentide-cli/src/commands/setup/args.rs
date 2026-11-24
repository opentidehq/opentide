//! The `setup` commands' options, from the clap derive structs of
//! `tree.rs`: what a command takes is read off its typed struct, and
//! `ArgMatches` is asked only where an option came from (`app.rs`).

use clap::ValueEnum;

use super::files::RepoOptions;
use super::run::GroupArgs;
use crate::tree::{
    Ci, CiPlatform, Mcp, SetupArgs, SetupMcpArgs, SetupPipelineFields, SetupPlatformsArgs,
    SetupRepoFields, SetupSkillsArgs, Skills,
};

/// The names the command line spells `values` with, each once, in order.
fn names<T: ValueEnum>(values: &[T]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.iter().filter_map(ValueEnum::to_possible_value) {
        let name = value.get_name().to_owned();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

impl From<&SetupRepoFields> for RepoOptions {
    fn from(fields: &SetupRepoFields) -> Self {
        RepoOptions {
            name: fields.name.as_deref().map(|name| name.trim().to_owned()),
            org: fields.org.clone(),
            description: fields.description.clone(),
            // Not deduplicated: the wizard and the scaffold see them as typed.
            platforms: fields
                .platform
                .iter()
                .filter_map(ValueEnum::to_possible_value)
                .map(|value| value.get_name().to_owned())
                .collect(),
        }
    }
}

impl SetupPipelineFields {
    /// `--promotion/--no-promotion`; `None` keeps the repository's setting.
    pub fn promotion_choice(&self) -> Option<bool> {
        if self.promotion {
            Some(true)
        } else if self.no_promotion {
            Some(false)
        } else {
            None
        }
    }
}

impl SetupPipelineFields {
    /// `--app-token/--no-app-token`; `None` keeps what the existing pipeline has.
    pub fn app_token_choice(&self) -> Option<bool> {
        if self.app_token {
            Some(true)
        } else if self.no_app_token {
            Some(false)
        } else {
            None
        }
    }
}

impl SetupPipelineFields {
    /// `--prune/--no-prune`; `None` keeps what the existing pipeline has.
    pub fn prune_choice(&self) -> Option<bool> {
        if self.prune {
            Some(true)
        } else if self.no_prune {
            Some(false)
        } else {
            None
        }
    }
}

impl From<CiPlatform> for opentide_compile::ci::Provider {
    fn from(platform: CiPlatform) -> Self {
        match platform {
            CiPlatform::Github => Self::GitHub,
            CiPlatform::Gitlab => Self::GitLab,
            CiPlatform::Azure => Self::Azure,
        }
    }
}

impl From<&SetupArgs> for GroupArgs {
    fn from(args: &SetupArgs) -> Self {
        let pipeline = &args.pipeline;
        GroupArgs {
            path: args.path.clone(),
            repo: RepoOptions::from(&args.repo),
            ci: args
                .ci
                .as_ref()
                .and_then(Ci::to_possible_value)
                .map(|value| value.get_name().to_owned()),
            pipeline: None,
            staging: !pipeline.no_staging,
            inflight: !pipeline.no_inflight,
            sharing: pipeline.sharing,
            lint_changed: pipeline.lint_changed,
            explorer_pages: pipeline.explorer_pages,
            variable_group: pipeline.variable_group.clone(),
            app_token: pipeline.app_token_choice(),
            prune: pipeline.prune_choice(),
            promotion: pipeline.promotion_choice(),
            promotion_target: pipeline.promotion_target.clone(),
            python_version: pipeline.python_version.clone(),
            default_branch: pipeline.default_branch.clone(),
            vscode_setup: args.vscode_setup,
            mcp: names::<Mcp>(&args.mcp),
            skills: names::<Skills>(&args.skills),
            plugin: args.plugin,
            hooks: args.hooks,
            env: args.env,
            plan: args.plan,
            yes: args.yes,
        }
    }
}

impl SetupPlatformsArgs {
    /// The ids of the platforms the flags enable, in the platform table's
    /// order.
    pub fn enabled(&self) -> Vec<String> {
        let flags = [
            ("sentinel", self.sentinel),
            ("defender_for_endpoint", self.defender_for_endpoint),
            ("splunk", self.splunk),
            ("sentinel_one", self.sentinel_one),
            ("crowdstrike", self.crowdstrike),
            ("harfanglab", self.harfanglab),
            ("carbon_black_cloud", self.carbon_black_cloud),
            ("elastic", self.elastic),
            ("sysdig", self.sysdig),
            ("bitdefender", self.bitdefender),
            ("graylog", self.graylog),
            ("exabeam", self.exabeam),
            ("google_secops", self.google_secops),
        ];
        opentide_schema::platforms::IDS
            .into_iter()
            .filter(|id| flags.iter().any(|(flag, on)| flag == id && *on))
            .map(str::to_owned)
            .collect()
    }
}

impl SetupMcpArgs {
    /// The hosts the flags name, in the flags' order.
    pub fn hosts(&self) -> Vec<String> {
        [
            ("vscode", self.vscode),
            ("cursor", self.cursor),
            ("claude-code", self.claude_code),
            ("generic", self.generic),
        ]
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(host, _)| host.to_owned())
        .collect()
    }
}

impl From<&SetupSkillsArgs> for super::skills::Options {
    fn from(args: &SetupSkillsArgs) -> Self {
        use super::skills::Target;
        let targets = [
            (args.cursor, Target::Cursor),
            (args.claude_code, Target::ClaudeCode),
            (args.generic, Target::Generic),
            (args.github_copilot, Target::GithubCopilot),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, target)| target)
        .collect();
        Self {
            targets,
            slugs: args.install.clone(),
            all: args.all_skills,
            name: args.name.clone(),
            org: args.org.clone(),
            description: args.description.clone(),
            plugin: args.plugin,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::tree::{Cli, RootCommand, SetupCommand};

    fn parse(words: &[&str]) -> SetupArgs {
        let words = std::iter::once("opentide").chain(words.iter().copied());
        match Cli::try_parse_from(words).map(|cli| cli.command) {
            Ok(Some(RootCommand::Setup(args))) => args,
            other => panic!("not a setup command: {other:?}"),
        }
    }

    #[test]
    fn platform_flags_are_listed_in_the_tables_order() {
        let args = parse(&["setup", "platforms", "--google-secops", "--sentinel"]);
        let Some(SetupCommand::Platforms(platforms)) = args.command else {
            panic!("not setup platforms");
        };
        assert_eq!(platforms.enabled(), ["sentinel", "google_secops"]);
    }

    #[test]
    fn mcp_hosts_keep_the_flags_order() {
        let args = parse(&["setup", "mcp", "--generic", "--vscode"]);
        let Some(SetupCommand::Mcp(mcp)) = args.command else {
            panic!("not setup mcp");
        };
        assert_eq!(mcp.hosts(), ["vscode", "generic"]);
    }

    #[test]
    fn the_group_deduplicates_hosts_and_keeps_repeated_platforms() {
        let args = parse(&[
            "setup",
            "--mcp",
            "cursor",
            "--mcp",
            "cursor",
            "--platform",
            "elastic",
            "--platform",
            "elastic",
            "--no-staging",
            "--promotion",
        ]);
        let group = GroupArgs::from(&args);
        assert_eq!(group.mcp, ["cursor"]);
        assert_eq!(group.repo.platforms, ["elastic", "elastic"]);
        assert!(!group.staging);
        assert_eq!(group.promotion, Some(true));
        assert_eq!(group.python_version, "3.12");
    }

    #[test]
    fn every_platform_of_the_table_has_a_flag_that_enables_it() {
        for id in opentide_schema::platforms::IDS {
            let flag = format!("--{}", id.replace('_', "-"));
            let args = parse(&["setup", "platforms", &flag]);
            let Some(SetupCommand::Platforms(platforms)) = args.command else {
                panic!("not setup platforms");
            };
            assert_eq!(platforms.enabled(), [id], "{flag}");
        }
    }
}
