//! The command tree of `opentide`, in clap derive (plan §3 invariant 1).
//!
//! Every path, option, type, choice, default and environment variable of the
//! Python CLI (opentide 0.23.0, the oracle) is here, hidden ones included, so
//! that every command line the oracle parses parses the same way. It was
//! written from the oracle's Click tree once; it is code now, and a command's
//! port (UC-3.5, UC-3.6) changes its struct here. `opentide --json commands`
//! is generated from it ([`crate::catalog`]), and `tests/framework_catalog.rs`
//! holds that document to the oracle's byte for byte.
//!
//! What clap cannot say about an argument, the catalogue reads from
//! `tree_meta.rs`: the negative flag of a pair (`--publish` /
//! `--no-publish`) and a default that is not the flag's (`null`, `true`, `[]`).
//! `long_about = ""` marks a command whose help text is empty: the catalogue's
//! `help` is `""` and its `summary` the `about` line.

#![expect(
    missing_docs,
    reason = "the fields and variants are the command line; each one's help is its documentation"
)]
#![expect(
    clippy::struct_excessive_bools,
    reason = "a command's flags are one field each, as clap parses them"
)]

use clap::{Args, Parser, Subcommand, ValueEnum};

/// A string option whose choices the catalogue lists but the command checks
/// itself, with its own message (`validate --type`: "Unknown object
/// type(s): …"): clap accepts any value and still knows the choices.
#[derive(Clone, Debug)]
pub struct CommandChecked(pub &'static [&'static str]);

impl clap::builder::TypedValueParser for CommandChecked {
    type Value = String;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<String, clap::Error> {
        clap::builder::StringValueParser::new().parse_ref(cmd, arg, value)
    }

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        Some(Box::new(
            self.0
                .iter()
                .map(|name| clap::builder::PossibleValue::new(*name)),
        ))
    }
}

/// The values of `Check`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Check {
    #[value(name = "id-uniqueness")]
    IdUniqueness,
    #[value(name = "uuid-format")]
    UuidFormat,
    #[value(name = "schema")]
    Schema,
    #[value(name = "cve")]
    Cve,
    #[value(name = "sharing-config")]
    SharingConfig,
    #[value(name = "configuration")]
    Configuration,
    #[value(name = "queries")]
    Queries,
}

/// The values of `Queries`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Queries {
    #[value(name = "error")]
    Error,
    #[value(name = "warn")]
    Warn,
    #[value(name = "off")]
    Off,
}

/// The values of `ReportFormat`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    #[value(name = "text")]
    Text,
    #[value(name = "sarif")]
    Sarif,
    #[value(name = "codequality")]
    Codequality,
}

/// The values of `Platform`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    #[value(name = "sentinel")]
    Sentinel,
    #[value(name = "splunk")]
    Splunk,
    #[value(name = "crowdstrike")]
    Crowdstrike,
    #[value(name = "defender_for_endpoint")]
    DefenderForEndpoint,
    #[value(name = "sentinel_one")]
    SentinelOne,
    #[value(name = "carbon_black_cloud")]
    CarbonBlackCloud,
    #[value(name = "harfanglab")]
    Harfanglab,
    #[value(name = "elastic")]
    Elastic,
    #[value(name = "sysdig")]
    Sysdig,
}

/// The values of `RowFormat`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RowFormat {
    #[value(name = "table")]
    Table,
    #[value(name = "jsonl")]
    Jsonl,
    #[value(name = "csv")]
    Csv,
}

/// The values of `Check2`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Check2 {
    #[value(name = "filenames")]
    Filenames,
    #[value(name = "metadata")]
    Metadata,
    #[value(name = "placeholders")]
    Placeholders,
    #[value(name = "queries")]
    Queries,
}

/// The values of `Ci`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Ci {
    #[value(name = "github")]
    Github,
    #[value(name = "gitlab")]
    Gitlab,
    #[value(name = "azure")]
    Azure,
    #[value(name = "none")]
    None,
}

/// The values of `Mcp`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mcp {
    #[value(name = "vscode")]
    Vscode,
    #[value(name = "cursor")]
    Cursor,
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "generic")]
    Generic,
}

/// The values of `Skills`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Skills {
    #[value(name = "cursor")]
    Cursor,
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "generic")]
    Generic,
    #[value(name = "github-copilot")]
    GithubCopilot,
}

/// The values of `CiPlatform`, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CiPlatform {
    #[value(name = "github")]
    Github,
    #[value(name = "gitlab")]
    Gitlab,
    #[value(name = "azure")]
    Azure,
}

/// `opentide`: the root and its options.
#[derive(Debug, Parser)]
#[command(
    name = "opentide",
    about = "Spec-driven development for agentic detection engineering",
    after_help = "Examples:\n  $ opentide setup\n  $ opentide validate\n  $ opentide --json validate",
    subcommand_required = true,
    subcommand_value_name = "COMMAND",
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(long = "repo", env = "OPENTIDE_REPO_ROOT", help = "Repository root")]
    pub repo: Option<String>,
    #[arg(long = "data", env = "OPENTIDE_DATA_ROOT", help = "Bundled data root")]
    pub data: Option<String>,
    #[arg(long = "debug", help = "Enable debug logging. Also OPENTIDE_DEBUG=1")]
    pub debug: bool,
    #[arg(long = "quiet", help = "Print only the outcome line and errors")]
    pub quiet: bool,
    #[arg(long = "no-color", help = "Disable colour")]
    pub no_color: bool,
    #[arg(
        long = "json",
        help = "Machine-readable output: one JSON object on stdout"
    )]
    pub json_output: bool,
    #[arg(
        long = "proxy",
        env = "OPENTIDE_PROXY",
        help = "HTTP(S) proxy URL (http://[user:pass@]host:port) for platform and lookup calls. Overrides HTTP_PROXY and HTTPS_PROXY; hosts in NO_PROXY are still reached directly."
    )]
    pub proxy: Option<String>,
    #[arg(
        long = "version",
        short = 'V',
        help = "Print the installed opentide version and exit"
    )]
    pub version: bool,
    #[command(subcommand)]
    pub command: Option<RootCommand>,
}

/// `opentide extract`.
#[derive(Debug, Args)]
pub struct ExtractArgs {
    #[command(subcommand)]
    pub command: Option<ExtractCommand>,
}

/// `opentide extract defender`.
#[derive(Debug, Args)]
pub struct ExtractDefenderArgs {}

/// `opentide extract sentinel`.
#[derive(Debug, Args)]
pub struct ExtractSentinelArgs {}

/// `opentide export`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    #[command(subcommand)]
    pub command: Option<ExportCommand>,
}

/// `opentide export revisions`.
#[derive(Debug, Args)]
pub struct ExportRevisionsArgs {}

/// `opentide export objects`.
#[derive(Debug, Args)]
pub struct ExportObjectsArgs {}

/// `opentide export navigator`.
#[derive(Debug, Args)]
pub struct ExportNavigatorArgs {}

/// `opentide document`.
#[derive(Debug, Args)]
pub struct DocumentArgs {
    #[arg(long = "output")]
    pub output: Option<String>,
    #[arg(long = "flavor")]
    pub flavor: Option<String>,
    #[command(subcommand)]
    pub command: Option<DocumentCommand>,
}

/// `opentide document index`.
#[derive(Debug, Args)]
pub struct DocumentIndexArgs {
    #[arg(long = "output")]
    pub output: Option<String>,
    #[arg(long = "flavor")]
    pub flavor: Option<String>,
}

/// `opentide document threats`.
#[derive(Debug, Args)]
pub struct DocumentThreatsArgs {
    #[arg(long = "output")]
    pub output: Option<String>,
    #[arg(long = "flavor")]
    pub flavor: Option<String>,
}

/// `opentide document objectives`.
#[derive(Debug, Args)]
pub struct DocumentObjectivesArgs {
    #[arg(long = "output")]
    pub output: Option<String>,
    #[arg(long = "flavor")]
    pub flavor: Option<String>,
}

/// `opentide document rules`.
#[derive(Debug, Args)]
pub struct DocumentRulesArgs {
    #[arg(long = "output")]
    pub output: Option<String>,
    #[arg(long = "flavor")]
    pub flavor: Option<String>,
}

/// `opentide serve`.
#[derive(Debug, Args)]
pub struct ServeArgs {}

/// `opentide lsp`.
#[derive(Debug, Args)]
pub struct LspArgs {
    #[command(subcommand)]
    pub command: Option<LspCommand>,
}

/// `opentide lsp start`.
#[derive(Debug, Args)]
pub struct LspStartArgs {
    #[arg(
        long = "stdio",
        help = "Speak on stdin and stdout: the only transport, accepted for editors that pass it"
    )]
    pub stdio: bool,
}

/// `opentide mcp`.
#[derive(Debug, Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: Option<McpCommand>,
}

/// `opentide mcp start`.
#[derive(Debug, Args)]
pub struct McpStartArgs {}

/// `opentide commands`.
#[derive(Debug, Args)]
pub struct CommandsArgs {}

/// `opentide explain`.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    #[arg(
        help = "A diagnostic code, such as vocab_unknown. Omit it to list every code.",
        value_name = "code"
    )]
    pub code: Option<String>,
}

/// `opentide tui`.
#[derive(Debug, Args)]
pub struct TuiArgs {}

/// `opentide migrate`.
#[derive(Debug, Args)]
pub struct MigrateArgs {
    #[command(subcommand)]
    pub command: Option<MigrateCommand>,
}

/// `opentide migrate vocab-scope`.
#[derive(Debug, Args)]
pub struct MigrateVocabScopeArgs {
    #[arg(long = "apply", help = "Rewrite the objects (default: dry-run report)")]
    pub apply: bool,
    #[arg(long = "field", help = "Limit to one scoped field (repeatable). Default: every scoped field.", action = clap::ArgAction::Append)]
    pub field: Vec<String>,
    #[arg(long = "force", help = "Exit 0 even when values need a human decision")]
    pub force: bool,
}

/// `opentide doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(
        long = "offline",
        help = "Skip the network checks (PyPI release, proxy reachability)"
    )]
    pub offline: bool,
}

/// `opentide setup`.
#[derive(Debug, Args)]
pub struct SetupArgs {
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path: String,
    #[arg(long = "name", help = "Repository name, used in the README")]
    pub name: Option<String>,
    #[arg(long = "org", help = "Organisation or team, used in the README")]
    pub org: Option<String>,
    #[arg(
        long = "description",
        help = "One-line description, used in the README"
    )]
    pub description: Option<String>,
    #[arg(long = "platform", help = "Enable a detection platform (repeatable): sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig", action = clap::ArgAction::Append, value_name = "PLATFORM")]
    pub platform: Vec<Platform>,
    #[arg(
        long = "ci",
        help = "CI/CD pipeline to write: github, gitlab, azure or none",
        value_name = "PROVIDER"
    )]
    pub ci: Option<Ci>,
    #[arg(
        long = "staging",
        help = "Deploy to staging tenants from pull requests",
        overrides_with = "no_staging"
    )]
    pub staging: bool,
    #[arg(
        long = "no-staging",
        overrides_with = "staging",
        help = "Turn --staging off"
    )]
    pub no_staging: bool,
    #[arg(
        long = "inflight",
        help = "Update .opentide/inflight/ preview shards on pull requests",
        overrides_with = "no_inflight"
    )]
    pub inflight: bool,
    #[arg(
        long = "no-inflight",
        overrides_with = "inflight",
        help = "Turn --inflight off"
    )]
    pub no_inflight: bool,
    #[arg(
        long = "sharing",
        help = "Share changed objects on the default branch (off unless selected)",
        overrides_with = "no_sharing"
    )]
    pub sharing: bool,
    #[arg(
        long = "no-sharing",
        overrides_with = "sharing",
        help = "Turn --sharing off"
    )]
    pub no_sharing: bool,
    #[arg(
        long = "lint-changed",
        help = "Gate lint on the object files each run changes, so a catalogue with inherited findings can adopt it (validate still checks every file)",
        overrides_with = "lint_all"
    )]
    pub lint_changed: bool,
    #[arg(
        long = "lint-all",
        overrides_with = "lint_changed",
        help = "Turn --lint-changed off"
    )]
    pub lint_all: bool,
    #[arg(
        long = "promotion",
        help = "Write [promotion] enabled in deployment.toml. Omit to keep the repository's setting.",
        overrides_with = "no_promotion"
    )]
    pub promotion: bool,
    #[arg(
        long = "no-promotion",
        overrides_with = "promotion",
        help = "Turn --promotion off"
    )]
    pub no_promotion: bool,
    #[arg(
        long = "promotion-target",
        help = "Status deploy promotes rules to. Omit to keep the repository's setting."
    )]
    pub promotion_target: Option<String>,
    #[arg(
        long = "python-version",
        help = "Python version the pipeline installs",
        default_value = "3.12"
    )]
    pub python_version: String,
    #[arg(
        long = "explorer-pages",
        help = "Include GitHub Pages explorer build and deploy jobs",
        overrides_with = "no_explorer_pages"
    )]
    pub explorer_pages: bool,
    #[arg(
        long = "no-explorer-pages",
        overrides_with = "explorer_pages",
        help = "Turn --explorer-pages off"
    )]
    pub no_explorer_pages: bool,
    #[arg(
        long = "default-branch",
        help = "Branch that deploys and receives inflight shards (default: origin/HEAD, then the checked-out branch, then init.defaultBranch, then main; GitLab uses $CI_DEFAULT_BRANCH)"
    )]
    pub default_branch: Option<String>,
    #[arg(
        long = "vscode-setup",
        help = "Run deprecated setup vscode: the extension recommendation and snippets"
    )]
    pub vscode_setup: bool,
    #[arg(long = "mcp", help = "Write MCP configuration for vscode, cursor, claude-code or generic (repeatable)", action = clap::ArgAction::Append, value_name = "HOST")]
    pub mcp: Vec<Mcp>,
    #[arg(long = "skills", help = "Install agent skills for claude-code, cursor, github-copilot or generic (repeatable)", action = clap::ArgAction::Append, value_name = "TARGET")]
    pub skills: Vec<Skills>,
    #[arg(
        long = "plugin",
        help = "Register the opentidehq/skills Agent Plugin for Claude Code (.claude/settings.json)"
    )]
    pub plugin: bool,
    #[arg(long = "hooks", help = "Validate objects on every commit")]
    pub hooks: bool,
    #[arg(long = "env", help = "Write .env.example and ignore .env")]
    pub env: bool,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(long = "yes", short = 'y', help = "Non-interactive mode")]
    pub yes: bool,
    #[command(subcommand)]
    pub command: Option<SetupCommand>,
}

/// `opentide setup skills`.
#[derive(Debug, Args)]
pub struct SetupSkillsArgs {
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path: String,
    #[arg(long = "cursor", help = "Copy the skills to .cursor/skills/")]
    pub cursor: bool,
    #[arg(
        long = "claude-code",
        help = "Write CLAUDE.md and copy the skills to .claude/skills/"
    )]
    pub claude_code: bool,
    #[arg(
        long = "generic",
        help = "Write AGENTS.md for any agent that reads .agents/skills/"
    )]
    pub generic: bool,
    #[arg(
        long = "github-copilot",
        help = "Write .github/copilot-instructions.md, and AGENTS.md as --generic does"
    )]
    pub github_copilot: bool,
    #[arg(long = "install", help = "Skill slug to install (repeatable); default: the rule and engineering skills", action = clap::ArgAction::Append)]
    pub install: Vec<String>,
    #[arg(long = "all", help = "Install every skill in the catalogue")]
    pub all_skills: bool,
    #[arg(
        long = "plugin",
        help = "Register the opentidehq/skills Agent Plugin (skills and MCP server) for Claude Code in .claude/settings.json"
    )]
    pub plugin: bool,
    #[arg(
        long = "name",
        help = "Heading of the agent files; default: the folder name"
    )]
    pub name: Option<String>,
    #[arg(long = "org", help = "Organisation named in the agent files")]
    pub org: Option<String>,
    #[arg(
        long = "description",
        help = "One paragraph under the heading of the agent files"
    )]
    pub description: Option<String>,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(long = "yes", short = 'y', help = "Install without asking")]
    pub yes: bool,
    #[command(subcommand)]
    pub command: Option<SetupSkillsCommand>,
}

/// `opentide setup skills show`.
#[derive(Debug, Args)]
pub struct SetupSkillsShowArgs {
    #[arg(help = "Skill slug or name", value_name = "name")]
    pub name: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path: String,
    #[arg(
        long = "refresh",
        help = "Fetch the catalogue again, not the in-process copy of the last 30s"
    )]
    pub refresh: bool,
}

/// `opentide setup skills discover`.
#[derive(Debug, Args)]
pub struct SetupSkillsDiscoverArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(
        long = "query",
        short = 'q',
        help = "Keep skills whose name, slug or description holds this text"
    )]
    pub query: Option<String>,
    #[arg(
        long = "installed",
        help = "Keep only the skills installed in .agents/skills/"
    )]
    pub installed: bool,
    #[arg(
        long = "refresh",
        help = "Fetch the catalogue again, not the in-process copy of the last 30s"
    )]
    pub refresh: bool,
}

/// `opentide setup vscode`.
#[derive(Debug, Args)]
pub struct SetupVscodeArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(
        long = "settings",
        help = "Recommend the opentide extension in .vscode/extensions.json, and remove opentide's yaml.schemas from .vscode/settings.json"
    )]
    pub settings: bool,
    #[arg(long = "snippets", help = "Write object template snippets")]
    pub snippets: bool,
    #[arg(long = "no-merge", help = "Replace extensions.json instead of merging")]
    pub no_merge: bool,
    #[arg(long = "no-generate", help = "Do not run opentide generate first")]
    pub no_generate: bool,
    #[arg(
        long = "mcp",
        help = "Also write .vscode/mcp.json (same as setup mcp --vscode)"
    )]
    pub mcp: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Accepted for symmetry with other setup subcommands; this command never prompts"
    )]
    pub yes: bool,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
}

/// `opentide setup mcp`.
#[derive(Debug, Args)]
pub struct SetupMcpArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(long = "vscode", help = "Configure VS Code (.vscode/mcp.json)")]
    pub vscode: bool,
    #[arg(long = "cursor", help = "Configure Cursor (.cursor/mcp.json)")]
    pub cursor: bool,
    #[arg(long = "claude-code", help = "Configure Claude Code (.mcp.json)")]
    pub claude_code: bool,
    #[arg(long = "generic", help = "Configure any MCP host (opentide.mcp.json)")]
    pub generic: bool,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide setup hooks`.
#[derive(Debug, Args)]
pub struct SetupHooksArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(
        long = "install",
        help = "Install .git/hooks/pre-commit when this path is a Git repository",
        overrides_with = "no_install"
    )]
    pub install: bool,
    #[arg(
        long = "no-install",
        overrides_with = "install",
        help = "Turn --install off"
    )]
    pub no_install: bool,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide setup env`.
#[derive(Debug, Args)]
pub struct SetupEnvArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide setup ci`.
#[derive(Debug, Args)]
pub struct SetupCiArgs {
    #[arg(
        help = "github, gitlab, or azure",
        ignore_case = true,
        value_name = "ci_platform"
    )]
    pub ci_platform: CiPlatform,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path: String,
    #[arg(
        long = "staging",
        help = "Deploy to staging tenants from pull requests",
        overrides_with = "no_staging"
    )]
    pub staging: bool,
    #[arg(
        long = "no-staging",
        overrides_with = "staging",
        help = "Turn --staging off"
    )]
    pub no_staging: bool,
    #[arg(
        long = "inflight",
        help = "Update .opentide/inflight/ preview shards on pull requests",
        overrides_with = "no_inflight"
    )]
    pub inflight: bool,
    #[arg(
        long = "no-inflight",
        overrides_with = "inflight",
        help = "Turn --inflight off"
    )]
    pub no_inflight: bool,
    #[arg(
        long = "sharing",
        help = "Share changed objects on the default branch (off unless selected)",
        overrides_with = "no_sharing"
    )]
    pub sharing: bool,
    #[arg(
        long = "no-sharing",
        overrides_with = "sharing",
        help = "Turn --sharing off"
    )]
    pub no_sharing: bool,
    #[arg(
        long = "lint-changed",
        help = "Gate lint on the object files each run changes, so a catalogue with inherited findings can adopt it (validate still checks every file)",
        overrides_with = "lint_all"
    )]
    pub lint_changed: bool,
    #[arg(
        long = "lint-all",
        overrides_with = "lint_changed",
        help = "Turn --lint-changed off"
    )]
    pub lint_all: bool,
    #[arg(
        long = "promotion",
        help = "Write [promotion] enabled in deployment.toml. Omit to keep the repository's setting.",
        overrides_with = "no_promotion"
    )]
    pub promotion: bool,
    #[arg(
        long = "no-promotion",
        overrides_with = "promotion",
        help = "Turn --promotion off"
    )]
    pub no_promotion: bool,
    #[arg(
        long = "promotion-target",
        help = "Status deploy promotes rules to. Omit to keep the repository's setting."
    )]
    pub promotion_target: Option<String>,
    #[arg(
        long = "python-version",
        help = "Python version the pipeline installs",
        default_value = "3.12"
    )]
    pub python_version: String,
    #[arg(
        long = "explorer-pages",
        help = "Include GitHub Pages explorer build and deploy jobs",
        overrides_with = "no_explorer_pages"
    )]
    pub explorer_pages: bool,
    #[arg(
        long = "no-explorer-pages",
        overrides_with = "explorer_pages",
        help = "Turn --explorer-pages off"
    )]
    pub no_explorer_pages: bool,
    #[arg(
        long = "default-branch",
        help = "Branch that deploys and receives inflight shards (default: origin/HEAD, then the checked-out branch, then init.defaultBranch, then main; GitLab uses $CI_DEFAULT_BRANCH)"
    )]
    pub default_branch: Option<String>,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide setup platforms`.
#[derive(Debug, Args)]
pub struct SetupPlatformsArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(long = "sentinel", help = "Enable Microsoft Sentinel")]
    pub sentinel: bool,
    #[arg(long = "splunk", help = "Enable Splunk Enterprise Security")]
    pub splunk: bool,
    #[arg(long = "crowdstrike", help = "Enable CrowdStrike Falcon")]
    pub crowdstrike: bool,
    #[arg(
        long = "defender-for-endpoint",
        help = "Enable Microsoft Defender for Endpoint"
    )]
    pub defender_for_endpoint: bool,
    #[arg(long = "sentinel-one", help = "Enable SentinelOne")]
    pub sentinel_one: bool,
    #[arg(long = "carbon-black-cloud", help = "Enable Carbon Black Cloud")]
    pub carbon_black_cloud: bool,
    #[arg(long = "harfanglab", help = "Enable HarfangLab")]
    pub harfanglab: bool,
    #[arg(long = "elastic", help = "Enable Elastic Security")]
    pub elastic: bool,
    #[arg(long = "sysdig", help = "Enable Sysdig Secure (Falco)")]
    pub sysdig: bool,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide setup repo`.
#[derive(Debug, Args)]
pub struct SetupRepoArgs {
    #[arg(
        hide = true,
        help = "Repository path (alias for --path)",
        default_value = ".",
        value_name = "path"
    )]
    pub path: String,
    #[arg(
        long = "path",
        short = 'C',
        help = "Repository path",
        default_value = "."
    )]
    pub path_flag: String,
    #[arg(long = "name", help = "Repository name, used in the README")]
    pub name: Option<String>,
    #[arg(long = "org", help = "Organisation or team, used in the README")]
    pub org: Option<String>,
    #[arg(
        long = "description",
        help = "One-line description, used in the README"
    )]
    pub description: Option<String>,
    #[arg(long = "platform", help = "Enable a detection platform (repeatable): sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig", action = clap::ArgAction::Append, value_name = "PLATFORM")]
    pub platform: Vec<Platform>,
    #[arg(
        long = "plan",
        help = "List the files each step would write, and write nothing"
    )]
    pub plan: bool,
    #[arg(
        long = "yes",
        short = 'y',
        help = "Write without asking for confirmation"
    )]
    pub yes: bool,
}

/// `opentide share`.
#[derive(Debug, Args)]
pub struct ShareArgs {
    #[arg(long = "target", help = "Destination block name. Repeatable.", action = clap::ArgAction::Append)]
    pub target: Vec<String>,
    #[arg(long = "uuid", help = "Limit to these object UUIDs.", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Limit to threat, objective, or rule.", action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "file", help = "Limit to these object files.", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(
        long = "dry-run",
        help = "Resolve the run locally and make no request."
    )]
    pub dry_run: bool,
    #[arg(
        long = "publish",
        help = "Override the block publish flag.",
        overrides_with = "no_publish"
    )]
    pub publish: bool,
    #[arg(
        long = "no-publish",
        overrides_with = "publish",
        help = "Turn --publish off"
    )]
    pub no_publish: bool,
    #[arg(
        long = "workers",
        help = "Parallel object workers for one destination.",
        default_value = "1"
    )]
    pub workers: i64,
    #[arg(
        long = "changed",
        help = "Share only objects the default-branch CI diff changed."
    )]
    pub changed: bool,
    #[arg(
        long = "since",
        help = "With --changed: diff from this commit SHA or ref to HEAD.",
        value_name = "COMMIT"
    )]
    pub since: Option<String>,
    #[command(subcommand)]
    pub command: Option<ShareCommand>,
}

/// `opentide share targets`.
#[derive(Debug, Args)]
pub struct ShareTargetsArgs {}

/// `opentide share retract`.
#[derive(Debug, Args)]
pub struct ShareRetractArgs {
    #[arg(long = "target", help = "Destination block name. Repeatable.", action = clap::ArgAction::Append)]
    pub target: Vec<String>,
    #[arg(long = "uuid", help = "Limit to these object UUIDs.", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Limit to threat, objective, or rule.", action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "file", help = "Limit to these object files.", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(
        long = "delete",
        help = "Delete the remote event instead of unpublishing it."
    )]
    pub delete: bool,
    #[arg(long = "yes", help = "Confirm --delete.")]
    pub yes: bool,
    #[arg(
        long = "workers",
        help = "Parallel object workers for one destination.",
        default_value = "1"
    )]
    pub workers: i64,
}

/// `opentide share status`.
#[derive(Debug, Args)]
pub struct ShareStatusArgs {
    #[arg(long = "target", help = "Destination block name. Repeatable.", action = clap::ArgAction::Append)]
    pub target: Vec<String>,
    #[arg(long = "uuid", help = "Limit to these object UUIDs.", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Limit to threat, objective, or rule.", action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "file", help = "Limit to these object files.", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
}

/// `opentide share preview`.
#[derive(Debug, Args)]
pub struct SharePreviewArgs {
    #[arg(long = "target", help = "Destination block name. Repeatable.", action = clap::ArgAction::Append)]
    pub target: Vec<String>,
    #[arg(long = "uuid", help = "Limit to these object UUIDs.", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Limit to threat, objective, or rule.", action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "file", help = "Limit to these object files.", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(
        long = "workers",
        help = "Parallel object workers for one destination.",
        default_value = "1"
    )]
    pub workers: i64,
}

/// `opentide share push`.
#[derive(Debug, Args)]
pub struct SharePushArgs {
    #[arg(long = "target", help = "Destination block name. Repeatable.", action = clap::ArgAction::Append)]
    pub target: Vec<String>,
    #[arg(long = "uuid", help = "Limit to these object UUIDs.", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Limit to threat, objective, or rule.", action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "file", help = "Limit to these object files.", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(
        long = "dry-run",
        help = "Resolve the run locally and make no request."
    )]
    pub dry_run: bool,
    #[arg(
        long = "publish",
        help = "Override the block publish flag.",
        overrides_with = "no_publish"
    )]
    pub publish: bool,
    #[arg(
        long = "no-publish",
        overrides_with = "publish",
        help = "Turn --publish off"
    )]
    pub no_publish: bool,
    #[arg(
        long = "workers",
        help = "Parallel object workers for one destination.",
        default_value = "1"
    )]
    pub workers: i64,
    #[arg(
        long = "changed",
        help = "Share only objects the default-branch CI diff changed."
    )]
    pub changed: bool,
    #[arg(
        long = "since",
        help = "With --changed: diff from this commit SHA or ref to HEAD.",
        value_name = "COMMIT"
    )]
    pub since: Option<String>,
}

/// `opentide deploy`.
#[derive(Debug, Args)]
pub struct DeployArgs {
    #[arg(
        long = "platform",
        help = "Detection platform: sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig",
        value_name = "PLATFORM"
    )]
    pub platform: Option<Platform>,
    #[arg(long = "strategy", help = "Status strategy this run deploys (repeatable). PREVIEW: rules whose status maps to PREVIEW or UNIVERSAL. RELEASE: rules whose status maps to RELEASE or UNIVERSAL, and disables or deletes those mapping to DISABLEMENT or DELETION. Each rule goes to the tenants whose 'strategies' accept the run's strategy. Status names such as STAGING or PRODUCTION are not strategies", action = clap::ArgAction::Append)]
    pub strategy: Vec<String>,
    #[arg(
        long = "all",
        help = "Read every rule file, not only those the run changed (the pull or merge request, the push, or outside CI the last commit)"
    )]
    pub all_files: bool,
    #[arg(long = "uuid", help = "Read this rule (metadata.uuid) instead of the changed ones (repeatable). Cannot be combined with --all", action = clap::ArgAction::Append)]
    pub uuids: Vec<String>,
    #[arg(long = "file", help = "Read this rule file, matched as by 'opentide validate --file', instead of the changed ones (repeatable). Cannot be combined with --all", action = clap::ArgAction::Append)]
    pub files: Vec<String>,
    #[arg(long = "plan", hide = true, help = "Removed in 0.17.0; use --strategy")]
    pub plan: Option<String>,
    #[arg(
        long = "wide",
        help = "Deploy the rule files read whatever their status strategy, INERT included"
    )]
    pub wide: bool,
    #[arg(
        long = "dry-run",
        help = "Print the plan and compile each rule; send nothing"
    )]
    pub dry_run: bool,
    #[arg(
        long = "keep-deprecated",
        help = "Include rules whose status maps to DISABLEMENT or DELETION, so a RELEASE run disables or deletes them. Default: on, off with --all",
        overrides_with = "drop_deprecated"
    )]
    pub keep_deprecated: bool,
    #[arg(
        long = "drop-deprecated",
        overrides_with = "keep_deprecated",
        help = "Turn --keep-deprecated off"
    )]
    pub drop_deprecated: bool,
    #[arg(
        long = "skip-promotion",
        help = "Skip the status promotion of a RELEASE run on a push"
    )]
    pub skip_promotion: bool,
    #[arg(
        long = "skip-unconfigured",
        help = "Exit 0 when every platform with rules to deploy has no [[tenants]] block"
    )]
    pub skip_unconfigured: bool,
    #[arg(
        long = "persist-state-externally",
        help = "Allow Defender, SentinelOne and CrowdStrike creates in a CI run other than a RELEASE run on a push; this pipeline must commit .opentide/states/deployment/ itself"
    )]
    pub persist_state_externally: bool,
    #[command(subcommand)]
    pub command: Option<DeployCommand>,
}

/// `opentide deploy metadata`.
#[derive(Debug, Args)]
pub struct DeployMetadataArgs {
    #[arg(
        long = "platform",
        help = "Detection platform: sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig",
        value_name = "PLATFORM"
    )]
    pub platform: Platform,
}

/// `opentide deploy replay-state`.
#[derive(Debug, Args)]
pub struct DeployReplayStateArgs {
    #[arg(
        help = "Commit whose deployment-state changes to replay",
        value_name = "state_commit"
    )]
    pub state_commit: String,
}

/// `opentide deploy migrate-state`.
#[derive(Debug, Args)]
pub struct DeployMigrateStateArgs {}

/// `opentide rules`.
#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: Option<RulesCommand>,
}

/// `opentide rules unreviewed`.
#[derive(Debug, Args)]
pub struct RulesUnreviewedArgs {
    #[arg(
        long = "older-than",
        help = "Positive review window (90d, 12h, 30m). A review equal to T-W is fresh.",
        default_value = "90d"
    )]
    pub older_than: String,
}

/// `opentide generate`.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[command(subcommand)]
    pub command: Option<GenerateCommand>,
}

/// `opentide generate inflight`.
#[derive(Debug, Args)]
pub struct GenerateInflightArgs {
    #[command(subcommand)]
    pub command: Option<GenerateInflightCommand>,
}

/// `opentide generate inflight prune`.
#[derive(Debug, Args)]
pub struct GenerateInflightPruneArgs {}

/// `opentide generate extract`.
#[derive(Debug, Args)]
pub struct GenerateExtractArgs {
    #[command(subcommand)]
    pub command: Option<GenerateExtractCommand>,
}

/// `opentide generate extract elastic`.
#[derive(Debug, Args)]
pub struct GenerateExtractElasticArgs {
    #[arg(long = "space", help = "Kibana space ID", default_value = "default")]
    pub space: String,
    #[arg(
        long = "include-prebuilt",
        help = "Include prebuilt rules converted to custom rules with derived UUIDs",
        overrides_with = "custom_only"
    )]
    pub include_prebuilt: bool,
    #[arg(
        long = "custom-only",
        overrides_with = "include_prebuilt",
        help = "Turn --include-prebuilt off"
    )]
    pub custom_only: bool,
}

/// `opentide generate extract defender`.
#[derive(Debug, Args)]
pub struct GenerateExtractDefenderArgs {}

/// `opentide generate extract sentinel`.
#[derive(Debug, Args)]
pub struct GenerateExtractSentinelArgs {}

/// `opentide generate exports`.
#[derive(Debug, Args)]
pub struct GenerateExportsArgs {
    #[command(subcommand)]
    pub command: Option<GenerateExportsCommand>,
}

/// `opentide generate exports revisions`.
#[derive(Debug, Args)]
pub struct GenerateExportsRevisionsArgs {}

/// `opentide generate exports objects`.
#[derive(Debug, Args)]
pub struct GenerateExportsObjectsArgs {}

/// `opentide generate exports navigator`.
#[derive(Debug, Args)]
pub struct GenerateExportsNavigatorArgs {}

/// `opentide generate docs`.
#[derive(Debug, Args)]
pub struct GenerateDocsArgs {
    #[arg(
        long = "output",
        help = "Write the pages here instead of the configured docs folder"
    )]
    pub output: Option<String>,
    #[arg(
        long = "flavor",
        help = "Markdown flavour: github, gitlab, azure_devops or generic"
    )]
    pub flavor: Option<String>,
    #[arg(
        long = "rules",
        help = "Only rule pages; combine with --threats, --objectives"
    )]
    pub rules: bool,
    #[arg(
        long = "threats",
        help = "Only threat pages; combine with --rules, --objectives"
    )]
    pub threats: bool,
    #[arg(
        long = "objectives",
        help = "Only objective pages; combine with --rules, --threats"
    )]
    pub objectives: bool,
    #[arg(
        long = "changed",
        help = "Regenerate only the pages of objects git reports as changed"
    )]
    pub changed: bool,
    #[command(subcommand)]
    pub command: Option<GenerateDocsCommand>,
}

/// `opentide generate docs index`.
#[derive(Debug, Args)]
pub struct GenerateDocsIndexArgs {
    #[arg(
        long = "output",
        help = "Write the pages here instead of the configured docs folder"
    )]
    pub output: Option<String>,
    #[arg(
        long = "flavor",
        help = "Markdown flavour: github, gitlab, azure_devops or generic"
    )]
    pub flavor: Option<String>,
}

/// `opentide generate docs threats`.
#[derive(Debug, Args)]
pub struct GenerateDocsThreatsArgs {
    #[arg(
        long = "output",
        help = "Write the pages here instead of the configured docs folder"
    )]
    pub output: Option<String>,
    #[arg(
        long = "flavor",
        help = "Markdown flavour: github, gitlab, azure_devops or generic"
    )]
    pub flavor: Option<String>,
}

/// `opentide generate docs objectives`.
#[derive(Debug, Args)]
pub struct GenerateDocsObjectivesArgs {
    #[arg(
        long = "output",
        help = "Write the pages here instead of the configured docs folder"
    )]
    pub output: Option<String>,
    #[arg(
        long = "flavor",
        help = "Markdown flavour: github, gitlab, azure_devops or generic"
    )]
    pub flavor: Option<String>,
}

/// `opentide generate docs rules`.
#[derive(Debug, Args)]
pub struct GenerateDocsRulesArgs {
    #[arg(
        long = "output",
        help = "Write the pages here instead of the configured docs folder"
    )]
    pub output: Option<String>,
    #[arg(
        long = "flavor",
        help = "Markdown flavour: github, gitlab, azure_devops or generic"
    )]
    pub flavor: Option<String>,
}

/// `opentide generate explorer`.
#[derive(Debug, Args)]
pub struct GenerateExplorerArgs {
    #[arg(
        long = "include-visibility",
        help = "Also write explorer.visibility.json: the log sources visibility.toml declares and the rules that use them. Off by default: it shows what you cannot see. A run without it removes the file"
    )]
    pub include_visibility: bool,
    #[arg(
        long = "visibility-tlp",
        help = "The TLP the explorer shows on the Visibility view: clear, green, amber, amber+strict or red",
        default_value = "amber"
    )]
    pub visibility_tlp: String,
}

/// `opentide new`.
#[derive(Debug, Args)]
pub struct NewArgs {
    #[command(subcommand)]
    pub command: Option<NewCommand>,
}

/// `opentide new rule`.
#[derive(Debug, Args)]
pub struct NewRuleArgs {
    #[arg(long = "name", help = "Object name; the filename is its slug")]
    pub name: Option<String>,
    #[arg(long = "platform", help = "Add a configuration block for this platform (repeatable): sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig", action = clap::ArgAction::Append, value_name = "PLATFORM")]
    pub platform: Vec<Platform>,
    #[arg(
        long = "objective",
        help = "UUID of the objective this rule implements (detection_model)"
    )]
    pub objective: Option<String>,
    #[arg(
        long = "path",
        help = "File to write, or a folder to write it in (default: the family's objects folder)"
    )]
    pub path: Option<String>,
}

/// `opentide new objective`.
#[derive(Debug, Args)]
pub struct NewObjectiveArgs {
    #[arg(long = "name", help = "Object name; the filename is its slug")]
    pub name: Option<String>,
    #[arg(long = "threat", help = "UUID of a threat this objective addresses (repeatable)", action = clap::ArgAction::Append)]
    pub threat: Vec<String>,
    #[arg(
        long = "path",
        help = "File to write, or a folder to write it in (default: the family's objects folder)"
    )]
    pub path: Option<String>,
}

/// `opentide new threat`.
#[derive(Debug, Args)]
pub struct NewThreatArgs {
    #[arg(long = "name", help = "Object name; the filename is its slug")]
    pub name: Option<String>,
    #[arg(
        long = "path",
        help = "File to write, or a folder to write it in (default: the family's objects folder)"
    )]
    pub path: Option<String>,
}

/// `opentide info`.
#[derive(Debug, Args)]
pub struct InfoArgs {
    #[arg(
        long = "platform",
        help = "Detection platform: sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig",
        value_name = "PLATFORM"
    )]
    pub platform: Option<Platform>,
    // Checked by the command, with its own message: `tree_meta::CHOICES`
    // gives the catalogue its choices.
    #[arg(value_name = "section")]
    pub section: Option<String>,
    #[arg(
        help = "Vocabulary to inspect, with the vocab section (e.g. surface)",
        value_name = "name"
    )]
    pub name: Option<String>,
    #[arg(
        long = "technique",
        help = "ATT&CK technique ID for the coverage section (T1059)"
    )]
    pub technique: Option<String>,
    #[arg(long = "strict", help = "Exit non-zero when any object failed to load")]
    pub strict: bool,
}

/// `opentide lint`.
#[derive(Debug, Args)]
pub struct LintArgs {
    #[arg(long = "fix", help = "Apply safe filename renames")]
    pub fix: bool,
    #[arg(long = "strict", help = "Exit non-zero when findings exist (CI gate)")]
    pub strict: bool,
    #[arg(long = "check", help = "Limit to one check: filenames, metadata, placeholders or queries (repeatable). Runs it even when lint.toml disables it", action = clap::ArgAction::Append, value_name = "CHECK")]
    pub check: Vec<Check2>,
    #[arg(
        long = "changed",
        help = "Lint only the object files this run changed: the pull or merge request, the push, or outside CI the last commit (the diff deploy reads)"
    )]
    pub changed: bool,
    #[arg(long = "file", help = "Lint only this object file (repeatable)", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(
        long = "format",
        help = "text: code frames. sarif: SARIF 2.1.0 for code scanning. codequality: GitLab Code Quality (Code Climate JSON). A report goes to --output, or to stdout instead of the text",
        default_value = "text"
    )]
    pub report_format: ReportFormat,
    #[arg(
        long = "output",
        help = "Write the --format report to this file and print the usual text output too"
    )]
    pub output: Option<std::path::PathBuf>,
}

/// `opentide query`.
#[derive(Debug, Args)]
pub struct QueryArgs {
    #[arg(
        help = "The query, in the platform's language. '-' reads it from stdin",
        value_name = "query"
    )]
    pub query: Option<String>,
    #[arg(
        long = "platform",
        help = "Detection platform: sentinel, splunk, crowdstrike, defender_for_endpoint, sentinel_one, carbon_black_cloud, harfanglab, elastic, sysdig",
        value_name = "PLATFORM"
    )]
    pub platform: Platform,
    #[arg(long = "tenant", help = "Run on this tenant (repeatable), or 'all'. Default: the only tenant configured", action = clap::ArgAction::Append)]
    pub tenant: Vec<String>,
    #[arg(
        long = "rule",
        help = "Run the query this rule (by UUID) deploys to the platform"
    )]
    pub rule: Option<String>,
    #[arg(long = "file", help = "Run the query of the rule in this file")]
    pub file: Option<String>,
    #[arg(long = "query-file", help = "Read the query from this file")]
    pub query_file: Option<String>,
    #[arg(
        long = "since",
        help = "Look back this far from --to or now: 15m, 24h, 7d, PT1H. Default: 24h"
    )]
    pub since: Option<String>,
    #[arg(
        long = "from",
        help = "Start of the window, ISO-8601 (UTC unless it names an offset)"
    )]
    pub start: Option<String>,
    #[arg(long = "to", help = "End of the window, ISO-8601. Default: now")]
    pub end: Option<String>,
    #[arg(
        long = "limit",
        help = "Rows per tenant, at most 5000",
        default_value = "100"
    )]
    pub limit: i64,
    #[arg(
        long = "language",
        help = "Elastic only: esql (default), eql, lucene or kuery"
    )]
    pub language: Option<String>,
    #[arg(long = "index", help = "Elastic index pattern or CrowdStrike repository (repeatable)", action = clap::ArgAction::Append)]
    pub index: Vec<String>,
    #[arg(
        long = "timeout",
        help = "Seconds to wait for a search to finish",
        default_value = "120.0"
    )]
    pub timeout: f64,
    #[arg(long = "columns", help = "Comma-separated columns the table shows")]
    pub columns: Option<String>,
    #[arg(
        long = "format",
        help = "table, jsonl or csv (--json prints the envelope)",
        default_value = "table"
    )]
    pub row_format: RowFormat,
}

/// `opentide validate`.
#[derive(Debug, Args)]
pub struct ValidateArgs {
    #[arg(
        long = "check",
        help = "Run one check only: id-uniqueness, uuid-format, schema, cve, sharing-config, configuration, queries",
        value_name = "CHECK"
    )]
    pub check: Option<Check>,
    #[arg(long = "file", help = "Validate only this file (repeatable)", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(long = "uuid", help = "Validate only the object with this UUID (repeatable)", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "type", help = "Validate only this type: rule, threat or objective (repeatable)", value_parser = CommandChecked(&["rule", "threat", "objective"]), action = clap::ArgAction::Append)]
    pub object_type: Vec<String>,
    #[arg(long = "strict", help = "Fail on warnings too")]
    pub strict: bool,
    #[arg(
        long = "queries",
        help = "How a query the platform would reject is reported: error (the default), warn (passes unless --strict) or off (queries are not checked)",
        value_name = "error|warn|off"
    )]
    pub queries: Option<Queries>,
    #[arg(
        long = "fix",
        help = "Apply every safe fix (vocabulary typos), then validate again"
    )]
    pub fix: bool,
    #[arg(
        long = "dry-run",
        help = "With --fix: print the edits as a diff and change nothing"
    )]
    pub dry_run: bool,
    #[arg(
        long = "watch",
        help = "Validate again each time an object file changes; Ctrl-C stops"
    )]
    pub watch: bool,
    #[arg(
        long = "format",
        help = "text: code frames. sarif: SARIF 2.1.0 for code scanning. codequality: GitLab Code Quality (Code Climate JSON). A report goes to --output, or to stdout instead of the text",
        default_value = "text"
    )]
    pub report_format: ReportFormat,
    #[arg(
        long = "output",
        help = "Write the --format report to this file and print the usual text output too"
    )]
    pub output: Option<std::path::PathBuf>,
    #[command(subcommand)]
    pub command: Option<ValidateCommand>,
}

/// `opentide validate query`.
#[derive(Debug, Args)]
pub struct ValidateQueryArgs {
    #[arg(
        long = "platform",
        help = "Check this platform's queries. Offline, default every platform the engine parses: carbon_black_cloud, crowdstrike, defender_for_endpoint, elastic, sentinel, splunk, sysdig. --live needs one of: carbon_black_cloud, defender_for_endpoint, elastic, sentinel, sentinel_one, splunk",
        value_name = "PLATFORM"
    )]
    pub platform: Option<Platform>,
    #[arg(long = "strategy", help = "Check only rules a run with this strategy deploys (repeatable), on the tenants that accept it. Default: PREVIEW and RELEASE", action = clap::ArgAction::Append)]
    pub strategy: Vec<String>,
    #[arg(long = "plan", hide = true, help = "Removed in 0.17.0; use --strategy")]
    pub plan: Option<String>,
    #[arg(
        long = "wide",
        help = "Check every status strategy but DISABLEMENT and DELETION (--live)"
    )]
    pub wide: bool,
    #[arg(
        long = "live",
        help = "Check the queries on the platform's tenants (needs credentials)"
    )]
    pub live: bool,
    #[arg(
        long = "changed",
        help = "Check only the rule files this run changed: the pull or merge request, the push, or outside CI the last commit (the files deploy reads)"
    )]
    pub changed: bool,
    #[arg(long = "file", help = "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, .lucene, .falco, .cql) offline (repeatable)", action = clap::ArgAction::Append)]
    pub file: Vec<String>,
    #[arg(long = "uuid", help = "Check only the rule with this UUID (repeatable)", action = clap::ArgAction::Append)]
    pub uuid: Vec<String>,
    #[arg(long = "strict", help = "Fail on warnings too")]
    pub strict: bool,
    #[arg(
        long = "queries",
        help = "How a rejected query is reported offline: error (the default) or warn",
        value_name = "error|warn"
    )]
    pub queries: Option<Queries>,
    #[arg(
        long = "check-timeout",
        help = "Seconds each query may take on a tenant before its check fails (--live; default: OPENTIDE_QUERY_CHECK_TIMEOUT, else 120)",
        value_name = "SECONDS"
    )]
    pub check_timeout: Option<String>,
}

/// The subcommands of `opentide`.
#[derive(Debug, Subcommand)]
pub enum RootCommand {
    #[command(
        name = "validate",
        about = "Validate objects and queries",
        after_help = "Examples:\n  $ opentide validate\n  $ opentide validate --strict --type rule\n  $ opentide validate --queries warn",
        subcommand_value_name = "COMMAND"
    )]
    Validate(ValidateArgs),
    #[command(
        name = "query",
        about = "Run a read-only query on platform tenants and show rows",
        long_about = "Run a read-only query on platform tenants and show rows\n\nSends the query, or a rule's query, to each selected tenant over the\nwindow and prints at most --limit rows per tenant. No search or rule is\nsaved on the tenant.",
        after_help = "Examples:\n  $ opentide query --platform sentinel 'SecurityEvent | take 10'\n  $ opentide query --platform splunk --rule <rule-uuid> --tenant all --since 7d\n  $ opentide query --platform elastic --language eql --index 'logs-*' --format jsonl 'process where process.name == \"cmd.exe\"'"
    )]
    Query(QueryArgs),
    #[command(
        name = "lint",
        about = "Check file names and recommended metadata",
        long_about = "Check file names and recommended metadata\n\nCatalogue hygiene: filename slugs and recommended metadata, not schema validation.",
        after_help = "Examples:\n  $ opentide lint\n  $ opentide lint --fix"
    )]
    Lint(LintArgs),
    #[command(
        name = "info",
        about = "Show repository and platform information",
        after_help = "Examples:\n  $ opentide info\n  $ opentide info --platform sentinel"
    )]
    Info(InfoArgs),
    #[command(
        name = "new",
        about = "Scaffold a threat, objective or rule from its template",
        long_about = "Scaffold a threat, objective or rule from its template\n\nThe new file gets a fresh UUID, today's date, your git author and the catalogue's organisation, and is named the way opentide lint expects. Required values nobody has chosen yet are placeholders, listed in the output: replace them, then run opentide validate --file on the path.",
        after_help = "Examples:\n  $ opentide new threat --name \"Credential Dumping\"",
        subcommand_required = true,
        arg_required_else_help = true,
        subcommand_value_name = "COMMAND"
    )]
    New(NewArgs),
    #[command(
        name = "generate",
        about = "Generate schemas, templates, docs and exports",
        long_about = "Generate schemas, templates, docs and exports\n\nRun with no argument for the full pipeline, or name one or more phases to run only those, in the order given: schemas, templates, vocabs, snippets.\n\nRegenerate editor schemas without paying for documentation: `opentide generate schemas templates vocabs snippets`.",
        after_help = "Examples:\n  $ opentide generate\n  $ opentide generate schemas templates",
        subcommand_value_name = "COMMAND"
    )]
    Generate(GenerateArgs),
    #[command(
        name = "rules",
        about = "Detection rule maintenance",
        after_help = "Examples:\n  $ opentide rules unreviewed --older-than 90d",
        subcommand_required = true,
        subcommand_value_name = "COMMAND"
    )]
    Rules(RulesArgs),
    #[command(
        name = "deploy",
        about = "Deploy rules to platform tenants",
        after_help = "Examples:\n  $ opentide deploy --strategy PREVIEW --all --dry-run\n  $ opentide deploy --strategy RELEASE",
        subcommand_value_name = "COMMAND"
    )]
    Deploy(DeployArgs),
    #[command(
        name = "share",
        about = "Publish objects to intelligence platforms",
        after_help = "Examples:\n  $ opentide share --dry-run\n  $ opentide share --target misp-prod",
        subcommand_value_name = "COMMAND"
    )]
    Share(ShareArgs),
    #[command(
        name = "setup",
        about = "Set up a detection repository and its tooling",
        after_help = "Examples:\n  $ opentide setup\n  $ opentide setup --yes --name \"Detections\" --platform sentinel --ci github\n  $ opentide setup --plan --platform sentinel --mcp vscode --hooks --env",
        subcommand_value_name = "COMMAND"
    )]
    Setup(SetupArgs),
    #[command(
        name = "doctor",
        about = "Check the installation, the workspace and its integrations",
        long_about = "Check the installation, the workspace and its integrations\n\nEach check prints a status, what it found and, when something needs doing,\nthe command that fixes it. Credentials are reported as set or unset, never\nprinted. Exits 1 when any check fails; warnings alone exit 0.",
        after_help = "Examples:\n  $ opentide doctor\n  $ opentide doctor --offline\n  $ opentide --json doctor"
    )]
    Doctor(DoctorArgs),
    #[command(
        name = "migrate",
        about = "Rewrite objects for a newer opentide model",
        after_help = "Examples:\n  $ opentide migrate vocab-scope\n  $ opentide migrate vocab-scope --apply",
        subcommand_required = true,
        subcommand_value_name = "COMMAND"
    )]
    Migrate(MigrateArgs),
    #[command(
        name = "tui",
        about = "Browse the catalogue and its diagnostics in a terminal UI",
        long_about = "Browse the catalogue and its diagnostics in a terminal UI\n\nA tree of threats, objectives and rules, each object's YAML and the\ndiagnostics from the last validate run, and coverage by ATT&CK technique.\nRun validate, generate and deploy --dry-run from the command palette\n(ctrl+p) or their keys. Needs an interactive terminal: it exits 2 under\n--json, in a pipe, in CI or under a coding agent.",
        after_help = "Examples:\n  $ opentide tui\n  $ opentide --repo path/to/detections tui"
    )]
    Tui(TuiArgs),
    #[command(
        name = "explain",
        about = "Explain a diagnostic code and how to fix it",
        long_about = "Explain a diagnostic code and how to fix it\n\nPrints what the code means, an example, and how to fix it.",
        after_help = "Examples:\n  $ opentide explain vocab_unknown\n  $ opentide explain"
    )]
    Explain(ExplainArgs),
    #[command(
        name = "commands",
        about = "List every command and option, for agents",
        long_about = "List every command and option, for agents\n\nEach command comes with its arguments, options (types, choices, defaults,\nenvironment variables) and an example. Add --json for the whole tree in one\ndocument.",
        after_help = "Examples:\n  $ opentide commands\n  $ opentide --json commands"
    )]
    Commands(CommandsArgs),
    #[command(
        name = "mcp",
        about = "Run the opentide MCP server for editors and agents",
        long_about = "Run the opentide MCP server for editors and agents\n\nThe server speaks on stdio. The editor owns the process: stop is the host closing stdin, and reload is the host spawning this command again. There is no reload or stop subcommand.",
        after_help = "Examples:\n  $ opentide mcp start",
        subcommand_required = true,
        arg_required_else_help = true,
        subcommand_value_name = "COMMAND"
    )]
    Mcp(McpArgs),
    #[command(
        name = "lsp",
        about = "Serve the language server for editors",
        long_about = "Serve the language server for editors\n\nThe server is the analysis engine that pip install opentide installs: KQL, SPL, ES|QL, EQL, Kibana KQL, Lucene and Tide YAML. The editor owns the process and speaks the protocol on stdio. On the command line, opentide validate and opentide lint report what it finds.",
        after_help = "Examples:\n  $ opentide lsp start",
        subcommand_required = true,
        arg_required_else_help = true,
        subcommand_value_name = "COMMAND"
    )]
    Lsp(LspArgs),
    #[command(
        name = "serve",
        about = "Run CLI commands in one warm process, for editors",
        long_about = "Run CLI commands in one warm process, for editors\n\nJSON-RPC 2.0 on stdio, one message per line. Each run request executes a\ncommand as opentide --json would and answers with its document and exit\ncode, without starting Python and rebuilding the registry each time. The\neditor owns the process: it ends on exit or when stdin closes. stdout\ncarries the protocol only; logs go to stderr.",
        after_help = "Examples:\n  $ opentide serve"
    )]
    Serve(ServeArgs),
    #[command(
        name = "document",
        about = "[deprecated] Use opentide generate docs",
        hide = true,
        subcommand_value_name = "COMMAND"
    )]
    Document(DocumentArgs),
    #[command(
        name = "export",
        about = "[deprecated] Use opentide generate exports",
        hide = true,
        subcommand_required = true,
        subcommand_value_name = "COMMAND"
    )]
    Export(ExportArgs),
    #[command(
        name = "extract",
        about = "[deprecated] Use opentide generate extract",
        hide = true,
        subcommand_required = true,
        subcommand_value_name = "COMMAND"
    )]
    Extract(ExtractArgs),
}

/// The subcommands of `opentide extract`.
#[derive(Debug, Subcommand)]
pub enum ExtractCommand {
    #[command(name = "sentinel", about = "")]
    Sentinel(ExtractSentinelArgs),
    #[command(name = "defender", about = "")]
    Defender(ExtractDefenderArgs),
}

/// The subcommands of `opentide export`.
#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    #[command(name = "navigator", about = "")]
    Navigator(ExportNavigatorArgs),
    #[command(name = "objects", about = "")]
    Objects(ExportObjectsArgs),
    #[command(name = "revisions", about = "")]
    Revisions(ExportRevisionsArgs),
}

/// The subcommands of `opentide document`.
#[derive(Debug, Subcommand)]
pub enum DocumentCommand {
    #[command(name = "rules", about = "")]
    Rules(DocumentRulesArgs),
    #[command(name = "objectives", about = "")]
    Objectives(DocumentObjectivesArgs),
    #[command(name = "threats", about = "")]
    Threats(DocumentThreatsArgs),
    #[command(name = "index", about = "")]
    Index(DocumentIndexArgs),
}

/// The subcommands of `opentide lsp`.
#[derive(Debug, Subcommand)]
pub enum LspCommand {
    #[command(
        name = "start",
        about = "Serve LSP on stdio until the editor closes stdin",
        long_about = "Serve the language server protocol on stdio until the editor closes stdin.",
        after_help = "Examples:\n  $ opentide lsp start"
    )]
    Start(LspStartArgs),
}

/// The subcommands of `opentide mcp`.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    #[command(
        name = "start",
        about = "Serve MCP on stdio until the host closes stdin",
        long_about = "Block on stdio until the host closes stdin. stdout is JSON-RPC only.",
        after_help = "Examples:\n  $ opentide mcp start"
    )]
    Start(McpStartArgs),
}

/// The subcommands of `opentide migrate`.
#[derive(Debug, Subcommand)]
pub enum MigrateCommand {
    #[command(
        name = "vocab-scope",
        about = "Re-prefix stage-scoped vocabulary values",
        long_about = "Re-prefix stage-scoped vocabulary values (`Process` -> `Host::Process`).\n\nApplies only mechanical outcomes: a key defined under exactly one stage,\nand a stage whose casing drifted. A key defined under several stages is\nreported, never guessed. Exits 2 when anything is left for a human.",
        after_help = "Examples:\n  $ opentide migrate vocab-scope\n  $ opentide migrate vocab-scope --apply"
    )]
    VocabScope(MigrateVocabScopeArgs),
}

/// The subcommands of `opentide setup`.
#[derive(Debug, Subcommand)]
pub enum SetupCommand {
    #[command(
        name = "repo",
        about = "Scaffold a detection repository",
        long_about = "Scaffold a detection repository.",
        after_help = "Examples:\n  $ opentide setup repo --yes --name \"Detections\" --platform sentinel"
    )]
    Repo(SetupRepoArgs),
    #[command(
        name = "platforms",
        about = "Enable platform configuration files",
        long_about = "Create and enable platform configuration files in `.opentide/configurations/platforms/`.",
        after_help = "Examples:\n  $ opentide setup platforms --sentinel --splunk --yes"
    )]
    Platforms(SetupPlatformsArgs),
    #[command(
        name = "ci",
        about = "Write CI/CD pipeline files",
        long_about = "Generate CI/CD pipeline files (platforms discovered from repo config).",
        after_help = "Examples:\n  $ opentide setup ci github --yes"
    )]
    Ci(SetupCiArgs),
    #[command(
        name = "env",
        about = "Write .env.example and ignore .env",
        long_about = "Write `.env.example` with `OPENTIDE_REPO_ROOT` and ignore `.env`.",
        after_help = "Examples:\n  $ opentide setup env --yes"
    )]
    Env(SetupEnvArgs),
    #[command(
        name = "hooks",
        about = "Validate objects on every commit",
        long_about = "Configure validate-on-commit hooks (pre-commit config + Git hook).",
        after_help = "Examples:\n  $ opentide setup hooks --yes"
    )]
    Hooks(SetupHooksArgs),
    #[command(
        name = "mcp",
        about = "Write MCP configuration for editors and agents",
        long_about = "Write opentide MCP configuration for editors and agents.",
        after_help = "Examples:\n  $ opentide setup mcp --vscode --yes"
    )]
    Mcp(SetupMcpArgs),
    #[command(
        name = "vscode",
        about = "Write VS Code schemas and snippets (deprecated)",
        long_about = "Recommend the opentide extension and write snippets (deprecated). Default: both.",
        after_help = "Examples:\n  $ opentide setup vscode --settings"
    )]
    Vscode(SetupVscodeArgs),
    #[command(
        name = "skills",
        about = "Discover and install agent skills",
        long_about = "Agent skills discovery and installation",
        after_help = "Examples:\n  $ opentide setup skills --claude-code --yes",
        subcommand_value_name = "COMMAND"
    )]
    Skills(SetupSkillsArgs),
}

/// The subcommands of `opentide setup skills`.
#[derive(Debug, Subcommand)]
pub enum SetupSkillsCommand {
    #[command(
        name = "discover",
        about = "List the skills in the opentidehq/skills catalogue",
        long_about = "List skills from the opentidehq/skills catalogue.",
        after_help = "Examples:\n  $ opentide setup skills discover --query sigma"
    )]
    Discover(SetupSkillsDiscoverArgs),
    #[command(
        name = "show",
        about = "Show one skill from the catalogue",
        long_about = "Show details for one skill from the catalogue.",
        after_help = "Examples:\n  $ opentide setup skills show <slug>"
    )]
    Show(SetupSkillsShowArgs),
}

/// The subcommands of `opentide share`.
#[derive(Debug, Subcommand)]
pub enum ShareCommand {
    #[command(
        name = "push",
        about = "Create or update one MISP event per selected object",
        long_about = "Create or update one MISP Event per selected Tide object.",
        after_help = "Examples:\n  $ opentide share push --target misp-prod"
    )]
    Push(SharePushArgs),
    #[command(
        name = "preview",
        about = "Show what push would do, without a request",
        long_about = "Show what push would do. Makes no request and writes nothing.",
        after_help = "Examples:\n  $ opentide share preview"
    )]
    Preview(SharePreviewArgs),
    #[command(
        name = "status",
        about = "Compare the local ledger with object versions",
        long_about = "Compare the local ledger with object versions. Does not contact the destination.",
        after_help = "Examples:\n  $ opentide share status"
    )]
    Status(ShareStatusArgs),
    #[command(
        name = "retract",
        about = "Unpublish or delete a shared event",
        long_about = "Unpublish a shared event, or delete it when `--delete --yes` is set.",
        after_help = "Examples:\n  $ opentide share retract --uuid <uuid>"
    )]
    Retract(ShareRetractArgs),
    #[command(
        name = "targets",
        about = "List sharing destinations, never their API keys",
        long_about = "List sharing destinations. The API key is never printed.",
        after_help = "Examples:\n  $ opentide share targets"
    )]
    Targets(ShareTargetsArgs),
}

/// The subcommands of `opentide deploy`.
#[derive(Debug, Subcommand)]
pub enum DeployCommand {
    #[command(
        name = "migrate-state",
        about = "Move vendor ids from rules into deployment state",
        long_about = "Move vendor rule ids off rules into .opentide/states/deployment/ (no vendor calls).\n\nRefuses with deployment_state_ignored, and edits nothing, while .gitignore\nhides .opentide/states/deployment/. Exits 1 when any rule cannot be migrated;\nids dropped from other platforms (external_id_unused) are warnings only.",
        after_help = "Examples:\n  $ opentide deploy migrate-state"
    )]
    MigrateState(DeployMigrateStateArgs),
    #[command(
        name = "replay-state",
        about = "Replay one commit's deployment-state changes onto the checkout (CI write-back).",
        long_about = "Replay one commit's deployment-state changes onto the checkout (CI write-back).\n\nUsed by the generated production write-back when its rule files conflict\nwith a concurrent merge. A subcommand rather than ``python -m`` so it runs\nin the interpreter that has opentide, whatever ``python`` is on PATH.",
        hide = true
    )]
    ReplayState(DeployReplayStateArgs),
    #[command(
        name = "metadata",
        about = "Reserved for a future metadata deployment implementation.",
        hide = true
    )]
    Metadata(DeployMetadataArgs),
}

/// The subcommands of `opentide rules`.
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    #[command(
        name = "unreviewed",
        about = "List rules not reviewed within a window",
        long_about = "List rules with no review date, or a review older than the window.\n\n`rule::1.0` is always listed. `rule::1.1` is listed when `metadata.reviewed`\nis absent or strictly earlier than now minus the window. This command does not\nmodify rules.",
        after_help = "Examples:\n  $ opentide rules unreviewed --older-than 90d"
    )]
    Unreviewed(RulesUnreviewedArgs),
}

/// The subcommands of `opentide generate`.
#[derive(Debug, Subcommand)]
pub enum GenerateCommand {
    #[command(
        name = "explorer",
        about = "Write the explorer bundle and search index",
        long_about = "Write explorer.bundle.json and explorer.search.json under .opentide/exports/.",
        after_help = "Examples:\n  $ opentide generate explorer"
    )]
    Explorer(GenerateExplorerArgs),
    #[command(
        name = "docs",
        about = "Generate markdown documentation for detection objects",
        after_help = "Examples:\n  $ opentide generate docs\n  $ opentide generate docs --changed",
        subcommand_value_name = "COMMAND"
    )]
    Docs(GenerateDocsArgs),
    #[command(
        name = "exports",
        about = "Export catalogue artefacts",
        after_help = "Examples:\n  $ opentide generate exports",
        subcommand_value_name = "COMMAND"
    )]
    Exports(GenerateExportsArgs),
    #[command(
        name = "extract",
        about = "Import rules from external platforms",
        after_help = "Examples:\n  $ opentide generate extract sentinel",
        subcommand_required = true,
        subcommand_value_name = "COMMAND"
    )]
    Extract(GenerateExtractArgs),
    #[command(
        name = "inflight",
        about = "Inflight preview shard generation and prune",
        after_help = "Examples:\n  $ opentide generate inflight",
        subcommand_value_name = "COMMAND"
    )]
    Inflight(GenerateInflightArgs),
    /// The phases named as words (`generate schemas templates`): a word that
    /// is not a subcommand starts them (`GeneratePhaseGroup`). Not a
    /// subcommand, so not in the catalogue.
    #[command(external_subcommand)]
    Phases(Vec<String>),
}

/// The subcommands of `opentide generate inflight`.
#[derive(Debug, Subcommand)]
pub enum GenerateInflightCommand {
    #[command(
        name = "prune",
        about = "Remove inflight shards already on the default branch",
        long_about = "Remove inflight shards superseded by committed objects on the default branch.",
        after_help = "Examples:\n  $ opentide generate inflight prune"
    )]
    Prune(GenerateInflightPruneArgs),
}

/// The subcommands of `opentide generate extract`.
#[derive(Debug, Subcommand)]
pub enum GenerateExtractCommand {
    #[command(
        name = "sentinel",
        about = "Import Sentinel analytics rules",
        long_about = "Import Sentinel analytics rules (needs Sentinel tenant credentials).",
        after_help = "Examples:\n  $ opentide generate extract sentinel"
    )]
    Sentinel(GenerateExtractSentinelArgs),
    #[command(
        name = "defender",
        about = "Import Defender custom detections",
        long_about = "Import Defender custom detections (needs tenant credentials).",
        after_help = "Examples:\n  $ opentide generate extract defender"
    )]
    Defender(GenerateExtractDefenderArgs),
    #[command(
        name = "elastic",
        about = "Import Elastic Security detection rules",
        long_about = "Import Elastic Security detection rules (needs tenant credentials).",
        after_help = "Examples:\n  $ opentide generate extract elastic --space default"
    )]
    Elastic(GenerateExtractElasticArgs),
}

/// The subcommands of `opentide generate exports`.
#[derive(Debug, Subcommand)]
pub enum GenerateExportsCommand {
    #[command(
        name = "navigator",
        about = "Export the ATT&CK Navigator layer",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate exports navigator"
    )]
    Navigator(GenerateExportsNavigatorArgs),
    #[command(
        name = "objects",
        about = "Export every object as one JSON file",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate exports objects"
    )]
    Objects(GenerateExportsObjectsArgs),
    #[command(
        name = "revisions",
        about = "Export the revisions snapshot",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate exports revisions"
    )]
    Revisions(GenerateExportsRevisionsArgs),
}

/// The subcommands of `opentide generate docs`.
#[derive(Debug, Subcommand)]
pub enum GenerateDocsCommand {
    #[command(
        name = "rules",
        about = "Generate rule documentation",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate docs rules"
    )]
    Rules(GenerateDocsRulesArgs),
    #[command(
        name = "objectives",
        about = "Generate objective documentation",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate docs objectives"
    )]
    Objectives(GenerateDocsObjectivesArgs),
    #[command(
        name = "threats",
        about = "Generate threat documentation",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate docs threats"
    )]
    Threats(GenerateDocsThreatsArgs),
    #[command(
        name = "index",
        about = "Generate the documentation index pages",
        long_about = "",
        after_help = "Examples:\n  $ opentide generate docs index"
    )]
    Index(GenerateDocsIndexArgs),
}

/// The subcommands of `opentide new`.
#[derive(Debug, Subcommand)]
pub enum NewCommand {
    #[command(
        name = "threat",
        about = "Scaffold a threat",
        long_about = "Scaffold a threat.",
        after_help = "Examples:\n  $ opentide new threat --name \"Credential Dumping\""
    )]
    Threat(NewThreatArgs),
    #[command(
        name = "objective",
        about = "Scaffold a detection objective",
        long_about = "Scaffold a detection objective.",
        after_help = "Examples:\n  $ opentide new objective --name \"Detect Credential Dumping\" --threat <threat-uuid>"
    )]
    Objective(NewObjectiveArgs),
    #[command(
        name = "rule",
        about = "Scaffold a detection rule",
        long_about = "Scaffold a detection rule.",
        after_help = "Examples:\n  $ opentide new rule --name \"Suspicious LSASS Access\" --platform sentinel --objective <objective-uuid>"
    )]
    Rule(NewRuleArgs),
}

/// The subcommands of `opentide validate`.
#[derive(Debug, Subcommand)]
pub enum ValidateCommand {
    #[command(
        name = "query",
        about = "Check rule queries offline, or on the tenants (--live)",
        long_about = "Check rule queries offline with the analysis engine, or on the tenants (--live).\n\nOffline, the engine reports the queries the platform would reject, as\n`opentide validate` does; `opentide lint` reports their style.",
        after_help = "Examples:\n  $ opentide validate query\n  $ opentide validate query --platform splunk --changed\n  $ opentide validate query --file hunting/lsass.kql\n  $ opentide validate query --platform sentinel --live"
    )]
    Query(ValidateQueryArgs),
}
