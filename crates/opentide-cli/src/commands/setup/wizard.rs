//! The setup wizards at a terminal (`services/setup/interactive.py`,
//! `orchestrator.run_interactive_setup`, `repo.run_interactive_repo_setup`,
//! `mcp.run_interactive_mcp_setup`, `ui/setup.py`): the same questions, in
//! the same order and with the same defaults as the Python wizards, asked
//! through a [`Prompter`]. At a terminal that is [`Inquire`], on the
//! inquire crate (crossterm, so Linux, macOS and Windows consoles); the
//! tests answer through a script.
//!
//! A wizard only gathers answers: what they ask for runs through the same
//! non-interactive steps a scripted `setup` runs (`run.rs`).

use std::io::Write;
use std::path::Path;

use super::files::RepoOptions;
use crate::mode::Mode;
use crate::render::outcome::Console;
use crate::render::table::columns;
use crate::render::text::{Colour, Style, Text};

/// Why a wizard stopped before it was answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Ctrl-C (or Escape) at a question: the run stops as Ctrl-C stops it.
    Interrupted,
    /// The terminal could not be read or written: the message.
    Failed(String),
}

/// An answer, or why there is none.
pub type Answer<T> = Result<T, Stop>;

/// Asks the questions (`ask_text`, `ask_confirm`, `ask_select`, `ask_checkbox`).
pub trait Prompter {
    /// Free text, `default` already filled in; with `required` an empty
    /// answer is refused, naming what is missing (`require_text`).
    fn text(&mut self, message: &str, default: &str, required: Option<&str>) -> Answer<String>;
    /// Yes or no.
    fn confirm(&mut self, message: &str, default: bool) -> Answer<bool>;
    /// One of `choices`, `default` selected first; its index.
    fn select(&mut self, message: &str, choices: &[&str], default: usize) -> Answer<usize>;
    /// Any of `choices`, `checked` ticked first; their indices, in order.
    /// With `required`, an empty selection is refused.
    fn checkbox(
        &mut self,
        message: &str,
        choices: &[&str],
        checked: &[usize],
        required: bool,
    ) -> Answer<Vec<usize>>;
}

// ---------------------------------------------------------------- the choices

/// The detection platforms, as `--platform` names them and the wizard shows
/// them (`DetectionPlatform`, `platform_label`), in their order.
pub const PLATFORMS: [(&str, &str); 9] = [
    ("sentinel", "Microsoft Sentinel"),
    ("splunk", "Splunk Enterprise Security"),
    ("crowdstrike", "CrowdStrike Falcon"),
    ("defender_for_endpoint", "Microsoft Defender for Endpoint"),
    ("sentinel_one", "SentinelOne"),
    ("carbon_black_cloud", "Carbon Black Cloud"),
    ("harfanglab", "HarfangLab"),
    ("elastic", "Elastic Security"),
    ("sysdig", "Sysdig Secure"),
];

/// The CI choices (`CI_LABELS`), after "Configure later".
pub const CI: [(&str, &str); 3] = [
    ("github", "GitHub Actions"),
    ("gitlab", "GitLab CI"),
    ("azure", "Azure Pipelines"),
];

/// The MCP hosts (`MCP_LABELS`).
pub const MCP: [(&str, &str); 4] = [
    ("vscode", "VS Code"),
    ("cursor", "Cursor"),
    ("claude-code", "Claude Code"),
    ("generic", "Generic (opentide.mcp.json)"),
];

/// The agent environments skills install for (`SKILL_LABELS`).
pub const SKILLS: [(&str, &str); 4] = [
    ("cursor", "Cursor"),
    ("claude-code", "Claude Code"),
    ("generic", "Generic (AGENTS.md)"),
    ("github-copilot", "GitHub Copilot"),
];

/// Said under the logo.
pub const TAGLINE: &str = "Spec-driven development for agentic detection engineering";
/// What the wizard does, under the tagline.
pub const WELCOME_LINE: &str =
    "A few questions, then a detection repository with CI, schemas and editor support.";

fn labels<'a>(choices: &[(&'a str, &'a str)]) -> Vec<&'a str> {
    choices.iter().map(|(_, label)| *label).collect()
}

fn keys(choices: &[(&str, &str)], picked: &[usize]) -> Vec<String> {
    picked
        .iter()
        .filter_map(|&index| choices.get(index))
        .map(|(key, _)| (*key).to_owned())
        .collect()
}

fn shown_labels(choices: &[(&str, &str)], keys: &[String]) -> Vec<String> {
    keys.iter()
        .map(|key| {
            choices
                .iter()
                .find(|(name, _)| name == key)
                .map_or_else(|| key.clone(), |(_, label)| (*label).to_owned())
        })
        .collect()
}

// ---------------------------------------------------------------- what is gathered

/// The `setup` wizard's answers: what `run_setup` is given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the CI workflow's features, one field each"
)]
pub struct Setup {
    /// The repository's name, organisation, description and platforms.
    pub repo: RepoOptions,
    /// The CI provider; `None`: configure later.
    pub ci: Option<String>,
    /// Staging deployments on pull requests.
    pub staging: bool,
    /// Inflight preview shards.
    pub inflight: bool,
    /// Sharing on the default branch.
    pub sharing: bool,
    /// Explorer pages (GitHub Actions only).
    pub explorer_pages: bool,
    /// Automatic status promotion, when the answer changes the repository's.
    pub promotion: Option<bool>,
    /// The MCP hosts, in order.
    pub mcp: Vec<String>,
    /// Warnings the run carries from the questions (`options.warnings`).
    pub warnings: Vec<String>,
}

/// What the `setup` wizard ends with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gathered {
    /// Apply the plan.
    Apply(Box<Setup>),
    /// The plan was declined: nothing is written; the warnings stand.
    Declined(Vec<String>),
}

/// What a person answers the wizards with at a terminal, and where they read it.
pub struct Screen<'a> {
    /// Where the welcome, the plan and the targets are printed (stdout).
    pub out: &'a mut dyn Write,
    /// stdout's styles and width.
    pub console: Console,
    /// The run's output mode: the logo is drawn in `human` mode only.
    pub mode: Mode,
    /// opentide's version, beside the logo.
    pub version: &'a str,
}

impl Screen<'_> {
    fn print(&mut self, text: &str) -> Answer<()> {
        self.out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush())
            .map_err(|error| Stop::Failed(error.to_string()))
    }

    fn line(&mut self, text: &Text) -> Answer<()> {
        let line = self.console.line(text);
        self.print(&line)
    }

    /// `Target: <path>` (`[bold]Target:[/] ...`).
    fn target(&mut self, root: &Path) -> Answer<()> {
        let mut line = Text::styled("Target:", &Style::new("bold"));
        line.push_str(&format!(" {}", root.display()));
        self.line(&line)
    }
}

/// The `setup` wizard (`run_interactive_setup`). `shown` is the target as
/// given, `root` the same made absolute; `promoting` is whether the
/// repository promotes statuses now (`effective_promotion`).
///
/// # Errors
///
/// Ctrl-C at a question, or a terminal that cannot be used.
pub fn setup(
    prompter: &mut dyn Prompter,
    screen: &mut Screen<'_>,
    shown: &str,
    root: &Path,
    promoting: bool,
) -> Answer<Gathered> {
    let welcome = welcome(screen.console, screen.mode, screen.version);
    screen.print(&welcome)?;
    let mut answers = Setup {
        staging: true,
        inflight: true,
        ..Setup::default()
    };
    answers.repo = repo_questions(prompter, root)?;
    let mut choices = vec!["Configure later"];
    choices.extend(labels(&CI));
    let ci = prompter.select("CI/CD platform", &choices, 0)?;
    answers.ci = ci
        .checked_sub(1)
        .and_then(|index| CI.get(index))
        .map(|(key, _)| (*key).to_owned());
    if let Some(ci) = answers.ci.as_deref() {
        let mut features: Vec<(&str, &str)> = vec![
            ("Staging deployments on pull requests", "staging"),
            ("Inflight preview shards", "inflight"),
            ("Automatic status promotion", "promotion"),
            ("Sharing on the default branch", "sharing"),
        ];
        if ci == "github" {
            features.push(("Explorer pages", "explorer"));
        }
        let mut checked = vec![0, 1];
        if promoting {
            checked.push(2);
        }
        let shown_features: Vec<&str> = features.iter().map(|(label, _)| *label).collect();
        let picked = prompter.checkbox("CI workflow features", &shown_features, &checked, false)?;
        let has = |key: &str| {
            picked
                .iter()
                .any(|&index| features.get(index).is_some_and(|(_, name)| *name == key))
        };
        answers.staging = has("staging");
        answers.inflight = has("inflight");
        answers.sharing = has("sharing");
        // Left where the repository has it, the checkbox writes nothing.
        let chosen = has("promotion");
        answers.promotion = (chosen != promoting).then_some(chosen);
        answers.explorer_pages = has("explorer");
    }
    if prompter.confirm("Configure opentide MCP?", false)? {
        let picked = prompter.checkbox("MCP hosts", &labels(&MCP), &[], true)?;
        answers.mcp = keys(&MCP, &picked);
    }
    if prompter.confirm("Install agent skills?", false)? {
        let picked = prompter.checkbox("Agent environments", &labels(&SKILLS), &[], true)?;
        let targets = keys(&SKILLS, &picked);
        // Installing the skills downloads them (UC-4.4, #834): the Python
        // implementation does it; this one says how to run it, as the
        // oracle says why it skipped them when the catalogue is out of reach.
        let flags: Vec<String> = targets.iter().map(|target| format!("--{target}")).collect();
        answers.warnings.push(format!(
            "Agent skills skipped: installing them has no Rust implementation yet. Run 'opentide setup skills {} --yes' with OPENTIDE_ENGINE unset.",
            flags.join(" ")
        ));
    }
    let rows = plan_rows(
        shown,
        root,
        &shown_labels(&PLATFORMS, &answers.repo.platforms),
        answers
            .ci
            .as_deref()
            .map(|ci| shown_labels(&CI, &[ci.to_owned()]).join("")),
        (!answers.mcp.is_empty()).then(|| shown_labels(&MCP, &answers.mcp)),
        None,
    );
    screen.print(&render_plan(screen.console, &rows))?;
    for warning in &answers.warnings {
        let line = screen.console.labelled("warning", warning, 0);
        screen.print(&line)?;
    }
    if !prompter.confirm("Apply this setup plan?", true)? {
        return Ok(Gathered::Declined(answers.warnings));
    }
    Ok(Gathered::Apply(Box::new(answers)))
}

/// The repository's questions: name, organisation, description, platforms.
fn repo_questions(prompter: &mut dyn Prompter, root: &Path) -> Answer<RepoOptions> {
    let folder = super::files::folder_name(root);
    let name = prompter.text("Repository name", &folder, Some("a name"))?;
    let org = prompter.text("Organisation / team for the README (optional)", "", None)?;
    let description = prompter.text("Description (optional)", "", None)?;
    let picked = prompter.checkbox("Detection platforms", &labels(&PLATFORMS), &[], true)?;
    let given = |text: String| (!text.is_empty()).then_some(text);
    Ok(RepoOptions {
        name: given(name),
        org: given(org),
        description: given(description),
        platforms: keys(&PLATFORMS, &picked),
    })
}

/// The `setup repo` wizard (`run_interactive_repo_setup`); `None` when the
/// scaffold is declined.
///
/// # Errors
///
/// Ctrl-C at a question, or a terminal that cannot be used.
pub fn repo(
    prompter: &mut dyn Prompter,
    screen: &mut Screen<'_>,
    root: &Path,
) -> Answer<Option<RepoOptions>> {
    let welcome = welcome(screen.console, screen.mode, screen.version);
    screen.print(&welcome)?;
    let options = repo_questions(prompter, root)?;
    screen.target(root)?;
    Ok(prompter
        .confirm("Create this repository scaffold?", true)?
        .then_some(options))
}

/// The `setup mcp` wizard (`run_interactive_mcp_setup`): the hosts, or
/// `None` when the write is declined.
///
/// # Errors
///
/// Ctrl-C at a question, or a terminal that cannot be used.
pub fn mcp(
    prompter: &mut dyn Prompter,
    screen: &mut Screen<'_>,
    root: &Path,
) -> Answer<Option<Vec<String>>> {
    let picked = prompter.checkbox("MCP hosts", &labels(&MCP), &[], true)?;
    let hosts = keys(&MCP, &picked);
    screen.target(root)?;
    let mut line = Text::styled("Hosts:", &Style::new("bold"));
    line.push_str(&format!(" {}", hosts.join(", ")));
    screen.line(&line)?;
    Ok(prompter
        .confirm("Write these MCP configurations?", true)?
        .then_some(hosts))
}

// ---------------------------------------------------------------- the screens

/// The `Setup plan` rows (`plan_rows`): one per step, in the questions' words.
fn plan_rows(
    shown: &str,
    root: &Path,
    platforms: &[String],
    ci: Option<String>,
    mcp: Option<Vec<String>>,
    skills: Option<Vec<String>>,
) -> Vec<(String, String)> {
    let mut place = shown.trim_end_matches('/').to_owned();
    if place.is_empty() || place == "." {
        place = format!("this folder ({})", super::files::folder_name(root));
    }
    let listed = |items: &[String]| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    };
    vec![
        ("Repository".into(), place),
        ("Platforms".into(), listed(platforms)),
        (
            "CI/CD".into(),
            ci.unwrap_or_else(|| "configure later".into()),
        ),
        (
            "MCP".into(),
            mcp.map_or_else(|| "none".to_owned(), |items| items.join(", ")),
        ),
        (
            "Agent skills".into(),
            skills.map_or_else(|| "none".to_owned(), |items| items.join(", ")),
        ),
    ]
}

/// `Setup plan` and its rows, with a blank line around them (`render_plan`).
fn render_plan(console: Console, rows: &[(String, String)]) -> String {
    let bold = Style::new("bold");
    let mut out = console.line(&Text::default());
    out.push_str(&console.line(&Text::styled("Setup plan", &bold)));
    let cells: Vec<Vec<Text>> = rows
        .iter()
        .map(|(label, choice)| vec![Text::styled(label, &bold), Text::plain(choice)])
        .collect();
    for row in columns(&cells, 3, &[]) {
        let mut line = Text::plain("  ");
        line.append_text(&row);
        out.push_str(&console.line(&line));
    }
    out.push_str(&console.line(&Text::default()));
    out
}

/// The pill logo, `logo-normal` from opentidehq/.github's assets: 80 × 20
/// pixels, `B` Reflex Blue, `W` white (`brand.LOGO`).
const LOGO: [&str; 20] = [
    ".......BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.......",
    ".....BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.....",
    "...BBBBWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB...",
    "..BBBWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "..BBWWWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBBBBBBBBBBBBB..",
    ".BBWWWWWWBBBWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBWWBBBBBWWBBBBBBBBBBBBBBB.",
    ".BBWWWWBBBBBWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWWBBBBBBBBBWWBBBBBBBBBBBBBBB.",
    "BBWWWWBBBBWBWWWWWWBBBBBWWWWBBWWWWWBBBWWWWBBWWWWWBBWWWWBWWBBWWWWWBBWWWWBBBBBBBBBB",
    "BBWWWBBWBWWBBWWWWWBBBBWWBBWWBWWBBWWBWWBBWWBWWBBWWBBWWBBWWBWWBBWWBWWBBWWBBBBBBBBB",
    "BBWWWBWWBWWWBBBWWWBBBBWWBBWWBWWBBWWBWWWWWWBWWBBWWBBWWBBWWBWWBBWWBWWWWWWBBBBBBBBB",
    "BBWWWBWWBBWWWWWWWWBBBBWWBBWWBWWBBWWBWWBBBBBWWBBWWBBWWBBWWBWWBBWWBWWBBBBBBBBBBBBB",
    "BBWWWBBBBBBBBBBWWWBBBBWWBBWWBWWBBWWBWWBBWWBWWBBWWBBWWBBWWBWWBBWWBWWBBWWBBBBBBBBB",
    "BBWWWWWWWWWWWWWWWWBBBBBWWWWBBWWWWWBBBWWWWBBWWBBWWBBBWWBWWBBWWWWWBBWWWWBBBBBBBBBB",
    ".BBWWBBBBBBBBBBWWBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.",
    ".BBWWWWWWWWWWWWWWBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.",
    "..BBWWWWWWWWWWWWBBBBBBBBBBBBBWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "..BBBWWWWWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB..",
    "...BBBBWWWWWWBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB...",
    ".....BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.....",
    ".......BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.......",
];

/// Terminal columns the logo needs, with its two-column indent.
const LOGO_MIN_WIDTH: usize = 82;

/// A pixel's 256-colour code: Reflex Blue (`#001489`) as the terminal's
/// 256 colours give it, and white.
fn pixel(cell: char) -> Option<u8> {
    match cell {
        'B' => Some(18),
        'W' => Some(231),
        _ => None,
    }
}

/// The logo's rows, two pixel rows to a line in upper half-blocks
/// (`brand.render`); without colour, the blue drawn in the terminal's own
/// foreground and the rest left blank.
fn logo(colour: Colour) -> Vec<Text> {
    LOGO.chunks(2)
        .map(|pair| {
            let (top, bottom) = (pair[0], pair.get(1).copied().unwrap_or(""));
            let mut line = Text::plain("  ");
            for (index, upper) in top.chars().enumerate() {
                let lower = bottom.chars().nth(index).unwrap_or('.');
                if colour != Colour::Full {
                    let cell = match (upper == 'B', lower == 'B') {
                        (true, true) => "█",
                        (true, false) => "▀",
                        (false, true) => "▄",
                        (false, false) => " ",
                    };
                    line.push_str(cell);
                    continue;
                }
                match (pixel(upper), pixel(lower)) {
                    (None, None) => {
                        line.push_str(" ");
                    }
                    (None, Some(lower)) => {
                        line.append("▄", &Style::new(&format!("color({lower})")));
                    }
                    (Some(upper), None) => {
                        line.append("▀", &Style::new(&format!("color({upper})")));
                    }
                    (Some(upper), Some(lower)) if upper == lower => {
                        line.append("█", &Style::new(&format!("color({upper})")));
                    }
                    (Some(upper), Some(lower)) => {
                        line.append(
                            "▀",
                            &Style::new(&format!("color({upper}) on_color({lower})")),
                        );
                    }
                }
            }
            line
        })
        .collect()
}

/// `▐ ≋ opentide ▌`, the one-line mark (`brand.pill`).
fn pill(colour: Colour) -> Text {
    let mut text = Text::default();
    if colour == Colour::Full {
        text.append("▐", &Style::new("color(18)"));
        text.append(" ≋ opentide ", &Style::new("bold color(231) on_color(18)"));
        text.append("▌", &Style::new("color(18)"));
    } else {
        text.push_str("▐");
        text.append(" ≋ opentide ", &Style::new("bold reverse"));
        text.push_str("▌");
    }
    text
}

/// The wizard's first screen (`welcome`): the logo (the pill on a narrow
/// terminal), the tagline and the version, and what happens next. Outside
/// `human` mode there is no mark, only the command and the tagline.
pub fn welcome(console: Console, mode: Mode, version: &str) -> String {
    let separator = " · ";
    let mut out = String::new();
    if mode == Mode::Human {
        out.push_str(&console.line(&Text::default()));
        if console.width.is_none_or(|width| width >= LOGO_MIN_WIDTH) {
            for row in logo(console.colour) {
                out.push_str(&console.line(&row));
            }
            let mut line = Text::styled(&format!("  {TAGLINE}"), &Style::new("italic"));
            line.append(&format!("{separator}{version}"), &Style::new("dim"));
            out.push_str(&console.line(&line));
        } else {
            let mut line = Text::plain("  ");
            line.append_text(&pill(console.colour));
            line.append(&format!("{separator}{version}"), &Style::new("dim"));
            out.push_str(&console.line(&line));
            out.push_str(&console.line(&Text::styled(
                &format!("  {TAGLINE}"),
                &Style::new("italic"),
            )));
        }
    } else {
        let mut line = Text::styled("opentide setup", &Style::new("bold"));
        line.push_str(&format!("{separator}{TAGLINE}"));
        out.push_str(&console.line(&line));
    }
    out.push_str(&console.line(&Text::default()));
    out.push_str(&console.line(&Text::styled(
        &format!("  {WELCOME_LINE}"),
        &Style::new("dim"),
    )));
    out.push_str(&console.line(&Text::default()));
    out
}

// ---------------------------------------------------------------- inquire

/// The questions at a terminal, on inquire: drawn on stderr, a question
/// mark in the brand (`≋` on Reflex Blue), answers in bold, a refused
/// answer's reason under the field (`PROMPT_STYLE`).
pub struct Inquire {
    config: inquire::ui::RenderConfig<'static>,
}

impl Inquire {
    /// The prompts for a stream with `colour`.
    pub fn new(colour: Colour) -> Inquire {
        use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};
        let config = if colour == Colour::Full {
            let mark = Styled::new("≋")
                .with_fg(Color::rgb(255, 255, 255))
                .with_bg(Color::rgb(0, 20, 137))
                .with_attr(Attributes::BOLD);
            let mut config = RenderConfig::default_colored();
            config.prompt_prefix = mark;
            config.answered_prompt_prefix = mark;
            config.prompt = StyleSheet::new().with_attr(Attributes::BOLD);
            config.answer = StyleSheet::new().with_attr(Attributes::BOLD);
            config
        } else {
            let mut config = RenderConfig::empty();
            config.prompt_prefix = Styled::new("≋");
            config.answered_prompt_prefix = Styled::new("≋");
            config
        };
        Inquire { config }
    }
}

/// inquire's answer as the wizard reads it: Ctrl-C and Escape stop the run.
fn answer<T>(result: inquire::error::InquireResult<T>) -> Answer<T> {
    use inquire::InquireError;
    result.map_err(|error| match error {
        InquireError::OperationInterrupted | InquireError::OperationCanceled => Stop::Interrupted,
        other => Stop::Failed(other.to_string()),
    })
}

impl Prompter for Inquire {
    fn text(&mut self, message: &str, default: &str, required: Option<&str>) -> Answer<String> {
        let mut prompt = inquire::Text::new(message)
            .with_initial_value(default)
            .with_render_config(self.config);
        if let Some(what) = required {
            let refusal = format!("Enter {what}; the field cannot be empty");
            prompt = prompt.with_validator(move |input: &str| {
                Ok(if input.trim().is_empty() {
                    inquire::validator::Validation::Invalid(refusal.clone().into())
                } else {
                    inquire::validator::Validation::Valid
                })
            });
        }
        answer(prompt.prompt())
    }

    fn confirm(&mut self, message: &str, default: bool) -> Answer<bool> {
        answer(
            inquire::Confirm::new(message)
                .with_default(default)
                .with_render_config(self.config)
                .prompt(),
        )
    }

    fn select(&mut self, message: &str, choices: &[&str], default: usize) -> Answer<usize> {
        answer(
            inquire::Select::new(message, choices.to_vec())
                .with_starting_cursor(default)
                .without_filtering()
                .with_render_config(self.config)
                .raw_prompt(),
        )
        .map(|picked| picked.index)
    }

    fn checkbox(
        &mut self,
        message: &str,
        choices: &[&str],
        checked: &[usize],
        required: bool,
    ) -> Answer<Vec<usize>> {
        let mut prompt = inquire::MultiSelect::new(message, choices.to_vec())
            .with_default(checked)
            .without_filtering()
            .with_render_config(self.config);
        if required {
            prompt =
                prompt.with_validator(|picked: &[inquire::list_option::ListOption<&&str>]| {
                    Ok(if picked.is_empty() {
                        inquire::validator::Validation::Invalid("Select at least one option".into())
                    } else {
                        inquire::validator::Validation::Valid
                    })
                });
        }
        answer(prompt.raw_prompt()).map(|picked| picked.iter().map(|option| option.index).collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Answers the questions from a script, recording each question.
    pub(crate) struct Script {
        pub(crate) answers: Vec<Reply>,
        pub(crate) asked: Vec<String>,
    }

    /// One scripted answer.
    #[derive(Clone, Debug)]
    pub(crate) enum Reply {
        /// The text; `None` takes the default.
        Text(Option<&'static str>),
        Confirm(Option<bool>),
        Select(Option<usize>),
        Checkbox(Option<Vec<usize>>),
        CtrlC,
    }

    impl Script {
        pub(crate) fn new(answers: Vec<Reply>) -> Script {
            Script {
                answers,
                asked: Vec::new(),
            }
        }

        fn next(&mut self, asked: String) -> Answer<Reply> {
            self.asked.push(asked);
            match self.answers.remove(0) {
                Reply::CtrlC => Err(Stop::Interrupted),
                reply => Ok(reply),
            }
        }
    }

    impl Prompter for Script {
        fn text(&mut self, message: &str, default: &str, required: Option<&str>) -> Answer<String> {
            match self.next(format!("text {message} [{default}] {required:?}"))? {
                Reply::Text(Some(text)) => Ok(text.to_owned()),
                Reply::Text(None) => Ok(default.to_owned()),
                other => panic!("{message}: {other:?}"),
            }
        }

        fn confirm(&mut self, message: &str, default: bool) -> Answer<bool> {
            match self.next(format!("confirm {message} [{default}]"))? {
                Reply::Confirm(answer) => Ok(answer.unwrap_or(default)),
                other => panic!("{message}: {other:?}"),
            }
        }

        fn select(&mut self, message: &str, choices: &[&str], default: usize) -> Answer<usize> {
            match self.next(format!("select {message} {choices:?} [{default}]"))? {
                Reply::Select(answer) => Ok(answer.unwrap_or(default)),
                other => panic!("{message}: {other:?}"),
            }
        }

        fn checkbox(
            &mut self,
            message: &str,
            choices: &[&str],
            checked: &[usize],
            required: bool,
        ) -> Answer<Vec<usize>> {
            match self.next(format!(
                "checkbox {message} {choices:?} {checked:?} required={required}"
            ))? {
                Reply::Checkbox(answer) => Ok(answer.unwrap_or_else(|| checked.to_vec())),
                other => panic!("{message}: {other:?}"),
            }
        }
    }

    fn screen(out: &mut Vec<u8>) -> Screen<'_> {
        Screen {
            out,
            console: Console {
                colour: Colour::None,
                width: None,
            },
            mode: Mode::Plain,
            version: "9.9.9",
        }
    }

    /// The questions, their defaults and their order are the oracle's
    /// (`run_interactive_setup`).
    #[test]
    fn the_setup_wizard_asks_the_oracles_questions_in_its_order() {
        let mut script = Script::new(vec![
            Reply::Text(None),
            Reply::Text(Some("SOC")),
            Reply::Text(Some("")),
            Reply::Checkbox(Some(vec![0, 7])),
            Reply::Select(Some(1)),
            Reply::Checkbox(Some(vec![0, 2, 4])),
            Reply::Confirm(Some(true)),
            Reply::Checkbox(Some(vec![1])),
            Reply::Confirm(None),
            Reply::Confirm(None),
        ]);
        let mut out = Vec::new();
        let gathered = setup(
            &mut script,
            &mut screen(&mut out),
            ".",
            Path::new("/r/detections"),
            false,
        )
        .unwrap();
        assert_eq!(
            script.asked,
            [
                "text Repository name [detections] Some(\"a name\")",
                "text Organisation / team for the README (optional) [] None",
                "text Description (optional) [] None",
                "checkbox Detection platforms [\"Microsoft Sentinel\", \"Splunk Enterprise Security\", \"CrowdStrike Falcon\", \"Microsoft Defender for Endpoint\", \"SentinelOne\", \"Carbon Black Cloud\", \"HarfangLab\", \"Elastic Security\", \"Sysdig Secure\"] [] required=true",
                "select CI/CD platform [\"Configure later\", \"GitHub Actions\", \"GitLab CI\", \"Azure Pipelines\"] [0]",
                "checkbox CI workflow features [\"Staging deployments on pull requests\", \"Inflight preview shards\", \"Automatic status promotion\", \"Sharing on the default branch\", \"Explorer pages\"] [0, 1] required=false",
                "confirm Configure opentide MCP? [false]",
                "checkbox MCP hosts [\"VS Code\", \"Cursor\", \"Claude Code\", \"Generic (opentide.mcp.json)\"] [] required=true",
                "confirm Install agent skills? [false]",
                "confirm Apply this setup plan? [true]",
            ]
        );
        let Gathered::Apply(answers) = gathered else {
            panic!("{gathered:?}");
        };
        assert_eq!(answers.repo.name.as_deref(), Some("detections"));
        assert_eq!(answers.repo.org.as_deref(), Some("SOC"));
        assert_eq!(answers.repo.description, None);
        assert_eq!(answers.repo.platforms, ["sentinel", "elastic"]);
        assert_eq!(answers.ci.as_deref(), Some("github"));
        assert!(answers.staging && !answers.inflight && !answers.sharing && answers.explorer_pages);
        assert_eq!(answers.promotion, Some(true));
        assert_eq!(answers.mcp, ["cursor"]);
        let printed = String::from_utf8(out).unwrap();
        assert!(
            printed.starts_with("opentide setup · Spec-driven"),
            "{printed}"
        );
        assert!(
            printed.contains(
                "Setup plan\n  Repository     this folder (detections)\n  Platforms      Microsoft Sentinel, Elastic Security\n  CI/CD          GitHub Actions\n  MCP            Cursor\n  Agent skills   none\n"
            ),
            "{printed}"
        );
    }

    #[test]
    fn promotion_left_as_the_repository_has_it_writes_nothing() {
        let mut script = Script::new(vec![
            Reply::Text(None),
            Reply::Text(None),
            Reply::Text(None),
            Reply::Checkbox(Some(vec![0])),
            Reply::Select(Some(2)),
            Reply::Checkbox(None),
            Reply::Confirm(None),
            Reply::Confirm(None),
            Reply::Confirm(Some(false)),
        ]);
        let mut out = Vec::new();
        let gathered = setup(
            &mut script,
            &mut screen(&mut out),
            "x",
            Path::new("/r/x"),
            true,
        )
        .unwrap();
        // GitLab has no explorer pages, and promotion was ticked already.
        assert!(
            script.asked[5].contains("\"Sharing on the default branch\"] [0, 1, 2]"),
            "{}",
            script.asked[5]
        );
        assert_eq!(gathered, Gathered::Declined(Vec::new()));
        let mut script = Script::new(vec![
            Reply::Text(None),
            Reply::Text(None),
            Reply::Text(None),
            Reply::Checkbox(Some(vec![0])),
            Reply::Select(Some(2)),
            Reply::Checkbox(None),
            Reply::Confirm(None),
            Reply::Confirm(None),
            Reply::Confirm(None),
        ]);
        let Gathered::Apply(answers) = setup(
            &mut script,
            &mut screen(&mut Vec::new()),
            "x",
            Path::new("/r/x"),
            true,
        )
        .unwrap() else {
            panic!();
        };
        assert_eq!(answers.promotion, None);
        assert_eq!(answers.ci.as_deref(), Some("gitlab"));
    }

    #[test]
    fn chosen_skills_are_skipped_with_how_to_install_them() {
        let mut script = Script::new(vec![
            Reply::Text(None),
            Reply::Text(None),
            Reply::Text(None),
            Reply::Checkbox(Some(vec![1])),
            Reply::Select(None),
            Reply::Confirm(None),
            Reply::Confirm(Some(true)),
            Reply::Checkbox(Some(vec![1, 2])),
            Reply::Confirm(None),
        ]);
        let mut out = Vec::new();
        let Gathered::Apply(answers) = setup(
            &mut script,
            &mut screen(&mut out),
            "x",
            Path::new("/r/x"),
            false,
        )
        .unwrap() else {
            panic!();
        };
        let warning = "Agent skills skipped: installing them has no Rust implementation yet. Run 'opentide setup skills --claude-code --generic --yes' with OPENTIDE_ENGINE unset.";
        assert_eq!(answers.warnings, [warning]);
        assert_eq!(answers.ci, None);
        let printed = String::from_utf8(out).unwrap();
        assert!(
            printed.contains("  Agent skills   none\n\nwarning: Agent skills skipped"),
            "{printed}"
        );
    }

    #[test]
    fn ctrl_c_stops_a_wizard() {
        let mut script = Script::new(vec![Reply::Text(None), Reply::CtrlC]);
        let stopped = setup(
            &mut script,
            &mut screen(&mut Vec::new()),
            ".",
            Path::new("/r/x"),
            false,
        );
        assert_eq!(stopped, Err(Stop::Interrupted));
    }

    #[test]
    fn the_repo_and_mcp_wizards_name_their_target() {
        let mut script = Script::new(vec![
            Reply::Text(Some("Mine")),
            Reply::Text(None),
            Reply::Text(None),
            Reply::Checkbox(Some(vec![8])),
            Reply::Confirm(None),
        ]);
        let mut out = Vec::new();
        let options = repo(&mut script, &mut screen(&mut out), Path::new("/r/x"))
            .unwrap()
            .unwrap();
        assert_eq!(options.name.as_deref(), Some("Mine"));
        assert_eq!(options.platforms, ["sysdig"]);
        assert_eq!(
            script.asked[4],
            "confirm Create this repository scaffold? [true]"
        );
        assert!(String::from_utf8(out).unwrap().ends_with("Target: /r/x\n"));
        let mut script = Script::new(vec![
            Reply::Checkbox(Some(vec![0, 3])),
            Reply::Confirm(Some(false)),
        ]);
        let mut out = Vec::new();
        assert_eq!(
            mcp(&mut script, &mut screen(&mut out), Path::new("/r/x")).unwrap(),
            None
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Target: /r/x\nHosts: vscode, generic\n"
        );
    }

    #[test]
    fn the_welcome_draws_the_logo_in_human_mode_only() {
        let wide = Console {
            colour: Colour::Full,
            width: Some(100),
        };
        let human = welcome(wide, Mode::Human, "1.2.3");
        assert!(human.contains("\u{1b}[38;5;18m"), "{human:?}");
        assert!(human.contains("Spec-driven development for agentic detection engineering"));
        assert_eq!(human.lines().count(), 1 + 10 + 1 + 1 + 1 + 1);
        let narrow = welcome(
            Console {
                colour: Colour::Mono,
                width: Some(60),
            },
            Mode::Human,
            "1.2.3",
        );
        assert!(narrow.contains("▐"), "{narrow}");
        assert!(!narrow.contains("38;5"), "{narrow:?}");
    }
}
