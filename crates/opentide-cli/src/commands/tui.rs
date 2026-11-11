//! `opentide tui` (`cli/commands/tui.py`): whether the terminal UI can open.
//!
//! The UI reads keys from stdin and draws on stdout, so it opens only in
//! `human` mode with a terminal on both. Anywhere else it is refused with
//! `usage_tui_needs_tty`, exit 2, naming what made the run unusable; a
//! person at a terminal put in `plain` mode by a setting is told which one,
//! and a `help:` says how to open it anyway.
//!
//! This module is that decision. The UI itself (`tui_app.py`, `tui_tabs/`)
//! has no Rust implementation yet: where it would open, the run is refused
//! with `engine_not_ported`, and `OPENTIDE_ENGINE=compare` runs the Python
//! UI (`src/opentide/cli/engines.py`, `ENGINE_HOSTS`).

use super::Report;
use crate::env::Env;
use crate::envelope::{Failure, USAGE_EXIT_CODE};
use crate::json::Json;
use crate::mode::{Mode, detect_ci};

const COMMAND: &str = "tui";

/// `failure.code` when `opentide tui` runs where nobody can use it.
pub const USAGE_TUI_NEEDS_TTY: &str = "usage_tui_needs_tty";

/// What the run knows about where it is.
#[derive(Clone, Copy, Debug)]
pub struct Place<'a> {
    /// The run's output mode.
    pub mode: Mode,
    /// Whether stdin and stdout are both terminals.
    pub interactive: bool,
    /// `--no-color`.
    pub no_color: bool,
    /// The environment.
    pub env: &'a Env,
}

/// `None` when the UI can open here; otherwise the refusal.
pub fn gate(place: &Place<'_>) -> Option<Report> {
    if place.mode == Mode::Human && place.interactive {
        return None;
    }
    let mut data = Vec::new();
    let reason = if place.mode == Mode::Plain && place.interactive {
        plain_reason(place)
    } else {
        None
    };
    let message = if let Some(reason) = reason {
        data.push((
            "advice".to_owned(),
            Json::str("set OPENTIDE_OUTPUT=human to open it anyway"),
        ));
        format!(
            "opentide tui runs only in the human output mode; this run is in plain mode because {reason}"
        )
    } else if place.mode == Mode::Human {
        "opentide tui needs an interactive terminal; stdin or stdout is not one".to_owned()
    } else {
        format!(
            "opentide tui needs an interactive terminal; this run is in {} mode",
            place.mode.as_str()
        )
    };
    let mut report = Report::failed(
        COMMAND,
        USAGE_EXIT_CODE,
        Failure::new(USAGE_TUI_NEEDS_TTY, message),
    );
    report.outcome.data.extend(data);
    report.next("opentide info", "catalogue counts and platforms");
    report.next("opentide validate", "diagnostics for every object");
    Some(report)
}

/// The setting that chose `plain` mode at a terminal, read in the order the
/// mode rules read them.
fn plain_reason(place: &Place<'_>) -> Option<&'static str> {
    let env = place.env;
    if env
        .get("OPENTIDE_OUTPUT")
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("plain")
    {
        return Some("OPENTIDE_OUTPUT is plain");
    }
    if place.no_color {
        return Some("--no-color was passed");
    }
    if env.get("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        return Some("NO_COLOR is set");
    }
    if env
        .get("TERM")
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("dumb")
    {
        return Some("TERM is dumb");
    }
    if detect_ci(env).is_some() {
        return Some("a CI environment was detected");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Place, USAGE_TUI_NEEDS_TTY, gate};
    use crate::env::Env;
    use crate::json::Json;
    use crate::mode::Mode;

    fn refusal(
        mode: Mode,
        interactive: bool,
        no_color: bool,
        pairs: &[(&str, &str)],
    ) -> Option<(String, Option<String>)> {
        let env = Env::from_pairs(pairs.iter().copied());
        let report = gate(&Place {
            mode,
            interactive,
            no_color,
            env: &env,
        })?;
        let outcome = report.outcome;
        assert_eq!(outcome.exit_code, 2);
        let failure = outcome.failure.expect("a refusal fails");
        assert_eq!(failure.code, USAGE_TUI_NEEDS_TTY);
        assert_eq!(outcome.next_actions.len(), 2);
        let advice = outcome.data.iter().find_map(|(key, value)| match value {
            Json::Str(text) if key == "advice" => Some(text.clone()),
            _ => None,
        });
        Some((failure.message, advice))
    }

    #[test]
    fn it_opens_only_for_a_person_at_a_terminal() {
        assert!(refusal(Mode::Human, true, false, &[]).is_none());
        assert_eq!(
            refusal(Mode::Human, false, false, &[]),
            Some((
                "opentide tui needs an interactive terminal; stdin or stdout is not one".into(),
                None
            ))
        );
    }

    #[test]
    fn machine_and_agent_modes_are_refused_by_name() {
        for (mode, name) in [
            (Mode::Json, "json"),
            (Mode::Agent, "agent"),
            (Mode::Plain, "plain"),
        ] {
            for interactive in [false, true] {
                if mode == Mode::Plain && interactive {
                    continue;
                }
                assert_eq!(
                    refusal(mode, interactive, false, &[]),
                    Some((
                        format!(
                            "opentide tui needs an interactive terminal; this run is in {name} mode"
                        ),
                        None
                    ))
                );
            }
        }
    }

    #[test]
    fn plain_at_a_terminal_names_the_setting_and_how_to_open_it_anyway() {
        type Case<'a> = (bool, &'a [(&'a str, &'a str)], &'a str);
        let cases: &[Case<'_>] = &[
            (
                false,
                &[("OPENTIDE_OUTPUT", " PLAIN ")],
                "OPENTIDE_OUTPUT is plain",
            ),
            (true, &[("NO_COLOR", "1")], "--no-color was passed"),
            (
                false,
                &[("NO_COLOR", "1"), ("TERM", "dumb")],
                "NO_COLOR is set",
            ),
            (false, &[("NO_COLOR", ""), ("TERM", "dumb")], "TERM is dumb"),
            (
                false,
                &[("GITLAB_CI", "true")],
                "a CI environment was detected",
            ),
            (false, &[("CI", "1")], "a CI environment was detected"),
        ];
        for (no_color, pairs, reason) in cases {
            assert_eq!(
                refusal(Mode::Plain, true, *no_color, pairs),
                Some((
                    format!(
                        "opentide tui runs only in the human output mode; \
                         this run is in plain mode because {reason}"
                    ),
                    Some("set OPENTIDE_OUTPUT=human to open it anyway".into())
                )),
                "{pairs:?}"
            );
        }
        // No setting to name (`CI=false` is not CI): the plain refusal.
        assert_eq!(
            refusal(Mode::Plain, true, false, &[("CI", "false")]),
            Some((
                "opentide tui needs an interactive terminal; this run is in plain mode".into(),
                None
            ))
        );
    }
}
