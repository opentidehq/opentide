//! Status strategies (`models/deployment_enums.py`, `deployment/utils.py`):
//! what a run deploys (`--strategy`), what a status maps to
//! (`deployment.toml` `[[statuses]]`), and which runs act on which rules.

use opentide_schema::FromNode;
use opentide_schema::configuration::errors::model_errors;
use opentide_schema::configuration::models::DeploymentConfiguration;
use opentide_schema::configuration::resolve::Resolved;
pub use opentide_schema::configuration::types::StatusStrategy;
use opentide_schema::node::{Node, Value};

/// What a run deploys, and what a tenant accepts: `--strategy` and a tenant's
/// `strategies` take only these, in this order.
pub const DEPLOYABLE: [StatusStrategy; 2] = [StatusStrategy::Preview, StatusStrategy::Release];

/// The strategies a `RELEASE` run retires.
pub const RETIRING: [StatusStrategy; 2] = [StatusStrategy::Disablement, StatusStrategy::Deletion];

/// The strategies a run deploys, in [`DEPLOYABLE`] order.
pub type RunStrategies = Vec<StatusStrategy>;

/// Whether a run with `run` acts on a rule whose status maps to `rule`
/// (`deploys`): `PREVIEW` deploys `PREVIEW` and `UNIVERSAL`; `RELEASE` deploys
/// `RELEASE` and `UNIVERSAL` and retires `DISABLEMENT` and `DELETION`;
/// nothing deploys `INERT`.
pub fn deploys(rule: StatusStrategy, run: StatusStrategy) -> bool {
    if rule == run || rule == StatusStrategy::Universal {
        return DEPLOYABLE.contains(&run);
    }
    run == StatusStrategy::Release && RETIRING.contains(&rule)
}

/// The run strategies that act on a rule whose status maps to `rule`.
pub fn deployed_by(rule: StatusStrategy) -> RunStrategies {
    DEPLOYABLE
        .into_iter()
        .filter(|run| deploys(rule, *run))
        .collect()
}

/// Why a name is not a strategy a run takes, and what to pass instead.
fn not_a_run_strategy(name: &str) -> Option<&'static str> {
    Some(match name {
        "UNIVERSAL" => {
            "UNIVERSAL is a status strategy that both PREVIEW and RELEASE runs deploy; pass \
             PREVIEW or RELEASE"
        }
        "DISABLEMENT" => {
            "a RELEASE run disables the changed rules whose status maps to DISABLEMENT; pass \
             RELEASE"
        }
        "DELETION" => {
            "a RELEASE run deletes the changed rules whose status maps to DELETION; pass RELEASE"
        }
        "INERT" => "rules whose status maps to INERT are never deployed",
        "FULL" => {
            "deployment plans were removed in 0.17.0; pass --strategy PREVIEW --strategy \
             RELEASE --all to deploy every rule"
        }
        "ALWAYS" => {
            "deployment plans were removed in 0.17.0; a tenant lists the strategies it accepts \
             in 'strategies'"
        }
        "MANUAL" => {
            "deployment plans were removed in 0.17.0; a tenant that only takes the rules naming \
             it sets 'manual = true'"
        }
        "DEBUG" => "deployment plans were removed in 0.17.0; pass PREVIEW or RELEASE",
        _ => return None,
    })
}

/// A value Python's `repr` writes for a string: single quotes unless the
/// text holds one and no double quote.
pub fn python_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// The configured statuses, in `[[statuses]]` order: each name with the
/// strategy it maps to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Statuses(pub Vec<(String, StatusStrategy)>, pub Option<String>);

/// Why `deployment.toml` does not match its model, as the oracle says it
/// (`ConfigurationError`): every failing key, never a value.
pub fn deployment_error(deployment: &Node) -> Option<String> {
    let mut cx = opentide_schema::from_node::Context::new();
    let _ = DeploymentConfiguration::from_node(deployment, &mut cx);
    let errors = cx.into_errors();
    if errors.is_empty() {
        return None;
    }
    let lines: Vec<String> = model_errors(&errors, deployment)
        .into_iter()
        .map(|error| {
            let message = match error.kind {
                "extra_forbidden" => "unknown key".to_owned(),
                "missing" => "required key is missing".to_owned(),
                _ if error.message.is_empty() => "invalid value".to_owned(),
                _ => error.message,
            };
            let place = if error.path.is_empty() {
                "(document)".to_owned()
            } else {
                error.path.join(".")
            };
            format!("{place}: {message}")
        })
        .collect();
    Some(format!("deployment.toml is invalid: {}", lines.join("; ")))
}

impl Statuses {
    /// The statuses of a resolved configuration (`deployment.statuses`). When
    /// `deployment.toml` does not match its model, every lookup fails with
    /// why, as the oracle's does.
    pub fn from_resolved(resolved: &Resolved) -> Self {
        let mut statuses = Vec::new();
        let Some(deployment) = resolved.get("deployment") else {
            return Self(statuses, None);
        };
        let invalid = deployment_error(deployment);
        let Some(Value::Seq(entries)) = deployment.get("statuses").map(|node| &node.value) else {
            return Self(statuses, invalid);
        };
        for entry in entries {
            let name = entry.get("name").and_then(|node| node.value.as_str());
            let strategy = entry
                .get("strategy")
                .and_then(|node| node.value.as_str())
                .and_then(StatusStrategy::from_name);
            if let (Some(name), Some(strategy)) = (name, strategy) {
                statuses.push((name.to_owned(), strategy));
            }
        }
        Self(statuses, invalid)
    }

    /// The strategy `status` maps to (`check_status`), or the error naming the
    /// statuses there are.
    pub fn strategy(&self, status: &str) -> Result<StatusStrategy, StatusError> {
        if let Some(invalid) = &self.1 {
            return Err(StatusError::Invalid(invalid.clone()));
        }
        self.0
            .iter()
            .find(|(name, _)| name == status)
            .map(|(_, strategy)| *strategy)
            .ok_or_else(|| {
                let available: Vec<&str> = self.0.iter().map(|(name, _)| name.as_str()).collect();
                StatusError::Unknown(format!(
                    "Status {} is not defined in deployment configuration. Available statuses: \
                     {}.",
                    python_repr(status),
                    available.join(", ")
                ))
            })
    }

    /// The status names, in order, whose strategy one of `runs` deploys
    /// (`statuses_deployed_by`).
    pub fn deployed_by(&self, runs: &[StatusStrategy]) -> Vec<&str> {
        self.0
            .iter()
            .filter(|(_, strategy)| runs.iter().any(|run| deploys(*strategy, *run)))
            .map(|(name, _)| name.as_str())
            .collect()
    }
}

/// Why a status has no strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {
    /// `deployment.toml` does not match its model (`ConfigurationError`).
    Invalid(String),
    /// The status is not configured (the oracle's `KeyError`).
    Unknown(String),
}

impl StatusError {
    /// The text the oracle's exception gives as `str(exc)`: a `KeyError`
    /// quotes its message.
    pub fn exception_text(&self) -> String {
        match self {
            Self::Invalid(message) => message.clone(),
            Self::Unknown(message) => python_repr(message),
        }
    }
}

/// Reads `--strategy` values (`parse_strategies`): `PREVIEW` and `RELEASE`, in
/// any case, comma-separated or repeated; anything else is refused with what to
/// pass, a configured status name answered with the strategy it maps to.
/// `source` names the option in the message (`--strategy`).
pub fn parse_strategies<S: AsRef<str>>(
    values: &[S],
    statuses: &Statuses,
    source: &str,
) -> Result<RunStrategies, String> {
    let mut chosen = Vec::new();
    for raw in values {
        for part in raw.as_ref().split(',') {
            let trimmed = part.trim();
            let name = trimmed.to_uppercase();
            if name.is_empty() {
                continue;
            }
            if let Some(member) = StatusStrategy::from_name(&name)
                && DEPLOYABLE.contains(&member)
            {
                chosen.push(member);
                continue;
            }
            let allowed: Vec<&str> = DEPLOYABLE.iter().map(|s| s.name()).collect();
            let mut hints = vec![format!(
                "{source} {} is not a deployable strategy. Use {}",
                python_repr(trimmed),
                allowed.join(" or ")
            )];
            if name == "STAGING" || name == "PRODUCTION" {
                hints.push(format!(
                    "{name} was a deployment plan, removed in 0.17.0: pass {}",
                    if name == "STAGING" {
                        "PREVIEW"
                    } else {
                        "RELEASE"
                    }
                ));
            } else if let Some(hint) = not_a_run_strategy(&name) {
                hints.push(hint.to_owned());
            }
            if let Some((_, mapped)) = statuses
                .0
                .iter()
                .find(|(status, _)| status.to_uppercase() == name)
            {
                let runs = deployed_by(*mapped);
                let mut hint = format!(
                    "{name} is also a configured status name; it maps to {}",
                    mapped.name()
                );
                if runs.is_empty() {
                    hint.push_str(", which no run deploys");
                } else {
                    let names: Vec<&str> = runs.iter().map(|run| run.name()).collect();
                    hint.push_str(&format!(", which a {} run deploys", names.join(" or ")));
                }
                hints.push(hint);
            }
            return Err(hints.join(". "));
        }
    }
    Ok(DEPLOYABLE
        .into_iter()
        .filter(|strategy| chosen.contains(strategy))
        .collect())
}

/// The variable that named a deployment plan, removed in 0.17.0.
pub const REMOVED_PLAN_ENV: &str = "DEPLOYMENT_PLAN";

/// The error for `--plan` (`option`) or `DEPLOYMENT_PLAN`, naming the
/// replacement (`removed_plan_message`).
pub fn removed_plan_message(value: Option<&str>, option: bool) -> String {
    let place = if option { "--plan" } else { REMOVED_PLAN_ENV };
    let replacement = match value.unwrap_or_default().trim().to_uppercase().as_str() {
        "STAGING" => "--strategy PREVIEW",
        "PRODUCTION" => "--strategy RELEASE",
        "FULL" => "--strategy PREVIEW --strategy RELEASE --all",
        _ => "--strategy PREVIEW or --strategy RELEASE",
    };
    let unset = if option {
        String::new()
    } else {
        format!(" Unset {REMOVED_PLAN_ENV}.")
    };
    format!(
        "{place} was removed in 0.17.0: a run now says which status strategy it deploys. Use \
         {replacement}.{unset} See 'opentide deploy --help'."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use StatusStrategy::{Deletion, Disablement, Inert, Preview, Release, Universal};

    fn statuses() -> Statuses {
        Statuses(
            vec![
                ("DEVELOPMENT".into(), Preview),
                ("STAGING".into(), Preview),
                ("PRODUCTION".into(), Release),
                ("DISABLED".into(), Disablement),
                ("REMOVED".into(), Deletion),
                ("DESIGN".into(), Inert),
            ],
            None,
        )
    }

    #[test]
    fn runs_act_on_the_strategies_the_oracle_says() {
        assert!(deploys(Preview, Preview));
        assert!(deploys(Universal, Preview));
        assert!(deploys(Universal, Release));
        assert!(deploys(Disablement, Release));
        assert!(!deploys(Disablement, Preview));
        assert!(!deploys(Inert, Release));
        assert!(!deploys(Release, Preview));
        assert_eq!(deployed_by(Universal), vec![Preview, Release]);
        assert!(deployed_by(Inert).is_empty());
    }

    #[test]
    fn strategies_parse_in_deployable_order() {
        let parsed = parse_strategies(&["release", "PREVIEW,"], &statuses(), "--strategy");
        assert_eq!(parsed, Ok(vec![Preview, Release]));
    }

    #[test]
    fn a_status_name_is_answered_with_its_strategy() {
        let error = parse_strategies(&["STAGING"], &statuses(), "--strategy").unwrap_err();
        assert_eq!(
            error,
            "--strategy 'STAGING' is not a deployable strategy. Use PREVIEW or RELEASE. STAGING \
             was a deployment plan, removed in 0.17.0: pass PREVIEW. STAGING is also a \
             configured status name; it maps to PREVIEW, which a PREVIEW run deploys"
        );
        let error = parse_strategies(&["design"], &statuses(), "--strategy").unwrap_err();
        assert!(error.ends_with(
            "DESIGN is also a configured status name; it maps to INERT, which no run deploys"
        ));
        let error = parse_strategies(&["UNIVERSAL"], &statuses(), "--strategy").unwrap_err();
        assert!(error.contains("both PREVIEW and RELEASE runs deploy"));
    }

    #[test]
    fn a_status_maps_to_its_strategy() {
        assert_eq!(statuses().strategy("PRODUCTION"), Ok(Release));
        assert!(
            statuses()
                .strategy("NOPE")
                .unwrap_err()
                .exception_text()
                .starts_with("\"Status 'NOPE' is not defined")
        );
        let mut invalid = statuses();
        invalid.1 = Some("deployment.toml is invalid: x: unknown key".into());
        assert_eq!(
            invalid.strategy("PRODUCTION").unwrap_err().exception_text(),
            "deployment.toml is invalid: x: unknown key"
        );
        assert_eq!(
            statuses().deployed_by(&[Preview]),
            vec!["DEVELOPMENT", "STAGING"]
        );
    }

    #[test]
    fn the_removed_plan_names_its_replacement() {
        assert_eq!(
            removed_plan_message(Some("full"), true),
            "--plan was removed in 0.17.0: a run now says which status strategy it deploys. Use \
             --strategy PREVIEW --strategy RELEASE --all. See 'opentide deploy --help'."
        );
        assert!(removed_plan_message(None, false).contains(" Unset DEPLOYMENT_PLAN."));
    }

    #[test]
    fn repr_quotes_as_python_does() {
        assert_eq!(python_repr("a"), "'a'");
        assert_eq!(python_repr("it's"), "\"it's\"");
        assert_eq!(python_repr("a\nb"), "'a\\nb'");
        // Both quotes: single quotes, the single one escaped (Python's repr).
        assert_eq!(python_repr("a'b\""), "'a\\'b\"'");
        assert_eq!(python_repr("\\\r\t\u{1}\u{7f}é"), "'\\\\\\r\\t\\x01\\x7fé'");
    }

    #[test]
    fn a_retired_name_says_what_to_pass() {
        let hint = |name: &str| parse_strategies(&[name], &statuses(), "--strategy").unwrap_err();
        for (name, says) in [
            ("universal", "both PREVIEW and RELEASE runs deploy"),
            ("DISABLEMENT", "disables the changed rules"),
            ("deletion", "deletes the changed rules"),
            ("INERT", "never deployed"),
            ("full", "--strategy PREVIEW --strategy RELEASE --all"),
            ("ALWAYS", "lists the strategies it accepts"),
            ("manual", "sets 'manual = true'"),
            ("debug", "pass PREVIEW or RELEASE"),
            (
                "PRODUCTION",
                "PRODUCTION was a deployment plan, removed in 0.17.0: pass RELEASE",
            ),
        ] {
            let error = hint(name);
            assert!(
                error.starts_with(&format!(
                    "--strategy {} is not a deployable strategy. Use PREVIEW or RELEASE. ",
                    python_repr(name)
                )),
                "{error}"
            );
            assert!(error.contains(says), "{name}: {error}");
        }
        // A status no run deploys says so.
        assert!(hint("design").ends_with("it maps to INERT, which no run deploys"));
        assert!(hint("removed").ends_with("it maps to DELETION, which a RELEASE run deploys"));
        assert_eq!(
            hint("nothing"),
            "--strategy 'nothing' is not a deployable strategy. Use PREVIEW or RELEASE"
        );
    }

    #[test]
    fn an_invalid_deployment_names_each_key() {
        let document = opentide_schema::node::load(
            "statuses:\n- name: A\n  strategy: PREVIEW\n  colour: red\n- strategy: RELEASE\n",
        )
        .unwrap();
        let error = deployment_error(document.root().unwrap()).unwrap();
        assert!(error.starts_with("deployment.toml is invalid: "), "{error}");
        assert!(error.contains("statuses.0.colour: unknown key"), "{error}");
        assert!(
            error.contains("statuses.1.name: required key is missing"),
            "{error}"
        );
        let valid = opentide_schema::node::load(
            "statuses:\n- name: A\n  description: d\n  strategy: PREVIEW\n",
        )
        .unwrap();
        assert_eq!(deployment_error(valid.root().unwrap()), None);
        let invalid = Statuses(Vec::new(), Some(error.clone()));
        assert_eq!(
            invalid.strategy("A"),
            Err(StatusError::Invalid(error.clone()))
        );
        assert_eq!(StatusError::Invalid(error.clone()).exception_text(), error);
    }
}
