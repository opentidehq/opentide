//! `validate`'s compile check (#660; UC-2.2, #817; `validation/compile_check.py`):
//! what a deploy would compile must compile.
//!
//! A platform's compiler has requirements its schema does not state (Sentinel
//! builds no alert rule without `grouping.alert`). Rather than restate them,
//! `validate` runs the offline compiler `deploy --dry-run` runs
//! ([`preview::compile_offline`]) on each rule whose block's status deploys,
//! for each enabled platform that has one, and reports its error with the
//! same code, reason and hint. [`Compilers`] is the
//! [`CompileCheck`] the host passes to `opentide-workspace`'s `validate`,
//! which sits below this crate.

use std::collections::BTreeSet;

use opentide_schema::vocab::Vocabularies;
use opentide_workspace::Workspace;
use opentide_workspace::validate::{CompileCheck, CompileFailure, CompileRule};

use crate::json::Json;
use crate::preview;
use crate::rule::Rule;
use crate::strategy::StatusStrategy;
use crate::{Context, Owned};

/// The strategies whose rules a deploy compiles (`_COMPILED_STRATEGIES`): an
/// inert rule is never sent, and a deleted one is removed by its vendor id.
const COMPILED: [StatusStrategy; 4] = [
    StatusStrategy::Preview,
    StatusStrategy::Release,
    StatusStrategy::Universal,
    StatusStrategy::Disablement,
];

/// The platforms' offline compilers, as `validate`'s compile check.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compilers;

impl CompileCheck for Compilers {
    fn check(
        &self,
        ws: &Workspace,
        rules: &[CompileRule<'_>],
        enabled: &BTreeSet<String>,
    ) -> Vec<Vec<CompileFailure>> {
        let owned = Owned::new(&Vocabularies::bundled(), &ws.configuration().resolved);
        let cx = owned.context(ws.index());
        rules
            .iter()
            .map(|rule| failures(&cx, rule, enabled))
            .collect()
    }
}

/// The failures of one rule, by platform name.
pub fn failures(
    cx: &Context<'_>,
    rule: &CompileRule<'_>,
    enabled: &BTreeSet<String>,
) -> Vec<CompileFailure> {
    let compiled = Rule::new(rule.root, Some(rule.path.to_string_lossy().into_owned()));
    let mut platforms: Vec<&str> = preview::offline()
        .into_iter()
        .filter(|platform| enabled.contains(*platform))
        .collect();
    platforms.sort_unstable();
    let mut found = Vec::new();
    for platform in platforms {
        if !deploys(cx, compiled.block(platform)) {
            continue;
        }
        if let Some(Err(error)) = preview::compile_offline(cx, platform, &compiled) {
            found.push(CompileFailure {
                platform: platform.to_owned(),
                code: error.code.to_owned(),
                message: error.reason,
                hint: error.hint,
                field_path: error.field,
            });
        }
    }
    found
}

/// Whether a deploy compiles `block` (`_deploys`): a mapping whose status
/// maps to a compiled strategy. An unknown status is the schema's finding.
fn deploys(cx: &Context<'_>, block: Option<&Json>) -> bool {
    let Some(Json::Object(block)) = block else {
        return false;
    };
    let Some(status) = block.get("status").and_then(Json::as_str) else {
        return false;
    };
    cx.statuses
        .strategy(status)
        .is_ok_and(|strategy| COMPILED.contains(&strategy))
}
