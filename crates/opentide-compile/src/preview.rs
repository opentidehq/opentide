//! A dry run's payload entries (`deployment/preview.py`): what each rule
//! would send, or why it would fail.

use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::{Context, elastic, sentinel};

/// The tenant a preview compiles for: exclusions scoped to a tenant name are
/// left out, so the payload is the one any tenant without a tenant-specific
/// exclusion receives.
pub const PREVIEW_TENANT: &str = "corpus-tenant";

/// The platforms whose request body opentide builds from the rule alone,
/// with no tenant (`OFFLINE_COMPILERS`), that this crate compiles.
pub const OFFLINE: [&str; 2] = ["sentinel", "elastic"];

/// The request body a deploy would send for `rule` on `platform` with no
/// tenant (`compile_offline`). `None` for a platform this crate does not
/// compile offline.
pub fn compile_offline(
    cx: &Context<'_>,
    platform: &str,
    rule: &Rule,
) -> Option<Result<Json, CompileError>> {
    match platform {
        "sentinel" => Some(sentinel::compile(cx, rule, PREVIEW_TENANT)),
        "elastic" => Some(elastic::compile(cx, rule, &elastic::Setup::none())),
        _ => None,
    }
}

/// One rule's preview entry.
#[derive(Debug, Clone, PartialEq)]
pub enum Preview {
    /// The entry, as the dry run's `payloads` lists it.
    Entry(Json),
    /// The oracle shows this rule's platform block as its model dump
    /// (`_config_preview`), which needs the platform models (UC-1.4, #810).
    ConfigDump,
}

/// The entry of a rule that compiled.
fn compiled(rule: &Rule, body: Json) -> Json {
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("api_request".into(), body);
    Json::Object(entry)
}

/// The entry of a rule that would fail to deploy (`_compile_failure`).
pub fn failure(rule: &Rule, error: &CompileError) -> Json {
    let mut entry = Object::new();
    entry.insert("uuid".into(), rule.uuid.clone().into());
    entry.insert("name".into(), rule.name.clone().into());
    entry.insert("status".into(), "failed".into());
    entry.insert("code".into(), error.code.into());
    entry.insert("error".into(), error.reason.clone().into());
    entry.insert(
        "help".into(),
        error.hint.clone().map_or(Json::Null, Json::Str),
    );
    entry.insert(
        "file".into(),
        rule.file.clone().map_or(Json::Null, Json::Str),
    );
    entry.insert("api_request".into(), Json::Null);
    Json::Object(entry)
}

/// The preview of `rule` on `platform` (`preview_rule_deployment`). Sentinel
/// reports a rule it cannot compile as a failure; Elastic falls back to the
/// block's dump, as every other platform does.
pub fn preview(cx: &Context<'_>, platform: &str, rule: &Rule) -> Preview {
    match platform {
        "sentinel" => match sentinel::compile(cx, rule, PREVIEW_TENANT) {
            Ok(body) => Preview::Entry(compiled(rule, body)),
            Err(error) => {
                // A compile error the oracle reports with the platform's
                // display name: compile_diagnostic(exc) names Sentinel.
                Preview::Entry(failure(rule, &error))
            }
        },
        "elastic" => match elastic::compile(cx, rule, &elastic::Setup::none()) {
            Ok(body) => Preview::Entry(compiled(rule, body)),
            Err(_) => Preview::ConfigDump,
        },
        _ => Preview::ConfigDump,
    }
}
