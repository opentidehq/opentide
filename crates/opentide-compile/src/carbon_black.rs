//! Carbon Black Cloud: the watchlist report a deploy creates on one tenant
//! for a rule, the body the Carbon Black SDK's
//! `Report.create(...).build().save_watchlist()` sends.
//!
//! What else a deploy does depends on what the org already holds (a report
//! of the same title is updated in place, its IOCs replaced or removed), so
//! the body compiled is the one sent when the report does not exist yet: the
//! rule's IOC in a new report, or nothing for a rule to retire. The SDK
//! stamps the report with the time it is built; `timestamp` is that time.

use crate::Context;
use crate::deploy::{self, Write};
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The platform's key under `configurations`.
pub const PLATFORM: &str = "carbon_black_cloud";

/// The platform's display name, in messages.
pub const DISPLAY: &str = "Carbon Black Cloud";

/// Carbon Black's severity of an opentide severity (`SEVERITY_MAPPING`).
fn severity(name: &str) -> Result<i64, CompileError> {
    Ok(match name {
        "Informational" => 1,
        "Low" => 3,
        "Medium" => 6,
        "High" => 8,
        "Critical" => 10,
        other => return Err(CompileError::failed(DISPLAY, &format!("{other:?}"))),
    })
}

/// What a deploy does with a rule's report on one tenant (`_deploy_to_org`'s
/// inputs): its IOC's query, the report's fields, the watchlist, and whether
/// the status deploys or retires it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The rule's name, trimmed.
    pub name: String,
    /// The rule's description, trimmed.
    pub description: String,
    /// The block's query, new lines as spaces.
    pub query: String,
    /// `true` unless the status disables or deletes the rule.
    pub deployment: bool,
    /// The status, the detection model and its techniques, the block's tags.
    pub tags: Vec<String>,
    /// The report's severity.
    pub severity: i64,
    /// The block's watchlist, else the tenant's.
    pub watchlist: String,
    /// The block's report, else the rule's name.
    pub report: String,
}

/// The report `rule` deploys on `tenant`, or `None` for a block with no
/// query (the Python deployer's `rule_skipped`).
pub fn report(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
) -> Result<Option<Report>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.is_filled()) else {
        return Ok(None);
    };
    let query = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if query.is_empty() {
        return Ok(None);
    }
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let strategy = deploy::strategy(cx, DISPLAY, status)?;
    let mut tags: Vec<String> = vec![status.to_owned()];
    if let Some(model) = deploy::rule_value(rule, &["detection_model"]).filter(|m| m.is_name()) {
        let techniques = deploy::inherited_techniques(cx, DISPLAY, rule)?;
        tags.push(Json::to_text(model));
        tags.extend(techniques);
    }
    if let Some(Json::Array(items)) = block.get("tags") {
        tags.extend(items.iter().map(Json::to_text));
    }
    let alert_severity = if rule.response().is_some() {
        rule.alert_severity()
    } else {
        "Low"
    };
    let name = rule.name.trim().to_owned();
    Ok(Some(Report {
        description: rule.description().trim().to_owned(),
        query: query.replace('\n', " "),
        deployment: !matches!(
            strategy,
            StatusStrategy::Disablement | StatusStrategy::Deletion
        ),
        tags,
        severity: severity(alert_severity)?,
        watchlist: block
            .get("watchlist")
            .filter(|value| value.is_filled())
            .or_else(|| deploy::setup(tenant, "watchlist"))
            .filter(|value| value.is_filled())
            .map(Json::to_text)
            .unwrap_or_default(),
        report: block
            .get("report")
            .filter(|value| value.is_filled())
            .map_or_else(|| name.clone(), Json::to_text),
        name,
    }))
}

/// The writes a deploy sends for `rule` to `tenant` when the org holds no
/// report of the rule's title: the new report (`POST .../reports`), then
/// the watchlist with the report added (`PUT .../watchlists/<id>`, the
/// watchlist as the deploy reads it from the tenant:
/// `<tenant-read:watchlist_id>`, `<tenant-read:watchlist>`), or none for a
/// rule to retire or a block with no query. Without a `timestamp` (a
/// dry run), the report's is the placeholder `<send-time:timestamp>`: the
/// deploy stamps it as it sends.
pub fn compile(
    cx: &Context<'_>,
    rule: &Rule,
    tenant: &Json,
    timestamp: Option<i64>,
) -> Result<Vec<Write>, CompileError> {
    let Some(block) = rule.block(PLATFORM).filter(|block| block.is_filled()) else {
        return Ok(Vec::new());
    };
    let query = block
        .get("query")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let name = rule.name.trim();
    let description = rule.description().trim();
    let status = block
        .get("status")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let query = query.replace('\n', " ");
    let strategy = deploy::strategy(cx, DISPLAY, status)?;
    let deployment = !matches!(
        strategy,
        StatusStrategy::Disablement | StatusStrategy::Deletion
    );
    let mut tags: Vec<String> = vec![status.to_owned()];
    if let Some(model) = deploy::rule_value(rule, &["detection_model"]).filter(|m| m.is_name()) {
        let techniques = deploy::inherited_techniques(cx, DISPLAY, rule)?;
        tags.push(Json::to_text(model));
        tags.extend(techniques);
    }
    if let Some(Json::Array(items)) = block.get("tags") {
        tags.extend(items.iter().map(Json::to_text));
    }
    let alert_severity = if rule.response().is_some() {
        rule.alert_severity()
    } else {
        "Low"
    };
    let severity = severity(alert_severity)?;
    let watchlist = block
        .get("watchlist")
        .filter(|value| value.is_filled())
        .or_else(|| deploy::setup(tenant, "watchlist"))
        .filter(|value| value.is_filled())
        .map(Json::to_text)
        .unwrap_or_default();
    let report = block
        .get("report")
        .filter(|value| value.is_filled())
        .map_or_else(|| name.to_owned(), Json::to_text);
    if watchlist.is_empty() {
        return Err(CompileError::failed(
            DISPLAY,
            &format!(
                "The CBC Deployer cannot create a detection in a nonexistent Watchlist: \
                 {watchlist}. Create it on the console before retriggering deployment."
            ),
        ));
    }
    if !deployment {
        return Ok(Vec::new());
    }
    let mut ioc = Object::new();
    ioc.insert("id".into(), rule.uuid.clone().into());
    ioc.insert("match_type".into(), "query".into());
    ioc.insert("values".into(), Json::Array(vec![query.into()]));
    let mut body = Object::new();
    body.insert("title".into(), report.into());
    body.insert("description".into(), description.into());
    body.insert("severity".into(), Json::Int(severity));
    body.insert(
        "timestamp".into(),
        timestamp.map_or_else(|| deploy::send_time("timestamp").into(), Json::Int),
    );
    body.insert(
        "tags".into(),
        Json::Array(
            tags.iter()
                .map(|tag| Json::Str(tag.trim().to_owned()))
                .collect(),
        ),
    );
    body.insert("iocs_v2".into(), Json::Array(vec![Json::Object(ioc)]));
    // The tenant's `url`, as the deploy reaches it, then the org's path.
    let org = format!(
        "{}/threathunter/watchlistmgr/v3/orgs/{}",
        deploy::setup_text(tenant, "url").trim_end_matches('/'),
        deploy::setup_text(tenant, "org_key")
    );
    // The new report joins the watchlist, which the deploy reads from the
    // tenant and writes back with the report's id added to `report_ids`.
    Ok(vec![
        Write::new("POST", format!("{org}/reports"), Json::Object(body)),
        Write::new(
            "PUT",
            format!("{org}/watchlists/{}", deploy::tenant_read("watchlist_id")),
            deploy::tenant_read("watchlist").into(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_are_carbon_blacks() {
        assert_eq!(severity("Informational").unwrap(), 1);
        assert_eq!(severity("Critical").unwrap(), 10);
        assert_eq!(
            severity("x").unwrap_err().reason,
            "Carbon Black Cloud cannot compile this rule: \"x\""
        );
    }
}
