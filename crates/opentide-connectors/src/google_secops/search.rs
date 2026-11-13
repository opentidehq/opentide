//! `opentide query --platform google_secops`: a YARA-L search through the
//! Chronicle API v1 `udmSearch` with `queryDialect=YL2`, a read-only search
//! that saves nothing, ported from 0.28.0's `platforms/google_secops/runner.py`.
//!
//! A filter search returns UDM events; a search with `match` or `outcome`
//! returns statistics, one column per grouped or computed value.
//! `moreDataAvailable` or `stats.tooManyResults` marks the result truncated.
//! `--rule` is not supported: a rule runs in the detection engine, whose
//! results differ from a search's, and a retrohunt writes detections.

use opentide_compile::Json;
use opentide_compile::json::Object;

use crate::connector::{
    QueryColumn, QueryOutcome, QueryRequest, Row, TimeWindow, columns_of, flatten,
};

/// `udmSearch` returns at most this many events; Google coerces a larger
/// limit to it.
pub const MAX_UDM_LIMIT: usize = 10_000;

/// The warning of a truncated result.
pub const TRUNCATED: &str =
    "the search matched more than it returned: narrow the window or the query";

/// The search's query parameters, in order.
pub fn params(request: &QueryRequest) -> Vec<(&'static str, String)> {
    vec![
        ("query", request.text.trim().to_owned()),
        ("queryDialect", "YL2".to_owned()),
        (
            "timeRange.startTime",
            TimeWindow::utc_z(request.window.start),
        ),
        ("timeRange.endTime", TimeWindow::utc_z(request.window.end)),
        (
            "limit",
            request
                .limit
                .saturating_add(1)
                .min(MAX_UDM_LIMIT)
                .to_string(),
        ),
    ]
}

/// A stats cell (`{"value": {"int64Val": "5"}}`, `{"list": {...}}`) as a
/// plain value.
fn cell_value(cell: &Json) -> Json {
    let Json::Object(object) = cell else {
        return cell.clone();
    };
    if let Some(Json::Object(inner)) = object.get("value") {
        return inner.values().next().cloned().unwrap_or(Json::Null);
    }
    if let Some(list @ Json::Object(_)) = object.get("list") {
        return Json::Array(match list.get("values") {
            Some(Json::Array(values)) => values.iter().map(cell_value).collect(),
            _ => Vec::new(),
        });
    }
    if object.len() == 1 {
        return object.values().next().cloned().unwrap_or(Json::Null);
    }
    cell.clone()
}

fn stats_rows(stats: &Json) -> (Vec<QueryColumn>, Vec<Row>) {
    let results: Vec<&Json> = match stats.get("results") {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|item| item.as_object().is_some())
            .collect(),
        _ => Vec::new(),
    };
    let columns: Vec<QueryColumn> = results
        .iter()
        .enumerate()
        .map(|(index, item)| {
            QueryColumn::named(
                item.get("column")
                    .filter(|value| value.truthy())
                    .map_or_else(|| format!("column_{index}"), opentide_compile::deploy::text),
            )
        })
        .collect();
    let cells: Vec<&[Json]> = results
        .iter()
        .map(|item| match item.get("values") {
            Some(Json::Array(values)) => values.as_slice(),
            _ => &[],
        })
        .collect();
    let count = cells.iter().map(|values| values.len()).max().unwrap_or(0);
    let rows = (0..count)
        .map(|index| {
            let mut row = Object::new();
            for (column, values) in columns.iter().zip(&cells) {
                row.insert(
                    column.name.clone(),
                    values.get(index).map_or(Json::Null, cell_value),
                );
            }
            row
        })
        .collect();
    (columns, rows)
}

/// A `udmSearch` answer as rows: its events, or its statistics.
pub fn search_result(answer: &Json, limit: usize) -> QueryOutcome {
    let stats = answer
        .get("stats")
        .filter(|stats| stats.as_object().is_some());
    let has_stats = stats
        .and_then(|stats| stats.get("results"))
        .is_some_and(Json::truthy);
    let (columns, rows, truncated) = if let (true, Some(stats)) = (has_stats, stats) {
        let (columns, rows) = stats_rows(stats);
        let truncated = stats.get("tooManyResults").is_some_and(Json::truthy) || rows.len() > limit;
        (columns, rows, truncated)
    } else {
        let mut raw = answer.get("events");
        if let Some(inner @ Json::Object(_)) = raw {
            raw = inner.get("events");
        }
        let rows: Vec<Row> = match raw {
            Some(Json::Array(items)) => items
                .iter()
                .filter_map(|item| {
                    let event = match item.get("udm") {
                        Some(udm @ Json::Object(_)) => udm,
                        _ => item,
                    };
                    event.as_object().map(flatten)
                })
                .collect(),
            _ => Vec::new(),
        };
        let columns = columns_of(&rows[..rows.len().min(limit)]);
        let truncated =
            answer.get("moreDataAvailable").is_some_and(Json::truthy) || rows.len() > limit;
        (columns, rows, truncated)
    };
    QueryOutcome {
        columns,
        rows: rows.into_iter().take(limit).collect(),
        truncated,
        warnings: if truncated {
            vec![TRUNCATED.to_owned()]
        } else {
            Vec::new()
        },
        language: Some("yaral".to_owned()),
        ..QueryOutcome::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}"))
    }

    #[test]
    fn events_are_flattened_udm() {
        let answer = json(
            r#"{"events": {"events": [
                {"name": "e1", "udm": {"metadata": {"eventType": "USER_LOGIN"}, "principal": {"ip": ["10.0.0.1"]}}},
                {"name": "e2", "udm": {"metadata": {"eventType": "PROCESS_LAUNCH"}}}]},
               "moreDataAvailable": false}"#,
        );
        let outcome = search_result(&answer, 1);
        assert_eq!(outcome.rows.len(), 1);
        assert!(outcome.truncated);
        assert_eq!(outcome.warnings, [TRUNCATED]);
        let names: Vec<&str> = outcome
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        assert_eq!(names, ["metadata.eventType", "principal.ip"]);
        let all = search_result(&answer, 5);
        assert!(!all.truncated);
        assert_eq!(all.language.as_deref(), Some("yaral"));
    }

    #[test]
    fn statistics_are_one_column_per_value() {
        let answer = json(
            r#"{"stats": {"results": [
                {"column": "user", "values": [{"value": {"stringVal": "alice"}}, {"value": {}}]},
                {"column": "attempts", "values": [{"value": {"int64Val": "12"}}]},
                {"values": [{"list": {"values": [{"value": {"stringVal": "a"}}, {"stringVal": "b"}]}}]}]}}"#,
        );
        let outcome = search_result(&answer, 10);
        let names: Vec<&str> = outcome
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        assert_eq!(names, ["user", "attempts", "column_2"]);
        assert_eq!(outcome.rows.len(), 2);
        assert_eq!(
            Json::Object(outcome.rows[0].clone()).to_compact(),
            r#"{"user":"alice","attempts":"12","column_2":["a","b"]}"#
        );
        assert_eq!(
            Json::Object(outcome.rows[1].clone()).to_compact(),
            r#"{"user":null,"attempts":null,"column_2":null}"#
        );
        assert!(!outcome.truncated);
        let many = json(
            r#"{"stats": {"results": [{"column": "c", "values": []}], "tooManyResults": true}}"#,
        );
        assert!(search_result(&many, 10).truncated);
        assert!(search_result(&json("{}"), 10).rows.is_empty());
    }

    #[test]
    fn the_parameters_ask_for_one_row_more() {
        let start =
            jiff::Timestamp::from_second(1_800_000_000).unwrap_or_else(|error| panic!("{error}"));
        let end =
            jiff::Timestamp::from_second(1_800_003_600).unwrap_or_else(|error| panic!("{error}"));
        let mut request = QueryRequest::new(
            " $e.metadata.event_type = \"X\"\n",
            "yaral",
            TimeWindow { start, end },
        );
        assert_eq!(
            params(&request),
            [
                ("query", "$e.metadata.event_type = \"X\"".to_owned()),
                ("queryDialect", "YL2".to_owned()),
                ("timeRange.startTime", "2027-01-15T08:00:00.000Z".to_owned()),
                ("timeRange.endTime", "2027-01-15T09:00:00.000Z".to_owned()),
                ("limit", "101".to_owned()),
            ]
        );
        request.limit = 50_000;
        assert_eq!(params(&request)[4].1, "10000");
    }
}
