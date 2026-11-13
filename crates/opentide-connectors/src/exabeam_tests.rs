//! The Exabeam client's pure parts: the pacer on a paused clock, `Retry-After`,
//! Exabeam's error bodies, the name check, the created id and the `SELECT`
//! columns, ported from 0.28.0's `test_exabeam_deployer.py` and
//! `test_exabeam_runner.py`.

use super::*;

fn object(value: serde_json::Value) -> Object {
    match serde_json::from_value::<Json>(value) {
        Ok(Json::Object(object)) => object,
        _ => Object::new(),
    }
}

fn reply(status: u16, body: &str) -> Reply {
    Reply {
        answer: Answer {
            status,
            content_type: Some("application/json".to_owned()),
            body: body.as_bytes().to_vec(),
            elapsed: Duration::from_millis(5),
        },
        retry_after: None,
        challenge: None,
    }
}

#[tokio::test(start_paused = true)]
async fn the_pacer_lets_a_hundred_through_a_minute() {
    let pacer = Pacer::default();
    let started = Instant::now();
    for _ in 0..PACED_CALLS {
        pacer.wait().await;
    }
    assert_eq!(Instant::now(), started, "the first hundred do not wait");
    pacer.wait().await;
    assert_eq!(
        Instant::now().duration_since(started),
        PACE_WINDOW,
        "the 101st waits for the first to leave the window"
    );
    // The window rolls: the next one waits only until the second call leaves it.
    pacer.wait().await;
    assert_eq!(Instant::now().duration_since(started), PACE_WINDOW);
}

#[tokio::test(start_paused = true)]
async fn the_pacer_rolls_with_time_and_resets() {
    let pacer = Pacer::new(2, Duration::from_secs(10));
    let started = Instant::now();
    pacer.wait().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    pacer.wait().await;
    pacer.wait().await;
    assert_eq!(
        Instant::now().duration_since(started),
        Duration::from_secs(10)
    );
    pacer.wait().await;
    assert_eq!(
        Instant::now().duration_since(started),
        Duration::from_secs(14)
    );
    pacer.reset().await;
    let now = Instant::now();
    pacer.wait().await;
    pacer.wait().await;
    assert_eq!(Instant::now(), now);
}

#[tokio::test(start_paused = true)]
async fn the_pacer_is_shared_by_every_session_of_the_process() {
    let pacer = shared_pacer();
    assert!(Arc::ptr_eq(&pacer, &shared_pacer()));
    assert_eq!(pacer.limit, PACED_CALLS);
    assert_eq!(pacer.window, PACE_WINDOW);
    assert!(Arc::ptr_eq(&Exabeam::new().pacer, &shared_pacer()));
}

#[tokio::test(start_paused = true)]
async fn concurrent_sessions_queue_on_one_pacer() {
    let pacer = Arc::new(Pacer::new(3, Duration::from_secs(60)));
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..7 {
        let pacer = Arc::clone(&pacer);
        tasks.push(tokio::spawn(async move {
            pacer.wait().await;
            Instant::now().duration_since(started)
        }));
    }
    let mut waited = Vec::new();
    for task in tasks {
        waited.push(task.await.unwrap_or_default());
    }
    waited.sort();
    let seconds: Vec<u64> = waited.iter().map(Duration::as_secs).collect();
    assert_eq!(seconds, [0, 0, 0, 60, 60, 60, 120]);
}

#[test]
fn retry_after_reads_seconds_and_dates() {
    let now: jiff::Timestamp = "2026-11-11T12:00:00Z".parse().unwrap_or_default();
    assert_eq!(retry_after(None, now), DEFAULT_RETRY_AFTER);
    assert_eq!(retry_after(Some("  "), now), DEFAULT_RETRY_AFTER);
    assert_eq!(retry_after(Some("7"), now), Duration::from_secs(7));
    assert_eq!(retry_after(Some(" 1.5 "), now), Duration::from_millis(1500));
    assert_eq!(retry_after(Some("-3"), now), Duration::ZERO);
    assert_eq!(retry_after(Some("inf"), now), DEFAULT_RETRY_AFTER);
    assert_eq!(retry_after(Some("NaN"), now), DEFAULT_RETRY_AFTER);
    assert_eq!(retry_after(Some("soon"), now), DEFAULT_RETRY_AFTER);
    assert_eq!(
        retry_after(Some("Wed, 11 Nov 2026 12:00:30 GMT"), now),
        Duration::from_secs(30)
    );
    assert_eq!(
        retry_after(Some("Wed, 11 Nov 2026 11:00:00 GMT"), now),
        Duration::ZERO
    );
}

#[test]
fn api_errors_carry_exabeams_details() {
    let error = api_error(
        "POST /x",
        &reply(
            400,
            r#"{"errors": [{"code": "INVALID", "message": " bad query ", "fields": ["query", "name"]},
                {"code": "TOO_LONG"}, {"message": "only words", "fields": "name"}, 3],
               "traceId": "abc"}"#,
        ),
    );
    assert_eq!(error.status, 400);
    assert_eq!(error.errors.len(), 3);
    assert_eq!(error.trace_id.as_deref(), Some("abc"));
    assert_eq!(
        error.detail,
        "INVALID: bad query (fields: query, name); TOO_LONG; only words (fields: name) \
         (traceId abc)"
    );
    assert_eq!(
        error.to_string(),
        format!("POST /x: HTTP 400: {}", error.detail)
    );
    assert_eq!(
        api_error("a", &reply(500, r#"{"message": "boom"}"#)).detail,
        "boom"
    );
    assert_eq!(
        api_error("a", &reply(500, r#"{"error": "bad"}"#)).detail,
        "bad"
    );
    assert_eq!(
        api_error("a", &reply(500, r#"{"traceId": "t"}"#)).detail,
        r#"{"traceId": "t"} (traceId t)"#
    );
    let mut empty = reply(503, "");
    empty.answer.content_type = None;
    let detail = api_error("a", &empty).detail;
    assert!(!detail.is_empty(), "{detail}");
    let html = Reply {
        answer: Answer {
            content_type: Some("text/html".to_owned()),
            ..reply(502, "<html><title>Bad gateway</title></html>").answer
        },
        ..reply(502, "")
    };
    assert!(api_error("a", &html).detail.contains("Bad gateway"));
    assert!(ApiError::new("a", 404, "").not_found());
    assert!(!ApiError::new("a", 400, "").not_found());
}

#[test]
fn an_expired_token_is_read_from_the_body_or_the_challenge() {
    assert!(reply(401, r#"{"message": "Jwt is expired"}"#).token_expired());
    let mut challenge = reply(401, "");
    challenge.challenge =
        Some("Bearer error=\"invalid_token\", error_description=\"EXPIRED\"".into());
    assert!(challenge.token_expired());
    assert!(!reply(401, r#"{"message": "bad key"}"#).token_expired());
}

#[test]
fn a_body_that_is_not_json_is_an_api_error() {
    assert_eq!(reply(200, "").json("a").ok(), Some(None));
    let mut text = reply(200, "<html>no</html>");
    text.answer.content_type = Some("text/html".to_owned());
    assert!(text.json("a").is_err());
    assert!(reply(200, "[1]").json("a").is_ok());
}

#[test]
fn the_name_check_is_exact_and_case_insensitive() {
    let rules = vec![
        object(serde_json::json!({"id": "1", "name": "Failed Logins"})),
        object(serde_json::json!({"id": "2", "name": "Failed logins from outside"})),
        object(serde_json::json!({"id": "3"})),
        object(serde_json::json!({"id": "4", "name": "STRASSE"})),
    ];
    let ids = |name: &str| -> Vec<String> {
        name_matches(&rules, name)
            .iter()
            .map(|rule| rule.get("id").map(py_str).unwrap_or_default())
            .collect()
    };
    assert_eq!(ids("failed logins"), ["1"]);
    assert_eq!(ids("Failed"), Vec::<String>::new());
    assert_eq!(ids("straße"), ["4"]);
}

#[test]
fn the_created_id_is_a_canonical_uuid() {
    let id = |value: serde_json::Value| returned_rule_id(&object(serde_json::json!({"id": value})));
    assert_eq!(
        id(serde_json::json!(" 016DBC1D-A727-43DF-A143-9546DCC81A5A ")),
        Some("016dbc1d-a727-43df-a143-9546dcc81a5a".to_owned())
    );
    assert_eq!(
        id(serde_json::json!("016dbc1da72743dfa1439546dcc81a5a")),
        None
    );
    assert_eq!(
        id(serde_json::json!("{016dbc1d-a727-43df-a143-9546dcc81a5a}")),
        None
    );
    assert_eq!(id(serde_json::json!(42)), None);
    assert_eq!(returned_rule_id(&Object::new()), None);
}

#[test]
fn a_retained_schedule_is_one_the_body_no_longer_sets() {
    let stored = object(serde_json::json!({"scheduleConfig": {"recurrences": [{"x": 1}]}}));
    assert!(schedule_retained(&stored, false));
    assert!(!schedule_retained(&stored, true));
    assert!(!schedule_retained(
        &object(serde_json::json!({"scheduleConfig": {"recurrences": []}})),
        false
    ));
    assert!(schedule_retained(
        &object(serde_json::json!({"scheduleConfig": "on"})),
        false
    ));
    assert!(!schedule_retained(
        &object(serde_json::json!({"scheduleConfig": null})),
        false
    ));
    assert!(!schedule_retained(&Object::new(), false));
}

#[test]
fn selected_columns_are_the_select_list() {
    for (query, columns) in [
        (
            "SELECT user, COUNT(*) AS logins WHERE x GROUP-BY user",
            vec!["user", "logins"],
        ),
        (
            "select distinct host, src_ip | where x",
            vec!["host", "src_ip"],
        ),
        ("SELECT * WHERE x", vec![]),
        ("activity_type:\"app-login\"", vec![]),
        (
            "SELECT CONCAT(a, \"x, y\") AS joined, b FROM t",
            vec!["joined", "b"],
        ),
        ("SELECT a,, b", vec!["a", "b"]),
        ("SELECT 'it\\'s', c", vec!["'it\\'s'", "c"]),
        ("SELECT", vec![]),
    ] {
        assert_eq!(selected_columns(query), columns, "{query}");
    }
}

#[test]
fn rows_are_flattened_with_their_total() {
    let payload: Json = serde_json::from_value(serde_json::json!({
        "rows": [{"a": {"b": 1}}, 3, {"c": 2}],
        "totalRows": 10,
    }))
    .unwrap_or(Json::Null);
    let (found, total) = rows(&payload);
    assert_eq!(found.len(), 2);
    assert!(found[0].contains_key("a.b"));
    assert_eq!(total, Some(10));
    let (found, total) = rows(&Json::Array(Vec::new()));
    assert!(found.is_empty());
    assert_eq!(total, None);
    let bool_total: Json =
        serde_json::from_value(serde_json::json!({"totalRows": true})).unwrap_or(Json::Null);
    assert_eq!(rows(&bool_total).1, None);
}

#[test]
fn errors_display_as_python_does() {
    let tenant = TenantError {
        code: UNAUTHORIZED,
        message: "tenant t refused the API key: HTTP 401".to_owned(),
    };
    assert_eq!(
        tenant.to_string(),
        "exabeam_tenant_unauthorized: tenant t refused the API key: HTTP 401"
    );
    let failure = TenantFailure::of(Failure::Tenant(tenant));
    assert_eq!(failure.code, UNAUTHORIZED);
    assert!(matches!(
        failure.into_error("t"),
        ConnectorError::Refused { .. }
    ));
    let failure = TenantFailure::of(Failure::Api(ApiError::new("a", 429, "slow")));
    assert_eq!(failure.code, UNREACHABLE);
    let failure = TenantFailure::of(Failure::NoAnswer(ConnectorError::Cancelled));
    assert!(matches!(failure.into_error("t"), ConnectorError::Cancelled));
    let rejected = failed(&ApiError {
        errors: vec![
            serde_json::from_value(serde_json::json!({"code": "C", "message": "m", "x": 1}))
                .unwrap_or(Json::Null),
        ],
        trace_id: Some("t".to_owned()),
        ..ApiError::new("a", 400, "C: m")
    });
    assert_eq!(rejected.code, "exabeam_request_rejected");
    assert_eq!(
        rejected.fields,
        [
            ("errors", r#"[{"code":"C","message":"m"}]"#.to_owned()),
            ("trace_id", "t".to_owned())
        ]
    );
    assert_eq!(
        failed(&ApiError::new("a", 500, "x")).code,
        "exabeam_request_failed"
    );
    let window = rule_check_window("2026-11-11T12:00:00Z".parse().unwrap_or_default());
    assert_eq!(window.start.to_string(), "2026-11-11T11:45:00Z");
    assert_eq!(http_defaults().timeout, Duration::from_secs(30));
}
