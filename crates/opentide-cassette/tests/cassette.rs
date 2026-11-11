//! Redaction, the cassette format and wiremock replay.

use opentide_cassette::cassette::{Request, Response};
use opentide_cassette::{Body, Cassette, Interaction, Redaction, Replay};

#[test]
fn headers_keep_their_scheme_and_lose_their_value() {
    let redaction = Redaction::new(["known-value-1".to_owned()]);
    let headers = redaction.request_headers([
        ("Authorization", "Bearer eyJhbGciOi"),
        ("X-Api-Key", "k-123"),
        ("Cookie", "a=b"),
        ("User-Agent", "python-requests/2.32.3"),
        ("Host", "tenant"),
        ("Accept", "*/*"),
        ("Content-Type", "application/json"),
        ("X-Trace", "carries known-value-1"),
        ("elastic-api-version", "2023-10-31"),
    ]);
    assert_eq!(
        headers,
        [
            ("authorization".to_owned(), "Bearer REDACTED".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
            ("cookie".to_owned(), "REDACTED".to_owned()),
            ("elastic-api-version".to_owned(), "2023-10-31".to_owned()),
            ("x-api-key".to_owned(), "REDACTED".to_owned()),
            ("x-trace".to_owned(), "carries REDACTED".to_owned()),
        ]
    );
    // An Accept that names a type is the client's choice: kept.
    assert_eq!(
        redaction.request_headers([("Accept", "application/json")]),
        [("accept".to_owned(), "application/json".to_owned())]
    );
    assert_eq!(
        redaction.header("Authorization", "SSWS abc"),
        "SSWS REDACTED"
    );
    assert_eq!(redaction.header("Authorization", "abc"), "REDACTED");
}

#[test]
fn urls_and_bodies_lose_secrets_in_place() {
    let redaction = Redaction::default();
    assert_eq!(
        redaction.url("https://u:p@tenant.invalid/a?token=t1&page=2&api_key=k&code=c"),
        "https://REDACTED:REDACTED@tenant.invalid/a?token=REDACTED&page=2&api_key=REDACTED&code=REDACTED"
    );
    assert_eq!(
        redaction.url("https://tenant.invalid/a?q=x"),
        "https://tenant.invalid/a?q=x"
    );
    // JSON: the value under a secret key goes, the layout stays.
    let body = br#"{"name": "r", "auth": {"client_secret": "s3cr3t", "password": "pw-1"}, "n": 1}"#;
    assert_eq!(
        String::from_utf8(redaction.body(body)).unwrap(),
        r#"{"name": "r", "auth": {"client_secret": "REDACTED", "password": "REDACTED"}, "n": 1}"#
    );
    // A form body.
    assert_eq!(
        redaction.body(b"grant_type=client_credentials&client_secret=abc123&scope=x"),
        b"grant_type=client_credentials&client_secret=REDACTED&scope=x"
    );
    // Nothing secret: the bytes are the same.
    let plain = br#"{"name":"r","tags":["a"]}"#;
    assert_eq!(redaction.body(plain), plain);
    let binary = [0xff_u8, 0x00, 0x10];
    assert_eq!(redaction.body(&binary), binary);
}

fn interaction(method: &str, url: &str, body: &str, status: u16, answer: &str) -> Interaction {
    Interaction {
        request: Request {
            method: method.into(),
            url: url.into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: Body::Text(body.into()),
        },
        response: Response {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Body::Text(answer.into()),
        },
    }
}

#[test]
fn a_cassette_is_recorded_never_edited() {
    let cassette = Cassette::new(
        "s",
        vec!["client".into()],
        vec![interaction("GET", "https://t.invalid/a", "", 200, "{}")],
    );
    let text = cassette.to_text();
    assert_eq!(Cassette::parse(&text).unwrap(), cassette);
    let edited = text.replace("\"status\": 200", "\"status\": 201");
    assert!(
        Cassette::parse(&edited)
            .unwrap_err()
            .contains("never edited")
    );
    let binary = Body::from_bytes(&[0xff, 0x01]);
    assert_eq!(binary.bytes(), [0xff, 0x01]);
    assert!(matches!(binary, Body::Binary { .. }));
}

#[test]
fn replay_serves_in_order_checks_bytes_and_repeats_whole_passes() {
    let cassette = Cassette::new(
        "s",
        vec![],
        vec![
            interaction(
                "POST",
                "https://t.invalid/rules",
                "{\"a\": 1}",
                201,
                "{\"id\": \"r-1\"}",
            ),
            interaction(
                "GET",
                "https://t.invalid/rules/r-1",
                "",
                200,
                "{\"ok\": true}",
            ),
        ],
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let send = |replay: &Replay, method: &str, path: &str, body: &str| {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = format!("{}{path}", replay.uri());
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        runtime.block_on(async {
            let answer = client
                .request(method, url)
                .header("content-type", "application/json")
                .body(body.to_owned())
                .send()
                .await
                .unwrap();
            (answer.status().as_u16(), answer.text().await.unwrap())
        })
    };
    let origin = Some("https://t.invalid".to_owned());
    let replay = runtime.block_on(Replay::start(
        cassette.clone(),
        Redaction::default(),
        origin.clone(),
    ));
    // Two passes, as compare mode's two runs send them.
    for _ in 0..2 {
        assert_eq!(
            send(&replay, "POST", "/rules", "{\"a\": 1}"),
            (201, "{\"id\": \"r-1\"}".into())
        );
        assert_eq!(
            send(&replay, "GET", "/rules/r-1", ""),
            (200, "{\"ok\": true}".into())
        );
    }
    assert_eq!(runtime.block_on(replay.verify()), Vec::new());

    // Out of order: the cassette's answer is not served, and verify says why.
    let replay = runtime.block_on(Replay::start(
        cassette.clone(),
        Redaction::default(),
        origin.clone(),
    ));
    assert_eq!(send(&replay, "GET", "/rules/r-1", "").0, 599);
    let mismatches = runtime.block_on(replay.verify());
    assert_eq!(mismatches[0].index, 0);
    assert!(
        mismatches[0]
            .detail
            .starts_with("method POST was recorded, GET sent")
    );

    // One byte off in a body.
    let replay = runtime.block_on(Replay::start(
        cassette.clone(),
        Redaction::default(),
        origin.clone(),
    ));
    assert_eq!(send(&replay, "POST", "/rules", "{\"a\": 2}").0, 599);
    let mismatches = runtime.block_on(replay.verify());
    assert_eq!(
        mismatches[0].detail,
        "bodies differ at byte 6: recorded \"{\\\"a\\\": 1}\", sent \"{\\\"a\\\": 2}\""
    );
    // A pass cut short.
    let replay = runtime.block_on(Replay::start(cassette, Redaction::default(), origin));
    send(&replay, "POST", "/rules", "{\"a\": 1}");
    let mismatches = runtime.block_on(replay.verify());
    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        mismatches[0].to_string(),
        "request 2: GET https://t.invalid/rules/r-1 was recorded and never sent"
    );
}

#[test]
fn a_name_ending_in_key_is_a_secret_and_one_merely_ending_in_key_is_not() {
    use opentide_cassette::redact::is_secret_name;
    // In no SECRET_WORDS entry: only the `_key` / `-key` suffix makes them secret.
    for name in ["client_key", "ACCESS_KEY", "x-tenant-key", "Key"] {
        assert!(is_secret_name(name), "{name}");
    }
    for name in ["monkey", "keyboard", "key_id", "hotkeys"] {
        assert!(!is_secret_name(name), "{name}");
    }
    let redaction = Redaction::default();
    let url = redaction.url("https://tenant.invalid/api?client_key=abc123&monkey=banana");
    assert_eq!(
        url,
        "https://tenant.invalid/api?client_key=REDACTED&monkey=banana"
    );
}

#[test]
fn known_secrets_of_three_characters_or_more_are_redacted() {
    // Short values (a tenant's three-letter PIN): redacted wherever they
    // appear. Two characters would redact half of every recording, so they
    // are not.
    let redaction = Redaction::new(["abc".to_owned(), "xy".to_owned(), String::new()]);
    assert_eq!(redaction.text("abc xy abcd"), "REDACTED xy REDACTEDd");
    assert_eq!(redaction.text("ab"), "ab");
}
