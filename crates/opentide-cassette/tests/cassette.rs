//! Redaction, the cassette format and wiremock replay.

use opentide_cassette::cassette::{Request, Response};
use opentide_cassette::replay::{compare, optional, same_body, same_form, same_url, verify};
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
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn replay_serves_in_order_checks_bodies_and_repeats_whole_passes() {
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

    // The same JSON in another layout: keys reordered, no spaces, non-ASCII
    // as UTF-8 rather than escaped. It is the same data, so it matches.
    let replay = runtime.block_on(Replay::start(
        Cassette::new(
            "s",
            vec![],
            vec![interaction(
                "POST",
                "https://t.invalid/rules",
                "{\"a\": 1, \"b\": [\"caf\\u00e9\", {\"c\": null}]}",
                201,
                "{}",
            )],
        ),
        Redaction::default(),
        origin.clone(),
    ));
    assert_eq!(
        send(
            &replay,
            "POST",
            "/rules",
            "{\"b\":[\"café\",{\"c\":null}],\"a\":1}"
        )
        .0,
        201
    );
    assert_eq!(runtime.block_on(replay.verify()), Vec::new());

    // A value changed in a body.
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

#[test]
fn json_bodies_match_as_data_and_other_bodies_as_bytes() {
    let matches = |want: &str, got: &str| same_body(want.as_bytes(), got.as_bytes());
    // Reordered, re-spaced, escaped differently: the same data.
    assert!(matches(r#"{"a": 1, "b": "x"}"#, r#"{"b":"x","a":1}"#));
    assert!(matches(
        "{\n    \"a\": [1, 2],\n    \"z\": \"\\u00e9\\ud83d\\ude00\"\n}",
        r#"{"z":"é😀","a":[1,2]}"#
    ));
    assert!(matches(r#"[{"k": true}]"#, r#"[{"k":true}]"#));
    // A JSON document held in a string (a rule sent as text) is data too.
    assert!(matches(
        r#"{"rule": "{\"q\": \"x\", \"n\": 2}"}"#,
        r#"{"rule":"{\"n\":2,\"q\":\"x\"}"}"#
    ));
    // A changed value, a key added or missing, a reordered array: different.
    assert!(!matches(r#"{"a": 1}"#, r#"{"a": 2}"#));
    assert!(!matches(r#"{"a": 1}"#, r#"{"a": "1"}"#));
    assert!(!matches(r#"{"a": 1}"#, r#"{"a": 1.0}"#));
    assert!(!matches(r#"{"a": 1}"#, r#"{"a": 1, "b": null}"#));
    assert!(!matches(r#"{"a": 1, "b": null}"#, r#"{"a": 1}"#));
    assert!(!matches("[1, 2]", "[2, 1]"));
    assert!(!matches(
        r#"{"rule": "{\"q\": \"x\"}"}"#,
        r#"{"rule": "{\"q\": \"y\"}"}"#
    ));
    // A string that is not a JSON document is compared as text.
    assert!(!matches(r#"{"q": "a  b"}"#, r#"{"q": "a b"}"#));
    // Not JSON: byte for byte. A form body, an empty body, binary.
    assert!(matches("a=1&b=2", "a=1&b=2"));
    assert!(!matches("a=1&b=2", "b=2&a=1"));
    assert!(!matches("a=1", "a=1 "));
    assert!(matches("", ""));
    assert!(!matches("", "{}"));
    assert!(!matches("{\"a\": 1}", "{\"a\": 1"));
    assert!(same_body(&[0xff, 0x00], &[0xff, 0x00]));
    assert!(!same_body(&[0xff, 0x00], &[0xff, 0x01]));
}

#[test]
fn urls_match_once_decoded_and_differ_by_value() {
    // Python's quote_plus and url's form_urlencoded write the same query.
    assert!(same_url(
        "https://t.invalid/a?q=a+b&p=%7E%2a",
        "https://t.invalid/a?q=a%20b&p=~*"
    ));
    assert!(same_url(
        "https://t.invalid/a?ts=2026-10-26T08%3A00%3A00Z",
        "https://t.invalid/a?ts=2026-10-26T08%3a00%3a00Z"
    ));
    // Parameter names in any order; no query and an empty one alike.
    assert!(same_url(
        "https://t.invalid/a?x=1&y=2",
        "https://t.invalid/a?y=2&x=1"
    ));
    assert!(same_url("https://t.invalid/a", "https://t.invalid/a?"));
    // The path, segment by segment, percent-decoded.
    assert!(same_url(
        "https://t.invalid/ws/soc%20workspace/r%7E1",
        "https://t.invalid/ws/soc%20workspace/r~1"
    ));
    assert!(same_url("https://t.invalid:443/a", "https://t.invalid/a"));
    // A different value, name, path, host or a missing parameter: different.
    assert!(!same_url(
        "https://t.invalid/a?q=a+b",
        "https://t.invalid/a?q=a+c"
    ));
    assert!(!same_url(
        "https://t.invalid/a?q=1",
        "https://t.invalid/a?r=1"
    ));
    assert!(!same_url(
        "https://t.invalid/a?q=1&r=2",
        "https://t.invalid/a?q=1"
    ));
    assert!(!same_url(
        "https://t.invalid/a?b=True",
        "https://t.invalid/a?b=true"
    ));
    assert!(!same_url("https://t.invalid/a/b", "https://t.invalid/a/c"));
    assert!(!same_url("https://t.invalid/a", "https://u.invalid/a"));
    assert!(!same_url("https://t.invalid/a", "http://t.invalid/a"));
    // An encoded slash stays inside its segment.
    assert!(!same_url(
        "https://t.invalid/a%2Fb",
        "https://t.invalid/a/b"
    ));
    // A repeated name's values keep their order.
    assert!(same_url(
        "https://t.invalid/a?id=1&x=0&id=2",
        "https://t.invalid/a?x=0&id=1&id=2"
    ));
    assert!(!same_url(
        "https://t.invalid/a?id=1&id=2",
        "https://t.invalid/a?id=2&id=1"
    ));
    // Not a URL: equal text only.
    assert!(same_url("not a url", "not a url"));
    assert!(!same_url("not a url", "not  a url"));
}

#[test]
fn form_bodies_match_as_decoded_fields() {
    let matches = |want: &str, got: &str| same_form(want.as_bytes(), got.as_bytes());
    assert!(matches(
        "scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&grant_type=client_credentials",
        "grant_type=client_credentials&scope=https%3a%2f%2fgraph.microsoft.com%2f.default"
    ));
    assert!(matches(
        "search=index%3Dmain+%7C+stats+count%0A%7C%60m%28x%29%60",
        "search=index%3Dmain%20%7C%20stats%20count%0A%7C%60m(x)%60"
    ));
    assert!(!matches("a=1&b=2", "a=1&b=3"));
    assert!(!matches("a=1&b=2", "a=1"));
    assert!(!matches("a=1", "a=1&b="));
    assert!(!matches("reload_macros=True", "reload_macros=true"));
    assert!(!matches("id=1&id=2", "id=2&id=1"));
}

fn request(method: &str, url: &str, headers: &[(&str, &str)], body: &str) -> Request {
    Request {
        method: method.into(),
        url: url.into(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: Body::Text(body.into()),
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
fn identity_headers_are_ignored_and_meaningful_ones_compared() {
    const URL: &str = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token";
    const ACCEPT: (&str, &str) = ("accept", "application/json");
    const FORM: (&str, &str) = ("content-type", "application/x-www-form-urlencoded");
    const BODY: &str =
        "client_id=app&client_secret=REDACTED&scope=https%3A%2F%2Fx.invalid%2F.default";
    // What MSAL.Python sent, as recorded.
    let recorded = request(
        "POST",
        URL,
        &[
            ACCEPT,
            ("client-request-id", "00000000-0000-4000-8000-000000000003"),
            FORM,
            ("x-client-current-telemetry", "4|730,2|"),
            ("x-client-last-telemetry", "4|0|||"),
            ("x-client-os", "linux"),
            ("x-client-sku", "MSAL.Python"),
            ("x-client-ver", "1.39.0"),
            (
                "x-ms-client-request-id",
                "00000000-0000-4000-8000-000000000004",
            ),
            ("x-ms-lib-capability", "retry-after, h429"),
        ],
        BODY,
    );
    let differs = |headers: &[(&str, &str)], body: &str| {
        compare(&[&recorded], &[request("POST", URL, headers, body)])
            .first()
            .map(|mismatch| mismatch.detail.clone())
    };
    // A plain client: no identity headers, its own encoding and field order.
    assert_eq!(
        differs(
            &[ACCEPT, FORM],
            "scope=https%3a%2f%2fx.invalid%2f.default&client_secret=REDACTED&client_id=app"
        ),
        None
    );
    // Other identity values, or other identity headers: still the same.
    assert_eq!(
        differs(
            &[
                ACCEPT,
                ("client-request-id", "another-id"),
                FORM,
                ("x-client-sku", "some-other-client"),
            ],
            BODY
        ),
        None
    );
    // A meaningful header missing, changed or added: a mismatch.
    let header_mismatch = |headers: &[(&str, &str)]| {
        differs(headers, BODY).is_some_and(|detail| detail.starts_with("headers "))
    };
    // `Accept` at a token endpoint: it answers JSON whatever is asked
    // (RFC 6749 §5.1), so the header is left out on both sides.
    assert_eq!(differs(&[FORM], BODY), None);
    assert_eq!(differs(&[("accept", "application/xml"), FORM], BODY), None);
    // Anywhere else it is compared.
    let elsewhere = request("GET", "https://api.invalid/rules", &[ACCEPT], "");
    assert!(
        compare(
            &[&elsewhere],
            &[request("GET", "https://api.invalid/rules", &[], "")]
        )
        .first()
        .is_some_and(|mismatch| mismatch.detail.starts_with("headers "))
    );
    // MSAL's `client_info=1` is left out of a form on both sides; any other
    // field is not.
    assert_eq!(
        differs(&[ACCEPT, FORM], &format!("{BODY}&client_info=1")),
        None
    );
    assert!(
        differs(&[ACCEPT, FORM], &format!("{BODY}&client_extra=1"))
            .is_some_and(|detail| detail.starts_with("bodies differ"))
    );
    // Only at Entra ID's token endpoint: another host's token endpoint, or
    // another Entra path, compares `client_info` like any field.
    for elsewhere in [
        "https://api.crowdstrike.invalid/oauth2/token",
        "https://login.microsoftonline.com.evil.invalid/tenant/oauth2/v2.0/token",
        "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
    ] {
        let want = request("POST", elsewhere, &[ACCEPT, FORM], BODY);
        let got = request(
            "POST",
            elsewhere,
            &[ACCEPT, FORM],
            &format!("{BODY}&client_info=1"),
        );
        assert!(
            compare(&[&want], &[got])
                .first()
                .is_some_and(|mismatch| mismatch.detail.starts_with("bodies differ")),
            "{elsewhere}"
        );
    }
    assert!(header_mismatch(&[
        ACCEPT,
        ("content-type", "application/json")
    ]));
    assert!(header_mismatch(&[
        ACCEPT,
        ("authorization", "Bearer REDACTED"),
        FORM
    ]));
    // A field's value changed: a mismatch in the body.
    assert!(
        differs(
            &[ACCEPT, FORM],
            "client_id=app&client_secret=REDACTED&scope=https%3A%2F%2Fy.invalid%2F.default"
        )
        .is_some_and(|detail| detail.starts_with("bodies differ"))
    );
    // A query encoded otherwise matches; a query value changed does not.
    let want = request("GET", "https://t.invalid/s?q=a+b%2A&n=1", &[], "");
    let sent = |url: &str| compare(&[&want], &[request("GET", url, &[], "")]);
    assert_eq!(sent("https://t.invalid/s?n=1&q=a%20b*"), []);
    assert!(
        sent("https://t.invalid/s?n=2&q=a%20b*")[0]
            .detail
            .starts_with("URL ")
    );
    // The method stays strict.
    assert!(
        compare(
            &[&want],
            &[request("POST", "https://t.invalid/s?q=a+b%2A&n=1", &[], "")]
        )[0]
        .detail
        .starts_with("method ")
    );
}

/// A repeated sign-in the recording client made and a client keeping its
/// token leaves out; the first sign-in, and any other repeated request,
/// are never optional.
#[test]
fn only_a_repeated_token_request_may_be_left_out() {
    const TOKEN: &str = "https://api.t.invalid/oauth2/token";
    const FORM: &str = "client_id=app&client_secret=REDACTED";
    const JOB: &str = "{\"q\": 1}";
    let interactions = vec![
        interaction("POST", TOKEN, FORM, 201, "{}"),
        interaction("POST", "https://api.t.invalid/jobs", JOB, 200, "{}"),
        interaction("POST", TOKEN, FORM, 201, "{}"),
        interaction("POST", "https://api.t.invalid/jobs", JOB, 200, "{}"),
        interaction(
            "POST",
            TOKEN,
            "client_id=other&client_secret=REDACTED",
            201,
            "{}",
        ),
    ];
    let optional_at: Vec<bool> = (0..7).map(|at| optional(&interactions, at)).collect();
    // Positions 5 and 6 begin the second pass: its first sign-in is not
    // optional.
    assert_eq!(
        optional_at,
        [false, false, true, false, false, false, false]
    );
    assert!(optional(&interactions, 7));
    let sent = |indices: &[usize]| -> Vec<Request> {
        indices
            .iter()
            .map(|&i| interactions[i].request.clone())
            .collect()
    };
    // The token kept: the second sign-in left out.
    assert_eq!(verify(&interactions, &sent(&[0, 1, 3, 4])), Vec::new());
    // As recorded.
    assert_eq!(verify(&interactions, &sent(&[0, 1, 2, 3, 4])), Vec::new());
    // A second pass signs in again, then may keep that token.
    assert_eq!(
        verify(&interactions, &sent(&[0, 1, 2, 3, 4, 0, 1, 3, 4])),
        Vec::new()
    );
    // A second pass with no sign-in of its own is a difference: each pass
    // needs at least one.
    let mismatches = verify(&interactions, &sent(&[0, 1, 2, 3, 4, 1, 3]));
    assert_eq!(mismatches.first().map(|mismatch| mismatch.index), Some(5));
    // The first sign-in, or another client's, is never left out.
    let mismatches = verify(&interactions, &sent(&[1, 3, 4]));
    assert_eq!(mismatches[0].index, 0);
    let mismatches = verify(&interactions, &sent(&[0, 1, 3]));
    assert_eq!(
        mismatches.last().map(ToString::to_string),
        Some(format!(
            "request 4: POST {TOKEN} was recorded and never sent"
        ))
    );
    // A repeated request that is not a sign-in is not optional either.
    assert!(!verify(&interactions, &sent(&[0, 1, 4])).is_empty());

    // Served: the left-out sign-in's answer is passed over.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let replay = runtime.block_on(Replay::start(
        Cassette::new("s", vec![], interactions.clone()),
        Redaction::default(),
        Some("https://api.t.invalid".to_owned()),
    ));
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let post = |path: &str, body: &str| {
        runtime.block_on(async {
            client
                .post(format!("{}{path}", replay.uri()))
                .header("content-type", "application/json")
                .body(body.to_owned())
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    assert_eq!(post("/oauth2/token", FORM), 201);
    assert_eq!(post("/jobs", JOB), 200);
    assert_eq!(post("/jobs", JOB), 200);
    assert_eq!(
        post("/oauth2/token", FORM),
        599,
        "not the other client's sign-in"
    );
    let mismatches = runtime.block_on(replay.verify());
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches[0].index, 3);
}

/// MSAL's OpenID discovery `GET` before a sign-in is optional: a
/// client-credentials client goes straight to the token endpoint.
#[test]
fn an_openid_discovery_get_may_be_left_out() {
    const DISCOVERY: &str =
        "https://login.microsoftonline.com/t/v2.0/.well-known/openid-configuration";
    const TOKEN: &str = "https://login.microsoftonline.com/t/oauth2/v2.0/token";
    // A discovery on any other host is a request like any other.
    for elsewhere in [
        "https://login.invalid/t/v2.0/.well-known/openid-configuration",
        "https://login.microsoftonline.com.evil.invalid/t/v2.0/.well-known/openid-configuration",
        "http://login.microsoftonline.com/t/v2.0/.well-known/openid-configuration",
    ] {
        let interactions = vec![interaction("GET", elsewhere, "", 200, "{}")];
        assert!(!optional(&interactions, 0), "{elsewhere}");
    }
    let interactions = vec![
        interaction("GET", DISCOVERY, "", 200, "{}"),
        interaction("POST", TOKEN, "client_id=a", 200, "{}"),
        interaction("GET", "https://api.invalid/x", "", 200, "{}"),
    ];
    assert_eq!(
        (0..3)
            .map(|at| optional(&interactions, at))
            .collect::<Vec<_>>(),
        [true, false, false]
    );
    let sent = |indices: &[usize]| -> Vec<Request> {
        indices
            .iter()
            .map(|&i| interactions[i].request.clone())
            .collect()
    };
    assert_eq!(verify(&interactions, &sent(&[1, 2])), Vec::new());
    assert_eq!(verify(&interactions, &sent(&[0, 1, 2])), Vec::new());
    // Only the discovery: the token request is still due.
    let mismatches = verify(&interactions, &sent(&[0, 2]));
    assert_eq!(mismatches[0].index, 1, "{mismatches:?}");
    assert!(
        mismatches[0]
            .detail
            .starts_with("method POST was recorded, GET sent"),
        "{mismatches:?}"
    );
}
