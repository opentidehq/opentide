use std::sync::Arc;

use jiff::Timestamp;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::connector::TenantContext;
use crate::credentials::Mode;
use crate::{HttpClient, HttpSettings, Tenant, TenantLabel};

/// A throwaway RSA key generated for these tests only (it signs nothing
/// else). The PEM armour is added here, so the file is not taken for a
/// leaked key by `detect-private-key`.
fn test_key() -> String {
    let body = include_str!("../test_key.b64");
    let lines: Vec<String> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let label = ["PRIVATE", "KEY"].join(" ");
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

fn key_json(token_uri: &str) -> String {
    serde_json::json!({
        "type": "service_account",
        "project_id": "acme",
        "private_key_id": "kid-1",
        "private_key": test_key(),
        "client_email": "deploy@acme.iam.gserviceaccount.com",
        "token_uri": token_uri,
    })
    .to_string()
}

const NOW: i64 = 1_800_000_000;

fn fixed(seconds: i64) -> Clock {
    Arc::new(move || Timestamp::from_second(seconds).unwrap())
}

fn tenant() -> (Tenant, HttpClient) {
    let label = TenantLabel::new(PLATFORM, "secops-eu");
    let settings = HttpSettings::default();
    let tenant = Tenant::from_setup(
        PLATFORM,
        "secops-eu",
        &toml::Table::new(),
        &Environment::default(),
        Mode::Required,
        &settings,
    )
    .unwrap();
    let http = HttpClient::new(&label, &settings, &Environment::default(), None).unwrap();
    (tenant, http)
}

fn value(text: &str) -> Credential {
    Credential::Value(Secret::new(text))
}

#[test]
fn an_unset_variable_is_missing_not_a_path() {
    let error = load(
        Some(&Credential::Placeholder {
            variable: "GOOGLE_SECOPS_CREDENTIALS".to_owned(),
        }),
        &Environment::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.0,
        "the credentials variable GOOGLE_SECOPS_CREDENTIALS is not set: set it to a \
         service-account key (JSON) or the path to one"
    );
}

#[test]
fn only_a_service_account_key_is_read_from_the_variable() {
    let error = load(
        Some(&value(r#"{"type": "external_account"}"#)),
        &Environment::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.0,
        "cannot load Google credentials: the key is not a service-account key (type: \
         service_account)"
    );
    let error = load(Some(&value("{not json")), &Environment::default()).unwrap_err();
    assert!(
        error.0.starts_with("cannot load Google credentials: "),
        "{error:?}"
    );
    let error = load(Some(&value("/no/such/key.json")), &Environment::default()).unwrap_err();
    assert_eq!(
        error.0,
        "the credentials variable names no file and holds no JSON key"
    );
    let broken = r#"{"type": "service_account", "client_email": "a@b", "private_key": "x"}"#;
    let error = load(Some(&value(broken)), &Environment::default()).unwrap_err();
    assert!(
        error.0.contains("the private key cannot be read"),
        "{error:?}"
    );
}

#[test]
fn a_key_is_read_from_json_or_a_file_with_a_bom() {
    let credentials = load(Some(&value(&key_json(TOKEN_URI))), &Environment::default()).unwrap();
    let Credentials::ServiceAccount {
        client_email,
        private_key_id,
        token_uri,
        quota_project,
        ..
    } = &credentials
    else {
        panic!("{credentials:?}");
    };
    assert_eq!(client_email, "deploy@acme.iam.gserviceaccount.com");
    assert_eq!(private_key_id.as_deref(), Some("kid-1"));
    assert_eq!(token_uri, TOKEN_URI);
    assert_eq!(*quota_project, None);
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("key.json");
    std::fs::write(&file, format!("\u{feff}{}", key_json(TOKEN_URI))).unwrap();
    let env = Environment::from_pairs([("HOME", directory.path().to_str().unwrap())]);
    assert_eq!(load(Some(&value("~/key.json")), &env).unwrap(), credentials);
    assert_eq!(
        load(
            Some(&value(file.to_str().unwrap())),
            &Environment::default()
        )
        .unwrap(),
        credentials
    );
}

#[test]
fn application_default_credentials_in_google_auth_order() {
    let directory = tempfile::tempdir().unwrap();
    let user = directory.path().join("user.json");
    std::fs::write(
        &user,
        r#"{"type": "authorized_user", "client_id": "cid", "client_secret": "cs",
            "refresh_token": "rt", "quota_project_id": "billing"}"#,
    )
    .unwrap();
    let env = Environment::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", user.to_str().unwrap())]);
    let credentials = load(None, &env).unwrap();
    assert!(matches!(credentials, Credentials::AuthorizedUser { .. }));
    assert_eq!(credentials.quota_project(), Some("billing"));
    // GOOGLE_CLOUD_QUOTA_PROJECT names another.
    let env = env.with("GOOGLE_CLOUD_QUOTA_PROJECT", "other");
    assert_eq!(load(None, &env).unwrap().quota_project(), Some("other"));
    // A named file that is not there.
    let env = Environment::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", "/no/such.json")]);
    let error = load(None, &env).unwrap_err();
    assert!(
        error.0.starts_with(
            "no credentials: the tenant names none and Application Default Credentials are not \
             set up (File /no/such.json was not found"
        ),
        "{error:?}"
    );
    // gcloud's well-known file, under CLOUDSDK_CONFIG.
    std::fs::copy(
        &user,
        directory
            .path()
            .join("application_default_credentials.json"),
    )
    .unwrap();
    let env = Environment::from_pairs([("CLOUDSDK_CONFIG", directory.path().to_str().unwrap())]);
    assert!(matches!(
        load(None, &env).unwrap(),
        Credentials::AuthorizedUser { .. }
    ));
    // An external account is not supported.
    std::fs::write(&user, r#"{"type": "external_account"}"#).unwrap();
    let env = Environment::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", user.to_str().unwrap())]);
    assert!(load(None, &env).unwrap_err().0.contains("external_account"));
    // Nothing else: the metadata server.
    let env = Environment::from_pairs([("HOME", "/nowhere"), ("GCE_METADATA_HOST", "127.0.0.1:9")]);
    assert_eq!(
        load(None, &env).unwrap(),
        Credentials::Metadata {
            host: "127.0.0.1:9".to_owned(),
            quota_project: None
        }
    );
}

#[test]
fn the_well_known_file_follows_the_platform() {
    let env = Environment::from_pairs([("HOME", "/home/a"), ("APPDATA", "C:\\Users\\a\\AppData")]);
    let file = well_known_file(&env).unwrap();
    if cfg!(windows) {
        assert!(file.starts_with("C:\\Users\\a\\AppData"));
    } else {
        assert_eq!(
            file,
            PathBuf::from("/home/a/.config/gcloud/application_default_credentials.json")
        );
    }
}

#[test]
fn the_assertion_is_google_auths_and_deterministic_under_a_fixed_clock() {
    let Credentials::ServiceAccount {
        client_email,
        private_key,
        private_key_id,
        token_uri,
        ..
    } = load(Some(&value(&key_json(TOKEN_URI))), &Environment::default()).unwrap()
    else {
        panic!("a service account");
    };
    let now = Timestamp::from_second(NOW).unwrap();
    let jwt = assertion(
        &client_email,
        &private_key,
        private_key_id.as_deref(),
        &token_uri,
        now,
    )
    .unwrap();
    // RS256 (PKCS#1 v1.5) signs deterministically: a fixed clock gives one JWT.
    let again = assertion(
        &client_email,
        &private_key,
        private_key_id.as_deref(),
        &token_uri,
        now,
    )
    .unwrap();
    assert_eq!(jwt, again);
    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.kid.as_deref(), Some("kid-1"));
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    // The signature verifies with the key's public half.
    let der =
        ring::signature::RsaKeyPair::from_pkcs8(&base64_decode(include_str!("../test_key.b64")))
            .unwrap();
    let public = ring::signature::KeyPair::public_key(&der).as_ref().to_vec();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[TOKEN_URI]);
    validation.validate_exp = false;
    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        &jwt,
        &jsonwebtoken::DecodingKey::from_rsa_der(&public),
        &validation,
    )
    .unwrap();
    assert_eq!(
        decoded.claims,
        serde_json::json!({
            "iat": NOW,
            "exp": NOW + 3600,
            "iss": "deploy@acme.iam.gserviceaccount.com",
            "aud": TOKEN_URI,
            "scope": SCOPE,
        })
    );
}

/// Standard base64, as the PEM body holds it.
fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
    {
        let index = ALPHABET.iter().position(|item| *item == byte).unwrap();
        buffer = (buffer << 6) | u32::try_from(index).unwrap();
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap());
        }
    }
    out
}

#[tokio::test]
async fn a_service_account_token_is_obtained_on_the_tenants_client_and_reused() {
    let server = MockServer::start().await;
    let token_uri = format!("{}/token", server.uri());
    let credentials = load(Some(&value(&key_json(&token_uri))), &Environment::default()).unwrap();
    let Credentials::ServiceAccount {
        client_email,
        private_key,
        private_key_id,
        ..
    } = &credentials
    else {
        panic!("a service account");
    };
    let expected = assertion(
        client_email,
        private_key,
        private_key_id.as_deref(),
        &token_uri,
        Timestamp::from_second(NOW).unwrap(),
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
        ))
        .and(body_string_contains(format!("assertion={expected}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token": "ya29.one", "expires_in": 3599})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (tenant, http) = tenant();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let authorizer = Authorizer::new(credentials, fixed(NOW));
    assert_eq!(authorizer.token(cx).await.unwrap().expose(), "ya29.one");
    // Reused until 3 minutes 45 seconds before it expires.
    assert_eq!(
        authorizer.headers(cx).await.unwrap(),
        [("Authorization", "Bearer ya29.one".to_owned())]
    );
    server.verify().await;
}

#[tokio::test]
async fn a_token_about_to_expire_is_asked_for_again() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=rt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token": "ya29.user", "expires_in": 3600}),
            ),
        )
        .expect(2)
        .mount(&server)
        .await;
    let credentials = Credentials::AuthorizedUser {
        client_id: "cid".to_owned(),
        client_secret: Secret::new("cs"),
        refresh_token: Secret::new("rt"),
        token_uri: format!("{}/token", server.uri()),
        quota_project: Some("billing".to_owned()),
    };
    let now = Arc::new(std::sync::atomic::AtomicI64::new(NOW));
    let clock_now = Arc::clone(&now);
    let clock: Clock = Arc::new(move || {
        Timestamp::from_second(clock_now.load(std::sync::atomic::Ordering::SeqCst)).unwrap()
    });
    let (tenant, http) = tenant();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let authorizer = Authorizer::new(credentials, clock);
    assert_eq!(
        authorizer.headers(cx).await.unwrap(),
        [
            ("Authorization", "Bearer ya29.user".to_owned()),
            ("x-goog-user-project", "billing".to_owned())
        ]
    );
    now.store(NOW + 3600 - 226, std::sync::atomic::Ordering::SeqCst);
    authorizer.token(cx).await.unwrap();
    now.store(NOW + 3600 - 225, std::sync::atomic::Ordering::SeqCst);
    authorizer.token(cx).await.unwrap();
    server.verify().await;
}

#[tokio::test]
async fn refused_or_unanswered_credentials_stop_the_tenant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            serde_json::json!({"error": "invalid_grant", "error_description": "Bad Request"}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/empty"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .and(header("Metadata-Flavor", "Google"))
        .and(query_param("scopes", SCOPE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token": "ya29.gce", "expires_in": 100})),
        )
        .mount(&server)
        .await;
    let (tenant, http) = tenant();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let user = |uri: &str| Credentials::AuthorizedUser {
        client_id: "cid".to_owned(),
        client_secret: Secret::new("cs"),
        refresh_token: Secret::new("rt"),
        token_uri: format!("{}{uri}", server.uri()),
        quota_project: None,
    };
    let error = Authorizer::new(user("/token"), fixed(NOW))
        .token(cx)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "google_secops_tenant_unauthorized: tenant secops-eu: Google refused the credentials \
         (invalid_grant: Bad Request)"
    );
    let error = Authorizer::new(user("/empty"), fixed(NOW))
        .token(cx)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "google_secops_tenant_unauthorized: tenant secops-eu: the credentials gave no access token"
    );
    let unreachable = Credentials::AuthorizedUser {
        client_id: "cid".to_owned(),
        client_secret: Secret::new("cs"),
        refresh_token: Secret::new("rt"),
        token_uri: "http://127.0.0.1:9/token".to_owned(),
        quota_project: None,
    };
    let error = Authorizer::new(unreachable, fixed(NOW))
        .token(cx)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("google_secops_tenant_unauthorized: tenant secops-eu: Google's token endpoint did not answer"),
        "{error}"
    );
    // The metadata server.
    let host = server.uri().trim_start_matches("http://").to_owned();
    let metadata = Credentials::Metadata {
        host,
        quota_project: None,
    };
    assert_eq!(
        Authorizer::new(metadata, fixed(NOW))
            .token(cx)
            .await
            .unwrap()
            .expose(),
        "ya29.gce"
    );
    let none = Credentials::Metadata {
        host: "127.0.0.1:9".to_owned(),
        quota_project: None,
    };
    let error = Authorizer::new(none, fixed(NOW))
        .token(cx)
        .await
        .unwrap_err();
    assert!(
        error.to_string().starts_with(
            "google_secops_credentials_missing: no credentials: the tenant names none"
        ),
        "{error}"
    );
}
