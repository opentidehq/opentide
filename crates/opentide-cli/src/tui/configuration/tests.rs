//! The redaction and the view (`tests/test_cli/test_tui_configuration.py`).

use super::*;

const SECRET: &str = "S3CRET-trigger-value";

fn env(pairs: &[(&str, &str)]) -> Env {
    Env::from_pairs(pairs.iter().copied())
}

/// Each input that leaked a credential from an earlier redactor (`TRIGGERS`).
fn triggers() -> Vec<(&'static str, String)> {
    vec![
        (
            "inline array of tables",
            format!(
                "tenants = [ {{ name = \"p\", setup = {{ client_secret = \"{SECRET}\" }} }} ]\n"
            ),
        ),
        (
            "inline array of tables over lines",
            format!(
                "tenants = [\n  {{ name = \"p\", setup = {{ client_secret = \"{SECRET}\" }} }},\n]\n"
            ),
        ),
        (
            "single-quoted header",
            format!("[[tenants]]\nname = \"p\"\n[tenants.'setup']\nregion = \"{SECRET}\"\n"),
        ),
        (
            "double-quoted key with a space",
            format!("[[tenants]]\n[tenants.setup]\n\"client id\" = \"{SECRET}\"\n"),
        ),
        (
            "single-quoted key with a space",
            format!("[[tenants]]\n[tenants.setup]\n'client id' = \"{SECRET}\"\n"),
        ),
        (
            "array item holding ]",
            format!(
                "[[tenants]]\n[tenants.setup]\nkeys = [\n  \"a]\",\n  \"{SECRET}\",\n]\nname = \"x\"\n"
            ),
        ),
        (
            "escaped quotes in a multi-line string",
            format!("[[tenants]]\n[tenants.setup]\ncert = \"\"\"\nab\\\"\"\"\n{SECRET}\n\"\"\"\n"),
        ),
        (
            "line separator in a value",
            format!("[[tenants]]\n[tenants.setup]\ntoken = \"a\u{2028}{SECRET}\"\n"),
        ),
        (
            "next line in a value",
            format!("[[tenants]]\n[tenants.setup]\ntoken = \"a\u{85}{SECRET}\"\n"),
        ),
        (
            "secret-named table",
            format!("[platform.credentials]\nvalue = \"{SECRET}\"\n"),
        ),
        ("auth table", format!("[auth]\nvalue = \"{SECRET}\"\n")),
        (
            "secret-named inline table",
            format!("api_key = {{ value = \"{SECRET}\" }}\n"),
        ),
        (
            "secret-named array of arrays",
            format!("nested = [[{{ token = \"{SECRET}\" }}]]\n"),
        ),
        (
            "password holding @",
            format!("url = \"https://user:pa@ss@{SECRET}@proxy.example/path\"\n"),
        ),
    ]
}

#[test]
fn no_trigger_shows_its_secret_raw() {
    for (name, text) in triggers() {
        let redacted = redact_toml(&text, &env(&[])).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(!redacted.contains(SECRET), "{name}: {redacted}");
        assert!(redacted.contains(HIDDEN), "{name}: {redacted}");
    }
}

#[test]
fn no_trigger_shows_its_secret_read() {
    for (name, text) in triggers() {
        let document = config_toml::parse(&text).unwrap();
        let resolved = config_toml::parse("[platforms.acme]\n").unwrap();
        // The file's own tree, as the platform's merged document.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("acme.toml"), &text).unwrap();
        let mut merged = resolved;
        if let Value::Map(entries) = &mut merged.value
            && let Some(platforms) = entries.first_mut()
            && let Value::Map(inner) = &mut std::sync::Arc::make_mut(&mut platforms.value).value
            && let Some(acme) = inner.first_mut()
        {
            acme.value = std::sync::Arc::new(document);
        }
        let view = load(Some(dir.path()), &merged, &[], &[], &env(&[]));
        let item = view.file("platforms/acme.toml").unwrap();
        assert!(item.raw.is_some() && item.raw_problem.is_none(), "{name}");
        assert!(!format!("{view:?}").contains(SECRET), "{name}");
        assert!(
            item.settings
                .iter()
                .any(|setting| setting.secret || setting.shown.contains(HIDDEN)),
            "{name}"
        );
    }
}

#[test]
fn redaction_covers_every_way_toml_writes_a_value() {
    let text = "[[tenants]]\nsetup.api_key = \"a1\"\nsetup.token = \"\"\"\na2\n\"\"\"\n\
                setup.keys = [\n  \"a3\",\n]\nsetup.password = 'a4'\n\
                [[tenants]]\nsetup = { api_key = \"a5\" }\nurl = \"https://user:a6@host\"\n";
    let redacted = redact_toml(text, &env(&[])).unwrap();
    for secret in ["a1", "a2", "a3", "a4", "a5", "a6"] {
        assert!(!redacted.contains(secret), "{secret}: {redacted}");
    }
    assert_eq!(redacted.matches(HIDDEN).count(), 6, "{redacted}");
}

#[test]
fn a_url_hides_its_user_up_to_the_last_at() {
    let text = format!("url = \"https://user:pa@ss@{SECRET}@proxy.example/path\"\n");
    assert_eq!(
        hide_userinfo(&format!("https://user:pa@ss@{SECRET}@proxy.example/path")),
        format!("https://{HIDDEN}@proxy.example/path")
    );
    let redacted = redact_toml(&text, &env(&[])).unwrap();
    assert!(redacted.contains(&format!("\"https://{HIDDEN}@proxy.example/path\"")));
}

#[test]
fn a_secret_table_keeps_its_switches() {
    let redacted = redact_toml(
        &format!("[auth]\nenabled = true\nvalue = \"{SECRET}\"\n"),
        &env(&[]),
    )
    .unwrap();
    assert!(redacted.contains("enabled = true") && !redacted.contains(SECRET));
}

#[test]
fn invalid_toml_has_no_raw_view() {
    let invalid = format!("[[tenants]]\n[tenants.setup]\nclient_secret: \"{SECRET}\"\n");
    let refused = redact_toml(&invalid, &env(&[])).unwrap_err();
    assert!(
        refused.0.starts_with("not valid TOML: line 3, column "),
        "{refused:?}"
    );
    assert!(!refused.0.contains(SECRET) && !refused.0.contains("client_secret"));
}

#[test]
fn a_secret_quoted_in_a_comment_withholds_the_raw_view() {
    let text = format!(
        "# the old token was {SECRET}\n[[tenants]]\n[tenants.setup]\ntoken = \"{SECRET}\"\n"
    );
    assert_eq!(
        redact_toml(&text, &env(&[])),
        Err(UnsafeRawView(UNSAFE_RAW.to_owned()))
    );
    // A variable reference is no secret: it is shown, with whether it is set.
    let redacted = redact_toml(
        "[auth]\ntoken = \"$OT_TEST_TOKEN\"\n",
        &env(&[("OT_TEST_TOKEN", SECRET)]),
    )
    .unwrap();
    assert_eq!(redacted, "[auth]\ntoken = \"${OT_TEST_TOKEN}\"  # set\n");
}

/// A redactor that misses a value: the proof withholds the raw view.
#[test]
fn a_redaction_that_cannot_be_proven_is_not_shown() {
    let document = config_toml::parse(&format!(
        "[[tenants]]\n[tenants.setup]\ntoken = \"{SECRET}\"\n"
    ))
    .unwrap();
    assert!(!proven(
        &document,
        &format!("[[tenants]]\n[tenants.setup]\ntoken = \"{SECRET}\"\n")
    ));
    assert!(proven(
        &document,
        &format!("[[tenants]]\n[tenants.setup]\ntoken = \"{HIDDEN}\"\n")
    ));
}

#[test]
fn secret_names_and_comment_descriptions() {
    for secret in [
        &["tenants", "0", "setup", "region"][..],
        &["api_key"],
        &["proxy_password"],
        &["client-key"],
        &["key"],
        &["Session"],
    ] {
        assert!(is_secret(secret), "{secret:?}");
    }
    for plain in [&["keys_seen"][..], &["monkey"], &["name"], &["0"]] {
        assert!(!is_secret(plain), "{plain:?}");
    }
    let described = comment_descriptions(Some(
        "# What a rule file is named\n[filenames]\n# The stem\nstyle = \"x\"\n# example = 1\n\n# lone\n\nother = 2\n",
    ));
    assert_eq!(described["filenames"], "What a rule file is named");
    assert_eq!(described["filenames.style"], "The stem");
    // A blank line keeps the comment above it (`if line: comments = []`).
    assert_eq!(described["filenames.other"], "lone");
    assert!(!described.values().any(|text| text.contains("example")));
}
