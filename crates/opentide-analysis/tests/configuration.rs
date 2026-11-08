//! Configuration TOML: the host checks, the engine places, and the host's
//! schemas give hover and completion. The checker and the schemas are
//! process-wide, so this binary has its own process and its tests take a lock.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{
    AnalyzeRequest, ConfigIssue, ConfigRequest, LanguageId, MemoryWorkspace, Severity, analyze,
    codes, configuration_completions, configuration_diagnostics, configuration_hover,
    install_configuration_schemas, set_configuration_checker,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

const SHARING: &str = "/w/.opentide/configurations/sharing.toml";

fn install_schemas() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/config/schemas");
    let mut router = None;
    let mut schemas = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("crates/testdata/config/schemas") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).expect("schema");
        if name == "configurations.router.json" {
            router = Some(text);
        } else {
            schemas.push((name, text));
        }
    }
    install_configuration_schemas(router.as_deref(), &schemas).expect("schemas");
}

fn issue(code: &str, path: &[&str], severity: Severity, message: &str) -> ConfigIssue {
    ConfigIssue {
        code: code.into(),
        field_path: path.iter().map(|s| s.to_string()).collect(),
        severity,
        message: message.into(),
    }
}

/// A checker that returns `issues` whatever it is asked, and records the
/// requests.
/// Each request a checker saw: its path and the open buffers' paths.
type Seen = Arc<Mutex<Vec<(String, Vec<String>)>>>;

fn fake_checker(issues: Vec<ConfigIssue>) -> Seen {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    set_configuration_checker(Some(Box::new(move |request: &ConfigRequest<'_>| {
        record.lock().unwrap().push((
            request.path.to_string(),
            request.open.iter().map(|(path, _)| path.clone()).collect(),
        ));
        Ok(issues.clone())
    })));
    seen
}

fn line_text(text: &str, line: u32) -> &str {
    text.lines().nth(line as usize).unwrap_or("")
}

#[test]
fn without_a_checker_there_are_no_diagnostics() {
    let _guard = lock();
    set_configuration_checker(None);
    let text = "[[misp]]\ndistribution = \"this-community\"\n";
    assert!(configuration_diagnostics(SHARING, text, &[]).is_empty());
}

#[test]
fn each_finding_is_placed_on_its_key() {
    let _guard = lock();
    let text = "# Sharing\n[[misp]]\nname = \"misp-internal\"\ndistribution = \"this-community\"\n\n[[misp]]\nname = \"misp-lab\"\nmax_tlp = \"white\"\n";
    fake_checker(vec![
        issue(
            "unknown_key",
            &["misp", "0", "distribution"],
            Severity::Error,
            "unknown key",
        ),
        issue(
            "max_tlp_unknown",
            &["misp", "1", "max_tlp"],
            Severity::Error,
            "not a tlp",
        ),
        issue(
            "missing_field",
            &["misp", "1", "url"],
            Severity::Error,
            "Field required",
        ),
        issue(
            "missing_field",
            &["misp", "1", "api_key"],
            Severity::Error,
            "[[misp]] block 'misp-lab' is missing api_key.",
        ),
        issue(
            "sharing_directory",
            &[],
            Severity::Error,
            "configurations/sharing/ is not a sharing configuration.",
        ),
    ]);
    let found = configuration_diagnostics(SHARING, text, &[]);
    set_configuration_checker(None);
    assert_eq!(found.len(), 5);

    let unknown = &found[0];
    assert_eq!(unknown.code, "unknown_key");
    assert_eq!(unknown.range.start.line, 3);
    assert_eq!(
        &line_text(text, 3)
            [unknown.range.start.character as usize..unknown.range.end.character as usize],
        "distribution"
    );
    assert_eq!(unknown.message, "unknown key");
    assert_eq!(
        unknown.field_path.as_deref(),
        Some(&["misp".to_string(), "0".into(), "distribution".into()][..])
    );

    assert_eq!(found[1].range.start.line, 7);
    assert_eq!(found[1].severity, Severity::Error);

    // A key the block lacks: the block's header, and the message names it.
    let missing = &found[2];
    assert_eq!(missing.range.start.line, 5, "{missing:?}");
    assert_eq!(missing.message, "misp[1].url: Field required");

    // A message that names the key is left as it is.
    assert_eq!(found[3].range.start.line, 5);
    assert_eq!(
        found[3].message,
        "[[misp]] block 'misp-lab' is missing api_key."
    );

    // About the whole file: its first line.
    let directory = &found[4];
    assert_eq!(directory.range.start.line, 0);
    assert_eq!(directory.range.end.character, "# Sharing".len() as u32);
    assert_eq!(directory.field_path, None);
}

#[test]
fn a_parse_error_is_placed_where_toml_breaks() {
    let _guard = lock();
    let text = "[promotion]\nenabled = \n";
    fake_checker(vec![issue(
        "config_parse",
        &[],
        Severity::Error,
        "Not valid TOML: TOMLDecodeError.",
    )]);
    let found = configuration_diagnostics("/w/.opentide/configurations/deployment.toml", text, &[]);
    set_configuration_checker(None);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, "config_parse");
    assert_eq!(found[0].range.start.line, 1, "{:?}", found[0]);
}

#[test]
fn a_failing_checker_is_one_warning() {
    let _guard = lock();
    set_configuration_checker(Some(Box::new(|_: &ConfigRequest<'_>| {
        Err("ImportError: no module".to_string())
    })));
    let found = configuration_diagnostics(SHARING, "[[misp]]\n", &[]);
    set_configuration_checker(None);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].code, codes::CONFIG_CHECK_FAILED);
    assert_eq!(found[0].severity, Severity::Warning);
    assert!(found[0].message.contains("ImportError"));
}

#[test]
fn analyze_hands_the_checker_the_other_open_configuration_buffers() {
    let _guard = lock();
    let seen = fake_checker(Vec::new());
    let deployment = "/w/.opentide/configurations/deployment.toml";
    let host = MemoryWorkspace {
        files: vec![
            (SHARING.into(), "[[misp]]\n".into()),
            (
                deployment.into(),
                "[[statuses]]\nname = \"STAGING\"\n".into(),
            ),
            ("/w/objects/rule.yaml".into(), "name: R\n".into()),
            ("/w/Cargo.toml".into(), "[package]\n".into()),
        ],
    };
    let response = analyze(
        &host,
        AnalyzeRequest {
            uri: SHARING.into(),
            language: LanguageId::Config,
            text: "[[misp]]\n".into(),
        },
    );
    set_configuration_checker(None);
    assert!(response.diagnostics.is_empty());
    assert!(
        response.tokens.is_empty(),
        "configuration TOML has no tokens"
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, SHARING);
    assert_eq!(seen[0].1, vec![deployment.to_string()]);
}

fn labels(path: &str, text: &str) -> Vec<String> {
    configuration_completions(path, text, text.len())
        .into_iter()
        .map(|item| item.label)
        .collect()
}

#[test]
fn completion_offers_the_schema_keys_and_values() {
    let _guard = lock();
    install_schemas();
    assert_eq!(
        labels(SHARING, "[[misp]]\nname = \"a\"\nmax_tlp = "),
        [
            "\"clear\"",
            "\"green\"",
            "\"amber\"",
            "\"amber+strict\"",
            "\"red\""
        ]
    );
    // Inside the quotes, the bare names.
    assert!(labels(SHARING, "[[misp]]\nmax_tlp = \"").contains(&"clear".to_string()));

    let keys = labels(SHARING, "[[misp]]\nname = \"a\"\n");
    for key in [
        "enabled",
        "url",
        "api_key",
        "max_tlp",
        "object_types",
        "verify_ssl",
    ] {
        assert!(keys.contains(&key.to_string()), "{key} in {keys:?}");
    }
    assert!(!keys.contains(&"name".to_string()), "name is already set");
    assert!(!keys.contains(&"distribution".to_string()));

    assert_eq!(labels(SHARING, "[["), ["misp"]);
    assert_eq!(labels(SHARING, "[[misp]]\nenabled = "), ["true", "false"]);
    assert_eq!(
        labels(SHARING, "[[misp]]\nobject_types = [\"threat\", "),
        ["\"threat\"", "\"objective\"", "\"rule\""]
    );
    install_configuration_schemas(None, &[]).unwrap();
}

#[test]
fn hover_shows_the_schema_and_never_the_value() {
    let _guard = lock();
    install_schemas();
    let text = "[[misp]]\napi_key = \"literal-secret\"\nmax_tlp = \"red\"\n";
    let hover =
        configuration_hover(SHARING, text, text.find("api_key").unwrap() + 2).expect("hover");
    assert!(hover.contains("Api Key"), "{hover}");
    assert!(hover.contains("${NAME}"), "{hover}");
    assert!(!hover.contains("literal-secret"), "{hover}");

    let on_value =
        configuration_hover(SHARING, text, text.find("literal").unwrap()).expect("hover");
    assert!(!on_value.contains("literal-secret"), "{on_value}");

    let tlp = configuration_hover(SHARING, text, text.find("max_tlp").unwrap()).expect("hover");
    assert!(tlp.contains("`\"amber+strict\"`"), "{tlp}");
    assert!(!tlp.contains("white"), "{tlp}");

    let header = configuration_hover(SHARING, text, 3).expect("header hover");
    assert!(header.contains("MISP instances"), "{header}");
    install_configuration_schemas(None, &[]).unwrap();
}

#[test]
fn files_route_through_the_router() {
    let _guard = lock();
    install_schemas();
    // A third-party platform file falls back to the generic platform schema.
    let acme = "/w/.opentide/configurations/platforms/acme.toml";
    let text = "[platform]\nenabled = ";
    assert_eq!(labels(acme, text), ["true", "false"]);
    // A file without a schema gets nothing.
    let resources = "/w/.opentide/configurations/resources.toml";
    assert!(labels(resources, "[").is_empty());
    assert!(configuration_hover(resources, "[x]\n", 1).is_none());
    // Without schemas, nothing either.
    install_configuration_schemas(None, &[]).unwrap();
    assert!(labels(SHARING, "[[").is_empty());
}

#[test]
fn schemas_that_are_not_json_change_nothing() {
    let _guard = lock();
    install_schemas();
    let err = install_configuration_schemas(Some("{"), &[]).unwrap_err();
    assert!(err.contains("configurations.router.json"), "{err}");
    assert_eq!(labels(SHARING, "[["), ["misp"]);
    install_configuration_schemas(None, &[]).unwrap();
}
