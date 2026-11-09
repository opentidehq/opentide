//! What each fuzz target does with its input (#182). The same function runs
//! the saved crashes in `fuzz/regressions/` on stable Rust
//! (`crates/opentide-analysis/tests/fuzz_regressions.rs` keeps a copy of
//! the loop), so a fixed crash stays fixed without nightly.

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace};

/// The largest byte offset at or below `offset` that starts a character: a
/// host always passes one (`opentide_core::position_to_offset`).
pub fn boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// Everything an editor asks of a document: analysis, hover, completion and
/// signature help at a few offsets, and for Tide its index, outline, links,
/// lens and inlay hints. A panic or a run past the fuzzer's `-timeout` is
/// the failure.
pub fn exercise(language: LanguageId, text: &str) {
    let path = match language {
        LanguageId::TideYaml => "/w/objects/rules/fuzz.yaml",
        _ => "/w/fuzz.query",
    };
    let host = MemoryWorkspace {
        files: vec![(path.to_string(), text.to_string())],
    };
    let response = opentide_analysis::analyze(
        &host,
        AnalyzeRequest {
            uri: path.to_string(),
            language,
            text: text.to_string(),
        },
    );
    // Every range the client gets must lie in the text.
    let lines = text.split('\n').count() as u32;
    for d in &response.diagnostics {
        assert!(d.range.start.line < lines.max(1), "{d:?}");
    }
    for offset in [0, text.len() / 3, text.len() / 2, text.len()] {
        let offset = boundary(text, offset);
        let _ = opentide_analysis::hover(&host, language, text, offset);
        let _ = opentide_analysis::completions(&host, language, text, offset);
        let _ = opentide_analysis::signature_help(&host, language, text, offset);
    }
    if language == LanguageId::TideYaml {
        let index: Vec<_> = opentide_tide::index_object(path, text).into_iter().collect();
        let _ = opentide_tide::outline(text);
        let _ = opentide_tide::document_links(text, &index);
        let _ = opentide_tide::reference_lens(text, &index);
        let _ = opentide_tide::inlay_hints(text, &index);
    }
}

/// Run a session of LSP messages against the host: each `\0`-separated
/// chunk of `data` is one message body, framed with its length, after an
/// `initialize` and before `shutdown` and `exit`. A handler that panics is
/// a failure even though the host would answer `-32603`: the fuzzer's panic
/// hook aborts first.
pub fn session(data: &[u8]) {
    let mut input = Vec::new();
    let mut frame = |body: &[u8]| {
        input.extend(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        input.extend(body);
    };
    frame(br#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{}}}"#);
    frame(br#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#);
    for body in data.split(|b| *b == 0) {
        if !body.is_empty() {
            frame(body);
        }
    }
    frame(br#"{"jsonrpc":"2.0","id":999999,"method":"shutdown"}"#);
    frame(br#"{"jsonrpc":"2.0","method":"exit"}"#);
    let mut output = Vec::new();
    let _ = opentide_lsp::serve(std::io::Cursor::new(input), &mut output);
}

/// The bytes a client sends, unframed: `data` is the whole input stream of
/// a session, headers included. `session` frames every body correctly; this
/// one reaches the header reader (`Content-Length`, `Content-Type`, line
/// endings, short and oversized bodies). A panic, or a read that does not
/// end, is the failure; an error return (a broken header ends the session)
/// is not.
pub fn framing(data: &[u8]) {
    let _ = opentide_lsp::serve(std::io::Cursor::new(data), std::io::sink());
}

/// The configuration files the schemas in `crates/testdata/config/schemas`
/// name (their router), one of which each input is.
pub const CONFIGURATION_FILES: &[&str] = &[
    "paths.toml",
    "global.toml",
    "deployment.toml",
    "schema.toml",
    "visibility.toml",
    "documentation.toml",
    "sharing.toml",
    "platforms/sentinel.toml",
    "platforms/splunk.toml",
    "platforms/carbon_black_cloud.toml",
    "platforms/sentinel_one.toml",
    "platforms/defender_for_endpoint.toml",
    "platforms/crowdstrike.toml",
    "platforms/harfanglab.toml",
    "platforms/elastic.toml",
    "platforms/other.toml",
];

macro_rules! schema {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("../../crates/testdata/config/schemas/", $name)),
        )
    };
}

/// opentide's configuration schemas, as a host installs them
/// (`install_configuration_schemas`): the copies the engine's tests use.
const SCHEMAS: &[(&str, &str)] = &[
    schema!("deployment.schema.json"),
    schema!("documentation.schema.json"),
    schema!("paths.schema.json"),
    schema!("platforms.carbon_black_cloud.schema.json"),
    schema!("platforms.crowdstrike.schema.json"),
    schema!("platforms.defender_for_endpoint.schema.json"),
    schema!("platforms.elastic.schema.json"),
    schema!("platforms.harfanglab.schema.json"),
    schema!("platforms.schema.json"),
    schema!("platforms.sentinel.schema.json"),
    schema!("platforms.sentinel_one.schema.json"),
    schema!("platforms.splunk.schema.json"),
    schema!("schema.schema.json"),
    schema!("sharing.schema.json"),
    schema!("visibility.schema.json"),
];

const ROUTER: &str = include_str!("../../crates/testdata/config/schemas/configurations.router.json");

/// Install the schemas once per process: hover and completion read them.
pub fn install_schemas() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let schemas: Vec<(String, String)> = SCHEMAS
            .iter()
            .map(|(name, text)| (name.to_string(), text.to_string()))
            .collect();
        if let Err(err) = opentide_analysis::install_configuration_schemas(Some(ROUTER), &schemas) {
            panic!("the test schemas do not install: {err}");
        }
    });
}

/// Configuration TOML as the engine sees it in an editor
/// (`opentide_analysis::config`): the host's checker reports findings by
/// `field_path`, and the engine places each in the buffer; hover and
/// completion walk the host's schemas.
///
/// The input is `<file byte><text>\0<field path>\0<field path>…`: the first
/// byte picks the file from [`CONFIGURATION_FILES`], the text is the buffer,
/// and each field path (`.`-separated, list items by index) is a finding the
/// checker returns, with a severity from its length. A path `!` makes the
/// checker fail instead, as a host's can.
pub fn configuration(data: &[u8]) {
    use opentide_analysis::{ConfigIssue, ConfigRequest, Severity};

    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let mut parts = rest.split(|b| *b == 0);
    let Some(Ok(text)) = parts.next().map(std::str::from_utf8) else {
        return;
    };
    let mut issues = Vec::new();
    let mut fail = false;
    for part in parts {
        let Ok(path) = std::str::from_utf8(part) else {
            continue;
        };
        if path == "!" {
            fail = true;
            continue;
        }
        let severity = match path.len() % 4 {
            0 => Severity::Error,
            1 => Severity::Warning,
            2 => Severity::Information,
            _ => Severity::Hint,
        };
        issues.push(ConfigIssue {
            code: "fuzz_finding".to_string(),
            field_path: if path.is_empty() {
                Vec::new()
            } else {
                path.split('.').map(str::to_string).collect()
            },
            severity,
            message: path.to_string(),
        });
    }
    install_schemas();
    opentide_analysis::set_configuration_checker(Some(Box::new(
        move |_: &ConfigRequest<'_>| {
            if fail {
                Err("the host's checker failed".to_string())
            } else {
                Ok(issues.clone())
            }
        },
    )));

    let file = CONFIGURATION_FILES[usize::from(pick) % CONFIGURATION_FILES.len()];
    let path = format!("/w/{}{file}", opentide_analysis::CONFIGURATIONS_DIRECTORY);
    // Another open configuration buffer: the engine hands the checker every
    // open one.
    let other = format!("/w/{}deployment.toml", opentide_analysis::CONFIGURATIONS_DIRECTORY);
    let host = MemoryWorkspace {
        files: vec![
            (path.clone(), text.to_string()),
            (other, "[deployment]\n".to_string()),
        ],
    };
    let response = opentide_analysis::analyze(
        &host,
        AnalyzeRequest {
            uri: path.clone(),
            language: LanguageId::Config,
            text: text.to_string(),
        },
    );
    let lines = text.split('\n').count() as u32;
    for d in &response.diagnostics {
        assert!(d.range.start.line < lines.max(1), "{d:?}");
        assert!(d.range.end.line < lines.max(1), "{d:?}");
        assert!(
            (d.range.start.line, d.range.start.character)
                <= (d.range.end.line, d.range.end.character),
            "{d:?}"
        );
    }
    for offset in [0, text.len() / 3, text.len() / 2, text.len()] {
        let offset = boundary(text, offset);
        let _ = opentide_analysis::configuration_hover(&path, text, offset);
        let _ = opentide_analysis::configuration_completions(&path, text, offset);
    }
}

/// A Tide object from arbitrary bytes (`from_node`, UC-1.2): read them as the
/// oracle reads an object file, convert the tree into every model, and check
/// what comes out. An error's span lies in the document; a value that
/// converts is written back ([`opentide_schema::node::to_yaml`]) and reads
/// back equal. `crates/opentide-schema/tests/fuzz_regressions.rs` keeps a
/// copy of this function for the saved inputs.
pub fn from_node(data: &[u8]) {
    use opentide_schema::node;
    use opentide_schema::sample::{SampleV1_0, SampleV1_1};
    let Ok(document) = node::load_bytes(data) else {
        return;
    };
    convert::<SampleV1_0>(&document);
    convert::<SampleV1_1>(&document);
}

fn convert<T>(document: &opentide_schema::node::Document)
where
    T: opentide_schema::FromNode + serde::Serialize + PartialEq + std::fmt::Debug,
{
    use opentide_schema::from_node::from_document;
    use opentide_schema::node;
    match from_document::<T>(document) {
        Ok(value) => {
            let yaml = node::to_yaml(&value).expect("a converted model writes");
            let again = node::load(&yaml).expect("what to_yaml writes reads back");
            let back: T = from_document(&again).expect("what to_yaml writes converts");
            assert_eq!(back, value, "{yaml}");
        }
        Err(errors) => {
            assert!(!errors.is_empty());
            // An upper bound on the CLI's lines (`\r\n` counts twice here).
            let lines = document.source().split(['\r', '\n']).count();
            for error in &errors {
                assert!(!error.message.is_empty(), "{error:?}");
                if let Some(span) = &error.span {
                    assert!(span.line >= 1 && span.line <= lines + 1, "{error:?}");
                    assert!(span.column >= 1 && span.end_column >= span.column, "{error:?}");
                }
            }
        }
    }
}
