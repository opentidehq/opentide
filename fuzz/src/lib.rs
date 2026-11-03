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
