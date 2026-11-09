//! Every session the `protocol` fuzz target saved (`fuzz/regressions/protocol/`,
//! #182) runs through `serve` on stable Rust, framed as the target frames it:
//! `initialize`, each `\0`-separated body, `shutdown`, `exit`. The seeds run
//! too. A saved session must end, and must not make a handler panic.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use std::path::Path;

fn session(data: &[u8]) -> Vec<u8> {
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
    opentide_lsp::serve(std::io::Cursor::new(input), &mut output).unwrap();
    output
}

#[test]
fn saved_protocol_sessions_end_without_a_failing_handler() {
    let fuzz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut ran = 0;
    for dir in ["seeds/protocol", "regressions/protocol"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let output = session(&std::fs::read(entry.path()).unwrap());
            let text = String::from_utf8_lossy(&output);
            // A panicking handler is answered `-32603`.
            assert!(
                !text.contains("\"code\":-32603"),
                "{}: {text}",
                entry.path().display()
            );
            assert!(
                text.contains("\"id\":999999"),
                "{}: no shutdown reply",
                entry.path().display()
            );
            ran += 1;
        }
    }
    assert!(ran >= 3, "the seeds ran");
}

/// The `framing` target (#843) feeds its input to `serve` unframed. A saved
/// input, or a seed, must end the session (with an error for a broken
/// header), never make a handler panic, never hang.
#[test]
fn saved_raw_streams_end_without_a_panic() {
    let fuzz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut ran = 0;
    for dir in ["seeds/framing", "regressions/framing"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let bytes = std::fs::read(entry.path()).unwrap();
            let start = std::time::Instant::now();
            let mut output = Vec::new();
            // A broken header ends the session with an error: that is an
            // answer, not a failure.
            let _ = opentide_lsp::serve(std::io::Cursor::new(bytes), &mut output);
            let took = start.elapsed();
            // Under libFuzzer a handler that panics aborts; here `serve`
            // catches it and answers `-32603`, which must not happen either.
            let text = String::from_utf8_lossy(&output);
            assert!(
                !text.contains("\"code\":-32603"),
                "{}: {text}",
                entry.path().display()
            );
            assert!(
                took < std::time::Duration::from_secs(30),
                "{}: {took:?}",
                entry.path().display()
            );
            ran += 1;
        }
    }
    assert!(ran >= 3, "the seeds ran");
}
