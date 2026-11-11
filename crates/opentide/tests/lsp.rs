//! The language server the facade carries (`lsp` feature).

#![cfg(feature = "lsp")]

use std::io::Cursor;

fn frame(body: &str) -> String {
    format!("Content-Length: {}\r\n\r\n{body}", body.len())
}

const INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}"#;
const SHUTDOWN: &str = r#"{"jsonrpc":"2.0","id":2,"method":"shutdown"}"#;
const EXIT: &str = r#"{"jsonrpc":"2.0","method":"exit"}"#;

#[test]
fn a_message_session_follows_the_lifecycle() {
    let mut server = opentide::lsp::MessageSession::new();
    let replies = server.handle(INITIALIZE);
    assert!(replies[0].contains("\"capabilities\""), "{replies:?}");
    server.handle(SHUTDOWN);
    assert!(!server.is_closed());
    server.handle(EXIT);
    assert!(server.is_closed() && server.shut_down());
    assert!(server.handle(INITIALIZE).is_empty());
    assert!(format!("{server:?}").contains("closed: true"));
}

#[test]
fn serve_answers_frames_and_reports_a_clean_exit() {
    let input = [INITIALIZE, SHUTDOWN, EXIT].map(frame).concat();
    let mut output = Vec::new();
    let clean = opentide::lsp::serve(Cursor::new(input), &mut output).unwrap();
    assert!(clean);
    let output = String::from_utf8(output).unwrap();
    assert!(output.starts_with("Content-Length: "), "{output}");
    assert!(output.contains("\"id\":2"), "{output}");

    let mut output = Vec::new();
    let abrupt = opentide::lsp::serve(Cursor::new(frame(EXIT)), &mut output).unwrap();
    assert!(!abrupt, "exit before shutdown is not a clean end");
    assert!(!opentide::lsp::VERSION.is_empty());
}
