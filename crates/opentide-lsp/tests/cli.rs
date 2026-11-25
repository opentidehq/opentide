//! The `opentide-lsp` command line, outside the editor protocol: the cases
//! in tests/cmd/*.trycmd run the built binary and compare its output and exit
//! status (trycmd; `TRYCMD=overwrite` rewrites the expected output after an
//! intended change). The CLI prints plain JSON or text, never JSON-RPC.

#[test]
fn cli() {
    trycmd::TestCases::new()
        .register_bin(
            "opentide-lsp",
            std::path::Path::new(env!("CARGO_BIN_EXE_opentide-lsp")),
        )
        .case("tests/cmd/*.trycmd");
}
