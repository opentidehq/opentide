//! The `opentide` command line as a person or a script types it: the cases in
//! tests/cmd/*.toml run the built binary and compare its output and exit
//! status (trycmd; `TRYCMD=overwrite` rewrites the expected output after an
//! intended change).

#[test]
fn cli() {
    trycmd::TestCases::new()
        .register_bin(
            "opentide",
            std::path::Path::new(env!("CARGO_BIN_EXE_opentide-cli")),
        )
        .case("tests/cmd/*.toml");
}
