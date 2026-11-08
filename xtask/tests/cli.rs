//! `cargo xtask` as a command: the cases in tests/cmd/*.trycmd run the built
//! binary and compare its output and exit status (trycmd; `TRYCMD=overwrite`
//! rewrites the expected output after an intended change).

#[test]
fn cli() {
    trycmd::TestCases::new()
        .register_bin("xtask", std::path::Path::new(env!("CARGO_BIN_EXE_xtask")))
        .case("tests/cmd/*.trycmd");
}
