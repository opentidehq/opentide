//! Compile-fail cases (trybuild): each `tests/ui/*.rs` must fail to compile
//! with the error in the `.stderr` beside it. After an intended change,
//! `TRYBUILD=overwrite cargo test -p opentide-schema --features python --test ui`
//! rewrites the `.stderr` files; read the diff before committing.
#![cfg(feature = "python")]

#[test]
fn ui() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
