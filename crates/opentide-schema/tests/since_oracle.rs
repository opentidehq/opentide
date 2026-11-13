//! The catch-up train's [`SINCE_ORACLE`] convention must not reach
//! integration. While the train carries platforms ported after the golden
//! oracle (opentide 0.23.0) was recorded, the oracle-comparing tests leave
//! those platforms out ([`opentide_schema::platforms::SINCE_ORACLE`]). That
//! list is sound only while the oracle is still 0.23.0, which the report-only
//! marker (`tests/golden/REPORT_ONLY`) marks. O2 moves the oracle to 0.28.x,
//! re-records every case and removes the marker; this test fails until
//! `SINCE_ORACLE` is emptied too, so the list can never leak to integration.
//!
//! It reads the marker file, so it lives here, not in the I/O-free `src`.

#![expect(
    clippy::expect_used,
    reason = "a test helper: the repository layout is fixed"
)]

use std::path::Path;

use opentide_schema::platforms::SINCE_ORACLE;

/// The repository root (two levels above the crate).
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate is two levels below the repository root")
}

#[test]
fn since_oracle_is_empty_without_the_report_only_marker() {
    let marker = repo().join("tests/golden/REPORT_ONLY");
    if !marker.is_file() {
        assert!(
            SINCE_ORACLE.is_empty(),
            "the report-only marker ({}) is gone, so the oracle gates again: \
             empty opentide_schema::platforms::SINCE_ORACLE (O2 does this). It still lists {:?}",
            marker.display(),
            SINCE_ORACLE,
        );
    }
}
