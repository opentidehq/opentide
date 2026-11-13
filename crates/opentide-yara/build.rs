//! Points `include_str!` at the shared catalogs, grammars, and highlight queries:
//! the workspace root in a checkout, or else the `assets/` copy that
//! `scripts/engine/release.py vendor` puts inside a published crate. The checkout wins, so
//! a copy left behind never shadows the real files.
#[expect(
    clippy::unwrap_used,
    reason = "cargo sets CARGO_MANIFEST_DIR for every build script"
)]
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.join("../..");
    // A packaged crate builds under target/package/ or the registry, where ../.. has no
    // data/catalogs/.
    let root = if workspace.join("data/catalogs").is_dir() {
        workspace
    } else {
        manifest.join("assets")
    };
    println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
    println!("cargo:rerun-if-changed=build.rs");
}
