//! Points `include_str!` at the package data the vocabularies are read from
//! (`src/opentide/data/{vocabulary,pins,sentinel}`): the workspace root in a
//! checkout, or else the `assets/` copy that `scripts/engine/release.py vendor`
//! puts inside a published crate, as opentide-tide does. The checkout wins, so a
//! copy left behind never shadows the real files.
#[expect(
    clippy::unwrap_used,
    reason = "cargo sets CARGO_MANIFEST_DIR for every build script"
)]
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.join("../..");
    // A packaged crate builds under target/package/ or the registry, where ../.. has no
    // src/opentide/data/.
    let root = if workspace.join("src/opentide/data/vocabulary").is_dir() {
        workspace
    } else {
        manifest.join("assets")
    };
    println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
    println!("cargo:rerun-if-changed=build.rs");
}
