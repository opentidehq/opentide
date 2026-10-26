//! Compiles the vendored tree-sitter parsers. The grammars, and the highlight queries
//! `include_str!` reads through `OPENTIDE_ASSETS`, sit at the workspace root in a
//! checkout, or else in the `assets/` copy that `scripts/release.py vendor` puts
//! inside a published crate. The checkout wins, so a copy left behind never shadows
//! the real files.
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.join("../..");
    // A packaged crate builds under target/package/ or the registry, where ../.. has no
    // catalogs/.
    let root = if workspace.join("catalogs").is_dir() {
        workspace
    } else {
        manifest.join("assets")
    };
    println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
    println!("cargo:rerun-if-changed=build.rs");

    compile_grammar(
        &root.join("grammars/tree-sitter-opentide-kql/src"),
        "tree-sitter-opentide-kql",
    );
    compile_grammar(
        &root.join("grammars/tree-sitter-opentide-spl/src"),
        "tree-sitter-opentide-spl",
    );
    for lang in ["esql", "eql", "kuery", "lucene"] {
        compile_grammar(
            &root.join(format!("grammars/tree-sitter-opentide-{lang}/src")),
            &format!("tree-sitter-opentide-{lang}"),
        );
    }

    for lang in ["kql", "spl", "esql", "eql", "kuery", "lucene"] {
        let src = root.join(format!("grammars/tree-sitter-opentide-{lang}/src"));
        println!("cargo:rerun-if-changed={}", src.join("parser.c").display());
        println!("cargo:rerun-if-changed={}", src.join("scanner.c").display());
    }
}

fn compile_grammar(src: &std::path::Path, name: &str) {
    let mut build = cc::Build::new();
    build.include(src);
    build.file(src.join("parser.c"));
    // External scanner, when the grammar declares `externals` (ES|QL nested comments).
    let scanner = src.join("scanner.c");
    if scanner.exists() {
        build.file(scanner);
    }
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-unused-but-set-variable");
    build.flag_if_supported("-Wno-trigraphs");
    build.compile(name);
}
