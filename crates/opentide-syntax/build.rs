fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..");

    compile_grammar(
        &root.join("grammars/tree-sitter-opentide-kql/src"),
        "tree-sitter-opentide-kql",
    );
    compile_grammar(
        &root.join("grammars/tree-sitter-opentide-spl/src"),
        "tree-sitter-opentide-spl",
    );

    println!("cargo:rerun-if-changed=../../grammars/tree-sitter-opentide-kql/src/parser.c");
    println!("cargo:rerun-if-changed=../../grammars/tree-sitter-opentide-spl/src/parser.c");
}

fn compile_grammar(src: &std::path::Path, name: &str) {
    let mut build = cc::Build::new();
    build.include(src);
    build.file(src.join("parser.c"));
    build.flag_if_supported("-Wno-unused-parameter");
    build.flag_if_supported("-Wno-unused-but-set-variable");
    build.flag_if_supported("-Wno-trigraphs");
    build.compile(name);
}
