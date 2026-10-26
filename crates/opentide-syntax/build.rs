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
    for lang in ["esql", "eql", "kuery", "lucene"] {
        compile_grammar(
            &root.join(format!("grammars/tree-sitter-opentide-{lang}/src")),
            &format!("tree-sitter-opentide-{lang}"),
        );
    }

    for lang in ["kql", "spl", "esql", "eql", "kuery", "lucene"] {
        println!("cargo:rerun-if-changed=../../grammars/tree-sitter-opentide-{lang}/src/parser.c");
        println!("cargo:rerun-if-changed=../../grammars/tree-sitter-opentide-{lang}/src/scanner.c");
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
