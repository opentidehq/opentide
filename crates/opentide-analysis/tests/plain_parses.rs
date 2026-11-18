//! Each language's plain `parses`, which the throughput benchmark times,
//! gives the verdict its `debug_kinds` gives (the corpus gate's): over every
//! file of its corpus and of its external set.

use std::path::{Path, PathBuf};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn texts(language: &str) -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    let mut paths = Vec::new();
    files(&root.join("corpus").join(language), &mut paths);
    files(
        &root.join("conformance/external").join(language),
        &mut paths,
    );
    paths.sort();
    paths
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
        .collect()
}

type Pair = (fn(&str) -> bool, fn(&str) -> (bool, Vec<String>));

#[test]
fn a_plain_parse_gives_the_verdict_of_debug_kinds() {
    let languages: [(&str, Pair); 6] = [
        ("spl", (opentide_spl::parses, opentide_spl::debug_kinds)),
        ("cql", (opentide_cql::parses, opentide_cql::debug_kinds)),
        (
            "falco",
            (opentide_falco::parses, opentide_falco::debug_kinds),
        ),
        ("yara", (opentide_yara::parses, opentide_yara::debug_kinds)),
        (
            "exabeam",
            (opentide_exabeam::parses, opentide_exabeam::debug_kinds),
        ),
        (
            "yaral",
            (opentide_yaral::parses, opentide_yaral::debug_kinds),
        ),
    ];
    for (language, (parses, debug_kinds)) in languages {
        let texts = texts(language);
        assert!(texts.len() > 20, "{language}: {} files", texts.len());
        for (path, text) in texts {
            let (error, _) = debug_kinds(&text);
            assert_eq!(parses(&text), !error, "{language}: {}", path.display());
        }
    }
}
