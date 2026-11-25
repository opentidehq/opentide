//! The languages `opentide lsp` says it serves (#1729, E2E-8): its help and
//! `docs/cli/lsp.md` named six of the eleven query languages the engine
//! analyses. Both are held to the engine's list, [`LanguageId`], so a language
//! added there fails here until the texts name it.

use opentide_core::LanguageId;

/// How the help and the page spell a language. No wildcard: a language
/// added to [`LanguageId`] must be given its spelling here.
fn spelling(language: LanguageId) -> &'static str {
    match language {
        LanguageId::Kql => "KQL",
        LanguageId::Spl => "SPL",
        LanguageId::Esql => "ES|QL",
        LanguageId::Eql => "EQL",
        LanguageId::Kuery => "Kibana KQL",
        LanguageId::Lucene => "Lucene",
        LanguageId::Falco => "Falco",
        LanguageId::Cql => "CQL",
        LanguageId::Yara => "YARA",
        LanguageId::Exabeam => "Exabeam",
        LanguageId::Yaral => "YARA-L",
        LanguageId::TideYaml => "Tide YAML",
        LanguageId::Config => "configuration",
    }
}

/// The spellings of `languages` that `text` does not carry: a spelling
/// inside a longer one of the list (`KQL` in `Kibana KQL`, `YARA` in
/// `YARA-L`) is not a mention.
fn missing(text: &str, languages: &[LanguageId]) -> Vec<&'static str> {
    let words: Vec<&'static str> = languages.iter().map(|l| spelling(*l)).collect();
    words
        .iter()
        .copied()
        .filter(|word| {
            let mut rest = text.to_owned();
            for longer in &words {
                if longer.len() > word.len() && longer.contains(word) {
                    rest = rest.replace(longer, "");
                }
            }
            !rest.contains(word)
        })
        .collect()
}

#[test]
fn the_help_names_every_query_language_the_engine_analyses() {
    let root = opentide_cli::catalog::root();
    let lsp = root.find_subcommand("lsp").expect("the lsp command");
    let help = lsp.get_long_about().expect("a long help").to_string();
    let mut wanted = LanguageId::QUERY_LANGUAGES.to_vec();
    wanted.push(LanguageId::TideYaml);
    assert_eq!(missing(&help, &wanted), Vec::<&str>::new(), "{help}");
}

#[test]
fn the_page_names_every_query_language_the_engine_analyses() {
    let page = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/cli/lsp.md"
    ))
    .expect("docs/cli/lsp.md");
    // The sentence that opens the page: "It understands ...".
    let sentence = page
        .lines()
        .find(|line| line.contains("It understands "))
        .expect("the sentence that says what the server understands");
    let mut wanted = LanguageId::QUERY_LANGUAGES.to_vec();
    wanted.push(LanguageId::TideYaml);
    assert_eq!(missing(sentence, &wanted), Vec::<&str>::new(), "{sentence}");
}

/// The check itself: a text that names `YARA-L` and not `YARA`, or `KQL` only
/// as part of `Kibana KQL`, is missing them.
#[test]
fn a_spelling_inside_another_is_not_a_mention() {
    let languages = [
        LanguageId::Yara,
        LanguageId::Yaral,
        LanguageId::Kql,
        LanguageId::Kuery,
    ];
    assert_eq!(
        missing("YARA-L and Kibana KQL", &languages),
        ["YARA", "KQL"]
    );
    assert_eq!(
        missing("KQL, Kibana KQL, YARA and YARA-L", &languages),
        Vec::<&str>::new()
    );
}
