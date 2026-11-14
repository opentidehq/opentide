//! The bundled vocabularies, resolution and suggestions.

use super::*;

/// What the object schemas ask of the bundled vocabularies (`tide.vocab`
/// and `tide.vocab.scoped` in every revision's schema, at the frozen tag).
const SCHEMA_SELECTORS: [(&str, bool); 16] = [
    ("actors::1.1", true),
    ("alert_severity::1.0", false),
    ("att&ck::1.2", false),
    ("chaining_relations::1.0", false),
    ("criticality::1.0", false),
    ("detection.composition::1.0", false),
    ("detection.methodology::1.0", false),
    ("detection.types::1.0", false),
    ("impact::1.0", false),
    ("killchain::1.0", false),
    ("leverage::1.0", false),
    ("severity::1.0", false),
    ("signal.entities::1.0", true),
    ("surface::1.0", true),
    ("tlp::1.0", false),
    ("viability::1.0", false),
];

fn selector(vocab: &str, scoped: bool) -> Selector {
    Selector::new(vocab.parse().unwrap()).scoped(scoped)
}

#[test]
fn every_bundled_vocabulary_reads_whole() {
    for field in bundled::fields() {
        let vocabulary = bundled::load(field).unwrap().unwrap();
        assert_eq!(vocabulary.field(), field);
        assert!(
            vocabulary.skipped.is_empty(),
            "{field}: {:?}",
            vocabulary.skipped
        );
        assert!(!vocabulary.entries.is_empty(), "{field}");
    }
    assert!(bundled::load("nothing").is_none());
}

#[test]
fn pinned_values() {
    let set = Vocabularies::bundled();
    assert_eq!(
        set.allowed(&selector("tlp::1.0", false)),
        ["clear", "green", "amber", "amber+strict", "red"]
    );
    assert_eq!(
        set.allowed(&selector("alert_severity::1.0", false)),
        ["Informational", "Low", "Medium", "High", "Critical"]
    );
    // A pin before an entry's version leaves it out.
    let early = set.allowed(&selector("att&ck::0.1", false));
    assert!(early.is_empty(), "{early:?}");
    assert!(
        set.allowed(&selector("att&ck::1.2", false))
            .contains(&"T1059".to_owned())
    );
    assert!(set.allowed(&selector("nothing::1.0", false)).is_empty());
}

#[test]
fn scoped_values_carry_their_stage() {
    let set = Vocabularies::bundled();
    let surface = selector("surface::1.0", true);
    let allowed = set.allowed(&surface);
    assert!(allowed.iter().all(|v| v.contains("::")));
    assert!(
        allowed.contains(&"OS::Windows::Desktop".to_owned()),
        "{:?}",
        &allowed[..5]
    );
    assert!(set.is_valid("OS::Windows::Desktop", &surface));
    assert!(!set.is_valid("Windows::Desktop", &surface));
    // A key that begins with a stage id is not stripped into another key.
    assert_eq!(
        set.identifier("surface", "Security::Kerberos"),
        "Security::Kerberos"
    );
    assert_eq!(
        set.identifier("surface", "OS::Windows::Desktop"),
        "Windows::Desktop"
    );
    // Only a stage id is stripped, never any `X::` prefix.
    assert_eq!(
        set.identifier("surface", "Bogus::Kerberos"),
        "Bogus::Kerberos"
    );
    let unscoped = selector("surface::1.0", false);
    assert!(set.is_valid("Windows::Desktop", &unscoped));
    assert!(set.is_valid("OS::Windows::Desktop", &unscoped));
    assert!(!set.is_valid("Bogus::Windows::Desktop", &unscoped));
    assert!(!set.is_valid("Bogus::Kerberos", &unscoped));

    let entities = selector("signal.entities::1.0", true);
    for value in ["Host::Account", "Cloud::Account", "Host::Process"] {
        assert!(set.is_valid(value, &entities), "{value}");
    }
    // Unscoped, a stage-prefixed value names its key.
    assert!(set.is_valid("Host::Account", &selector("signal.entities::1.0", false)));

    // An id-keyed vocabulary is scoped by its first stage.
    let actors = selector("actors::1.1", true);
    assert!(set.is_valid("att&ck::G1028", &actors));
    assert!(set.allowed(&actors).iter().any(|v| v.starts_with("misp::")));
}

#[test]
fn stage_filters_apply_to_name_keyed_vocabularies() {
    let set = Vocabularies::bundled();
    let os = selector("surface::1.0", false).stages(["OS"]);
    assert!(set.is_valid("Windows::Desktop", &os));
    assert!(!set.is_valid("Kerberos", &os));
    let scoped = selector("surface::1.0", true).stages(["OS"]);
    assert!(set.allowed(&scoped).iter().all(|v| v.starts_with("OS::")));
    // An id-keyed vocabulary ignores the filter.
    let attack = selector("att&ck::1.2", false);
    assert_eq!(
        set.allowed(&attack),
        set.allowed(&attack.clone().stages(["Impact"]))
    );
}

#[test]
fn the_vocab_unknown_findings_of_the_goldens() {
    // tests/golden/cases/validate/json/{fault,tide-corpus-typo,vscode}: the
    // same message and help as the oracle, except where APPROVED.md says.
    let set = Vocabularies::bundled();
    let cases: [(&str, &str, bool, Option<&str>); 6] = [
        ("tlp::1.0", "clearr", false, Some("clear")),
        ("tlp::1.0", "ambr", false, Some("amber")),
        ("tlp::1.0", "whitish", false, None),
        ("alert_severity::1.0", "high", false, Some("High")),
        // The oracle suggests 'Substantial incident' and 'Host::File':
        // unrelated words that share letters (tests/golden/vocab/APPROVED.md).
        ("severity::1.0", "Big incident", false, None),
        ("signal.entities::1.0", "Host::Gizmo", true, None),
    ];
    for (vocab, value, scoped, suggestion) in cases {
        let unknown = set.check(value, &selector(vocab, scoped)).unwrap();
        assert_eq!(unknown.suggestion.as_deref(), suggestion, "{value}");
        assert_eq!(
            unknown.message(),
            format!("Value {value:?} is not a valid {vocab:?} vocabulary entry")
        );
        assert_eq!(
            unknown.help(),
            suggestion.map(|s| format!("did you mean {s:?}?"))
        );
    }
    assert_eq!(set.check("amber", &selector("tlp::1.0", false)), None);
    assert_eq!(Unknown::CODE, "vocab_unknown");
}

#[test]
fn identifiers_are_not_typos() {
    let set = Vocabularies::bundled();
    let actors = selector("actors::1.1", true);
    let uuid = "0b9b4c4c-7c1a-4b0e-9a5e-6b1e1d5c2a11";
    assert_eq!(set.suggest(uuid, &actors), None);
    // One character from a real actor id: as an edit, it is a typo of that id
    // (one edit, well within the bound), yet an identifier is never one.
    let real = "misp::1cb7e1cc-d695-42b1-92f4-fd0112a3c9be";
    assert!(set.is_valid(real, &actors));
    let near = "misp::1cb7e1cc-d695-42b1-92f4-fd0112a3c9bf";
    assert!(!set.is_valid(near, &actors));
    assert_eq!(
        opentide_core::suggest::closest(near, set.resolve(&actors).values()),
        Some(real)
    );
    assert_eq!(set.suggest(near, &actors), None);
    assert_eq!(set.suggest(&format!("misp::{uuid}"), &actors), None);
    assert!(is_opaque_identifier(&format!(" {} ", uuid.to_uppercase())));
    assert!(!is_opaque_identifier("0b9b4c4c-7c1a-4b0e-9a5e-6b1e1d5c2a1"));
    assert!(!is_opaque_identifier(
        "0b9b4c4c+7c1a-4b0e-9a5e-6b1e1d5c2a11"
    ));
}

#[test]
fn a_value_with_the_wrong_stage_prefix_suggests_the_key() {
    let set = Vocabularies::bundled();
    // Unscoped field, prefixed value: the stripped key is the suggestion.
    let surface = selector("surface::1.0", false);
    assert!(set.is_valid("OS::Windows::Desktop", &surface));
    let entities = selector("signal.entities::1.0", false);
    assert_eq!(
        set.suggest("Host::Proces", &entities).as_deref(),
        Some("Process")
    );
}

#[test]
fn quotes_as_every_message_does() {
    assert_eq!(quote("amber"), "\"amber\"");
    assert_eq!(quote("it's"), "\"it's\"");
    assert_eq!(quote("it's \"x\""), "\"it's \\\"x\\\"\"");
    assert_eq!(quote("a\\b\n\t\u{7}"), "\"a\\\\b\\n\\t\\u{7}\"");
    assert_eq!(quote("Zürich"), "\"Zürich\"");
    // C1 controls (NEL) and DEL.
    assert_eq!(quote("\u{85}"), "\"\\u{85}\"");
    assert_eq!(quote("\u{7f}"), "\"\\u{7f}\"");
}

/// A character that does not show is escaped, so `High` and a no-break space
/// never reads as `High`.
#[test]
fn quotes_invisible_characters_escaped() {
    let cases = [
        ("High\u{a0}", r#""High\u{a0}""#),
        ("a\u{ad}b", r#""a\u{ad}b""#),
        ("a\u{200b}b", r#""a\u{200b}b""#),
        ("a\u{2028}b", r#""a\u{2028}b""#),
        ("a\u{3000}b", r#""a\u{3000}b""#),
        ("\u{e0001}", r#""\u{e0001}""#),
        ("\u{10ffff}", r#""\u{10ffff}""#),
        // What shows stays as written: a space, an emoji.
        ("a b", "\"a b\""),
        ("\u{1f600}", "\"\u{1f600}\""),
    ];
    for (text, quoted) in cases {
        assert_eq!(quote(text), quoted, "{text:?}");
    }
    let unknown = Unknown {
        vocab: "alert_severity::1.0".to_owned(),
        value: "High\u{a0}".to_owned(),
        suggestion: Some("High".to_owned()),
    };
    assert_eq!(
        unknown.message(),
        r#"Value "High\u{a0}" is not a valid "alert_severity::1.0" vocabulary entry"#
    );
}

#[test]
fn a_data_root_replaces_the_bundle_and_objects_add_vocabularies() {
    let tlp = "name = \"TLP\"\nfield = \"tlp\"\n[[keys]]\nname = \"white\"\n";
    let (mut set, errors) = Vocabularies::from_files([
        ("tlp.vocab.toml", tlp),
        ("pap.vocab.toml", tlp),
        ("README.md", "not a vocabulary"),
    ]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(set.allowed(&selector("tlp", false)), ["white"]);
    assert!(set.get("att&ck").is_none());
    assert_eq!(set.fields().into_iter().collect::<Vec<_>>(), ["tlp"]);

    let objectives = Vocabulary::parse(
        "name = \"Objectives\"\nfield = \"objective\"\nmodel = true\n[[keys]]\nid = \"6f1c\"\nname = \"Detect\"\n",
        "objective",
    )
    .unwrap();
    set.insert(objectives);
    assert_eq!(set.allowed(&selector("objective", false)), ["6f1c"]);
    assert!(Vocabularies::default().fields().contains("att&ck"));
}

/// An id-keyed vocabulary's scoped values carry the entry's first stage,
/// however many it has.
#[test]
fn an_id_keyed_entry_is_scoped_by_its_first_stage() {
    let text = "name = \"G\"\nfield = \"groups\"\nkey = \"id\"\n\
                stages = [{ id = \"misp\" }, { id = \"att&ck\" }]\n\
                [[keys]]\nid = \"G1\"\nname = \"One\"\n\"tide.vocab.stages\" = [\"att&ck\", \"misp\"]\n";
    let (set, errors) = Vocabularies::from_files([("groups.vocab.toml", text)]);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(set.allowed(&selector("groups", true)), ["att&ck::G1"]);
    assert_eq!(set.allowed(&selector("groups", false)), ["G1"]);
}

/// A workspace's object vocabularies (`threat`, `objective`, `rule`) resolve
/// as id-keyed ones do, whatever the document says: every key, without a
/// stage filter.
#[test]
fn object_vocabularies_ignore_stage_filters() {
    let document = |field: &str| {
        format!(
            "name = \"N\"\nfield = \"{field}\"\nkey = \"name\"\n[[keys]]\nname = \"r1\"\n\"tide.vocab.stages\" = [\"x\"]\n"
        )
    };
    let (rule, other) = (document("rule"), document("other"));
    let (set, errors) = Vocabularies::from_files([
        ("rule.vocab.toml", rule.as_str()),
        ("other.vocab.toml", other.as_str()),
    ]);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(set.allowed(&selector("rule", false).stages(["y"])), ["r1"]);
    assert_eq!(
        set.allowed(&selector("rule", true).stages(["y"])),
        ["x::r1"]
    );
    // A name-keyed vocabulary that is no object family applies the filter.
    assert!(
        set.allowed(&selector("other", false).stages(["y"]))
            .is_empty()
    );
}

/// Every single-edit misspelling of every value a schema field accepts: the
/// intended value is the first suggestion, unless another allowed value is as
/// close to the misspelling (then nothing tells the two apart, and the
/// suggestion must be one of the equally close values).
#[test]
fn single_edit_misspellings_suggest_the_intended_value() {
    let set = Vocabularies::bundled();
    let mut checked = 0usize;
    let mut ambiguous = 0usize;
    for (vocab, scoped) in SCHEMA_SELECTORS {
        let selector = selector(vocab, scoped);
        let resolved = set.resolve(&selector);
        let allowed: Vec<String> = resolved.values().map(str::to_owned).collect();
        assert!(!allowed.is_empty(), "{vocab}");
        // A sample of each vocabulary, spread over it, keeps the run short.
        let step = (allowed.len() / 40).max(1);
        for (n, intended) in allowed.iter().enumerate().step_by(step) {
            // An identifier is never a suggestion's target (`identifiers_are_not_typos`).
            if is_opaque_identifier(intended) {
                continue;
            }
            for typo in misspellings(intended, n) {
                if resolved.is_valid(&typo) || is_opaque_identifier(&typo) {
                    continue;
                }
                checked += 1;
                let suggestion = resolved.suggest(&typo);
                if suggestion.as_deref() == Some(intended.as_str()) {
                    continue;
                }
                // Another value at least as close: the typo is ambiguous.
                let suggested = suggestion.unwrap_or_else(|| {
                    panic!("{vocab}: {typo:?} (from {intended:?}) suggests nothing")
                });
                let lower = |s: &str| s.to_lowercase();
                let to_intended = strsim::osa_distance(&lower(&typo), &lower(intended));
                let to_suggested = strsim::osa_distance(&lower(&typo), &lower(&suggested));
                assert!(
                    to_suggested <= to_intended,
                    "{vocab}: {typo:?} (from {intended:?}) suggests {suggested:?}"
                );
                ambiguous += 1;
            }
        }
    }
    eprintln!("{checked} single-edit misspellings, {ambiguous} as close to another value");
    assert!(checked > 10_000, "{checked} misspellings checked");
    assert!(
        ambiguous * 50 < checked,
        "{ambiguous} of {checked} ambiguous"
    );
}

/// Single-edit misspellings of `value`: each deletion, each transposition
/// of adjacent characters, and a substitution and an insertion at each
/// position, the replacement letter chosen by `seed` and the position.
fn misspellings(value: &str, seed: usize) -> Vec<String> {
    let chars: Vec<char> = value.chars().collect();
    let letters: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let pick = |i: usize| letters[(seed * 7 + i * 13) % letters.len()];
    let collect = |v: Vec<char>| v.into_iter().collect::<String>();
    let mut typos = Vec::new();
    for i in 0..chars.len() {
        let mut deleted = chars.clone();
        deleted.remove(i);
        typos.push(collect(deleted));
        if i + 1 < chars.len() && chars[i] != chars[i + 1] {
            let mut swapped = chars.clone();
            swapped.swap(i, i + 1);
            typos.push(collect(swapped));
        }
        let mut substituted = chars.clone();
        if !substituted[i].to_lowercase().eq(pick(i).to_lowercase()) {
            substituted[i] = pick(i);
            typos.push(collect(substituted));
        }
        let mut inserted = chars.clone();
        inserted.insert(i, pick(i + 1));
        typos.push(collect(inserted));
    }
    typos.retain(|t| {
        !t.is_empty() && opentide_core::suggest::fold(t) != opentide_core::suggest::fold(value)
    });
    typos
}
