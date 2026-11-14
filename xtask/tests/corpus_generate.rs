//! The generator is deterministic by seed (UC-0.6, #804, acceptance 1): a
//! seed and its options always give the same bytes. The digests below are
//! recorded; a change to the generator that changes its output updates
//! them in the same commit, and the commit says why (the golden recordings
//! of UC-0.5 and the benchmark baselines of UC-0.8 are made from this
//! output).

use xtask::corpus::generate::{self, Counts, Layout, Options};
use xtask::corpus::workspace::Family;

fn small(seed: u64, layout: Layout) -> Options {
    Options {
        seed,
        counts: Counts {
            threats: 30,
            objectives: 30,
            rules: 50,
        },
        layout,
        platforms: xtask::corpus::vocab::PLATFORMS,
    }
}

#[test]
fn recorded_digests() {
    let cases = [
        (small(1, Layout::Explicit), "b00e36255367af94"),
        (small(1, Layout::Standard), "5e4a4003b4ceb472"),
        (Options::new(20_261_107), "2548baff64b1685f"),
        (
            Options {
                counts: Counts::scaled(0.1).unwrap(),
                layout: Layout::Custom,
                ..Options::new(20_261_107)
            },
            "69467fa3f9feee22",
        ),
        // The benchmarks' workspace: the platforms their 0.23.0 oracle knows,
        // the corpus their baselines were measured on (tests/bench/budgets.toml).
        (
            Options {
                platforms: xtask::bench::oracle::ORACLE_PLATFORMS,
                ..Options::new(20_261_107)
            },
            "5978a2ab7c093587",
        ),
    ];
    for (options, digest) in cases {
        assert_eq!(
            generate::generate(&options).digest(),
            digest,
            "{options:?}: the output changed; if that is intended, record the new digest"
        );
    }
}

#[test]
fn same_seed_same_bytes_other_seed_other_bytes() {
    let one = generate::generate(&small(1, Layout::Explicit));
    let again = generate::generate(&small(1, Layout::Explicit));
    assert_eq!(one.rendered(), again.rendered());
    let two = generate::generate(&small(2, Layout::Explicit));
    assert_ne!(one.digest(), two.digest());
}

#[test]
fn counts_and_coverage_of_the_default_workspace() {
    let workspace = generate::generate(&Options::new(20_261_107));
    assert_eq!(workspace.family(Family::Threat).count(), 300);
    assert_eq!(workspace.family(Family::Objective).count(), 300);
    assert_eq!(workspace.family(Family::Rule).count(), 500);
    // Every platform, both rule revisions and every feature the scope names.
    // Each platform is the primary of one rule in each rotation of the list,
    // so it holds at least its share of the rules, more with the second and
    // third platforms some rules add.
    let rules: Vec<_> = workspace.family(Family::Rule).collect();
    let platforms = xtask::corpus::vocab::PLATFORMS;
    let share = rules.len() / platforms.len();
    for platform in platforms {
        let count = rules
            .iter()
            .filter(|r| r.platforms.iter().any(|p| p == platform))
            .count();
        assert!(
            count > share,
            "{platform}: {count} rules, its share is {share}"
        );
    }
    for tag in [
        "rule::1.0",
        "rule::1.1",
        "reviewed",
        "hunt",
        "responders",
        "references",
        "model:signal",
        "model:objective",
        "sentinel:nrt",
        "elastic:eql",
        "elastic:esql",
        "elastic:threshold",
        "harfanglab:yara",
        "sentinel_one:correlation",
        "sysdig:macro",
        "sentinel:tenants",
        "elastic:tenants",
    ] {
        assert!(rules.iter().any(|r| r.has_tag(tag)), "no rule has {tag}");
    }
    for tag in ["chaining", "actors", "references"] {
        assert!(
            workspace.family(Family::Threat).any(|t| t.has_tag(tag)),
            "no threat has {tag}"
        );
    }
    assert!(
        workspace
            .family(Family::Objective)
            .any(|o| o.has_tag("signal-parent"))
    );
    // Five platforms with tenants, and no literal secret or real host.
    let configs: Vec<_> = workspace.family(Family::Config).collect();
    let with_tenants = configs.iter().filter(|c| c.has_tag("tenants")).count();
    assert!(with_tenants >= 5, "{with_tenants} platforms with tenants");
    for config in &configs {
        let problems = credential_problems(&config.render());
        assert!(problems.is_empty(), "{}: {problems:?}", config.path);
    }
}

/// What in a configuration file is not a placeholder: a credential (a key
/// that names a secret, token, key or password, or an `*_id` of a tenant's
/// setup) whose value is not a `$VARIABLE` reference, or a `url`/`*_url`
/// whose host is not on a reserved example domain.
fn credential_problems(text: &str) -> Vec<String> {
    fn walk(value: &toml::Value, path: &str, setup: bool, problems: &mut Vec<String>) {
        match value {
            toml::Value::Table(table) => {
                for (key, value) in table {
                    let here = format!("{path}.{key}");
                    let lower = key.to_ascii_lowercase();
                    if let toml::Value::String(text) = value {
                        let credential = ["secret", "token", "key", "password"]
                            .iter()
                            .any(|word| lower.contains(word))
                            || (setup && lower.ends_with("_id"));
                        if credential && !text.starts_with('$') {
                            problems.push(format!("{here} = {text:?} is not a $VARIABLE"));
                        }
                        if lower == "url" || lower.ends_with("_url") {
                            let host = text
                                .split("://")
                                .nth(1)
                                .and_then(|rest| rest.split(['/', ':']).next())
                                .unwrap_or("");
                            if !(host.ends_with(".example") || host.ends_with(".example.internal"))
                            {
                                problems.push(format!("{here} = {text:?} is not an example host"));
                            }
                        }
                    }
                    walk(value, &here, setup || key == "setup", problems);
                }
            }
            toml::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{path}.{index}"), setup, problems);
                }
            }
            _ => {}
        }
    }
    let mut problems = Vec::new();
    match toml::from_str::<toml::Table>(text) {
        Ok(table) => walk(&toml::Value::Table(table), "", false, &mut problems),
        Err(error) => problems.push(format!("does not parse: {error}")),
    }
    problems
}

#[test]
fn the_credential_check_catches_literals_and_real_hosts() {
    let bad = "[[tenants]]\nname = \"t\"\n[tenants.setup]\nclient_secret = \"hunter2\"\n\
               api_token = \"abc\"\nclient_id = \"0000\"\nurl = \"https://soc.contoso.com:9200\"\n\
               elasticsearch_url = \"https://es.example\"\n";
    let problems = credential_problems(bad);
    assert_eq!(problems.len(), 4, "{problems:?}");
    let good = "[[tenants]]\nname = \"t\"\n[tenants.setup]\nclient_secret = \"$X_SECRET\"\n\
                client_id = \"$X_ID\"\nurl = \"https://kibana.t.example\"\n";
    assert!(credential_problems(good).is_empty());
}

#[test]
fn every_layout_places_objects_in_its_folders() {
    for layout in Layout::ALL {
        let workspace = generate::generate(&small(3, layout));
        for family in [Family::Threat, Family::Objective, Family::Rule] {
            for file in workspace.family(family) {
                assert!(
                    file.path.starts_with(layout.folder(family)),
                    "{}",
                    file.path
                );
            }
        }
        let paths = workspace.file(".opentide/configurations/paths.toml");
        assert_eq!(paths.is_some(), layout != Layout::Standard, "{layout:?}");
    }
}

#[test]
fn file_names_are_slugs_of_the_names() {
    let workspace = generate::generate(&small(4, Layout::Explicit));
    for file in workspace
        .files
        .iter()
        .filter(|f| matches!(f.family, Family::Threat | Family::Objective | Family::Rule))
    {
        let xtask::corpus::workspace::Body::Yaml(doc) = &file.body else {
            panic!("{} is not YAML", file.path);
        };
        let name = doc.get("name").and_then(|n| n.as_str()).unwrap();
        let stem = file
            .path
            .rsplit('/')
            .next()
            .unwrap()
            .trim_end_matches(".yaml");
        assert_eq!(stem, generate::slugify(name));
    }
}
