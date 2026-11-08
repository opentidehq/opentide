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
    }
}

#[test]
fn recorded_digests() {
    let cases = [
        (small(1, Layout::Explicit), "d9a812c55c9b093f"),
        (small(1, Layout::Standard), "e53e81ab33ed3999"),
        (Options::new(20_261_107), "6f22a6344e5ff87c"),
        (
            Options {
                counts: Counts::scaled(0.1).unwrap(),
                layout: Layout::Custom,
                ..Options::new(20_261_107)
            },
            "15f88840c2958c75",
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
    let rules: Vec<_> = workspace.family(Family::Rule).collect();
    for platform in xtask::corpus::vocab::PLATFORMS {
        let count = rules
            .iter()
            .filter(|r| r.platforms.iter().any(|p| p == platform))
            .count();
        assert!(count >= 50, "{platform}: {count} rules");
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
    // Three or more platforms with tenants, and no literal secret: every
    // credential is a $VARIABLE reference.
    let configs: Vec<_> = workspace.family(Family::Config).collect();
    let with_tenants = configs.iter().filter(|c| c.has_tag("tenants")).count();
    assert!(with_tenants >= 3, "{with_tenants} platforms with tenants");
    for config in &configs {
        for line in config.render().lines() {
            let lower = line.to_ascii_lowercase();
            if ["secret", "token", "api_key", "password"]
                .iter()
                .any(|k| lower.starts_with(k) || lower.starts_with(&format!("azure_client_{k}")))
            {
                let value = line.split_once('=').map(|(_, v)| v.trim()).unwrap_or("");
                assert!(value.starts_with("\"$"), "{}: {line}", config.path);
            }
        }
    }
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
