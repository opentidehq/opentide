//! `cargo xtask check-layers`: every dependency between workspace crates
//! points down the layer table.
//!
//! The table (`xtask/layers.toml`) lists the layers of plan §4 from the bottom
//! up, each split into tiers from the bottom up. A crate's rank is its layer,
//! then its tier. A crate may depend only on a crate of strictly lower rank: a
//! lower layer, or a lower tier of its own layer. Normal, build and dev
//! dependencies all count, whatever their target. Every workspace member must
//! be placed exactly once, and every crate the table places must be a member.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

/// The layer table, as `xtask/layers.toml` writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerTable {
    /// The layers, from the bottom up.
    pub layer: Vec<Layer>,
}

/// One layer of the table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    /// The layer's name (`foundation`, `domain`, ...).
    pub name: String,
    /// The layer's crates by package name, in tiers from the bottom up. A
    /// layer no crate is in yet has none.
    #[serde(default)]
    pub tiers: Vec<Vec<String>>,
}

impl LayerTable {
    /// Reads a layer table from its TOML text.
    ///
    /// # Errors
    ///
    /// The text is not TOML, or not a table of `[[layer]]` entries with a
    /// `name` and `tiers`.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// The part of `cargo metadata --format-version 1 --no-deps` the check reads.
#[derive(Debug, Deserialize)]
pub struct Metadata {
    /// The workspace's packages.
    pub packages: Vec<Package>,
    /// The ids of the packages that are workspace members.
    pub workspace_members: Vec<String>,
    /// The workspace's root directory. cargo always prints it; a hand-written
    /// document may leave it out.
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
}

impl Metadata {
    /// Reads the JSON document `cargo metadata --format-version 1` prints.
    ///
    /// # Errors
    ///
    /// The text is not that document.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The workspace's layer table, `xtask/layers.toml` under its root, or
    /// `None` when the metadata does not name the root.
    pub fn layer_table(&self) -> Option<PathBuf> {
        Some(
            self.workspace_root
                .as_ref()?
                .join("xtask")
                .join("layers.toml"),
        )
    }
}

/// A package of the metadata.
#[derive(Debug, Deserialize)]
pub struct Package {
    /// Cargo's package id, as `workspace_members` lists it.
    pub id: String,
    /// The package name.
    pub name: String,
    /// Every dependency the manifest declares, of every kind and target.
    pub dependencies: Vec<Dependency>,
}

/// A dependency a manifest declares.
#[derive(Debug, Deserialize)]
pub struct Dependency {
    /// The package depended on. A renamed dependency keeps the package's
    /// name here; its alias is in `rename`, which the check ignores.
    pub name: String,
    /// `None` for a normal dependency, `"dev"` or `"build"` otherwise.
    pub kind: Option<String>,
}

/// The kind of a dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepKind {
    /// `[dependencies]`.
    Normal,
    /// `[build-dependencies]`.
    Build,
    /// `[dev-dependencies]`.
    Dev,
}

impl DepKind {
    fn of(dependency: &Dependency) -> Self {
        match dependency.kind.as_deref() {
            Some("build") => Self::Build,
            Some("dev") => Self::Dev,
            _ => Self::Normal,
        }
    }
}

impl fmt::Display for DepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Build => "build",
            Self::Dev => "dev",
        })
    }
}

/// Where the table places a crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// The layer's name.
    pub layer_name: String,
    /// The layer's index, from 0 at the bottom.
    pub layer: usize,
    /// The tier's index within the layer, from 0 at the bottom.
    pub tier: usize,
}

impl Place {
    fn rank(&self) -> (usize, usize) {
        (self.layer, self.tier)
    }
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} tier {}", self.layer_name, self.tier)
    }
}

/// A breach of the layer table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A workspace member the table does not place.
    Unplaced {
        /// The member's package name.
        krate: String,
    },
    /// A crate the table places that is not a workspace member.
    Stale {
        /// The name the table gives.
        krate: String,
    },
    /// A crate the table places more than once.
    Duplicate {
        /// The crate's package name.
        krate: String,
    },
    /// A dependency on a crate of the same rank or a higher one.
    NotDownward {
        /// The crate that declares the dependency.
        from: String,
        /// Where `from` is placed.
        from_place: Place,
        /// The crate depended on.
        to: String,
        /// Where `to` is placed.
        to_place: Place,
        /// The dependency's kind.
        kind: DepKind,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unplaced { krate } => write!(
                f,
                "`{krate}` is a workspace member the layer table does not place: \
                 add it to a layer (plan §4) and say why in the change"
            ),
            Self::Stale { krate } => write!(
                f,
                "the layer table places `{krate}`, which is not a workspace member: remove it"
            ),
            Self::Duplicate { krate } => {
                write!(f, "the layer table places `{krate}` more than once")
            }
            Self::NotDownward {
                from,
                from_place,
                to,
                to_place,
                kind,
            } => {
                let direction = if to_place.rank() == from_place.rank() {
                    "the same tier"
                } else {
                    "a higher place"
                };
                write!(
                    f,
                    "`{from}` ({from_place}) has a {kind} dependency on `{to}` ({to_place}), \
                     {direction}: a crate may depend only on crates of a lower layer, \
                     or of a lower tier of its own layer"
                )
            }
        }
    }
}

/// What the check found.
#[derive(Debug, Default)]
pub struct Report {
    /// The workspace members.
    pub crates: usize,
    /// The layers of the table.
    pub layers: usize,
    /// The dependencies between workspace members, counted per declaration.
    pub edges: usize,
    /// Every breach, in a stable order.
    pub violations: Vec<Violation>,
}

impl Report {
    /// Whether the workspace follows the table.
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Checks the workspace that `metadata` describes against `table`.
pub fn check(table: &LayerTable, metadata: &Metadata) -> Report {
    let mut report = Report {
        layers: table.layer.len(),
        ..Report::default()
    };

    let members: BTreeMap<&str, &Package> = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| (package.name.as_str(), package))
        .collect();
    report.crates = members.len();

    let mut places: BTreeMap<&str, Place> = BTreeMap::new();
    for (layer_index, layer) in table.layer.iter().enumerate() {
        for (tier_index, tier) in layer.tiers.iter().enumerate() {
            for krate in tier {
                let place = Place {
                    layer_name: layer.name.clone(),
                    layer: layer_index,
                    tier: tier_index,
                };
                if places.insert(krate.as_str(), place).is_some() {
                    report.violations.push(Violation::Duplicate {
                        krate: krate.clone(),
                    });
                }
            }
        }
    }

    for krate in places.keys().filter(|krate| !members.contains_key(*krate)) {
        report.violations.push(Violation::Stale {
            krate: (*krate).to_string(),
        });
    }
    for krate in members.keys().filter(|krate| !places.contains_key(*krate)) {
        report.violations.push(Violation::Unplaced {
            krate: (*krate).to_string(),
        });
    }

    for (name, package) in &members {
        for dependency in &package.dependencies {
            // Only dependencies on workspace members are edges of the table;
            // crates.io and git dependencies are not placed.
            if !members.contains_key(dependency.name.as_str()) {
                continue;
            }
            report.edges += 1;
            // An unplaced crate is reported once, above, not per edge.
            let (Some(from_place), Some(to_place)) =
                (places.get(name), places.get(dependency.name.as_str()))
            else {
                continue;
            };
            if to_place.rank() >= from_place.rank() {
                report.violations.push(Violation::NotDownward {
                    from: (*name).to_string(),
                    from_place: from_place.clone(),
                    to: dependency.name.clone(),
                    to_place: to_place.clone(),
                    kind: DepKind::of(dependency),
                });
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The table the repository checks against.
    const REPOSITORY_TABLE: &str = include_str!("../layers.toml");

    /// Crates, each with its dependencies on other packages as `(name, kind)`,
    /// where kind is `None`, `Some("dev")` or `Some("build")`.
    type Graph<'a> = [(&'a str, &'a [(&'a str, Option<&'a str>)])];

    /// The metadata `cargo metadata` would print for `crates`.
    fn metadata(crates: &Graph<'_>) -> Metadata {
        let packages: Vec<_> = crates
            .iter()
            .map(|(name, deps)| {
                json!({
                    "id": format!("path+file:///ws/{name}#0.1.0"),
                    "name": name,
                    "dependencies": deps
                        .iter()
                        .map(|(dep, kind)| json!({"name": dep, "kind": kind, "rename": null, "target": null}))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let members: Vec<_> = crates
            .iter()
            .map(|(name, _)| format!("path+file:///ws/{name}#0.1.0"))
            .collect();
        Metadata::parse(&json!({"packages": packages, "workspace_members": members}).to_string())
            .expect("synthetic metadata")
    }

    fn table(text: &str) -> LayerTable {
        LayerTable::parse(text).expect("synthetic table")
    }

    /// core < syntax (one layer, two tiers) < lsp (a layer above).
    const SMALL: &str = r#"
        [[layer]]
        name = "foundation"
        tiers = [["core"], ["syntax", "highlight"]]

        [[layer]]
        name = "application"
        tiers = [["lsp"]]
    "#;

    #[test]
    fn dependencies_on_lower_layers_and_lower_tiers_pass() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[("serde", None)]),
                ("syntax", &[("core", None)]),
                ("highlight", &[("core", None)]),
                (
                    "lsp",
                    &[
                        ("syntax", None),
                        ("core", Some("dev")),
                        ("highlight", Some("build")),
                    ],
                ),
            ]),
        );
        assert_eq!(report.violations, []);
        assert!(report.passed());
        assert_eq!((report.crates, report.layers, report.edges), (4, 2, 5));
    }

    #[test]
    fn an_upward_dependency_fails() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[("lsp", None)]),
                ("syntax", &[]),
                ("highlight", &[]),
                ("lsp", &[("core", None)]),
            ]),
        );
        assert!(!report.passed());
        assert_eq!(report.violations.len(), 1);
        let violation = &report.violations[0];
        assert!(matches!(
            violation,
            Violation::NotDownward { from, to, kind: DepKind::Normal, .. }
                if from == "core" && to == "lsp"
        ));
        assert_eq!(
            violation.to_string(),
            "`core` (foundation tier 0) has a normal dependency on `lsp` (application tier 0), \
             a higher place: a crate may depend only on crates of a lower layer, \
             or of a lower tier of its own layer"
        );
    }

    #[test]
    fn an_upward_dev_or_build_dependency_fails_too() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[("lsp", Some("dev")), ("syntax", Some("build"))]),
                ("syntax", &[]),
                ("highlight", &[]),
                ("lsp", &[]),
            ]),
        );
        let kinds: Vec<_> = report
            .violations
            .iter()
            .map(|violation| match violation {
                Violation::NotDownward { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, [Some(DepKind::Dev), Some(DepKind::Build)]);
    }

    #[test]
    fn a_dependency_within_one_tier_fails() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[]),
                ("syntax", &[("highlight", None)]),
                ("highlight", &[]),
                ("lsp", &[]),
            ]),
        );
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].to_string().contains("the same tier"));
    }

    #[test]
    fn a_dependency_on_a_higher_tier_of_the_same_layer_fails() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[("syntax", None)]),
                ("syntax", &[]),
                ("highlight", &[]),
                ("lsp", &[]),
            ]),
        );
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].to_string().contains("a higher place"));
    }

    #[test]
    fn a_member_the_table_does_not_place_fails() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[]),
                ("syntax", &[]),
                ("highlight", &[]),
                ("lsp", &[]),
                ("xtask", &[("lsp", None)]),
            ]),
        );
        assert_eq!(
            report.violations,
            [Violation::Unplaced {
                krate: "xtask".into()
            }]
        );
    }

    #[test]
    fn a_placed_crate_that_is_not_a_member_fails() {
        let report = check(
            &table(SMALL),
            &metadata(&[("core", &[]), ("syntax", &[]), ("lsp", &[])]),
        );
        assert_eq!(
            report.violations,
            [Violation::Stale {
                krate: "highlight".into()
            }]
        );
    }

    #[test]
    fn a_crate_placed_twice_fails() {
        let report = check(
            &table(
                r#"
                [[layer]]
                name = "foundation"
                tiers = [["core"], ["core"]]
                "#,
            ),
            &metadata(&[("core", &[])]),
        );
        assert_eq!(
            report.violations,
            [Violation::Duplicate {
                krate: "core".into()
            }]
        );
    }

    #[test]
    fn dependencies_outside_the_workspace_are_not_edges() {
        let report = check(
            &table(SMALL),
            &metadata(&[
                ("core", &[("serde", None), ("tree-sitter", Some("build"))]),
                ("syntax", &[]),
                ("highlight", &[]),
                ("lsp", &[]),
            ]),
        );
        assert!(report.passed());
        assert_eq!(report.edges, 0);
    }

    #[test]
    fn a_package_that_is_not_a_member_is_not_checked() {
        let mut metadata = metadata(&[
            ("core", &[]),
            ("syntax", &[]),
            ("highlight", &[]),
            ("lsp", &[]),
            ("fuzz", &[("lsp", None)]),
        ]);
        metadata
            .workspace_members
            .retain(|id| !id.contains("/fuzz#"));
        assert!(check(&table(SMALL), &metadata).passed());
    }

    #[test]
    fn the_layer_table_is_the_one_of_the_workspace_the_metadata_describes() {
        let mut metadata = metadata(&[("core", &[])]);
        assert_eq!(metadata.layer_table(), None);
        metadata.workspace_root = Some(PathBuf::from("/work/tree-b"));
        assert_eq!(
            metadata.layer_table(),
            Some(PathBuf::from("/work/tree-b/xtask/layers.toml"))
        );
        let printed = Metadata::parse(
            r#"{"packages": [], "workspace_members": [], "workspace_root": "/work/tree-c"}"#,
        )
        .expect("metadata");
        assert_eq!(
            printed.layer_table(),
            Some(PathBuf::from("/work/tree-c/xtask/layers.toml"))
        );
    }

    #[test]
    fn the_table_rejects_unknown_keys() {
        assert!(LayerTable::parse("[[layer]]\nname = \"x\"\ncrates = [\"a\"]\n").is_err());
    }

    /// Today's workspace graph: each member with its dependencies on other
    /// members (from `cargo metadata`). `cargo xtask check-layers` reads the
    /// real graph; this copy lets a unit test change it.
    const WORKSPACE: &Graph<'static> = &[
        ("opentide-core", &[]),
        ("opentide-syntax", &[("opentide-core", None)]),
        ("opentide-highlight", &[("opentide-core", None)]),
        ("opentide-ecs", &[("opentide-core", None)]),
        (
            "opentide-kql",
            &[
                ("opentide-core", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-spl",
            &[
                ("opentide-core", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-kuery",
            &[
                ("opentide-core", None),
                ("opentide-ecs", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-lucene",
            &[
                ("opentide-core", None),
                ("opentide-ecs", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-falco",
            &[
                ("opentide-core", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-cql",
            &[
                ("opentide-core", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-esql",
            &[
                ("opentide-core", None),
                ("opentide-ecs", None),
                ("opentide-lucene", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-eql",
            &[
                ("opentide-core", None),
                ("opentide-ecs", None),
                ("opentide-lucene", None),
                ("opentide-syntax", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-tide",
            &[
                ("opentide-core", None),
                ("opentide-ecs", None),
                ("opentide-kql", None),
                ("opentide-spl", None),
                ("opentide-esql", None),
                ("opentide-eql", None),
                ("opentide-kuery", None),
                ("opentide-lucene", None),
                ("opentide-falco", None),
                ("opentide-cql", None),
                ("opentide-highlight", None),
            ],
        ),
        (
            "opentide-analysis",
            &[
                ("opentide-core", None),
                ("opentide-highlight", None),
                ("opentide-kql", None),
                ("opentide-spl", None),
                ("opentide-esql", None),
                ("opentide-eql", None),
                ("opentide-kuery", None),
                ("opentide-lucene", None),
                ("opentide-falco", None),
                ("opentide-cql", None),
                ("opentide-ecs", None),
                ("opentide-tide", None),
            ],
        ),
        (
            "opentide-lsp",
            &[
                ("opentide-core", None),
                ("opentide-analysis", None),
                ("opentide-highlight", None),
                ("opentide-kql", None),
                ("opentide-spl", None),
                ("opentide-tide", None),
            ],
        ),
        (
            "opentide-wasm",
            &[
                ("opentide-core", None),
                ("opentide-analysis", None),
                ("opentide-highlight", None),
                ("opentide-lsp", None),
            ],
        ),
        (
            "opentide-native",
            &[
                ("opentide-analysis", None),
                ("opentide-lsp", None),
                ("opentide-compare", None),
            ],
        ),
        (
            "xtask",
            &[("opentide-compare", None), ("opentide-schema", None)],
        ),
        // Appended, not in layer order, so the indexes the tests below use stay put.
        ("opentide-compare", &[]),
        (
            "opentide-schema",
            &[("opentide-core", None), ("opentide-schema-derive", None)],
        ),
        ("opentide-schema-derive", &[]),
    ];

    #[test]
    fn the_repository_table_places_todays_workspace() {
        let report = check(&table(REPOSITORY_TABLE), &metadata(WORKSPACE));
        assert_eq!(report.violations, []);
        assert_eq!(report.crates, 21);
    }

    #[test]
    fn the_repository_table_fails_a_deliberate_upward_dependency() {
        // opentide-core (foundation) on opentide-lsp (application).
        let mut crates = WORKSPACE.to_vec();
        crates[0] = ("opentide-core", &[("opentide-lsp", None)]);
        let report = check(&table(REPOSITORY_TABLE), &metadata(&crates));
        assert_eq!(report.violations.len(), 1);
        assert!(matches!(
            &report.violations[0],
            Violation::NotDownward { from, to, from_place, to_place, .. }
                if from == "opentide-core"
                    && to == "opentide-lsp"
                    && from_place.layer_name == "foundation"
                    && to_place.layer_name == "application"
        ));
    }

    #[test]
    fn the_repository_table_fails_a_query_engine_on_its_own_tier() {
        // opentide-kql and opentide-spl share foundation tier 2.
        let mut crates = WORKSPACE.to_vec();
        crates[4] = ("opentide-kql", &[("opentide-spl", None)]);
        let report = check(&table(REPOSITORY_TABLE), &metadata(&crates));
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].to_string().contains("the same tier"));
    }

    #[test]
    fn the_repository_table_fails_a_dependency_on_a_binding_or_on_xtask() {
        // opentide-lsp (application) on opentide-wasm (bindings), as a dev
        // dependency; opentide-analysis (domain) on xtask (tooling), as a build one.
        let mut crates = WORKSPACE.to_vec();
        crates[14] = ("opentide-lsp", &[("opentide-wasm", Some("dev"))]);
        crates[13] = ("opentide-analysis", &[("xtask", Some("build"))]);
        let report = check(&table(REPOSITORY_TABLE), &metadata(&crates));
        let edges: Vec<_> = report
            .violations
            .iter()
            .map(|violation| match violation {
                Violation::NotDownward { from, to, kind, .. } => {
                    format!("{from} -> {to} ({kind})")
                }
                other => other.to_string(),
            })
            .collect();
        assert_eq!(
            edges,
            [
                "opentide-analysis -> xtask (build)",
                "opentide-lsp -> opentide-wasm (dev)"
            ]
        );
    }
}
