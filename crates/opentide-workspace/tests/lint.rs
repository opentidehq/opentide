//! `lint` over a workspace in memory (UC-2.3, #818): every rule of
//! `LINT_CODES`, `lint.toml`, `--check`, `--file`, `--changed`, `--strict`,
//! `--fix`, the JSON entry of each finding (its keys in the oracle's order)
//! and the frame's diagnostic. The oracle comparison is `cargo xtask lint
//! diff` (every recorded `lint --json` case).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every configuration they parse is valid"
)]

mod lint {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use opentide_schema::configuration::lint::{LintConfig, parse_lint_config};
    use opentide_schema::configuration::toml;
    use opentide_workspace::lint::{
        Changed, LintCheck, LintFinding, LintOptions, LintReport, LintStatus, NextAction, lint,
    };
    use opentide_workspace::{FileSystem, MemoryFs, RootOptions, Severity, Workspace};

    const ROOT: &str = "/ws";
    const U1: &str = "11111111-1111-4111-8111-111111111111";
    const U2: &str = "22222222-2222-4222-8222-222222222222";

    fn rule(uuid: &str, name: &str) -> String {
        format!(
            "name: {name}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.1\n  author: me\n  organisation: us\n"
        )
    }

    fn workspace() -> MemoryFs {
        let fs = MemoryFs::new();
        fs.create_dir("/ws/.opentide/configurations");
        for family in ["rules", "threats", "objectives"] {
            fs.create_dir(format!("/ws/objects/{family}"));
        }
        fs
    }

    fn config(text: &str) -> LintConfig {
        parse_lint_config(Some(&toml::parse(text).unwrap())).unwrap()
    }

    fn options() -> LintOptions<'static> {
        LintOptions {
            cwd: PathBuf::from(ROOT),
            ..LintOptions::default()
        }
    }

    fn run(fs: &MemoryFs, config: &LintConfig, options: &LintOptions<'_>) -> LintReport {
        lint(fs, Some(fs), Path::new(ROOT), config, options)
    }

    fn codes(report: &LintReport) -> Vec<(&str, &str)> {
        report
            .findings
            .iter()
            .map(|finding| (finding.code(), finding.path()))
            .collect()
    }

    fn json(finding: &LintFinding) -> String {
        serde_json::to_string(finding).unwrap()
    }

    #[test]
    fn a_clean_catalogue_passes_with_its_count() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a-rule.yaml", rule(U1, "A rule"));
        let report = run(&fs, &LintConfig::default(), &options());
        assert!(report.findings.is_empty(), "{:?}", codes(&report));
        assert_eq!(report.status, LintStatus::Completed);
        assert_eq!(report.message, "Catalogue lint passed");
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.summary.unwrap().files, 1);
        assert_eq!(report.outcome.as_deref(), Some("1 file clean"));
        assert_eq!(
            report.checks,
            [
                LintCheck::Filenames,
                LintCheck::Metadata,
                LintCheck::Placeholders,
                LintCheck::Queries
            ]
        );
    }

    #[test]
    fn a_file_name_that_is_not_the_slug_is_a_warning_with_a_rename_step() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/rule-0001.yaml",
            rule(U1, "Sentinel KQL Rule"),
        );
        let report = run(&fs, &LintConfig::default(), &options());
        assert_eq!(
            codes(&report),
            [("filename_mismatch", "objects/rules/rule-0001.yaml")]
        );
        assert_eq!(
            json(&report.findings[0]),
            format!(
                r#"{{"check":"filenames","severity":"warning","path":"objects/rules/rule-0001.yaml","yaml_line":null,"uuid":"{U1}","expected":"objects/rules/sentinel-kql-rule.yaml","message":"Filename 'rule-0001.yaml' does not match slugify(name)='sentinel-kql-rule'","code":"filename_mismatch","field_path":[],"line":null,"column":null,"end_line":null,"end_column":null,"help":"rename it to objects/rules/sentinel-kql-rule.yaml","fix":null,"explain":"opentide explain filename_mismatch"}}"#
            )
        );
        assert_eq!(report.status, LintStatus::Issues);
        assert_eq!(
            report.next_actions,
            [NextAction {
                command: "opentide lint --fix".to_owned(),
                reason: "rename 1 file to match their names".to_owned(),
            }]
        );
        assert_eq!(report.outcome.as_deref(), Some("1 finding in 1 file"));
    }

    #[test]
    fn fix_renames_through_the_writer_and_reports_where_the_file_went() {
        let fs = workspace();
        // No organisation: its note follows the file to its new name.
        fs.write(
            "/ws/objects/rules/rule-0001.yaml",
            format!("name: Sentinel KQL Rule\nmetadata:\n  uuid: {U1}\n  author: me\n"),
        );
        // Debug output keeps its suffix.
        fs.write("/ws/objects/rules/x.debug.yaml", rule(U2, "B"));
        let report = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                fix: true,
                ..options()
            },
        );
        assert!(fs.is_file(Path::new("/ws/objects/rules/sentinel-kql-rule.yaml")));
        assert!(!fs.is_file(Path::new("/ws/objects/rules/rule-0001.yaml")));
        assert!(fs.is_file(Path::new("/ws/objects/rules/b.debug.yaml")));
        assert_eq!(report.fixed, 2);
        assert!(report.next_actions.is_empty());
        let note = &report.findings[0];
        assert_eq!(note.code(), "metadata_recommended");
        assert_eq!(note.json["path"], "objects/rules/sentinel-kql-rule.yaml");
        // Read from the file at its new name: the `metadata` key's place.
        assert_eq!(note.json["line"], 2);
        let first = &report.findings[1];
        assert_eq!(first.json["fixed"], true);
        assert_eq!(first.json["from"], "objects/rules/rule-0001.yaml");
        assert_eq!(first.json["path"], "objects/rules/sentinel-kql-rule.yaml");
        // `fixed` and `from` follow the message; a fixed finding has no step.
        let keys: Vec<&str> = first.json.keys().map(String::as_str).collect();
        assert_eq!(
            keys[5..10],
            ["expected", "message", "fixed", "from", "code"]
        );
        assert_eq!(first.json["help"], serde_json::Value::Null);
        assert_eq!(
            first.diagnostic.notes,
            [(
                "note".to_owned(),
                "renamed from objects/rules/rule-0001.yaml".to_owned()
            )]
        );
        assert_eq!(
            report.outcome.as_deref(),
            Some("1 note in 1 file · 2 fixed")
        );
    }

    #[test]
    fn fix_leaves_a_file_whose_name_is_taken() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/other.yaml", rule(U2, "A"));
        let report = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                fix: true,
                ..options()
            },
        );
        // `a.yaml` holds the slug; the other object gets its UUID's prefix.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].json["expected"],
            "objects/rules/a-22222222.yaml"
        );
        assert!(fs.is_file(Path::new("/ws/objects/rules/a-22222222.yaml")));
        // Now a name taken by a file lint does not read (not YAML).
        let fs = workspace();
        fs.write("/ws/objects/rules/one.yaml", rule(U1, "Two"));
        fs.write("/ws/objects/rules/two.yaml", "not: [yaml\n");
        let report = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                fix: true,
                ..options()
            },
        );
        let mismatch = report
            .findings
            .iter()
            .find(|f| f.code() == "filename_mismatch")
            .unwrap();
        assert_eq!(mismatch.json["fixed"], false);
        assert!(
            mismatch.json["message"]
                .as_str()
                .unwrap()
                .ends_with("; --fix skipped because objects/rules/two.yaml exists"),
            "{}",
            mismatch.json["message"]
        );
        assert!(fs.is_file(Path::new("/ws/objects/rules/one.yaml")));
        assert_eq!(report.fixed, 0);
    }

    #[test]
    fn a_file_that_does_not_parse_is_an_error_at_the_parsers_place() {
        let fs = workspace();
        fs.write("/ws/objects/rules/bad.yaml", "name: x\nlist: [a, b\n");
        fs.write("/ws/objects/rules/empty.yaml", "");
        let report = run(&fs, &LintConfig::default(), &options());
        let bad = &report.findings[0];
        assert_eq!(bad.code(), "yaml_parse");
        assert_eq!(bad.severity(), "error");
        assert!(
            bad.json["message"]
                .as_str()
                .unwrap()
                .starts_with("Could not parse object YAML: ")
        );
        assert!(bad.json["line"].is_u64() && bad.json["column"].is_u64());
        assert_eq!(bad.json["end_line"], bad.json["line"]);
        let empty = &report.findings[1];
        assert_eq!(
            empty.json["message"],
            "Could not parse object YAML: expected a mapping at the top of the file, found an empty file"
        );
        assert_eq!(empty.json["line"], serde_json::Value::Null);
        assert_eq!(report.summary.unwrap().errors, 2);
        assert_eq!(report.status, LintStatus::Issues);
        // Errors do not fail the run; --strict does.
        let strict = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                strict: true,
                ..options()
            },
        );
        assert_eq!(strict.status, LintStatus::Failed);
        assert_eq!(strict.exit_code, 1);
        assert_eq!(strict.failure_code, Some("issues_found"));
    }

    #[test]
    fn an_object_without_a_name_cannot_have_its_file_name_checked() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/x.yaml",
            format!("name: '  '\nmetadata:\n  uuid: {U1}\n"),
        );
        let report = run(&fs, &LintConfig::default(), &options());
        let finding = &report.findings[0];
        assert_eq!(finding.code(), "name_missing");
        assert_eq!(
            finding.json["message"],
            "Object has no name; cannot check filename slug"
        );
        // The `name` key is on the first line.
        assert_eq!(finding.json["yaml_line"], 0);
        assert_eq!(finding.json["line"], 1);
        assert_eq!(finding.json["column"], 1);
        assert_eq!(finding.json["end_column"], 5);
        assert_eq!(
            finding.json["help"],
            "add a name: the file name is derived from it"
        );
    }

    #[test]
    fn recommended_metadata_is_a_note_at_the_metadata_key() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!("name: A\nmetadata:\n  uuid: {U1}\n  schema: rule::1.1\n  organisation:\n    name: us\n"),
        );
        // A threat's schema has no `reviewed`: it is not recommended there.
        fs.write(
            "/ws/objects/threats/t.yaml",
            format!("name: T\nmetadata:\n  uuid: {U2}\n  schema: threat::1.0\n  author: me\n  organization: us\n"),
        );
        let config =
            config("[metadata]\nrequired = [\"author\", \"organisation\", \"reviewed\"]\n");
        let report = run(&fs, &config, &options());
        assert_eq!(
            codes(&report),
            [("metadata_recommended", "objects/rules/a.yaml")]
        );
        let finding = &report.findings[0];
        assert_eq!(
            json(finding),
            format!(
                r#"{{"check":"metadata","severity":"info","path":"objects/rules/a.yaml","yaml_line":1,"uuid":"{U1}","message":"Recommended metadata missing: author, reviewed","code":"metadata_recommended","field_path":["metadata"],"line":2,"column":1,"end_line":2,"end_column":9,"help":"add the missing keys under metadata","fix":null,"explain":"opentide explain metadata_recommended"}}"#
            )
        );
        // Lint's info is a note: its frame says so, its run is not a warning.
        assert_eq!(finding.diagnostic.severity, Severity::Info);
        assert_eq!(finding.diagnostic.severity.frame_label(), "note");
        assert!(report.outcome_ok);
        assert_eq!(report.outcome.as_deref(), Some("1 note in 1 file"));
        assert_eq!(report.summary.unwrap().notes, 1);
    }

    #[test]
    fn blank_or_empty_metadata_counts_as_missing() {
        let fs = workspace();
        for (file, uuid, author) in [
            ("blank", U1, "\"  \""),
            ("list", U2, "[]"),
            ("map", "33333333-3333-4333-8333-333333333333", "{}"),
        ] {
            fs.write(
                format!("/ws/objects/rules/{file}.yaml"),
                format!(
                    "name: {file}\nmetadata:\n  uuid: {uuid}\n  schema: rule::1.1\n  author: {author}\n  organisation: us\n"
                ),
            );
        }
        // A filled-in author is not reported.
        fs.write(
            "/ws/objects/rules/kept.yaml",
            rule("44444444-4444-4444-8444-444444444444", "kept"),
        );
        let report = run(&fs, &LintConfig::default(), &options());
        let mut reported: Vec<(&str, &str, &str)> = report
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.code(),
                    finding.path(),
                    finding.json["message"].as_str().unwrap(),
                )
            })
            .collect();
        reported.sort_unstable();
        assert_eq!(
            reported,
            [
                (
                    "metadata_recommended",
                    "objects/rules/blank.yaml",
                    "Recommended metadata missing: author"
                ),
                (
                    "metadata_recommended",
                    "objects/rules/list.yaml",
                    "Recommended metadata missing: author"
                ),
                (
                    "metadata_recommended",
                    "objects/rules/map.yaml",
                    "Recommended metadata missing: author"
                ),
            ]
        );
    }

    #[test]
    fn a_placeholder_points_at_its_value() {
        let fs = workspace();
        fs.write(
            "/ws/objects/rules/a.yaml",
            format!(
                "name: A\nmetadata:\n  uuid: {U1}\n  author: Your Name  # opentide:placeholder\n  organisation: us\ndescription: |  # opentide:placeholder\n  text\nsurface:\n  - x\n  - Y  # opentide:placeholder\n"
            ),
        );
        let report = run(&fs, &LintConfig::default(), &options());
        let marked: Vec<(String, u64, u64, u64)> = report
            .findings
            .iter()
            .filter(|f| f.code() == "placeholder")
            .map(|f| {
                (
                    f.json["message"].as_str().unwrap().to_owned(),
                    f.json["line"].as_u64().unwrap(),
                    f.json["column"].as_u64().unwrap(),
                    f.json["end_column"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            marked,
            [
                (
                    "author holds a placeholder value written by opentide new".to_owned(),
                    4,
                    11,
                    20
                ),
                (
                    "description holds a placeholder value written by opentide new".to_owned(),
                    6,
                    1,
                    12
                ),
                (
                    "surface[1] holds a placeholder value written by opentide new".to_owned(),
                    10,
                    5,
                    6
                ),
            ]
        );
        let keys: Vec<&str> = report.findings[0].json.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "check",
                "severity",
                "path",
                "yaml_line",
                "uuid",
                "help",
                "line",
                "column",
                "end_column",
                "message",
                "code",
                "field_path",
                "end_line",
                "fix",
                "explain"
            ]
        );
    }

    #[test]
    fn a_file_in_a_subfolder_is_reported_once() {
        let fs = workspace();
        fs.write("/ws/objects/rules/team/r.yaml", rule(U1, "R"));
        let report = run(&fs, &LintConfig::default(), &options());
        assert_eq!(
            codes(&report),
            [("nested_object_file", "objects/rules/team/r.yaml")]
        );
        assert!(report.findings[0].json["message"]
            .as_str()
            .unwrap()
            .starts_with("objects/rules/team/r.yaml is in a subfolder of objects/rules and is not an object instance"));
        assert_eq!(report.summary.unwrap().files, 0);
    }

    #[test]
    fn lint_toml_sets_styles_patterns_severities_and_checks() {
        let fs = workspace();
        fs.write("/ws/objects/rules/Rule One.yaml", rule(U1, "Rule One"));
        fs.write("/ws/objects/threats/t.yaml", rule(U2, "T 2"));
        let config = config(
            "[filenames]\nstyle = \"slug\"\nseverity = \"error\"\n[filenames.rules]\nstyle = \"name\"\npattern = \"R-.*\"\n[metadata]\nenabled = false\n",
        );
        let report = run(&fs, &config, &options());
        assert_eq!(
            report
                .findings
                .iter()
                .map(|f| (f.code(), f.severity(), f.path()))
                .collect::<Vec<_>>(),
            // Threats come first: lint reads threats, objectives, rules.
            [
                ("filename_mismatch", "error", "objects/threats/t.yaml"),
                ("filename_pattern", "error", "objects/rules/Rule One.yaml"),
            ]
        );
        assert_eq!(
            report.findings[1].json["help"],
            "rename the file so its name matches the pattern R-.*"
        );
        assert_eq!(report.findings[1].diagnostic.severity, Severity::Error);
        assert!(!report.checks.contains(&LintCheck::Metadata));
        // `--check` runs a check the file disables.
        let named = run(
            &fs,
            &config,
            &LintOptions {
                checks: vec![LintCheck::Metadata],
                ..options()
            },
        );
        assert_eq!(named.checks, [LintCheck::Metadata]);
        assert!(named.findings.is_empty());
    }

    #[test]
    fn file_narrows_every_check_but_stems_still_collide() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/b.yaml", rule(U2, "A"));
        let report = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                files: vec!["objects/rules/b.yaml".to_owned()],
                ..options()
            },
        );
        assert_eq!(report.scope, Some("selected"));
        assert_eq!(
            codes(&report),
            [("filename_mismatch", "objects/rules/b.yaml")]
        );
        assert_eq!(
            report.findings[0].json["expected"],
            "objects/rules/a-22222222.yaml"
        );
        assert_eq!(report.summary.unwrap().files, 1);
        assert_eq!(
            report.next_actions[0].command,
            "opentide lint --fix --file objects/rules/b.yaml"
        );
        // A target that selects nothing fails the run and is named.
        let missing = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                files: vec!["objects/rules/none.yaml".to_owned()],
                ..options()
            },
        );
        assert_eq!(missing.exit_code, 1);
        assert_eq!(missing.unmatched, ["objects/rules/none.yaml"]);
        assert_eq!(
            missing.message,
            "No object file directly in objects/threats, objects/objectives, objects/rules matched: objects/rules/none.yaml"
        );
        assert!(missing.summary.is_none());
        let payload = missing.payload();
        assert_eq!(
            payload.keys().copied().collect::<Vec<_>>(),
            ["path", "checks", "findings", "count", "fixed", "unmatched"]
        );
    }

    #[test]
    fn stems_that_differ_only_in_case_collide_in_one_folder() {
        const U3: &str = "33333333-3333-4333-8333-333333333333";
        const U4: &str = "44444444-4444-4444-8444-444444444444";
        let fs = workspace();
        fs.write("/ws/objects/rules/Rule One.yaml", rule(U1, "Rule One"));
        fs.write("/ws/objects/rules/x.yaml", rule(U2, "RULE ONE"));
        // Lowercase, not casefold: `ß` and `ss` are two names.
        fs.write("/ws/objects/rules/Straße.yaml", rule(U3, "Straße"));
        fs.write("/ws/objects/rules/y.yaml", rule(U4, "STRASSE"));
        let config = config("[filenames]\nstyle = \"name\"\n");
        let report = run(&fs, &config, &options());
        let mut expected: Vec<(&str, &str)> = report
            .findings
            .iter()
            .filter(|finding| finding.code() == "filename_mismatch")
            .map(|finding| (finding.path(), finding.json["expected"].as_str().unwrap()))
            .collect();
        expected.sort_unstable();
        assert_eq!(
            expected,
            [
                (
                    "objects/rules/x.yaml",
                    "objects/rules/RULE ONE-22222222.yaml"
                ),
                ("objects/rules/y.yaml", "objects/rules/STRASSE.yaml"),
            ]
        );
    }

    #[test]
    fn changed_narrows_to_the_hosts_diff_and_refuses_with_file() {
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        fs.write("/ws/objects/rules/x.yaml", rule(U2, "B"));
        let report = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                changed: Some(Changed::Files {
                    files: vec![PathBuf::from("/ws/objects/rules/a.yaml")],
                    warning: None,
                }),
                ..options()
            },
        );
        assert_eq!(report.scope, Some("changed"));
        assert!(report.findings.is_empty());
        assert_eq!(report.summary.unwrap().files, 1);
        let nothing = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                changed: Some(Changed::Files {
                    files: Vec::new(),
                    warning: Some("no commit yet".to_owned()),
                }),
                ..options()
            },
        );
        assert_eq!(
            nothing.outcome.as_deref(),
            Some("No changed object file to lint")
        );
        assert_eq!(nothing.warnings, ["no commit yet"]);
        let failed = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                changed: Some(Changed::Failed("--changed needs a git checkout".to_owned())),
                ..options()
            },
        );
        assert_eq!((failed.exit_code, failed.failure_code), (1, None));
        let both = run(
            &fs,
            &LintConfig::default(),
            &LintOptions {
                changed: Some(Changed::Failed(String::new())),
                files: vec!["a.yaml".to_owned()],
                ..options()
            },
        );
        assert_eq!(both.exit_code, 2);
        assert_eq!(both.failure_code, Some("usage_error"));
        assert_eq!(both.message, "--changed cannot be combined with --file");
    }

    #[test]
    fn one_file_gets_the_editors_file_name_and_metadata_findings() {
        use opentide_workspace::lint::lint_file;
        let fs = workspace();
        fs.write("/ws/objects/rules/a.yaml", rule(U1, "A"));
        // Shares A's name: expected with its UUID's prefix; no organisation.
        fs.write(
            "/ws/objects/rules/a-v2.yaml",
            format!("name: A\nmetadata:\n  uuid: {U2}\n  author: me\n"),
        );
        fs.write("/ws/objects/rules/team/n.yaml", rule(U2, "N"));
        let found = lint_file(
            &fs,
            Path::new(ROOT),
            &LintConfig::default(),
            Path::new("/ws/objects/rules/a-v2.yaml"),
        );
        assert_eq!(
            found
                .iter()
                .map(|f| (
                    f.code(),
                    f.json
                        .get("expected")
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                ))
                .collect::<Vec<_>>(),
            [
                ("metadata_recommended", ""),
                ("filename_mismatch", "objects/rules/a-22222222.yaml"),
            ]
        );
        assert_eq!(found[0].diagnostic.severity, Severity::Info);
        assert!(
            lint_file(
                &fs,
                Path::new(ROOT),
                &LintConfig::default(),
                Path::new("/ws/objects/rules/a.yaml")
            )
            .is_empty()
        );
        // Not an object file: nothing; the checks lint.toml disables: nothing.
        assert!(
            lint_file(
                &fs,
                Path::new(ROOT),
                &LintConfig::default(),
                Path::new("/ws/objects/rules/team/n.yaml")
            )
            .is_empty()
        );
        let off = config("[filenames]\nenabled = false\n[metadata]\nenabled = false\n");
        assert!(
            lint_file(
                &fs,
                Path::new(ROOT),
                &off,
                Path::new("/ws/objects/rules/a-v2.yaml")
            )
            .is_empty()
        );
    }

    #[test]
    fn no_workspace_points_at_setup() {
        let fs = MemoryFs::new();
        fs.create_dir("/ws");
        let report = run(&fs, &LintConfig::default(), &options());
        assert_eq!(
            report.outcome.as_deref(),
            Some("Catalogue lint passed, but found no object files under ./")
        );
        assert_eq!(report.next_actions[0].command, "opentide setup");
    }

    #[test]
    fn the_workspace_reads_its_lint_toml_and_refuses_one_it_cannot_use() {
        let fs = Arc::new(workspace());
        fs.write("/ws/objects/rules/r.yaml", rule(U1, "Other"));
        fs.write(
            "/ws/.opentide/configurations/lint.toml",
            "[filenames]\nstyle = \"none\"\n",
        );
        let open = |fs: &Arc<MemoryFs>| {
            Workspace::open(
                Arc::clone(fs) as Arc<dyn FileSystem>,
                opentide_workspace::Options {
                    roots: RootOptions {
                        repo: Some(PathBuf::from(ROOT)),
                        cwd: PathBuf::from(ROOT),
                        ..RootOptions::default()
                    },
                },
            )
            .unwrap()
        };
        let report = open(&fs).lint(None, &options());
        assert!(report.findings.is_empty(), "{:?}", codes(&report));
        fs.write(
            "/ws/.opentide/configurations/lint.toml",
            "[filenames]\nstyle = \"camel\"\n",
        );
        let refused = open(&fs).lint(None, &options());
        assert_eq!(refused.exit_code, 2);
        assert!(
            refused.message.contains("style must be one of"),
            "{}",
            refused.message
        );
    }
}
