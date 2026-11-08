//! The comparator's acceptance cases (#805): `cargo nextest run -p xtask
//! comparator`. Synthetic runs of a fake command go through
//! `opentide_compare::compare` with a ledger, as `cargo xtask compare` and
//! `golden check --engine compare` use it.

mod comparator {
    use opentide_compare::ledger::{Ledger, Usage};
    use opentide_compare::{
        Case, CaseReport, FileState, Kind, Normaliser, Run, RunReport, compare,
    };

    const ISSUE: &str = "https://github.com/opentidehq/opentide/issues/805";

    fn run(exit_code: i32, stdout: &str, stderr: &str) -> Run {
        Run {
            exit_code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            files: std::collections::BTreeMap::new(),
        }
    }

    fn with_file(mut run: Run, path: &str, bytes: &str) -> Run {
        run.files.insert(
            path.to_owned(),
            FileState::Written {
                mode: 0o644,
                bytes: bytes.as_bytes().to_vec(),
            },
        );
        run
    }

    fn entry(case: &str, target: &str, rule: &str, oracle: &str, candidate: &str) -> String {
        format!(
            "[[diff]]\ncommand = \"info\"\ncase = {case:?}\ntarget = {target:?}\nrule = {rule:?}\n\
             oracle = '{oracle}'\ncandidate = '{candidate}'\nreason = \"intended\"\n\
             issue = \"{ISSUE}\"\nchangelog = \"**Intended**\"\n"
        )
    }

    fn check(oracle: &Run, candidate: &Run, ledger: &Ledger) -> (CaseReport, Usage) {
        let mut usage = Usage::default();
        let report = compare(
            Case {
                command: "info",
                id: "json/tide_corpus",
            },
            oracle,
            candidate,
            ledger,
            &mut usage,
        );
        (report, usage)
    }

    fn kinds(report: &CaseReport) -> Vec<(String, Kind, Option<String>)> {
        report
            .differences
            .iter()
            .map(|difference| {
                (
                    difference.target.clone(),
                    difference.kind,
                    difference.pointer.clone(),
                )
            })
            .collect()
    }

    const DOCUMENT: &str =
        "{\"ok\":true,\"summary\":{\"rules\":3,\"threats\":1},\"exit_code\":0}\n";

    #[test]
    fn equal_runs_are_equal() {
        let oracle = with_file(run(0, DOCUMENT, "warning: x\n"), "out/a.md", "# A\n");
        let (report, _) = check(&oracle, &oracle.clone(), &Ledger::default());
        assert!(report.equal, "{report:?}");
        assert!(report.differences.is_empty() && report.approved.is_empty());
    }

    #[test]
    fn different_stdout_is_reported_at_its_pointer() {
        let oracle = run(0, DOCUMENT, "");
        let candidate = run(0, &DOCUMENT.replace("\"rules\":3", "\"rules\":4"), "");
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert!(!report.equal);
        assert_eq!(
            kinds(&report),
            vec![(
                "stdout".into(),
                Kind::JsonValue,
                Some("/summary/rules".into())
            )]
        );
        assert_eq!(
            (
                report.differences[0].oracle.as_str(),
                report.differences[0].candidate.as_str()
            ),
            ("3", "4")
        );
    }

    #[test]
    fn different_text_stdout_is_reported_at_its_line() {
        let oracle = run(0, "✓ 3 rules\n→ opentide validate\n", "");
        let candidate = run(0, "✓ 3 rules\n→ opentide lint\n", "");
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert_eq!(kinds(&report), vec![("stdout".into(), Kind::Bytes, None)]);
        assert_eq!(report.differences[0].at.as_deref(), Some("line 2, byte 25"));
        assert_eq!(report.differences[0].candidate, "→ opentide lint");
    }

    #[test]
    fn different_stderr_is_reported() {
        let (report, _) = check(
            &run(1, "", "error: a\n"),
            &run(1, "", "error: b\n"),
            &Ledger::default(),
        );
        assert_eq!(kinds(&report), vec![("stderr".into(), Kind::Bytes, None)]);
    }

    #[test]
    fn different_exit_code_is_reported() {
        let (report, _) = check(&run(1, "", ""), &run(2, "", ""), &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("exit_code".into(), Kind::ExitCode, None)]
        );
        assert_eq!(
            (
                report.differences[0].oracle.as_str(),
                report.differences[0].candidate.as_str()
            ),
            ("1", "2")
        );
    }

    #[test]
    fn different_file_bytes_are_reported() {
        let oracle = with_file(run(0, "", ""), "docs/rule.md", "# Rule\n\nbody\n");
        let candidate = with_file(run(0, "", ""), "docs/rule.md", "# Rule\n\nBody\n");
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("file:docs/rule.md".into(), Kind::Bytes, None)]
        );
        assert_eq!(report.differences[0].at.as_deref(), Some("line 3, byte 8"));
    }

    #[test]
    fn a_file_on_one_side_its_mode_and_its_deletion_are_reported() {
        let oracle = with_file(run(0, "", ""), "a.json", "{}");
        let (report, _) = check(&oracle, &run(0, "", ""), &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("file:a.json".into(), Kind::FileMissing, None)]
        );
        let (report, _) = check(&run(0, "", ""), &oracle, &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("file:a.json".into(), Kind::FileExtra, None)]
        );

        let mut executable = oracle.clone();
        executable.files.insert(
            "a.json".into(),
            FileState::Written {
                mode: 0o755,
                bytes: b"{}".to_vec(),
            },
        );
        let (report, _) = check(&oracle, &executable, &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("file:a.json".into(), Kind::FileMode, None)]
        );

        let mut deleted = oracle.clone();
        deleted.files.insert("a.json".into(), FileState::Deleted);
        let (report, _) = check(&oracle, &deleted, &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![("file:a.json".into(), Kind::FileState, None)]
        );
    }

    #[test]
    fn json_files_are_compared_as_json() {
        let oracle = with_file(run(0, "", ""), "catalog.json", "{\"a\":1,\"b\":2}");
        let candidate = with_file(run(0, "", ""), "catalog.json", "{\"a\":1,\"b\":3}");
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert_eq!(
            kinds(&report),
            vec![(
                "file:catalog.json".into(),
                Kind::JsonValue,
                Some("/b".into())
            )]
        );
    }

    #[test]
    fn json_key_order_must_be_equal() {
        let oracle = run(0, DOCUMENT, "");
        let candidate = run(
            0,
            "{\"ok\":true,\"summary\":{\"threats\":1,\"rules\":3},\"exit_code\":0}\n",
            "",
        );
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert!(!report.equal);
        assert_eq!(
            kinds(&report),
            vec![("stdout".into(), Kind::JsonKeyOrder, Some("/summary".into()))]
        );
        assert_eq!(report.differences[0].oracle, "rules, threats");
        assert_eq!(report.differences[0].candidate, "threats, rules");
    }

    #[test]
    fn the_same_json_in_other_bytes_is_reported() {
        let indented = "{\n  \"ok\": true,\n  \"summary\": {\n    \"rules\": 3,\n    \"threats\": 1\n  },\n  \"exit_code\": 0\n}\n";
        let (report, _) = check(
            &run(0, DOCUMENT, ""),
            &run(0, indented, ""),
            &Ledger::default(),
        );
        assert_eq!(
            kinds(&report),
            vec![("stdout".into(), Kind::JsonBytes, None)]
        );
        let no_newline = DOCUMENT.trim_end();
        let (report, _) = check(
            &run(0, DOCUMENT, ""),
            &run(0, no_newline, ""),
            &Ledger::default(),
        );
        assert_eq!(
            kinds(&report),
            vec![("stdout".into(), Kind::JsonBytes, None)]
        );
    }

    #[test]
    fn an_approved_diff_is_approved_and_only_there() {
        let ledger = Ledger::parse(&entry("json/*", "stdout", "json:/summary/rules", "3", "4"))
            .expect("valid");
        let candidate = run(0, &DOCUMENT.replace("\"rules\":3", "\"rules\":4"), "");
        let (report, usage) = check(&run(0, DOCUMENT, ""), &candidate, &ledger);
        assert!(report.equal, "{report:?}");
        assert_eq!(report.approved.len(), 1);
        assert_eq!(report.approved[0].entry, 1);
        assert!(usage.is_used(0));

        // Narrow: another difference beside the approved one is still reported.
        let both = run(
            0,
            &DOCUMENT
                .replace("\"rules\":3", "\"rules\":4")
                .replace("\"threats\":1", "\"threats\":2"),
            "",
        );
        let (report, _) = check(&run(0, DOCUMENT, ""), &both, &ledger);
        assert_eq!(
            kinds(&report),
            vec![(
                "stdout".into(),
                Kind::JsonValue,
                Some("/summary/threats".into())
            )]
        );

        // Narrow: the candidate's value must be the one approved.
        let other = run(0, &DOCUMENT.replace("\"rules\":3", "\"rules\":5"), "");
        let (report, usage) = check(&run(0, DOCUMENT, ""), &other, &ledger);
        assert!(!report.equal);
        assert!(!usage.is_used(0));

        // Narrow: another case is not approved.
        let mut usage = Usage::default();
        let report = compare(
            Case {
                command: "info",
                id: "plain/tide_corpus",
            },
            &run(0, DOCUMENT, ""),
            &candidate,
            &ledger,
            &mut usage,
        );
        assert!(!report.equal);
    }

    #[test]
    fn an_approved_insertion_keeps_key_order_checked() {
        let ledger = Ledger::parse(&entry(
            "*",
            "stdout",
            "json:/engine",
            "(absent)",
            "\"rust\"",
        ))
        .expect("valid");
        let candidate = run(
            0,
            "{\"ok\":true,\"summary\":{\"rules\":3,\"threats\":1},\"engine\":\"rust\",\"exit_code\":0}\n",
            "",
        );
        let (report, _) = check(&run(0, DOCUMENT, ""), &candidate, &ledger);
        assert!(report.equal, "{report:?}");
        let reordered = run(
            0,
            "{\"summary\":{\"rules\":3,\"threats\":1},\"ok\":true,\"engine\":\"rust\",\"exit_code\":0}\n",
            "",
        );
        let (report, _) = check(&run(0, DOCUMENT, ""), &reordered, &ledger);
        assert_eq!(
            kinds(&report),
            vec![("stdout".into(), Kind::JsonKeyOrder, Some(String::new()))]
        );
    }

    #[test]
    fn an_approved_diff_still_checks_the_layout() {
        let ledger =
            Ledger::parse(&entry("*", "stdout", "json:/summary/rules", "3", "4")).expect("valid");
        let indented = "{\n  \"ok\": true,\n  \"summary\": {\n    \"rules\": 4,\n    \"threats\": 1\n  },\n  \"exit_code\": 0\n}\n";
        let (report, _) = check(&run(0, DOCUMENT, ""), &run(0, indented, ""), &ledger);
        assert_eq!(
            kinds(&report),
            vec![("stdout".into(), Kind::JsonBytes, None)]
        );
    }

    #[test]
    fn approved_text_and_exit_code_diffs() {
        let text = entry(
            "*",
            "stderr",
            "text",
            "help: run opentide doctor",
            "help: run opentide doctor --json",
        );
        let exit = entry("*", "exit_code", "text", "1", "2");
        let ledger = Ledger::parse(&format!("{text}{exit}")).expect("valid");
        let oracle = run(1, "", "error: x\n  help: run opentide doctor\n");
        let candidate = run(2, "", "error: x\n  help: run opentide doctor --json\n");
        let (report, usage) = check(&oracle, &candidate, &ledger);
        assert!(report.equal, "{report:?}");
        assert!(usage.is_used(0) && usage.is_used(1));
    }

    #[test]
    fn a_text_rule_applies_only_on_the_line_it_explains() {
        let ledger =
            Ledger::parse(&entry("*", "stdout", "text", "help: a", "help: b")).expect("valid");
        // Both texts are present, but on different lines: not this difference.
        let oracle = run(0, "help: a\nx\n", "");
        let candidate = run(0, "help: a\ny\nhelp: b\n", "");
        let (report, usage) = check(&oracle, &candidate, &ledger);
        assert!(!report.equal);
        assert!(!usage.is_used(0));
    }

    #[test]
    fn a_stale_ledger_entry_fails_the_run() {
        let ledger = Ledger::parse(&format!(
            "{}{}",
            entry("json/*", "stdout", "json:/summary/rules", "3", "4"),
            entry("json/*", "stdout", "json:/summary/threats", "1", "9"),
        ))
        .expect("valid");
        let candidate = run(0, &DOCUMENT.replace("\"rules\":3", "\"rules\":4"), "");
        let (case, usage) = check(&run(0, DOCUMENT, ""), &candidate, &ledger);
        assert!(case.equal);
        let report = RunReport::new(vec![case], &ledger, &usage);
        assert!(!report.equal, "a stale entry fails the run");
        assert_eq!(report.stale.len(), 1);
        assert_eq!(report.stale[0].entry, 2);
        assert_eq!(report.stale[0].rule, "json:/summary/threats");

        // Once the Rust side matches the oracle again, the first entry is stale too.
        let (case, usage) = check(&run(0, DOCUMENT, ""), &run(0, DOCUMENT, ""), &ledger);
        assert_eq!(RunReport::new(vec![case], &ledger, &usage).stale.len(), 2);
    }

    #[test]
    fn a_ledger_missing_a_field_fails() {
        let complete = entry("*", "stdout", "json:/a", "1", "2");
        assert!(Ledger::parse(&complete).is_ok());
        let without_issue: String = complete
            .lines()
            .filter(|line| !line.starts_with("issue"))
            .collect::<Vec<_>>()
            .join("\n");
        let error = Ledger::parse(&without_issue).expect_err("issue is required");
        assert!(
            error.to_string().contains("missing field `issue`"),
            "{error}"
        );
    }

    #[test]
    fn runs_are_normalised_before_they_are_compared() {
        let oracle = run(0, "{\"repo\":\"/tmp/a/ws\",\"duration_ms\":12}\n", "");
        let candidate = run(0, "{\"repo\":\"/tmp/b/ws\",\"duration_ms\":340}\n", "");
        let mut left = oracle.clone();
        let mut right = candidate.clone();
        Normaliser::new()
            .replace("/tmp/a/ws", "<WS>")
            .run(&mut left);
        Normaliser::new()
            .replace("/tmp/b/ws", "<WS>")
            .run(&mut right);
        let (report, _) = check(&left, &right, &Ledger::default());
        assert!(report.equal, "{report:?}");
        let (report, _) = check(&oracle, &candidate, &Ledger::default());
        assert!(!report.equal);
    }

    #[test]
    fn the_report_serialises() {
        let (report, usage) = check(&run(1, "", ""), &run(2, "", ""), &Ledger::default());
        let text = serde_json::to_string(&RunReport::new(vec![report], &Ledger::default(), &usage))
            .expect("serialises");
        assert!(
            text.starts_with(
                "{\"schema_version\":1,\"equal\":false,\"cases\":[{\"command\":\"info\""
            ),
            "{text}"
        );
        assert!(text.contains("\"kind\":\"exit_code\""), "{text}");
    }
}
