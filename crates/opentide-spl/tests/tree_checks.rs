//! The checks that read the tree (formerly `stages.rs`, `rejects.rs` and
//! `parse_errors.rs`, on the tree-sitter tree), on the analysis of the pure-
//! Rust tree (`syntax::analyze`): the same tests, unchanged.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod stages {
    use opentide_core::{Diagnostic, Severity, codes};
    use opentide_spl::analyze;

    fn with_code(src: &str, code: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == code)
            .collect()
    }

    fn only(src: &str, code: &str) -> Diagnostic {
        let found = with_code(src, code);
        assert_eq!(found.len(), 1, "{src}: {found:?}");
        let all = analyze(src).diagnostics;
        assert!(
            !all.iter().any(|d| d.code == codes::SPL_PARSE_ERROR),
            "{src}: {all:?}"
        );
        found.into_iter().next().unwrap()
    }

    #[test]
    fn no_op_commands_warn() {
        for (src, name) in [
            ("index=a | where", "where"),
            ("index=a | search", "search"),
            ("index=a | fields", "fields"),
            ("index=a | fields -", "fields"),
            ("index=a | eventstats", "eventstats"),
            ("index=a | streamstats", "streamstats"),
            ("index=a | sistats", "sistats"),
            ("index=a | lookup", "lookup"),
            ("index=a | where | stats count", "where"),
            ("index=a [search b | where] | stats count", "where"),
        ] {
            let d = only(src, codes::SPL_EMPTY_COMMAND);
            assert_eq!(d.severity, Severity::Warning, "{src}");
            assert!(
                d.message
                    .starts_with(&format!("`{name}` with no arguments")),
                "{d:?}"
            );
        }
    }

    #[test]
    fn empty_stats_and_inputlookup_are_errors() {
        let d = only("index=a | stats", codes::SPL_EMPTY_COMMAND);
        assert_eq!(d.severity, Severity::Error);
        assert!(d.message.contains("returns no results"), "{d:?}");
        for src in ["| inputlookup", "index=a [| inputlookup]"] {
            let d = only(src, codes::SPL_EMPTY_COMMAND);
            assert_eq!(d.severity, Severity::Error, "{src}");
            assert!(d.message.contains("lookup table"), "{d:?}");
        }
    }

    #[test]
    fn commands_with_defaults_or_arguments_are_not_empty() {
        for src in [
            "index=a | head",
            "index=a | spath",
            "index=a | fillnull",
            "index=a | tojson",
            "index=a | geostats latfield=lat longfield=lon",
            "index=a | where x=1 | search b | fields a | stats count | lookup t a",
            "| inputlookup t.csv",
            "search a",
        ] {
            assert!(with_code(src, codes::SPL_EMPTY_COMMAND).is_empty(), "{src}");
        }
    }

    #[test]
    fn syntax_errors_are_not_empty_commands() {
        for src in [
            "index=a | where (x=1",
            "index=a | lookup local=t",
            "| makeresults | inputlookup",
        ] {
            assert!(with_code(src, codes::SPL_EMPTY_COMMAND).is_empty(), "{src}");
            assert!(!with_code(src, codes::SPL_PARSE_ERROR).is_empty(), "{src}");
        }
    }

    #[test]
    fn trailing_pipe_warns_and_an_empty_middle_stage_is_an_error() {
        let d = only("index=a | stats count |", codes::SPL_EMPTY_STAGE);
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!((d.range.start.character, d.range.end.character), (22, 23));
        let d = only("search |", codes::SPL_EMPTY_STAGE);
        assert_eq!(d.severity, Severity::Warning);
        assert!(!with_code("index=a | | stats count", codes::SPL_PARSE_ERROR).is_empty());
        assert!(with_code("index=a | | stats count", codes::SPL_EMPTY_STAGE).is_empty());
        // Splunk rejects an empty last stage in a subsearch.
        assert!(!with_code("index=a [search b |]", codes::SPL_PARSE_ERROR).is_empty());
        assert!(with_code("index=a | stats count", codes::SPL_EMPTY_STAGE).is_empty());
    }

    #[test]
    fn command_word_without_pipe_is_an_error_with_a_fix() {
        let src = "tstats count where index=a by sourcetype";
        let d = only(src, codes::SPL_COMMAND_WITHOUT_PIPE);
        assert_eq!(d.severity, Severity::Error);
        assert_eq!((d.range.start.character, d.range.end.character), (0, 6));
        assert_eq!(d.suggestion.as_deref(), Some("| tstats"));
        assert!(d.message.contains("`tstats`"), "{d:?}");
        assert!(with_code(src, codes::SPL_UNKNOWN_COMMAND).is_empty());
        for src in [
            "stats count by host",
            "```note```\nlookup t.csv a OUTPUT b",
            "TSTATS count where index=a",
        ] {
            only(src, codes::SPL_COMMAND_WITHOUT_PIPE);
        }
    }

    #[test]
    fn searches_that_look_for_words_are_not_commands_without_pipe() {
        for src in [
            "index=a",
            "search foo",
            "search foo bar baz",
            "error",
            "tstats",
            "delete user",
            "error code failed",
            "index=a tstats count where x",
            "| tstats count where index=a by sourcetype",
            "`m` stats count by x",
        ] {
            assert!(
                with_code(src, codes::SPL_COMMAND_WITHOUT_PIPE).is_empty(),
                "{src}: {:?}",
                analyze(src).diagnostics
            );
            assert!(with_code(src, codes::SPL_PARSE_ERROR).is_empty(), "{src}");
        }
    }
}

mod rejects {
    use opentide_core::codes;
    use opentide_spl::analyze;

    fn parse_errors(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_PARSE_ERROR)
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn loose_comparisons_are_syntax_errors_in_tstats_where_only() {
        for op in ["==", "<>", "=>", "=<", "!~"] {
            for src in [
                format!("| tstats count where index=a sourcetype{op}b by host"),
                format!("| tstats count where index=a sourcetype {op} b by host"),
            ] {
                let errors = parse_errors(&src);
                assert_eq!(errors.len(), 1, "{src}: {errors:?}");
                assert!(errors[0].contains(&format!("'{op}'")), "{errors:?}");
            }
            for src in [
                format!("index=a status{op}200"),
                format!("index=a status {op} 200"),
                format!("index=a NOT status{op}\"200\""),
                format!("index=a | search status{op}200"),
                format!("index=a [search status{op}200 | fields status]"),
                format!("| inputlookup t.csv where status{op}200"),
                format!("| tstats count where index=a [search x{op}1 | fields x] by host"),
            ] {
                assert!(
                    parse_errors(&src).is_empty(),
                    "{src}: {:?}",
                    parse_errors(&src)
                );
            }
        }
        // `=~` is `=` with the value `~b`; tstats takes it.
        assert!(parse_errors("| tstats count where index=a sourcetype=~b by host").is_empty());
    }

    #[test]
    fn geostats_needs_an_aggregate_before_by() {
        for src in [
            "index=a | geostats by x",
            "| geostats latfield=lat longfield=lon BY x",
        ] {
            let errors = parse_errors(src);
            assert_eq!(errors.len(), 1, "{src}: {errors:?}");
            assert!(errors[0].contains("geostats"), "{errors:?}");
        }
        for src in [
            "index=a | geostats count by x",
            "| geostats latfield=lat longfield=lon",
            "index=a | stats by x",
        ] {
            assert!(parse_errors(src).is_empty(), "{src}");
        }
    }
}

mod parse_errors {
    use opentide_core::{Diagnostic, Position, codes};
    use opentide_spl::analyze;

    fn parse_errors(src: &str) -> Vec<Diagnostic> {
        analyze(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.code == codes::SPL_PARSE_ERROR)
            .collect()
    }

    fn only_error(src: &str) -> Diagnostic {
        let errors = parse_errors(src);
        assert_eq!(errors.len(), 1, "{src}: {errors:?}");
        errors.into_iter().next().unwrap()
    }

    /// Line and column of the first occurrence of `needle` at or after `from`.
    fn at(src: &str, needle: &str, from: usize) -> Position {
        let offset = from + src[from..].find(needle).expect(needle);
        opentide_core::offset_to_position(src, offset)
    }

    #[test]
    fn stray_token_mid_pipeline_points_at_the_token() {
        let src = "index=a | stats count by host ) | head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, ")", 0), "{d:?}");
        assert_eq!(d.range.end.character, d.range.start.character + 1);
        // The parenthesis pass names the cause (#135).
        assert!(
            d.message.contains("unbalanced parentheses"),
            "{}",
            d.message
        );
    }

    #[test]
    fn unclosed_paren_points_at_the_paren() {
        let src = "index=a\n| stats count by host\n| where x=(1\n| head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, "(", 0), "{d:?}");
        assert_eq!(d.range.start.line, 2);
        assert!(d.message.contains("'(' is never closed"), "{}", d.message);
    }

    #[test]
    fn unclosed_subsearch_points_at_the_bracket() {
        let src = "index=a | join host [ search index=b | head 1";
        let d = only_error(src);
        assert_eq!(d.range.start, at(src, "[", 0), "{d:?}");
        assert!(d.message.contains("'[' is never closed"), "{}", d.message);
    }

    #[test]
    fn eval_concatenation_error_is_on_its_line() {
        // `.` with nothing after it is not concatenation.
        let src = "index=a\n| stats count\n| eval k=a..b";
        let errors = parse_errors(src);
        assert!(!errors.is_empty(), "{errors:?}");
        let d = &errors[0];
        assert_eq!(d.range.start.line, 2, "{d:?}");
        assert!(d.range.start.character > 0, "{d:?}");
        let start = d.range.start.character as usize;
        let line = src.lines().nth(2).unwrap();
        assert_eq!(&line[start..=start], ".", "{d:?}");
    }

    #[test]
    fn recovery_around_valid_text_still_finds_the_bad_token() {
        // The error is the stray `=`, not the start of the query that
        // recovery wraps.
        let src = "index=a | stats count by host , , = | head 1";
        let d = &parse_errors(src)[0];
        assert_eq!(d.range.start, at(src, "=", 8), "{d:?}");
    }

    #[test]
    fn one_diagnostic_per_region_and_capped() {
        let two = "index=a | stats count ) | head 1 | eval x=1 = = 2";
        assert_eq!(parse_errors(two).len(), 2, "{:?}", parse_errors(two));
        let many = (0..20)
            .map(|_| "| eval x=1 = = 2")
            .collect::<Vec<_>>()
            .join(" ");
        let src = format!("index=a {many}");
        let errors = parse_errors(&src);
        assert_eq!(errors.len(), 5, "{errors:?}");
    }

    #[test]
    fn valid_query_has_no_parse_error() {
        assert!(parse_errors("index=a | stats count by host | head 1").is_empty());
    }
}
