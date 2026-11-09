//! The corpus runner's pass/fail guards, driven through a fake oracle: a
//! shell script that prints `opentide 0.23.0` for `--version` and canned
//! JSON documents otherwise (the clean base's from `base-<command>.json`,
//! every other workspace's from `kind-<command>.json`). Each test fails if
//! its guard in `xtask/src/corpus/cli.rs` is removed.
#![cfg(unix)]

#[cfg(test)]
mod runner {

    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use xtask::corpus::cli::run;
    use xtask::corpus::faults::Catalogue;
    use xtask::corpus::generate::generate;
    use xtask::corpus::workspace::Family;

    const SCRIPT: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "opentide 0.23.0"; exit 0; fi
dir=$(dirname "$0")
case "$3" in
  */_base) cat "$dir/base-$4.json" ;;
  *) cat "$dir/kind-$4.json" ;;
esac
"#;

    const CATALOGUE: &str = r#"
oracle = "0.23.0"
[base]
seed = 1
threats = 6
objectives = 6
rules = 36
layout = "explicit"
"#;

    struct Lab {
        dir: PathBuf,
    }

    impl Lab {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("xtask-corpus-runner-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let script = dir.join("opentide");
            std::fs::write(&script, SCRIPT).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn oracle(&self) -> String {
            self.dir.join("opentide").to_string_lossy().into_owned()
        }

        fn path(&self, name: &str) -> String {
            self.dir.join(name).to_string_lossy().into_owned()
        }

        fn write(&self, name: &str, text: &str) {
            std::fs::write(self.dir.join(name), text).unwrap();
        }

        /// The document the fake prints for `command`, on the base or on a kind.
        fn answer(
            &self,
            which: &str,
            command: &str,
            codes: &[&str],
            objects: usize,
            failure: bool,
        ) {
            let issues: Vec<serde_json::Value> = codes
            .iter()
            .map(|c| serde_json::json!({"code": c, "severity": "error", "path": "objects/rules/x.yaml", "message": c}))
            .collect();
            let failure = if failure {
                serde_json::json!({"code": "command_failed"})
            } else {
                serde_json::Value::Null
            };
            let document = serde_json::json!({
                "report": {"issues": issues, "warnings": []},
                "summary": {"objects": objects, "files": objects},
                "failure": failure,
            });
            self.write(&format!("{which}-{command}.json"), &document.to_string());
        }

        fn catalogue(&self, kinds: &str) -> String {
            let text = format!("{CATALOGUE}{kinds}");
            self.write("faults.toml", &text);
            self.path("faults.toml")
        }

        fn faults(&self, kinds: &str) -> anyhow::Result<u8> {
            let catalogue = self.catalogue(kinds);
            let args = [
                "faults",
                "--check",
                "--engine",
                "python",
                "--oracle",
                &self.oracle(),
                "--catalogue",
                &catalogue,
                "--jobs",
                "1",
                "--keep",
                &self.path("scratch"),
            ];
            run(&args.map(str::to_string))
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The base's object files, which a whole `validate` must have checked.
    fn base_objects() -> usize {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        generate(&catalogue.base.options().unwrap())
            .files
            .iter()
            .filter(|f| matches!(f.family, Family::Threat | Family::Objective | Family::Rule))
            .count()
    }

    const EXPECTS_UUID: &str = r#"
[[kind]]
id = "expects-uuid"
codes = ["invalid_uuid"]
severity = "error"
target = { family = "rule" }
per_target = false
ops = [{ op = "set", path = "metadata.uuid", value = "bad-{n}" }]
"#;

    const SILENT: &str = r#"
[[kind]]
id = "silent"
codes = []
severity = "error"
target = { family = "rule" }
gap = "KG-00"
ops = [{ op = "set", path = "status", value = "NOPE" }]
"#;

    #[test]
    fn a_kind_whose_codes_differ_fails_the_run() {
        let lab = Lab::new("mismatch");
        let n = base_objects();
        lab.answer("base", "validate", &[], n, false);
        lab.answer("kind", "validate", &["invalid_uuid"], n, false);
        assert_eq!(lab.faults(EXPECTS_UUID).unwrap(), 0, "the control passes");
        let lab = Lab::new("mismatch2");
        lab.answer("base", "validate", &[], n, false);
        lab.answer("kind", "validate", &["schema_validation"], n, false);
        assert_eq!(lab.faults(EXPECTS_UUID).unwrap(), 1);
    }

    #[test]
    fn a_base_with_a_finding_is_an_error() {
        let lab = Lab::new("dirty-base");
        let n = base_objects();
        lab.answer("base", "validate", &["vocab_unknown"], n, false);
        lab.answer("kind", "validate", &["invalid_uuid"], n, false);
        let error = lab.faults(EXPECTS_UUID).unwrap_err();
        assert!(format!("{error:#}").contains("clean base"), "{error:#}");
    }

    #[test]
    fn a_silent_kind_must_have_checked_everything() {
        let n = base_objects();
        let lab = Lab::new("silent-ok");
        lab.answer("base", "validate", &[], n, false);
        lab.answer("kind", "validate", &[], n, false);
        assert_eq!(lab.faults(SILENT).unwrap(), 0, "the control passes");
        let lab = Lab::new("silent-failed");
        lab.answer("base", "validate", &[], n, false);
        lab.answer("kind", "validate", &[], n, true);
        assert_eq!(lab.faults(SILENT).unwrap(), 2, "a failed run is no silence");
        let lab = Lab::new("silent-short");
        lab.answer("base", "validate", &[], n, false);
        lab.answer("kind", "validate", &[], n - 1, false);
        assert_eq!(
            lab.faults(SILENT).unwrap(),
            2,
            "an object left unchecked is no silence"
        );
    }

    #[test]
    fn clean_fails_on_a_finding_and_on_nothing_checked() {
        let clean = |lab: &Lab| {
            let args = [
                "clean",
                "--engine",
                "python",
                "--oracle",
                &lab.oracle(),
                "--repo",
                &lab.path("repo"),
            ];
            run(&args.map(str::to_string)).unwrap()
        };
        let lab = Lab::new("clean");
        lab.answer("kind", "validate", &[], 10, false);
        lab.answer("kind", "lint", &[], 10, false);
        assert_eq!(clean(&lab), 0, "the control passes");
        lab.answer("kind", "lint", &["placeholder"], 10, false);
        assert_eq!(clean(&lab), 1);
        lab.answer("kind", "lint", &[], 0, false);
        assert_eq!(clean(&lab), 1);
    }

    #[test]
    fn coverage_check_fails_on_a_missing_code() {
        let lab = Lab::new("coverage");
        lab.catalogue(EXPECTS_UUID);
        let codes = |extra: &str| {
            format!(
                "oracle = \"0.23.0\"\nout_of_scope = []\n\n[groups]\nvalidation = [\"invalid_uuid\"{extra}]\n\
             lint = []\nconfiguration = []\nquery = []\ncompile = []\n"
            )
        };
        let coverage = |mode: &str| {
            let args = ["coverage", mode, "--dir", &lab.path("")];
            run(&args.map(str::to_string)).unwrap()
        };
        lab.write("codes.toml", &codes(""));
        assert_eq!(coverage("--write"), 0);
        assert_eq!(coverage("--check"), 0, "the control passes");
        lab.write("codes.toml", &codes(", \"yaml_parse\""));
        assert_eq!(coverage("--write"), 1, "yaml_parse has no kind");
        assert_eq!(coverage("--check"), 1);
        assert!(Path::new(&lab.path("COVERAGE.md")).exists());
        // A problem fails it too: codes recorded from another oracle.
        lab.write("codes.toml", &codes("").replace("0.23.0", "0.22.0"));
        assert_eq!(coverage("--write"), 1, "codes.toml is from another oracle");
        assert_eq!(coverage("--check"), 1);
    }

    #[test]
    fn generate_writes_once_and_faults_out_writes_the_manifest() {
        let lab = Lab::new("generate");
        let out = lab.path("ws");
        let args = [
            "generate",
            "--seed",
            "3",
            "--threats",
            "4",
            "--objectives",
            "4",
            "--rules",
            "9",
            "--out",
            &out,
        ];
        assert_eq!(run(&args.map(str::to_string)).unwrap(), 0);
        assert!(
            Path::new(&out)
                .join(".opentide/configurations/paths.toml")
                .exists()
        );
        let again = run(&args.map(str::to_string)).unwrap_err();
        assert!(format!("{again:#}").contains("not empty"), "{again:#}");
        let catalogue = lab.catalogue(EXPECTS_UUID);
        let faults = lab.path("faults");
        let args = ["faults", "--out", &faults, "--catalogue", &catalogue];
        assert_eq!(run(&args.map(str::to_string)).unwrap(), 0);
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(lab.path("faults.faults.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["kinds"][0]["id"], "expects-uuid");
        assert_eq!(manifest["kinds"][0]["files"].as_array().unwrap().len(), 1);
        assert!(
            run(&args.map(str::to_string)).is_err(),
            "the manifest is never overwritten"
        );
    }

    #[test]
    fn usage_errors() {
        let fails = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
            run(&args).is_err()
        };
        assert!(fails(&[]));
        assert!(fails(&["nope"]));
        assert!(fails(&["generate", "--seed", "x"]));
        assert!(fails(&["generate", "--seed", "1", "--scale", "0"]));
        assert!(fails(&["generate", "--seed", "1", "--rules", "-1"]));
        assert!(
            fails(&["generate", "--seed", "1"]),
            "no --out and no --digest"
        );
        assert!(fails(&["generate", "--seed"]), "a flag without its value");
        assert!(fails(&["faults"]), "needs --check or --out");
        assert!(fails(&["faults", "--check", "--engine", "perl"]));
        assert!(fails(&[
            "faults",
            "--check",
            "--engine",
            "python",
            "--only",
            "no-such-kind",
            "--oracle",
            "/nonexistent/opentide"
        ]));
        assert!(fails(&["clean", "--engine", "python"]), "no --repo");
        assert!(fails(&["codes", "--bogus"]));
        assert!(fails(&["coverage", "--bogus"]));
        // The Rust engine checks the structural kinds against the oracle
        // (UC-1.2): without one it cannot run; any other kind is refused.
        assert!(fails(&[
            "faults",
            "--check",
            "--engine",
            "rust",
            "--oracle",
            "/nonexistent/opentide"
        ]));
        assert!(fails(&[
            "faults",
            "--check",
            "--engine",
            "rust",
            "--only",
            "uuid-invalid-rule"
        ]));
        // The configuration kinds (UC-1.5) need the oracle too.
        assert!(fails(&[
            "faults",
            "--check",
            "--engine",
            "rust",
            "--only",
            "configuration",
            "--oracle",
            "/nonexistent/opentide"
        ]));
        let args = ["clean", "--engine", "rust", "--repo", "."].map(str::to_string);
        assert_eq!(run(&args).unwrap(), 1, "clean has no Rust run: it fails");
        assert_eq!(run(&["help".to_string()]).unwrap(), 0);
    }

    #[test]
    fn a_wrong_oracle_version_is_refused() {
        let lab = Lab::new("version");
        std::fs::write(
            lab.dir.join("opentide"),
            "#!/bin/sh\necho \"opentide 0.22.0\"\n",
        )
        .unwrap();
        let args = [
            "clean",
            "--engine",
            "python",
            "--oracle",
            &lab.oracle(),
            "--repo",
            &lab.path("repo"),
        ];
        let error = run(&args.map(str::to_string)).unwrap_err();
        assert!(
            format!("{error:#}").contains("not opentide 0.23.0"),
            "{error:#}"
        );
    }
}
