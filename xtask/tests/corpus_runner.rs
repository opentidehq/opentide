//! The corpus commands' guards: `generate` writes once, `faults --out`
//! writes its manifest once, `coverage --check` fails on a code no kind
//! produces, and the usage errors.
#![cfg(unix)]

#[cfg(test)]
mod runner {

    use std::path::{Path, PathBuf};
    use xtask::corpus::cli::run;

    const CATALOGUE: &str = r#"
oracle = "0.28.1"
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
            Self { dir }
        }

        fn path(&self, name: &str) -> String {
            self.dir.join(name).to_string_lossy().into_owned()
        }

        fn write(&self, name: &str, text: &str) {
            std::fs::write(self.dir.join(name), text).unwrap();
        }

        fn catalogue(&self, kinds: &str) -> String {
            let text = format!("{CATALOGUE}{kinds}");
            self.write("faults.toml", &text);
            self.path("faults.toml")
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
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

    #[test]
    fn coverage_check_fails_on_a_missing_code() {
        let lab = Lab::new("coverage");
        lab.catalogue(EXPECTS_UUID);
        let codes = |extra: &str| {
            format!(
                "oracle = \"0.28.1\"\nout_of_scope = []\n\n[groups]\nvalidation = [\"invalid_uuid\"{extra}]\n\
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
        lab.write("codes.toml", &codes("").replace("0.28.1", "0.22.0"));
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
        assert!(fails(&["faults"]), "needs --out");
        assert!(fails(&["faults", "--check"]), "retired with the oracle");
        assert!(fails(&["clean"]), "retired with the oracle");
        assert!(fails(&["codes"]), "retired with the oracle");
        assert!(fails(&["coverage", "--bogus"]));
        assert_eq!(run(&["help".to_string()]).unwrap(), 0);
    }
}
