# YARA conformance cases

`cases.json` is written by `scripts/sync_yara_conformance.py`; never hand-edit it. Each case is a rule taken from one of the two engines' own test suites, with its origin (`<project>:<file>[:<line>]`) and the verdict each engine gives it: libyara through `yara-python` 4.5.4 (`ok`, `warning` or `error`), YARA-X through the `yara-x` 1.23.0 wheel (`ok` or `error`), and the first message of each.

| Origin | From | What |
|--------|------|------|
| `yara-x:lib/src/tests/mod.rs:<line>` | [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) at `v1.23.0` (`afe4585b12f56c698794dc80b3d28ddb87b56c0a`) | the first argument of each `condition_true!`, `condition_false!`, `rule_true!`, `rule_false!`, `pattern_true!`, `pattern_false!` and `pattern_match!`, expanded as the macro expands it |
| `yara-x:lib/src/compiler/tests/testdata/{errors,warnings}/<n>.in` | the same | each compiler error and warning input, unchanged (the expected `.out` texts are not copied) |
| `libyara:tests/test-rules.c:<line>` | [VirusTotal/yara](https://github.com/VirusTotal/yara) at `v4.5.4` (`7ff39042be5c63682a037e13a75221d59393cf8b`) | the rule of each `assert_true_rule*`, `assert_false_rule*`, `assert_error` and `assert_warning*` written as a C string literal |

A rule that both suites have is kept once. Copyright The YARA-X Authors and The YARA Authors, both BSD-3-Clause: [`LICENSE-BSD-3-Clause-YARA-X.txt`](LICENSE-BSD-3-Clause-YARA-X.txt), [`LICENSE-BSD-3-Clause-libyara.txt`](LICENSE-BSD-3-Clause-libyara.txt).

Harness: `crates/opentide-yara/tests/conformance.rs`. Differences are the `[[yara]]` entries of `testdata/oracles/exceptions.toml`. `scripts/oracles/yara/oracle.py` checks the recorded verdicts against the live engines in CI.
