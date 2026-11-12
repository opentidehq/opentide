# Sources

Everything in this directory comes from
[opentidehq/specifications](https://github.com/opentidehq/specifications) at
commit `1dd376319f23a69b354c85aa74f8475d383e04dd` (2026-11-12, exabeam-1.0),
licensed under the Creative Commons Attribution 4.0 International License
(<https://creativecommons.org/licenses/by/4.0/>). Copyright the opentide authors.

| File here | Upstream |
| --- | --- |
| `valid/*.exabeam` | `fixtures/languages/exabeam/valid/`: each clean under the profile its name ends in (`.rule.`, `.search.`) |
| `invalid/<code>.<profile>.exabeam` | `fixtures/languages/exabeam/invalid/`: each reports exactly `<code>` (catalogue warnings aside, below) |
| `highlight/*.exabeam`, `*.tokens.json` | `fixtures/languages/exabeam/highlight/`: the highlight goldens |
| `objects/valid/platform-exabeam.yaml` | `fixtures/platforms/exabeam.yaml` |
| `objects/valid/rule-exabeam-*.yaml` | `fixtures/valid/rule-exabeam-*.yaml` |
| `objects/invalid/rule-exabeam-*.yaml` | `fixtures/invalid/rule-exabeam-*.yaml`; each names its expected code in its first lines |

The files are unchanged. The reference checker (`scripts/exabeam_language.py`)
has no field catalogue, so it never reports `exabeam_unknown_field` or
`exabeam_string_field_number`; the engine does, and the conformance tests
compare the other codes. `crates/opentide-exabeam/src/tests.rs` checks the
language files and `crates/opentide-tide/tests/exabeam_spec.rs` the objects.
