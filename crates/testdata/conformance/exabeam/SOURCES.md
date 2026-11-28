# Sources

Everything in this directory comes from
[opentidehq/specifications](https://github.com/opentidehq/specifications) at
commit `f400f15751b9698f2d7f89ee5b1b67dc545e345d` (2026-11-13, language-exabeam 1.1),
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
has no field catalogue, so it never reports `exabeam_unknown_field`,
`exabeam_string_field_number` or `exabeam_unknown_value`; the engine does, and
the conformance tests compare the other codes. `crates/opentide-exabeam/src/tests.rs` checks the language files and
`crates/opentide-tide/tests/exabeam_spec.rs` the objects.
