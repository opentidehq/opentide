# Sources

Everything in this directory comes from
[opentidehq/specifications](https://github.com/opentidehq/specifications) at
commit `a6378a8787a19a47ee05cc2eb3987c75961d6237` (2026-11-10), licensed under
the Creative Commons Attribution 4.0 International License
(<https://creativecommons.org/licenses/by/4.0/>). Copyright the opentide authors.

| File here | Upstream |
| --- | --- |
| `spec-tables.md` | two sections of `specs/platforms/bitdefender-1.0.md`, unchanged |
| `valid/platform-bitdefender.yaml` | `fixtures/platforms/bitdefender.yaml` |
| `valid/rule-bitdefender-*.yaml` | `fixtures/valid/rule-bitdefender-*.yaml` |
| `invalid/rule-bitdefender-*.yaml` | `fixtures/invalid/rule-bitdefender-*.yaml`; each names its expected code in its first lines |

`crates/opentide-tide/tests/bitdefender_spec.rs` checks them.
