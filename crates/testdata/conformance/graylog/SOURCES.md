# Sources

Everything in this directory comes from
[opentidehq/specifications](https://github.com/opentidehq/specifications) at
commit `7c9dcba6351c39401057510a60c25512220266f2` (2026-11-11, graylog-1.0 1.0), licensed under
the Creative Commons Attribution 4.0 International License
(<https://creativecommons.org/licenses/by/4.0/>). Copyright the opentide authors.

| File here | Upstream |
| --- | --- |
| `valid/platform-graylog.yaml` | `fixtures/platforms/graylog.yaml` |
| `valid/rule-graylog-*.yaml` | `fixtures/valid/rule-graylog-*.yaml` |
| `invalid/rule-graylog-*.yaml` | `fixtures/invalid/rule-graylog-*.yaml`; each names its expected code in its first line |

`crates/opentide-tide/tests/graylog_spec.rs` checks them.
