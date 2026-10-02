---
title: opentide rules
description: Detection rule maintenance — list rules with no review date, or a review older than a window.
---

# opentide rules

Maintenance commands for detection rules. `unreviewed` is a read. It does not validate, deploy, or write `metadata.reviewed`.

```bash
opentide rules unreviewed
opentide rules unreviewed --older-than 90d
opentide --json rules unreviewed --older-than 12h
```

## `rules unreviewed`

A rule is listed when any of the following is true, evaluated at the current time `T` against the window `W`:

| Condition | `reason` |
|-----------|----------|
| `metadata.schema` is `rule::1.0` | `schema` |
| `metadata.schema` is `rule::1.1` and `metadata.reviewed` is absent | `absent` |
| `metadata.schema` is `rule::1.1` and `reviewed` is strictly earlier than `T − W` | `stale` |

A review instant equal to `T − W` is not listed. Date-only values are `00:00:00Z` on that date. The default window is `90d`. `--older-than` also accepts `12h`, `30m`, or a bare positive day count.

The command walks `objects/rules/**/*.{yaml,yml}`. Exit code is 0 when the window parses, including when rules are listed. A non-positive or unrecognised window exits non-zero.

JSON includes `evaluated_at`, `window`, `count`, and `rules` (`path`, `schema`, `reason`, `reviewed`).

Set `metadata.reviewed` on a `rule::1.1` document when a person reviews the rule. `opentide validate`, `deploy`, `share`, and `generate templates` do not fill the field. `rule::1.0` cannot carry it; move the rule to `schema: rule::1.1` first. See [Schema revision](../usage/concepts/schema-revision.md).
