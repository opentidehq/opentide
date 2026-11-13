---
title: opentide migrate
description: Rewrite objects authored for an earlier opentide model so they validate under the current one.
---

# opentide migrate

Rewrites objects that an earlier opentide release accepted into the form the current one validates. Each subcommand is a dry run unless you pass `--apply`.

```bash
opentide migrate vocab-scope            # report what would change (default)
opentide migrate vocab-scope --apply    # rewrite the objects
```

For vendor rule ids that 0.14 and earlier kept on rules, see [`deploy migrate-state`](./deploy.md#deploy-migrate-state).

## migrate vocab-scope

Re-prefixes the values of stage-scoped vocabulary fields: `Process` becomes `Host::Process`. Since 0.14.0, `threat.surface` and `objective.signals[].entities` author `<stage>::<key>`, so an object written before then stops validating until its values carry the stage.

It applies only mechanical outcomes:

- a key defined under exactly one stage takes that stage;
- a stage whose casing drifted (`host::Process`) takes the vocabulary's casing.

A key defined under several stages (`Account` is both `Host::Account` and `Cloud::Account`) is reported with its candidates and left untouched: choose the stage by hand, then run the command again.

Values are found by their path through the document, never by key name, so a Sentinel block's own `entities` key is never touched. Each value is replaced over the exact characters its scalar occupies, so comments, block scalars, quoting, key order and line endings survive. Every rewritten file is parsed again and compared with the intended result; a file that does not match is left unchanged and reported.

### Flags

| Flag | Purpose |
|------|---------|
| `--apply` | Rewrite the objects (default: dry run) |
| `--field <name>` | Limit to one scoped field (`surface`, `entities`); repeatable. Default: every scoped field |
| `--force` | Exit `0` even when values need a human decision |

### Exit codes

| Code | When |
|------|------|
| `0` | Nothing left to do, or `--force` |
| `1` | A file could not be rewritten safely and was left unchanged, or `--field` names no scoped field |
| `2` | Values are defined under several stages and need a person to choose (`failure.code` `needs_human_decision`) |

## Source

`crates/opentide-cli/src/commands/migrate.rs`
