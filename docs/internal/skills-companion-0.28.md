---
title: Skills companion for the 0.28 catch-up
description: The change opentidehq/skills needs for the thirteen platforms of the 0.28 catch-up, drafted here for the maintainer to apply.
---

# Skills companion for the 0.28 catch-up

The [definition of done](https://github.com/opentidehq/opentide/blob/development/AGENTS.md#definition-of-done) (item 5) asks for a companion pull request on [opentidehq/skills](https://github.com/opentidehq/skills) when a platform is added or its capabilities change. The 0.28 catch-up (epic [#790](https://github.com/opentidehq/opentide/issues/790)) adds four platforms and changes what two others can do. The sessions that ported it cannot reach that repository, so this page is the draft. A maintainer applies it there, following its [process](https://github.com/opentidehq/skills/blob/main/AGENTS.md#keeping-skills-in-step-with-opentide), and links the pull request from the one that adds this page.

The capabilities below come from the registry, `crates/opentide-schema/src/platforms.rs` (`PLATFORMS`), the same table `opentide info --json` prints (`can_deploy`, `can_validate`, `can_query`). The root [`AGENTS.md`](https://github.com/opentidehq/opentide/blob/development/AGENTS.md#platforms) has the whole matrix.

## Platform skills to add

The catalogue's recorded manifest (`tests/cassettes/skills/manifest.json`) has no skill for these four. Check the live `manifest.json` first: add each skill that is still missing, and give it a `coverage.json` entry.

| Platform (`--platform`) | Rule block | Deploy | `validate query --live` | Offline check | `opentide query` |
|---|---|:-:|:-:|---|---|
| Bitdefender GravityZone (`bitdefender`) | `platform::bitdefender::1.0`: Basic `detection` (a target and its criteria from GravityZone's catalogue) or a `yara` signature; severity, tags, targets, automatic actions | yes | no (`supported: false`) | YARA, Bitdefender profile (`.yar`, `.yara`) | no |
| Graylog (`graylog`) | `platform::graylog::1.0`: an event definition (Graylog 6.3 to 7.2) | yes | yes | no: tenant only | Lucene (Graylog dialect) |
| Exabeam New-Scale SIEM (`exabeam`) | `platform::exabeam::1.0`: a correlation rule of sequences | yes | yes (each sequence's filter, through Search) | no: tenant only | Exabeam Query Language |
| Google Security Operations (`google_secops`) | `platform::google_secops::1.0`: a YARA-L 2.0 rule in sections (`events`, `match`, `outcome`, `condition`, ...) | yes | yes (`verifyRuleText`) | YARA-L 2.0 (`.yaral`, `.yl2`) | YARA-L 2.0 (`udmSearch`) |

What each skill should teach the agent, beyond the block's fields:

- **Bitdefender:** a block sets exactly one of `detection` and `yara`. Criteria fields, relations (`is`, `contains`, `any`) and values come from GravityZone's catalogue. A `contains` value matches as written unless it has `*` or `?`. GravityZone has three severities, so `Critical` and `Informational` collapse. `kill_process` is not allowed on a YARA rule. The signature is ASCII only and at most 30,000 characters, with no `include`. The `bitdefender_*` and `yara_*` codes (`opentide explain <code>`) name each constraint. Check with `opentide validate` and `opentide validate query --platform bitdefender`; `--live` reports `supported: false`.
- **Graylog:** the query is Lucene in Graylog's dialect, checked on the tenant only: `opentide validate query --platform graylog --live`. The `graylog_*` codes cover the schedule, aggregation, event fields and priority.
- **Exabeam:** sequences, thresholds and correlation windows. The tenant checks each sequence's filter; the condition and windows are checked by `opentide validate` only (`exabeam_*` codes).
- **Google SecOps:** YARA-L 2.0 sections assembled into one rule, checked offline by `opentide validate` and `validate query`, and on the tenant by `--live`. A section written as a YAML alias is `yaral_section_alias`; two rules sharing a name is `google_secops_name_duplicate`.

## Platform skills to update

- **`harfanglab`:** its YARA is checked offline now, as libyara 4.5 compiles it under the HarfangLab profile: `yara.signature`, the rule the decomposed form (`strings`, `condition`, `imports`, `meta`) assembles, and `.yar`/`.yara` files, with `opentide validate query --platform harfanglab`. `--live` reports `supported: false`; the skill must no longer call HarfangLab "deploy-only" or say its YARA cannot be checked. A `signature` written as a YAML alias is `yara_signature_alias`.
- **`crowdstrike-falcon`:** a Next-Gen SIEM correlation rule's `query` is CrowdStrike Query Language (CQL), checked offline (`cql_*` codes) by `opentide validate` and `validate query --platform crowdstrike`. `--live` reports `supported: false`, and `opentide query --platform crowdstrike` runs it on a tenant.
- **Elastic and Sysdig**, if the catalogue has skills for them: Elastic's four languages (ES|QL, EQL, Kibana KQL, Lucene) are checked offline and on the tenant. Sysdig's Falco conditions are checked offline only, and Sysdig runs no `opentide query`.

## `coverage.json`

One entry per platform above, with the capabilities of the matrix. A platform whose capabilities changed (`harfanglab`, `crowdstrike`) gets its entry corrected. Match the file's existing schema; the values to set are the four columns of the table above and of [`AGENTS.md`](https://github.com/opentidehq/opentide/blob/development/AGENTS.md#platforms): deploy, tenant check, offline check (with its language) and `opentide query`.
