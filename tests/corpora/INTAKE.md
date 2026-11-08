# Real-world intake

How a shared repository of detection objects joins the corpora (plan §5.3, "real-world corpora the
team can share"). Generated workspaces find what we thought of; real repositories find what users
write. A real-world corpus is never vendored blindly: it passes the three gates below, and it is
recorded by reference (repository, commit, licence), not copied, unless its licence and size allow
a copy and the copy adds something a reference cannot.

## Gates

1. **Licence.** The repository's licence must allow us to run it in CI and, if we copy it, to
   redistribute it under its terms. Accepted: EUPL-1.2, Apache-2.0, MIT, BSD, CC-BY-4.0,
   CC-BY-SA-4.0 (keep the attribution and the share-alike terms with any copy). A repository
   without a licence is not usable, whatever its visibility, until its owner adds one or grants
   written permission (record the permission in the entry).
2. **Anonymisation.** Before anything is copied or recorded beyond a reference, check and strip:
   - secrets and credentials: tenant `setup` values that are not `$VARIABLE` references, API keys,
     tokens, webhook URLs (run `gitleaks detect --no-git --source <dir>`, or the repository's own
     secret scan, and read every hit);
   - internal identifiers: hostnames, IP ranges, tenant, subscription, workspace and organisation
     IDs, e-mail addresses, people's names in `author` and `contributors` (replace with
     `Corpus Contributor`), internal wiki links (replace the host with `wiki.example.internal`);
   - customer or incident detail in descriptions, sightings and hunt queries.
   An object that cannot be anonymised without losing what makes it interesting stays out. Never
   commit a secret, even a revoked one, and never paste one into a PR, an issue or a log.
3. **Size.** A reference has no size limit (CI clones it at the recorded commit). A copy under
   `tests/corpora/real/<name>/` stays below 5 MB and 2,000 files; larger corpora are references.

## Recording a corpus

Add an entry to the table below with: repository, commit, licence, what it holds (object counts and
model revisions), how to materialise it, and what the oracle reports on it (`opentide --json --repo
DIR validate` and `lint` summaries at that commit). Those results are the corpus's golden: a change
in what the oracle or the engine reports on it is reviewed like any other golden difference.

```bash
git clone --depth 1 <url> /tmp/real/<name> && git -C /tmp/real/<name> checkout <commit>
opentide --json --repo /tmp/real/<name> validate > /tmp/real/<name>.validate.json
opentide --json --repo /tmp/real/<name> lint > /tmp/real/<name>.lint.json
```

Run the oracle on untrusted content only as a validator (it reads YAML and TOML); never run a
repository's own scripts, hooks or CI.

## Public repositories the team can use

Checked on 2026-11-08 with opentide 0.23.0 as the oracle.

| Repository | Commit | Licence | Content | Use | Oracle at that commit |
|------------|--------|---------|---------|-----|-----------------------|
| [opentidehq/library](https://github.com/opentidehq/library) | `60f744b71b1008d1da504e6120c121caf5add847` | CC-BY-SA-4.0 | The public registry of published detection objects: 267 YAML files under `objects/` (threats, objectives, rules) | Reference; a copy keeps the attribution and CC-BY-SA terms | `validate`: 265 objects, 17 queries, 0 errors, 11 `platform_not_enabled` warnings (no platform configured); `lint`: 265 `metadata_recommended` (info), 5 `kql_unknown_table` (warning) |
| [opentidehq/specifications](https://github.com/opentidehq/specifications) | `1b320847f2cbe205eaee3db2c3000ed8d7d810e9` | CC-BY-4.0 | The normative specs' fixtures: valid, invalid, per-platform, cross-object and deployment objects (59 YAML files) | Reference; its `fixtures/invalid` are ready-made faults with expected outcomes | Not a workspace (0 objects found): its fixtures are copied into a generated workspace one by one |
| [adanalvarez/OpenTideTest](https://github.com/adanalvarez/OpenTideTest) | `4fe679dddb1d64f1a62cb7c2fa1fd3aee3c3dbe0` | EUPL-1.2 | A third-party workspace in the legacy layout (`Objects/`, `Configurations/`; 15 YAML files) | Reference; a real migration input for `opentide migrate` | 0 objects found until migrated: the legacy layout is not read by 0.23.0 |

Not usable as they stand: repositories without a licence (for example the public Hack.lu 2026
workshop repository `remg427/Hacklu2026_ws`), and private ones (`supertide/app`), until their
owners grant it in writing.
