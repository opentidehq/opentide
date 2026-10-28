---
title: Troubleshooting
description: Common opentide failures — validation errors, generation drift, platform loading, and deployment — with fixes.
---

# Troubleshooting

The failures you are most likely to hit, why they happen, and how to fix them. If your problem is a genuine bug, open an issue on [opentide](https://github.com/opentidehq/opentide/issues).

Start with `opentide doctor`. It checks the installation, the workspace, git, the generated templates and schemas, enabled platforms and their SDKs, tenant credentials (set or unset, never printed), the proxy, editor settings and MCP configuration, and prints the command that fixes each problem it finds. See [`opentide doctor`](../cli/doctor.md).

```bash
opentide doctor
opentide --json doctor --offline
```

## Unexpected errors

### opentide stops with `error[internal]`

An `error[internal]: <Type>: <message>` line is an exception opentide did not handle: a bug, not a mistake in your input. The run exits `1`. On stderr, under the error, opentide prints the path of a crash log and a link that opens a GitHub issue pre-filled with the opentide version, Python version, operating system and the command's name (never its arguments or any path). Under `--json` stdout still carries one document, with `failure.code` `internal` and `failure.crash_log`. Under `opentide mcp start` nothing is written to stdout.

```text illustrative
error[internal]: RuntimeError: index exploded
  note: crash log, with credentials and tenant names redacted: /home/me/.local/state/opentide/crash-20261023T110335102704Z-648.log
  help: this is a bug in opentide; report it: https://github.com/opentidehq/opentide/issues/new?title=Crash+in+opentide+info&body=…
  help: add --debug to see the traceback
```

The crash log holds the version, the command line, the `OPENTIDE_*` and proxy variables, and the traceback. It is written to a private (`0700`) directory outside the repository, and the last ten are kept:

| Platform | Directory |
|----------|-----------|
| Linux and other Unix | `$XDG_STATE_HOME/opentide`, or `~/.local/state/opentide` |
| macOS | `~/Library/Logs/opentide` |
| Windows | `%LOCALAPPDATA%\opentide\logs` |

Before anything is printed or written, opentide removes: proxy and URL credentials (`http://user:pass@proxy` becomes `http://***@proxy`), the value of an `Authorization` or `Proxy-Authorization` header whatever its scheme (`Bearer`, `Basic`, `Token`, `ApiKey`, `ApiToken`, ...), well-known token formats, the values of environment variables, options and `key=value` pairs (URL query strings included) named like a secret (`*_TOKEN`, `*_SECRET`, `*PASSWORD*`, `*_KEY`), and, from `.opentide/configurations/platforms/*.toml` and `sharing.toml`, every secret value and each tenant's or destination's name, URLs, hosts, ids, resource group and Splunk app (built-in apps such as `search`, `launcher`, `SA-*`, `TA-*` and `splunk_*` name no tenant and are kept). Read the log before you attach it to the issue all the same: a value opentide cannot recognise as a secret is left as it is.

Add `--debug` (or set `OPENTIDE_DEBUG=1`) to print the traceback on stderr too, redacted the same way.

## Setup and paths

### `Could not resolve repository root` / objects not found

opentide does not know where your content lives. Set the repo root explicitly:

```bash
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
# or per-command
opentide --repo /path/to/detection-repo validate
```

See [Installation → environment variables](./installation.md#environment-variables).

### `validate --strict` passes with 0 objects from `objects/rules` or a monorepo subdirectory

Through `0.5.0` root discovery walked up for `.git` only. Outside git, from `objects/rules`, the current directory itself became the root; in a workspace kept below a larger checkout (`monorepo/detections/`), the checkout root did. Neither holds `objects/`, so `info` counted nothing, every platform showed as disabled, and `validate --strict` passed having checked no objects. Releases after `0.5.0` walk up to the nearest `.opentide/` or `objects/` without leaving the git checkout ([#294](https://github.com/opentidehq/opentide/issues/294)); see [Repository root resolution](../cli/global-options.md#repository-root-resolution). A `validate` run that still finds nothing names the directory it looked in. On `0.5.0`, run from the workspace root or pass it explicitly:

```bash
opentide --repo /path/to/detections validate --strict
```

### The command `opentide` is not found

The CLI ships with the package. Install it:

```bash
pip install 'opentide==0.18.0'
```

Inside a virtualenv, confirm it is on `PATH` (`which opentide`). For MCP/agent hosts, point the host at that environment's `opentide` binary with args `mcp` and `start` — see [MCP configuration](../mcp/configuration.md).

### `UnicodeDecodeError` reading bundled configurations after pip install

`0.1.0` loaded every file under nested configuration directories as UTF-8 TOML. A pip install compiles `opentide/data/configurations/__init__.py` to `__pycache__/*.pyc`. Python 3.13+ bytecode starts with `0xf3`, which is not valid UTF-8, so `validate` and `generate` crashed.

Upgrade:

```bash
pip install 'opentide==0.18.0'
```

`0.1.1` skips hidden/dunder directories and loads nested `*.toml` only.

### `setup skills discover` starts an install wizard or reports skills unavailable

`0.1.0` bound a positional `PATH` on the skills group, so Click treated `discover` and `show` as a path. The install wizard then ran and tried to download from GitHub.

```bash
pip install 'opentide==0.18.0'
opentide setup skills discover
opentide setup skills --generic --yes
```

Use `--path` / `-C` for the repository root. Catalogue discovery reads the live [opentidehq/skills](https://github.com/opentidehq/skills) `manifest.json`. The four authoring skills are then copied from the package; other skills need the GitHub tree.

### `setup skills` warns that the remote catalogue is unavailable

`opentide setup skills` fetches `manifest.json` from GitHub. The four authoring skills are copied from the package. Other skills are the full tree under `skills/<slug>/`. `AGENTS.md` is rendered from the package template. If you see `Could not fetch skills catalogue from opentidehq/skills@main`, check network access and that [opentidehq/skills](https://github.com/opentidehq/skills) is publicly reachable, then retry:

```bash
opentide setup skills discover --refresh
opentide setup skills --generic --yes
```

### Interactive `opentide setup` crashes with `validate must be callable`

Selecting GitHub Actions (or another CI provider) in the wizard then failed on **CI workflow features**:

```text
ValueError: validate must be callable
```

`0.1.5` passed `validate=None` into Questionary for optional checkboxes. **0.1.6** omits the argument when a selection is optional. Non-interactive `opentide setup --ci github` was already fine. Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide setup
```

### `setup vscode` crashes with `FileNotFoundError`

Generate-first `opentide setup vscode` `chdir`s into the target before writing files. **0.1.6** raised `FileNotFoundError` when that path did not exist yet. **0.1.7** creates the directory first (same as other setup commands). Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide setup vscode
```

### `setup vscode` reports success but snippets are missing

`0.1.6` wrote `.vscode/settings.json` even when templates (and therefore snippets) were missing. **0.1.7** generates templates and schemas first, then fails (`status: failed`) if snippets were requested but could not be written. Re-run:

```bash
pip install 'opentide==0.18.0'
opentide setup vscode
```

Pass `--no-generate` only when `.opentide/templates` already exist. A missing target directory is created automatically.

### `could_not_find_object_folder` at error on an empty repo

`0.1.7` logged missing `objects/{threats,objectives,rules}` at **error** during generate-first `setup vscode` or `generate` on a brand-new scaffold. Those folders are empty until you author YAML. **0.1.8** logs absence at **debug** (once per path). A path that exists but is not a directory still logs at error. Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide generate
```

### `setup repo --platform` does not enable Sentinel (or other) TOML

`0.1.7` accepted `--platform sentinel` on `opentide setup repo` but did not write `.opentide/configurations/platforms/sentinel.toml`. The parent `opentide setup --platform` path already did. **0.1.8** runs platform setup from `setup repo --platform` as well, so `generate` emits `#sentinel:` configuration stubs. Upgrade and re-run:

```bash
pip install 'opentide==0.18.0'
opentide setup repo --yes --name SOC --platform sentinel
opentide generate
```

### Generated templates contain YAML `null` or attach children under the wrong parent

`0.1.7` dumped `default: None` as YAML `null`, and commented `#organisation:` without commenting nested `uuid` / `name`, so those keys parsed as children of `metadata.tlp`. **0.1.8** patched the legacy JSON Schema walker. **0.2.0** replaces that walker: templates come from Pydantic `FieldInfo`, optional sections are commented as whole blocks with `#` hugging each key (nested optionals are not commented again), and there are no `null` tokens. Upgrade and regenerate:

```bash
pip install 'opentide==0.18.0'
opentide generate templates
```

Confirm `.opentide/templates/rule.1.0.template.yaml` has no `null`, `metadata.tlp` is a scalar, and `configurations:` lists commented platform stubs (`#sentinel:`) rather than `{}`.

### `setup ci` YAML fails to parse in GitHub, GitLab, or Azure

`0.1.2` built pipeline files with `textwrap.dedent` around already-indented step blocks, which produced invalid YAML. This is fixed in **0.1.3**. Re-run:

```bash
opentide setup ci github --yes
```

### GitLab merge request pipeline fails: `'deploy_staging' job needs 'generate' job, but it was not added to the pipeline`

A GitLab job with no `rules` defaults to `except: merge_requests`. Through 0.16.1 the generated `.gitlab-ci.yml` had no `workflow:rules`, so the merge request pipeline held only `deploy_staging` and `inflight_shards`, which need `generate`, and GitLab refused to start it. Each push to the branch also ran a branch pipeline. The generated file now sets `workflow:rules` for merge request and default-branch pipelines; regenerate it:

```bash
opentide setup ci gitlab --yes
```

A hand-edited `workflow:` block that did the same can go.

### GitLab inflight job pushes to a host called `${{CI_SERVER_HOST}}`

Through `0.3.0` the GitLab inflight jobs wrote the push URL with GitHub Actions expression syntax (`${{CI_JOB_TOKEN}}`). GitLab only expands `$VAR` / `${VAR}`, so the job tried to reach a literal host. Fixed in **0.4.0** — re-run:

```bash
opentide setup ci gitlab --yes
```

### Azure inflight job says nothing changed and never commits

Through `0.3.0` the Azure job scripts were joined with `&&`. `git diff --staged --quiet` exits 1 when there *are* staged changes, so the chain stopped before `git commit`; when there were none, `exit 0` swallowed every later command. **0.4.0** emits a multi-line `set -e` script with an explicit `if … fi` guard, and checks out with `persistCredentials: true` so the push can authenticate. Azure jobs also no longer declare `dependsOn` on a job from another stage, which Azure cannot resolve. Re-run `opentide setup ci azure --yes`.

### The inflight job pushed pull-request changes to the default branch

Pipelines generated before **0.4.0** committed the refreshed shards on top of the pull request checkout and then ran `git push origin HEAD:<default branch>`. Whenever the pull request was up to date with the default branch that push was a fast-forward, so the unreviewed pull request landed on the default branch; on Azure, which builds the merge commit, the pull request was effectively merged. **0.4.0** copies only `.opentide/inflight/` into a worktree of the default branch and commits there, starting from the default branch's own shards so pruned ones stay pruned. The GitLab jobs also install `git`, which `python:<version>-slim` does not ship. Regenerate every pipeline, then review the default branch's first-parent history: a fast-forwarded pull request shows up as its own commits directly below a `ci: update inflight preview shards` commit, with no merge commit.

```bash
opentide setup ci github --yes   # or gitlab / azure
git log --first-parent --format='%h %s' origin/main
```

### The pre-commit hook reports `OK Validation passed` and commits broken YAML

Through `0.3.0` the generated hook ran `opentide validate --strict` with no `--repo`. `OPENTIDE_REPO_ROOT` (and `OPENTIDE_TIDE_WORKSPACE`) take precedence over directory discovery, so with either exported to another detection repository — as `.env.example` suggests — the hook validated that tree and passed. **0.4.0** pins the committed worktree, and `--repo` now overrides an exported workspace. A workspace in a subdirectory of a larger repository is pinned by its path below the Git root; before, setup reported "Not a Git repository" and installed nothing, and a hook wired in by hand validated the root, which holds no objects. Re-run:

```bash
opentide setup hooks --yes
```

### `opentide --json setup` prints a wizard before the JSON

Through `0.3.0` `--json` only changed the final document: on a terminal the setup wizard still drew its panel and prompts on stdout first, so `json.loads(stdout)` failed. **0.4.0** refuses the combination and exits non-zero with a JSON error. Script it instead:

```bash
opentide --json setup --yes --platform sentinel --ci github
```

### `deploy` or `validate query --live` crashes locally with `illegal_deployment_plan`

`0.1.2` treated an unset `DEPLOYMENT_PLAN` as the string `"None"`. This was fixed in **0.1.3**. Since 0.17.0 there are no deployment plans: `deploy` takes `--strategy`, and `DEPLOYMENT_PLAN` fails with a message naming the replacement ([below](#--plan-or-deployment_plan-was-removed)).

### Tutorial objects fail `validate --strict` or `lint --strict`

`0.1.2` tutorial YAML omitted `metadata.created` / `modified` and used filename/severity values that lint rejected. Copy the examples from the current [Tutorial](./tutorial.md), or upgrade to **0.1.3** and re-run `opentide setup` so templates include dates.

### `info` reports `can_deploy: false` after `pip install opentide`

`0.1.2` imported Azure and pandas when loading Sentinel (and other) deployers, so a base install reported no deploy capability. **0.1.3** lazy-loads those SDKs. Re-run `opentide info` after upgrading. CrowdStrike and HarfangLab still report `can_validate: false` by design.

## Generation

### `opentide generate` warns `Vocab identifier not found` or `Vocab parameter not found` for `criticality`

```text illustrative
warning: Vocab identifier not found · identifier: Critical · vocab: criticality
```

The editor schemas describe each objective with its `priority`, and through 0.16.1 looked that value up in the `criticality` vocabulary for an icon. No vocabulary defines `icon` (`Vocab parameter not found` for `High`), and an objective's `priority` is free text, commonly an `alert_severity` value such as `Critical`, which `criticality` does not have (`Vocab identifier not found`). Nothing failed; the warnings repeated for every objective on every run. The sample above is illustrative: a current release no longer prints it. The description now prints the value as authored, labelled **Priority** (objectives), **Severity** (signals) or **Criticality** (threats), with no lookup. Upgrade and run `opentide generate`.

### `opentide generate` crashes with `Object of type date is not JSON serializable`

Unquoted `metadata.created` / `modified` values (`created: 2026-09-11`) are valid Tide YAML. PyYAML loads them as `datetime.date`, and `0.1.5` crashed when writing `.opentide/exports/objects.export.json`. **0.1.6** stringifies those timestamps at YAML load. Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide generate
```

Quoted dates (`created: "2026-09-11"`) already worked; you do not need to quote them.

### Generated templates comment out required nested fields

`0.1.6` expanded `$ref` / `$defs` in templates but nested objects still inherited a shallow parent `required` list, so required fields under array items were commented out. **0.1.7** uses each nested object's own required list. Upgrade and regenerate:

```bash
pip install 'opentide==0.18.0'
opentide generate
```

### `opentide generate` crashes with `'str' object has no attribute 'get'`

`0.1.3` leaked `threat.actors` as `list[str]` while table export still called `.get("name")`. **0.1.4** restores the CoreTide object form (`name`, optional `sighting` / `references`). Upgrade:

```bash
pip install 'opentide==0.18.0'
```

Write actors as objects, not bare IDs:

```yaml
actors:
  - name: att&ck::G0006
```

### `opentide generate` crashes with `subschemas` on a new repo

Snippet generation used a legacy `Paths.Core.subschemas` path that the current layout never populates, so `opentide generate` aborted after docs and exports. This is fixed in **0.1.2**. An empty catalogue is valid: generate writes empty exports and creates `.vscode` snippets from whatever templates exist.

### `validate` complains that schemas are missing

Validation checks objects against generated JSON Schemas. If they do not exist yet, generate them first:

```bash
opentide generate
opentide validate --strict
```

Run [`generate`](../cli/generate.md) after cloning a repo, after upgrading the opentide package, and whenever schema revisions change.

### Editor stopped validating YAML / "Matches multiple schemas"

Routers generated up to `0.14.2` combined their branches with `oneOf` and no `else`, so every valid object matched several branches and the Red Hat YAML extension reported **Matches multiple schemas**. Those releases mapped each object folder to one revision schema instead, which flags valid `rule::1.1` rules because `objects/rules/**/*.yaml` pointed at `rule.1.0.schema.json`. Current releases generate a router that applies exactly one revision schema per object, and `opentide setup vscode` maps `objects/**/*.yaml` to it and removes the old per-folder mappings.

```bash
pip install --upgrade opentide
opentide generate schemas
opentide setup vscode --settings --no-generate
```

Then reload the YAML language server. If schemas are stale or missing:

```bash
opentide generate schemas
```

## Documentation

### CVE documentation still links to NVD / uses `mitrecve`

`0.2.0` and earlier scraped NVD through `mitrecve`. **0.2.1** looks up `threat.cve` on [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu). Generated threat pages link to `https://vulnerability.circl.lu/vuln/{id}` and can enrich published date, severity, and aliases. Upgrade, regenerate docs, and (optionally) run the opt-in check:

```bash
pip install 'opentide==0.18.0'
opentide generate docs
opentide validate --check cve
```

Default `opentide validate` does not call the network. Empty JSON from CIRCL means the identifier is unknown. GNA 0 GCVE ids (`GCVE-0-YEAR-N`) are stored under the corresponding `CVE-YEAR-N` key.

### GitHub docs land under `docs/Threats/{uuid}.md` instead of slug paths

`0.1.7` applied GitLab `uuid_permalinks` to every flavour and built index links from the UUID while page files used slugify. GitHub pages were therefore `simulated-actor.md` while indexes linked to `{uuid}.md`, and folders used Title Case (`docs/Threats`). **0.1.8** scopes UUID permalinks to GitLab and writes lowercase `docs/{rules,objectives,threats}/<slug>.md`. Upgrade and regenerate:

```bash
pip install 'opentide==0.18.0'
opentide generate docs
```

### Docs warn that `objective.priority: Critical` is not in `criticality::1.0`

Objective `priority` is an unconstrained alert-style string (High / Critical), not an incident `criticality::1.0` token. **0.1.7** looked it up in that vocab. **0.1.8** renders the author value as-is. Threat `criticality` and impact vocab spelling (including `Impairement`) are unchanged. Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide generate docs
```

## Validation errors

### `invalid_ref` points at a parent object (`detection`, not `detection_model`)

`0.1.6` attributed `invalid_ref` to the nested object that contained the UUID. **0.1.7** reports the leaf field (`detection_model`, `objective.threats`, …). Vocabulary names also skip YAML list indices (`[0]`). Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide validate --strict
```

### JSON `validate` stamps every check `invalid`

`--json` used a single repo-wide `valid`/`invalid` for every check name. A vocab failure then looked like a failing `uuid` or `metadata` check. **0.1.7** emits per-check `status`. Upgrade:

```bash
pip install 'opentide==0.18.0'
opentide --json validate
```

### `unknown schema identifier` / object won't load

`metadata.schema` must be a registered identifier such as `rule::1.0` or `rule::1.1`. A typo (`rule:1.0`, `rule::1`, `rules::1.0`) means no model matches. Fix the value; the valid identifiers are `threat::1.0`, `objective::1.0`, `rule::1.0`, and `rule::1.1`. `metadata.reviewed` is valid only on `rule::1.1`. A `schema_missing` issue means the file has no `metadata.schema` at all: add the identifier the object follows, because opentide does not assume the newest revision. See [Schema revision](./concepts/schema-revision.md).

### Threat `impact` / `leverage`: `Input should be a valid string`, `must be a YAML list`, or `packs several vocabulary names`

`threat::1.0` makes `threat.impact` and `threat.leverage` non-empty lists of vocabulary names. Up to **0.4.0** the engine typed them as single strings, so a threat written to the spec failed with `Input should be a valid string`. **0.5.0** follows the spec: a single string fails with `must be a YAML list of … vocabulary names` (plus `list each name in '…' as its own item` when it joins several with `;`), and a list item that joins several names fails with `packs several vocabulary names into one string`. Give every name its own list item, and keep all of them — do not shorten a packed value to its first name:

```yaml
threat:
  impact:
    - Data Breach
    - Identity Theft
  leverage:
    - Elevation of privilege
    - Repudiation
```

If your CI patches the installed `opentide` model to accept lists, drop that step once you upgrade:

```bash
pip install 'opentide==0.18.0'
opentide validate --strict
```

### `duplicate UUID`

Two objects share a `metadata.uuid`. UUIDs must be unique across the repo — you almost certainly copy-pasted an object. Generate a fresh one:

```bash
python -c "import uuid; print(uuid.uuid4())"
```

### `unknown objective` / dangling reference

A `detection_model` or `objective.threats` UUID points at an object that does not exist. This is the [dangling reference](./concepts/object-model.md#anti-patterns-to-avoid) anti-pattern — usually a typo or a deleted file. Fix the UUID or restore the target.

### `unknown status`

A rule's `status` (or a platform block's `status`) is not defined in the merged `deployment.toml`. Use a bundled status (`STAGING`, `PRODUCTION`, …) or add your own — see [Configuration → deployment statuses](./configuration.md#deployment-statuses-and-strategies).

### Warnings fail my build but pass locally

Warnings alone exit `0` by default and are listed in `--json` output under `warnings`. Pass `--strict` to fail the run with exit `1`; `platform_not_enabled` is the one warning `--strict` ignores. If your pipeline uses `--strict`, reproduce it locally with the same flag:

```bash
opentide validate --strict
```

See [Exit codes](../cli/exit-codes.md).

### `<file>.toml is invalid: …: unknown key` after upgrading

From **0.18.0** every file under `.opentide/configurations/` is checked against its model. An unknown or misspelt key, or a value of the wrong type, fails each command that reads the file, naming the file and the key: `deployment.toml is invalid: promotion.enabeld: unknown key`. Through 0.17.2 such a key was ignored. Run `opentide validate` to list them all (check `configuration`), then fix or remove each one. `opentide explain unknown_key` describes the finding.

Seen while preparing 0.18.0:

- A Splunk tenant's `schedule_offset = "5"` (a string): write `schedule_offset = 5`.
- A `documentation.toml` that `opentide migrate` copied from CoreTIDE: delete `skip_vocabularies`, `model_cover_pages` and the `[titles]` table, which opentide never read.

```bash
pip install 'opentide==0.18.0'
opentide validate
```

### `deploy` fails with `'NoneType' object is not iterable`

A rule whose `configurations` holds no platform block stopped the whole deploy with this message. `opentide new rule` writes that shape when no `--platform` is given. **0.18.0** skips the rule. Add a platform block from `.opentide/templates/rule.1.1.template.yaml` to deploy it.

```bash
pip install 'opentide==0.18.0'
```

## Query validation

### `supported: false` for a platform

CrowdStrike and HarfangLab are **deploy-only** — they cannot validate query syntax, and opentide reports this honestly rather than faking a pass. This is expected behaviour, not an error. Validate queries on a supporting platform (Sentinel, Defender, Splunk, Elastic, SentinelOne, Carbon Black). See [Platforms](./concepts/platforms.md#query-validation-policy).

### MCP `validate_query` refuses

The default checks the `query` string offline. It refuses, without scanning, an empty query and a SentinelOne query: S1QL has no offline engine, so pass `live: true` to check the catalogue rules against the tenant. A missing plan fails that check. `run_query` is not implemented and returns `stub: true` with `rows: null`.
See [Agentic setup](./workflows/agentic-setup.md).

### `opentide validate query` fails with `engine_unavailable`

The offline check, `validate --deep` and `opentide lsp` run the analysis engine, which is compiled into the opentide package. When it does not import, they fail rather than skip, and say so:

```text illustrative
error: The opentide analysis engine does not load: No module named 'opentide._native'
  help: reinstall opentide: pip install --force-reinstall opentide
```

Reinstall opentide. `opentide doctor` reports the engine (`analysis_engine`). pip downloads opentide's wheel for Linux (x86_64 and arm64, glibc and musl), macOS and Windows x64, engine included; elsewhere it builds opentide from its sdist, which compiles the engine and needs a Rust toolchain ([rustup.rs](https://rustup.rs)). See `opentide explain engine_unavailable`.

### `opentide validate query --live` fails before it reaches the tenant

`--live` needs tenant credentials; the vendor SDKs ship with `pip install opentide`.

Through 0.15.0 the SDKs were extras, so a pipeline that installed only
`opentide==<version>` failed `--live` with `needs a vendor SDK: No module named
'azure'`. Upgrade to 0.16.0 or later; there is no extra to add. If a current
release still reports that an SDK will not import, the environment is damaged:
run `pip install --force-reinstall opentide`.

### Live query validation in CI takes most of an hour

Through 0.16.1 the generated pipelines ran `opentide validate query --platform <platform> --live` with no scope, so every run sent every rule in the catalogue to the tenant. The step now passes `--changed` and checks only the rule files the pull request, merge request or push changed, on the tenants a deploy sends them to ([which rules are checked](../cli/validate.md#which-rules-are-checked)). Regenerate the pipeline with `opentide setup ci <github|gitlab|azure> --yes`. Do not add `--strategy PREVIEW` to it: that drops the changed rules in a `RELEASE` status from the pull request's check. To check particular rules by hand, pass `--file` or `--uuid`.

## Platforms and deployment

### A platform I configured is not loaded

Platforms load only when enabled in your workspace config:

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true
```

Verify with `opentide info --platform sentinel`. See [Configuration → enabling a platform](./configuration.md#enabling-a-platform).

### `No module named 'six.moves'` from `botocore` or `cbc_sdk`

python-dateutil 3.0.0 (21 October 2026) led `uv`'s resolver to install boto3 `0.0.3` with opentide **0.17.1** and earlier; its botocore cannot import on current Python. **0.17.2** requires `boto3>=1.35`. Upgrade; to stay on an older version, add `'boto3>=1.35'` to the same install command.

```bash
uv pip install 'opentide==0.18.0'
```

### Splunk answers with HTML instead of XML behind a proxy

Through **0.17.1** this failed as `xml.etree.ElementTree.ParseError: mismatched tag`, which reads like a TLS fault but is not one. **0.17.2** names it: `Splunk at https://<host>:8089 answered with an HTML page, not its REST API … The request went through the proxy http://<proxy>:<port> …`, with the `NO_PROXY` value to set. Each connection also logs `splunk_tenant_route` with `via` set to the proxy or `direct`.

The request went through the proxy, and the proxy answered with its own error page. An internal tenant must not be reached through the corporate proxy: add its host to `NO_PROXY` and `no_proxy` (`NO_PROXY=splunk.internal.example`). opentide's platform clients honour it, so the same run still reaches a cloud tenant such as Sentinel through the proxy, and the deploy does not have to be split per platform. See [CI/CD → Behind a proxy or a private CA](./workflows/ci-cd.md#behind-a-proxy-or-a-private-ca).

Do not replace opentide's Splunk handler with splunklib's own (`verify=not ssl_enabled` patches): that handler ignores `HTTPS_PROXY` and `NO_PROXY` alike, so it only appears to work by skipping the proxy, and with `ssl = false` it turns certificate verification on. A cloud-hosted Splunk that must be reached through the proxy then fails. Set `NO_PROXY` instead.

### Splunk fails on the certificate although the tenant sets `ssl = false`

Through **0.17.0** the Splunk client ignored a tenant's `ssl = false` and verified the certificate anyway, so a self-signed Splunk failed every `deploy` and `validate query --live` with `CERTIFICATE_VERIFY_FAILED`. **0.17.1** honours each tenant's `ssl`. Upgrade, and delete any pipeline step that patches the installed `opentide/platforms/splunk/client.py`:

```bash
pip install 'opentide==0.18.0'
```

An `xml.etree.ElementTree.ParseError: mismatched tag` is not a certificate failure: the answer was an HTML page, usually a proxy's. See [Splunk answers with HTML instead of XML behind a proxy](#splunk-answers-with-html-instead-of-xml-behind-a-proxy).

### `Argument "quantity" is not supported by this handler`

Through **0.17.0** a Splunk rule with a `trigger` block sent the `savedsearches.conf` names `counttype`, `relation` and `quantity`, which Splunk's REST endpoint refuses. **0.17.1** sends `alert_type`, `alert_comparator` and `alert_threshold`. Upgrade, and delete any pipeline step that patches the installed `opentide/platforms/splunk/deployer.py`.

### `setup: ssl is unset ($VAR)`

The tenant's `ssl` names an environment variable that is not set in this shell or CI job. Set it to `true` or `false`, or write the value in the platform TOML. Through **0.17.0** this failed later, as `Could not find a suitable TLS CA certificate bundle`, on every platform but Splunk.

### `setup: ssl must be true or false`

A tenant's `ssl` is neither a boolean nor one of `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`. When `ssl` names an environment variable (`ssl = "$SPLUNK_SSL"`), check that variable's value. See [Configuration → TLS verification](./configuration.md#tls-verification).

### `--plan` or `DEPLOYMENT_PLAN` was removed

opentide 0.17.0 removed deployment plans. A run now names the status strategy it deploys: `--strategy PREVIEW` in the pull or merge request job, `--strategy RELEASE` in the default-branch job. `--plan STAGING` becomes `--strategy PREVIEW`, `--plan PRODUCTION` becomes `--strategy RELEASE`, and `--plan FULL` (or no plan) becomes `--strategy PREVIEW --strategy RELEASE --all`. Unset `DEPLOYMENT_PLAN` in your CI variables, and regenerate the pipeline with `opentide setup ci <github|gitlab|azure> --yes`. See [Statuses, strategies and tenants](./concepts/statuses-and-strategies.md#moving-from-deployment-plans-016-and-earlier).

### `--strategy 'STAGING' is not a deployable strategy`

`STAGING` and `PRODUCTION` are default status names, not strategies. A status maps to a strategy in `deployment.toml`; with the defaults, `STAGING` maps to `PREVIEW` and `PRODUCTION` to `RELEASE`. Pass the strategy: `--strategy PREVIEW` or `--strategy RELEASE`. The error names the strategy any status in your configuration maps to.

### `the tenant key 'deployment' was removed in 0.17.0`

A tenant now lists the strategies it accepts. Replace the `deployment` line the error names: `deployment = "STAGING"` becomes `strategies = ["PREVIEW"]`, `"PRODUCTION"` becomes `strategies = ["RELEASE"]`, `"ALWAYS"` is removed (a tenant accepts both by default), and `"MANUAL"` becomes `manual = true`.

### A changed rule was not deployed

`deploy` counts the rules a status kept out (`Skipped: No rule has a status PREVIEW deploys · 4 rules in DESIGN`, or a `note:` under the plan's tally) and names the statuses that would deploy; the JSON document lists them under `skipped`. Then check three things, all named in the `rule_skipped_for_strategy` and `skipping_tenant` log lines that `--debug` prints:

1. The strategy its status maps to. A `PREVIEW` run skips a rule in `PRODUCTION` (it maps to `RELEASE`); a `RELEASE` run skips one in `DEVELOPMENT` (`PREVIEW`) unless promotion rewrites it first; `INERT` rules never deploy.
2. The tenant's `strategies`. A tenant with `strategies = ["RELEASE"]` never receives a `PREVIEW` run, and a `manual` tenant only receives rules that list it.
3. The rule files the run read. Outside CI, `deploy` reads only the last commit: commit the rule, or pass `--all`.

`opentide --json deploy --dry-run --strategy <S>` lists, per platform, the tenants each rule would reach. See [Statuses, strategies and tenants](./concepts/statuses-and-strategies.md).

### Deploy fails with an authentication error

Credentials are missing or wrong. opentide reads them from your platform TOML, typically via environment variables. Confirm the variables are set in your shell (or CI secrets) and match the keys the platform expects (`opentide info --platform <name>`). Never commit secrets — see [Configuration → credentials](./configuration.md#credentials).

### `deploy` exits with `[Errno 2] No such file or directory`

Through **0.5.0**, `deploy` required `objects/rules/` to exist. A fresh clone has no such folder until the first rule is committed, so the command exited `1` with `Errno 2`. **0.6.0** reports `skipped` with exit `0` and contacts no platform ([#300](https://github.com/opentidehq/opentide/issues/300)).

### `deploy` or `validate query --live` says a platform has no tenants

`setup repo` enables a platform and leaves the `[[tenants]]` example commented out. **0.6.0** stops a real `deploy` and a `--live` query check before any engine loads, and names the file to edit. `--dry-run` still previews payloads and warns that a real deploy would stop ([#314](https://github.com/opentidehq/opentide/issues/314)). Uncomment a `[[tenants]]` entry in `.opentide/configurations/platforms/<platform>.toml`.

### `WARNING` names rule files in subfolders of `objects/rules`

A rule file has to sit directly in `objects/rules/`. A file in a subdirectory is outside the rule catalogue and is not deployed. **0.6.0** warns and names the files it skipped ([#300](https://github.com/opentidehq/opentide/issues/300)). Move a rule up into `objects/rules/` to deploy it.

### `nested_object_file`: an object file in a subfolder is skipped

The same rule holds for every object folder and every command. A threat, objective or rule file in a subfolder of its folder is not an object: `validate`, `share`, `lint`, docs and exports skip it and name it in a `nested_object_file` warning ([#584](https://github.com/opentidehq/opentide/issues/584)). Through 0.17.2 those commands still read subfolders, so a full `share push` could publish a file `deploy` skipped. Move the file up into its object folder.

### `--promotion` or `--promotion-target` does not change what `deploy` promotes

Through **0.5.0** those flags were accepted and ignored, so `deploy` kept promoting to `PRODUCTION`. **0.6.0** writes them when the same command also generates CI ([#307](https://github.com/opentidehq/opentide/issues/307)). A plain `opentide setup --no-promotion` or `--promotion-target`, without `--ci`, still ignored them. **0.6.1** writes the `[promotion]` table on that command too ([#325](https://github.com/opentidehq/opentide/issues/325)). Omitting the flags keeps the file as it is. An explicit flag that disagrees with an existing table exits `2` and writes nothing.

### CI `STAGING` or `PRODUCTION` deploys none of the changed rules

Through **0.6.0** a CI diff plan matched changed paths against an absolute rules directory, so a repo-relative change such as `objects/rules/rule.yaml` was left out and the plan deployed nothing for it. **0.6.1** includes a changed file that sits directly in `objects/rules/` ([#318](https://github.com/opentidehq/opentide/issues/318)). A file in a subdirectory stays out of the plan; the warning names it.

### CI diff plan crashes with `encode`, `KeyError`, `Invalid object name`, or `list index out of range`

Through **0.6.2** several CI diff arms still leaked an exception after the GitLab base and GitHub pull-request-ref fixes. **0.6.3** still exits `1`. The message is a sentence ([#339](https://github.com/opentidehq/opentide/issues/339)):

- An unset tip SHA names `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION`.
- Azure `STAGING` without `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME` names those variables, before it fetches `origin`.
- A pull-request ref that is not on `origin` names `origin/<name>`.
- `DEBUG`, `MANUAL`, and `ALWAYS` said the plan was not a CI diff plan. Plans were removed in 0.17.0; the CI context now decides which diff a run reads.
- A GitLab merged-result commit with only one parent keeps `CI_COMMIT_SHA` and exits `0` when both SHAs are in the checkout.

### GitLab `STAGING` or `PRODUCTION` crashes with `lookup_ref`

Through **0.6.1** a GitLab diff plan whose base SHA was unset (`CI_MERGE_REQUEST_DIFF_BASE_SHA` or `CI_COMMIT_BEFORE_SHA`) or not in the checkout walked `origin/main` through Dulwich `Repo.lookup_ref` and exited `1` with `FATAL: 'Repo' object has no attribute 'lookup_ref'`. **0.6.2** still exits `1`, with `No Source Commit Found`. The same command succeeds when both SHAs are in the checkout ([#333](https://github.com/opentidehq/opentide/issues/333)). Set the base variable GitLab provides for that pipeline, and check the job out with enough history for that commit to be present.

### GitHub `STAGING` asks for Azure pull-request variables

Through **0.6.1** a GitHub Actions `STAGING` plan without `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` exited `1` after asking for `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then `FATAL: KeyError while compiling the deployment plan`. **0.6.2** still exits `1`. The message names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` ([#334](https://github.com/opentidehq/opentide/issues/334)). Run the plan from a pull-request workflow, which sets those variables. An Azure pipeline still names the Azure variables it reads.

### `deploy --plan STAGING` says no git repository was found at `None`

Through **0.6.0** a `STAGING` or `PRODUCTION` plan with `GITHUB_ACTIONS`, `CI`, or `TF_BUILD` set and no checkout exited `1` with `FATAL: No git repository was found at None`. **0.6.1** still exits `1`. The message names the directory it searched ([#310](https://github.com/opentidehq/opentide/issues/310)). Since 0.17.0 every deploy without `--all` reads a diff, outside CI too (the last commit). Run the command inside the repository, or pass `--all`, which does not need a checkout.

### `setup --path .` writes the scaffold at the git root

Through **0.6.0**, `opentide setup --path .` run from a subdirectory of a git checkout scaffolded the git root, because the discovered root was treated as `--repo`. **0.6.1** scaffolds the working directory ([#324](https://github.com/opentidehq/opentide/issues/324)). Pass `--repo` explicitly when the scaffold should land somewhere else.

### `setup --ci` ignores `--default-branch` or hides CI warnings

Through **0.5.0** only `setup ci` accepted `--default-branch`, and a repository whose only branch was not `main` could get a pipeline that fetched and deployed `main`. The one-shot `setup --ci` also dropped the warnings `setup ci` printed. **0.6.0** accepts the flag on both forms and prints the same warnings ([#288](https://github.com/opentidehq/opentide/issues/288), [#308](https://github.com/opentidehq/opentide/issues/308)). Regenerate with `opentide setup ci <github|gitlab|azure> --yes`.

### `deploy metadata` fails with "not implemented"

`opentide deploy metadata` is reserved for pushing Splunk lookup tables and is not implemented. It deploys nothing and exits `2`, so a CI step that runs it fails:

```bash
opentide deploy metadata --platform splunk
```

```text output-of="opentide deploy metadata --platform splunk" exit=2
error: Metadata deployment is not implemented for splunk
```

With `--json` it prints one document with `"ok": false` and the same message. Remove the step from your pipeline; lookup tables are not deployed by opentide yet. See [`deploy metadata`](../cli/deploy.md#deploy-metadata).

### `generate` exits 1 with an empty JSON body

Through **0.6.3** a rule whose `detection_model` UUID is not in the catalogue made `generate` exit `1` with empty stdout and a traceback ending in a bare `Exception`. **0.6.4** still exits `1`. `--json` returns one document whose `message` names the missing UUID and `detection_model` ([#352](https://github.com/opentidehq/opentide/issues/352)). Add the objective (and its threat) to the catalogue, or point `detection_model` at one that exists. `generate inflight` on that tree still exits `0`.

### MCP `deploy_rule` crashes or marks an undeployed rule deployed

Through **0.6.3** an unknown platform crashed with `KeyError`, and a config with no `external_id` and no tenants was reported as deployed. **0.6.4** returns a structured failure for an unknown platform and for a platform with no tenants. `deployment_status` sets `deployed` to false in that case ([#345](https://github.com/opentidehq/opentide/issues/345)).

### `--json setup` says it would write to `..`

Through **0.6.3** a target of `.` was printed without quotes, so the trailing period made the path look like `..`. **0.6.4** quotes the path ([#346](https://github.com/opentidehq/opentide/issues/346)).

### GitHub production deploy is skipped

Through **0.6.3** the generated production job needed `deploy_staging`, and staging runs only on a pull request, so a push to the default branch skipped production. **0.6.4** needs `generate` and still runs only on a push to the default branch ([#348](https://github.com/opentidehq/opentide/issues/348)). Deploy jobs also fetch full history, so a depth-1 checkout no longer exits `1` with a bare parent SHA. Regenerate:

```bash
pip install 'opentide==0.18.0'
opentide setup ci github --yes
```

GitLab and Azure use the same full-history checkout on their deploy jobs. The GitLab `No Source Commit Found` sentence is unchanged.

### Explorer pages on GitLab or Azure write no job

Through **0.6.3** setup accepted Explorer pages for GitLab and Azure, wrote no job, and printed no warning. **0.6.4** offers that choice only for GitHub. On GitLab or Azure the command exits `0` and warns that Explorer pages were not written ([#347](https://github.com/opentidehq/opentide/issues/347)).

### `setup --ci none` reports success and writes nothing

Through **0.6.3** `setup --yes --ci none` exited `0` with `Setup complete` and an empty `steps` list. **0.6.4** scaffolds the repository and writes no pipeline ([#349](https://github.com/opentidehq/opentide/issues/349)). `setup ci` accepts `github`, `gitlab`, or `azure`. CI-only flags without one of those platforms are named in warnings.

### Re-running setup replaces README, gitignore, or platform comments

Through **0.6.3** `setup --platform` replaced `README.md` and `.gitignore`, and `setup platforms` rewrote an existing platform toml and dropped comments. **0.6.4** keeps those files when they already exist ([#350](https://github.com/opentidehq/opentide/issues/350)). The first scaffold still creates them. `setup ci` still replaces the workflow.

### `lint --fix` reports metadata on the old filename

Through **0.6.3** `lint --fix` renamed a threat file and the metadata finding in the same run still named the old path. **0.6.4** rewrites that finding onto the new path. A second `--fix` does not rename the file again ([#353](https://github.com/opentidehq/opentide/issues/353)).

### `validate` exits 0 when an object YAML has no `uuid`

Through **0.7.0** a rule, objective, or threat file with no `uuid` did not fail the schema check, so `opentide validate` exited 0. **0.8.0** fails that file. The schema check reports `missing_uuid`. An empty catalogue still exits 0 ([#397](https://github.com/opentidehq/opentide/issues/397)). Add a uuid and re-run `opentide validate --strict`.

### `deploy --plan STAGING` crashes with `list index out of range`

Through **0.7.0** a GitHub or Azure pull-request checkout (detached `HEAD`) died inside the git fetch with `list index out of range` ([#402](https://github.com/opentidehq/opentide/issues/402), [#415](https://github.com/opentidehq/opentide/issues/415)). **0.8.0** fetches `origin` by name. A missing ref still exits 1 with `Could not find git ref`.

### The inflight prune job fails because `.opentide/inflight` was never committed

Through **0.7.0** the generated prune job ran `git add .opentide/inflight/` and exited 128 when that directory was absent. **0.8.0** creates the directory first ([#403](https://github.com/opentidehq/opentide/issues/403)). Regenerate:

```bash
pip install 'opentide==0.18.0'
opentide setup ci github --yes
```

GitLab and Azure use the same step.

### Generated CI stays green when lint fails, or fails with no tenants

Through **0.7.0** generated validate did not pass `--strict`, and lint was not a gate, so a misnamed file stayed green. Deploy also failed while every `[[tenants]]` block was still commented out ([#408](https://github.com/opentidehq/opentide/issues/408), [#409](https://github.com/opentidehq/opentide/issues/409)). **0.8.0** runs `opentide validate --strict` and `opentide lint --strict`. Deploy previews with `--dry-run`, then runs `opentide deploy --plan <PLAN> --skip-unconfigured`. That flag exits 0 only when every platform in the plan has no tenants. A mix still fails with `Cannot deploy:`. Regenerate the pipeline. GitHub deploy jobs map each bundled credential name from `secrets`.

### Azure Pipelines reports `No pool was specified`

Through **0.7.0** `opentide setup ci azure` wrote no `pool`, so Azure Repos refused the file. `pr:` is ignored on Azure Repos Git, so a pull request never set `Build.Reason` ([#398](https://github.com/opentidehq/opentide/issues/398)). **0.8.0** sets `pool.vmImage` to `ubuntu-latest` and triggers on every branch so a topic-branch push still validates. Add a build validation policy on the default branch so a pull request sets `Build.Reason` to `PullRequest`. Staging deploy stays gated on that reason. The pipeline file cannot create the policy. Regenerate with `opentide setup ci azure --yes`.

### `setup skills` installs a short tree or CoreTide authoring instructions

Through **0.7.0** a skill install copied the skills-repository `AGENTS.md`, dropped files under `references/`, and the four authoring skills still described CoreTide schemas ([#399](https://github.com/opentidehq/opentide/issues/399), [#405](https://github.com/opentidehq/opentide/issues/405)). **0.8.0** downloads every file under `skills/<slug>/`, renders `AGENTS.md` from the package, and installs `opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` from the package. Those skills describe `rule::1.0`, `objective::1.0`, and `threat::1.0`. Re-run `opentide setup skills`.

### `setup repo` hardcodes Sentinel or ignores `--name`

Through **0.7.0** the scaffold README always showed a Sentinel dry-run, empty directories were not kept by git, and `--name`, `--org`, and `--description` left an existing README unchanged with no warning ([#400](https://github.com/opentidehq/opentide/issues/400), [#404](https://github.com/opentidehq/opentide/issues/404)). **0.8.0** writes `.gitkeep` in empty scaffold directories, lists one dry-run per enabled platform, and warns when those flags are ignored because `README.md` already exists.

### `generate docs` links to section READMEs that were not written

Through **0.7.0** an empty `rules/`, `objectives/`, or `threats/` folder produced no `README.md`, so the root index linked to a missing page ([#401](https://github.com/opentidehq/opentide/issues/401)). **0.8.0** writes those indexes, including a zero count.

### MCP `get_chaining` returns an empty graph for a linked threat

Through **0.7.0** `get_chaining` returned an empty graph unless the threat itself had `threat.chaining`, so a threat listed on an objective and used by a rule looked unconnected ([#407](https://github.com/opentidehq/opentide/issues/407)). **0.8.0** returns that lineage under `lineage` and, when the node has no relation map, under `graph`. When `threat.chaining` is set, `graph` stays the relation map. `Opentide.Models.chaining` is unchanged.

### `lint` prints `OK` while findings are listed

Through **0.7.0** human `lint` printed `OK` when findings existed, and the exit code stayed 0. **0.8.0** prints `ISSUES` in that case; later releases print the `!` outcome glyph instead. The exit code stays 0 unless you pass `--strict`. JSON keeps `"ok": true`.

### Installation pages name 0.6.1 as the latest release

Through **0.7.0** the docs home and installation page said the latest release was 0.6.1 while the install block pinned 0.7.0 ([#406](https://github.com/opentidehq/opentide/issues/406)). **0.8.0** names 0.8.0 in both places. **0.8.1** names 0.8.1. **0.8.2** names 0.8.2. **0.9.0** names 0.9.0. **0.10.0** names 0.10.0. **0.11.0** names 0.11.0. **0.12.0** names 0.12.0. **0.12.1** names 0.12.1. **0.13.0** shipped the regression instead: four pages still named 0.12.1, which is what the 0.14.0 preparation found beside those pages' own 0.14.0 install block. **0.14.0** restored the claim and added a test checking every claim, pin and PyPI link against the newest `CHANGELOG.md` entry, so the sentence can no longer drift unnoticed. **0.14.1** names 0.14.1. **0.14.2** names 0.14.2. Pin `opentide==0.18.0`.

### GitLab deploy runs after `validate query` fails

Through **0.8.0** a generated GitLab pipeline started `generate` as soon as the object `validate` job finished. Query checks are separate jobs in the same stage, and GitLab starts a job when its `needs` finish, so a failed `opentide validate query` did not stop deploy ([#429](https://github.com/opentidehq/opentide/issues/429)). **0.8.1** lists every query-validation job in `generate`'s `needs`. GitHub and Azure already gated generate this way. Regenerate:

```bash
pip install 'opentide==0.18.0'
opentide setup ci gitlab --yes
```

### GitLab CI rejects an empty document job, or ShellCheck fails the inflight script

Through **0.8.0** a document job with no commands was written with an empty `script`, which GitLab rejects, and the inflight job fetched `origin $CI_DEFAULT_BRANCH` unquoted ([#430](https://github.com/opentidehq/opentide/issues/430)). **0.8.1** omits that job and the `document` stage when there is nothing to run, quotes the branch, and exits if `cd` into the worktree fails. Regenerate with `opentide setup ci gitlab --yes`.

### CI logs contain a CrowdStrike or Defender OAuth token

Through **0.8.2** CrowdStrike auth logged the full token response at info, which `--json` and the MCP server copy to stderr. Defender logged the token at debug and a client-secret prefix when authentication failed ([#441](https://github.com/opentidehq/opentide/pull/441)). **0.9.0** keeps the bearer token and the client secret out of the log. A failed authentication still names the tenant.

### `share push` leaves a retracted object unpublished

Through **0.8.2** a content hash that still matched the ledger skipped the next push even when that line was `retracted`. Preview reported an update and the MISP event stayed unpublished ([#385](https://github.com/opentidehq/opentide/pull/385)). **0.9.0** treats only a `synced` line as unchanged, so the next push publishes the object again.

### `deploy` dies with `RecursionError` on a long history

Through **0.8.2** loading a commit walked every ancestor. A repository deeper than the Python recursion limit raised `RecursionError` from `repo.head` while computing the diff, and deploy aborted ([#369](https://github.com/opentidehq/opentide/pull/369)). **0.9.0** records only the immediate parent.

### `metadata.reviewed` is rejected, or every rule looks unreviewed

Through **0.8.2** no schema accepted `metadata.reviewed`. **0.9.0** accepts an ISO 8601 date or datetime on `rule::1.1` only. `rule::1.0`, threats, and objectives still reject the field ([#437](https://github.com/opentidehq/opentide/issues/437), [#438](https://github.com/opentidehq/opentide/pull/438)). `opentide rules unreviewed` lists `rule::1.0` as `schema`, a `rule::1.1` with no review as `absent`, and a review older than the window as `stale`. It does not write the date. Set `schema: rule::1.1` before adding `reviewed`, then run `opentide generate` so the editor schema includes the field.

### A technique or log source that validated on 0.8.2 now fails

**0.9.0** pins techniques to `att&ck::1.1` and objective logsources to `datasources::1.1` ([#392](https://github.com/opentidehq/opentide/issues/392), [#445](https://github.com/opentidehq/opentide/pull/445)). The catalogues were ATT&CK 19.2. An identifier that is not in the pinned catalogue fails validation. Regenerate schemas if the editor still offers the previous list: `opentide generate schemas`.

### A recent ATT&CK technique such as T1685 or T1059.013 fails validation

**0.13.0** through **0.15.0** bundled an ATT&CK v17 catalogue under the `att&ck::1.1` pin. [#504](https://github.com/opentidehq/opentide/pull/504) re-synced the bundle from a specifications copy that never had the 19.2 refresh, so T1685–T1690, T1059.013 and the other ATT&CK v18 and v19 techniques failed validation ([#568](https://github.com/opentidehq/opentide/issues/568)). **0.16.0** restores ATT&CK 19.2 as `att&ck::1.1`, adds ATT&CK 20.0 as `att&ck::1.2` (T1696–T1701 and others), and pins threats, objectives and rules to `att&ck::1.2`. Run `opentide generate schemas` so the editor offers the new list.

Techniques that MITRE has revoked since then, such as T1562.001 (now T1685) and T1070.001, stay valid under every `att&ck::1.x` pin. They are marked `removed = "2.0"`. T1574.002 is not in any bundled catalogue: MITRE merged it into T1574.001, so use that ID.

ATT&CK v19 renamed Defense Evasion (TA0005) to Stealth and split Defense Impairment (TA0112) out of it. Elastic rules carry TA0005 Stealth and TA0112 Defense Impairment. The Sentinel tactic list has no such tactics, so Sentinel rules carry `DefenseEvasion` for Stealth, Defense Impairment and the ICS Evasion tactic.

## Still stuck?

- Run `opentide doctor` and fix what it reports first.
- Re-run with debug logging: `OPENTIDE_DEBUG=1 opentide validate --strict`.
- Compare your object against a known-good [fixture](https://github.com/opentidehq/specifications/blob/main/fixtures/valid).
- Check the [CLI reference](../cli/index.md) for the exact flags and [exit codes](../cli/exit-codes.md).
