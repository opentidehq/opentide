---
title: Releases
description: Public package versions of opentide on PyPI.
---

# Releases

Every version of the [`opentide`](https://pypi.org/project/opentide/) package, newest first. Each opens with what it does for you, then the steps to take after upgrading, then what changed, under the same headings every time: Breaking, Added, Changed, Deprecated, Removed, Fixed and Security. Pin a version in CI. [`CHANGELOG.md`](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md) records every change in full; GitHub Releases are tagged `v*` and publish to PyPI.

## 0.22.0 — 4 November 2026

The [opentide VS Code extension](https://marketplace.visualstudio.com/items?itemName=opentidehq.opentide) ships its first release, built on `opentide --json info catalog` and `opentide serve`. Installs are smaller without pandas and numpy, and Windows on Arm gets a wheel.

**Install**

```bash
pip install opentide==0.22.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup vscode --settings --no-generate` to drop the `yaml.schemas` mappings earlier releases wrote.
- Run `opentide generate snippets`, so the snippets complete in the extension's object files.
- Install the recommended [opentide extension](https://marketplace.visualstudio.com/items?itemName=opentidehq.opentide) and reload the window.
- If your code imports pandas or numpy because opentide installed them, add them to your own requirements.
- Re-run `opentide setup ci <provider> --yes`, so the live query job guards the same variable names.
- If a script reads a query finding's `end_column` as a column of `line`, read `end_line` first.

**Breaking**

- **`pip install opentide` no longer installs pandas or numpy.** They were most of the size of every install, and no other dependency pulls them in. Deployed configurations are unchanged ([#747](https://github.com/opentidehq/opentide/issues/747)).

**Added**

- **`opentide --json info catalog` prints the catalogue and its relationships.** It holds every threat, objective and rule with its metadata, platform blocks, deployment state and techniques, the edges between them (`missing: true` when one dangles), the signals and the ATT&CK matrix. A 500-rule workspace answers in about 1.3 s ([#749](https://github.com/opentidehq/opentide/issues/749)).
- **`opentide serve` answers CLI commands from one warm process.** It speaks JSON-RPC on stdio, answering each `run` with the document `opentide --json <argv>` prints. A repeat `validate --file` at 500 rules takes about 0.3 s instead of 1.6 s ([#750](https://github.com/opentidehq/opentide/issues/750)).
- **`setup --plan` lists the files setup would write or remove.** It works on every `setup` subcommand and writes nothing; `setup --yes` with the same flags writes exactly those files ([#751](https://github.com/opentidehq/opentide/issues/751)).
- **`setup` flags answer every question the wizard asks.** `--mcp`, `--skills`, `--plugin`, `--hooks` and `--env` cover the remaining ones, so one command does the whole setup ([#751](https://github.com/opentidehq/opentide/issues/751)).
- **`deploy --uuid` and `--file` select the rules a run reads.** They replace the git-diff default, so `deploy --dry-run --uuid <rule>` plans and renders only that rule. A value that selects no rule fails the run, named in `unmatched` ([#753](https://github.com/opentidehq/opentide/issues/753)).
- **`opentide --json info` lists each platform's tenants.** Each has its `name`, `description`, `strategies`, `manual` and every `$VAR` its setup references, with whether it is set; a value is never printed ([#754](https://github.com/opentidehq/opentide/issues/754)).
- **`OPENTIDE_PROGRESS=json` writes progress events on stderr.** `generate`, `validate`, `validate query`, `deploy --dry-run` and `query` write one ASCII JSON object per line as they go, and stdout still holds one document ([#756](https://github.com/opentidehq/opentide/issues/756)).
- **Every `validate`, `validate query` and `lint` finding carries `end_line`.** SARIF regions carry `endLine` ([#755](https://github.com/opentidehq/opentide/issues/755)).
- **Windows on Arm installs a wheel.** It has the engine compiled in, and replaces a build from the sdist, which needs Rust ([#748](https://github.com/opentidehq/opentide/issues/748)). Use CPython 3.11 or later and `pip install --only-binary cryptography opentide` ([Installation](./installation.md#windows-and-powershell)).

**Changed**

- **The engine is [language-server 0.10.0](https://github.com/opentidehq/language-server/releases/tag/v0.10.0), from crates.io.** The editor no longer reports a placeholder query `opentide new` leaves as a parse error, `opentide/catalog` serves editors the workspace index, and a folder deleted, created or moved under `objects/` is read again.
- **`setup vscode` sets up the opentide VS Code extension.** It recommends `opentidehq.opentide` instead of `redhat.vscode-yaml`, writes no `yaml.schemas` and removes the mappings earlier releases wrote. Snippets are scoped to `yaml,opentide-yaml` ([#752](https://github.com/opentidehq/opentide/issues/752)).
- **A multi-line query finding's `end_column` is on `end_line`.** It is the column after the finding's last character, where it was one past its first character, on its first line. A one-line finding is unchanged ([#755](https://github.com/opentidehq/opentide/issues/755)).

**Fixed**

- **`deploy` and `--changed` no longer fail with `b'HEAD'` before the first commit.** Outside CI, `deploy`, `validate query --changed` and `lint --changed` report, with a warning, that nothing has changed; in CI they still fail, with a readable message ([#769](https://github.com/opentidehq/opentide/pull/769)).
- **`${VAR}` tenant setup values resolve on every platform.** Only Elastic's `api_key` and Sysdig's `api_token` resolved them. A secret that only starts with `$` is used as written, and `doctor` names the variable ([#766](https://github.com/opentidehq/opentide/pull/766), [#768](https://github.com/opentidehq/opentide/pull/768)).
- **`info` counts a duplicate UUID as a load error.** It said `0 load errors` where `validate` reported `duplicate_id`; `info --strict` fails on it ([#766](https://github.com/opentidehq/opentide/pull/766)).
- **Interrupting `opentide generate` no longer leaves an empty schema.** The empty file made every later command fail with `internal` (`JSONDecodeError`); a schema that cannot be parsed is skipped with a warning and rewritten ([#766](https://github.com/opentidehq/opentide/pull/766), [#768](https://github.com/opentidehq/opentide/pull/768)).
- **`setup skills` keeps files you added to a skill's folder.** It no longer deletes the skills when `.claude/skills` links to `.agents/skills` ([#767](https://github.com/opentidehq/opentide/pull/767), [#768](https://github.com/opentidehq/opentide/pull/768)).
- **`setup vscode` keeps your settings' comments and line endings.** It reads files saved with a byte-order mark, which made it fail with `internal`, and leaves a file it cannot edit in place unchanged, with a warning ([#767](https://github.com/opentidehq/opentide/pull/767), [#768](https://github.com/opentidehq/opentide/pull/768)).
- **A `[[modifiers]]` entry with an empty `modifications` table changes nothing.** It failed with `IndexError` ([#747](https://github.com/opentidehq/opentide/issues/747)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0220--2026-11-04) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.22.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.22.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)
- [opentide for VS Code](https://marketplace.visualstudio.com/items?itemName=opentidehq.opentide)

## 0.21.0 — 3 November 2026

Sysdig Secure and Falco become the ninth platform, with Falco conditions checked offline. CoreTIDE files, keys and commands are retired: migrating CoreTIDE content is not a supported path.

**Install**

```bash
pip install opentide==0.21.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide validate --strict` and fix what it reports: it names each retired file and key, and what replaces it.
- If your code imports `DeployTide`, `TideRepo`, `DetectionSystems` or `TideErrors`, import `EnabledPlatforms`, `GitRepository`, `DetectionPlatforms` or `Errors` instead.
- If a script runs `opentide migrate objects` or `opentide export playbook-map`, remove those calls.
- If a Sentinel block's `alert.techniques` lists an id newer than ATT&CK v18, replace it with the v18 id the `sentinel_attack_technique` message names, or remove it.
- Re-run `opentide setup ci <provider> --yes` to pick up the pipeline fixes.
- If you use GitLab, set the `opentide-production` resource group's process mode to `oldest_first`, so production deploys run in pipeline order.
- If another TOML language server runs in your editor, turn it off for `.opentide/configurations/**`, where opentide checks the files.

**Breaking**

- **`global.toml`, `schema.toml` and `systems/` fail every command.** Under `.opentide/configurations/` they were loaded and ignored. `retired_configuration_file` names what replaces each: `paths.toml` for `global.toml`, `platforms/<platform>.toml` for `systems/`, and nothing for `schema.toml`.
- **A platform file is identified by its file name.** `[platform] identifier`, `subschema` and `flags`, and the `[tide]` table, are unknown keys. So are the tables that configured a platform without tenants: declare `[[tenants]]` with `[tenants.setup]`.
  - Splunk: `[setup]`, `[secrets]`, `[defaults]` and table-form `[modifiers]`
  - Carbon Black: `[setup]`, `[secrets]` and `[validation]`
- **`[debug] proxy_enabled` in `deployment.toml` is an unknown key.** It was kept, and ignored, so a CoreTIDE file would load; `[proxy]` already was one.
- **A Splunk block takes the `platform::splunk::1.0` layout only.** The splunk::2.x keys, such as `search`, `cron_schedule` and `advanced`, are unknown keys; they were rewritten onto the current layout before validation.
- **An objective's root `composition` is an unknown key.** It was accepted and dropped: write it as `objective.composition`. The editor schema also drops a rule's `meta:`, which validation already refused.
- **A platform block's `schema` is `platform::<platform>::1.0` or absent.** It took any string, which nothing read; any other value fails validation (`schema_validation`).
- **`opentide migrate objects` is removed, with the migration guide.** It moved CoreTIDE folders but not their content, which opentide never read. `migrate vocab-scope` and `deploy migrate-state` stay.
- **`opentide export playbook-map` is removed.** It read rule fields `rule::1.0` does not have, so it exported nothing; the `openpyxl` dependency goes with it.
- **`configurations.sentinel.alert.techniques` takes ATT&CK v18 ids only.** That is the version Microsoft Sentinel is aligned to. The field accepted any string; any other value fails validation with `sentinel_attack_technique`, whose message names what to use instead ([#686](https://github.com/opentidehq/opentide/issues/686)).
- **CoreTIDE names leave the Python API.** `EnabledPlatforms` replaces `DeployTide` and its aliases, `GitRepository` replaces `TideRepo`, `DetectionPlatforms` replaces `DetectionSystems`, and `Errors` replaces `TideErrors`.

**Added**

- **Sysdig Secure and Falco are the ninth platform, `sysdig`.** A `configurations.sysdig` block is a Falco rule, or a tuning of an existing one, deployed through the Sysdig Secure runtime API with the block's macros and lists expanded. `opentide setup --sysdig` enables it ([#143](https://github.com/opentidehq/opentide/issues/143)).
- **Falco conditions are checked offline.** `validate`, `lint`, the editor and MCP parse a Sysdig block's `condition`, macros and `output`: a syntax error fails validation (`falco_parse_error`), and an unknown field, macro or list is a warning.
- **`opentide lint --changed` lints only the files a run changed.** `--file` lints the files it names, and `setup ci --lint-changed` gates the generated pipelines on `lint --strict --changed`, so strict lint can gate an inherited catalogue.
- **`[skip deploy]` keeps a catalogue-wide change from deploying.** Generated pipelines leave out the live query checks, the deploys and the share when the commit message or the pull or merge request title says `[skip deploy]`, or, on GitHub and GitLab, a `skip-deploy` label is set; validation and `lint` still run.
- **Generated GitLab write-backs push over SSH, or to any URL.** Set `OPENTIDE_PUSH_URL`, or the File variables `OPENTIDE_PUSH_SSH_KEY` and `OPENTIDE_PUSH_SSH_KNOWN_HOSTS`; without them the jobs push to the job-token URL.
- **`validate query --live --check-timeout` bounds each query check.** `--check-timeout SECONDS`, or `OPENTIDE_QUERY_CHECK_TIMEOUT`, sets how long each check waits, on every platform.
- **The editor checks configuration files.** `opentide lsp start` checks each open TOML file under `.opentide/configurations/` as `opentide validate` does, as you type ([#730](https://github.com/opentidehq/opentide/issues/730)).
- **Carbon Black queries are checked against its field catalog.** `validate` and the editor report `cbc_unknown_field`, a warning, for a near miss of a process search field, and suggest the field (`process_nmae` → `process_name`).

**Changed**

- **The engine is [language-server 0.9.1](https://github.com/opentidehq/language-server/releases/tag/v0.9.1), from crates.io.** Its rebuilt server host answers a keystroke in a 500-object workspace in half the time and no longer crashes after an edit next to `日本` or an emoji; VS Code no longer shows each diagnostic twice.
- **Generated pipelines pin opentide once, in `OPENTIDE_VERSION`.** Every job runs `pip install "opentide==$OPENTIDE_VERSION"`, and on GitLab a project or group CI/CD variable of that name overrides the file's.
- **Generated GitLab deploy jobs record deployments.** `deploy_production` deploys to `production` and `deploy_staging` to `staging/mr-$CI_MERGE_REQUEST_IID`, one environment per merge request, so GitLab keeps a deployment history.
- **`generate templates` writes platform templates into the workspace.** Each is `.opentide/templates/platforms/<platform>.template.yaml`, which `generate snippets` reads; they were written into the installed package, which failed on a read-only install.

**Fixed**

- **Rule pages show each platform block's own status and severity.** Rule pages, the rules index and MCP showed `STAGING` and `Informational` for every rule; they read each block's `status` and `response.alert_severity`.
- **Promotion rewrites only `configurations.<platform>.status`.** It keeps the file's line endings, and refuses an aliased status rather than half-writing a set of files.
- **One slow query no longer marks a tenant unreachable.** In `validate query --live` it ended the run as "Cannot reach the tenant"; it fails only that rule's check, and Splunk's gateway page is reported as a gateway timeout.
- **The deploy loaders refuse every key `validate` refuses.** They had dropped Splunk `scheduling`, Sentinel `grouping`, SentinelOne `condition` and others.
- **Generated GitLab validate jobs work on GitLab Runner 18.9.** The job failed after both gates passed, with `only one file can be sent as raw`; it declares one merged Code Quality report.
- **GitLab pipelines start when a query job has `rules:`.** GitLab refused to create them (`'generate' job needs 'validate_query_sentinel' job`); every need of a job with `rules` is optional.
- **The generated `document` job keeps the pages it renders.** They were lost with the runner; GitLab, GitHub and Azure keep them as the `opentide-docs` artifact.
- **`lint --fix` keeps a file's `.debug` suffix.** It dropped the suffix when renaming a `*.debug.yaml` fixture, which put the fixture in the catalogue and in the next deploy.
- **`setup repo` adds its ignore lines to an existing `.gitignore`.** It skipped the file, leaving the sharing cache and `opentide-reports/` committable.
- **Sentinel deploy sends ATT&CK sub-techniques in `subTechniques`.** Deploy reduced each technique to its parent, so `T1556.009` went out as `T1556` ([#686](https://github.com/opentidehq/opentide/issues/686)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0210--2026-11-03) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.21.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.21.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.20.1 — 3 November 2026

A `visibility.toml` log source is one dataset, named by its `name`, and can declare its columns for the query checks. The dataset lists of 0.20.0 were a defect of `visibility::1.0`, corrected here in place.

**Install**

```bash
pip install opentide==0.20.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If your `visibility.toml` uses the 0.20.0 lists (`tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views`, `ecs`), rewrite it with one `[[logsources]]` per table, sourcetype or index pattern, named after it ([Upgrading from 0.20.0](./configuration.md#upgrading-from-0200)).
- If your `visibility.toml` declares `indexes`, `macros`, `data_views` or `ecs`, remove them: they cannot be declared.
- If you rewrote `visibility.toml`, update the signals' `data.logsources` references to the log sources' names.

**Breaking**

- **Each `visibility.toml` log source is one dataset.** Its `name` is its KQL table, Splunk sourcetype or Elastic index pattern, and `columns` gives each column's `type` and an optional `description`. The 0.20.0 keys fail validation and say what to do instead; there is no migration command ([#718](https://github.com/opentidehq/opentide/issues/718)).

**Added**

- **`lint.toml` sets the filename convention per object kind.** `[filenames.threats]`, `[filenames.objectives]` and `[filenames.rules]` take `style` and `pattern`; a kind without a table follows `[filenames]` ([#721](https://github.com/opentidehq/opentide/issues/721)).

**Changed**

- **The engine is [language-server 0.7.1](https://github.com/opentidehq/language-server/releases/tag/v0.7.1), from crates.io.** Its query checks know the columns a log source declares:
  - a near miss of a declared column is `kql_unknown_column`
  - an operator the column's type does not support is `kql_type_mismatch`
  - hover and completion show the declared columns
  - a typo in a Defender table name fails `validate` again
  - lower-case table names are checked
  - column patterns in `project-reorder`, `project-away` and `project-keep` parse
- **Generated docs and editor schemas use ATT&CK 20.0 group labels.** `[Enterprise] APT28` replaces `[Mobile] APT28`, and `threat::1.0` accepts the same values.

**Fixed**

- **`lint` checks a file that starts with a byte-order mark.** None of its queries was analysed, so `lint` reported nothing for it while `validate` did ([#719](https://github.com/opentidehq/opentide/issues/719)).
- **MCP `validate_query` reads `visibility.toml`.** It reports what `opentide validate query` reports, reading the file afresh on every call ([#720](https://github.com/opentidehq/opentide/issues/720)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0201--2026-11-03) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.20.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.20.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.20.0 — 2 November 2026

`validate` catches what a deploy would reject: it compiles every rule, and the query checks know the documented tables and their columns.

**Install**

```bash
pip install opentide==0.20.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide validate --strict` and fix what it reports: a rule the platform compiler cannot build, or a query with a near miss of a documented column, fails it. `--queries warn` reports the queries as warnings while you fix them.
- If a script reads `VALIDATION_ERROR_RAISED` or `VALIDATION_WARNING_RAISED`, read the exit code instead.
- If your code calls `validation_exit_code` or `exit_on_validation_errors`, call `validation_outcome(failed=, warned=)` or `report_outcome(report)` instead.

**Breaking**

- **`validate` fails a rule a platform compiler cannot build.** It compiles each rule a deploy would compile, with the dry run's offline compiler, and reports its code (`compile_missing_field`, ...) at the key at fault, so a rule that validates deploys ([#660](https://github.com/opentidehq/opentide/issues/660)).
- **The `VALIDATION_ERROR_RAISED` and `VALIDATION_WARNING_RAISED` flags are gone.** `validate query --live` no longer sets them: read its exit code, which is unchanged, or `report_outcome(report)` from Python ([#673](https://github.com/opentidehq/opentide/issues/673)).
- **`validation_exit_code` and `exit_on_validation_errors` are removed.** `validation_outcome(failed=, warned=)` and `report_outcome(report)` replace them.

**Added**

- **A `visibility.toml` log source names the datasets it fills.** By its `system` it takes `tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views` or `ecs`, which `validate`, `lint`, `tui` and the language server read. Undeclared-dataset warnings are opt-in ([#695](https://github.com/opentidehq/opentide/issues/695)).
- **`lint.toml` sets the filename convention.** `[filenames]` takes `style` (`slug`, `name` or `none`) and `pattern`, and a stem that misses the pattern is a `filename_pattern` finding ([#699](https://github.com/opentidehq/opentide/issues/699)).
- **`setup skills --plugin` enables the opentidehq/skills Agent Plugin.** It adds the plugin to `.claude/settings.json`, so Claude Code offers the skills and the MCP server to whoever opens the project ([#431](https://github.com/opentidehq/opentide/issues/431)).
- **The MCP server finds the workspace under an Agent Plugin.** Started in a plugin's directory, it served an empty catalogue; it serves the workspace `OPENTIDE_REPO_ROOT` names, the plugin directory when it is a workspace, or else the host's project directory ([#431](https://github.com/opentidehq/opentide/issues/431)).
- **`setup mcp --generic` writes an Agent Plugins 1.0.0 `mcp.json`.** It validates against the Agent Plugins schema, so a plugin can ship it unchanged ([#431](https://github.com/opentidehq/opentide/issues/431)).
- **`opentide lint` reports the engine's ECS findings.** `ecs_unknown_field`, `ecs_type_mismatch` and the undeclared-dataset warnings appear with the other query warnings, where `lint` dropped them.

**Changed**

- **The engine is [language-server 0.7.0](https://github.com/opentidehq/language-server/releases/tag/v0.7.0), from crates.io.** Its query checks know the documented tables and their columns:
  - `kql_unknown_column`, `kql_type_mismatch`, `spl_unknown_datamodel_field` and `ecs_type_mismatch` are errors
  - under the `sentinel` profile an unknown table is a warning
  - the Azure Monitor Logs, Defender XDR and ASIM tables are known
  - more KQL forms that Kusto accepts parse
  - KQL hover shows column descriptions
- **`validate query --live` runs on the `opentide query` runners.** Each query is checked as deploy sends it, so a Sentinel or Defender rule's tenant exclusions are in the checked query ([#673](https://github.com/opentidehq/opentide/issues/673)).

**Fixed**

- **Deploy errors no longer say "MDR".** They name the key at fault: a Splunk rule without its block fails with `The rule has no configurations.splunk block` ([#617](https://github.com/opentidehq/opentide/issues/617)).
- **`doctor` no longer reports fresh templates as stale.** In a workspace that sets `[metadata].required` in `lint.toml`, `templates_fresh` asked you to regenerate templates you had just generated.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0200--2026-11-02) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.20.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.20.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.19.0 — 29 October 2026

The language server and its query engine ship in every install, so `validate` checks every rule query offline, `lint` checks query style and `opentide lsp start` serves editors. `opentide query` runs a query on a tenant.

**Install**

```bash
pip install opentide==0.19.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide validate --strict` and fix what it reports: a rule whose query the platform would reject fails it.
- Run `opentide generate schemas` to write the language server's catalogs.
- If a script relied on `opentide validate query` refusing without `--live` (exit `2`), or on `--platform` being required there, pass `--live`: without it the command checks every query offline.
- If you install opentide where no wheel is built (free-threaded Python, another platform), install a Rust toolchain first: pip builds the sdist.

**Breaking**

- **`validate` checks every rule query.** A query the platform would reject fails `validate` (exit `1`); `--queries warn` reports it as a warning, and `--queries off` skips queries ([#685](https://github.com/opentidehq/opentide/issues/685)).
- **`validate query` without `--live` checks queries offline.** It checks every rule query (exit `1` on an error) instead of refusing with exit `2`, and `--platform` is not required; `--live` is unchanged.
- **MCP `validate_query` without `live` checks offline.** `valid` is `true` or `false` instead of `null`; a SentinelOne query and an empty one are still refused, with `valid: null`.
- **Wheels are built per platform.** Linux, macOS and Windows x64 get a prebuilt wheel; elsewhere, including free-threaded Python, pip builds from the sdist and needs a Rust toolchain.

**Added**

- **The analysis engine ships in every install.** KQL for Sentinel and Defender, SPL, ES|QL, EQL, Kibana KQL, Lucene and Carbon Black's Lucene are checked offline, with no extra and no second package ([#332](https://github.com/opentidehq/opentide/issues/332)).
- **`lint` checks query style.** Its `queries` check reports the engine's warnings and notes, such as slow query shapes (`kql_where_not_first`, `spl_wildcard`) ([#685](https://github.com/opentidehq/opentide/issues/685)).
- **`validate query --file` takes query files.** It checks `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` and `.lucene` files offline; `--strategy` and `--wide` need `--live`.
- **`opentide lsp start` serves editors.** It gives diagnostics, hover, completion and highlighting for Tide objects and their queries, and for `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` and `.lucene` files; `opentide tui` shows what it reports.
- **`opentide query` runs a read-only query on a platform's tenants.** It returns the rows, and MCP `run_query` and `DetectionRule.run_query` do the same ([#665](https://github.com/opentidehq/opentide/issues/665)).
- **`opentide deploy` reports each rule as it is sent.** It prints one line per rule as it finishes, with the platform's own message for a failure, and lists the rules it never reached ([#675](https://github.com/opentidehq/opentide/issues/675)).
- **`opentide explain` and `doctor` cover the engine.** `explain` has a page for every engine code (`kql_unknown_table`, `spl_parse_error`, ...), and `doctor` checks the engine and the language server's catalogs.

**Changed**

- **The engine is [language-server 0.6.0](https://github.com/opentidehq/language-server/releases/tag/v0.6.0), from crates.io.** The sdist builds from published crates.
- **A real deploy prints the plan before it sends anything.** Its outcome line always counts `failed` and `not attempted`.
- **Elastic advisories use the specification's codes.** `lookback_long`, `threshold_lookback`, `risk_band` and the others replace event names such as `elastic_lookback_long_warning`, which `legacy_event` keeps until the release after next ([#637](https://github.com/opentidehq/opentide/issues/637)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0190--2026-10-29) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.19.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.19.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.18.0 — 27 October 2026

Configuration files are validated, rule `severity` uses the alert labels, and the CLI gains commands for authoring and for agents: `new`, `doctor`, `explain`, `tui` and `commands`.

**Install**

```bash
pip install opentide==0.18.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide validate --strict` and fix what it reports: a file that loaded under 0.17.2 can fail, and the error names the file and the key.
- If a rule's `severity` is an incident-scale value, replace it with an alert label (`Substantial incident` → `High`).
- If you pin `mcp` 1.x beside opentide, move the pin to `mcp>=2.3,<3`.
- Run `opentide setup ci <github|gitlab|azure> --yes`, so the pipeline keeps the SARIF and Code Quality reports.
- Run `opentide generate` to refresh schemas and templates, and `opentide setup skills` to refresh agent instruction files.
- If a pipeline tests for exit `1` on a usage error, test for non-zero, or read `failure.code` from `--json`.
- If a script matches indented `--json` text (`grep '"ok": true'`), parse it (`jq .ok`) or set `OPENTIDE_JSON_INDENT=2`.
- If a script reads `failure.code` `command_failed` when findings fail a run, read `issues_found`.
- If your code reads a signal's objective from `parent` or `SignalRecord.parent_uuid` and `parent_name`, read `owner`, `owner_uuid` and `owner_name`.

**Breaking**

- **Configuration files are checked when a command reads them.** An unknown key or a wrong type in `.opentide/configurations/` fails the command, naming the file and the key, and `opentide validate` runs the same check ([#374](https://github.com/opentidehq/opentide/issues/374)). For example:
  - a Splunk `schedule_offset = "5"` must be `5`
  - a CoreTIDE `documentation.toml` must drop `skip_vocabularies`, `model_cover_pages` and `[titles]`
  - `sharing.toml`'s `api_key` names an upper-case variable (`${MISP_KEY}`)
- **Usage errors a command detects exit `2`, not `1`.** An unknown `info` section, an invalid `validate --type` and a `setup` prompt with no terminal are among them, as the exit codes page already said.
- **`failure.code` is `issues_found` when findings fail a run.** It was `command_failed`, for `validate`, `lint --strict` and `info --strict`.
- **`--json` prints one compact line unless stdout is a terminal.** A script that parses the document is unaffected; one that matched indented text is not.
- **A signal's objective is `owner`, not `parent`.** `SignalRecord.parent_uuid` and `parent_name` are `owner_uuid` and `owner_name`, and `parent` holds the authored parent signal ([#585](https://github.com/opentidehq/opentide/issues/585)).

**Added**

- **`opentide new` scaffolds a threat, objective or rule.** The file validates at once, and `opentide lint` lists each placeholder until it is replaced.
- **`opentide doctor` checks the installation and the workspace.** It checks the workspace's integrations too, with a fix per check, and exits `1` when a check fails.
- **`validate --fix` applies safe fixes, and `--watch` re-validates on save.** A safe fix replaces a vocabulary value that differs from a valid one only in case, spaces, `-` or `_`, and nothing else; `--fix --dry-run` prints the diff.
- **`opentide explain <code>` explains any diagnostic or failure code.** It is also an MCP tool.
- **`opentide tui` browses the catalogue in a terminal.** It shows each object with its diagnostics and coverage, and runs `validate`, `generate` and `deploy --dry-run` from its command palette.
- **`opentide info vocab` reports a vocabulary's revisions.** It lists the contract revisions and the schema fields pinned to the vocabulary ([#523](https://github.com/opentidehq/opentide/issues/523)).
- **`opentide commands` lists the command tree for agents.** `opentide --json commands` gives the whole tree in one document, with each command's JSON output schema.
- **Findings carry a location and a fix.** Every finding has `path`, `line`, `column`, `help`, `fix` and `explain`, in the CLI, in `--json` and in the MCP tools.
- **Findings become CI annotations, SARIF and Code Quality reports.** In CI, `validate` and `lint` write annotations and a job summary, and `--format sarif|codequality` writes the reports, which regenerated pipelines keep.
- **`lint.toml` sets the metadata keys lint requires.** It also sets each check's severity ([#489](https://github.com/opentidehq/opentide/issues/489)).
- **Elastic tenants declare their stack version.** `[tenants.setup] version` takes `"8.19"`, `"9.5"` or `"serverless"`, as a string, and the language server checks ES|QL against it ([#661](https://github.com/opentidehq/opentide/issues/661)).

**Changed**

- **Rule `severity` uses the alert labels, `Informational` to `Critical`.** They are the labels of `response.alert_severity`; threats keep the incident scale ([opentidehq/specifications#60](https://github.com/opentidehq/specifications/pull/60)).
- **The CLI's output follows one grammar.** Findings print as code frames, and every `--json` run prints one document, usage errors included; a script that matched the human output should read `--json`.
- **The MCP server needs `mcp` 2.x.** `opentide mcp start` runs on `mcp>=2.3,<3`; with `mcp` 1.x installed it exits with the upgrade instruction on stderr instead of a traceback ([#581](https://github.com/opentidehq/opentide/issues/581)).
- **The CLI starts faster.** `opentide --version` answers in about 30 ms, and `--help` and shell completion list the commands without loading the engine.
- **`opentide` depends on Textual, for `opentide tui`.** It loads only when the UI opens, so start-up is unchanged.

**Fixed**

- **Deploy no longer stops on a rule without platform blocks.** It failed every deploy with `'NoneType' object is not iterable`; `opentide new rule` without `--platform` writes that shape.
- **Object files in subfolders are ignored everywhere, as deploy did.** `validate`, `lint`, docs and sharing treated them as objects; each is a `nested_object_file` warning, which fails `validate --strict` ([#584](https://github.com/opentidehq/opentide/issues/584)).
- **A rule the production deploy promotes is shared that run.** It was not shared until it changed again; regenerated pipelines run the share job after the production deploy ([#590](https://github.com/opentidehq/opentide/issues/590)).
- **A signal keeps its authored `parent`.** Its objective overwrote it, and `validate` reports two signals that share a UUID ([#585](https://github.com/opentidehq/opentide/issues/585)).
- **Elastic ES|QL and EQL checks read past comments and strings.** A comment before `FROM` no longer sends the check to the wrong indices ([#616](https://github.com/opentidehq/opentide/issues/616)). Empty durations, non-ASCII digits and malformed `api_key` references are reported ([#589](https://github.com/opentidehq/opentide/issues/589)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0180--2026-10-27) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.18.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.18.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.17.2 — 22 October 2026

`uv` installs resolve a current boto3 again, and a Splunk tenant behind a proxy that answers with an HTML page fails with a message naming the proxy and the `NO_PROXY` entry to add.

**Install**

```bash
pip install opentide==0.17.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If your pipeline replaces opentide's Splunk handler with `verify=not ssl_enabled`, delete that step: with `ssl = false` it turns certificate verification on.
- If you deleted it, list the Splunk host in `NO_PROXY` and `no_proxy`: the patch worked only by skipping the proxy.

**Added**

- **Each Splunk connection logs the route it takes.** `splunk_tenant_route` names the proxy it goes through, or `direct`.

**Fixed**

- **A proxy's page is named, not parsed as Splunk's.** It failed as `xml.etree.ElementTree.ParseError: mismatched tag`, which read as a certificate problem; the error names the Splunk address, the page title, the proxy and `NO_PROXY=<host>` ([Splunk answers with HTML instead of XML behind a proxy](./troubleshooting.md#splunk-answers-with-html-instead-of-xml-behind-a-proxy)).
- **`uv` installs resolve a current boto3 again.** python-dateutil 3.0.0 led `uv` to install boto3 `0.0.3`, so the Carbon Black SDK failed to import (`No module named 'six.moves'`). opentide requires `boto3>=1.35`; `pip` was not affected.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0172--2026-10-22) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.17.2/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.17.2)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.17.1 — 21 October 2026

A tenant's `ssl` applies to every call made to it, on every platform, so Splunk works again with `ssl = false`. Splunk rules with a `trigger` block deploy.

**Install**

```bash
pip install opentide==0.17.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If your pipeline patches the installed `opentide/platforms/splunk/client.py` or `deployer.py` with `sed`, delete those steps: after upgrading, their patterns match nothing.

**Fixed**

- **A Splunk tenant with `ssl = false` skips certificate verification.** 0.17.0 verified it anyway, so every `deploy` and `validate query --live` against a self-signed Splunk failed on the TLS handshake. Each tenant keeps its own setting, and `TIDE_SPLUNK_SSL_ENABLED` is no longer used.
- **Defender for Endpoint and Sentinel apply `ssl` to every request.** Their Entra ID token request, and Defender's Graph API fallback, verified certificates whatever `ssl` said.
- **An unset `ssl = "$VAR"` is refused, naming the tenant.** On every platform but Splunk it reached the HTTP client as a CA bundle path, failing with `Could not find a suitable TLS CA certificate bundle`.
- **Splunk rules with a `trigger` block deploy.** `trigger.condition`, `comparator` and `threshold` are sent as `alert_type`, `alert_comparator` and `alert_threshold`; Splunk refused the old names with `Argument "quantity" is not supported by this handler`.
- **A refused Splunk request reports Splunk's reason.** The error read `HTTP 400 Bad Request -- b''`.
- **A tenant's `ssl` must be a boolean.** `ssl = "$SPLUNK_SSL"` read as text, and the text `false` verified too. `true`/`false`, `yes`/`no`, `on`/`off` and `1`/`0` read as booleans on every platform, and any other value fails, naming the tenant ([Configuration → TLS verification](./configuration.md#tls-verification)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0171--2026-10-21) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.17.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.17.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.17.0 — 20 October 2026

Deployment plans are removed: a deploy names the status strategy it carries out, and a tenant lists the strategies it accepts. Each old setting fails with a message naming its replacement.

**Install**

```bash
pip install opentide==0.17.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Replace `--plan` with `--strategy`: `--plan STAGING` becomes `--strategy PREVIEW`, `--plan PRODUCTION` becomes `--strategy RELEASE`, and `--plan FULL`, or no plan, becomes `--strategy PREVIEW --strategy RELEASE --all`, with `--keep-deprecated` to also disable or delete the rules that map to `DISABLEMENT` or `DELETION`.
- Unset `DEPLOYMENT_PLAN`.
- Replace each tenant's `deployment` key in `.opentide/configurations/platforms/*.toml`: `"STAGING"` becomes `strategies = ["PREVIEW"]`, `"PRODUCTION"` becomes `strategies = ["RELEASE"]`, `"ALWAYS"` is removed, and `"MANUAL"` becomes `manual = true`.
- Run `opentide setup ci <github|gitlab|azure> --yes`, so deploy jobs pass `--strategy`, the live query check reads only the changed rules, and GitLab merge request pipelines start.
- If your code uses `DeploymentStrategy` or passes `deployment_plan`, pass `strategies` instead.
- Run `opentide generate` to refresh the editor schemas' objective and signal labels.

**Breaking**

- **`--strategy` replaces `--plan`.** A deploy names the status strategy it carries out, `PREVIEW` in the pull or merge request job and `RELEASE` on the default branch, and deploys the changed rules whose status maps to it. `STAGING` and `PRODUCTION` are default status names, not strategies ([Statuses, strategies and tenants](./concepts/statuses-and-strategies.md)).
- **`--plan` and `DEPLOYMENT_PLAN` exit `2`, naming the replacement.** Generated inflight jobs no longer export `DEPLOYMENT_PLAN`.
- **Tenants declare `strategies` and `manual`.** `strategies` takes `PREVIEW`, `RELEASE` or both (the default when omitted), and `manual = true` takes only the rules that name the tenant. The `deployment` key fails to load; the [migration table](./concepts/statuses-and-strategies.md#moving-from-deployment-plans-016-and-earlier) maps each old value.
- **Deploy reads the changed rules, by CI context.** In CI that is the pull or merge request or the push; outside CI it is the last commit, where deploy read every rule file. `--all` reads every rule file and leaves out the rules that map to `DISABLEMENT` or `DELETION`, which `--keep-deprecated` includes.
- **`validate query --live` checks each rule where deploy sends it.** It reached every tenant; `--json` reports `strategies` instead of `plan`.
- **`DeploymentStrategy` is removed from the SDK.** Deployers and validators take `strategies`, and `rule.deploy(..., strategies=None)` deploys by the rule's own status.
- **The `mdr_skipped_for_plan` log event is `rule_skipped_for_strategy`.** It carries the rule's `strategy`, the run's `run_strategies` and `deployed_by`.

**Added**

- **`deploy --dry-run --json` lists the tenants each rule would reach.** Every deploy result names its `strategies`.
- **`validate query --changed`, `--file` and `--uuid` narrow the live check.** `--changed` checks the rules a deploy of the same run reads, and `--file` and `--uuid` the rules you select ([Which rules are checked](../cli/validate.md#which-rules-are-checked)).
- **`OPENTIDE_PROXY` sets the global `--proxy`.** Hosts in `NO_PROXY` are reached directly, so one deploy reaches a cloud tenant through the proxy and an internal Splunk without it ([CI/CD → Behind a proxy or a private CA](./workflows/ci-cd.md#behind-a-proxy-or-a-private-ca)).

**Fixed**

- **Generated pipelines check only the queries a run changed.** They sent the whole catalogue to the tenant on every run, most of an hour for a few hundred Splunk rules; they pass `--changed` and fetch full history.
- **Generated GitLab merge request pipelines start.** Without `workflow:rules` GitLab refused every one, so the staging deploy never ran; a branch without a merge request no longer runs a pipeline.
- **`opentide generate` no longer warns once per objective.** `Vocab identifier not found` and `Vocab parameter not found` are gone: an objective's priority is printed as authored.
- **`--proxy` and `OPENTIDE_PROXY` set the lowercase proxy variables too.** An inherited `http_proxy` used to override them.
- **GitHub pull requests from forks diff from the merge ref.** `deploy` and `validate query --changed` failed with `Could not find git ref origin/<branch>`.
- **GitLab runs with no previous tip diff from HEAD's parent.** A manual run, a schedule or a branch's first push failed with `No Source Commit Found`.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0170--2026-10-20) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.17.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.17.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.16.1 — 20 October 2026

The SDK class is spelled `Opentide`, and `OpenTide` still imports with a deprecation warning; CLI help, docs, generated pipelines and the MCP server name spell the project in lowercase.

**Install**

```bash
pip install opentide==0.16.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **CLI help, docs, pipelines and MCP spell the project `opentide`.** Generated pipelines say `name: opentide` with `opentidehq` as the GitHub owner, and the MCP server is named `opentide`, not `OpenTide`. The `OPENTIDE_*` environment variables and the Elastic rule tag `OpenTide` are unchanged.

**Deprecated**

- **The SDK's `OpenTide` spelling is deprecated: use `Opentide`.** `Opentide` and `OpentideRegistry` replace `OpenTide` and `OpenTideRegistry`, and these old paths return the same objects with a `DeprecationWarning` until a later release removes them:
  - `from opentide import OpenTide`
  - `opentide.core.OpenTide`
  - `opentide.core.registry.OpenTide` and `OpenTideRegistry`

**Fixed**

- **`setup skills` accepts the catalogue's source in any letter case.** A manifest that spelled itself `OpenTideHQ/skills` no longer logs `Skills manifest source rejected` on every run.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0161--2026-10-20) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.16.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.16.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.16.0 — 19 October 2026

`pip install opentide` is the only install and carries every vendor SDK, so generated pipelines validate Sentinel live. They stop a pull request from redirecting platform credentials, and technique pins follow ATT&CK 20.0.

**Install**

```bash
pip install opentide==0.16.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup ci <github|gitlab|azure> --yes` for the security fix: live query validation and the staging deploy take tenant configuration from the default branch.
- Run `opentide generate schemas`, so the editor offers the ATT&CK 20.0 techniques.
- Run `opentide validate` to list every broken object: a missing or unknown `metadata.schema` fails validation, and a malformed object file stops `generate`.

**Breaking**

- **`generate` exits `1` when a phase logs an error.** A malformed object file stops the run, where it used to be skipped, and the result names the phase and the object; with `--json`, `generate docs` and `generate exports` print one result document instead of a traceback ([#579](https://github.com/opentidehq/opentide/issues/579)).
- **A missing or unknown `metadata.schema` fails validation.** `validate` reports `schema_missing` or `schema_validation` at `metadata.schema` instead of checking the latest revision, and the SDK's `load_rule_from_dict` and `Opentide.Rules` raise `SchemaMissingError` or `SchemaIdentifierError` instead of defaulting to `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).

**Added**

- **`opentide --version` prints the installed version.** `--version` or `-V` prints `opentide <version>` before the workspace is resolved, so a CI job can log which opentide it installed ([#187](https://github.com/opentidehq/opentide/issues/187)).
- **`opentide setup platforms` takes `--elastic`** ([#414](https://github.com/opentidehq/opentide/issues/414)).
- **`opentide lint` findings carry `uuid`, `severity` and `yaml_line`.** The JSON change is additive and `--strict` exit codes are unchanged; the human line reads `[check/severity] path[:line]: message` ([#488](https://github.com/opentidehq/opentide/issues/488)).
- **`validate` flags blocks for platforms the workspace has not enabled.** An imported Splunk block in a Sentinel-only repository, for example, gets one `platform_not_enabled` warning naming the `opentide setup platforms` flag; it does not fail `--strict`, and the block still does not deploy ([#413](https://github.com/opentidehq/opentide/issues/413), [#410](https://github.com/opentidehq/opentide/issues/410)).

**Changed**

- **`pip install opentide` installs every vendor SDK.** The optional extras are gone, and `pip install 'opentide[sentinel]'` still installs, with a warning about the unknown extra. Live Sentinel query validation in generated pipelines no longer fails with `No module named 'azure'` ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Sentinel deploys through the ARM REST API directly.** Request bodies and the API version are unchanged, and an ARM error fails the rule with `SentinelApiError`, naming the HTTP status, error code and message ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Technique pins move to `att&ck::1.2`, ATT&CK 20.0.** Elastic and Sentinel tactics follow ATT&CK's split of Defense Evasion into Stealth and Defense Impairment, both of which Sentinel deploys as `DefenseEvasion` ([#568](https://github.com/opentidehq/opentide/issues/568)).
- **Signal `effort` is an integer score from 1 to 10.** It is no longer pinned to the `efforts` vocabulary ([#111](https://github.com/opentidehq/opentide/issues/111)).

**Removed**

- **`opentide.extraction.malapi` is no longer part of the package.** It scraped malapi.io on import and needed an undeclared BeautifulSoup dependency; it lives on as a maintainer script ([#539](https://github.com/opentidehq/opentide/issues/539)).

**Fixed**

- **Techniques added since ATT&CK v17 validate again.** ATT&CK 19.2 is restored at `att&ck::1.1`, so T1685–T1690, T1059.013 and the other v18 and v19 techniques pass, and the IDs MITRE has since revoked still validate ([#568](https://github.com/opentidehq/opentide/issues/568)).
- **SDK validation checks a rule against its `metadata.schema` revision.** `Opentide.validate_rule()` and `validate_raw_payload()` no longer fail a valid `rule::1.1` rule with `metadata.reviewed` as `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).
- **`share push` selects promoted rules by their platform status.** A sharing block's `rule_statuses` match the status of the rule's enabled platform blocks, which promotion rewrites, not the root `status`, which promotion leaves at `STAGING` ([#583](https://github.com/opentidehq/opentide/issues/583), [#590](https://github.com/opentidehq/opentide/issues/590)).
- **`generate extract sentinel` imports near-real-time rules.** ARM lists them as kind `NRT`, and every one was skipped as an unsupported kind ([#577](https://github.com/opentidehq/opentide/issues/577)).
- **Elastic deploy and `validate query --live` work again.** Both failed with `filter_shape`, `type_block` or `index_list` before reaching Kibana; optional fields set to `null` are treated as absent ([#557](https://github.com/opentidehq/opentide/issues/557), [#561](https://github.com/opentidehq/opentide/pull/561)).
- **Elastic `kill-process` and `suspend-process` actions deploy without a `field`.** They compile to Kibana's default `config`, so such a rule, including one `generate extract elastic` wrote, no longer fails deploy and preview with HTTP 400 ([#558](https://github.com/opentidehq/opentide/issues/558), [#562](https://github.com/opentidehq/opentide/pull/562)).
- **`generate extract elastic` no longer writes `negate: null`.** A `threat_match` mapping entry where Kibana omits `negate` is written without it, and an explicit `false` is kept ([#559](https://github.com/opentidehq/opentide/issues/559), [#563](https://github.com/opentidehq/opentide/pull/563)).
- **Sentinel and Elastic accept compound durations such as `1h10m`.** Units go in `d`, `h`, `m`, `s` order, each at most once and lower case, as in the official Azure-Sentinel rules, and Sentinel shorthand also accepts seconds ([#560](https://github.com/opentidehq/opentide/issues/560), [#564](https://github.com/opentidehq/opentide/pull/564)).
- **Elastic reads every managed rule, not only the first 1,000.** `ElasticClient.find_managed` pages through all of them and raises `requests.HTTPError` when a page fails, instead of returning the rules collected so far ([#566](https://github.com/opentidehq/opentide/issues/566), [#569](https://github.com/opentidehq/opentide/pull/569)).
- **Splunk correlation searches carry the rule's own techniques.** They list its `techniques` with those inherited from its objective, de-duplicated, and compiling a rule outside the catalogue index (SDK, MCP `deploy_rule`) no longer crashes ([#567](https://github.com/opentidehq/opentide/issues/567), [#570](https://github.com/opentidehq/opentide/pull/570)).
- **An unreachable tenant fails the live check instead of crashing.** `validate query --live` and MCP `validate_query` report a refused connection, DNS, TLS, timeout or proxy failure as a failed check with exit `1`, naming the `tenant` and `host`, where five platforms printed a traceback.
- **`validate` reports a `metadata` that is not a mapping.** It is a shape error at `metadata`, where the default `opentide validate` crashed with `AttributeError`.
- **The ATT&CK Navigator layer is written in a fixed order.** Techniques sort by ID and each comment lists threats, then rules, by name, so renaming or moving files no longer reshuffles it; expect a one-time reorder diff the first time you regenerate it ([#521](https://github.com/opentidehq/opentide/issues/521)).
- **`migrate objects` renames `Objects/` to `objects/` on macOS and Windows.** On a case-insensitive filesystem the migrated folders stayed inside `Objects/`, so a Linux checkout found no objects; re-running it repairs such a repository ([#522](https://github.com/opentidehq/opentide/issues/522)).
- **`setup skills` writes `opentide mcp start`, not `opentide-mcp`.** The `AGENTS.md` and `CLAUDE.md` it writes named the command 0.12.0 removed ([#460](https://github.com/opentidehq/opentide/issues/460)).
- **Advice for a disabled platform names a flag that exists.** The advice deploy and a live `validate query` print when they skip a disabled platform names `--defender-for-endpoint`, `--sentinel-one` or `--carbon-black-cloud`, and so does the Defender import advice ([#414](https://github.com/opentidehq/opentide/issues/414)).

**Security**

- **Generated pipelines take tenant configuration from the default branch.** Live query validation and the staging deploy use the default branch's `.opentide/configurations`, so a pull request cannot send platform credentials to a host it chose; a platform with no tenant there yet skips its live query step ([#565](https://github.com/opentidehq/opentide/pull/565)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0160--2026-10-19) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.16.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.16.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.15.0 — 16 October 2026

Vendor rule ids move out of rule YAML into committed deployment state shards, and generated pipelines retire rules and persist their write-backs. Elastic Security joins as a supported platform.

**Install**

```bash
pip install opentide==0.15.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Replace `.opentide/states/` with `.opentide/states/sharing.jsonl` in `.gitignore`, since `opentide deploy migrate-state` refuses an ignored destination.
- Run `opentide deploy migrate-state` to move vendor rule ids from rule YAML into `.opentide/states/deployment/`.
- Run `opentide validate --strict`, which fails a rule still carrying a vendor id key with `external_id_in_rule`.
- Commit the stripped rules together with `.opentide/states/deployment/` before the next deploy.
- Run `opentide setup ci <provider> --yes`, so generated pipelines retire rules, deploy from the default branch's latest deployment state and persist write-backs.

**Breaking**

- **Vendor rule ids move from rule YAML to deployment state.** `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` leave Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab and Carbon Black blocks; Defender, SentinelOne and CrowdStrike ids live in `.opentide/states/deployment/<uuid>.json`, one committed shard per rule ([deployment state spec](https://github.com/opentidehq/specifications/blob/main/specs/deployment-state.md), [#396](https://github.com/opentidehq/opentide/issues/396)).
  - `validate` fails a rule that keeps a key: `external_id_in_rule`.
  - `deploy` refuses such a rule on every platform, before any HTTP call.
  - With neither key nor shard, deploy creates a second remote rule.
- **Deploy writes vendor ids to the shard, not the rule.** A create records the id and logs `external_id_recorded`, and is refused with `deployment_state_ignored` while git ignores the shard directory; a `DELETION` or `DISABLEMENT` with no entry warns `external_id_missing` and calls nothing. `opentide.deployment.ExternalIdHelper` is removed ([#396](https://github.com/opentidehq/opentide/issues/396)).
- **Non-production CI deploys refuse to create untracked vendor rules.** In CI, a deploy whose plan is not `PRODUCTION` refuses to create a Defender for Endpoint, SentinelOne or CrowdStrike rule with `deployment_state_unpersisted`, since only the production job commits shards. A pipeline that commits `.opentide/states/deployment/` itself passes `opentide deploy --persist-state-externally` ([#554](https://github.com/opentidehq/opentide/issues/554)).
- **A shard not in canonical form refuses its rule.** A file name other than the rule's lowercase uuid, a mismatched `object_uuid` or a second file for the same rule is `deployment_state_uuid_mismatch`, and a tenant key with surrounding spaces is `deployment_state_shape` ([#396](https://github.com/opentidehq/opentide/issues/396)).
- **`deploy --plan PRODUCTION` disables and deletes retired rules.** It includes `DISABLED` and `REMOVED` rules, as [the deployment spec](https://github.com/opentidehq/specifications/blob/main/specs/deployment.md) defines, where the `--keep-deprecated` default dropped them and a retirement never reached the platform; `--drop-deprecated` restores the old behaviour ([#548](https://github.com/opentidehq/opentide/issues/548)).
- **`validate --file` fails when any target matches no object.** It reports `scope_no_match` and names the target in `context.targets`, where a run passed as long as one target matched; a script passing `--file` for a file that may not exist exits `1`.
- **`validate` rejects a quoted or boolean signal `effort`.** Signals take an integer such as `3`, as in the editor schema, which types `effort` as an integer instead of the efforts names that made every authored value invalid ([#552](https://github.com/opentidehq/opentide/issues/552)).

**Added**

- **Elastic Security is a supported platform** ([RFC 0007](https://github.com/opentidehq/specifications/blob/main/rfcs/0007-elastic-security-platform.md), [#386](https://github.com/opentidehq/opentide/issues/386)–[#390](https://github.com/opentidehq/opentide/issues/390)). A rule compiles to a Kibana detection rule whose `rule_id` is its `metadata.uuid`, so Elastic keeps no shard; there is no offline syntax check.
  - Tenants live in `.opentide/configurations/platforms/elastic.toml`, with the API key as an `$ENV` reference.
  - Deploy creates, updates, disables and deletes rules, and never modifies prebuilt ones.
  - `validate query --platform elastic --live` previews each rule through Kibana.
- **`opentide generate extract elastic` imports one Kibana space's rules.** `--space` picks the space, disabled rules import as `DISABLED`, prebuilt rules convert only with `--include-prebuilt`, and a rule that would not load is skipped and reported.
- **`opentide deploy migrate-state` moves vendor ids into shards.** It writes each shard before stripping the YAML, keeps comments and layout, and exits `1` when a rule fails or the destination is ignored; Sentinel, Splunk, HarfangLab and Carbon Black Cloud keys are removed without being stored, reported as `external_id_unused` ([#396](https://github.com/opentidehq/opentide/issues/396)).
- **Full-workspace `validate` checks every deployment state shard.** That includes orphans whose rule was deleted ([#396](https://github.com/opentidehq/opentide/issues/396)).
- **MCP `deployment_status` returns `external_ids` from the shard** ([#396](https://github.com/opentidehq/opentide/issues/396)).
- **`opentide validate --file` is repeatable** ([#548](https://github.com/opentidehq/opentide/issues/548)).
- **`validate query --live` JSON reports `plan`, `queries_validated` and `queries_per_tenant`** ([#547](https://github.com/opentidehq/opentide/issues/547)).

**Changed**

- **Generated production jobs commit promoted statuses and shards back.** On GitHub, GitLab and Azure the job commits promoted rule statuses and `.opentide/states/deployment/` to the default branch with `[skip ci]` ([#548](https://github.com/opentidehq/opentide/issues/548)).
  - Starts from the default branch's latest shards, so a rule is not created twice.
  - Queued on GitLab, and on Azure once an Exclusive lock check is added.
  - Overlapping GitHub runs that create the same rule fail with `deployment_state_conflict`.
  - Writes back whenever the deploy started, even after a failure.
  - Commits rule files only when `opentide validate --strict` passes on them.
  - Pushes a state commit that cannot land to `refs/opentide/deployment-state/<commit>`.
- **`opentide setup repo` ignores only `.opentide/states/sharing.jsonl`.** It no longer ignores the whole `.opentide/states/` directory, where the shards live ([#396](https://github.com/opentidehq/opentide/issues/396)).

**Fixed**

- **Sentinel rules with `alert.dynamic_properties` deploy.** The `sentinel` extra resolved `azure-mgmt-securityinsight` 1.0.0, so every such rule failed with `AttributeError`; it requires 2.0.0b2 or later ([#545](https://github.com/opentidehq/opentide/issues/545)).
- **Sentinel rules accept ISO 8601 durations such as `PT1H`.** Only the `1h` shorthand parsed, though the platform spec documents ISO 8601 ([#545](https://github.com/opentidehq/opentide/issues/545)).
- **A Sentinel rule without `entities` deploys.** It sends no empty `entityMappings`, which ARM rejected with 400 ([#549](https://github.com/opentidehq/opentide/issues/549)).
- **A missing Sentinel `grouping.alert` is reported, not an `AttributeError`.** Deploy and `--dry-run` fail a rule without `grouping` or `grouping.alert` with an error naming the rule and `configurations.sentinel.grouping.alert` ([#549](https://github.com/opentidehq/opentide/issues/549)).
- **`deploy --dry-run` shows Sentinel compile errors.** It shows the ARM request a deploy would send and lists a rule that would fail as `failed` with its `error`, exiting `1`, where it fell back to the configuration block and reported `completed` ([#545](https://github.com/opentidehq/opentide/issues/545)).
- **The `PRODUCTION` plan deploys what a merge commit changed.** On GitHub Actions and Azure Pipelines it diffs against HEAD's first parent, not the merged branch's head, which left those rules undeployed and pull-request jobs on the merge ref `skipped` ([#546](https://github.com/opentidehq/opentide/issues/546)).
- **`validate query --live` checks every reachable tenant by default.** With no `--plan` it checks `STAGING` and `PRODUCTION` tenants alike and `MANUAL` ones only when listed; rules that reach no configured tenant report `skipped` with exit `2` instead of `passed` ([#547](https://github.com/opentidehq/opentide/issues/547)).
- **Editors validate `rule::1.0` and `rule::1.1` side by side.** `setup vscode` maps `objects/**/*.yaml` to `.opentide/schemas/opentide.schema.json`, which applies the one revision schema `metadata.schema` selects instead of failing with "Matches multiple schemas", and removes the per-folder mappings earlier releases wrote ([#550](https://github.com/opentidehq/opentide/issues/550)).
- **The `rule::1.1` editor schema includes `metadata.reviewed`.** It accepts the same date and datetime forms as `opentide validate` ([#551](https://github.com/opentidehq/opentide/issues/551)).
- **CrowdStrike rules deploy with the right status.** Enabled rules deploy as `active` and disabled ones as `inactive`, where the status was inverted, and compiling a CrowdStrike rule no longer raises `AttributeError` ([#553](https://github.com/opentidehq/opentide/issues/553)).
- **A rule refused with `external_id_in_rule` fails every deploy path.** That covers `--platform`, `--skip-unconfigured` and direct deployer calls; MCP `deploy_rule` returns `status: failed` with an `error` for a refused or failed rule instead of a plain `deploy`, and error flags no longer leak between deploys in a long-lived process.
- **Bundled platform templates load with their `[[tenants]]` example uncommented.** The retired `proxy` key is gone, and the HarfangLab `type` and SentinelOne `url` and `account_id` placeholders are valid TOML.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0150--2026-10-16) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.15.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.15.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.14.2 — 14 October 2026

`opentide setup skills` can no longer be steered into installing skill content from a repository other than the pinned catalogue; upgrade promptly if you or your agents run it.

**Install**

```bash
pip install opentide==0.14.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Security**

- **`setup skills` cannot be steered off the pinned catalogue.** A manifest `ref`, skill `slug` or tree path containing `..` could install another repository's `SKILL.md` files or write any file, a git hook included. A rejected ref falls back to `main`; a rejected slug or path aborts the install ([#483](https://github.com/opentidehq/opentide/pull/483)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0142--2026-10-14) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.14.2/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.14.2)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.14.1 — 14 October 2026

Documentation generation takes 1.44 s instead of 722 s on a 265-object corpus, with byte-identical output, and techniques are read only from the fields models declare.

**Install**

```bash
pip install opentide==0.14.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **Techniques under a nested `tags` mapping are no longer reported.** Techniques, actors and platform configurations are read from the fields their models declare. If pre-0.9 objects carry techniques under `tags:`, catalogue search and `opentide info` skip them until they move to the model's field; validation is unchanged.

**Fixed**

- **`generate docs` and `generate exports` are fast again.** On a 265-object corpus `generate docs` takes 1.44 s instead of 722 s and `generate exports` 0.61 s instead of 152 s, with byte-identical output, so there is nothing to regenerate ([#510](https://github.com/opentidehq/opentide/issues/510)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0141--2026-10-14) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.14.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.14.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.14.0 — 14 October 2026

Signal entities are stage-scoped, and `opentide migrate vocab-scope` adds the prefix for you. `response.responders` accepts the teams `deployment.toml` declares, and documentation generation finishes on catalogues that timed out.

**Install**

```bash
pip install opentide==0.14.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide migrate vocab-scope --apply` to add the stage prefix to `objective.signals[].entities` and `threat.surface` values.
- If it exits `2`, set the stage by hand for each value it reports with candidates.
- If your rules name responders, declare those teams in a `[[responders]]` block in `deployment.toml`, so the editor offers them and `validate` rejects any other value.
- If you emptied `response.responders` to pass validation on 0.13.0, put the team back.
- Run `opentide generate schemas templates vocabs snippets`, so the editor offers the scoped values and your teams.

**Breaking**

- **`objective.signals[].entities` values carry their stage: `Host::Hostname`.** Seven keys, such as `Account`, are defined under two stages, so a bare name could not tell a host account from a cloud account. Stage ids are capitalised (`Host`, `Network`, `Cloud`), as in `threat.surface` ([#509](https://github.com/opentidehq/opentide/issues/509), [RFC 0005](https://github.com/opentidehq/specifications/blob/main/rfcs/0005-scoped-signal-entities.md)).
- **`response.responders` is a configuration enum, not a vocabulary.** The shipped vocabulary was empty, so every value failed validation; the `[[responders]]` teams in `deployment.toml` are the allowed values, declaring none leaves the field unconstrained, and `[deployment] default_responders` names the team for a rule without one ([#507](https://github.com/opentidehq/opentide/issues/507)).

**Added**

- **`opentide migrate vocab-scope` adds the stage prefix to scoped values.** It applies only what the vocabulary implies, reports a key defined under several stages with its candidates, exiting `2` while one is left, and keeps comments, quoting and layout.
- **`generate --help` names the four positional phases.** They are `schemas`, `templates`, `vocabs` and `snippets`, the cheap phases that refresh a stale editor schema.
- **`generate` reports what each phase costs.** It names the slowest phase and records timing even when a phase raises, so a job killed at a timeout shows how far it got ([#510](https://github.com/opentidehq/opentide/issues/510)).

**Changed**

- **`pip install opentide` includes the MCP server.** `mcp` is a base dependency, so `opentide mcp` runs on a bare install, and the `[mcp]` extra stays as an empty alias for configurations that name it ([#526](https://github.com/opentidehq/opentide/issues/526)).

**Fixed**

- **Documentation and export generation are 68× faster on 1497 objects.** They rescanned the whole catalogue for every object, so a `generate docs` phase exceeded a one-hour CI job timeout and `generate exports` took 395 s ([#510](https://github.com/opentidehq/opentide/issues/510)).
- **A relation is no longer attributed to the wrong object.** Ids were matched by substring, so `o-1` matched a signal referencing `o-186`; they are compared by equality, and UUID-shaped ids were never affected.
- **`validate` and `generate` resolve a vocabulary value the same way.** A repository green on `validate` could still produce degraded documentation: three `Security::*` surface keys resolved to a different entry and three more missed entirely ([#508](https://github.com/opentidehq/opentide/issues/508)).
- **A renamed deployment status keeps its behaviour.** A status resolves by the strategy it maps to, where resolving by its configured name made a renamed status silently take the wrong branch ([#506](https://github.com/opentidehq/opentide/issues/506)).
- **`mcp start` and `setup mcp` advise an install that helps.** With `mcp` unimportable they advised `pip install 'opentide[mcp]'`, which installs nothing; they name `pip install 'mcp>=1.28.1,<2'` and tell an incomplete environment from an incompatible `mcp` 2.x ([#526](https://github.com/opentidehq/opentide/issues/526)).
- **The documentation names the release it installs.** Four pages named 0.12.1 as the latest release beside their own 0.14.0 install command.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0140--2026-10-14) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.14.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.14.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.13.0 — 12 October 2026

`threat.surface` values carry their stage, so every surface is reachable, and generated CI deploys and pushes only for pull requests that target the default branch.

**Install**

```bash
pip install opentide==0.13.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide generate schemas templates vocabs snippets`, so the editor offers the stage-scoped `threat.surface` values.
- Prefix each `threat.surface` value with its stage: `Windows::Desktop` becomes `OS::Windows::Desktop`.
- Add `status` to each `configurations.<platform>` block that has none; `validate` reports a missing one as `status: Field required`.
- If a script reads `issues.issues` or `errors` from `opentide --json validate`, read `report.issues` instead.
- Run `opentide setup ci <github|gitlab|azure> --yes`, so generated pipelines deploy and push only for pull requests to the default branch.

**Breaking**

- **`threat.surface` values carry their stage: `OS::Windows::Desktop`.** Five keys, such as `VPN` and `Wireless`, are defined under both `Infrastructure` and `Protocol`, so a bare name was ambiguous and they were unreachable; the enum carries all 900 values. Vocabulary entry keys are unchanged.
- **Platform configuration blocks require `status`.** A rule without `configurations.<platform>.status` passed `validate` and then crashed `deploy`; validation reports `status: Field required` with the field path.
- **`opentide --json validate` emits one document shape.** The report is always at `report`, and `--check <x>` narrows `checks` and adds `check` instead of moving the report to `issues`. The legacy `errors` map is removed: read `report.issues`.
- **A `[vocabulary]` block in `schema.toml` no longer adds entries.** Vocabularies are canonical in [specifications](https://github.com/opentidehq/specifications), where a missing entry is added.

**Fixed**

- **Only pull requests to the default branch deploy and push.** A pull request between two feature branches deployed detections to the live staging tenant and committed to the default branch; six generated GitLab, GitHub and Azure jobs check the target branch.
- **`threat.actors.name` accepts 220 more MISP clusters.** It is pinned to `actors::1.1`, so a correctly authored MISP cluster UUID is no longer reported as an unknown vocabulary value; `actors::1.0` keys are unaffected.
- **`setup skills --install` accepts every bundled authoring skill.** Three of the four, such as `opentide-detection-rule`, were missing from the discovery catalogue and failed as an unknown slug, although the default set installed them.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0130--2026-10-12) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.13.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.13.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.12.1 — 9 October 2026

A missing credential is logged once instead of once per object, and the generated live query job checks only the variables your platform file uses.

**Install**

```bash
pip install opentide==0.12.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup ci <github|gitlab|azure> --yes`, so the live query job guards only the `$VAR` names in the enabled platform file and exits `2` when one is unset.

**Fixed**

- **Each unset configuration variable is logged once.** It was logged once per object; the live check still ends on the FATAL panel that names those variables.
- **Generated CI checks only the platform file's `$VAR` names.** It treated every `$VAR` in the bundled sample as required; the guard reads the enabled platform file, ignores comments and literal values, and exits `2` on a skip, so exit `0` means the tenant check ran.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0121--2026-10-09) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.12.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.12.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.12.0 — 9 October 2026

The MCP server starts with `opentide mcp start`, replacing the removed `opentide-mcp` command, and a live query check fails on a credential still written as `$VARIABLE`.

**Install**

```bash
pip install opentide==0.12.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you use the MCP server, run `opentide setup mcp` to regenerate its configuration with `opentide mcp start`.
- Run `opentide setup ci <github|gitlab|azure> --yes`, so a live query job runs only when every required credential variable is set.
- Run `opentide generate` to regenerate schemas without a string vocabulary enum on `threat.chaining`.

**Breaking**

- **`opentide-mcp` is removed: start the server with `opentide mcp start`.** The console script has no alias. `opentide setup mcp` writes `command: opentide` and `args: ["mcp", "start"]`, and `opentide mcp` with no subcommand prints help and exits ([#460](https://github.com/opentidehq/opentide/issues/460)).

**Fixed**

- **Splunk `[[modifiers]]` loads as an array of tables.** A configuration error during engine load is reported as that error, not only as a missing `declare` ([#466](https://github.com/opentidehq/opentide/issues/466)).
- **Generated schemas put no string enum on `threat.chaining`.** Neither its items nor the array node carry one, and `list[str]` vocabulary fields keep `items.enum` ([#468](https://github.com/opentidehq/opentide/issues/468)).
- **Stage-prefix suggestions strip the prefix using the field name.** That holds when the caller passes `surface::1.0`, and MISP actor UUIDs still get no suggestion ([#467](https://github.com/opentidehq/opentide/issues/467)).
- **A retired `[tenants.setup] proxy` key fails the live query check.** Its message names `opentide --proxy`: the retirement covers platform tenant configuration, not only `[cve].proxy` ([#469](https://github.com/opentidehq/opentide/issues/469)).
- **`--live` fails when a credential is still an unsubstituted `$VARIABLE`.** Generated CI runs that job only when every required credential variable is set ([#471](https://github.com/opentidehq/opentide/issues/471)).
- **Vocabulary and cross-object findings record `yaml_line`.** Validate findings point at their line, list indexes such as `actors[0]` included; lint findings are unchanged ([#470](https://github.com/opentidehq/opentide/issues/470)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0120--2026-10-09) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.12.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.12.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.11.0 — 7 October 2026

`validate query --live` is the tenant check, and bare `validate query` no longer scans query text; generated pipelines pass `--live` and skip a platform without credentials.

**Install**

```bash
pip install opentide==0.11.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup ci <github|gitlab|azure> --yes`, so generated pipelines pass `--live` and pin this release.
- Run `opentide generate`, so optional vocabulary lists in generated schemas include `items.enum`.

**Breaking**

- **Bare `opentide validate query` exits `1` and names `--live`.** It does not scan query text: `--live` checks the tenant, a missing SDK or plan fails that check, and CrowdStrike and HarfangLab stay unsupported ([#456](https://github.com/opentidehq/opentide/issues/456)).
- **MCP `validate_query` refuses unless `live` is true.** With `live: true` it checks the catalogue rules for the platform against the tenant ([#456](https://github.com/opentidehq/opentide/issues/456)).

**Added**

- **`opentide generate` runs several named phases in one invocation.** `opentide generate schemas templates vocabs snippets` runs them in that order, and `docs`, `exports`, `extract` and `inflight` stay subcommands ([#455](https://github.com/opentidehq/opentide/issues/455)).

**Changed**

- **Generated pipelines pass `--live` and skip platforms without credentials.** GitHub, GitLab and Azure pipelines skip a platform when every credential variable for it is empty ([#456](https://github.com/opentidehq/opentide/issues/456)).
- **Generated schemas stamp `items.enum` on optional vocabulary lists.** Each branch of a string-or-list union gets it too ([#450](https://github.com/opentidehq/opentide/issues/450)).
- **The bundled actors vocabulary matches the specifications snapshot.** That snapshot is refreshed from the live MISP galaxy ([opentidehq/specifications#34](https://github.com/opentidehq/specifications/issues/34)).

**Fixed**

- **Validation findings print `file:line` when `yaml_line` is set** ([#451](https://github.com/opentidehq/opentide/issues/451)).
- **`validate --check` returns only that check's issues.** Parse findings belong to the schema check ([#452](https://github.com/opentidehq/opentide/issues/452)).
- **Unknown `sharing.toml` keys name `[[misp]]`** ([#453](https://github.com/opentidehq/opentide/issues/453)).
- **Surface suggestions try the exact de-prefixed key first** ([#454](https://github.com/opentidehq/opentide/issues/454)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0110--2026-10-07) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.11.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.11.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.10.0 — 6 October 2026

Signals name the log sources your `visibility.toml` declares and take alert-label severities, technique lists are `mitre_attack`, and `opentide --proxy` sets the HTTP proxy for a run.

**Install**

```bash
pip install opentide==0.10.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide generate` to regenerate editor schemas and templates.
- Rename threat and objective technique lists to `mitre_attack`.
- Make each signal's `data.logsources` a log source name from `visibility.toml`.
- Set each signal's `severity` to `Informational`, `Low`, `Medium`, `High` or `Critical`.
- If your configuration sets `[proxy]`, `[cve].proxy` or a tenant's `setup.proxy`, replace it with `opentide --proxy http://[user:pass@]host:port`.
- Run `opentide setup ci <github|gitlab|azure> --yes`, so the generated install pin is exact.

**Breaking**

- **Threat and objective technique lists are `mitre_attack`.** They are pinned to `att&ck::1.1`, `att&ck` and `attack` are not accepted, and actor values stay scoped (`att&ck::G0007`).
- **Signal log sources are names from `visibility.toml`.** `signals[].data.logsources` come from the workspace `visibility.toml`, and the `datasources` pin on that field is gone.
- **Signal `severity` uses alert labels.** It takes `Informational` through `Critical` from `alert_severity::1.0`, while threat `severity` keeps the incident vocabulary.
- **Proxy keys in configuration are errors: use `opentide --proxy`.** `opentide --proxy http://[user:pass@]host:port` sets `HTTP_PROXY` and `HTTPS_PROXY` for the run, and a `[proxy]`, `[cve].proxy` or tenant `setup.proxy` key fails with a message naming the flag.

**Added**

- **`python -m opentide` starts the CLI.** `python -m opentide.mcp_server` starts the MCP server.
- **`opentide info` reports object files that failed to load.** It prints how many failed, and `--strict` exits non-zero when any did.

**Changed**

- **`objective.composition` is the required composition block.** A root `composition` block is accepted and ignored, and templates emit the block once, under `objective`.
- **`detection_model` accepts an objective UUID or a signal UUID.**
- **A `visibility.toml` asset's `custom_details` accepts strings, booleans and numbers.**
- **The generated Sentinel schema no longer requires `grouping` or `entities`.**
- **`opentide setup ci` pins the installed version.** Generated pipelines install `opentide==<installed version>`.

**Fixed**

- **A `schema.toml` vocabulary extension applies during validation.** Extensions are looked up by field name.
- **`opentide lint` reports an unreadable file instead of crashing.**
- **`opentide setup vscode` accepts JSONC.** It reads comments and trailing commas, and names the file when the JSON is still invalid.
- **Duplicate YAML keys are rejected with the key and line.**

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#0100--2026-10-06) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.10.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.10.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.9.0 — 5 October 2026

`rule::1.1` can record `metadata.reviewed`, and `opentide rules unreviewed` lists rules with no review or a review older than the window you give.

**Install**

```bash
pip install opentide==0.9.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide generate` to regenerate editor schemas and templates, so the editor accepts `metadata.reviewed` on `rule::1.1` and checks techniques against `att&ck::1.1` and logsources against `datasources::1.1`.

**Added**

- **`rule::1.1` records an optional `metadata.reviewed` date.** It takes an ISO 8601 date or datetime, and `rule::1.0`, threats and objectives still reject it. Validate, deploy, share and template generation never write it ([#437](https://github.com/opentidehq/opentide/issues/437), [#438](https://github.com/opentidehq/opentide/pull/438)).
- **`opentide rules unreviewed` lists rules due for review.** With `--older-than 90d` it lists `rule::1.0` as `schema`, a `rule::1.1` with no review as `absent` and a review older than the window as `stale`; it exits `0` when the window parses ([#437](https://github.com/opentidehq/opentide/issues/437)).

**Changed**

- **Techniques validate against `att&ck::1.1`, ATT&CK 19.2.** Objective logsources validate against `datasources::1.1`, and the bundled ATT&CK, groups, datasources and mitigations match upstream 19.2 ([#392](https://github.com/opentidehq/opentide/issues/392), [#445](https://github.com/opentidehq/opentide/pull/445)).

**Fixed**

- **`share push` publishes a retracted object again.** A matching content hash skips the push only when the ledger line is `synced`, and preview no longer reports an update that push then skips ([#385](https://github.com/opentidehq/opentide/pull/385)).
- **Deploy on a deep git history no longer raises `RecursionError`.** A history deeper than the Python recursion limit aborted the diff; commit loading records the immediate parent ([#369](https://github.com/opentidehq/opentide/pull/369)).

**Security**

- **CrowdStrike and Defender authentication no longer log credentials.** CrowdStrike logged the token response and Defender the bearer token or a client-secret prefix, which `--json` and the MCP server send to stderr, where a CI reader could reuse them ([#441](https://github.com/opentidehq/opentide/pull/441)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#090--2026-10-05) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.9.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.9.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.8.2 — 2 October 2026

The SDK's object index is built once per registry snapshot, and vocabulary writers quote dotted list keys so TOML does not read them as nested tables.

**Install**

```bash
pip install opentide==0.8.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **`Opentide.Models.FlatIndex` is built once per registry snapshot.** Dropping the registry cache drops it too, so a rebuilt index cannot serve the previous objects ([#436](https://github.com/opentidehq/opentide/pull/436)).
- **Extraction runners accept keyword arguments.** `run_extract` and `run_extract_import` forward them, and the CLI passes none, so an existing `run()` still works; an unexpected keyword raises `TypeError` naming the module ([#436](https://github.com/opentidehq/opentide/pull/436)).

**Fixed**

- **Vocabulary writers quote dotted list keys.** They write `"tide.vocab.stages"` instead of a bare dotted key TOML reads as nested tables, and a file that already nests the stages under `tide.vocab` is still read ([#436](https://github.com/opentidehq/opentide/pull/436)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#082--2026-10-02) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.8.2/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.8.2)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.8.1 — 1 October 2026

Generated GitLab pipelines wait for query validation before `generate` and deploy, as GitHub and Azure pipelines already did.

**Install**

```bash
pip install opentide==0.8.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you use GitLab, run `opentide setup ci gitlab --yes`, so query validation gates `generate` and deploy.

**Fixed**

- **Generated GitLab pipelines wait for query validation before deploying.** The `generate` job needs `validate` and every `validate_query_*` job, so a failed `opentide validate query` no longer starts deploy ([#429](https://github.com/opentidehq/opentide/issues/429)).
- **The generated GitLab inflight shell quotes `$CI_DEFAULT_BRANCH`.** It exits if `cd` into the worktree fails, and `gitlab-ci-verify` (ShellCheck) and glint accept the file ([#430](https://github.com/opentidehq/opentide/issues/430)).
- **Generated GitLab pipelines omit a document job with no commands.** The job and its `document` stage are left out, instead of an empty `script` GitLab rejects ([#430](https://github.com/opentidehq/opentide/issues/430)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#081--2026-10-01) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.8.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.8.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.8.0 — 30 September 2026

Generated pipelines gate on strict validation and lint and skip a deploy plan whose platforms have no tenants, and an object file with no `uuid` fails validation.

**Install**

```bash
pip install opentide==0.8.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Run `opentide setup ci <github|gitlab|azure> --yes` to pick up the strict gates and the `--skip-unconfigured` deploy.
- If you use Azure Repos, add a build validation policy on the default branch, so a pull request sets `Build.Reason` to `PullRequest`; the pipeline file cannot create it.

**Added**

- **`opentide deploy --skip-unconfigured` passes a plan with no tenants.** It exits `0` when no platform in the plan has a `[[tenants]]` block, and a plan mixing configured and unconfigured platforms still fails with `Cannot deploy:` ([#408](https://github.com/opentidehq/opentide/issues/408)).
- **Generated GitHub deploy jobs map platform credentials from `secrets`.** Each credential the bundled platform files name comes from `secrets`, GitLab and Azure read the same names from the project variable store, and there is no `OPENTIDE_SECRETS` variable ([#408](https://github.com/opentidehq/opentide/issues/408)).

**Changed**

- **Generated gates run `opentide validate --strict` and `opentide lint --strict`.** Deploy runs `--dry-run`, then `opentide deploy --plan <PLAN> --skip-unconfigured` ([#409](https://github.com/opentidehq/opentide/issues/409), [#408](https://github.com/opentidehq/opentide/issues/408)).
- **Azure pipelines run on `ubuntu-latest` and trigger on every branch.** A topic-branch push still validates, and the staging deploy stays gated on `Build.Reason` `PullRequest` ([#398](https://github.com/opentidehq/opentide/issues/398)).
- **`lint` prints `ISSUES` when it has findings.** The exit code stays `0` unless `--strict`, and JSON keeps `"ok": true`.
- **MCP `get_chaining` returns threat, objective and rule lineage.** It follows `objective.threats`, `rule.detection_model` and threat-to-threat links into `lineage`, and a non-empty `threat.chaining` map stays in `graph` ([#407](https://github.com/opentidehq/opentide/issues/407)).

**Fixed**

- **An object file with no `uuid` fails validation.** The schema check reports `missing_uuid`, and an empty catalogue still exits `0` ([#397](https://github.com/opentidehq/opentide/issues/397)).
- **`deploy --plan STAGING` works on a detached pull-request checkout.** It fetches `origin` by name instead of dying with `list index out of range` ([#402](https://github.com/opentidehq/opentide/issues/402), [#415](https://github.com/opentidehq/opentide/issues/415)).
- **The inflight prune job creates `.opentide/inflight` before `git add`.** A repository that never committed that directory no longer exits 128 ([#403](https://github.com/opentidehq/opentide/issues/403)).
- **`setup skills` downloads every file under `skills/<slug>/`.** It renders `AGENTS.md` from the package template, and the four authoring skills it installs from the package describe `rule::1.0`, `objective::1.0` and `threat::1.0` ([#399](https://github.com/opentidehq/opentide/issues/399), [#405](https://github.com/opentidehq/opentide/issues/405)).
- **`setup repo` keeps empty directories and names every enabled platform** ([#400](https://github.com/opentidehq/opentide/issues/400), [#404](https://github.com/opentidehq/opentide/issues/404)).
  - Empty scaffold directories get a `.gitkeep`.
  - The README lists one `deploy --platform <name> --dry-run` per enabled platform.
  - `--name`, `--org` or `--description` on an existing `README.md` keeps the file and warns.
- **`generate docs` writes the section indexes for an empty folder.** `rules/README.md`, `objectives/README.md` and `threats/README.md` are written when the folder has no objects ([#401](https://github.com/opentidehq/opentide/issues/401)).
- **The installation pages name 0.8.0 as the latest release** ([#406](https://github.com/opentidehq/opentide/issues/406)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#080--2026-09-30) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.8.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.8.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.7.0 — 29 September 2026

`opentide share` publishes threats, objectives and rules to MISP, one Event each, and `setup ci --sharing` adds a job that shares changed objects on the default branch.

**Install**

```bash
pip install opentide==0.7.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you already generated a workflow, run `opentide setup ci <github|gitlab|azure> --yes` again, so a GitHub production job compares `github.ref` to a literal branch ref.
- If that pipeline should run `opentide share push --changed` on the default branch, add `--sharing` to the command.

**Added**

- **`opentide share` publishes Tide objects to MISP.** Each threat, objective or rule is one MISP Event, and the subcommands are `push`, `preview`, `status`, `retract` and `targets`. `preview` and `status` make no request, `preview` needs no API key, and the key is never printed ([#184](https://github.com/opentidehq/opentide/issues/184), [#371](https://github.com/opentidehq/opentide/issues/371), [#372](https://github.com/opentidehq/opentide/issues/372)).
- **`sharing.toml` holds the MISP destinations.** `.opentide/configurations/sharing.toml` merges `[[misp]]` blocks by `name`; `opentide validate --check sharing-config` checks it, and `share push` runs the same check ([#370](https://github.com/opentidehq/opentide/issues/370)).
- **Successful shares are recorded in `.opentide/states/sharing.jsonl`.** A skip or a failure leaves the file unchanged, and setup gitignores `.opentide/states/` ([#373](https://github.com/opentidehq/opentide/issues/373)).
- **`opentide share` exit codes tell failures apart.** Exit `2` means every failure was authentication or connectivity, and exit `3` means the run both succeeded and failed.
- **`--sharing` adds a share job to generated pipelines.** `opentide setup` and `setup ci` take `--sharing` / `--no-sharing`, off by default; the job runs `opentide share push --changed` after generate on a push to the default branch, and deploy does not wait for it ([#375](https://github.com/opentidehq/opentide/issues/375)).

**Changed**

- **Generated GitHub workflows compare `github.ref` to a literal ref.** A regenerated workflow compares it with `'refs/heads/<branch>'`, because `format()` with only the format string is not a valid Actions expression.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#070--2026-09-29) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.7.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.7.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.6.4 — 28 September 2026

A push to the default branch deploys from a regenerated GitHub pipeline even when staging is skipped, and re-running setup keeps your edited README, `.gitignore` and platform comments.

**Install**

```bash
pip install opentide==0.6.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you generated a workflow with `opentide setup ci`, regenerate it with `opentide setup ci github` (or `gitlab` or `azure`), so production deploy and the checkout depth match this release.

**Fixed**

- **`generate` names a missing detection model.** It exits `1` with a JSON `message` that names the missing `detection_model` UUID, instead of empty stdout and a bare `Exception` ([#352](https://github.com/opentidehq/opentide/issues/352)).
- **MCP `deploy_rule` reports an unknown or tenantless platform.** It returns a structured failure instead of `KeyError` or `TypeError`, and `deployment_status` is `deployed: false` when the config has no `external_id` and no tenants ([#345](https://github.com/opentidehq/opentide/issues/345)).
- **`--json setup` quotes the path it would write.** A target of `.` no longer reads as `..` ([#346](https://github.com/opentidehq/opentide/issues/346)).
- **Explorer pages are offered only for GitHub.** GitLab and Azure write no Explorer job and warn that the pages were not written, instead of skipping them silently ([#347](https://github.com/opentidehq/opentide/issues/347)).
- **GitHub production deploy runs when staging is skipped.** The generated production job needs `generate`, so a push to the default branch deploys. Deploy jobs on GitHub, GitLab and Azure fetch full history, and name a missing parent commit instead of a bare SHA ([#348](https://github.com/opentidehq/opentide/issues/348)).
- **`setup --yes --ci none` writes no pipeline.** It scaffolds the repository, `setup ci none` is rejected, and CI-only flags without `github`, `gitlab` or `azure` are named in warnings ([#349](https://github.com/opentidehq/opentide/issues/349)).
- **Re-running setup keeps your edits.** An edited `README.md`, `.gitignore` and the comments in an existing platform toml survive, and `setup ci` still replaces the workflow ([#350](https://github.com/opentidehq/opentide/issues/350)).
- **`lint --fix` reports metadata on the path it renamed.** A second `--fix` does not rename that file again ([#353](https://github.com/opentidehq/opentide/issues/353)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#064--2026-09-28) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.6.4/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.6.4)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.6.3 — 24 September 2026

CI diff plans say what is wrong instead of crashing with `encode`, `KeyError`, `Invalid object name` or `list index out of range`, and a GitLab merged-result commit with one parent no longer fails.

**Install**

```bash
pip install opentide==0.6.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **A missing tip SHA names the variable to set.** A CI diff plan whose `CI_COMMIT_SHA`, `GITHUB_SHA` or `BUILD_SOURCEVERSION` is unset exits `1` and names that variable, instead of `'NoneType' object has no attribute 'encode'` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- **Azure `STAGING` names its missing pull-request variables.** Without `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME` it exits `1` naming them, before any fetch, instead of `KeyError while compiling the deployment plan` or, with no remote, `No git repository was found at origin` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- **A pull-request ref missing from `origin` is named.** GitHub or Azure `STAGING` exits `1` with `Could not find git ref origin/<name>` instead of `Invalid object name` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- **`DEBUG`, `MANUAL` and `ALWAYS` are refused as CI diff plans.** Under CI they exit `1` with `Deployment plan <NAME> is not a CI diff plan. Use STAGING, PRODUCTION, or FULL.`; `ALWAYS` is no longer an alias of `FULL`, which is unchanged ([#339](https://github.com/opentidehq/opentide/issues/339)).
- **GitLab merged-result commits with one parent no longer fail.** The plan keeps `CI_COMMIT_SHA` as the tip and exits `0` when both SHAs are in the checkout, instead of `list index out of range` ([#339](https://github.com/opentidehq/opentide/issues/339)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#063--2026-09-24) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.6.3/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.6.3)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.6.2 — 24 September 2026

GitLab diff plans with a missing base commit report `No Source Commit Found` instead of crashing on `lookup_ref`, and GitHub `STAGING` names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` instead of Azure variables.

**Install**

```bash
pip install opentide==0.6.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **GitLab diff plans report a missing base commit.** `STAGING` and `PRODUCTION` with an unset or unknown base SHA exit `1` with `No Source Commit Found` instead of `FATAL: 'Repo' object has no attribute 'lookup_ref'`, and still succeed when both SHAs are in the checkout ([#333](https://github.com/opentidehq/opentide/issues/333)).
- **GitHub `STAGING` asks for the GitHub pull-request variables.** Without `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` it exits `1` with a message naming them, instead of Azure variable names and `KeyError while compiling the deployment plan` ([#334](https://github.com/opentidehq/opentide/issues/334)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#062--2026-09-24) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.6.2/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.6.2)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.6.1 — 23 September 2026

CI `STAGING` and `PRODUCTION` plans deploy a changed rule file that sits directly in `objects/rules/`, which 0.6.0 left out; a file in a subfolder is still not deployed.

**Install**

```bash
pip install opentide==0.6.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **CI plans deploy a changed rule file directly in `objects/rules/`.** `STAGING` and `PRODUCTION` include a changed `objects/rules/*.yaml` (or `.yml`) that 0.6.0 left out of the plan; a file under `objects/rules/<subfolder>/` stays out, and the existing warning names it ([#318](https://github.com/opentidehq/opentide/issues/318)).

**Fixed**

- **A diff plan outside a git checkout points at `--plan FULL`.** `deploy --plan STAGING` or `PRODUCTION` still exits `1`, but names the directory it searched instead of `No git repository was found at None`; `FULL` still needs no checkout ([#310](https://github.com/opentidehq/opentide/issues/310)).
- **`setup --path .` scaffolds the directory you run it in.** From a subdirectory of a git checkout it scaffolds that directory, not the git root, and an explicit `--repo` still replaces `.` ([#324](https://github.com/opentidehq/opentide/issues/324)).
- **`setup --no-promotion` and `--promotion-target` work without `--ci`.** A plain `opentide setup` writes `[promotion]` in `.opentide/configurations/deployment.toml` from them ([#325](https://github.com/opentidehq/opentide/issues/325)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#061--2026-09-23) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.6.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.6.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.6.0 — 23 September 2026

Commands find the detection workspace from any folder inside it, human output shows what `--json` already showed, and `deploy` handles a repository with no rules or tenants yet instead of crashing.

**Install**

```bash
pip install opentide==0.6.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you generated CI with `opentide setup ci`, regenerate it with `opentide setup ci <github|gitlab|azure> --yes`, so `--default-branch` matches the branch you deploy from.
- If a script reads `note` from `opentide --json setup mcp --generic`, read `advice` instead.

**Breaking**

- **`setup mcp --generic` reports its instruction as `advice`, not `note`.** Human output prints the copy-the-file instruction too ([#292](https://github.com/opentidehq/opentide/issues/292)).
- **SDK: `ValidationScope.path_basenames` is removed.** A path target matches only the object's own file, through `ValidationScope.matches_file()`, and the registry index has a `file_paths` map from UUID to the file each object was read from ([#297](https://github.com/opentidehq/opentide/issues/297)).

**Changed**

- **`opentide --json validate` names the workspace it read.** The directory is under `workspace`, and a full run that finds no objects still exits `0`, with a message that names that directory ([#294](https://github.com/opentidehq/opentide/issues/294)).

**Fixed**

- **Commands find the workspace from any folder inside it.** The CLI, SDK and MCP server stop at the nearest directory holding `.opentide/` or `objects/`, so a nested workspace is found and `validate --strict` no longer passes having checked nothing ([#294](https://github.com/opentidehq/opentide/issues/294)).
- **`validate --file` with a path checks only that file.** A bare file name still matches in every subfolder; issues name the object's own file, and the SDK's `rule.file` points at it ([#297](https://github.com/opentidehq/opentide/issues/297)).
- **Human output shows what `--json` carries** ([#292](https://github.com/opentidehq/opentide/issues/292)).
  - bracketed text: `[deploy, validate]`, `[error]`, `opentide[sentinel]`
  - each result's `advice` and `detail`
  - `lint` findings, as `[check] path: message`
- **`info` subcommands print the section you ask for.** `info rules`, `info threats`, `info objectives` and `info coverage --technique …` list their objects instead of the plain `info` summary ([#293](https://github.com/opentidehq/opentide/issues/293)).
- **SDK `rule.metadata.schema` returns the schema id.** It returns `"rule::1.0"`, not Pydantic's `BaseModel.schema` method ([#298](https://github.com/opentidehq/opentide/issues/298)).
- **`generate docs` writes an actor's stage as `att&ck`, not `('att&ck',)`** ([#296](https://github.com/opentidehq/opentide/issues/296)).
- **Splunk frequency warnings appear only where they apply.** A repository that does not use Splunk no longer logs them, and an unset `frequency_scheduling` keeps the mode it deployed with before: `current` for a legacy `[setup]` table, `random` for a `[[tenants]]` entry ([#295](https://github.com/opentidehq/opentide/issues/295)).
- **`deploy` without `objects/rules/` reports `skipped`.** It exits `0` and contacts no platform, instead of failing with `Errno 2` ([#300](https://github.com/opentidehq/opentide/issues/300)).
- **`deploy` names the rule files in subfolders it skips.** Files under `objects/rules/<subfolder>/` are still not deployed, and every plan warns once and names them ([#300](https://github.com/opentidehq/opentide/issues/300), [#312](https://github.com/opentidehq/opentide/issues/312)).
- **An enabled platform without tenants names the file to edit.** `deploy` and `validate query --live` exit `1` before any engine loads, instead of a bare `Exception`, and `--dry-run` previews payloads and warns ([#314](https://github.com/opentidehq/opentide/issues/314)).
- **`setup --ci` takes `--default-branch`, as `setup ci` does.** Without the flag, a repository with no `origin/HEAD` gets its checked-out branch, ahead of `init.defaultBranch` and `main`, so a `trunk`-only repository no longer gets a pipeline on `main` ([#288](https://github.com/opentidehq/opentide/issues/288)).
- **`setup` prints the warnings of its steps.** The one-shot `setup --ci <provider>` shows the CI step's `WARNING` lines, and `--json` puts them in the top-level `warnings` too ([#308](https://github.com/opentidehq/opentide/issues/308)).
- **`--no-promotion` and `--promotion-target` take effect.** They write `[promotion]` in `.opentide/configurations/deployment.toml`, so `--promotion-target STAGING` no longer promotes to `PRODUCTION`; a flag that disagrees with an existing table exits `2` ([#307](https://github.com/opentidehq/opentide/issues/307)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#060--2026-09-23) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.6.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.6.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.5.0 — 23 September 2026

Threats written to `threat::1.0` validate: `impact` and `leverage` are lists of vocabulary names, so a single string, which 0.4.0 required, fails until it becomes a one-item list.

**Install**

```bash
pip install opentide==0.5.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- Rewrite each single-string `impact` or `leverage` (`impact: Data Breach`) as a list with one item per vocabulary name, before you upgrade a pipeline.
- Run `opentide generate`, so threats you create start from the list template.
- If your CI patches the installed `opentide` model to accept lists, drop that step.

**Breaking**

- **`threat.impact` and `threat.leverage` are non-empty lists of vocabulary names.** A single string fails with `must be a YAML list of … vocabulary names`, and so does a value or item that joins several names with `;` ([#189](https://github.com/opentidehq/opentide/issues/189)). Give every name its own item and keep them all ([Troubleshooting](./troubleshooting.md#threat-impact--leverage-input-should-be-a-valid-string-must-be-a-yaml-list-or-packs-several-vocabulary-names)).
- **SDK: `ThreatBody.impact` and `.leverage` are `list[str]`.** Threat templates, editor schemas (`type: array`, `minItems: 1`) and the explorer bundle carry both fields as lists ([#189](https://github.com/opentidehq/opentide/issues/189)).

**Fixed**

- **Threats written to the `threat::1.0` spec validate.** `impact: [Data Breach, Identity Theft]` no longer fails with `Input should be a valid string`, and `validate` no longer suggests a single name for a `;`-joined value, which would drop the others ([#189](https://github.com/opentidehq/opentide/issues/189)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#050--2026-09-23) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.5.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.5.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.4.0 — 22 September 2026

First-run commands stop crashing, printing tracebacks or quietly doing nothing, a regenerated GitHub inflight job no longer lands pull requests unreviewed, and `validate query` checks syntax offline by default.

**Install**

```bash
pip install opentide==0.4.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you generated CI with `opentide setup ci`, regenerate it with `opentide setup ci <github|gitlab|azure> --yes` to pick up the fixed templates, including the inflight job under **Security**.
- If you installed the pre-commit hook with `opentide setup hooks`, run `opentide setup hooks --yes`, so the hook validates the commit rather than `OPENTIDE_REPO_ROOT`.
- If you deploy to Splunk or Carbon Black, run `opentide validate --strict` and give each rule it reports a non-blank `query`.
- If a pipeline runs `validate query` against a tenant, add `--live` to keep the round-trip.

**Breaking**

- **`validate query` checks syntax offline by default.** It checks KQL, SPL, S1QL and Lucene with no SDK, credentials or network; the tenant round-trip is `validate query --live` ([#239](https://github.com/opentidehq/opentide/issues/239)).
- **Splunk and Carbon Black rules need a non-blank `query`.** A missing or blank `query` fails validation instead of deploying nothing ([#233](https://github.com/opentidehq/opentide/issues/233), [Upgrading to 0.4.0](./concepts/platforms.md#upgrading-to-040)).

**Changed**

- **CrowdStrike and HarfangLab `validate query` returns the normal envelope.** It reports `ok` and `status` with `supported: false`, instead of a bare payload ([#247](https://github.com/opentidehq/opentide/issues/247)).
- **`opentide --json setup` without `--yes` refuses to start the wizard.** It exits non-zero with one JSON error instead ([#255](https://github.com/opentidehq/opentide/issues/255)).
- **MCP `search` always returns a list.** `platform=` matches the configuration key exactly, and `coverage` for a parent technique includes sub-technique rules and reports `matched_techniques` ([#252](https://github.com/opentidehq/opentide/issues/252), [#253](https://github.com/opentidehq/opentide/issues/253)).
- **MCP `opentide://vocabularies` is an index.** It lists `metadata`, `entry_count` and `uri`; entries live at `opentide://vocabularies/{name}` ([#254](https://github.com/opentidehq/opentide/issues/254)).
- **MCP `run_query` is an explicit stub.** It returns `stub: true` and `rows: null` rather than a successful empty result ([#258](https://github.com/opentidehq/opentide/issues/258)).
- **`mcp` is pinned `<2`, and `fastmcp` is not a dependency.** `opentide[sentinel]` declares the Azure packages it imports ([#256](https://github.com/opentidehq/opentide/issues/256)).

**Deprecated**

- **Positional `PATH` on `setup` subcommands is deprecated.** Use `--path` / `-C` instead; giving both is a usage error ([#248](https://github.com/opentidehq/opentide/issues/248)).

**Fixed**

- **`deploy metadata` and `generate inflight prune` skip their parent command.** They no longer run it first: a live deploy, or a second JSON document on stdout ([#243](https://github.com/opentidehq/opentide/issues/243)).
- **`info coverage --technique T1059` parses in either argument order** ([#257](https://github.com/opentidehq/opentide/issues/257)).
- **`generate docs --changed` no longer misses changes or crashes without a commit.** `generate inflight` finds changes the same way ([#241](https://github.com/opentidehq/opentide/issues/241), [#251](https://github.com/opentidehq/opentide/issues/251)):
  - on a trunk other than `main`
  - on a pushed feature branch
  - in untracked rules and non-ASCII file names
  - in a workspace nested inside the checkout
- **`generate extract sentinel|defender` names what is missing.** It reports the missing extra, tenant or key instead of failing at import ([#242](https://github.com/opentidehq/opentide/issues/242)).
- **`opentide generate explorer` is registered.** The GitHub CI template calls it instead of the nonexistent `opentide explorer build` ([#202](https://github.com/opentidehq/opentide/issues/202)).
- **Sentinel-only runs load only the Sentinel engine.** An engine that fails to load is reported instead of ending `deploy` with a traceback ([#246](https://github.com/opentidehq/opentide/issues/246)).
- **`validate --file objects/rules/x.yaml` honours the directory.** A path no longer matches a same-named file elsewhere, in the ID check and the MCP `validation_report` tool too ([#240](https://github.com/opentidehq/opentide/issues/240)).
- **Unparseable object YAML is a `yaml_parse` issue, not a traceback** ([#250](https://github.com/opentidehq/opentide/issues/250)).
- **Generated inflight jobs push on GitLab and Azure.** GitHub and Azure jobs target the repository's default branch instead of `main`, and concurrent inflight jobs retry instead of failing or dropping each other's shards ([#244](https://github.com/opentidehq/opentide/issues/244)).
- **The pre-commit hook validates the commit being made.** It checks that worktree rather than `OPENTIDE_REPO_ROOT`, covers nested and multiple workspaces, fails when its workspace is gone, and is not installed into a user-wide `core.hooksPath` ([#249](https://github.com/opentidehq/opentide/issues/249)).
- **`setup --path DIR --yes <subcommand>` applies both flags.** Every `setup` subcommand takes `--path` / `-C` and `--yes` / `-y`, and other `setup` options there are refused without hiding the subcommand's `--help` ([#248](https://github.com/opentidehq/opentide/issues/248)).
- **`--no-color`, `NO_COLOR`, `FORCE_COLOR=0` and `PY_COLORS=0` strip every ANSI escape.** That covers Typer help and usage errors on CI runners that force colour ([#282](https://github.com/opentidehq/opentide/pull/282)).
- **MCP `coverage` and actor search read `rule.techniques` and `threat.actors`.** UUID searches honour the other filters and ignore case, in `search` and `get_chaining` ([#252](https://github.com/opentidehq/opentide/issues/252)).
- **MCP schemas and templates resolve.** `opentide://schemas/rule` no longer returns `{}`, versioned template IDs resolve, and vocabularies are JSON rather than Pydantic `repr()` strings ([#254](https://github.com/opentidehq/opentide/issues/254)).
- **MCP `validate_query` reports real findings.** It no longer returns `valid: true` for any string ([#245](https://github.com/opentidehq/opentide/issues/245)).
- **`opentide-mcp` without the `mcp` extra prints the install line.** It no longer ends in a traceback, and `opentide setup mcp` warns when the extra is missing ([#256](https://github.com/opentidehq/opentide/issues/256)).
- **`splunk::2.x` rules map the same way in `validate` and `deploy`.** `search` and `cron_schedule` map onto `query` and `scheduling`, and a migrated `cron_schedule` is scheduled ([#233](https://github.com/opentidehq/opentide/issues/233)).
- **Tutorial and CLI reference samples match live output** ([#247](https://github.com/opentidehq/opentide/issues/247)).

**Security**

- **The GitHub inflight job no longer lands pull requests unreviewed.** In 0.3.0 it pushed an up-to-date pull request's head to the default branch; inflight jobs on every CI commit only `.opentide/inflight/` shards, from a worktree of the default branch ([#244](https://github.com/opentidehq/opentide/issues/244)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#040--2026-09-22) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.4.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.4.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.3.0 — 21 September 2026

The runtime floors rise to cryptography 50.x (CVE-2026-69247) and typer 0.27.

**Install**

```bash
pip install opentide==0.3.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **Runtime floors rise to cryptography 50.x and typer 0.27.** The cryptography upgrade is 50.0.1 (CVE-2026-69247), and typer 0.27 has no `all` extra: rich, shellingham and colorama are its default dependencies ([#235](https://github.com/opentidehq/opentide/pull/235)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#030--2026-09-21) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.3.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.3.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.2.1 — 18 September 2026

CVE checks and generated threat CVE tables use CIRCL Vulnerability-Lookup instead of NVD, and `validate --check cve` also looks up GHSA and GCVE identifiers.

**Install**

```bash
pip install opentide==0.2.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Added**

- **`validate --check cve` also looks up GHSA and GCVE identifiers.** GNA 0 GCVE ids (`GCVE-0-YEAR-N`) map to the reserved CVE key, and the check stays opt-in, so a default `opentide validate` stays offline ([#109](https://github.com/opentidehq/opentide/issues/109)).
- **Generated threat docs link each CVE to Vulnerability-Lookup.** Links go to `https://vulnerability.circl.lu/vuln/{id}`, and with `[cve].retrieve_details` true the docs add the published date, severity and aliases ([#109](https://github.com/opentidehq/opentide/issues/109)).
- **`threat.cve` is a first-class optional list on the threat body.** Schema validation accepts CVE identifiers there.

**Changed**

- **CVE lookups use CIRCL Vulnerability-Lookup instead of NVD.** CVE validation and generated threat CVE tables no longer scrape NVD through `mitrecve`; the bundled `[cve]` defaults point at [Vulnerability-Lookup](https://vulnerability.circl.lu), and legacy NVD link prefixes are remapped ([#109](https://github.com/opentidehq/opentide/issues/109)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#021--2026-09-18) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.2.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.2.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.2.0 — 18 September 2026

Generated templates hug `#` to each optional key, keep spacer lines blank and write rule `configurations` as commented platform stubs instead of `{}`.

**Install**

```bash
pip install opentide==0.2.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Changed**

- **Template placeholders are typed, with no YAML `null`.** `opentide generate templates` builds them from the models' fields, so nested bodies come from nested models ([#223](https://github.com/opentidehq/opentide/issues/223)).
- **Optional sections are commented with `#` hugging each key.** A nested key reads `  #enabled:`, not `#  enabled:`; nested optionals are not commented again, and spacer lines stay blank ([#223](https://github.com/opentidehq/opentide/issues/223)).
- **Rule `configurations` are commented platform stubs.** A rule template holds `#sentinel:` rather than `{}` ([#223](https://github.com/opentidehq/opentide/issues/223)).
- **VS Code snippets keep `configurations:` as a mapping.** Snippet conversion treats commented nested keys as children, so `configurations:` with only `#sentinel:` stubs is not turned into a tabstop.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#020--2026-09-18) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.2.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.2.0)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.8 — 16 September 2026

First-time `setup` and `generate` write templates without YAML `null` or misplaced children, and VS Code snippets get `tide-*` prefixes, descriptions and tabstops.

**Install**

```bash
pip install opentide==0.1.8
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Added**

- **VS Code snippets use `tide-*` prefixes.** `tide-threat`, `tide-objective`, `tide-rule` and `tide-<platform>` snippets have `scope: yaml`, descriptions and tabstops ([#194](https://github.com/opentidehq/opentide/issues/194)).
- **`opentide setup vscode --mcp` writes `.vscode/mcp.json`.** The parent `--vscode-setup` does not imply MCP ([#193](https://github.com/opentidehq/opentide/issues/193)).

**Fixed**

- **Missing `objects/*` folders log at debug, not error** ([#212](https://github.com/opentidehq/opentide/issues/212)).
- **Optional `#key:` template blocks comment their nested children.** YAML no longer attaches those children to the previous mapping ([#209](https://github.com/opentidehq/opentide/issues/209)).
- **Generated templates never emit YAML `null`.** Typed placeholders are restored ([#210](https://github.com/opentidehq/opentide/issues/210)).
- **`setup repo --platform` writes the enabled platform TOML.** `generate` then emits configuration stubs for those platforms ([#211](https://github.com/opentidehq/opentide/issues/211)).
- **Objective docs show `priority` as written.** It is not looked up in `criticality::1.0` ([#204](https://github.com/opentidehq/opentide/issues/204)).
- **GitHub docs use lowercase slug paths.** GitHub and generic docs write `docs/{rules,objectives,threats}/<slug>.md` instead of Title-Case UUID paths; UUID permalinks stay GitLab-only ([#203](https://github.com/opentidehq/opentide/issues/203)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#018--2026-09-16) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.8/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.8)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.7 — 16 September 2026

VS Code no longer reports "Matches multiple schemas", generated templates show required nested fields, and `opentide --json validate` reports each check's own status.

**Install**

```bash
pip install opentide==0.1.7
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **`invalid_ref` points at the leaf UUID field.** It no longer points at the parent object ([#186](https://github.com/opentidehq/opentide/issues/186)).
- **`opentide --json validate` reports each check's own `status`.** The `uuid`, `metadata`, `schema`, `vocab`, `query` and `references` checks no longer all read as failed ([#186](https://github.com/opentidehq/opentide/issues/186)).
- **Vocabulary names skip YAML list indices** ([#186](https://github.com/opentidehq/opentide/issues/186)).
- **VS Code no longer reports "Matches multiple schemas".** `yaml.schemas` maps each object folder recursively (`objects/threats/**/*.yaml`) instead of the router glob, so nested files keep their schema ([#185](https://github.com/opentidehq/opentide/issues/185)).
- **MCP templates match each host** ([#188](https://github.com/opentidehq/opentide/issues/188)).
  - `servers` for VS Code 1.102+ and Cursor
  - `OPENTIDE_REPO_ROOT` as `${workspaceFolder}` or `${CLAUDE_PROJECT_DIR}`
  - `.vscode/extensions.json` and `AGENTS.md`
- **Generated templates keep required nested fields uncommented.** `$ref` bodies are inlined, and a nested `required` list is no longer inherited from its parent ([#191](https://github.com/opentidehq/opentide/issues/191)).
- **`setup vscode` generates templates and schemas before snippets.** It fails if requested snippets could not be written ([#192](https://github.com/opentidehq/opentide/issues/192)).
- **`setup vscode` creates a missing target directory.** It no longer fails with `FileNotFoundError` ([#200](https://github.com/opentidehq/opentide/pull/200)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#017--2026-09-16) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.7/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.7)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.6 — 15 September 2026

`opentide generate` handles unquoted YAML dates, and interactive `opentide setup` no longer crashes after you choose a CI provider.

**Install**

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **`opentide generate` accepts unquoted YAML dates.** An unquoted `YYYY-MM-DD` in `metadata.created` or `modified` no longer fails with `TypeError: Object of type date is not JSON serializable` ([#178](https://github.com/opentidehq/opentide/issues/178)).
- **Interactive `opentide setup` gets past the CI features checkbox.** It no longer raises `ValueError: validate must be callable` after you choose a CI provider ([#177](https://github.com/opentidehq/opentide/issues/177)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#016--2026-09-15) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.6/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.6)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.5 — 13 September 2026

MITRE ATT&CK and MISP threat-actor vocabularies are ingested weekly with per-key versions, and ATT&CK groups stay catalogue-only, pinned through `threat.actors.name`.

**Install**

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Added**

- **ATT&CK and MISP threat-actor vocabularies are ingested weekly.** MITRE ATT&CK STIX and MISP threat actors merge with RFC 0003 per-key versions, and the schema pins for techniques, actors and datasources bump with them ([#174](https://github.com/opentidehq/opentide/pull/174)).

**Fixed**

- **ATT&CK groups stay catalogue-only (`att&ck.groups`).** Live objects pin them through `threat.actors.name` → `actors::*`.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#015--2026-09-13) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.5/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.5)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.4 — 13 September 2026

`threat.actors` takes objects with a scoped `name`, so `opentide generate` no longer crashes on actors, and nested vocabulary fields are checked against the pinned vocabularies.

**Install**

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Upgrade**

- If you wrote `threat.actors` as vocabulary ID strings, rewrite each actor as an object with a `name`, such as `name: att&ck::G0006`.

**Fixed**

- **`threat.actors` is a list of objects.** Each has a scoped actors-vocabulary `name` such as `att&ck::G0006`, and optional `sighting` and `references`; the generated JSON Schema no longer teaches `list[str]` ([#172](https://github.com/opentidehq/opentide/issues/172)).
- **`opentide generate` exports actors without crashing.** It no longer raises `'str' object has no attribute 'get'` on `threat.actors` ([#172](https://github.com/opentidehq/opentide/issues/172)).
- **Nested vocabulary fields are checked against the pinned vocabularies.** Threat leverage and viability, and objective composition, are no longer skipped.
- **The package imports on Python 3.10.**

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#014--2026-09-13) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.4/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.4)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.3 — 11 September 2026

`opentide setup ci` writes YAML that GitHub, GitLab and Azure parse, and `deploy` and `validate query` work locally without `DEPLOYMENT_PLAN` set.

**Install**

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **`opentide setup ci` emits parseable GitHub, GitLab and Azure YAML** ([#163](https://github.com/opentidehq/opentide/issues/163)).
- **`deploy` and `validate query` default `DEPLOYMENT_PLAN` to `FULL`.** With the variable unset or blank they no longer crash locally, and an illegal plan name fails with a clear error ([#164](https://github.com/opentidehq/opentide/issues/164)).
- **The tutorial's objects validate and lint** ([#165](https://github.com/opentidehq/opentide/issues/165)).
- **Generated templates include `YYYY-MM-DD` dates** ([#165](https://github.com/opentidehq/opentide/issues/165)).
- **`generate docs` writes under the detection repository** ([#165](https://github.com/opentidehq/opentide/issues/165)).
- **A base `pip install` can deploy.** `opentide info` reports `can_deploy: true` without the Azure or pandas extras, which a dry run and platform loading no longer need ([#166](https://github.com/opentidehq/opentide/issues/166)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#013--2026-09-11) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.3/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.3)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.2 — 11 September 2026

`opentide lint` checks filename slugs and recommended metadata, `setup hooks` installs a validate-on-commit hook, and `opentide generate` completes on a freshly scaffolded repository.

**Install**

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Added**

- **Generated pipelines set `OPENTIDE_REPO_ROOT`.** `opentide setup ci` sets it for every GitHub, GitLab and Azure job, to `github.workspace`, `$CI_PROJECT_DIR` or `$(Build.SourcesDirectory)` ([#51](https://github.com/opentidehq/opentide/issues/51)).
- **`opentide setup env` writes `.env.example`.** It holds `OPENTIDE_REPO_ROOT`, and `.env` is added to `.gitignore` ([#48](https://github.com/opentidehq/opentide/issues/48)).
- **`opentide setup hooks` installs a validate-on-commit hook.** The pre-commit hook runs `opentide validate --strict`, and is installed into `.git/hooks` when the path is a Git repository ([#49](https://github.com/opentidehq/opentide/issues/49)).
- **`opentide lint` checks filename slugs and recommended metadata.** `--fix` renames mismatched files, and `--strict` is the CI gate ([#108](https://github.com/opentidehq/opentide/issues/108)).
- **`opentide migrate objects` moves a CoreTide layout.** It dry-runs by default, and with `--apply` moves CoreTide `Configurations/` and `Objects/` into `.opentide/configurations/` and `objects/` ([#100](https://github.com/opentidehq/opentide/issues/100)).

**Changed**

- **`opentide setup skills` installs from the live opentidehq/skills catalogue.** The wheel no longer ships a snapshot, so discover, show and install fail with an actionable error when GitHub is unreachable ([#152](https://github.com/opentidehq/opentide/issues/152)).

**Fixed**

- **`opentide generate` completes on a freshly scaffolded repository.** It no longer fails with `AttributeError: SimpleNamespace has no attribute 'subschemas'`, and an empty catalogue is a valid export ([#153](https://github.com/opentidehq/opentide/issues/153)).

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#012--2026-09-11) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.2/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.2)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.1 — 11 September 2026

`opentide validate` and `generate` no longer crash with `UnicodeDecodeError` once pip has compiled bytecode beside the bundled configuration, and `setup skills discover` and `show` run as subcommands.

**Install**

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Fixed**

- **`opentide validate` and `generate` no longer crash with `UnicodeDecodeError`.** Nested configuration directories load `*.toml` only, so the `__pycache__` pip compiles beside the bundled TOMLs is skipped.
- **`opentide setup skills discover` and `show` run as subcommands.** A positional PATH on the skills group no longer swallows those names and starts an interactive install.
- **Starter skills install when GitHub is unreachable.** `opentide-detection-rule` and `detection-engineering` install from the packaged skill trees.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#011--2026-09-11) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.1/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.1)
- [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md)

## 0.1.0 — 9 September 2026

First public beta, not 1.0: the DetectionOps engine is a PyPI package you pin instead of a CoreTide submodule SHA, with the CLI, MCP server, SDK and seven platform adapters in one wheel.

**Install**

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**Added**

- **One wheel for Python 3.10–3.14.** `pip install opentide` installs the CLI (`opentide`), the MCP server (`opentide-mcp`), the SDK (`from opentide import Opentide`) and seven platform adapters; enable platforms with `opentide setup platforms`, not pip extras.
- **`opentide setup` scaffolds a detection repository.** It also sets up CI (GitHub, GitLab, Azure DevOps), the MCP client configuration and agent skills.
- **`validate`, `generate`, `deploy` and `document` are the operator commands.** `--strict` is the CI gate.
- **Seven platforms deploy, and five validate query syntax.** Sentinel, Defender for Endpoint, Splunk, SentinelOne and Carbon Black Cloud validate syntax; CrowdStrike and HarfangLab deploy only, and the CLI and MCP report `supported: false` for their query checks.
- **The object model is threat → objective → rule.** JSON Schema is generated from the models, and vocabularies are versioned TOML.

See the [CHANGELOG](https://github.com/opentidehq/opentide/blob/development/CHANGELOG.md#010--2026-09-09) for every change.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.0/)
- [GitHub Release](https://github.com/opentidehq/opentide/releases/tag/v0.1.0)
- [Announcement](https://opentide.org/blog/the-engine-is-opentide/)
- [Installation](./installation.md)
