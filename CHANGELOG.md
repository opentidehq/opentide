# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

## [Unreleased]

### Changed

- **Usage errors a command detects exit `2`, not `1`.** An unknown `info` section, an unknown `generate` phase, an invalid `validate --type`, a `share --target` that names no configured block, `info coverage` without `--technique`, `generate docs --changed` combined with a scope, and a `setup` prompt with no terminal (or under `--json`) now exit `2`, as [exit codes](docs/cli/exit-codes.md) already promised. A pipeline that tested for `1` on these should test for non-zero, or read `failure.code` from `--json`. A `share --target` naming a block that exists but is disabled still exits `1`.
- **One JSON document for every `--json` run, usage errors included.** `opentide --json valdate` prints a document with `failure.code` `usage_unknown_command` and `failure.suggestion` `validate`, and exits `2`; it used to print a Rich panel on stderr. Every document gains `schema_version`, `command`, `duration_ms`, `exit_code`, `summary`, `next_actions` and `failure`. Existing keys are unchanged; `error` is still a string. See [JSON output](docs/cli/json-output.md).
- **Every failure document carries `error`, and usage errors name the input at fault.** `error` is set on every non-zero exit, `--json validate` with issues included. `deploy --strategy PREVEW` names `--strategy` and suggests `PREVIEW`; a suggestion ignores case and `-`/`_`, so `validate --type RULE`, `info RULES` and `VALIDATE` suggest `rule`, `rules` and `validate`. `next_actions` commands in a document read `opentide --json …`. `opentide --json mcp` (a group with no subcommand) is a `usage_error` document instead of the help screen. Typer's multi-line `Choose from:` list is one line: `Missing option '--platform': choose from sentinel, splunk, …`.
- **`validate query` without `--live` and `rules unreviewed --older-than 9x` exit `2`** (`usage_missing_option`, `usage_invalid_value`) instead of `1`.
- **No colour in plain and agent output, on a terminal too**, unless `FORCE_COLOR` or `PY_COLORS` asks for it: CI logs (`CI=true`), `OPENTIDE_OUTPUT=plain` and coding agents get no colour escapes.
- **No `UnicodeEncodeError` on an ASCII stream.** With `PYTHONIOENCODING=ascii`, `·` prints as `-` and `…` as `...`, and a `--json` document escapes non-ASCII characters.
- Splunk schedule and time-range errors no longer start with `[FATAL]`.
- **`--json`, `--no-color`, `--debug` and the new `--quiet` work after the command.** `opentide validate --json` is the same as `opentide --json validate`.
- **Human output follows one grammar.** Warnings print first (`warning: …`), then one outcome line (`✓ Validation passed`, `! Catalogue lint found issues`, `Skipped: …`), then at most three next steps (`→ opentide lint --fix`). An ordinary failure is an `error:` line on stderr instead of a `FATAL` panel. Plain output (pipes, CI, `NO_COLOR`) is never wrapped, so paths stay on one line. Scripts that matched `OK `, `ISSUES `, `SKIPPED `, `WARNING ` or `FATAL:` should use `--json`.
- **`--debug` reads `OPENTIDE_DEBUG`.** `DEBUG` is still read when it is a boolean (`1`, `true`, `0`, ...). `DEBUG='*'`, which Node tooling exports, made every command exit `2`; it is now ignored. opentide no longer exports `DEBUG` to the processes it starts; it exports `OPENTIDE_DEBUG=1`.
- **`--json` logs `WARNING` and above on stderr**, like every other mode, instead of `INFO`; `--debug` shows everything. Log lines carry one level label (`warning: Tenant targets failed · system: sentinel`) instead of two.
- **Coding agents and `OPENTIDE_OUTPUT`.** Under a coding agent (`AI_AGENT`, `CLAUDECODE`, `CURSOR_AGENT`, ...) `setup` never prompts: it exits `2` and names the flags to pass. A failure ends with a tip to add `--json`. `OPENTIDE_OUTPUT=json|agent|plain|human` chooses the output mode.
- **The MCP server's stderr logs `WARNING` and above by default**, like `--json`; `--debug` (or `OPENTIDE_DEBUG=1`) shows everything.
- **`opentide mcp start` keeps stdout for JSON-RPC alone.** A `print`, a console line or a child process writing to stdout while a tool runs lands on stderr instead of corrupting a frame.
- **Faster start.** `opentide --version` answers before Typer, Rich or the detection registry load: about 30 ms instead of about 1 s. `opentide --help` and shell completion list the commands without importing them (about 0.3 s instead of 1 s); a command's module loads when it runs. `import opentide` no longer loads the registry; `from opentide import Opentide` still works and loads it then. Output, help text and JSON are unchanged.
- **Long runs show their steps.** `generate` (every phase and subcommand), `validate query`, and the promotion and deploy steps of `deploy` print one line per finished step in a pipe or in CI (`✓ schemas · 6 files · 2.6s · .opentide/schemas/`) and a live checklist with a spinner at a terminal. They replace the `== Section ==` headers, which engine modules no longer print. `--quiet` and `--json` show no steps; the JSON document carries them under `steps`.
- **Shell completion completes values, and installs with an outcome line.** Tab after `--uuid`, `--file`, `--type`, `--technique`, `--platform` (enabled platforms first) or `--strategy` offers values from the workspace, with names and titles beside them. Completing a value never loads the command or the engine (about 0.2 s, the same as a command name). `opentide --install-completion` prints `✓ Installed zsh completion in ~/.zfunc/_opentide` and the command that loads it; `--install-completion zsh` and `--show-completion zsh` take the shell named after them, and any other word is a usage error naming the shells. `opentide completion` points at both options.
- **Long runs show progress in the tab or taskbar** (OSC 9;4) in Windows Terminal, WezTerm, kitty, Ghostty 1.2 or later and iTerm2 3.6.6 or later, cleared on exit and on Ctrl-C. `OPENTIDE_PROGRESS=0` turns it off, `OPENTIDE_PROGRESS=1` sends it to any terminal.
- **Outcome lines carry counts.** `✓ Generated 21 files in 5.8s · 6 phases`, `✓ Imported 14 rules from sentinel · 2 skipped`, `✓ Shared 4 objects to misp-prod · 3 new, 1 updated`, `! 5 rules unreviewed for 90 days` (`Skipped: No rules yet` on an empty catalogue), `✓ 12 queries valid on 2 tenants` (`validate query --live`), `Would move 3 folders · pass --apply to migrate`, `Would share …` (dry runs take no `✓`), `✓ Moved 6 vendor ids to .opentide/states/deployment/ · …`. The JSON `message` reads the same, and `summary` holds the numbers. Scripts that matched `Full generation pipeline completed`, `Deployment completed`, `Setup complete`, `Share finished: …` or `Listed N unreviewed rules` should read `ok`, `status` and `summary` from `--json`.
- **`deploy --dry-run` prints a plan**: each rule on each tenant with `+ create`, `~ update`, `- disable` or `× delete`, then `Plan: 1 to create, 0 to update, 0 to disable, 0 to delete`; the platforms and tenants it covers are on the plan's header. A rule that would fail to deploy prints above the tally as `error[compile_missing_field]: configurations.sentinel.grouping is missing`, its file and a `help:` line, instead of a raw Python error such as `AttributeError: 'NoneType' object has no attribute 'alert_severity'` (an empty `response:` block); `--json` lists them under `diagnostics`. The tally never takes `error:`; the exit code carries the failure. A dry run reports an unset `$VARIABLE` as `warning: a real deploy would need $…`, not as an error. Sentinel, Splunk, Elastic, Carbon Black and HarfangLab write a rule by its UUID, so their rows say `create or update` rather than guess. A real run ends with `✓ Deployed 3 rules to 2 tenants · 1 created, 2 updated · 12.4s`. `--json` adds `changes` (one entry per rule and tenant) and the tally in `summary`.
- **`setup` has a welcome, a summary and next steps.** The interactive wizard opens with the opentide logo and the tagline, prompts in the brand style, and refuses an empty repository name on the row below the field. The setup plan it confirms names each choice as the prompts did (`GitHub Actions`, `VS Code`, `none`) and the folder relative to where you are; setting up the current folder ends with `✓ Created … here`. Ctrl-C prints one line. Without a terminal, or under a coding agent, every `setup` command exits `2` naming its flags (`--platform, --ci`). Every `setup` command lists what it wrote, prints its warnings once before the outcome line (`✓ Created Tutorial Detections in ./tutorial-detections`, `✓ Wrote .github/workflows/opentide.yml`) and numbers the next steps. The "no default branch" warning is no longer printed twice.
- **A bare `opentide` at a terminal shows a home screen**: the icon, the tagline, the workspace and its git state, catalogue counts, schema health, enabled platforms, and up to three next steps. The workspace shows relative to the current directory (`.` at its root), and a narrow terminal drops the step descriptions rather than wrap them. In a pipe, in CI, under an agent or with `NO_COLOR` it prints the help, as before.
- **Help is grouped and shorter.** `opentide --help` lists commands under Author, Ship, Workspace, and Agents and integrations, carries the tagline instead of "DetectionOps Engine", and every command's help ends with examples. Summaries are at most 60 characters. `--platform` shows `PLATFORM` and lists its values instead of eight names run together, and `--proxy` no longer shows a stray backslash. Every option has help text, examples are single-spaced, and help ends with one newline. `info` lists each platform as `enabled · deploy, validate` instead of `enabled=True [deploy, validate]`.
- **"MDR" is gone from what people read.** `TideMDRDataModelErrors` is now `TideRuleDataModelErrors`; the old name still works in `except` clauses, and error messages carry the new one. VS Code platform snippets are titled `Platform configuration : Microsoft Sentinel Template` instead of `MDR Systems Deployment : …`; their prefixes (`tide-sentinel`, …) are unchanged. Log events say `rule` (`rule_skipped_for_strategy`, `rule_promoted`, …, was `mdr_…`), generated docs head the section `Signal rule coverage`, and the ATT&CK Navigator legend reads `Rule Only - Needs to be checked`. Configuration keys (`mdr_test_uuids`) are unchanged; the `MDR Alert Severity` vocabulary keeps the name the specifications repository gives it.
- **A rule's `severity` uses the alert labels, `Informational` to `Critical`.** Rule `severity` was pinned to `severity::1.0`, the Threat Severity incident scale (*Localised incident* … *National cyber emergency*). That contradicted the rule spec, its examples and opentide's own default, `Informational`, which therefore failed validation. Rules now use `alert_severity::1.0`, the same labels as `response.alert_severity`; threats keep the incident scale ([specifications#60](https://github.com/opentidehq/specifications/pull/60)). **Action:** a rule whose top-level `severity` is an incident-scale value now fails `validate`. Replace it with an alert label (for example `Substantial incident` → `High`), then run `opentide generate` to refresh schemas and templates.
- **The docs flavor adapts to where the docs are read.** Without `--flavor`, `generate docs` uses the CI platform running the job (`GITHUB_ACTIONS`, `GITLAB_CI`, `TF_BUILD`), then the host of the repository's `origin` remote (Azure DevOps over HTTPS or SSH included), so a local run renders what CI would, then `[flavor] default` (CommonMark `generic`). Any CI that sets only `CI` (Jenkins, CircleCI) used to get the GitLab flavor; it now follows the remote or the default.

### Deprecated

- `opentide.core.logging.print_banner()` (also `opentide.cli.print_banner`) warns with a `DeprecationWarning`, draws the new icon and returns it with the tagline as text. It will be removed in a later release.

### Removed

- `coretide-logo.png` from the repository root.

### Fixed

- **Elastic ES|QL and EQL checks read past comments and strings** ([#616](https://github.com/opentidehq/opentide/issues/616)). The ES|QL pre-flight now takes its index sources from the `FROM`/`TS` command alone: a comment before `FROM`, a leading `SET …;`, a `FROM` subquery, or an index pattern containing `metadata` (`logs-metadata-*`) no longer makes it check the wrong indices. The validation warnings changed with it: `METADATA _id` written only in a comment or string no longer counts, `INLINE STATS` no longer makes a query aggregating (as in Kibana), `sequence` in a string no longer makes an EQL query a sequence, and `maxspan=500ms` is 500 milliseconds, not 500 minutes.
- **`ssl = false` was ignored on Elastic when a CA bundle is exported.** With `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` set, as on many corporate hosts and CI runners, `requests` replaces a session's `verify` with the bundle for every request that does not pass its own (psf/requests#3829). Elastic set verification only on its session, so `deploy` and `validate query --live` against a self-signed Kibana failed with `CERTIFICATE_VERIFY_FAILED`; Defender's Graph API fallback and Sentinel's ARM calls had the same gap. Every platform's HTTP session now keeps the tenant's `ssl` for every request; with `ssl = true` an exported bundle is still used.
- **`share retract --type` and `--file` retracted every shared object.** Retract added every UUID in the sharing ledger to its candidates and only `--uuid` narrowed them, so `share retract --type rule --delete --yes` also deleted the threat and objective events. An object still in the repository is now retracted only when the filters select it; a deleted object is matched by `--type` against the schema its ledger line recorded, and never by `--file`.
- **`share push --publish` left an unchanged event unpublished.** After a push without publish, a later `push --publish` saw the same content hash, reported `unchanged`, exited `0` and never published. Push now publishes a matched event that is still unpublished when the run asks for it and reports `updated`; `push --dry-run --publish` predicts the same.
- **Two objects whose names slugify alike shared one docs page.** `Sentinel KQL Rule` and `Sentinel-KQL rule`, or any two names with no ASCII letters (both `object.md`), wrote the same file and both index rows linked to it. The second object's page now gets a `-<uuid[:8]>` suffix; existing page names change only on a collision.
- **`generate docs --changed` deleted pages of objects that still exist, and renames left stale pages.** A moved but unstaged YAML file, or a deleted rule replaced by one with the same name, had its new page unlinked; a renamed object's old page was never removed, and pages under a renamed objective kept linking it. Every docs run now removes the generated pages no object writes any more, leaving `README.md` and hand-written files alone, and `--changed` rewrites the pages that link to a renamed object.
- **Elastic platform configurations were missing from rule pages.** The section walked a hard-coded platform list written before Elastic existed.
- **A `|` or a newline in a name broke Markdown tables.** Rule, signal and author values shifted the columns of the metadata, coverage and index tables. Table cells are now escaped.
- **Signal links on GitHub pages did not jump to the signal.** The anchor collapsed punctuation (`#process-cmd-exe-spawn`) where GitHub ids the heading `process---cmdexe-spawn`. GitHub pages now use GitHub's anchor rule.
- **`generate extract sentinel` wrote unparsable YAML** for rules that group incidents by entities or details, alert titles starting with `{{Column}}`, names containing `"` or `\`, and descriptions or queries whose first line is indented. Values are now written as proper YAML scalars, and each file is parsed before it is written.
- **Imported Defender rules targeted the tenant `PandoraStores`,** a name from the original author's environment. The tenant the rule was listed from is now written.
- **Imported rules with the same display name overwrote each other** on Sentinel and Defender. The second file name now gets the first eight characters of the rule's UUID.
- **A Defender detection deployed to several tenants imported as one file per tenant, all with the same UUID.** It is now one rule whose `tenants` lists every tenant it was found in; a warning names tenants whose copy differs.
- **`generate extract defender` read only the first page of rules and could hang.** The listing now follows `@odata.nextLink`, times out after 60 s per page, and an HTTP error names the tenant and status instead of raising `KeyError`.
- **Imported Elastic rules were marked TLP:CLEAR.** Enabled rules import as PRODUCTION, which `share push` shares by default, so an organisation's private detections would have been published as TLP:CLEAR. They now import as `amber`, as Sentinel's do.
- **Splunk retirements never removed anything.** The request handler built `urllib` requests without a method, so splunklib's DELETE went out as a GET; Splunk answered with the saved search and the run reported it deleted. A lookup that failed for any reason (401, TLS, a refused connection) was also read as "already absent". DELETE is sent as DELETE, and only a missing saved search counts as absent.
- **A Splunk deploy answered with a gateway redirect counted as success.** A `307` on the update request was logged and returned as success; it now fails the deploy.
- **Splunk and Carbon Black deployed every tenant with the first tenant's settings** (Splunk actions, scheduling, skew and offset; the Carbon Black watchlist). Each tenant now uses its own.
- **Carbon Black updates appended a second IOC and retirements removed nothing.** `remove_iocs_by_id` was given a string, which the SDK read as a set of characters. A shared report is now deleted only when no other rule's IOC remains in it.
- **Defender, SentinelOne, CrowdStrike, HarfangLab and Splunk calls had no timeout,** so a tenant that accepted the connection and never answered hung the job until the runner killed it. Every platform session now times out.
- **Defender's minimal-configuration retry posted to the wrong endpoint** and could never succeed; it now retries where the rule is created, and an error body that is not JSON no longer hides the HTTP status.
- **CrowdStrike rejected the `US-GOV-1` API domain** because of a stray colon in the match.
- **SentinelOne sent `cool_off` as the raw string** (`"30m"`) instead of minutes.
- **KQL `let` values with a backslash or quote broke the Sentinel and Defender query** (`C:\Windows\Temp\` escaped the closing quote). String values are now escaped.
- **HarfangLab Sigma rules with `:` or quotes in a title or value were invalid YAML, and a value like `yes` became a boolean.** The rule is now serialised with a YAML dumper.
- **Deploys could ship another open pull request's unreviewed query.** Every registry build applied the inflight preview shards, so deploy and `validate --strict` read a shard of the same or higher version instead of the committed file. Only preview output applies shards now: `generate docs`, the docs SDK's `write_all` and the explorer export.
- **Pull request runs deployed and validated rules the target branch changed.** The diff ran from the merge base to the merge commit GitHub, Azure and GitLab merged-results build; it now starts at the merge commit's first parent. A `pull_request_target` run saw none of the request's changes. Both are fixed; a `pull_request_target` run takes the request's base and head commits from the event payload, so a pull request from a fork no longer needs its branch on `origin`.
- **A push of several commits deployed only the last commit's rules** on GitHub; the diff now starts at the push's `before`.
- **`setup ci github --explorer-pages` could cancel queued production deploys:** `concurrency: group: pages` sat on the whole workflow and Pages permissions on every job. Both are now on the `deploy-explorer` job.
- **Rules saved as `.yml` were never validated** and failed deploy with `KeyError: '<uuid>'`. The registry indexes `.yml` objects.
- **A platform modifier applied when only some of its conditions held** (`tenants` replaced the `status` result, and a `flags` condition was skipped for rules without flags). All set conditions must now hold.
- **`setup hooks` could corrupt an existing `.pre-commit-config.yaml`** in the `pre-commit sample-config` layout or with a top-level key after `repos:`. The hook is inserted after the last repo, and the file is written only if it still parses.
- **Hook scripts were written with CRLF on Windows,** which Git Bash refuses; they are written with LF and re-running setup repairs a broken one.
- **Options typed before a subcommand were silently dropped:** `opentide share --dry-run push` really pushed and `opentide deploy --dry-run migrate-state` rewrote files. They are passed to the subcommand or refused.
- **`DEBUG=*` (the Node convention) made every command exit 2.** `DEBUG` is now read leniently.
- **`setup mcp` overwrote `.mcp.json` and `setup skills` overwrote `AGENTS.md`, `CLAUDE.md` and Copilot instructions.** MCP configs are merged; existing agent entrypoints are kept with a warning.
- **A `TypeError` inside a deployer surfaced as an unrelated "unexpected keyword argument 'deployment'" traceback** with no JSON result. The legacy retry is gone; a platform failure is a failed result naming it.
- **`migrate vocab-scope --apply` rewrote every line ending,** and **`migrate objects` reported success while leaving `Configurations/` behind.** Line endings are kept, and every skipped path is a warning (exit 1 under `--apply`).
- **`setup skills --install X` without a target ignored `--install`, `--all` and `--name`;** **`lint --fix` could not fix a case-only filename on macOS/Windows;** **`rules unreviewed` crashed on one unreadable rule;** **`generate docs --rules --threats` generated only rules;** **`setup --json --no-promotion` reported no platforms;** **`setup skills --all` made one GitHub API call per skill.** All fixed.
- **`validate` crashed on a `threat:` or `objective:` block whose keys are all commented out,** and on a YAML parse error recorded without an object type. Both are now reported as issues.
- **A Defender block without `scope` passed validation, then broke loading of every rule.**
- **The `uuid-format` check accepted any UUID** (v1, v5, nil, braced, unhyphenated). It now requires a hyphenated version-4 UUID.
- **Duplicate signal UUIDs were never reported;** a copied objective silently took over its original's signals.
- **An unreachable CVE lookup passed silently, even with `--strict`.** It is now a `cve_lookup_unavailable` warning.
- **A small YAML file of nested aliases took seconds to minutes to validate, and a recursive alias crashed `validate`.** Parsing is linear and a recursive alias is a YAML error.
- **The MCP `validate_rule` and `validation_report` tools validated the workspace as it was when the server started,** and one rule that failed to load broke `validate_rule` for all. They now reload and look rules up individually.
- **`validate_all_objects(objects_index)` and `DetectionRule.validate_query` in the SDK ignored their input / always returned `ok=True`.**
- **`DetectionRule.validate_query()` in the SDK raised `TypeError` or checked nothing.** It called the platform validator without run strategies, which most validators require; without them no tenant is targeted. It now validates this rule object (an edited or unregistered rule used to be looked up again by UUID) against the strategies the CLI uses by default.
- **A Carbon Black org without any watchlist failed with `AttributeError`** instead of the "nonexistent Watchlist" error that names the watchlist to create.
- **Defender's deployer rejected rule objects and its validator an empty selection** (SDK callers). Both now accept rules as objects or UUIDs, like the other platforms.
- **A rule without a `configurations` block failed deep in a deployer with `'NoneType' object has no attribute …`.** The error now names the rule.
- **Generated schemas:** the visibility configuration schema rejected every valid configuration; a misspelled rule tenant passed and deployed nowhere (tenants are now an enum of the configured ones); a Splunk rule from the shipped template was flagged for missing `scheduling`; `metadata.tlp` ignored its vocabulary pin; a scoped vocabulary entry without stages crashed generation.
- **ATT&CK groups present in several domains kept the Mobile entry** (`G0007` read `[Mobile] APT28`); the generator now keeps the Enterprise one. The bundled vocabulary is regenerated upstream in `opentidehq/specifications`.

## [0.17.2] — 2026-10-22

Patch release. Nothing to regenerate. A `uv` install resolves a current boto3 again (python-dateutil 3.0.0 had sent it back to a 2014 release that cannot import). A Splunk tenant reached through a proxy that answers with its own HTML page now fails with a message naming the proxy and the `NO_PROXY` value to set, instead of `xml.etree.ElementTree.ParseError: mismatched tag`. If your pipeline replaces opentide's Splunk handler with `verify=not ssl_enabled`, delete that step and list the Splunk host in `NO_PROXY` and `no_proxy`: the patch works only by skipping the proxy, and with `ssl = false` it turns certificate verification on.

### Fixed

- **A proxy's HTML page read as a Splunk TLS failure.** When `HTTPS_PROXY` or `OPENTIDE_PROXY` sends an internal Splunk tenant through a TLS-inspecting proxy, the proxy answers with its own page. With `ssl = false` the proxy's certificate is accepted, and splunklib failed to parse the page as XML with `ParseError: mismatched tag`, which read as a certificate fault; 0.17.1's notes repeated that reading. Splunk's REST API never answers with HTML, so the client now raises `SplunkAnsweredHtmlError` (a `ConnectionError`; `validate query --live` reports it as the tenant's result). The message names the address, the page title and the proxy (without credentials), and gives the `NO_PROXY` entry to add. Without a proxy it points at the port: 8089 is the REST API, 8000 Splunk Web.
- Each Splunk connection logs `splunk_tenant_route` with `via` set to the proxy it goes through, or `direct`.
- **A `uv` install of opentide could not import the Carbon Black SDK.** python-dateutil 3.0.0 came out on 21 October. botocore caps it below 3, and `uv`'s resolver chose dateutil 3 and walked boto3 back to `0.0.3`, whose botocore fails on `from six.moves import configparser`. Carbon Black deploys and live query checks, and anything importing `cbc_sdk`, failed. opentide now requires `boto3>=1.35`, so the resolver keeps a current boto3 and caps python-dateutil. `pip` was not affected. Until you upgrade, `uv pip install opentide==0.17.1 'boto3>=1.35'` works around it.
- The troubleshooting entry for 0.17.0's `ssl = false` bug said that it often failed with an XML `ParseError`. It failed with `CERTIFICATE_VERIFY_FAILED`; a `ParseError` means an HTML answer.

### Install

```bash
pip install opentide==0.17.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.17.1] — 2026-10-21

Patch release. Nothing to regenerate. A tenant's `ssl` now decides certificate verification for every call opentide makes to that tenant, on every platform. Splunk deploys and live query checks work again against a tenant with `ssl = false` (a self-signed certificate), and Splunk rules with a `trigger` block deploy. If your pipeline patches the installed `opentide/platforms/splunk/client.py` or `deployer.py` with `sed` to work around either bug, delete those steps: after upgrading their patterns match nothing. A patch, not a minor: each fix restores what the configuration already documented, and the stricter `ssl` check only refuses values that never worked.

### Fixed

- **A Splunk tenant with `ssl = false` still verified the certificate.** The tenant's `ssl` reached the HTTP handler through the `TIDE_SPLUNK_SSL_ENABLED` environment variable, which held the string `"False"`, and the handler tested the string, which is true. Against a Splunk with a self-signed certificate, every `deploy` and `validate query --live` failed on the TLS handshake, often reported as an XML `ParseError`. Each connection now carries its own tenant's `ssl`, so two tenants with different settings in one run each get their own. `TIDE_SPLUNK_SSL_ENABLED` is no longer read or written. `TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS` is gone the same way: once a live query check had set it, a later deploy in the same process stopped raising on HTTP errors.
- **Splunk rules with a `trigger` block failed to deploy** with `HTTP 400 Bad Request -- Argument "quantity" is not supported by this handler.` The deployer sent the `savedsearches.conf` names `counttype`, `relation` and `quantity`, which the `saved/searches` REST endpoint refuses. `trigger.condition`, `comparator` and `threshold` now deploy as `alert_type`, `alert_comparator` and `alert_threshold`, the names the bundled `splunk.toml` defaults already used.
- **Defender for Endpoint and Sentinel ignored `ssl = false` for part of their traffic.** Defender requested its Entra ID token, and deployed through the Graph API fallback for a custom detection, with verification always on. Sentinel's Entra ID token request (deploy and live query check) always verified too. Behind a TLS-inspecting proxy that is what failed first. Both now apply the tenant's `ssl` to every request, the token request included.
- **An unset `ssl = "$VAR"` failed with an unrelated error.** On every platform but Splunk, the literal `$VAR` reached the HTTP client as the path of a CA bundle, and the call failed with `Could not find a suitable TLS CA certificate bundle`. Every platform now refuses it before the first request and names the tenant and the variable: `crowdstrike tenant 'Primary' setup: ssl is unset ($CROWDSTRIKE_SSL)`.
- **A refused Splunk request lost Splunk's reason.** The handler read the error body into the log, then gave splunklib an empty one, so the raised error read `HTTP 400 Bad Request -- b''`. The error now carries Splunk's message.
- **A tenant's `ssl` must be a boolean.** `ssl = "$SPLUNK_SSL"` resolves to the variable's text, and the text `false` verified the certificate too. `true`/`false`, `yes`/`no`, `on`/`off` and `1`/`0` (any case) now read as booleans on every platform. Any other value fails to load and names the tenant: `splunk tenant 'Primary' setup: ssl must be true or false, got 'sometimes'`.
- Carbon Black no longer logs `ssl_has_been_set_to` with the first tenant's value, which read as if it applied to every tenant; each tenant's `ssl` is passed to the SDK, as before.

### Install

```bash
pip install opentide==0.17.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.17.0] — 2026-10-20

Minor release with **breaking changes**: deployment plans are removed. A deploy now names the status strategy it carries out, and a tenant lists the strategies it accepts. Three things need action after upgrading; each old setting fails with a message naming its replacement.
- **Replace `--plan` and unset `DEPLOYMENT_PLAN`.** `--plan STAGING` becomes `--strategy PREVIEW`, `--plan PRODUCTION` becomes `--strategy RELEASE`, and `--plan FULL` (or no plan) becomes `--strategy PREVIEW --strategy RELEASE --all`.
- **Replace each tenant's `deployment` key** in `.opentide/configurations/platforms/*.toml`: `"STAGING"` becomes `strategies = ["PREVIEW"]`, `"PRODUCTION"` becomes `strategies = ["RELEASE"]`, `"ALWAYS"` is removed, and `"MANUAL"` becomes `manual = true`.
- **Regenerate generated pipelines** with `opentide setup ci <github|gitlab|azure> --yes`. Deploy jobs then pass `--strategy`, live query validation checks only the rules each run changed, and GitLab merge request pipelines start at all.

Run `opentide generate` to refresh the editor schemas' objective and signal labels; the vocabulary warnings stop either way.

### Breaking

- **`opentide deploy --strategy` replaces `--plan`.** A run deploys the rule files it changed whose status maps to its strategy, to the tenants that accept that strategy. `--strategy PREVIEW` deploys rules whose status maps to `PREVIEW` or `UNIVERSAL`. `--strategy RELEASE` deploys rules mapping to `RELEASE` or `UNIVERSAL`, and disables or deletes those mapping to `DISABLEMENT` or `DELETION`. The option is required and repeatable, and takes only `PREVIEW` and `RELEASE`. A status name such as `STAGING` is refused with the strategy it maps to in your configuration. Plans named a pipeline with the same words as two default statuses, which read as if `STAGING` and `PRODUCTION` were canonical statuses. They are not: they are two of the default statuses, and only the strategy a status maps to decides anything.
- **Which rule files a deploy reads follows the CI context.** In a pull or merge request pipeline, deploy reads the files changed since the merge base. In any other CI run, it reads those the push changed. Outside CI, it reads those the last commit changed; it used to read every rule file. `--all` reads every rule file. Without `--all`, rules that map to `DISABLEMENT` or `DELETION` are included (`--drop-deprecated` leaves them out); with `--all` they are left out (`--keep-deprecated` includes them).
- **Tenants declare `strategies`** (`PREVIEW`, `RELEASE`, or both when omitted) and optionally `manual = true` (only rules that list the tenant). The `deployment` key fails to load and names the replacement line.
- **`--plan` and `DEPLOYMENT_PLAN` are removed.** `--plan`, or `deploy` and `validate query --live` with `DEPLOYMENT_PLAN` set, exits `2` and names the `--strategy` to pass. Generated inflight jobs no longer export `DEPLOYMENT_PLAN`.
- **`validate query --live` checks each rule on the tenants a deploy sends it to.** Before, a run without `--plan` reached every tenant. Now a `PREVIEW` rule is not checked on a tenant that only accepts `RELEASE`; the pull request that moves it to a `RELEASE` status checks it there. `--strategy` narrows the check. `--json` reports `strategies` instead of `plan`.
- **SDK and deployer API.** `DeploymentStrategy` is removed. Deployers and validators take `strategies` (a tuple of `StatusStrategy`) instead of `deployment_plan`. `rule.deploy(platform, dry_run=False, *, strategies=None)` deploys a rule by the runs its own status needs when `strategies` is omitted.
- The `mdr_skipped_for_plan` log event is now `rule_skipped_for_strategy`, with the rule's `strategy`, the run's `run_strategies`, and `deployed_by`. `adding_tenant` and `skipping_tenant` name the rule strategy, the tenant's strategies and the run's.

### Added

- **[Statuses, strategies and tenants](https://opentide.org/docs/usage/concepts/statuses-and-strategies/)**: a page on how a status maps to a strategy, which runs deploy which strategies, which tenants accept them, and how promotion interacts. It includes worked examples and a migration table from plans.
- **`deploy --dry-run --json` lists the tenants** each platform's rules would reach (`tenants`), and every deploy result names its `strategies`.
- **`opentide validate query --changed`** checks only the rule files a deploy of the same run reads: the pull or merge request's diff, the push's, or outside CI the last commit's. `--json` reports `"scope": "changed"`.
- **`opentide validate query --file` and `--uuid`** (repeatable) check only the selected rules. A target that selects no rule file directly in the rules folder fails with exit `1` and is listed under `unmatched`, before any query is sent. `--json` reports `"scope": "selected"`.
- **`OPENTIDE_PROXY`** sets the global `--proxy` when the flag is omitted, so a CI/CD variable can send opentide's platform calls through a proxy without editing the generated pipeline. Hosts in `NO_PROXY` are still reached directly, with or without `--proxy`: one deploy reaches a cloud tenant through the proxy and an internal Splunk directly, with no per-platform job.

### Changed

- Generated pipelines run `opentide deploy --strategy PREVIEW` in the pull or merge request job and `opentide deploy --strategy RELEASE` in the default-branch job. The job ids (`deploy_staging`, `deploy_production`) are unchanged. The CI/CD guide's hand-written pipelines match; they used to run `DEPLOYMENT_PLAN: staging` on pushes to `main`, which has no pull request to diff.
- The CI/CD guide covers pipelines behind a proxy or a private CA: which proxy variables `pip`, `apt-get`, `git` and opentide read (set both spellings), `NO_PROXY` for internal tenants, and the CA bundle variables to use instead of `GIT_SSL_NO_VERIFY`. The global options page lists `--proxy`.
- `--wide` is documented as what it does: ignore the strategy filter, not widen the output.

### Fixed

- **Generated pipelines checked every rule's query on every run.** The live query step ran `opentide validate query --platform <p> --live` with no scope, so a pull request that edited one rule sent the whole catalogue to the tenant; a catalogue of a few hundred Splunk rules took most of an hour. It now passes `--changed`, and the jobs that run it fetch full history (GitHub `fetch-depth: 0`, GitLab `GIT_DEPTH: "0"`, Azure `fetchDepth: 0`).
- **Generated GitLab pipelines could not start a merge request pipeline.** A GitLab job with no `rules` defaults to `except: merge_requests`, so the merge request pipeline held only `deploy_staging` and `inflight_shards`, whose `needs: generate` named a job that was not added: GitLab refused the pipeline, the staging deploy and the inflight shards never ran, and every push to the branch also ran a branch pipeline. The file now sets `workflow:rules` for merge request and default-branch pipelines, so every job runs in a merge request pipeline and one push starts one pipeline. A push to a branch that has no merge request yet starts no pipeline; open a (draft) merge request to validate it, as GitHub validates pull requests.
- **`opentide generate` logged a vocabulary warning per objective.** The editor schemas describe each objective with its priority, and looked that value up in the `criticality` vocabulary for an icon: `High` logged `Vocab parameter not found` (no vocabulary defines `icon`) and `Critical` logged `Vocab identifier not found` (an objective's `priority` is free text, commonly an `alert_severity` value, not a `criticality` one). The description prints the value as authored, labelled **Priority** for an objective, **Severity** for a signal and **Criticality** for a threat, with no lookup. Regenerate schemas with `opentide generate` to update the labels.
- `--proxy` (and now `OPENTIDE_PROXY`) also sets the lowercase `http_proxy` and `https_proxy`. Python's HTTP clients prefer the lowercase spelling, so an inherited `http_proxy` used to win over the flag.
- A GitHub pull request diff from a fork, whose head branch is not on origin, takes the request's base from the merge ref's two parents instead of failing with `Could not find git ref origin/<branch>`. This applies to `deploy` and `validate query --changed`.
- A GitLab push diff with no previous tip (`CI_COMMIT_BEFORE_SHA` all zeros, as on a branch's first push, a manual run or a schedule) diffs from HEAD's first parent, as on GitHub and Azure, instead of failing with `No Source Commit Found`.

### Install

```bash
pip install opentide==0.17.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup ci <github|gitlab|azure> --yes
opentide validate --strict
```

## [0.16.1] — 2026-10-20

Patch release. Nothing to regenerate and nothing to do after upgrading: the SDK class is renamed `Opentide` with the old spelling kept as a deprecated alias.

### Changed

- **The SDK class names lose their second capital.** `Opentide` (the registry singleton) and `OpentideRegistry` replace `OpenTide` and `OpenTideRegistry`. `from opentide import OpenTide`, `opentide.core.OpenTide` and `opentide.core.registry.OpenTide` / `OpenTideRegistry` still import and return the same objects, and raise a `DeprecationWarning`; the old spelling goes in a later release. Docs and snippets use `Opentide`.
- The project is spelled `opentide`, lowercase, across the CLI help, docs, generated pipelines (`name: opentide`, `opentidehq` as the GitHub owner) and the MCP server name (`opentide`, was `OpenTide`). The `OPENTIDE_*` environment variables and the Elastic rule tag `OpenTide` are unchanged.

### Fixed

- `opentide setup skills` accepts the catalogue manifest's `source` in any letter case. GitHub names are case-insensitive, and a manifest that spelled itself `OpenTideHQ/skills` logged `Skills manifest source rejected` on every run, although the fallback installed the same catalogue.

### Install

```bash
pip install opentide==0.16.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.16.0] — 2026-10-19

Minor release: `pip install opentide` is the only install, and two things need action after upgrading.
- **Regenerate generated pipelines** with `opentide setup ci <provider> --yes`. They now take tenant configuration from the default branch before credentialed jobs (security), and an install with no extras validates every platform live.
- **Regenerate schemas** with `opentide generate schemas`: technique pins move to `att&ck::1.2` (ATT&CK 20.0), and techniques added since ATT&CK v17 validate again.

It is a minor because `generate` and `validate` now fail on input they used to accept (a phase that logs an error, a missing or unknown `metadata.schema`), and lint and generate output change.

### Security

- **Generated pipelines no longer let a pull request choose where platform credentials go.** Live query validation and the staging deploy hold platform secrets and send them to the tenant URLs and `$VAR` references in `.opentide/configurations`. On a pull request that directory came from the pull request itself, so a configuration-only change could send a credential to any host. The generated GitHub, GitLab and Azure pipelines now replace `.opentide/configurations` with the default branch's copy, in the same step, right before those commands. A platform the default branch has no tenant for yet skips its live query step with a note and exits `0`, so the pull request that adds the first tenant can pass. Regenerate existing pipelines with `opentide setup ci <github|gitlab|azure> --yes` ([#565](https://github.com/opentidehq/opentide/pull/565)).

### Added

- `opentide --version` / `-V` prints `opentide <version>` and exits before the workspace is resolved, so CI jobs can log which opentide they installed ([#187](https://github.com/opentidehq/opentide/issues/187)).
- `opentide setup platforms --elastic` ([#414](https://github.com/opentidehq/opentide/issues/414)).
- `opentide lint` findings carry the object's `uuid`, a `severity` (`error` for an unparseable or unnamed object, `warning` for a filename slug mismatch, `info` for missing recommended metadata) and a zero-based `yaml_line` like `validate`'s, so they can be sorted, joined to their object and opened at the right line. The human line reads `[check/severity] path[:line]: message`. The JSON change is additive and `--strict` exit codes are unchanged ([#488](https://github.com/opentidehq/opentide/issues/488)).

### Changed

- **`pip install opentide` is the only install: every optional extra is removed.** The vendor SDKs (`azure-identity`, `azure-monitor-query`, `splunk-sdk`, `pandas`, `openpyxl`, `carbon-black-cloud-sdk`) are base dependencies, so live query validation, deploy and the importers work for every platform on a stock install. Generated CI pipelines install exactly `opentide==<version>`, so through 0.15.0 the pipeline's `validate query --live` for Sentinel failed with `Live query validation for sentinel needs a vendor SDK: No module named 'azure'` and staging and production never deployed. The `sentinel`, `splunk`, `carbon-black`, `crowdstrike`, `cli`, `mcp` and `dev` extras no longer exist: pip and uv warn about the unknown extra and install opentide with everything, so an existing `pip install 'opentide[sentinel]'` keeps working. Contributors use `uv sync --group dev` ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Sentinel deploys through the ARM `alertRules` REST API directly**, with an `azure-identity` token, instead of `azure-mgmt-securityinsight`. That SDK has published only pre-releases since 2.0, and uv refuses a transitive pre-release, so it could not become a base dependency without breaking `uv tool install opentide` and `uvx opentide`. The request body, the API version (`2025-10-01-preview`, the only one that accepts `NRT` rules) and the dry-run preview are unchanged: the bodies of the 0.15.0 deployer were captured and are asserted byte-for-byte. An ARM error now fails the rule with `SentinelApiError`, naming the HTTP status, the ARM error code and its message. `deploy --dry-run` always previews the compiled ARM body; the fallback to the configuration block when the SDK was missing is gone ([#576](https://github.com/opentidehq/opentide/issues/576)).
- When a vendor SDK will not import, `validate query --live` and `generate extract` report an incomplete install and advise `pip install --force-reinstall opentide`, instead of naming an extra ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Technique pins move to `att&ck::1.2` (ATT&CK 20.0).** Run `opentide generate schemas` so the editor offers the new IDs. Elastic threat arrays follow the ATT&CK v19 split of Defense Evasion: TA0005 is now Stealth and TA0112 Defense Impairment is new, and the legacy Defense Evasion stage of revoked keys maps to Stealth. Sentinel tactics are mapped onto the ARM `AttackTactic` enum: Stealth, Defense Impairment and the ICS Evasion tactic deploy as `DefenseEvasion`, and a stage with no Sentinel tactic is dropped with a `dropping_attack_stage_without_sentinel_tactic` warning. Tactics for every other technique are unchanged ([#568](https://github.com/opentidehq/opentide/issues/568)).
- **`generate` fails when a phase raises or logs an error.** Before, a phase that logged an error, for example after skipping an object file it could not parse, still exited `0`. The run now stops at that phase and exits `1`; the result names the phase in `phase` and at the start of `message`, keeps the exception type, and ends with the UUID of the object being rendered when one object caused it (`exports: KeyError: 'mitre_attack' while rendering <uuid>`, where 0.15.0 printed only `'mitre_attack'`). With `--json`, `generate docs` and `generate exports` and their subcommands print one result document instead of a traceback. A phase that logged errors and then raised reports both, and an error logged again when a phase reloads the registry counts once. A malformed object file fails the first phase that loads the registry, so the editor refresh `generate schemas templates vocabs snippets` now stops at `schemas`; run `opentide validate` to list every broken object at once. The documentation SDK (`opentide.documentation.run`, `write_all`) raises `ObjectGenerationError` around a per-object failure, with the original exception as its cause ([#579](https://github.com/opentidehq/opentide/issues/579)).
- **`opentide validate` warns `platform_not_enabled`** when a rule has a block for a platform the workspace has not enabled, for example an imported Splunk rule in a Sentinel-only repository. One warning per block, at `configurations.<platform>`, naming the `opentide setup platforms` flag. It does not fail `--strict`, the commit hook or CI; malformed blocks and unknown platform keys still fail. Such blocks still do not deploy ([#413](https://github.com/opentidehq/opentide/issues/413), [#410](https://github.com/opentidehq/opentide/issues/410)).
- **A missing or unknown `metadata.schema` is no longer checked against the newest revision of its object type** (versioning 1.1). Without `metadata.schema`, `opentide validate` fails the `schema` check with a new `schema_missing` issue at that field. An unregistered identifier, or one that names another object type (a rule declaring `threat::1.0`), fails with `schema_validation`. Both are reported at `metadata.schema` with its line, and a `metadata` that is not a mapping is a shape error at `metadata`. `load_rule_from_dict` and `Opentide.Rules` raise `SchemaMissingError` or the new `SchemaIdentifierError` (a `LookupError`) instead of defaulting to `rule::1.0`, so a rule declaring another family's schema now stops registry load instead of loading as `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).
- Signal `effort` is no longer pinned to the `efforts` vocabulary: it is an integer score from 1 to 10 (specifications#42). The unused `threat::2.1` pin table is removed, and an `objective::1.1` table is bundled, unused until opentide ships that revision ([#111](https://github.com/opentidehq/opentide/issues/111)).
- The MalAPI vocabulary scraper is no longer part of the package: `opentide.extraction.malapi` scraped malapi.io on import and needed an undeclared BeautifulSoup dependency. It is now the maintainer script `scripts/vocabulary/generate_malapi.py` ([#539](https://github.com/opentidehq/opentide/issues/539)).
- Docs: a rule's `detection_model` names the objective it implements, or one signal defined under that objective. Both are referenceable by design (specifications#48).

### Fixed

- **ATT&CK techniques added since v17 validate again.** 0.13.0 ([#504](https://github.com/opentidehq/opentide/pull/504)) re-synced the bundled `att&ck` vocabulary from a specifications copy that was still ATT&CK v17, while every schema pinned `att&ck::1.1`, so T1685–T1690, T1059.013 and the other v18 and v19 techniques failed validation. ATT&CK 19.2 is restored as `att&ck::1.1` (the 60 keys 0.9.0–0.12.1 shipped) and ATT&CK 20.0 is added as `att&ck::1.2` (19 keys, including T1696–T1701). The 27 IDs MITRE has since revoked (T1562.*, T1070.001/.002, T1656, …) still validate under `att&ck::1.x`. `att&ck.groups`, `mitigations` and `datasources` are refreshed from the same releases, and the generator names enterprise sub-techniques `Parent: Sub` again ([#568](https://github.com/opentidehq/opentide/issues/568)).
- `Opentide.validate_rule()` and `validate_raw_payload()` check a rule against the revision its `metadata.schema` names, so a valid `rule::1.1` rule with `metadata.reviewed` no longer fails as `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).
- `opentide share push` matches a block's `rule_statuses` against the status of the rule's enabled platform blocks, which deploy uses and promotion rewrites, instead of the root `status`, which promotion leaves at `STAGING`. The root `status` is used only when no enabled block has one. In generated pipelines the share job still runs before the production deploy promotes, so a rule promoted by that deploy is shared the next time a push selects it ([#583](https://github.com/opentidehq/opentide/issues/583), follow-up [#590](https://github.com/opentidehq/opentide/issues/590)).
- `opentide generate extract sentinel` imports near-real-time rules. ARM lists them as kind `NRT`, and the importer compared the kind with `nrt`, so every NRT rule was skipped as an unsupported kind ([#577](https://github.com/opentidehq/opentide/issues/577)).
- **Elastic deploy and live validation work again.** The planner dumps each rule with `exclude_none=False` and reloads it, and the Elastic block's checks tested key *presence*, so the dumped `null` keys raised `filter_shape`, `type_block` and `index_list` and every Elastic deploy and `validate query --live` failed before reaching Kibana. Optional fields set to `null` are now treated as absent. A raw filter that also carries a top-level `negate` is still rejected as mixing the two filter shapes ([#557](https://github.com/opentidehq/opentide/issues/557), [#561](https://github.com/opentidehq/opentide/pull/561)).
- Elastic `kill-process` and `suspend-process` response actions without a `field` compile to Kibana's default `config` (`{field: process.entity_id, overwrite: true}`). Kibana requires `config` for both, so such a rule — including any rule `extract elastic` wrote for a default-field action — failed deploy and preview with HTTP 400 ([#558](https://github.com/opentidehq/opentide/issues/558), [#562](https://github.com/opentidehq/opentide/pull/562)).
- `opentide generate extract elastic` no longer writes `negate: null` on `threat_match` mapping entries when Kibana omits `negate`; an explicit `false` is kept ([#559](https://github.com/opentidehq/opentide/issues/559), [#563](https://github.com/opentidehq/opentide/pull/563)).
- Sentinel and Elastic accept compound shorthand durations (`1h10m`, `1d2h`, `2m30s`; units in `d`, `h`, `m`, `s` order, each at most once, lower case) as used by the official Azure-Sentinel rules, alongside single-unit shorthand and ISO 8601. Sentinel shorthand also accepts seconds. An upper-case shorthand unit (`1M`) is rejected, as in 0.15.0 ([#560](https://github.com/opentidehq/opentide/issues/560), [#564](https://github.com/opentidehq/opentide/pull/564)).
- `ElasticClient.find_managed` pages through every managed rule instead of stopping at the first 1,000, and raises `requests.HTTPError` when a page fails rather than returning the rules collected so far ([#566](https://github.com/opentidehq/opentide/issues/566), [#569](https://github.com/opentidehq/opentide/pull/569)).
- Splunk correlation searches carry the rule's own `techniques` together with the techniques inherited from its objective, de-duplicated in order, and compiling a rule that is not in the catalogue index (SDK, MCP `deploy_rule`) no longer crashes or logs a CRITICAL lookup failure ([#567](https://github.com/opentidehq/opentide/issues/567), [#570](https://github.com/opentidehq/opentide/pull/570)).
- Follow-ups to those fixes: an Elastic raw filter that also carries a top-level `negate` is rejected again as mixing filter shapes, as RFC 0007 requires; a Splunk compile of a rule outside the catalogue no longer logs a CRITICAL lookup failure; Sentinel shorthand durations are case-sensitive again, as in 0.15.0, and accept seconds (`2m30s`); out-of-order and repeated units are rejected on Sentinel and Elastic.
- `validate query --live` and the MCP `validate_query` tool report a tenant they cannot reach (a refused connection, DNS, TLS, timeout or proxy failure) as a failed check with exit `1`, naming the `tenant` and `host`. Splunk, SentinelOne, Elastic, Carbon Black Cloud and Defender for Endpoint used to crash with a `URLError` or `requests` traceback and print nothing on stdout. The new `TenantUnreachableError` is an `Errors.TenantConnectionError`.
- The default `opentide validate` no longer crashes with `AttributeError` on an object whose `metadata` is not a mapping.
- `opentide generate exports navigator` writes the ATT&CK Navigator layer in a fixed order: techniques by ID, and each comment lists threats, then rules, by name. Renaming or moving object files no longer reshuffles the whole file. Expect a one-time reorder diff the first time you regenerate the layer ([#521](https://github.com/opentidehq/opentide/issues/521)).
- `opentide migrate objects --apply` on macOS and Windows (case-insensitive filesystems) renames the legacy `Objects/` folder to `objects/` after the moves. Before, the migrated folders stayed inside `Objects/` and a Linux checkout found no objects. `--json` lists the rename under `case_renamed`, and the command explains how to make git record the new folder case. Re-running it repairs a repository an earlier release left in `Objects/` ([#522](https://github.com/opentidehq/opentide/issues/522)).
- The `AGENTS.md` and `CLAUDE.md` that `opentide setup skills` writes name `opentide mcp start`, not the `opentide-mcp` command removed in 0.12.0 ([#460](https://github.com/opentidehq/opentide/issues/460)).
- Importing a platform client, deployer or validator no longer builds the whole registry index: `DebugEnvironment` reads its debug deployment settings on access instead of at import ([#539](https://github.com/opentidehq/opentide/issues/539)).
- The advice printed when deploy or live `validate query` skips a disabled platform names a flag that exists (`--defender-for-endpoint`, `--sentinel-one`, `--carbon-black-cloud`), and so does the Defender import advice ([#414](https://github.com/opentidehq/opentide/issues/414)).
- opentide's own CI checks the bundled vocabulary pins against the specifications. The drift gate never ran before, because it filtered changed paths with `rg`, which GitHub-hosted runners do not ship ([#111](https://github.com/opentidehq/opentide/issues/111)).
- `data/specifications.lock.json` no longer lists `responders.vocab.toml`, which was removed in #512.
- The PyPI publish workflow warns, naming the cause, when the website was not notified of a release ([#540](https://github.com/opentidehq/opentide/issues/540)).

### Install

```bash
pip install opentide==0.16.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup ci <github|gitlab|azure> --yes
opentide generate schemas
opentide validate --strict
```

## [0.15.0] — 2026-10-16

Minor release: two things need action after upgrading.
- **Vendor rule ids move out of rule YAML into committed deployment state shards** (RFC 0010, [specs/deployment-state.md](https://github.com/opentidehq/specifications/blob/main/specs/deployment-state.md)). Run `opentide deploy migrate-state` and commit its output before the next deploy.
- **Generated pipelines must be regenerated** with `opentide setup ci <provider> --yes`. They now retire rules, deploy from the default branch's newest deployment state, queue production deploys on GitLab and Azure, and persist deploy write-backs.

Elastic Security is also now a supported platform, with an `opentide extract elastic` importer. Nothing to do unless you use it.

### Breaking

- `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` are removed from the Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab and Carbon Black blocks. Vendor ids for Defender, SentinelOne and CrowdStrike now live in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), one committed shard per rule.
  - `opentide validate` fails a rule that still carries any of those keys with `external_id_in_rule`.
  - `opentide deploy` refuses it for **every** platform before any HTTP call.
  - There is no fallback read of the YAML. A deploy with neither the key nor a shard would create a second remote rule, so migrate first.
  - Upgrade: in `.gitignore`, replace `.opentide/states/` with `.opentide/states/sharing.jsonl`. Then run `opentide deploy migrate-state` and `opentide validate --strict`, and commit the stripped rules together with `.opentide/states/deployment/` ([#396](https://github.com/opentidehq/opentide/issues/396)).
- Deploy no longer writes ids into rule files. A create records the returned id in the shard, and logs it as `external_id_recorded` at warning level so the CI log keeps it. `DELETION` or `DISABLEMENT` without an entry is the warning `external_id_missing`: nothing is called and the run does not fail, since nothing is known to exist on that tenant. A create is refused with `deployment_state_ignored` while git ignores the shard directory. `opentide.deployment.ExternalIdHelper` is removed ([#396](https://github.com/opentidehq/opentide/issues/396)).
- In CI, a deploy whose plan is not `PRODUCTION` (the pull-request staging job, or a `FULL`, `ALWAYS` or `MANUAL` run) refuses to create a Defender for Endpoint, SentinelOne or CrowdStrike rule with `deployment_state_unpersisted`, before any vendor call, because only the production job commits the shards. Updates and deletes of bound rules still run, and local runs may still create. A pipeline that commits `.opentide/states/deployment/` itself can pass `opentide deploy --persist-state-externally`. Before, every staging rerun created another untracked remote rule ([#554](https://github.com/opentidehq/opentide/issues/554)).
- Shards are read in canonical form only: a file name that is not the lowercase canonical uuid, an `object_uuid` that is not exactly the file name, or a second file naming the same rule is `deployment_state_uuid_mismatch`, and a tenant key with surrounding spaces is `deployment_state_shape`. The rule is refused rather than read as having no id ([#396](https://github.com/opentidehq/opentide/issues/396)).

### Added

- **Elastic Security platform** (`elastic`, `platform::elastic::1.0`, [RFC 0007](https://github.com/opentidehq/specifications/blob/main/rfcs/0007-elastic-security-platform.md); [#386](https://github.com/opentidehq/opentide/issues/386)–[#390](https://github.com/opentidehq/opentide/issues/390)). A rule compiles to a Kibana detection engine body whose `rule_id` is its `metadata.uuid`, so Elastic keeps no deployment state shard. Deploy creates, updates, disables and deletes rules; a type change is a delete then a create; remote fields the rule does not set (`actions`, `exceptions_list` and others) are kept; prebuilt rules are never modified. `validate query --platform elastic --live` previews each rule through Kibana `rules/preview` and runs the Elasticsearch pre-flight (ES|QL `LIMIT 0`, then `_field_caps` on aggregation, timestamp and indicator-match fields); the same pre-flight runs before every deploy. A 401 or 403 fails the tenant, any other error fails only that rule. There is no offline syntax check. Tenants live in `.opentide/configurations/platforms/elastic.toml`, with the API key as an `$ENV` reference.
- `opentide generate extract elastic` imports the detection rules of one Kibana space (`--space`) as `platform::elastic::1.0` rules. Disabled rules import as `DISABLED`, prebuilt rules are converted to custom rules with derived UUIDs only with `--include-prebuilt`, and a rule that would not load is skipped and reported rather than written.
- `opentide deploy migrate-state` moves existing Defender, SentinelOne and CrowdStrike ids into shards. It writes the shard before stripping the lines, preserves comments and layout, reports `external_id_conflict` and `external_id_shape`, refuses a gitignored destination, and is idempotent. Keys on every other platform (Sentinel, Splunk, HarfangLab, Carbon Black Cloud) are removed without being stored and reported as `external_id_unused` with platform, tenant, value and file. It exits `0` on success, on a clean second run and on `external_id_unused` warnings only, and `1` when any rule fails or the destination is ignored ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide deploy --persist-state-externally` ([#554](https://github.com/opentidehq/opentide/issues/554)).
- Full-workspace `opentide validate` checks every shard under `.opentide/states/deployment/`, including orphans whose rule was deleted ([#396](https://github.com/opentidehq/opentide/issues/396)).
- MCP `deployment_status` returns `external_ids` from the shard ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide validate --file` is repeatable ([#548](https://github.com/opentidehq/opentide/issues/548)).
- `validate query --live` JSON reports `plan`, `queries_validated` and `queries_per_tenant` ([#547](https://github.com/opentidehq/opentide/issues/547)).

### Changed

- `opentide setup repo` ignores `.opentide/states/sharing.jsonl` instead of the whole `.opentide/states/` directory ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide validate --file` fails with `scope_no_match` when any one `--file` target matches no object, and names that target in `context.targets`. Before, a run with several targets passed as long as one of them matched, so a mistyped or quoted path was never validated. A script that passes a `--file` for a file that may not exist now exits `1`.
- `opentide deploy --plan PRODUCTION` now includes `DISABLED` and `REMOVED` rules, so they are disabled or deleted as [specs/deployment.md](https://github.com/opentidehq/specifications/blob/main/specs/deployment.md) defines. Before, the `--keep-deprecated` default dropped them before the `PRODUCTION` allow-list was consulted, and a retirement never reached the platform. `--drop-deprecated` restores the old behaviour ([#548](https://github.com/opentidehq/opentide/issues/548)).
- The generated production job (GitHub, GitLab, Azure) commits promoted rule statuses and `.opentide/states/deployment/` back to the default branch with `[skip ci]` ([#548](https://github.com/opentidehq/opentide/issues/548)):
  - Before the dry-run it replaces the checkout's `.opentide/states/deployment/` with the default branch tip's, so a merge made before an earlier run's write-back landed updates the rule that run created instead of creating it again.
  - Production jobs are queued on GitLab (`resource_group: opentide-production`) and Azure (`lockBehavior: sequential`, which takes effect once an Exclusive lock check is added to a resource the stage uses). GitHub deliberately has no `concurrency` group: it cancels pending runs, and a cancelled diff-scoped deploy would silently never deploy its rules. Overlapping GitHub runs that create the same rule fail loudly with `deployment_state_conflict`.
  - The write-back runs whenever the deploy started: after a deploy that failed part way, was cancelled or timed out (GitHub `always()`, Azure `always()`, GitLab `after_script` on cancel; GitLab skips `after_script` on a timeout), so ids from the creates that succeeded are never lost.
  - Rule files are committed only when `opentide validate --strict` passes on exactly those files, read NUL-delimited so no file name is C-quoted.
  - If a concurrent merge conflicts with the rule files, this run's shard changes are replayed per tenant onto the new tip and pushed alone, and the job fails. Bindings other runs recorded and shards either run deleted are preserved.
  - Any failure that leaves the state commit off the default branch (push rejected every time, a failed fetch or replay) prints the state diff and pushes the commit to `refs/opentide/deployment-state/<commit>`.
- `opentide setup vscode` maps `objects/**/*.yaml` to `.opentide/schemas/opentide.schema.json`, so `rule::1.0` and `rule::1.1` rules validate side by side. A merge removes the per-folder revision mappings earlier releases wrote ([#550](https://github.com/opentidehq/opentide/issues/550)).
- `opentide validate` rejects a quoted or boolean signal `effort` (for example `"3"`), as the editor schema does ([#552](https://github.com/opentidehq/opentide/issues/552)).
- The `sentinel` extra requires `azure-mgmt-securityinsight>=2.0.0b2`; the lock uses 2.0.0b4 ([#545](https://github.com/opentidehq/opentide/issues/545)).
- The router no longer lists `visibility::1.0`, which is configuration rather than an object ([#550](https://github.com/opentidehq/opentide/issues/550)).

### Fixed

- **Sentinel deploy:**
  - Rules with `alert.dynamic_properties` deploy. The `sentinel` extra resolved `azure-mgmt-securityinsight` 1.0.0, which has no `AlertPropertyMapping`, so every such rule failed with `AttributeError`. Both the `SecurityInsights` and `SecurityInsightsMgmtClient` client names now work ([#545](https://github.com/opentidehq/opentide/issues/545)).
  - Rules accept ISO 8601 durations (`PT1H`, `P1D`) as the platform spec documents; before, only the `1h` shorthand parsed ([#545](https://github.com/opentidehq/opentide/issues/545)).
  - A rule without `entities` no longer sends an empty `entityMappings`, which ARM rejected with 400 ([#549](https://github.com/opentidehq/opentide/issues/549)).
  - A missing `grouping` or `grouping.alert` fails with an error naming the rule and `configurations.sentinel.grouping.alert`, in deploy and in `--dry-run`, instead of an `AttributeError` ([#549](https://github.com/opentidehq/opentide/issues/549)).
- `deploy --dry-run` no longer hides Sentinel compile errors. It previously fell back to the configuration block and reported `completed`. It now shows the ARM request a deploy would send, and a rule that would fail is listed as `failed` with its `error`; the run exits `1` ([#545](https://github.com/opentidehq/opentide/issues/545)).
- The `PRODUCTION` plan on GitHub Actions and Azure Pipelines diffs against HEAD's first parent. Before, on a merge commit the diff was taken against the merged branch's head, so the rules the merge changed were not deployed, and pull-request jobs on the merge ref reported `skipped` ([#546](https://github.com/opentidehq/opentide/issues/546)).
- `validate query --live` with no `--plan` checks every tenant a rule can reach, `STAGING` and `PRODUCTION` alike. `MANUAL` tenants are checked only when listed, and `deploy` targets are unchanged. If the rules reach no configured tenant at all, the run reports `skipped` with exit `2` instead of `passed`. An explicit `--plan` that only narrows every rule out (a staging-only rule under `--plan PRODUCTION`) is an ordinary `skipped` with exit `0` ([#547](https://github.com/opentidehq/opentide/issues/547)).
- `opentide.schema.json` applies exactly one revision schema per object, selected by `metadata.schema`. It offers the registered identifiers as completions and resolves its references to the files next to it. Before, its `oneOf` could never be satisfied ("Matches multiple schemas"), and its `$id` sent references to a remote URL ([#550](https://github.com/opentidehq/opentide/issues/550)).
- `rule.1.1.schema.json` includes `metadata.reviewed` and accepts the same date and datetime forms as `opentide validate` ([#551](https://github.com/opentidehq/opentide/issues/551)).
- Signal `effort` is typed as an integer in `objective.1.0.schema.json`; the efforts names had made every authored value invalid in the editor ([#552](https://github.com/opentidehq/opentide/issues/552)).
- CrowdStrike rules deploy as `active`, and disabled rules as `inactive`; the status was inverted. Compiling any CrowdStrike rule had also raised `AttributeError` ([#553](https://github.com/opentidehq/opentide/issues/553)).
- A rule refused with `external_id_in_rule` fails the deploy on every path: with `--platform`, with `--skip-unconfigured`, and when the Sentinel or Splunk deployer is called directly (SDK, MCP `deploy_rule`). MCP `deploy_rule` returns `status: failed` with an `error` when the deployer refused or failed the rule; it used to report a plain `deploy`. Error and warning flags no longer leak from one deploy to the next in a long-lived process.
- The commented `[[tenants]]` example in every bundled platform template loads when uncommented. The retired `proxy` key is gone, and the HarfangLab `type` and SentinelOne `url`/`account_id` placeholders are valid TOML.

### Install

```bash
pip install opentide==0.15.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide deploy migrate-state
opentide validate --strict
```

## [0.14.2] — 2026-10-14

Patch on 0.14.1. Nothing to do after upgrading, but upgrade promptly if you run `opentide setup skills`: it could be made to install skill content from a repository other than the pinned catalogue. A patch rather than a minor because no input contract, generated artefact, exit code or command surface changes — the installer refuses inputs that no legitimate catalogue produces, and a normal install behaves exactly as before.

### Fixed

- `opentide setup skills` can no longer be steered outside the pinned `opentidehq/skills` catalogue. The installer interpolated the catalogue manifest's `ref`, the skill `slug`, and each tree path straight into `raw.githubusercontent.com` and `api.github.com` URLs without rejecting `..`. GitHub normalises dot segments server-side, so a manifest ref of `../../../attacker/payload/main` resolved to a **different public repository** and its `SKILL.md` files were installed into `.agents/skills/` on a developer or agent machine — unreviewed instructions, delivered by the tool whose whole promise is that the catalogue is pinned. The same gap existed on the write side: a tree entry such as `skills/<slug>/../../.git/hooks/pre-commit` escaped the staging directory, which turns a catalogue listing into arbitrary file write, a git hook being the obvious target. Containment is now checked at four points — the ref, the slug, each repository path, and the fully-assembled URL after dot-segment removal (host, scheme, prefix, query, and absence of credentials or a fragment all re-verified) — and the destination of every written file is confirmed to resolve inside the skill tree. A rejected manifest ref falls back to `main` rather than being used, and a rejected slug or path aborts the install instead of writing a partial tree ([#483](https://github.com/opentidehq/opentide/pull/483)).

### Changed

- Runtime dependencies moved up: `pydantic` 2.13.5 → 2.14.0, `orjson` 3.12.0 → 3.13.0, `dulwich` 1.2.15 → 1.2.17, `typer` 0.27.2 → 0.27.3. No API, schema or output change — the full matrix (Python 3.10–3.14), the CLI E2E shards and the Windows smoke job are green on each ([#502](https://github.com/opentidehq/opentide/pull/502), [#500](https://github.com/opentidehq/opentide/pull/500), [#501](https://github.com/opentidehq/opentide/pull/501), [#498](https://github.com/opentidehq/opentide/pull/498)).

### Install

```bash
pip install opentide==0.14.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.14.1] — 2026-10-14

Patch on 0.14.0. Nothing to do after upgrading. Documentation and export generation are dramatically faster again — a 265-object corpus that took **722s** on 0.14.0 now completes in **under a second**, and the generated output is byte-identical, so no regeneration is required. Field extraction for ATT&CK techniques, threat actors and platform configurations is now derived from the Pydantic models rather than a hardcoded key list. A patch rather than a minor because no input contract, generated artefact, exit code or command surface changes; the one behaviour change is an undeclared legacy key that no model ever described, noted under Changed.

### Fixed

- The vocabulary index is no longer rebuilt on every access. `Opentide.Vocabularies.Index` was a `@property` calling `VocabularyLoader.load_index()` on each read, and `generation.framework.VOCAB_INDEX` is a `_LazyMapping` whose `_data()` re-read that property for every `[]`, `in`, `.get`, iteration and `len` — so a single `get_vocab_entry()` call rebuilt all 35 vocabularies, `actors` and its ~1,249 entries included. A full-corpus run made **169 million** `_build_entry` calls and re-validated the same vocabulary models **172 million** times. `generate docs` goes from **722s to 1.44s** on a 265-object corpus and `generate exports` from 152s to 0.61s; generated documentation is byte-identical to the same corpus generated under 0.14.0, verified file by file. `_LazyMapping`'s own docstring already promised the cost was "paid once per process" — nothing tested it, so the claim and the code had diverged indefinitely ([#510](https://github.com/opentidehq/opentide/issues/510)).
- The threat chaining graph is no longer recomputed on every access. `Opentide.Models.chaining` rebuilt the whole graph per read and `generation.framework.CHAINING_INDEX` re-read it per lookup — the same defect shape as the vocabulary index, measured at **4,273** `compute_chains` calls on a 265-object corpus. It is now memoised against the registry snapshot's identity, mirroring `FlatIndex` two properties above it in the same class, whose metaclass already clears that cache whenever the registry reloads. Worth **3.82s → 0.91s** on top of the vocabulary fix, output byte-identical ([#510](https://github.com/opentidehq/opentide/issues/510)).

### Changed

- ATT&CK techniques, threat actors and platform configurations are extracted by deriving the field locations **from the Pydantic models** instead of scanning hardcoded key tuples. The previous `_TECHNIQUE_KEYS = ("techniques", "mitre_attack", "attack")` was wrong on two counts: `attack` was declared by **no model at all**, and the tuple conflated field names with model types — every key was tried in every section, so a rule was scanned for `mitre_attack` and a threat for `techniques`, fields those models do not have. Each role-bearing field now carries a `FieldRole` marker on the model that declares it, and the search paths are built per model by walking `model_fields`, selected by the body's `metadata.schema`. A renamed or added role-bearing field is picked up by tagging the model, with no edit to the extractor, and every registered revision of a model is covered. **Behaviour change:** the undocumented tolerance for a nested `tags` mapping carrying techniques is gone. No model declares that shape — the only model-declared `tags` is a `list[str]` on platform configuration, which is not a technique holder — and no object in the reference catalogue uses it. If you hold pre-0.9 objects that carry techniques under a `tags:` mapping, catalogue search and `opentide info` will stop reporting those techniques until the values are moved to the field the object's model declares.

### Install

```bash
pip install opentide==0.14.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.14.0] — 2026-10-14

Minor on 0.13.0. Two things need action after upgrading. `objective.signals[].entities` values are now stage-scoped (`Hostname` → `Host::Hostname`), and `opentide migrate vocab-scope` re-prefixes them for you. `response.responders` becomes a configuration enum you declare in `deployment.toml`, so a value that no instance could make valid under 0.13.0 now validates. Documentation and export generation are dramatically faster — a corpus that previously exceeded a one-hour CI timeout now completes.

### Breaking

- `objective.signals[].entities` entries are stage-scoped: an authored value is `<stage>::<key>`. Seven of the 28 entity keys are defined under two stages (`Account`, `User`, `Authentication`, `Token`, `Permissions`, `Email` and `API Call`), so a bare key name could not say whether a signal keyed on a **host** account or a **cloud** account — different telemetry, a different data contract, often a different platform. The enum carried 28 values where the vocabulary defines 35, and now carries all 35. Stage identifiers are capitalised to `Host`, `Network` and `Cloud`, matching the convention `threat.surface` already uses. Vocabulary entry keys are unchanged — the prefix is applied at resolve time — so the `signal.entities::1.0` pin is unaffected. Migrate with `opentide migrate vocab-scope --apply`, then `opentide generate schemas templates vocabs snippets` ([#509](https://github.com/opentidehq/opentide/issues/509), [RFC 0005](https://github.com/opentidehq/specifications/blob/main/rfcs/0005-scoped-signal-entities.md)).
- `response.responders` is a **configuration enum**, not a vocabulary. The shipped `responders` vocabulary had `keys = []` while both rule revisions pinned the field to it, so every authored value failed validation and no instance could clear it — vocabularies are canonical and not locally extensible. One corpus reported 483 unclearable findings from two values. The alert handling team is per-organisation, so an instance now declares its teams in a `[[responders]]` block in `deployment.toml`; the generated schema offers them in the editor with their descriptions, and `validate` rejects anything else. Declaring **none** leaves the field unconstrained, so a fresh install carries no constraint it cannot satisfy. `[deployment] default_responders` supplies the team for a rule that names none — a key that shipped in the configuration template and in the spec but **was read by no code**, so the documented fallback never happened. The `responders` vocabulary file is removed ([#507](https://github.com/opentidehq/opentide/issues/507)).

### Changed

- `mcp` is a base dependency, so a bare `pip install opentide` ships a working MCP server. It previously lived in an optional `[mcp]` extra, so a plain install omitted it and `opentide mcp` told the user to install an extra before the command would run — a requirement for a first-class CLI command. The `[mcp]` extra is kept as an empty alias, so an existing `pip install opentide[mcp]`, or an editor configuration naming it, keeps resolving. The now-redundant pin is dropped from the `dev` extra and the `dev` dependency group, leaving `mcp` declared in exactly one place ([#526](https://github.com/opentidehq/opentide/issues/526)).

### Added

- `opentide migrate vocab-scope` re-prefixes authored values for every stage-scoped field. It applies only mechanical outcomes — a key defined under exactly one stage, and a stage whose casing drifted — and reports a key defined under several stages with its candidates rather than guessing, exiting 2 while anything is left for a human. Values are located by path through the document rather than by leaf key name, so a Sentinel platform block that also carries a key called `entities` is never touched, and each value is replaced over the exact span its scalar occupies, so comments, block scalars, quoting style and flow sequences survive.

- `opentide generate --help` names the four positional phases (`schemas`, `templates`, `vocabs`, `snippets`). Typer renders the sub-app's help string rather than the callback docstring, which already named them, so the only place the list appeared was an error string you had to trigger deliberately — while naming the cheap phases is the documented remedy for a stale editor schema after a contract change.
- `generate` reports what each phase costs, and names the slowest. A run that overran a CI job timeout previously emitted no phase boundary and no timing, so a killed job gave no way to tell whether it was 10% or 90% through. Timing is recorded even when a phase raises, which is the case that needed it ([#510](https://github.com/opentidehq/opentide/issues/510)).

### Fixed

- Documentation and export generation no longer rescan the whole catalogue for every object. `childs()` walked every model on every call while all of its callers are per-object — the table exporter per row, the documentation catalogue per signal, and `relations_downstream()` recursively at every level — so cost grew with the square of the corpus. It is now a reverse index built once per catalogue generation: **68× faster** on a 1497-object corpus. This is the root cause behind both a `generate docs` phase that exceeded a one-hour CI job timeout and a `generate exports` phase measured at 395s ([#510](https://github.com/opentidehq/opentide/issues/510)).
- `childs()` matched a model id against reference values with a substring test, so a short non-UUID id matched a longer one that merely contained it — `o-1` matched a signal referencing `o-186`, returning 113 spurious children. Relations are now compared by equality. UUID-shaped ids could not trigger this; any other id scheme could.
- `validate` and `generate` no longer disagree on the same vocabulary value. `get_vocab_entry()` stripped the stage prefix unconditionally before lookup while `is_valid()` checked the raw value first, so the two paths could resolve one value differently. Both now go through one helper that tries the raw value first. Three `Security::*` surface keys resolved to a different entry under the stripping path and three more missed entirely; those keys are reachable now ([#508](https://github.com/opentidehq/opentide/issues/508)).
- `check_status` resolved a deployment status by its configured *name* rather than by the strategy it maps to, so a renamed status silently took the wrong branch. It now resolves the strategy, and raises typed errors instead of a bare `Exception` ([#506](https://github.com/opentidehq/opentide/issues/506)).
- `opentide mcp start` and `opentide setup mcp` no longer advise an install that cannot help. Both told a user with an unimportable `mcp` to run `pip install 'opentide[mcp]'`, but that extra is now an empty alias, so following the advice installed nothing and left the user where they started. They now name the real remedy, `pip install 'mcp>=1.28.1,<2'`, and distinguish an incomplete environment from an incompatible `mcp` 2.x. The wheel gate that was meant to cover this could only ever skip once `mcp` became a base dependency; it now proves the stronger claim, that a **bare** wheel install answers a stdio `initialize` ([#526](https://github.com/opentidehq/opentide/issues/526)).
- The documentation no longer advertises a release it does not install. Four pages named 0.12.1 as the latest release beside their own `pip install 'opentide==0.14.0'` block — the defect [#406](https://github.com/opentidehq/opentide/issues/406) closed at 0.8.0, regressed silently through 0.13.0 because the release tests covered the release *commands* and nothing covered the version *claims*. Every claim, pin and PyPI link outside the historical release log is now checked against the newest `CHANGELOG.md` entry on every run.
- The test suite no longer operates on the repository under test. Git tests ran `git` with `cwd=` set to a temporary repository but inherited the environment, and `GIT_DIR` overrides `cwd` — so when `git push` exported `GIT_DIR` to its hooks and a hook ran the suite, the fixtures committed and checked out branches **in the real repository**, producing a commit that deleted 890 files. The environment is now sanitised for every test, with a collection-time guard so the hazard cannot return silently ([#513](https://github.com/opentidehq/opentide/issues/513)).

### Install

```bash
pip install opentide==0.14.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide migrate vocab-scope --apply
opentide generate schemas templates vocabs snippets
opentide validate --strict
```

## [0.13.0] — 2026-10-12

Minor on 0.12.1. `threat.surface` values are now stage-scoped (`Windows::Desktop` → `OS::Windows::Desktop`), platform configuration blocks require `status`, `opentide --json validate` emits one document shape and drops its legacy `errors` map, and the local `[vocabulary]` extension block is removed. Re-run `opentide setup ci` — generated pipelines deployed to the staging tenant and pushed to your default branch from any pull request. Regenerate with `opentide generate schemas templates vocabs snippets`.

### Changed

- `threat.surface` entries are stage-scoped: an authored value is `<stage>::<key>`. The vocabulary groups keys under 8 stages and defines the same key under two of them, so a bare key name was ambiguous and five values were unreachable (`VPN`, `VPN::OpenVPN`, `VPN::WireGuard`, `Wireless` and `Industrial` are each both `Infrastructure` and `Protocol`). The enum carried 895 values where the vocabulary defines 900, and now carries all 900. Vocabulary entry keys are unchanged — the prefix is applied at resolve time.
- `configurations.<platform>.status` is required. A rule omitting it previously passed `validate`, failed the published JSON Schema, and crashed the deployer; validation now reports `status: Field required` with the field path. Platform templates emit `status:` live rather than commented.
- `opentide --json validate` and `opentide --json validate --check <x>` return the same document. The report is always at `report` and `checks` maps each check that ran to its verdict; `--check` narrows `checks` and adds `check` rather than relocating the report to `issues`. The duplicate legacy `errors` map is removed — read `report.issues`.
- The `[vocabulary]` extension block in `schema.toml` no longer injects vocabulary entries and has been removed from the shipped template. Vocabularies are canonical in the specifications repository and are not locally extensible.

### Fixed

- Generated CI gated staging deployment and default-branch pushes on pull-request *events* rather than the pull request's *target branch*, so a pull request between two feature branches deployed detections to a live staging tenant and committed to the default branch. Six jobs across the GitLab, GitHub and Azure renderers now require the target to be the default branch. Re-run `opentide setup ci`.
- `threat.actors.name` is pinned to `actors::1.1`. 220 threat-actor galaxy clusters were present in the bundled vocabulary but invisible behind the `actors::1.0` pin, so a correctly-authored MISP cluster UUID was reported as an unknown vocabulary value. The actors enum goes from 1029 to 1249 values; `actors::1.0` keys are unaffected.
- `opentide setup skills --install opentide-detection-rule` no longer fails as an unknown slug. Three of the four wheel-bundled authoring skills were missing from the discovery catalogue while remaining in the default starter set, so the CLI installed a slug it refused to name.
- The weekly vocabulary refresh workflow had never completed a run: its opentide pull-request step was not gated on the App credential the specifications step already required, so it fell back to `GITHUB_TOKEN`, force-pushed the branch, then failed at `gh pr create`, leaving an updated branch with no pull request. It now fails fast before any mutation and names the missing secrets.
- `platform_loader` reported a missing `status` as a type error (`None is not a valid string`) instead of `Field required`.

### Install

```bash
pip install opentide==0.13.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide generate schemas templates vocabs snippets
opentide validate --strict
```

## [0.12.1] — 2026-10-09

Patch on 0.12.0. A missing credential is logged once, not once per object. Re-run `opentide setup ci` so a live query job guards only the `$VAR` names in that platform file and exits 2 when one of them is unset.

### Fixed

- `fetch_config_envvar` reports each unset configuration variable once per process. The live check still ends on the FATAL panel that names those variables.
- Generated CI no longer treats every `$VAR` in the bundled platform sample as required. The guard reads the enabled platform file, ignores comments and literals, and exits 2 on a skip. Exit 0 means the tenant check ran.

### Install

```bash
pip install opentide==0.12.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.12.0] — 2026-10-09

Minor on 0.11.0. The `opentide-mcp` console script is gone. The stdio server is `opentide mcp start`. Regenerate editor config with `opentide setup mcp`. Re-run `opentide setup ci` so a live query job runs only when every required credential variable is set. Regenerate schemas with `opentide generate` so object lists such as `threat.chaining` are not given a string vocabulary enum.

### Removed

- The `opentide-mcp` console script. The stdio server is `opentide mcp start`. There is no alias ([#460](https://github.com/opentidehq/opentide/issues/460)).

### Changed

- `opentide setup mcp` writes `command: opentide` and `args: ["mcp", "start"]`. `opentide mcp` with no subcommand prints help and exits. The editor owns stop and reload ([#460](https://github.com/opentidehq/opentide/issues/460)).

### Fixed

- Splunk `[[modifiers]]` loads as an array of tables. A config `ValueError` during engine load is no longer reported only as a missing `declare` ([#466](https://github.com/opentidehq/opentide/issues/466)).
- Generated schemas no longer put a string vocabulary enum on `threat.chaining` items or on the array node. `list[str]` vocabulary fields still get `items.enum` ([#468](https://github.com/opentidehq/opentide/issues/468)).
- Stage-prefix suggestions strip using the field name, including when the caller passes `surface::1.0`. MISP actor UUIDs still get no suggestion ([#467](https://github.com/opentidehq/opentide/issues/467)).
- A retired `[tenants.setup] proxy` key fails the live query check with a message naming `opentide --proxy`. That retirement covers platform tenant config, not only `[cve].proxy` ([#469](https://github.com/opentidehq/opentide/issues/469)).
- `--live` fails when a credential is still an unsubstituted `$VARIABLE`. Generated CI runs that job only when every required credential variable is set ([#471](https://github.com/opentidehq/opentide/issues/471)).
- Validate findings for vocabulary and cross-object checks record `yaml_line`, including list indexes such as `actors[0]`. Lint findings are unchanged ([#470](https://github.com/opentidehq/opentide/issues/470)).

### Install

```bash
pip install opentide==0.12.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.11.0] — 2026-10-07

Minor on 0.10.0. Bare `validate query` no longer scans. `--live` is the tenant check. Regenerate CI with `opentide setup ci` so generated pipelines pass `--live` and pin this release. Regenerate schemas with `opentide generate` so optional vocabulary lists include `items.enum`.

### Added

- `opentide generate` accepts `schemas`, `templates`, `vocabs`, and `snippets` together and runs them in that order. `docs`, `exports`, `extract`, and `inflight` stay subcommands ([#455](https://github.com/opentidehq/opentide/issues/455)).
- The bundled actors vocabulary matches the specifications snapshot refreshed from the live MISP galaxy ([specifications#34](https://github.com/opentidehq/specifications/issues/34)).

### Changed

- Bare `opentide validate query` refuses and names `--live`. It does not scan query text. `--live` checks the tenant. A missing SDK or plan fails that check. CrowdStrike and HarfangLab stay `supported: false` ([#456](https://github.com/opentidehq/opentide/issues/456)).
- Generated GitHub, GitLab, and Azure pipelines pass `--live` and skip a platform when every credential variable for that platform is empty ([#456](https://github.com/opentidehq/opentide/issues/456)).
- MCP `validate_query` refuses unless `live` is true. `live: true` checks the catalogue rules for the platform against the tenant ([#456](https://github.com/opentidehq/opentide/issues/456)).
- Generated schemas stamp `items.enum` on optional vocabulary lists and on each branch of a string-or-list union ([#450](https://github.com/opentidehq/opentide/issues/450)).

### Fixed

- Validation findings print `file:line` when `yaml_line` is set ([#451](https://github.com/opentidehq/opentide/issues/451)).
- `validate --check` returns only that check's issues. Parse findings belong to the schema check ([#452](https://github.com/opentidehq/opentide/issues/452)).
- Unknown `sharing.toml` keys name `[[misp]]` ([#453](https://github.com/opentidehq/opentide/issues/453)).
- Surface suggestions try the exact de-prefixed key before difflib ([#454](https://github.com/opentidehq/opentide/issues/454)).

### Install

```bash
pip install opentide==0.11.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.10.0] — 2026-10-06

Minor on 0.9.0. Upgrade, rename technique lists to `mitre_attack`, and regenerate schemas with `opentide generate`. Regenerate CI with `opentide setup ci` so the install pin is exact. A root `composition` block is still accepted and is no longer required.

### Added

- `opentide --proxy http://[user:pass@]host:port` sets `HTTP_PROXY` and `HTTPS_PROXY` for that process. A passed flag wins over the existing environment. Omitting the flag leaves the environment as it is.
- `python -m opentide` and `python -m opentide.mcp_server` start the CLI and the MCP server.
- `opentide info` prints how many object files failed to load. `--strict` exits non-zero when that count is not zero.
- `opentide migrate objects` moves `Models Library/Threat Vector Models`, `Models Library/Detection Objectives`, and `Models Library/Managed Detection Rules`, and object folders named in `Configurations/global.toml`.

### Changed

- Threat and objective technique lists are `mitre_attack`, pinned to `att&ck::1.1`. `att&ck` and `attack` are not accepted. Actor values stay scoped (`att&ck::G0007`).
- `objective.composition` is required. A root `composition` block is accepted and ignored. Templates emit the block once, under `objective`.
- `signals[].data.logsources` come from workspace `visibility.toml`. The `datasources` pin on that field is gone.
- Signal `severity` uses `alert_severity::1.0` (`Informational` through `Critical`). Threat `severity` stays the incident vocabulary.
- `detection_model` accepts an objective UUID or a signal UUID.
- `VisibilityAsset.custom_details` accepts strings, booleans, and numbers.
- Sentinel generated schema no longer requires `grouping` or `entities`.
- `surface` and `signal.entities` descriptions say stages group keys. Authored values are not prefixed with the stage id.
- `opentide setup ci` installs `opentide==<installed version>`.

### Fixed

- Vocabulary extensions are looked up by field name, so a `schema.toml` extension applies during validation.
- `opentide lint` reports an unreadable file instead of crashing.
- `opentide setup vscode` accepts JSONC comments and trailing commas, and names the file when the JSON is still invalid.
- Duplicate YAML keys are rejected with the key and line.
- An unreadable object file is logged separately from malformed YAML.
- Legacy `tvm`, `dom`, `mdr`, and `cdm` object types in `Configurations/global.toml` raise an error that names the rename and tells you to delete that file.
- Unknown vocabulary values that are a UUID or `misp::<uuid>` do not get a "did you mean" suggestion.
- A leftover `[proxy]`, `[cve].proxy`, or tenant `setup.proxy` key is an error that names `--proxy`.

### Install

```bash
pip install opentide==0.10.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.9.0] — 2026-10-05

Minor on 0.8.2. Upgrade and regenerate schemas with `opentide generate` so `rule::1.1` can record `metadata.reviewed` and technique and logsource checks use `att&ck::1.1` and `datasources::1.1`. `opentide rules unreviewed` lists rules with no review, or a review older than the window. It does not require regenerating CI.

### Added

- `rule::1.1` accepts optional `metadata.reviewed` (ISO 8601 date or datetime). `rule::1.0`, threats, and objectives still reject the field. Validate, deploy, share, and template generation do not write it. `opentide rules unreviewed --older-than 90d` (also `12h`, `30m`, or a bare positive day count) lists `rule::1.0` as `schema`, a `rule::1.1` with no review as `absent`, and a review strictly earlier than now minus the window as `stale`. A review equal to the window boundary is fresh. Exit code is 0 when the window parses, including when rules are listed ([#437](https://github.com/opentidehq/opentide/issues/437), [#438](https://github.com/opentidehq/opentide/pull/438), [specifications#29](https://github.com/opentidehq/specifications/pull/29)).

### Changed

- Technique pins are `att&ck::1.1` on threats, objectives, `rule::1.0`, and `rule::1.1`. Objective logsources pin `datasources::1.1`. Bundled ATT&CK, groups, datasources, and mitigations match upstream 19.2 ([#392](https://github.com/opentidehq/opentide/issues/392), [#445](https://github.com/opentidehq/opentide/pull/445)).
- Production dependencies: `orjson` 3.12.0 ([#443](https://github.com/opentidehq/opentide/pull/443)) and `azure-identity` 1.26.0 ([#444](https://github.com/opentidehq/opentide/pull/444)). The `mcp` extra stays below 2 and is 1.30.0 ([#442](https://github.com/opentidehq/opentide/pull/442)). Transitive `oauthlib` 4.0.0, `urllib3` 2.8.0, and `virtualenv` 21.14.5 ([#435](https://github.com/opentidehq/opentide/pull/435)).

### Fixed

- CrowdStrike auth no longer logs the token response. Defender no longer logs the bearer token or a client-secret prefix. `--json` and the MCP server emit those logs to stderr, so a CI reader could reuse the credential ([#441](https://github.com/opentidehq/opentide/pull/441)).
- `share push` publishes a retracted object again. A matching content hash skips the push only when the ledger line is `synced`. Preview no longer reports an update that push then skips ([#385](https://github.com/opentidehq/opentide/pull/385)).
- Deploy commit loading records the immediate parent. Walking every ancestor raised `RecursionError` on a history deeper than the Python recursion limit and aborted the diff ([#369](https://github.com/opentidehq/opentide/pull/369)).

### Install

```bash
pip install opentide==0.9.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.2] — 2026-10-02

Patch on 0.8.1. Upgrade for a memoised object index and vocabulary files that keep dotted keys quoted. It does not change accepted input, CLI output, or exit codes, and it does not require regenerating CI.

### Changed

- `Opentide.Models.FlatIndex` is memoised for the current registry snapshot. Clearing `IndexManager._cache` drops that memo with the snapshot, so a rebuilt index cannot return the previous object map ([#436](https://github.com/opentidehq/opentide/pull/436)).
- `run_extract` and `run_extract_import` forward keyword arguments to the extraction runner. The CLI passes none, so an existing `run()` still works. Unexpected keywords raise `TypeError` with the module name ([#436](https://github.com/opentidehq/opentide/pull/436)).

### Fixed

- Vocabulary writers quote dotted list keys (`"tide.vocab.stages"`) instead of emitting a bare dotted key that TOML reads as nested tables. An entry that already stores stages under the nested table is still read ([#436](https://github.com/opentidehq/opentide/pull/436)).

### Install

```bash
pip install opentide==0.8.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.1] — 2026-10-01

Patch on 0.8.0. Upgrade and regenerate GitLab CI with `opentide setup ci gitlab` so query validation gates generate and deploy, and the inflight shell matches ShellCheck. This restores the documented gate that GitHub and Azure already enforced. It does not change accepted input, CLI output, or exit codes.

### Fixed

- Generated GitLab pipelines start `generate` only after object validation and every `validate query` job. A failed query check no longer starts deploy. Regenerate with `opentide setup ci gitlab` ([#429](https://github.com/opentidehq/opentide/issues/429)).
- Inflight shell quotes `$CI_DEFAULT_BRANCH` and exits if `cd` into the worktree fails. A document job with no commands is omitted, instead of an empty `script` GitLab rejects. `gitlab-ci-verify` (ShellCheck) and glint both accept the file ([#430](https://github.com/opentidehq/opentide/issues/430)).

### Install

```bash
pip install opentide==0.8.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.0] — 2026-09-30

Minor on 0.7.0. Upgrade and regenerate CI with `opentide setup ci` so validation and lint are strict, deploy skips a plan whose platforms have no tenants, and an Azure pipeline has a pool. An object file with no `uuid` now fails validation. `get_chaining` returns the threat, objective, and rule lineage.

### Added

- `opentide deploy --skip-unconfigured` exits 0 when every platform in the plan has no `[[tenants]]` block. A plan that mixes configured and unconfigured platforms still fails with `Cannot deploy:` ([#408](https://github.com/opentidehq/opentide/issues/408)).
- Generated GitHub deploy jobs map each credential named in the bundled platform files from `secrets`. GitLab and Azure read the same names from the project variable store. There is no `OPENTIDE_SECRETS` variable ([#408](https://github.com/opentidehq/opentide/issues/408)).

### Changed

- Generated catalogue gates are `opentide validate --strict` and `opentide lint --strict` ([#409](https://github.com/opentidehq/opentide/issues/409)).
- Azure pipelines set `pool.vmImage` to `ubuntu-latest` and trigger on every branch, so a topic-branch push still validates. `pr:` stays for Azure Pipelines hosted on GitHub or Bitbucket. Azure Repos Git ignores `pr:`; add a build validation policy on the default branch so `Build.Reason` is `PullRequest`. Staging deploy stays gated on that reason. The YAML cannot create the policy ([#398](https://github.com/opentidehq/opentide/issues/398)).
- `lint` prints `ISSUES` when findings exist. The exit code stays 0 unless `--strict`. JSON keeps `"ok": true`.
- MCP `get_chaining` returns the threat → objective → rule lineage reached through `objective.threats`, `rule.detection_model`, and threat-to-threat links. When `threat.chaining` is non-empty, `graph` stays that relation map and `lineage` lists the related objects. `Opentide.Models.chaining` is still the threat-to-threat map only ([#407](https://github.com/opentidehq/opentide/issues/407)).

### Fixed

- An object YAML file with no `uuid` fails validation. The schema check reports `missing_uuid`. An empty catalogue still exits 0 ([#397](https://github.com/opentidehq/opentide/issues/397)).
- `deploy --plan STAGING` on a detached pull-request checkout fetches `origin` by name. It no longer dies with `list index out of range` ([#402](https://github.com/opentidehq/opentide/issues/402), [#415](https://github.com/opentidehq/opentide/issues/415)).
- The generated inflight prune job creates `.opentide/inflight` before `git add`, so a repository that never committed that directory no longer exits 128 ([#403](https://github.com/opentidehq/opentide/issues/403)).
- `setup skills` downloads every file under `skills/<slug>/` and renders `AGENTS.md` from the package template. `opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` are installed from the package and describe `rule::1.0`, `objective::1.0`, and `threat::1.0` ([#399](https://github.com/opentidehq/opentide/issues/399), [#405](https://github.com/opentidehq/opentide/issues/405)).
- `setup repo` writes `.gitkeep` in empty scaffold directories and does not create `.github/workflows` itself. The README lists one `opentide deploy --platform <name> --dry-run` per enabled platform. `--name`, `--org`, or `--description` on an existing `README.md` keeps the file and warns ([#400](https://github.com/opentidehq/opentide/issues/400), [#404](https://github.com/opentidehq/opentide/issues/404)).
- `generate docs` writes `rules/README.md`, `objectives/README.md`, and `threats/README.md` when the folder has no objects ([#401](https://github.com/opentidehq/opentide/issues/401)).
- The docs home and installation page name **0.8.0** as the latest release ([#406](https://github.com/opentidehq/opentide/issues/406)).

### Install

```bash
pip install opentide==0.8.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.7.0] — 2026-09-29

Minor on 0.6.4. Upgrade to publish Tide objects to MISP, or to regenerate CI so a GitHub production job compares `github.ref` to a literal ref. Sharing is a new command. The share stage stays off until `opentide setup ci` is run with `--sharing`.

### Added

- `opentide share` publishes a threat, objective, or rule to MISP as one Event. `push`, `preview`, `status`, `retract`, and `targets` share `.opentide/configurations/sharing.toml`. `preview` and `status` do not contact the destination. An API key is never printed ([#184](https://github.com/opentidehq/opentide/issues/184), [#371](https://github.com/opentidehq/opentide/issues/371)).
- `sharing.toml` merges `[[misp]]` blocks by `name`. `opentide validate --check sharing-config` reports the sharing checker codes. The check is off unless requested, and it runs for `opentide share push` ([#370](https://github.com/opentidehq/opentide/issues/370)).
- Successful shares are recorded in `.opentide/states/sharing.jsonl`. A skip or a failure leaves that file unchanged. Setup gitignores `.opentide/states/` ([#373](https://github.com/opentidehq/opentide/issues/373)).
- The MISP connector wraps PyMISP. One Tide object is one Event, the object YAML is copied verbatim, and the Event UUID is assigned by MISP ([#372](https://github.com/opentidehq/opentide/issues/372)).
- `opentide setup` and `opentide setup ci` take `--sharing` / `--no-sharing`, default off. When selected, GitHub, GitLab, and Azure run `opentide share push --changed` after generate on a push to the default branch. Deploy still depends only on generate ([#375](https://github.com/opentidehq/opentide/issues/375)).

### Changed

- A regenerated GitHub workflow compares `github.ref` with `'refs/heads/<branch>'`. `format()` with only the format string is not a valid Actions expression.
- `opentide share preview` does not require the API key. `push` and `retract` still do.

### Fixed

- A create that fails after the remote lookup no longer deletes the matching ledger line.
- Importing the CLI no longer imports PyMISP, so usage errors and `--json` stay free of the `pymisp loaded properly` line.

### Install

```bash
pip install opentide==0.7.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.4] — 2026-09-28

Patch on 0.6.3. Upgrade if `generate` printed an empty error for a missing detection model, a GitHub production deploy never ran, setup rewrote a README or platform comments, or MCP `deploy_rule` crashed. Regenerate a GitHub, GitLab, or Azure workflow with `opentide setup ci` so production deploy and the checkout depth match this release.

### Fixed

- `generate` exits `1` with one JSON document whose `message` names the missing UUID and `detection_model`. 0.6.3 printed empty stdout and a traceback that ended in a bare `Exception`. A catalogue that contains the objective still completes, and `generate inflight` on the broken tree still exits `0` ([#352](https://github.com/opentidehq/opentide/issues/352)).
- MCP `deploy_rule` returns a structured failure for an unknown platform and for a platform with no tenants, instead of `KeyError` or `TypeError`. `deployment_status` reports `deployed: false` when the authoring config has no `external_id` and no tenants ([#345](https://github.com/opentidehq/opentide/issues/345)).
- `--json setup` quotes the path it would write. A target of `.` no longer reads as `..` ([#346](https://github.com/opentidehq/opentide/issues/346)).
- Explorer pages are offered only for GitHub. GitLab and Azure exit `0` and warn that Explorer pages were not written, instead of writing no job and no warning ([#347](https://github.com/opentidehq/opentide/issues/347)).
- A generated GitHub production deploy needs `generate`, so a push to the default branch still deploys when the pull-request staging job is skipped. GitHub, GitLab, and Azure deploy jobs fetch full history. A missing parent commit is named instead of a bare SHA ([#348](https://github.com/opentidehq/opentide/issues/348)).
- `setup --yes --ci none` scaffolds the repository and writes no pipeline. `setup ci none` is rejected. CI-only flags without `github`, `gitlab`, or `azure` are named in warnings ([#349](https://github.com/opentidehq/opentide/issues/349)).
- Re-running setup keeps an edited `README.md`, `.gitignore`, and comments in an existing platform toml. The first scaffold still creates those files. `setup ci` still replaces the workflow ([#350](https://github.com/opentidehq/opentide/issues/350)).
- `lint --fix` rewrites a metadata finding onto the path it just renamed. A second `--fix` does not rename that file again ([#353](https://github.com/opentidehq/opentide/issues/353)).
- Usage and CLI pages no longer tell the reader to run a command that exits `2` ([#354](https://github.com/opentidehq/opentide/issues/354)).

### Install

```bash
pip install opentide==0.6.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.3] — 2026-09-24

Patch on 0.6.2. Upgrade if a CI diff plan still crashed after 0.6.2: a missing tip SHA died on `encode`, Azure `STAGING` died on `KeyError` or a fetch of a missing `origin`, a ref that is not on `origin` died on `Invalid object name`, or `DEBUG`, `MANUAL`, or `ALWAYS` died on `KeyError`. Each still exits `1`, with the sentence for that case. `FULL` is unchanged.

### Fixed

- A CI diff plan whose tip SHA is unset exits `1` and names the variable: `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION` is required to compute the changed rules. 0.6.2 reached `repo.commit(None)` and died with `'NoneType' object has no attribute 'encode'` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- Azure `STAGING` without `SYSTEM_PULLREQUEST_SOURCEBRANCH` or `SYSTEM_PULLREQUEST_TARGETBRANCHNAME` exits `1` with `Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME | Ensure this is running in a Pull Request pipeline`. 0.6.2 fetched `origin` first, so a checkout with no remote died with `No git repository was found at origin`, and a checkout that had one died with `KeyError while compiling the deployment plan`. The variables are read before the fetch ([#339](https://github.com/opentidehq/opentide/issues/339)).
- GitHub or Azure `STAGING` whose pull-request ref is not on `origin` exits `1` with `Could not find git ref origin/<name>`. 0.6.2 died with `Invalid object name` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- `DEBUG`, `MANUAL`, and `ALWAYS` under CI exit `1` with `Deployment plan <NAME> is not a CI diff plan. Use STAGING, PRODUCTION, or FULL.` `ALWAYS` was an alias of `FULL` because both enum values were the same string, so `--plan ALWAYS` took the full-redeploy path. It is now its own plan. `FULL` still does not compute a git diff ([#339](https://github.com/opentidehq/opentide/issues/339)).
- A GitLab merged-result pipeline reads the second parent only when that commit has more than one parent. A one-parent `CI_COMMIT_BEFORE_SHA` keeps `CI_COMMIT_SHA` as the tip and exits `0` when both SHAs are in the checkout. 0.6.2 died with `list index out of range` ([#339](https://github.com/opentidehq/opentide/issues/339)).

### Tests

- Each skipped arm is checked for human and JSON output on GitLab, GitHub, and Azure, including Azure `STAGING` with no `origin` remote. The messages are the sentences above, and the output does not contain `lookup_ref`, `encode`, `list index out of range`, `KeyError while compiling the deployment plan`, or `Invalid object name` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- A one-parent merged-result commit exits `0`. The 0.6.2 GitLab base and GitHub pull-request-ref checks still pass ([#333](https://github.com/opentidehq/opentide/issues/333), [#334](https://github.com/opentidehq/opentide/issues/334), [#339](https://github.com/opentidehq/opentide/issues/339)).

### Install

```bash
pip install opentide==0.6.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.2] — 2026-09-24

Patch on 0.6.1. Upgrade if a GitLab `STAGING` or `PRODUCTION` plan crashed with `'Repo' object has no attribute 'lookup_ref'`, or a GitHub `STAGING` plan asked for Azure pull-request variables and then `KeyError`. Both still exit `1`. GitLab reports `No Source Commit Found`. GitHub names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF`.

### Fixed

- GitLab `STAGING` and `PRODUCTION` with an unset or unknown base SHA exit `1` with `No Source Commit Found`. 0.6.1 walked `origin/main` through Dulwich `Repo.lookup_ref`, which does not exist, so the command died with `FATAL: 'Repo' object has no attribute 'lookup_ref'` and never reached that message. The same command still succeeds when both SHAs are in the checkout ([#333](https://github.com/opentidehq/opentide/issues/333)).
- GitHub Actions `STAGING` without `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` exits `1` with `Expected to find GITHUB_HEAD_REF and GITHUB_BASE_REF | Ensure this is running in a Pull Request pipeline`. 0.6.1 fetched `origin` first, logged Azure `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then raised a bare `KeyError`, which deploy printed as `KeyError while compiling the deployment plan`. The Azure branch still cites the Azure names it reads ([#334](https://github.com/opentidehq/opentide/issues/334)).

### Tests

- A GitLab diff plan with an unset or unknown base, for `STAGING` and `PRODUCTION` and for human and JSON output, exits `1` with `No Source Commit Found` and does not mention `lookup_ref`. The same command exits `0` when both SHAs are in the checkout, including when `origin/main` exists and still does not contain the base ([#333](https://github.com/opentidehq/opentide/issues/333)).
- GitHub `STAGING` with an `origin` remote and neither pull-request ref set exits `1` with the GitHub variable sentence, in human and JSON output, and does not mention `SYSTEM_PULLREQUEST` or `KeyError` ([#334](https://github.com/opentidehq/opentide/issues/334)).

### Install

```bash
pip install opentide==0.6.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.1] — 2026-09-23

Patch on 0.6.0. Upgrade if a CI `STAGING` or `PRODUCTION` plan skipped a changed rule file that sits directly in `objects/rules/`: 0.6.0 left that file out of the plan, and 0.6.1 deploys it. A file in a subdirectory of `objects/rules/` is still not deployed. The missing-checkout failure is still exit `1`, with a different message.

### Changed

- CI `STAGING` and `PRODUCTION` plans include a changed rule file that sits directly in `objects/rules/`. 0.6.0 matched the git diff against an absolute rules path, so a repo-relative entry such as `objects/rules/rule.yaml` was left out and the plan deployed nothing for that change. A file under `objects/rules/<subfolder>/` stays out of the plan; the existing warning names it ([#318](https://github.com/opentidehq/opentide/issues/318)).

### Fixed

- `deploy --plan STAGING` or `PRODUCTION` with `GITHUB_ACTIONS`, `CI`, or `TF_BUILD` set and no git checkout exits `1` and names the directory it searched, and points at `--plan FULL`. 0.6.0 exited `1` with `FATAL: No git repository was found at None`. `FULL` still does not need a checkout. A directory that has `.git` is still opened ([#310](https://github.com/opentidehq/opentide/issues/310)).
- `opentide setup --path .` from a subdirectory of a git checkout scaffolds that directory. 0.6.0 treated the discovered git root as `--repo` and wrote the scaffold there. An explicit `--repo` still replaces `.` when it is not the working directory ([#324](https://github.com/opentidehq/opentide/issues/324)).
- `opentide setup --no-promotion` and `--promotion-target` write `[promotion]` in `.opentide/configurations/deployment.toml` without `--ci`. 0.6.0 applied those flags only when the same command generated a CI pipeline. Omitting them still keeps the repository's setting, and an explicit flag that disagrees with an existing table still exits `2` before anything is written ([#325](https://github.com/opentidehq/opentide/issues/325)).

### Tests

- CI diff selection keeps a top-level `.yaml` or `.yml` (repo-relative or absolute) in the plan and a file under `objects/rules/<subfolder>/` in the skipped list, and rejects lookalike paths such as `objects/rules-archive/` ([#318](https://github.com/opentidehq/opentide/issues/318)).
- The missing-checkout failure is checked for all three CI markers, both diff plans, human and JSON output, a `FULL` plan, and a real `git init` checkout. The CI overlay clears `GITHUB_WORKSPACE` and the other platform variables, so a GitHub-hosted run does not open the checkout the job itself is in ([#310](https://github.com/opentidehq/opentide/issues/310)).
- `setup --path .` from a subdirectory of a git checkout writes `.opentide` there, and an explicit `--repo` still selects the git root ([#324](https://github.com/opentidehq/opentide/issues/324)).
- A plain `setup` applies or refuses `--no-promotion` and `--promotion-target` before any file is written ([#325](https://github.com/opentidehq/opentide/issues/325)).

### Install

```bash
pip install opentide==0.6.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.0] — 2026-09-23

Minor on 0.5.0. Upgrade if a command checked the wrong directory, hid what `--json` already showed, or crashed on a repository that was not finished yet. A few JSON fields and exit results change, so read **Changed** before upgrading a pipeline.

### Changed

- SDK: the registry index has a `file_paths` map from UUID to the file each object was read from; `files` still holds bare file names. `ValidationScope.matches_file()` matches a path target only through the object's own path, and the `ValidationScope.path_basenames` field is removed ([#297](https://github.com/opentidehq/opentide/issues/297)).
- `opentide --json setup mcp --generic` returns its copy-the-file instruction as `advice` instead of `note`, so human output prints it too. Scripts that read `note` should read `advice` ([#292](https://github.com/opentidehq/opentide/issues/292)).
- `opentide validate` reports the directory it read objects from as `workspace` in `--json` output. A full run that finds no objects still passes with exit `0`, `--strict` included, but its message names that directory (`Validation passed, but no detection objects were found under …`) instead of a bare `Validation passed` ([#294](https://github.com/opentidehq/opentide/issues/294)).

### Fixed

- In the SDK, `rule.metadata.schema` returns the schema identifier (`"rule::1.0"`), as `docs/sdk/models.md` shows. It returned Pydantic's deprecated `BaseModel.schema` method, so the documented line printed a bound method; the same held for `.schema` on platform blocks (`rule.configurations.sentinel.schema`). `schema_id` / `platform_schema` stay the canonical fields, and validation, `model_dump(by_alias=True)` and generated JSON Schemas still use the `schema` key ([#298](https://github.com/opentidehq/opentide/issues/298)).
- `opentide setup --ci <github|gitlab|azure>` accepts `--default-branch`, like `setup ci`. Without the flag, a repository with no `origin/HEAD` now gets its checked-out branch, ahead of `init.defaultBranch` and `main`: a repository whose only branch was `trunk` got a pipeline that fetched from, pushed to, and deployed on `main`. Both forms warn when the pipeline falls back to a `main` branch the repository does not have, or targets the checked-out branch while other local branches exist ([#288](https://github.com/opentidehq/opentide/issues/288)).
- `opentide setup` prints the warnings of its steps. The one-shot `setup --ci <provider>` showed none of the CI step's `WARNING` lines that `setup ci <provider>` prints for the same condition, such as GitLab ignoring `--default-branch`; with `--json` they now also appear in the top-level `warnings`, not only under `steps[].warnings` ([#308](https://github.com/opentidehq/opentide/issues/308)).
- `validate --file` with a repo-relative or absolute path validates only that file when object folders have subfolders. The index kept only each object's file name, so `--file objects/rules/x.yaml` also validated `objects/rules/other/x.yaml` and reported its issues against `objects/rules/x.yaml`, while `--file objects/rules/other/x.yaml` matched nothing. A path no longer falls back to its file name, a bare file name still matches that name in every subfolder, and every issue names the file of the object it concerns — in the CLI, MCP `validation_report`, and `--check cve` ([#297](https://github.com/opentidehq/opentide/issues/297)).
- The duplicate-ID check reads object files in subfolders, as indexing does. A UUID duplicated in a file under `objects/rules/<subfolder>/` passed a full `validate` ([#297](https://github.com/opentidehq/opentide/issues/297)).
- SDK: `rule.file` on `Opentide.Rules[...]` and `Opentide.Models.Rules[...]` points at the rule's own file in subfolders. It was rebuilt as `<rules folder>/<file name>`, so a rule in `objects/rules/other/x.yaml` got `objects/rules/x.yaml` — another rule's file, or none ([#297](https://github.com/opentidehq/opentide/issues/297)).
- Human output no longer drops bracketed text. Rich read it as markup, so the `info` platform rows lost `[deploy, validate]`, the `validate` issues panel lost each `[error]` tag, and `generate extract sentinel` told you to `install opentide` without `[sentinel]` — `--no-color` included, while `--json` was correct. Help text that named `opentide[sentinel]` or `[deprecated]` lost it the same way ([#292](https://github.com/opentidehq/opentide/issues/292)).
- Human output prints a result's `advice` and `detail` as indented lines under its message, as `--json` carries them: `validate query --live` without the vendor SDK names the extra to install, and a live run on a disabled platform says how to enable it ([#292](https://github.com/opentidehq/opentide/issues/292)).
- Human `opentide lint` lists each finding as `[check] path: message` above its summary line. It used to print only `OK Catalogue lint found issues`, so without `--json` there was no way to see what to fix ([#292](https://github.com/opentidehq/opentide/issues/292)).
- `opentide info rules`, `info threats`, `info objectives`, and `info coverage --technique …` print the section asked for — UUID and name per object, the platforms each rule configures, the technique and its rule count — instead of the plain `info` summary ([#293](https://github.com/opentidehq/opentide/issues/293)).
- `generate docs` writes an actor's Source cell as its vocabulary stage (`att&ck`) instead of the Python tuple `('att&ck',)`. Documentation cells join any collection of values the same way, and a cell with no value shows `-` ([#296](https://github.com/opentidehq/opentide/issues/296)).
- `opentide info` and `Opentide.initialise()` no longer build a client for every installed platform, so a repo that does not use Splunk no longer logs `The frequency scheduling setting was not correct set` twice. Clients are built only when a command deploys to or validates against their platform. A Splunk setup without `frequency_scheduling` no longer warns and keeps the mode it deployed with before: `random` for a `[[tenants]]` entry, `current` for a legacy `[setup]` table. An invalid value logs one `frequency_scheduling_is_not_valid` warning that names the value ([#295](https://github.com/opentidehq/opentide/issues/295)).
- Commands run from inside a detection workspace find it. Root discovery walked up for `.git` only, so from `objects/rules` in a scaffold outside git, or anywhere in a workspace kept below a larger checkout (`monorepo/detections/`), the root was the current directory or the checkout: `info` counted no objects, configured platforms showed as disabled, and `validate --strict` passed having checked nothing. The CLI, SDK, and MCP server now stop at the nearest directory holding `.opentide/` or `objects/`, never above the enclosing git checkout, and fall back to the git top level as before. `--repo`, `OPENTIDE_REPO_ROOT`, and `OPENTIDE_TIDE_WORKSPACE` still take precedence, and `generate docs --changed` finds a nested workspace's changes from the cwd alone ([#294](https://github.com/opentidehq/opentide/issues/294)).
- `deploy` in a workspace without `objects/rules/` (an empty directory, or a fresh clone before the first rule is committed) no longer exits `1` with `FATAL: [Errno 2] No such file or directory`. It reports `skipped` with exit `0` and contacts no platform, as `validate`, `lint`, `info`, and `generate` already did. The same applies to `validate query --live`, and to a rules folder holding only `.gitkeep` or a subfolder, which failed with `'NoneType' object is not subscriptable` and `[Errno 21] Is a directory`. A skipped deploy now returns the same JSON keys as one that planned rules: `dry_run`, an empty `plan` and `deployed`, and `payloads` on `--dry-run` ([#300](https://github.com/opentidehq/opentide/issues/300)).
- `deploy` no longer skips rule files in subfolders of `objects/rules/` silently. Deploy still reads only the files directly in `objects/rules/` ([#312](https://github.com/opentidehq/opentide/issues/312)), but every plan now warns once and names the skipped files: a `WARNING` line in human output, and the result's `warnings` with `--json`. The list shows five names and then `+N more`. In CI, where `STAGING` and `PRODUCTION` plan from the git diff, only changed files are named. A repository whose rules all sit in subfolders reports `skipped` with the warning ([#300](https://github.com/opentidehq/opentide/issues/300)).
- The `deploy` reference, troubleshooting, and tutorial pages match the commands they document: a dry-run prints `== MDR Deployment ==` and `OK Deployment completed` (the plan and payloads only with `--json`). The tutorial scaffold leaves `[[tenants]]` commented out, so that dry-run's JSON leaves `deployed` empty and warns that a real deploy would stop. `deploy metadata` exits `2` with `FATAL: Metadata deployment is not implemented for splunk` rather than logging intent, and the tutorial's T1059 coverage query lists the rule alone, not an objective ([#299](https://github.com/opentidehq/opentide/issues/299)).
- `deploy` and `validate query --live` no longer crash with a bare `Exception` when an enabled platform has rules but no `[[tenants]]` entry. Both exit `1` with the platform and the file to edit, before any engine loads. `deploy --dry-run` still previews payloads, leaves that platform out of `deployed`, and warns that a real deploy would stop ([#314](https://github.com/opentidehq/opentide/issues/314)).
- `opentide setup`, `setup --ci <provider>` and `setup ci <provider>` now apply `--no-promotion` and `--promotion-target <STATUS>`. Both flags were accepted and ignored: no generated pipeline has a promotion job, and `opentide deploy` promotes as the merged `deployment.toml` says, so `--promotion-target STAGING` still promoted rules to `PRODUCTION`. Setup now writes those values to the `[promotion]` table of `.opentide/configurations/deployment.toml`, keeping the rest of an existing file, and lists the file in its result. Omitting the flags keeps the repository's setting. A target that is not a status of the repository, or an explicit flag that disagrees with an existing `[promotion]` table, exits with code 2 before anything is written. An explicit value equal to the bundled default writes nothing when the repository has no `[promotion]` table. The never-rendered promotion jobs are removed from the GitHub, GitLab and Azure renderers; generated pipelines are unchanged ([#307](https://github.com/opentidehq/opentide/issues/307)).
- `vocab-upstream.yml` no longer puts `secrets` in a step `if`, which GitHub's workflow parser rejected, so the vocabulary drift gate never ran ([#287](https://github.com/opentidehq/opentide/issues/287)).
- `publish-pypi.yml` can be retried after a PyPI 5xx: an upload that already succeeded is skipped, and the job checks that the release files are on PyPI before it finishes ([#289](https://github.com/opentidehq/opentide/issues/289)).

### Tests

- A parity test fails when a `setup ci` option is missing from the one-shot `setup --ci`, declared with a different default, or not passed on to CI generation ([#288](https://github.com/opentidehq/opentide/issues/288)).
- A human-vs-JSON parity test runs a matrix of commands on the tutorial workspace with and without `--json` and requires every top-level prose string in the payload, plus its warnings, issue severities, findings, platform capabilities, and section items, to appear verbatim in the human output. A unit guard sends markup-like text through every emit helper and checks that every help string renders its brackets ([#292](https://github.com/opentidehq/opentide/issues/292), [#293](https://github.com/opentidehq/opentide/issues/293)).
- A console-script E2E runs `info`, `validate --strict`, `lint --strict`, `generate docs`, and `generate` from the root of a scaffold, from `objects/rules` and `.opentide/configurations/platforms` inside it, and from a workspace nested in a parent git checkout, with no `OPENTIDE_*` variables set, and requires the same workspace, counts, and output location from each ([#294](https://github.com/opentidehq/opentide/issues/294)).
- A `text` or `json` fence in `docs/` tagged `output-of="opentide …"` (plus `exit=N` for a command meant to fail) is run against a repository scaffolded as in the tutorial, with deployers stubbed. Its lines or JSON values and its exit code must match the live command, the command must be printed on the same page, and a failing sample's section must say which code it exits with ([#299](https://github.com/opentidehq/opentide/issues/299)).
- A sample of a failure the finished tutorial does not produce names the repository edit it needs, `state=dangling-reference` or `state=unterminated-string`, so the `exit-codes` failure envelope and the `validate` offline-syntax finding are checked like any other sample ([#299](https://github.com/opentidehq/opentide/issues/299)).
- Pairing is no longer opt-in for CLI output. A `text`, `json`, or unlabelled fence under `docs/cli/` or `docs/usage/` that holds an `"ok"` / `"status"` key, or a line starting `OK `, `SKIPPED `, `WARNING `, `DEPRECATED `, `FATAL`, or `== … ==`, fails the golden test unless it carries `output-of=` or is marked `illustrative` ([#299](https://github.com/opentidehq/opentide/issues/299)).
- Every platform is deployed and live-query-validated from a `setup repo` scaffold whose tenant example is still commented out. A real deploy must fail before an engine import; a dry run must not list the platform as deployed ([#314](https://github.com/opentidehq/opentide/issues/314)).

### Install

```bash
pip install opentide==0.6.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

If you generated CI with `opentide setup ci`, regenerate it so `--default-branch` matches the branch you deploy from: `opentide setup ci <github|gitlab|azure> --yes`.

## [0.5.0] — 2026-09-23

Minor on 0.4.0. Upgrade if your threats follow `threat::1.0` and list their `impact` / `leverage` names: 0.4.0 rejected every such threat with `Input should be a valid string` ([#189](https://github.com/opentidehq/opentide/issues/189)). It is a minor rather than a patch because a threat written the way 0.4.0 required (`impact: Data Breach`) now fails validation until it becomes a one-item list — read **Changed** before upgrading a pipeline.

### Changed

- `threat.impact` and `threat.leverage` must be non-empty YAML lists of vocabulary names, as `threat::1.0` specifies. A single string (`impact: Data Breach`), which 0.4.0 required, now fails validation with `must be a YAML list of impact vocabulary names`; rewrite it as a one-item list. Several names joined with `;` fail too, as the whole value or as one list item: give each name its own item and keep all of them ([#189](https://github.com/opentidehq/opentide/issues/189)).
- In the SDK `ThreatBody.impact` and `ThreatBody.leverage` are `list[str]`. Generated threat templates, editor schemas (`type: array`, `minItems: 1`), and the explorer bundle carry both fields as lists ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Fixed

- A threat written to the `threat::1.0` spec (`impact: [Data Breach, Identity Theft]`) no longer fails with `Input should be a valid string`, and `validate` no longer suggests a single vocabulary name for a `;`-joined value, which would drop the other names ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Tests

- The 14 `threat-*.yaml` conformance fixtures from [opentidehq/specifications](https://github.com/opentidehq/specifications) are vendored under `tests/fixtures/specifications/threat-1.0/` and run through `opentide validate --file` in the E2E suite. The valid fixture must pass, each invalid one must fail on the field it breaks, and a guard test fails when upstream adds a fixture without an expectation ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Install

```bash
pip install opentide==0.5.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Rewrite each `impact: Data Breach` as a one-item list (same for `leverage`), then run `opentide generate` so new threats start from the list template. If your CI patches the installed model to accept lists, drop that step.

## [0.4.0] — 2026-09-22

Minor on the public 0.3.0 beta. Upgrade if a first-run command crashed, printed a traceback, or quietly did nothing: this release fixes the first-user bugs filed against 0.3.0 ([#239](https://github.com/opentidehq/opentide/issues/239)–[#258](https://github.com/opentidehq/opentide/issues/258), [#202](https://github.com/opentidehq/opentide/issues/202), [#233](https://github.com/opentidehq/opentide/issues/233)) and the test-harness gaps that let them ship ([#259](https://github.com/opentidehq/opentide/issues/259)). It is a minor rather than a patch because several fixes change output that scripts can depend on — read **Changed** before upgrading a pipeline. If you generated GitHub CI with `opentide setup ci`, regenerate it — see **Security**.

### Security

- The inflight job written by `opentide setup ci github` checked out the pull request head and ran `git push origin HEAD:<default branch>`. Whenever the pull request was up to date with the default branch, that push fast-forwarded the default branch to the pull request, landing its unreviewed changes. Generated GitHub, GitLab, and Azure inflight jobs now commit only `.opentide/inflight/` shards, on a separate worktree of the default branch, and push that. Regenerate existing pipelines with `opentide setup ci <github|gitlab|azure> --yes` ([#244](https://github.com/opentidehq/opentide/issues/244)).

### Changed

- `opentide validate query` is an offline syntax check (KQL, SPL, S1QL, Lucene) by default and needs no platform SDK, credentials, or network. It follows each dialect's quoting and escaping: KQL multi-line strings (```` ``` ```` and `~~~`), S1QL `||` (with an operand on each side), and Lucene backslash escapes, mixed range ends, and `/regex/` terms. The previous tenant round-trip is `validate query --live`, which names the extra to install when the SDK is missing. JSON output reports `mode: offline-syntax` or `mode: live` ([#239](https://github.com/opentidehq/opentide/issues/239)).
- `validate query` for CrowdStrike and HarfangLab returns the normal `ok` / `status` envelope with `supported: false` instead of a bare payload ([#247](https://github.com/opentidehq/opentide/issues/247)).
- `query` is required and must not be blank on Splunk and Carbon Black configurations, as on the other query platforms. A rule with `query: ""` now fails validation instead of deploying nothing ([#233](https://github.com/opentidehq/opentide/issues/233)). See [Upgrading to 0.4.0](https://opentide.org/docs/usage/concepts/platforms/#upgrading-to-040).
- `opentide --json setup` without `--yes` refuses to start the interactive wizard and exits non-zero with one JSON error ([#255](https://github.com/opentidehq/opentide/issues/255)).
- MCP `search` always returns a list (a UUID lookup included, which also honours the other filters and ignores case; `get_chaining` resolves UUIDs the same way and returns the graph for them), `platform=` matches the configuration key exactly, and `coverage` for a parent technique includes sub-technique rules and reports `matched_techniques` ([#252](https://github.com/opentidehq/opentide/issues/252), [#253](https://github.com/opentidehq/opentide/issues/253)).
- MCP `opentide://vocabularies` returns an index (`metadata`, `entry_count`, `uri`) instead of every entry; read `opentide://vocabularies/{name}` for entries ([#254](https://github.com/opentidehq/opentide/issues/254)).
- MCP `run_query` is an explicit stub (`stub: true`, `rows: null`, no `results` key) rather than a successful empty result ([#258](https://github.com/opentidehq/opentide/issues/258)).
- `mcp` is pinned `<2` and the unused `fastmcp` dependency is gone. `opentide[sentinel]` declares the Azure packages the Sentinel validator and deployer import ([#256](https://github.com/opentidehq/opentide/issues/256), [#239](https://github.com/opentidehq/opentide/issues/239)).
- The positional `PATH` on `setup` subcommands is deprecated in favour of `--path` / `-C`. Giving both is a usage error ([#248](https://github.com/opentidehq/opentide/issues/248)).

### Fixed

- `deploy metadata` and `generate inflight prune` no longer run their parent command first — a live deploy, or a second JSON document on stdout ([#243](https://github.com/opentidehq/opentide/issues/243)).
- `opentide info coverage --technique T1059` works in either argument order ([#257](https://github.com/opentidehq/opentide/issues/257)).
- Every `setup` subcommand accepts `--path` / `-C` and `--yes` / `-y`. Given before the subcommand (`opentide setup --path DIR --yes env`) they apply to it; other `setup` options in that position are refused instead of silently ignored, and a subcommand's `--help` after them still shows its help ([#248](https://github.com/opentidehq/opentide/issues/248)).
- `validate --file objects/rules/x.yaml` honours the directory; a path target no longer matches a same-named file elsewhere. The ID-uniqueness check and the MCP `validation_report` tool resolve the same targets against the workspace, so a duplicate UUID is reported and an MCP server started outside the repository still finds the file ([#240](https://github.com/opentidehq/opentide/issues/240)).
- Unparseable object YAML is reported as a `yaml_parse` validation issue instead of a traceback, including files the indexer skips ([#250](https://github.com/opentidehq/opentide/issues/250)).
- `generate docs --changed` reports a structured failure in a repository without commits instead of a traceback. `generate docs --changed` and `generate inflight` find the baseline on `development`, `main`, or `master` (upstream, remote, or local), or whatever `origin/HEAD` names, count untracked object YAML, keep non-ASCII file names, and work when the workspace is nested inside the checkout. A pushed feature branch (`git push -u`, or an `actions/checkout` job) is compared with the default branch rather than its own remote copy, which hid every committed change ([#241](https://github.com/opentidehq/opentide/issues/241), [#251](https://github.com/opentidehq/opentide/issues/251)).
- `generate extract sentinel|defender` fail with a reportable error that names the missing extra, tenant, or key instead of `ModuleNotFoundError` / `KeyError` at import ([#242](https://github.com/opentidehq/opentide/issues/242)).
- `opentide generate explorer` is registered and writes `explorer.bundle.json` / `explorer.search.json`; the GitHub CI template calls it instead of the nonexistent `opentide explorer build` ([#202](https://github.com/opentidehq/opentide/issues/202)).
- A Sentinel-only `validate query` or deploy loads only the Sentinel engine: no missing-validator warnings for other vendors and no `ERROR` for platforms the repository disabled. An engine that fails to load is reported instead of a traceback ([#246](https://github.com/opentidehq/opentide/issues/246)).
- `setup ci gitlab` inflight jobs use `${CI_JOB_TOKEN}` / `${CI_SERVER_HOST}` and a commit message GitLab can parse; `setup ci azure` inflight jobs actually commit and push (`set -e` script, `persistCredentials: true`, no cross-stage `dependsOn`); GitLab jobs that run `git` install it on the `python:*-slim` image. GitHub and Azure jobs target the repository's default branch (`setup ci --default-branch`, else `origin/HEAD`) instead of assuming `main`, and inflight jobs retry when another job publishes first and keep the shards other pull requests publish while they run ([#244](https://github.com/opentidehq/opentide/issues/244)).
- The pre-commit hook validates the worktree being committed rather than an exported `OPENTIDE_REPO_ROOT`, and `--repo` overrides an exported workspace ([#249](https://github.com/opentidehq/opentide/issues/249)). A workspace nested below the Git root is validated at its own path, several workspaces in one repository share the hook instead of the last `setup hooks` run replacing the others, and a hook whose workspace was moved or deleted fails instead of passing every commit. Setup no longer installs into a user-wide `core.hooksPath`, where the hook would fail commits in every other repository, and no longer crashes on Windows when the hooks directory is on another drive.
- `--no-color`, `NO_COLOR`, `FORCE_COLOR=0`, and `PY_COLORS=0` keep every line free of ANSI escapes, including Typer help and usage errors on CI runners that force colour. Importing `opentide.ci` no longer changes a host application's Typer colour settings ([#282](https://github.com/opentidehq/opentide/pull/282)).
- MCP `coverage` and actor search read `rule.techniques` and `threat.actors`, not only `tags.*` ([#252](https://github.com/opentidehq/opentide/issues/252)).
- MCP `opentide://schemas/{object_type}` resolves `rule` / `rule::1.0` instead of returning `{}`, `opentide://templates/{object_type}` accepts the same forms for the current schema version, and vocabularies are JSON rather than Pydantic `repr()` strings ([#254](https://github.com/opentidehq/opentide/issues/254)).
- MCP `validate_query` returns real findings instead of `valid: true` for any string ([#245](https://github.com/opentidehq/opentide/issues/245)).
- `opentide-mcp` from a plain `pip install opentide` prints the install line for the `mcp` extra instead of a traceback, and `opentide setup mcp` warns when the extra is missing ([#256](https://github.com/opentidehq/opentide/issues/256)).
- `splunk::2.x` rules map `search`, `cron_schedule`, and flat throttling / notable / risk / email fields the same way in `validate` and `deploy`, and a migrated `cron_schedule` deploys as a scheduled search ([#233](https://github.com/opentidehq/opentide/issues/233)).
- Tutorial, quickstart, and CLI reference samples match live output ([#247](https://github.com/opentidehq/opentide/issues/247)).

### Tests

The CI harness now exercises the paths a first user takes, so these bugs fail CI if they return ([#259](https://github.com/opentidehq/opentide/issues/259)): interactive setup on a real PTY ([#260](https://github.com/opentidehq/opentide/issues/260)); `validate query` against the real validators ([#261](https://github.com/opentidehq/opentide/issues/261)); the wheel job runs `opentide-mcp` with and without the extra ([#262](https://github.com/opentidehq/opentide/issues/262)); a Typer argv matrix ([#263](https://github.com/opentidehq/opentide/issues/263)); unmocked MCP tests plus a stdio JSON-RPC client ([#264](https://github.com/opentidehq/opentide/issues/264)); hook tests that run `git commit` ([#265](https://github.com/opentidehq/opentide/issues/265)); unmocked `generate extract` / `generate explorer` ([#266](https://github.com/opentidehq/opentide/issues/266)); repo-relative `validate --file` ([#267](https://github.com/opentidehq/opentide/issues/267)); git-baseline e2e for HEAD-less and non-`main` repositories ([#268](https://github.com/opentidehq/opentide/issues/268)); assertions on GitLab and Azure job scripts ([#269](https://github.com/opentidehq/opentide/issues/269)); and every documented `opentide` command resolved against the live CLI, with read-only samples executed as golden tests ([#270](https://github.com/opentidehq/opentide/issues/270)).

### Not in this release

- [#189](https://github.com/opentidehq/opentide/issues/189) (`ThreatBody.impact` / `leverage` as `list[str]`) waits on [opentidehq/specifications#12](https://github.com/opentidehq/specifications/issues/12).

### Install

```bash
pip install opentide==0.4.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Regenerate generated CI and hooks to pick up the fixed templates: `opentide setup ci <github|gitlab|azure> --yes` and `opentide setup hooks --yes`.

## [0.3.0] — 2026-09-21

Minor maintenance release on the public 0.2.1 beta. Upgrade for current runtime and toolchain floors (cryptography 50.x, typer 0.27) and a clean GitHub Code Quality pass.

### Changed

- Recreated stale Dependabot uv upgrades on current trunk ([#235](https://github.com/opentidehq/opentide/pull/235)): cryptography **50.0.1** (CVE-2026-69247), dulwich **1.2.15**, typer **0.27.2** (extra `all` was removed in 0.27; rich/shellingham/colorama are default deps), syrupy **5.5.3** (stay on 5.x), ruff **0.16.8**, ty **0.0.82** (dev extra only; `typing_extensions` stays a runtime dependency).
- Cleared GitHub Code Quality findings from the CodeQL `python-code-quality` suite ([#236](https://github.com/opentidehq/opentide/pull/236)).

### Install

```bash
pip install opentide==0.3.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.1] — 2026-09-18

Patch on the public 0.2.0 beta. Upgrade if you validate `threat.cve` identifiers or generate threat documentation that should link to CIRCL Vulnerability-Lookup.

### Added

- CVE validation and generated threat CVE tables use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) instead of scraping NVD through `mitrecve`. `opentide validate --check cve` looks up CVE, GHSA, and GCVE identifiers (`GET /api/vulnerability/{id}`); unknown IDs return empty JSON. Generated docs link to `https://vulnerability.circl.lu/vuln/{id}` and can enrich published date, severity, and aliases ([#109](https://github.com/opentidehq/opentide/issues/109)).
- `threat.cve` is a first-class optional list on the threat body, so schema validation accepts CVE identifiers. GNA 0 GCVE ids (`GCVE-0-YEAR-N`) map to the reserved CVE key.

### Changed

- Bundled `documentation.toml` `[cve]` defaults to Vulnerability-Lookup (`base_url` / `default_db_link`). Legacy NVD link prefixes are remapped. The CVE check stays **opt-in** (`--check cve`) so default `opentide validate` stays offline.

### Install

```bash
pip install opentide==0.2.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.0] — 2026-09-18

Minor on the public 0.1.8 beta. Upgrade if you generate templates or VS Code snippets — optional YAML now hugs `#` to each key, spacers stay blank, and rule `configurations` are commented platform stubs rather than `{}`.

### Changed

- `opentide generate templates` walks Pydantic `FieldInfo` instead of the JSON Schema `gen_template` walker. Optional sections are commented YAML blocks (`#` hugs each key; nested optionals are not commented again; spacer blanks stay blank), placeholders are typed (no `null`), nested bodies come from nested models, and rule `configurations` are commented platform stubs rather than `{}` ([#223](https://github.com/opentidehq/opentide/issues/223)).
- VS Code snippet conversion treats commented nested keys as mapping children, so `configurations:` with only `#sentinel:` stubs is not turned into a tabstop.

### Install

```bash
pip install opentide==0.2.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.8] — 2026-09-16

Patch on the public 0.1.7 beta. Upgrade if first-time `setup` / `generate` logged missing object folders as errors, dumped YAML `null`, attached live children under `#key:` parents, skipped platform TOML from `setup repo --platform`, emitted Title-Case UUID documentation paths, or looked up `objective.priority` in `criticality::1.0`.

### Added

- VS Code snippets use `tide-threat` / `tide-objective` / `tide-rule` / `tide-<platform>` prefixes, `scope: yaml`, descriptions, and tabstops on empty scalars. Missing core or enabled-platform templates fail loud ([#194](https://github.com/opentidehq/opentide/issues/194)).
- `opentide setup vscode --mcp` writes `.vscode/mcp.json` through the existing MCP helper. Parent `--vscode-setup` still does not imply MCP ([#193](https://github.com/opentidehq/opentide/issues/193)).

### Fixed

- Absent `objects/{threats,objectives,rules}` folders log at **debug**, once per path. Paths that exist but are not a directory still log at **error** ([#212](https://github.com/opentidehq/opentide/issues/212)).
- Optional template subtrees dumped as `#key:` now comment nested children, so `uuid` / `name` no longer attach to the previous mapping ([#209](https://github.com/opentidehq/opentide/issues/209)).
- Generated templates skip `default: None` (no YAML `null`) and restore typed placeholders ([#210](https://github.com/opentidehq/opentide/issues/210)).
- `opentide setup repo --platform` writes and enables `.opentide/configurations/platforms/*.toml`, so `generate` emits `#sentinel:` (and other) configuration stubs ([#211](https://github.com/opentidehq/opentide/issues/211)).
- Objective documentation renders `priority` as the author string. It is not looked up in `criticality::1.0` ([#204](https://github.com/opentidehq/opentide/issues/204)).
- GitHub/generic docs use lowercase `docs/{rules,objectives,threats}/<slug>.md`. UUID permalinks stay GitLab-only ([#203](https://github.com/opentidehq/opentide/issues/203)).

### Install

```bash
pip install opentide==0.1.8
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.7] — 2026-09-16

Patch on the public 0.1.6 beta. Upgrade if VS Code YAML reported "Matches multiple schemas", generated templates hid required nested fields, `setup vscode` skipped snippets or crashed on a missing path, JSON validate stamped every check failed, or `invalid_ref` pointed at parent objects.

### Fixed

- `invalid_ref` is attributed to the leaf UUID field. JSON `validate` reports per-check `status` (`uuid`, `metadata`, `schema`, `vocab`, `query`, `references`). Vocabulary names skip YAML list indices ([#186](https://github.com/opentidehq/opentide/issues/186)).
- VS Code `yaml.schemas` maps each object folder recursively (`objects/threats/**/*.yaml`) instead of the `opentide.schema.json` router glob, so nested files keep editor association ([#185](https://github.com/opentidehq/opentide/issues/185)).
- MCP templates use `servers` for VS Code 1.102+ / Cursor, host-specific `OPENTIDE_REPO_ROOT` (`${workspaceFolder}` vs `${CLAUDE_PROJECT_DIR}`), `.vscode/extensions.json`, and `AGENTS.md` ([#188](https://github.com/opentidehq/opentide/issues/188)).
- Template `$ref` / `$defs` expansion inlines nested object bodies. Nested `required` lists are no longer inherited from the parent, so required nested fields stay uncommented ([#191](https://github.com/opentidehq/opentide/issues/191)).
- `opentide setup vscode` generates templates and schemas before writing snippets, and fails if snippets were requested but could not be written ([#192](https://github.com/opentidehq/opentide/issues/192)).
- `opentide setup vscode` creates a missing target directory before generate, so `chdir` no longer raises `FileNotFoundError` ([#200](https://github.com/opentidehq/opentide/pull/200)).

### Install

```bash
pip install opentide==0.1.7
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.6] — 2026-09-15

Patch on the public 0.1.5 beta. Upgrade if `opentide generate` crashed on unquoted YAML dates, or if interactive `opentide setup` crashed after choosing a CI provider.

### Fixed

- Unquoted `YYYY-MM-DD` values in `metadata.created` / `modified` no longer crash `opentide generate` with `TypeError: Object of type date is not JSON serializable`. The YAML loader stringifies timestamps so export JSON matches the schema's string dates ([#178](https://github.com/opentidehq/opentide/issues/178)).
- Interactive `opentide setup` no longer raises `ValueError: validate must be callable` on the CI workflow features checkbox. Optional Questionary checkboxes omit `validate` ([#177](https://github.com/opentidehq/opentide/issues/177)).

### Install

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.5] — 2026-09-13

Patch on the public 0.1.4 beta. Upgrade if you regenerate ATT&CK or MISP vocabularies, or if you run the weekly ingest workflow.

### Added

- Weekly (and `workflow_dispatch`) ingest for MITRE ATT&CK STIX and MISP threat actors. Vocabularies merge with per-key RFC 0003 versions; schema pins for techniques, actors, and datasources bump in the same PRs. `uv run python scripts/vocabulary/sync_upstream.py --check|--apply`.

### Fixed

- ATT&CK groups are catalog-only (`att&ck.groups`); live objects pin them via `threat.actors.name` → `actors::*`. Ingest no longer reports pin bumps for vocabs that no pin file references (`att&ck.groups`, `mitigations`).
- Weekly ingest fetches `chore/vocab-upstream` before `git push --force-with-lease` so later cycles can update the specifications branch.

### Install

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.4] — 2026-09-13

Patch on the public 0.1.3 beta. Upgrade if `opentide generate` crashed with `'str' object has no attribute 'get'` on `threat.actors`, or if you authored actors as vocabulary ID strings.

### Fixed

- `threat.actors` is a list of objects (`name` is a scoped actors-vocabulary ID such as `att&ck::G0006`; optional `sighting` and `references`), matching CoreTide. Generated JSON Schema no longer teaches `list[str]`. `opentide generate` no longer crashes calling `.get` on a string ([#172](https://github.com/opentidehq/opentide/issues/172)).
- Nested vocabulary fields (for example threat leverage / viability and objective composition) are validated against the pinned vocabs instead of being skipped.
- Explorer export uses timezone-aware UTC so the package imports on Python 3.10.

### Install

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.3] — 2026-09-11

Patch on the public 0.1.2 beta. Upgrade if you ran `setup ci`, `deploy` / `validate query` locally, followed the tutorial, or installed without Azure/pandas extras.

### Fixed

- `opentide setup ci` emits parseable GitHub, GitLab, and Azure YAML. `textwrap.dedent` no longer strips indentation from already-indented step blocks ([#163](https://github.com/opentidehq/opentide/issues/163)).
- `opentide deploy` and `validate query` no longer crash locally when `DEPLOYMENT_PLAN` is unset. Unset or blank env defaults to `FULL`; illegal names fail with a clear error. Local debug compiles from the rules folder; PRODUCTION promotion is skipped for `--dry-run` and LocalDebug ([#164](https://github.com/opentidehq/opentide/issues/164)).
- Tutorial objects validate and lint: required `metadata.created` / `modified`, severity vocabulary, filenames matching `slugify(name)`, nested organisation and author. `setup` scaffolds `docs/Rules`, `docs/Objectives`, and `docs/Threats`. Templates emit `YYYY-MM-DD` dates. `generate docs` joins relative docs paths against the repository root ([#165](https://github.com/opentidehq/opentide/issues/165)).
- `opentide info` reports `can_deploy: true` after a base `pip install` (no Azure/pandas extras). Platforms lazy-load optional SDKs; `requests` is a core dependency. Tenant `[platform]` identity is not parsed as a detection-rule schema. Coverage counts top-level `techniques`. `generate extract` runs the installed package modules ([#166](https://github.com/opentidehq/opentide/issues/166)).

### Install

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.2] — 2026-09-11

Patch on the public 0.1.1 beta. Upgrade if you scaffold new detection repos, generate on an empty catalogue, or install agent skills.

### Added

- Generated GitHub, GitLab, and Azure pipelines from `opentide setup ci` now set `OPENTIDE_REPO_ROOT` for every job (`github.workspace`, `$CI_PROJECT_DIR`, `$(Build.SourcesDirectory)`) ([#51](https://github.com/opentidehq/opentide/issues/51)).
- `opentide setup env` writes `.env.example` with `OPENTIDE_REPO_ROOT` and adds `.env` to `.gitignore` ([#48](https://github.com/opentidehq/opentide/issues/48)).
- `opentide setup hooks` writes a local pre-commit hook that runs `opentide validate --strict` and installs it into `.git/hooks` when the path is a Git repository ([#49](https://github.com/opentidehq/opentide/issues/49)).
- `opentide lint` reports filename slug mismatches (`slugify(name)`) and missing recommended metadata. `--fix` renames files; `--strict` is the CI gate ([#108](https://github.com/opentidehq/opentide/issues/108)).
- `opentide migrate objects` dry-runs (default) or applies (`--apply`) moves from CoreTide `Configurations/` and `Objects/` paths into `.opentide/configurations/` and `objects/` ([#100](https://github.com/opentidehq/opentide/issues/100)).

### Changed

- `opentide setup skills` discovers the catalogue from the live [opentidehq/skills](https://github.com/opentidehq/skills) `manifest.json` and installs skill trees from that repository. The wheel no longer ships a stale catalogue snapshot or starter `SKILL.md` files. If GitHub is unreachable, discover / show / install fail with an actionable error instead of installing outdated copies ([#152](https://github.com/opentidehq/opentide/issues/152)).

### Fixed

- `opentide generate` on a freshly scaffolded repository no longer crashes in snippet generation (`AttributeError: SimpleNamespace has no attribute 'subschemas'`). Platform templates are resolved from `platform_templates` (with a legacy `subschemas` alias), missing template files are skipped, and an empty object catalogue is treated as a valid export rather than an error ([#153](https://github.com/opentidehq/opentide/issues/153)).

### Install

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.1] — 2026-09-11

Patch for the public 0.1.0 wheel. Upgrade if you installed from PyPI and hit `UnicodeDecodeError` on `validate` / `generate`, or if `opentide setup skills discover` started an install wizard.

### Fixed

- `opentide generate` and `opentide validate` no longer crash with `UnicodeDecodeError` when pip has compiled `__pycache__` next to bundled configuration TOMLs. Nested configuration directories load `*.toml` only (same class of fix as [#150](https://github.com/opentidehq/opentide/pull/150)).
- `opentide setup skills discover` and `show` are parsed as subcommands. A positional PATH on the skills group was consuming those names (and prompting for an install).
- Starter skill install (`opentide-detection-rule`, `detection-engineering`) falls back to the packaged skill trees when GitHub is unreachable.

### Install

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.0] — 2026-09-09

First public release of the DetectionOps engine as a **PyPI package**. This is a beta (`Development Status :: 4 - Beta`), not a 1.0. The old engine and companion repos are archived; pinned CoreTide submodules still resolve.

### Added

- Install with `pip install opentide` (Python 3.10–3.14). One wheel: CLI (`opentide`), MCP server (`opentide-mcp`), SDK (`from opentide import Opentide`), and seven platform adapters.
- `opentide setup` scaffolds a detection repository, CI (GitHub, GitLab, Azure DevOps), MCP client config, and agent skills.
- `opentide validate`, `generate`, `deploy`, and `document` as the operator surface. `--strict` is the CI gate.
- Query syntax validation on five platforms: Sentinel, Defender for Endpoint, Splunk, SentinelOne, Carbon Black Cloud. CrowdStrike and HarfangLab **deploy only** — the CLI and MCP report `supported: false` and do not fake a pass.
- Object model: threat → objective → rule, generated JSON Schema from the models, vocabularies as versioned TOML.
- Public companion repos: [specifications](https://github.com/opentidehq/specifications), [library](https://github.com/opentidehq/library), [explorer](https://github.com/opentidehq/explorer), [skills](https://github.com/opentidehq/skills). Docs: [opentide.org](https://opentide.org).

### Changed

- The engine is no longer consumed as a git submodule. Pin a package version instead of a SHA.
- Platform flags use `--platform` (not `--system`).

### Migration

There is no `opentide migrate`. Drop the CoreTide submodule, depend on this package, replace `Orchestration/` scripts with the CLI, set `OPENTIDE_REPO_ROOT`, run `opentide validate --strict`. Guide: [Usage → Migration](https://opentide.org/docs/usage/migration/).

### Stabilization

For four weeks after this release, work is bugs, docs, deployers, agent setup, and migration questions — not new platforms.

### Install

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

[Unreleased]: https://github.com/opentidehq/opentide/compare/v0.17.2...HEAD
[0.17.2]: https://github.com/opentidehq/opentide/releases/tag/v0.17.2
[0.17.1]: https://github.com/opentidehq/opentide/releases/tag/v0.17.1
[0.17.0]: https://github.com/opentidehq/opentide/releases/tag/v0.17.0
[0.16.1]: https://github.com/opentidehq/opentide/releases/tag/v0.16.1
[0.16.0]: https://github.com/opentidehq/opentide/releases/tag/v0.16.0
[0.15.0]: https://github.com/opentidehq/opentide/releases/tag/v0.15.0
[0.14.2]: https://github.com/opentidehq/opentide/releases/tag/v0.14.2
[0.14.1]: https://github.com/opentidehq/opentide/releases/tag/v0.14.1
[0.14.0]: https://github.com/opentidehq/opentide/releases/tag/v0.14.0
[0.13.0]: https://github.com/opentidehq/opentide/releases/tag/v0.13.0
[0.12.1]: https://github.com/opentidehq/opentide/releases/tag/v0.12.1
[0.12.0]: https://github.com/opentidehq/opentide/releases/tag/v0.12.0
[0.11.0]: https://github.com/opentidehq/opentide/releases/tag/v0.11.0
[0.10.0]: https://github.com/opentidehq/opentide/releases/tag/v0.10.0
[0.9.0]: https://github.com/opentidehq/opentide/releases/tag/v0.9.0
[0.8.2]: https://github.com/opentidehq/opentide/releases/tag/v0.8.2
[0.8.1]: https://github.com/opentidehq/opentide/releases/tag/v0.8.1
[0.8.0]: https://github.com/opentidehq/opentide/releases/tag/v0.8.0
[0.7.0]: https://github.com/opentidehq/opentide/releases/tag/v0.7.0
[0.6.4]: https://github.com/opentidehq/opentide/releases/tag/v0.6.4
[0.6.3]: https://github.com/opentidehq/opentide/releases/tag/v0.6.3
[0.6.2]: https://github.com/opentidehq/opentide/releases/tag/v0.6.2
[0.6.1]: https://github.com/opentidehq/opentide/releases/tag/v0.6.1
[0.6.0]: https://github.com/opentidehq/opentide/releases/tag/v0.6.0
[0.5.0]: https://github.com/opentidehq/opentide/releases/tag/v0.5.0
[0.4.0]: https://github.com/opentidehq/opentide/releases/tag/v0.4.0
[0.3.0]: https://github.com/opentidehq/opentide/releases/tag/v0.3.0
[0.2.1]: https://github.com/opentidehq/opentide/releases/tag/v0.2.1
[0.2.0]: https://github.com/opentidehq/opentide/releases/tag/v0.2.0
[0.1.8]: https://github.com/opentidehq/opentide/releases/tag/v0.1.8
[0.1.7]: https://github.com/opentidehq/opentide/releases/tag/v0.1.7
[0.1.6]: https://github.com/opentidehq/opentide/releases/tag/v0.1.6
[0.1.5]: https://github.com/opentidehq/opentide/releases/tag/v0.1.5
[0.1.4]: https://github.com/opentidehq/opentide/releases/tag/v0.1.4
[0.1.3]: https://github.com/opentidehq/opentide/releases/tag/v0.1.3
[0.1.2]: https://github.com/opentidehq/opentide/releases/tag/v0.1.2
[0.1.1]: https://github.com/opentidehq/opentide/releases/tag/v0.1.1
[0.1.0]: https://github.com/opentidehq/opentide/releases/tag/v0.1.0
