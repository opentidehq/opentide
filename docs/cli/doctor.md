---
title: opentide doctor
description: One checklist for the installation, the workspace and its integrations, with a stable code, a status and a fix for every check.
---

# opentide doctor

Check the installation, the workspace and its integrations in one run. Each check prints a status, what it found and, when something needs doing, the command that fixes it.

```bash
opentide doctor
opentide doctor --offline
opentide doctor --live
opentide --json doctor
```

| Option | Purpose |
|--------|---------|
| `--offline` | Skip the network checks (`opentide_latest`, and `proxy` reachability) |
| `--live` | Reach each tenant whose credentials are set: the `connectivity` check. Refused with `--offline` (exit `2`) |

The [global options](./global-options.md) apply: `--repo` picks the workspace to check, and `--proxy` is the proxy the network checks use.

## Checks

Every check has a code that keeps its meaning. A check that repeats per platform or tenant carries a `subject` (`sentinel`, `sentinel/prod`).

| Code | Checks | `fail` | `warn` | `skip` |
|------|--------|--------|--------|--------|
| `python_version` | The running Python | Older than 3.10 | | |
| `opentide_version` | The installed opentide version | | | |
| `opentide_latest` | Whether PyPI has a newer release | | A newer release exists, or PyPI did not answer | `--offline` |
| `workspace` | Where the workspace is and why: `.opentide/` or `objects/`, found from the current directory or set by `--repo` / `OPENTIDE_REPO_ROOT` | Neither folder is there, or the folder `OPENTIDE_REPO_ROOT` or `OPENTIDE_TIDE_WORKSPACE` names does not exist or is not a directory (other commands exit `2` on it; a `--repo` naming no folder exits `2` here too) | `objects/` without `.opentide/` | |
| `git` | git is on `PATH` | | git is missing | |
| `git_repository` | The workspace is in a repository, and its default branch (`origin/HEAD`) | | Not a repository, or `origin/HEAD` is not set | |
| `configuration` | The workspace configuration TOMLs (`.opentide/configurations/`, and a parent instance's) load | One does not parse: the message names the file and line | | |
| `templates_fresh` | Every template this version generates exists and matches what it would write, with the metadata keys `lint.toml` requires rendered live as `generate templates` does | | A template is missing or differs, or `lint.toml` holds a value opentide rejects | |
| `schemas_fresh` | Every schema this version generates exists and matches what `generate schemas` would write now: the schemas follow the workspace's objects (the names a rule's `detection_model` offers), visibility, statuses and enabled platforms, so a changed object or configuration makes them stale too. Line endings and a byte order mark do not count. When the workspace does not open, only the presence of each schema is checked, and the message says so | | A schema is missing or differs | |
| `lsp_catalog` | No catalog is committed, or the committed copy (`.opentide/lsp/catalogs/generated/`, which no program reads: the language server generates its own) comes from this opentide version and matches what `generate schemas` would write now (`fields.json`, `deprecations.json`) | | The committed copy does not parse, comes from another version, is missing a file or differs | No workspace |
| `platforms_enabled` | Which platforms are enabled | | None is | |
| `platform_sdk` | Each enabled platform's SDK imports | It does not | | |
| `analysis_engine` | The analysis engine compiled into opentide loads, and the language-server version it was built from: what `validate`, `validate query`, `lint` and `opentide lsp` run | It does not | | |
| `credentials` | Per configured tenant of an enabled platform, whether every `$VARIABLE` its setup names is set | | A variable is unset or empty | The platform has no tenant |
| `connectivity` | With `--live`, each tenant whose credential variables are all set can be reached with them ([Connectivity](#connectivity)) | A tenant with its credentials set refuses them or does not answer | | A tenant without its credentials, a platform with no read-only request, or no `--live` |
| `proxy` | The proxy opentide's requests go through accepts a connection: the one an `https://` request uses, chosen as every command chooses it ([proxy precedence](../usage/configuration.md#proxy)), else the `http://` one | It does not | | No proxy is set, or `--offline` |
| `vscode_settings` | `.vscode/extensions.json` recommends the opentide VS Code extension (`opentidehq.opentide`), and `.vscode/settings.json` maps no object files to opentide's schemas in `yaml.schemas` | | `settings.json` maps objects to opentide's schemas (a YAML extension would report them a second time), `extensions.json` does not recommend the extension, or either is not valid JSON | No `.vscode/extensions.json`, or it lists the extension under `unwantedRecommendations` |
| `vscode_snippets` | The snippet file `opentide generate snippets` writes exists | | | It does not |
| `mcp_config` | An MCP configuration from `opentide setup mcp` runs `opentide mcp start`, with the command on `PATH`; or `.vscode/extensions.json` recommends the opentide extension, which provides the server to VS Code (with both, the message says so) | | No file has such a server, or the command is not on `PATH` | No configuration, and the extension is not recommended |

`credentials` only reports: a variable that is unset is a `warn`, never a `fail`, because most people hold no tenant secret locally (the CI runner does). Its message names the tenant and the variables.

`skip` marks an optional integration that is not set up, or a check that did not run. It never changes the exit code.

`doctor` runs neither `python_version` nor `platform_sdk`, which opentide 0.28.1 listed: the command line does not run on Python, and its platforms are its own connectors, which import no Python SDK. Their rows are left out of the checklist, `checks` and the summary counts.

When `configuration` fails, the checks that read the configuration (`templates_fresh`, `schemas_fresh`, `platforms_enabled`, `platform_sdk`, `credentials`, `connectivity`, `vscode_settings`, `vscode_snippets`) are skipped with `Not checked: the configuration does not load`, so one broken file is reported once, where it is.

`mcp_config` passes when at least one host runs opentide. A file that lists only other servers, such as a Claude Code `.mcp.json`, is named in the message but is not a warning.

A check that raises an unexpected error fails under its own codes with `The check itself failed (<exception type>)`. The exception's text is left out, since it can quote what the check was reading; `--debug` logs the traceback.

### Secrets

`doctor` never prints a secret. `credentials` names the variables a tenant's setup refers to and whether each is set, never a value, and never a value written into the TOML. A proxy is shown as `scheme://host:port`, without its user and password, even when the password holds an unencoded `@` or `:`. A password with an unencoded `/`, `#`, `?` or `\` cannot be told apart from the host (a URL parser would read part of it as the host), so such a URL is not shown at all: it is `<unparseable proxy URL>`, the `proxy` check fails with ``The proxy URL cannot be parsed: an `@` follows a `/`, `?`, `#` or `\` …``, and every command refuses it. Percent-encode those characters (`%2F`, `%23`, `%3F`, `%5C`, `%40` for `@`).

### In the VS Code extension

The extension runs the WASI build of opentide, which cannot start another program. There the `git` check passes when git is on `PATH` and says `git found; version not checked (no subprocesses under WASI)`, and `git_repository` reads the repository itself (its top level, origin's default branch, the current branch), so it reports what it reports elsewhere. The network checks fail with "this command needs the network" unless `--offline` skips them.

### Connectivity

`credentials` says whether a tenant's variables are set, not whether the tenant answers with them. `opentide doctor --live` adds that, as the `connectivity` check, one line per tenant (`subject` `sentinel/prod`). It reads the same list `credentials` does, so it only reaches a tenant `credentials` found ready.

For each tenant whose credential variables are all set, `doctor --live` opens the tenant the way [`deploy`](./deploy.md) does: the credentials resolved from the environment, then the platform's sign-in where it has one (Microsoft Entra ID for Sentinel and Microsoft Defender, OAuth2 for CrowdStrike, Exabeam and Google SecOps). It then makes **one read-only request** that needs the credentials. It writes nothing to the tenant.

| Outcome | `status` | Message |
|---------|----------|---------|
| The sign-in and the request succeed | `pass` | `sentinel/prod: reached with its credentials` |
| A variable the tenant's setup names is unset | `skip` | `sentinel/prod: not reached, credentials not set: AZURE_CLIENT_SECRET`. The tenant is not contacted |
| The tenant refuses the credentials (HTTP 401 or 403, or a sign-in the platform's token endpoint refuses with 400, 401 or 403) | `fail` | `sentinel/prod: could not be reached (authentication_failed): …`. No answer body is quoted |
| A token endpoint answers 429 or 500, or a gateway's 502, 503 or 504 | `fail` | `tenant_refused` or `tenant_gateway`, not `authentication_failed`: the credentials are not blamed for a rate limit or an outage (CrowdStrike) |
| The tenant does not answer, or the connection fails | `fail` | The error's code (`tenant_unreachable`, `tenant_timeout`, `tenant_gateway`) and message, naming the tenant and its address (`scheme://host:port`, never a path or a credential) |
| The tenant answers anything else that is not a success | `fail` | `tenant_refused`, with the HTTP status |
| The platform has no read-only request opentide can make (Bitdefender) | `skip` | `…: not supported by doctor --live: <platform> has no read-only request to make`. Checked before the variables, so it is never told to set one |
| Google SecOps names no `credentials`, `GOOGLE_APPLICATION_CREDENTIALS` is unset, there is no gcloud credentials file and the metadata server does not answer | `skip` | `…: not reached, … names no credentials and none are set up`. `credentials` reports it as a `warn`. A `credentials` value or `GOOGLE_APPLICATION_CREDENTIALS` that is set but unusable still fails |
| No `--live` | `skip` | `Not checked: --live not set` |

Ctrl-C stops a request in flight at once, as it does for `deploy`; the tenants not yet reached are `skip`, and the run ends interrupted (exit `130`).

A failing tenant fails the check, and `doctor` exits `1`. A tenant that is skipped never changes the exit code. A platform with no tenant, or none enabled, is one `skip` line.

The requests go through the tenant's own HTTP client, as a deploy's do: its `ssl` setting, CA bundle, the run's `--proxy` and `no_proxy`, and the platform's timeout and retries (Sentinel's ARM session 60 s, Elastic 30 s, 120 s otherwise). The one exception is Google's metadata server, asked only for a Google SecOps tenant that names no `credentials` and finds none locally: it is asked **direct**, never through the proxy, and within 3 seconds, as Google's own libraries ask it. Only an answer that carries `Metadata-Flavor: Google` is a metadata server's; a transport error, a timeout or any other answer (a proxy's 502, a resolver's page) means no credentials, and the tenant is skipped. A tenant that never answers is therefore reported after its timeout, not after the 3 seconds the `opentide_latest` and `proxy` checks wait.

The sign-in and the request for each platform:

| Platform | Sign-in | Read-only request |
|----------|---------|-------------------|
| `sentinel` | Entra ID client credentials | `GET` the workspace's analytics rules (first page) |
| `microsoft_defender` | Entra ID client credentials | `GET` the first page of custom detection rules |
| `splunk` | None: the token | `GET /services/server/info` |
| `sentinel_one` | None: the API token | `GET` one STAR rule (`cloud-detection/rules?limit=1`) |
| `crowdstrike` | OAuth2 token | `GET` one correlation rule id (`limit=1`) |
| `harfanglab` | None: the API token | `GET` one Sigma rule (`limit=1`) |
| `carbon_black_cloud` | None: the API token | `GET` the organisation's watchlists |
| `elastic` | None: the API key | `GET` one detection rule from Kibana (`per_page=1`) |
| `sysdig` | None: the API token | `GET /api/v2/policies` |
| `graylog` | None: the API token | `GET /api/system` |
| `exabeam` | OAuth2 token | `GET` the correlation rules named `opentide` |
| `google_secops` | Google OAuth2 token | `GET` one rule of the instance (`pageSize=1`) |
| `datadog` | None: the API and application keys | `GET` one detection rule (`page[size]=1`) |
| `bitdefender` | None | Not checked: the connector only sends rule writes, so there is no read-only request to make (`skip`) |

`--live` and `--offline` contradict each other: together they exit `2` (`usage_error`).

### Network

`opentide_latest` asks `https://pypi.org/pypi/opentide/json`, and `proxy` opens a TCP connection to the proxy, each with a 3-second timeout. Both use the proxy every command would use, and honour `no_proxy` (else `NO_PROXY`); when it sends PyPI direct the `proxy` check says `pypi.org bypasses it (NO_PROXY)`. Offline, `opentide_latest` is a warning, not a failure; `--offline` skips both.

A failed check says what went wrong: for `opentide_latest`, the HTTP client's error (`Cannot reach pypi tenant 'pypi.org' at …: …`), PyPI's status (`PyPI answered HTTP 503`) or an answer without a version; for `proxy`, the operating system's error (`Connection refused (os error 111)`) or `cannot resolve <host>: …`. Versions are ordered as PEP 440 orders them.

## Exit codes

| Exit | When |
|-----:|------|
| `0` | No check failed. Warnings and skips do not change it |
| `1` | At least one check failed, a tenant `--live` could not reach included; `failure.code` is `doctor_checks_failed` |
| `2` | A usage error, such as `--live` with `--offline` |

## Output

One line per check, its fix under it, then the outcome line. `✓` is a pass, `!` a warning, `✗` a failure and `○` a skip (`ok`, `!`, `x` and `o` on a stream that cannot encode them). Paths are relative to the current directory, `./` being the directory itself. A tutorial workspace with no tenant, editor settings or MCP configuration yet, outside git, run from inside the workspace, prints:

```text illustrative
✓ Python 3.13.16 · python_version
✓ opentide 0.18.0 · opentide_version
○ Not checked: --offline · opentide_latest
✓ Workspace ./ has .opentide/ (found from the current directory) · workspace
✓ git 2.43.0 · git
! ./ is not in a git repository · git_repository
  → git init ./
✓ 1 configuration file loads · configuration
✓ Templates match the installed version · templates_fresh
✓ Schemas match the installed version (6) · schemas_fresh
✓ Enabled: sentinel · platforms_enabled
✓ sentinel: azure.identity, azure.monitor.query, requests import · platform_sdk
○ sentinel: no tenant configured · credentials
  → add a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml
○ No proxy set (--proxy, OPENTIDE_PROXY, https_proxy, http_proxy, all_proxy) · proxy
○ No .vscode/extensions.json: VS Code does not suggest opentidehq.opentide · vscode_settings
  → code --install-extension opentidehq.opentide (or opentide setup vscode, to recommend it to the team)
○ No snippets at .vscode/model-templates.code-snippets · vscode_snippets
  → opentide generate snippets
○ No MCP configuration: agents in editors cannot call opentide tools · mcp_config
  → opentide setup mcp --vscode (or --cursor, --claude-code, --generic)
! 1 warning · 9 passed, 6 skipped
```

With `--quiet`, only the outcome line prints.

### JSON

`--json` adds `checks` to the [envelope](./json-output.md), in the order above:

```json illustrative
{
  "checks": [
    {"code": "python_version", "status": "pass", "message": "Python 3.13.16", "fix": null, "subject": null},
    {"code": "credentials", "status": "warn", "message": "sentinel/prod: 1 of 2 variables unset: AZURE_CLIENT_SECRET", "fix": "set AZURE_CLIENT_SECRET in the environment (or a .env file you load)", "subject": "sentinel/prod"}
  ],
  "summary": {"checks": 15, "passed": 9, "warnings": 2, "failed": 0, "skipped": 4}
}
```

`status` is `pass`, `warn`, `fail` or `skip`; `fix` is `null` when there is nothing to do.

## Source

`crates/opentide-cli/src/commands/doctor.rs`, `crates/opentide-cli/src/commands/doctor_network.rs`
