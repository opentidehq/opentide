---
title: opentide doctor
description: One checklist for the installation, the workspace and its integrations, with a stable code, a status and a fix for every check.
---

# opentide doctor

Check the installation, the workspace and its integrations in one run. Each check prints a status, what it found and, when something needs doing, the command that fixes it.

```bash
opentide doctor
opentide doctor --offline
opentide --json doctor
```

| Option | Purpose |
|--------|---------|
| `--offline` | Skip the network checks (`opentide_latest`, and `proxy` reachability) |

The [global options](./global-options.md) apply: `--repo` picks the workspace to check, and `--proxy` is the proxy the network checks use.

## Checks

Every check has a code that keeps its meaning. A check that repeats per platform or tenant carries a `subject` (`sentinel`, `sentinel/prod`).

| Code | Checks | `fail` | `warn` | `skip` |
|------|--------|--------|--------|--------|
| `python_version` | The running Python | Older than 3.10 | | |
| `opentide_version` | The installed opentide version | | | |
| `opentide_latest` | Whether PyPI has a newer release | | A newer release exists, or PyPI did not answer | `--offline` |
| `workspace` | Where the workspace is and why: `.opentide/` or `objects/`, found from the current directory or set by `--repo` / `OPENTIDE_REPO_ROOT` | Neither folder is there | `objects/` without `.opentide/` | |
| `git` | git is on `PATH` | | git is missing | |
| `git_repository` | The workspace is in a repository, and its default branch (`origin/HEAD`) | | Not a repository, or `origin/HEAD` is not set | |
| `configuration` | The workspace configuration TOMLs (`.opentide/configurations/`, and a parent instance's) load | One does not parse: the message names the file and line | | |
| `templates_fresh` | Every template this version generates exists and matches what it would write | | A template is missing or differs | |
| `schemas_fresh` | Every schema this version generates exists | | A schema is missing | |
| `lsp_catalog` | The language server's catalogs `opentide generate schemas` writes (`.opentide/lsp/catalogs/generated/`) exist and come from this opentide version | | They are missing, do not parse, or come from another version | No workspace |
| `platforms_enabled` | Which platforms are enabled | | None is | |
| `platform_sdk` | Each enabled platform's SDK imports | It does not | | |
| `analysis_engine` | The analysis engine compiled into opentide loads, and the language-server version it was built from: what `validate query`, `validate --deep` and `opentide lsp` run | It does not | | |
| `credentials` | Per configured tenant of an enabled platform, whether every `$VARIABLE` its setup names is set | | A variable is unset or empty | The platform has no tenant |
| `proxy` | The proxy in `--proxy`, `OPENTIDE_PROXY` or `HTTPS_PROXY` accepts a connection | It does not | | No proxy is set, or `--offline` |
| `vscode_settings` | `.vscode/settings.json` maps the object folders to the generated schemas | | It maps something else or is not valid JSON | The file does not exist |
| `vscode_snippets` | The snippet file `opentide generate snippets` writes exists | | | It does not |
| `mcp_config` | An MCP configuration from `opentide setup mcp` runs `opentide mcp start`, with the command on `PATH` | | No file has such a server, or the command is not on `PATH` | No configuration |

`skip` marks an optional integration that is not set up, or a check that did not run. It never changes the exit code.

When `configuration` fails, the checks that read the configuration (`templates_fresh`, `schemas_fresh`, `platforms_enabled`, `platform_sdk`, `credentials`, `vscode_settings`, `vscode_snippets`) are skipped with `Not checked: the configuration does not load`, so one broken file is reported once, where it is.

`mcp_config` passes when at least one host runs opentide. A file that lists only other servers, such as a Claude Code `.mcp.json`, is named in the message but is not a warning.

A check that raises an unexpected error fails under its own codes with `The check itself failed (<exception type>)`. The exception's text is left out, since it can quote what the check was reading; `--debug` logs the traceback.

### Secrets

`doctor` never prints a secret. `credentials` names the variables a tenant's setup refers to and whether each is set, never a value, and never a value written into the TOML. A proxy is shown as `scheme://host:port`, without its user and password, even when the password holds an unencoded `/`, `#`, `?` or `@`; a URL that cannot be parsed is shown as `<unparseable proxy URL>`.

### Network

`opentide_latest` asks `https://pypi.org/pypi/opentide/json`, and `proxy` opens a TCP connection to the proxy, each with a 3-second timeout. Both go through `--proxy` and honour `NO_PROXY`. Offline, `opentide_latest` is a warning, not a failure; `--offline` skips both.

## Exit codes

| Exit | When |
|-----:|------|
| `0` | No check failed. Warnings and skips do not change it |
| `1` | At least one check failed; `failure.code` is `doctor_checks_failed` |

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
✓ Every schema this version generates is present (6) · schemas_fresh
✓ Enabled: sentinel · platforms_enabled
✓ sentinel: azure.identity, azure.monitor.query, requests import · platform_sdk
○ sentinel: no tenant configured · credentials
  → add a [[tenants]] entry in .opentide/configurations/platforms/sentinel.toml
○ No proxy set (--proxy, HTTPS_PROXY) · proxy
○ No .vscode/settings.json: editors get no schema completion · vscode_settings
  → opentide setup vscode
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

`src/opentide/cli/commands/doctor.py`, `src/opentide/cli/services/doctor.py`
