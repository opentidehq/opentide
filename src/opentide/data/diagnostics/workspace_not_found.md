# workspace_not_found

`opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there. Or the MCP server was started in an Agent Plugin's directory, which is not a workspace, and nothing named one.

Exit 1, as `failure.code`. `new` writes only into a workspace, the folder `--repo` names or the one discovery finds, so a stray run in your home directory cannot make it a workspace that every folder below it would discover.

The MCP server reports it as an error from every tool and resource that reads the catalogue (`search`, `validation_report`, `deploy_rule`, `opentide://rules`, ...). An Agent Plugins client starts a plugin's server in the plugin's directory; the server never serves that directory, such as the opentidehq/skills package, as the catalogue. `explain` and offline `validate_query` still answer.

## Example

```text
cd ~ && opentide new threat --name "Credential Dumping"
```

## How to fix

Run it from inside your detection repository, or pass `--repo path/to/detections`. To start a new one, run `opentide setup`. `opentide doctor` applies the same test as its `workspace` check.

For the MCP server, set `OPENTIDE_REPO_ROOT` to the detection repository in the host's settings for the `opentide` server, or start the host from inside the repository, so its `PWD` (or Claude Code's `CLAUDE_PROJECT_DIR`) lies in it. `opentide setup mcp`, run in the repository, writes the host's MCP file with the project directory filled in.
