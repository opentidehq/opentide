# MCP Server

Start the detection engineering MCP server:

```bash
pip install "opentide[mcp]"
opentide-mcp
```

VS Code configuration:

```json
{ "mcpServers": { "opentide": { "command": "opentide-mcp" } } }
```

Tools: `search`, `get_chaining`, `coverage`, `validate_rule`, `validate_query`, `run_query`, `deploy_rule`, `deployment_status`.

Resources: catalogue index, rules, threats, objectives, schemas, templates, vocabularies, platforms.
