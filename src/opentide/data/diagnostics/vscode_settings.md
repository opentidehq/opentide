# vscode_settings

`.vscode/settings.json` maps the object folders to the generated schemas.

Reported by `opentide doctor`. Warns when it maps something else or is not valid JSON; skipped when the file does not exist.

## Example

```text
○ No .vscode/settings.json: editors get no schema completion · vscode_settings
  → opentide setup vscode
```

## How to fix

Run `opentide setup vscode`.
