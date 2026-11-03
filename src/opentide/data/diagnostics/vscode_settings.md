# vscode_settings

`.vscode/settings.json` maps the object folders to the generated schemas.

Reported by `opentide doctor`. The object glob may be a string (`"objects/**/*.yaml"`) or a list that holds it, among other globs (`["objects/**/*.yaml", "hunts/**/*.yaml"]`), as the YAML extension accepts both. Warns when it maps something else or is not valid JSON; skipped when the file does not exist.

## Example

```text
○ No .vscode/settings.json: editors get no schema completion · vscode_settings
  → opentide setup vscode
```

## How to fix

Run `opentide setup vscode`.
