# vscode_settings

The workspace recommends the opentide VS Code extension (`opentidehq.opentide`) in `.vscode/extensions.json`, and `.vscode/settings.json` maps no object files to opentide's JSON schemas in `yaml.schemas`.

The extension's language server checks object files. A `yaml.schemas` mapping to `.opentide/schemas/opentide.schema.json`, which earlier releases wrote, makes a YAML extension report the same problems a second time.

Reported by `opentide doctor`. Warns when `settings.json` maps objects to opentide's schemas (the globs written as a string or as a list, as the YAML extension accepts both), when `extensions.json` does not recommend the extension, or when either file is not valid JSON; skipped when there is no `.vscode/extensions.json`.

## Example

```text
! .vscode/settings.json maps objects to .opentide/schemas/opentide.schema.json in yaml.schemas: a YAML extension would report what the opentide extension already does · vscode_settings
  → opentide setup vscode
```

## How to fix

Run `opentide setup vscode`. It recommends the extension and removes opentide's `yaml.schemas` entries, keeping your other settings.
