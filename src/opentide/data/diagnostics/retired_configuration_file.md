# retired_configuration_file

A file or folder under `.opentide/configurations/` that opentide does not read.

Severity: error. Reported by every command that reads the configuration (`validate`, `deploy`, `generate`, …), which then stops with exit 1 and `failure.code` `retired_configuration_file`, for these entries of the workspace's (or the parent instance's) `.opentide/configurations/`:

| Entry | What replaces it |
|-------|------------------|
| `global.toml` | `paths.toml`: workspace paths and artifact names |
| `schema.toml` | Nothing: template defaults are not configurable, and vocabularies are not extended locally |
| `systems/` | `platforms/<platform>.toml` |

Loading such a file and ignoring it would leave the workspace believing it is configured by settings that have no effect.

## Example

```text
.opentide/configurations/
├── global.toml
└── systems/
    └── splunk.toml
```

## How to fix

Move the settings you need into the file the diagnostic names (`paths.toml`, `platforms/<platform>.toml`), in its current format, then delete the retired file or folder. `opentide validate --check configuration` then checks what you moved.
