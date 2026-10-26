# configuration

The workspace configuration files under `.opentide/configurations/` load.

Reported by `opentide doctor`. Fails when one does not parse; the message names the file and line. The checks that read the configuration are then skipped, so the broken file is reported once.

## Example

```text
✗ .opentide/configurations/platforms/sentinel.toml is not valid TOML: Expected '=' after a key (at line 4, column 9) · configuration
```

## How to fix

Fix the TOML at the line it names. `opentide explain config_parse` shows the common mistakes.
