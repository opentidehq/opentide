# Sources

Copied from [opentidehq/specifications](https://github.com/opentidehq/specifications) at `1255063db857571afbc1ff5687a503ee34abb228` (RFC 0021, specifications#102), unchanged:

- `microsoft-defender.yaml`, `microsoft-defender-complete.yaml`: `fixtures/platforms/`
- `rule-microsoft-defender*.api.json`, `graph-beta-properties.json`: `fixtures/platforms/microsoft-defender/`
- `invalid/`: `fixtures/invalid/rule-microsoft-defender-*.yaml`

The tests compare the compiled bodies with the `.api.json` goldens byte for byte, check the invalid rules' codes, and check beta coverage against the property snapshot.
