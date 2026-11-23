# spl_unknown_command

The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command.

Reported by the analysis engine in an SPL query (`splunk`), at the place in the query. One edit from a known command (`stas` for `stats`), it is an error, a query the platform would reject: `opentide validate` (its `queries` check) and `opentide validate query` fail on it, and the help names the command. Further from every known command, it is a warning: a command an app on the search head provides (`decrypt`, `mispsearch`) looks the same, so `validate` passes and `opentide lint` (its `queries` check) reports it. An editor running `opentide lsp start` shows both.

opentide has no setting that declares a search head's app commands yet: neither `visibility.toml` nor `platforms/splunk.toml` takes a list of them. What `lint.toml` can do is change the warning's severity, under [Severity per code](lint.md#severity-per-code). That reaches the warning only: `[queries.codes]` changes the engine's warnings and notes, never an error, so a typo's error stays whatever `lint.toml` says. It changes `opentide lint` and `lint --strict`; the editor shows the engine's own severity.

## Example

```text
index=main sourcetype=misp | mispsearch value=evil.example | table value
```

## How to fix

When the name is a typo, correct it; the error cannot be lowered in `lint.toml`. When an app on the search head provides the command, the warning is expected and the query deploys as written. `opentide lint --strict` fails on a warning, so lower this one code and keep the check's other findings:

```toml
# .opentide/configurations/lint.toml
[queries.codes]
spl_unknown_command = "info"   # a note: --strict no longer fails on it ("off" drops it)
```

Or narrow the gate to the files a change touches (`opentide lint --strict --changed`).
