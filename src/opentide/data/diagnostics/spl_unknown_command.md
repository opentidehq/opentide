# spl_unknown_command

The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command.

Reported by the analysis engine in an SPL query (`splunk`), at the place in the query. One edit from a known command (`stas` for `stats`), it is an error, a query the platform would reject: `opentide validate` (its `queries` check) and `opentide validate query` fail on it, and the help names the command. Further from every known command, it is a warning: a command an app on the search head provides (`decrypt`, `mispsearch`) looks the same, so `validate` passes and `opentide lint` (its `queries` check) reports it. An editor running `opentide lsp start` shows both.

opentide has no setting that declares a search head's app commands yet: neither `visibility.toml` nor `platforms/splunk.toml` takes a list of them, so the warning stays for every query that uses one. Through 0.20.1 the CLI's message asked to declare the command, which nothing could do; an editor running `opentide lsp start` still shows the engine's own wording, which does.

## Example

```text
index=main sourcetype=misp | mispsearch value=evil.example | table value
```

## How to fix

When the name is a typo, correct it. When an app on the search head provides the command, the warning is expected and the query deploys as written. `opentide lint --strict` fails on any finding, so a catalogue that gates on it and uses app commands narrows the gate to the files a change touches (`opentide lint --strict --changed`), or turns the `queries` check off in `lint.toml` (`[queries] enabled = false`), which drops every other query style finding too.
