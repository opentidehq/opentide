# engine_unavailable

The analysis engine (the `opentide-analysis` package) does not import, so the command cannot check queries or serve the language server.

Exit 1, as `failure.code`, from `opentide validate query` (offline), `opentide lsp check` and `opentide lsp start`; an error issue of the `queries` check in `opentide validate --deep`; and the `analysis_engine` check of `opentide doctor`. The check is never skipped: a missing engine fails the command.

## Example

```text
error: The opentide analysis engine does not load: No module named 'opentide_analysis._native'
  help: reinstall opentide: pip install --force-reinstall opentide
```

## How to fix

The engine is a dependency of opentide, compiled for each platform: `pip install opentide` installs it, and there is no extra to add. Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). When pip builds `opentide-analysis` from source instead of downloading a wheel, your platform has no prebuilt wheel: install a Rust toolchain (https://rustup.rs) and reinstall, or report the platform at https://github.com/opentidehq/opentide/issues.
