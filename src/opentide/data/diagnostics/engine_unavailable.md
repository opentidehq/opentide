# engine_unavailable

The analysis engine (the Rust module compiled into opentide) does not load, so the command cannot check queries or serve the language server.

Exit 1, as `failure.code`, from `opentide validate query` (offline), `opentide lint` (its `queries` check) and `opentide lsp start`; an error issue of the `queries` check in `opentide validate`, whatever `--queries` says but `off`; and the `analysis_engine` check of `opentide doctor`. The check is never skipped: a missing engine fails the command.

## Example

```text
error: The opentide analysis engine does not load: cannot import name '_native' from 'opentide'
  help: reinstall opentide: pip install --force-reinstall opentide
```

## How to fix

The engine is part of the opentide package: each opentide wheel carries it, compiled for its platform, and there is nothing else to install. Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). When pip builds opentide from source instead of downloading a wheel, your platform has no prebuilt wheel and the build compiles the engine: install a Rust toolchain (https://rustup.rs) and reinstall, or report the platform at https://github.com/opentidehq/opentide/issues.
