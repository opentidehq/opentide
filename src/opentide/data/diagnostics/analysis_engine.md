# analysis_engine

The analysis engine loads: the Rust module compiled into opentide (`opentide._native`) behind the `queries` checks of `opentide validate` and `opentide lint`, `opentide validate query` and `opentide lsp`.

Reported by `opentide doctor`, with the version of the language-server crates compiled in. Fails when the engine does not load (`engine_unavailable`).

## Example

```text
✗ The opentide analysis engine does not load: cannot import name '_native' from 'opentide' · analysis_engine
  → pip install --force-reinstall opentide
```

## How to fix

Reinstall opentide with the command it prints. The engine is part of the opentide package, in the wheel for each supported platform, so a failed import means a broken or mixed environment, or an install from source that did not compile it: see `opentide explain engine_unavailable`.
