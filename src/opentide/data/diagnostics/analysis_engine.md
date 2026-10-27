# analysis_engine

The analysis engine imports: the compiled `opentide-analysis` package behind `opentide validate query`, `opentide validate --deep` and `opentide lsp`.

Reported by `opentide doctor`, with the package's and the Rust engine's versions. Fails when the engine does not import (`engine_unavailable`).

## Example

```text
✗ The opentide analysis engine does not load: No module named 'opentide_analysis' · analysis_engine
  → pip install --force-reinstall opentide
```

## How to fix

Reinstall opentide with the command it prints. `opentide-analysis` is a dependency of opentide with a prebuilt wheel for each supported platform, so a failed import means a broken or mixed environment, or a platform with no wheel: see `opentide explain engine_unavailable`.
