# opentide-yara — agent guide

The YARA engine (HarfangLab `configurations.harfanglab.yara`, Bitdefender GravityZone
`configurations.bitdefender.yara`, `.yar` and `.yara` files): YARA-X 1.x is the language (#1225),
so what YARA-X refuses is an error. A signature goes through the platform profile's text checks,
VirusTotal's `yara-x-parser` (its errors classified in `errors.rs`), then `check::Checker` (the
symbol table, types, the module catalogue and the profile's portability check,
`yara_x_only_syntax`). `.yar` files are formatted with `yara-x-fmt`. Catalogs: `data/catalogs/yara/`
(the module catalogue, written by `cargo xtask codegen` from YARA-X's reflection of its modules,
`scripts/engine/yara-modules`). Design, and each code with its source and its test:
`docs/engine/YARA.md`.

## Place

foundation, tier 2: depends on opentide-core, -dataset and -highlight, and on `yara-x-parser` and
`yara-x-fmt`; on no other query engine (`xtask/layers.toml`). Used by opentide-tide, -analysis and
-cli.

## Invariants

- I/O-free: no `std::fs` in `src/`; the catalogs are embedded (`opentide_dataset::text!`) and
  parsed once.
- The `yara-x` compiler crate is never a dependency: it brings wasmtime and breaks the WASI build.
  It is an oracle only (`scripts/engine/oracles`, the `yara-x` wheel), as is `yara-python`;
  `scripts/engine/ci-oracle.sh` fails if a shipped manifest depends on either.
- Findings are `opentide_core::Diagnostic`s with codes from `opentide_core::codes`, YARA-X's own
  message kept.
- A profile that does not take a YARA-X-only construct refuses it (`yara_x_only_syntax`); libyara's
  quirks that YARA-X refuses are errors, not warnings.

## Test

```bash
cargo nextest run --profile fast -p opentide-yara
```

`tests/conformance.rs` holds the engine to the YARA-X verdicts recorded in
`crates/testdata/conformance/yara/cases.json` (`scripts/engine/sync_yara_conformance.py`), with the
exceptions of `crates/testdata/oracles/exceptions.toml`; `tests/codes.rs` and `tests/document.rs`
the codes and the editor features; `tests/external_corpus.rs` the public rules (left out of the
fast profile). The live `yara-x` wheel runs in `scripts/engine/ci-oracle.sh` (`oracle.yml`).

## Do not

- Add the `yara-x` compiler crate, or `yara-python`, to any shipped manifest.
- Share code, catalogue or grammar with `opentide-yaral`: YARA-L shares only the name.

## Every engine crate

- Lints, tests, snapshots and the layer rule: [`crates/AGENTS.md`](../AGENTS.md); the Rust
  conventions (errors, `OnceLock` catalogs, dependencies): the
  [rust-engine](../../.agents/skills/rust-engine/SKILL.md) skill; the catalogs and the conformance
  corpora: the [catalogs](../../.agents/skills/catalogs/SKILL.md) skill.
