---
title: Supply chain
description: The Rust workspace's supply-chain and safety gates — cargo-deny, cargo audit, fuzzing and SBOMs — and why each says what it says.
---

# Supply chain

The Rust workspace is safe by policy, not by review (UC-X.1, [#843](https://github.com/opentidehq/opentide/issues/843)).
Each gate below runs in CI; the required ones are in `.github/AGENTS.md` ("Required checks").

| Gate | Where | When | Fails on |
|------|-------|------|----------|
| `cargo deny check` | ci.yml `deny` (Supply chain (cargo deny)) | every pull request and push | a licence not on the list, a RustSec advisory, a second version of a shipped crate, OpenSSL, a source other than crates.io |
| `cargo audit` | `rust-audit.yml` | daily | an advisory published since the last change; opens or comments on one issue |
| Fuzz smoke | ci.yml `fuzz-smoke` | every pull request and push | a panic or a timeout in 60 s of any target |
| Nightly fuzz | `engine-fuzz.yml` | nightly | a panic or a timeout in 10 minutes of any target; the input is uploaded |
| Unsafe policy | clippy, `xtask/tests/lint_policy.rs`, `xtask/tests/unsafe_listing.rs` | every pull request | `unsafe` outside two crates, a block without `// SAFETY:` or with two operations, a site missing from [Unsafe code](./unsafe.md) |
| SBOMs | `engine-release-build.yml` `sbom` (Engine release (dry run) / SBOMs) | every pull request (dry run) and every engine release | an SBOM that does not validate against CycloneDX 1.5 |

## deny.toml

**Licences.** The allow-list is `about.toml`'s, which cargo-about uses to render
`THIRD-PARTY-LICENSES.html` for each release: permissive licences and EUPL-1.2 itself, every one
compatible with distributing the engine under EUPL-1.2. `tests/test_ci/test_supply_chain.py` keeps
the two lists equal. Only what ships is checked: dev-dependencies (test tools) never leave a
checkout, and build dependencies (`cc`) run at build time and link nothing in, as `about.toml`'s
`ignore-build-dependencies` says.

**Advisories.** Vulnerable, unsound, unmaintained and yanked crates all fail. An exception is an
`[advisories] ignore` entry with its reason and its follow-up issue; `cargo audit` reads the same
list (`scripts/engine/audit.py ignores`). Today there is one:

| Advisory | Crate | Why it is excepted | Follow-up |
|----------|-------|--------------------|-----------|
| RUSTSEC-2024-0449 | `unsafe-libyaml` (unmaintained), through `serde_yaml` 0.9 | `opentide-tide` and `opentide-lsp` read Tide YAML with `serde_yaml`. Replacing it changes the YAML the engine accepts and the positions it reports, a behaviour change that needs a parity proof on every corpus | [#850](https://github.com/opentidehq/opentide/issues/850) |

**Bans.** A second version of a crate we ship fails (there is none today). Dev-dependencies are
left out, as cargo-deny leaves them out by default. These test tools duplicate a shipped crate,
reviewed and harmless because none of them ships: `trycmd`'s `toml_edit` 0.25 (with `winnow` 1,
`toml_datetime` 1 and `serde_spanned` 1) beside the engine's `toml` 0.8 and `toml_edit` 0.22;
`trycmd`'s `shlex` 1 beside `cc`'s `shlex` 2; `insta`'s `similar` 2 beside `snapbox`'s `similar` 3;
`tempfile`'s `bitflags` 2 beside `lsp-types`'s `bitflags` 1. `openssl-sys`, `openssl` and
`native-tls` are banned: TLS is rustls (plan D-8; per-tenant TLS settings are a §3 invariant), with
no system library to link on every wheel target. Wildcard version requirements fail.

**Sources.** crates.io only. A git dependency, or another registry's, fails until it is added to
`allow-git` or `allow-registry` with a comment saying why.

**fuzz/.** The fuzz targets are a workspace of their own with their own lock file, built on
nightly and never distributed. The `deny` job checks them for advisories, bans and sources with the
same `deny.toml`, and `--locked` keeps `fuzz/Cargo.lock` current. Their licences are not checked:
nothing in `fuzz/` ships.

**publishing/.** The crate that reserves the name `opentide` on crates.io
(`publishing/placeholders/crates/opentide`) has its own workspace and lock file and no
dependencies. It is published, so the `deny` job runs every check on it, licences included.

**Versions.** CI pins cargo-deny 0.20.2 (older releases cannot parse the advisory database's CVSS
4.0 entries) and cargo-audit 0.22.2. A newer release comes in a change of its own.

## Fuzzing

Eleven targets, one per input the engine reads from a user: the seven query languages, Tide YAML,
configuration TOML (`config`), the language server's sessions (`protocol`) and its raw input stream
(`framing`). `fuzz/README.md` lists their seeds and the targets later items add (`from_node`, the
CLI's argument parser, `opentide serve`'s reader). A crash becomes a regression test that fails
without the fix, and its input goes under `fuzz/regressions/<target>/`, where the normal test run
replays it on stable Rust.

## SBOMs

`scripts/engine/sbom.py generate` writes a CycloneDX 1.5 SBOM for each artifact, and `validate`
checks each against the schema (cyclonedx-python-lib, pinned) and for references that resolve:

| SBOM | Artifact | Made from |
|------|----------|-----------|
| `opentide-wheel.cdx.json` | the PyPI wheel this commit builds (its version from hatch-vcs; no wheel is built for the SBOM) | `uv export` (the Python dependencies, no dev group) and the crates compiled into `opentide._native` |
| `opentide-lsp.cdx.json` | the `opentide-lsp` binaries and the WASI build | cargo-cyclonedx, every target |
| `opentide-wasm.cdx.json` | the browser build | cargo-cyclonedx for wasm32-unknown-unknown, and the wasi-libc it links |
| `opentide-lsp-client.cdx.json`, `opentide-lsp-worker.cdx.json` | the npm packages | `npm sbom`, no dev dependencies |

The engine's four are assets of every engine release, listed in `SHA256SUMS` and covered by its
provenance attestation. The wheel's is generated and validated on every pull request and engine
release and uploaded as the `sbom-wheel` workflow artifact; it is not an engine asset (the wheel
ships on PyPI, and its `splunk-sdk` dependency is a name the oracle licence scan refuses in engine
assets). Attaching it to the PyPI GitHub Release is left to the release train (UC-5.5, #840). Rust SBOMs leave out build dependencies and name workspace crates by their path in
the repository, never the build machine's.
