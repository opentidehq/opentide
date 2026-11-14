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
| `cargo audit` (every `Cargo.lock`) | `rust-audit.yml` | daily | an advisory published since the last change; opens or comments on one issue |
| Fuzz smoke | ci.yml `fuzz-smoke` | the nightly set (nightly and Run workflow) | a panic or a timeout in 60 s of any target |
| Nightly fuzz | `engine-fuzz.yml` | nightly | a panic or a timeout in 10 minutes of any target; the input is uploaded |
| Unsafe policy | clippy, `xtask/tests/lint_policy.rs`, `xtask/tests/unsafe_listing.rs` | every pull request | `unsafe` outside two crates, a block without `// SAFETY:` or with two operations, a site missing from [Unsafe code](./unsafe.md) |
| SBOMs | `engine-release-build.yml` `sbom` (Engine release (dry run) / SBOMs) | the dry run in the nightly set (nightly and Run workflow); every release | an SBOM that does not validate against CycloneDX 1.5 |

## deny.toml

**Licences.** The allow-list is `about.toml`'s, which cargo-about uses to render
`THIRD-PARTY-LICENSES.html` for each release: permissive licences and EUPL-1.2 itself,
every one compatible with distributing the engine under EUPL-1.2. `tests/test_ci/test_supply_chain.py` keeps
the two lists equal, and keeps both free of per-crate exceptions.

*Policy (maintainer decision, #952).* A permissive open-source licence (MIT, MIT-0, Apache-2.0,
BSD-2/3-Clause, ISC, Zlib, CC0-1.0, CDLA-Permissive-2.0, Unicode-3.0, BSL-1.0 and the like) goes on
the global list in both files when a new dependency brings it, for every crate, never as a
`[licenses] exceptions` entry or an `about.toml` crate table, and needs no maintainer. A copyleft
licence (GPL, LGPL, MPL, AGPL, EPL) or one that restricts the field of use needs a maintainer's
decision before it is added anywhere. Only what ships is checked: dev-dependencies (test tools) never leave a
checkout, and build dependencies (`cc`) run at build time and link nothing in, as `about.toml`'s
`ignore-build-dependencies` says.

**Advisories.** Vulnerable, unsound, unmaintained and yanked crates all fail. An exception is an
`[advisories] ignore` entry with its reason and its follow-up issue; `cargo audit` reads the same
list (`scripts/engine/audit.py ignores`). Today there is none. The last one, RUSTSEC-2024-0449
(`unsafe-libyaml`, unmaintained, through `serde_yaml` 0.9), went when the engine moved its Tide
YAML onto the node tree every crate reads YAML with, `opentide_core::node` (saphyr, YAML 1.2)
([#850](https://github.com/opentidehq/opentide/issues/850)).

**Bans.** A second version of a crate we ship fails, unless `[bans] skip` lists it with its reason. There is one: `syn` 2, which `garde_derive` 0.23 needs (`opentide-schema`'s validation derive, plan D-2; no garde release uses `syn` 3 yet), beside the `syn` 3 of every other proc macro. Dev-dependencies are
left out, as cargo-deny leaves them out by default. These test tools duplicate a shipped crate,
reviewed and harmless because none of them ships: `trycmd`'s `toml_edit` 0.25 (with `winnow` 1,
`toml_datetime` 1 and `serde_spanned` 1) beside the engine's `toml` 0.8 and `toml_edit` 0.22;
`trycmd`'s `shlex` 1 beside `cc`'s `shlex` 2; `insta`'s `similar` 2 beside `snapbox`'s `similar` 3
(the shipped `opentide-workspace`, for `validate --fix --dry-run`'s diff, and xtask use `similar` 2,
so the shipped graph holds one `similar`);
`tempfile`'s `bitflags` 2 beside `lsp-types`'s `bitflags` 1. `trybuild`'s `toml` 1 (with its `toml_*` crates) beside the engine's `toml` 0.8, for `opentide-schema`'s compile-fail tests. xtask (tooling, never shipped) uses `rustix` (the golden runner's pseudo-terminals) and `tempfile` at run time, and `opentide-workspace` uses `tempfile` (`validate --fix`'s writes) and `notify` (`--watch`), whose `inotify` brings `bitflags` 2 while `kqueue-sys` (BSD, macOS) keeps `bitflags` 1, and `opentide-cli`'s setup wizard prompts with `inquire` on `crossterm`, both on `bitflags` 2: `skip` names `bitflags@2.13.2` with that reason. The wizard's pseudo-terminal test drives the CLI with wezterm's `portable-pty` (a dev-dependency), which brings `nix` 0.28 beside the shipped `nix` 0.31. xtask's schema comparison (`cargo xtask codegen --check`, UC-1.8b) validates with the `jsonschema` crate, which brings `fancy-regex` 0.20, `fluent-uri` 0.4, `getrandom` 0.3 and `r-efi` 5 beside the shipped crates' versions: `skip` names each, with that reason; and `borrow-or-share` under MIT-0, which the global list allows. The connectors' HTTP client (UC-4.1, #831: reqwest 0.13 on rustls with ring, the one HTTP client of the workspace) brings ring's `getrandom` 0.2 and, on Windows, `windows-sys` 0.52, and the recorded-HTTP harness (`opentide-cassette`, never shipped) wiremock's `base64` 0.22: `skip` names each with that reason. The Google SecOps connector (UC-4) signs a service-account JWT with `jsonwebtoken` 9 on ring, which ships `pem` 3, while `opentide-cassette`'s `rcgen` (its test certificates, never shipped) brings `pem` 4: `skip` names `pem@4.0.0` with that reason. reqwest's rustls backend requires `rustls-platform-verifier`, which brings `webpki-root-certs` (Mozilla's root certificates as data, CDLA-Permissive-2.0, on the global list). Two proc macros convert identifiers' case at compile time with different `convert_case` versions, crossterm's `derive_more-impl` (0.10) and `napi-derive` (0.12, the Node binding, UC-5.3): `skip` names 0.10 with that reason; neither links into an artifact. `openssl-sys`, `openssl` and
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
| `opentide-lsp-client.cdx.json`, `opentide-lsp-worker.cdx.json`, `opentide-wasi-host.cdx.json` | the npm packages | `npm sbom`, no dev dependencies |
| `opentide.cdx.json` | the `opentide` binaries and crate (`cargo install opentide --features cli`) | cargo-cyclonedx for the facade with `cli`, every target |
| `opentide-node.cdx.json` | the npm package `@opentide/opentide` and its native packages | `npm sbom`, no dev dependencies, with the facade's crates |

All seven are assets of every release of the release train (`publish.yml`, UC-5.5, #840), listed
in `SHA256SUMS` and covered by its provenance attestations, and are generated and validated in
every dry run (CI's nightly set). The engine's four are scanned for oracle references like every
engine asset, and the product's three (`opentide.cdx.json`, `opentide-node.cdx.json` and, since
the wheel depends on `pydantic` alone (UC-6.2), `opentide-wheel.cdx.json`) with `--product`.
Rust SBOMs leave out build dependencies and name workspace crates by their path in
the repository, never the build machine's.
