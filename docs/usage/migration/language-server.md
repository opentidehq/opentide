---
title: Moving from the language-server distribution
description: Editor users who ran opentide-lsp from opentidehq/language-server switch to opentide lsp start or to the opentide-lsp binary opentide releases.
---

# Moving from the language-server distribution

The opentide language server used to be released from its own repository, opentidehq/language-server, with its own version numbers (up to 0.12.0). Its crates moved into opentide, and opentide releases the server now, at opentide's version. The server is the same: the same languages, language ids, diagnostics, settings and custom requests. What changes is where you get it, its version, and what it reads.

## Pick how you run it

| You run | Get it from | Editor command |
|---------|-------------|----------------|
| `opentide lsp start`, with the `opentide` command line | `pip install opentide`: the server is compiled into the package, with nothing else to install | `opentide lsp start` |
| `opentide-lsp` on its own, without Python | The `opentide-lsp-vX.Y.Z-<target>` asset of an opentide [GitHub Release](https://github.com/opentidehq/opentide/releases), `opentide-installer.sh` or `opentide-installer.ps1` from the same release (which install `opentide` too), `cargo binstall opentide-lsp`, or `cargo install opentide-lsp` | `opentide-lsp --stdio` |

Both are the same server. Use `opentide lsp start` when opentide is installed, so the editor and `opentide validate` always come from one version. See [opentide lsp start and opentide-lsp](../../cli/lsp.md#opentide-lsp-start-and-opentide-lsp).

There is no musl build of `opentide-lsp`. On Alpine, build it with `cargo install opentide-lsp`, or install opentide from its sdist ([Installation](../installation.md#the-analysis-engine-and-the-language-server)).

## Update your editor

1. **Replace the binary.** Remove an `opentide-lsp` you downloaded from opentidehq/language-server's releases, and install one of the two above. A `cargo install opentide-lsp` or `cargo binstall opentide-lsp` you run again fetches opentide's: the crate keeps its name on crates.io, and its versions continue at opentide's.
2. **Keep or change the command.** A configuration that runs `opentide-lsp --stdio` keeps working with opentide's binary. To run the server through opentide, use `opentide lsp start` as the command ([Configuring an editor](../../cli/lsp.md#configuring-an-editor) has Neovim and Helix examples). The language ids and their aliases are unchanged ([Languages](../../cli/lsp.md#languages)).
3. **Take the samples from opentide.** The Helix, Neovim and Zed samples are in opentide's [`editors/`](https://github.com/opentidehq/opentide/tree/development/editors) folder.
4. **Take the grammars from opentide's release.** An editor that copies the TextMate grammars or the Monaco and Helix maps takes them from `highlights-vX.Y.Z.zip` on opentide's GitHub Release; the browser build is `opentide-wasm-web-vX.Y.Z.zip` there. The assets keep their names.
5. **Pin opentide's version.** A check of the server's version (`opentide-lsp --version`, `serverInfo.version`, `capabilities.experimental.opentide.engine`) now reads opentide's version (1.0.0 and later), not language-server's (0.12.0 and earlier). Under `opentide lsp start`, `capabilities.experimental.opentide.host` names opentide; from `opentide-lsp` on its own it is `null` ([Server identity](../../cli/lsp.md#server-identity)).

In VS Code, the opentide extension (`opentidehq.opentide`) brings the server: there is nothing to change.

## What the server reads now

- **Catalogs.** The server generates each workspace folder's field catalogs and configuration schemas from the models it was built with and the folder's configuration (`initialize` reports `catalog: "models"`). A committed `.opentide/lsp/catalogs/generated/` is no longer read: to change what the editor offers, change the workspace's configuration.
- **Configuration files.** `opentide-lsp` on its own checks `.opentide/configurations/**/*.toml` too, with hover and completion, as `opentide lsp start` does ([Configuration files](../../cli/lsp.md#configuration-files)).
- **Object findings.** An object's findings are `opentide validate`'s, with `opentide lint`'s file name and metadata findings. The editor no longer reports `filename_slug`, `filename_pattern`, `missing_author`, `missing_organisation` or `recommended_field_missing`: a setting or suppression list that names them names `filename_mismatch` and `metadata_recommended` instead.

## Verify a download

opentide's release workflow signs each asset. Check an `opentide-lsp` binary against the release's `SHA256SUMS`, and its build provenance with `--repo opentidehq/opentide`, as [`crates/opentide-lsp`](https://github.com/opentidehq/opentide/tree/development/crates/opentide-lsp#releases) describes. A language-server release (0.12.0 and earlier) still verifies with `--repo opentidehq/language-server`.

## Issues

Report language server issues on [opentidehq/opentide](https://github.com/opentidehq/opentide/issues).
