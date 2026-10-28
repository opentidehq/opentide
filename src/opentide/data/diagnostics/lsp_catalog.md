# lsp_catalog

opentide can generate the language server's catalog for this workspace, and a committed copy is current.

Reported by `opentide doctor`. `opentide lsp start` and `opentide tui` check objects with the catalog this opentide generates from its models and the workspace's configuration, cached under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). The copy `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/` is read only by editors that run the `opentide-lsp` binary on its own, and when generation fails. Warns when the catalog cannot be generated, or when a committed copy does not parse or comes from another opentide version.

## Example

```text
! The language-server catalog committed in .opentide/lsp/catalogs/generated is from opentide 0.18.0, not 0.19.0: editors that run opentide-lsp on their own use it · lsp_catalog
  → opentide generate schemas
```

## How to fix

For a committed copy, run `opentide generate schemas` (or `opentide generate`) and commit the files it writes, so editors that run `opentide-lsp` on its own use the same catalog. When the catalog cannot be generated, `opentide doctor --debug` shows why; until then objects are checked with the committed or the bundled catalog.
