"""Fail when the engine opentide pins carries another catalog than opentide's models generate.

opentide checks objects with the catalog it generates itself (#677), but the
engine also ships a bundled one: for editors that run ``opentide-lsp`` on its
own, and for when generation fails. language-server generates it with
opentide's own generator (``scripts/sync_opentide_schemas.py``), so it is
current exactly when it equals what this checkout generates, version label
aside. A change to the models, the vocabulary or a pin makes it stale until
language-server regenerates it and opentide pins that engine::

    uv run python scripts/build/check_engine_catalog.py

The catalog is generated in an empty workspace, as language-server generates
it, so no workspace configuration (log sources, statuses) enters it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

FIX = """\
  help: regenerate the bundled catalogs in opentidehq/language-server with this checkout,
        uv run --project <opentide checkout> python scripts/sync_opentide_schemas.py
        then pin that commit in analysis/Cargo.toml (opentide-analysis and opentide-lsp)"""


@contextmanager
def empty_workspace() -> Iterator[None]:
    """An empty workspace for the duration, as language-server generates in."""
    names = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE")
    saved = {name: os.environ.get(name) for name in names}
    with tempfile.TemporaryDirectory() as workspace:
        os.environ.update(dict.fromkeys(names, workspace))
        try:
            yield
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


def differences() -> list[tuple[str, str]]:
    """``(file, how it differs)`` between the pinned engine's catalogs and this checkout's."""
    from opentide.analysis import engine
    from opentide.generation.lsp_catalog import (
        DEPRECATIONS_FILE,
        FIELDS_FILE,
        catalog_differences,
        catalog_texts,
    )

    with empty_workspace():
        expected = catalog_texts()

    fields, deprecations = engine().bundled_catalog()
    return catalog_differences(expected, {FIELDS_FILE: fields, DEPRECATIONS_FILE: deprecations})


def main() -> int:
    from opentide.analysis import EngineUnavailableError, engine_versions

    try:
        found = differences()
        versions = engine_versions()
    except EngineUnavailableError as exc:
        print(f"error: {exc}\n  help: {exc.advice}", file=sys.stderr)
        return 1
    if not found:
        print(f"the engine's bundled catalogs (language server {versions['engine']}) are current")
        return 0
    for name, difference in found:
        print(f"error: the engine's bundled {name} is stale: {difference}", file=sys.stderr)
    print(FIX, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
