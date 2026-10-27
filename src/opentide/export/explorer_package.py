"""The ``@opentide/explorer`` npm package that renders ``explorer.bundle.json``.

``opentide explorer`` and the generated GitHub Pages job both run it through
``npx``. Neither pins it: they run the ``latest`` release unless told otherwise.
"""

from __future__ import annotations

import re

#: npm package that builds and serves the explorer.
EXPLORER_PACKAGE = "@opentide/explorer"
#: The release ``npx`` resolves when no version is asked for.
DEFAULT_EXPLORER_VERSION = "latest"
#: The package's command. It ships two bins, so ``npx <package>`` alone cannot
#: tell which to run; ``npx --package <spec> opentide-explorer`` names it.
EXPLORER_BIN = "opentide-explorer"
#: Oldest Node.js the package supports (its ``engines.node``).
MIN_NODE_VERSION = (20, 19)

#: A version (``0.5.0``), a range npm reads (``0.5``, ``^0.5.1``, ``~0.5``) or a
#: dist-tag (``latest``, ``next``). Never a path, URL, or anything starting
#: with ``-``, which npx would read as a different package or an option.
_VERSION = re.compile(r"^[~^]?[0-9A-Za-z][0-9A-Za-z.+-]*$")


def is_explorer_version(version: str) -> bool:
    """Whether *version* is a version, simple range or dist-tag of the package."""
    return bool(_VERSION.match(version))


def explorer_package_spec(version: str | None = None) -> str:
    """``@opentide/explorer@<version>``, as ``npx --package`` takes it."""
    return f"{EXPLORER_PACKAGE}@{version or DEFAULT_EXPLORER_VERSION}"


def npx_explorer_args(spec: str | None = None) -> list[str]:
    """Arguments after ``npx`` that run the explorer CLI from *spec*."""
    return ["--yes", "--package", spec or explorer_package_spec(), EXPLORER_BIN]
