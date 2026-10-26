"""The ``@opentide/explorer`` npm package that renders ``explorer.bundle.json``.

``opentide explorer`` and the generated GitHub Pages job both run it through
``npx``, so the version range they accept lives here once.
"""

from __future__ import annotations

#: npm package that builds and serves the explorer.
EXPLORER_PACKAGE = "@opentide/explorer"
#: Version range ``npx`` resolves: the newest ``0.5.x`` release.
EXPLORER_VERSION_RANGE = "0.5"
#: The package's command. It ships two bins, so ``npx <package>`` alone cannot
#: tell which to run; ``npx --package <spec> opentide-explorer`` names it.
EXPLORER_BIN = "opentide-explorer"
#: Oldest Node.js the package supports (its ``engines.node``).
MIN_NODE_VERSION = (20, 19)


def explorer_package_spec() -> str:
    """``@opentide/explorer@<range>``, as ``npx --package`` takes it."""
    return f"{EXPLORER_PACKAGE}@{EXPLORER_VERSION_RANGE}"


def npx_explorer_args(spec: str | None = None) -> list[str]:
    """Arguments after ``npx`` that run the explorer CLI from *spec*."""
    return ["--yes", "--package", spec or explorer_package_spec(), EXPLORER_BIN]
