"""Template generation — TemplateRenderer entry point."""

from __future__ import annotations


def run() -> None:
    """Generate YAML templates via the legacy pipeline (migration in progress)."""
    import sys

    from opentide.core.root import repository_root

    root = str(repository_root())
    if root not in sys.path:
        sys.path.append(root)
    from Engines.framework import templates

    templates.run()
