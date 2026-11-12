"""``opentide.cli.rust``: what the launcher hands the Rust command line (UC-3.5c, #928; UC-6.0d)."""

from __future__ import annotations

import os

import pytest

from opentide.cli import rust

#: What the launcher handed the Rust command line before UC-6.0d (#841): the
#: platforms' Python SDK imports for ``doctor``, and whether the Python MCP
#: server imported for ``setup mcp``.
RETIRED = ("OPENTIDE_PYTHON_MODULES", "OPENTIDE_MCP_SERVER")


@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "doctor", "--offline"],
        ["setup", "mcp", "--vscode"],
        ["--json", "setup", "--mcp", "cursor", "--yes"],
        ["setup"],
    ],
)
def test_the_rust_run_gets_exactly_the_environment_it_is_given(
    argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``doctor`` checks no Python module and ``setup mcp`` probes the Rust server:
    the launcher probes nothing in Python and adds no variable."""
    import opentide._native

    seen: list[dict[str, str]] = []

    def cli_main(args: list[str], version: str) -> int:
        seen.append(dict(os.environ))
        return 0

    monkeypatch.setattr(opentide._native, "cli_main", cli_main)
    given = {"PATH": os.environ.get("PATH", ""), "OPENTIDE_OUTPUT": "plain"}
    before = dict(os.environ)
    assert rust.run_in_process(argv, given) == 0
    assert seen == [given]
    assert not any(name in seen[0] for name in RETIRED)
    assert dict(os.environ) == before
