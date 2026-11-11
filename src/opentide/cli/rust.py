"""``python -m opentide.cli.rust``: the Rust command line, compiled into ``opentide._native``.

``OPENTIDE_ENGINE=rust`` and ``compare`` run a ported command here
(:data:`opentide.cli.engines.RUST_COMMANDS`); it prints and exits as the
command does. The Python launcher replaces it in UC-3.8 (#830).
"""

from __future__ import annotations

import json
import os
import sys

#: What ``opentide doctor`` on Rust reads to check the platforms' Python
#: modules (``PYTHON_MODULES_ENV`` in ``crates/opentide-cli/src/commands/doctor.rs``):
#: each platform mapped to its modules, in order, each a ``[module, status]``
#: pair whose status is ``null`` when it imports here, else why not.
PYTHON_MODULES_ENV = "OPENTIDE_PYTHON_MODULES"

#: What ``opentide setup mcp`` (and ``setup --mcp``) on Rust reads to report
#: whether ``opentide mcp start``, which every configuration it writes
#: launches, can start here (``MCP_SERVER_ENV`` in
#: ``crates/opentide-cli/src/commands/setup/files.rs``): the imports it cannot
#: satisfy and the command that repairs them.
MCP_SERVER_ENV = "OPENTIDE_MCP_SERVER"


def python_modules(argv: list[str]) -> str | None:
    """The import status of each platform's SDKs for a ``doctor`` run, as JSON; else ``None``.

    The Rust command line cannot import Python modules, so this launcher,
    which runs in the environment the platforms deploy from, checks them, and
    names them: which modules a platform needs is the Python package's to say.
    Only ``doctor`` reads them, and only it pays for the imports.
    """
    if "doctor" not in argv:
        return None
    from opentide.cli.services.doctor import PLATFORM_SDKS, _importable

    status = {module: _importable(module) for names in PLATFORM_SDKS.values() for module in names}
    return json.dumps(
        {
            platform: [[module, status[module]] for module in names]
            for platform, names in PLATFORM_SDKS.items()
        }
    )


def mcp_server(argv: list[str]) -> str | None:
    """Whether the MCP server can start here, as JSON, for ``setup`` with MCP; else ``None``.

    The server is still Python's (``opentide mcp start``), so only this
    environment can say whether it imports; only a run that writes MCP
    configurations pays for the probe.
    """
    if "setup" not in argv or not any(arg == "mcp" or arg.startswith("--mcp") for arg in argv):
        return None
    from opentide.mcp_server.launcher import MCP_INSTALL_HINT, missing_requirements

    return json.dumps({"missing": missing_requirements(), "hint": MCP_INSTALL_HINT})


def main() -> int:
    """Run the Rust CLI on this process's arguments; its exit code."""
    from opentide import __version__
    from opentide._native import cli_main

    modules = python_modules(sys.argv[1:])
    if modules is not None:
        os.environ[PYTHON_MODULES_ENV] = modules
    server = mcp_server(sys.argv[1:])
    if server is not None:
        os.environ[MCP_SERVER_ENV] = server
    # Flush what Python buffered before the engine writes to the same streams.
    sys.stdout.flush()
    sys.stderr.flush()
    return cli_main(sys.argv[1:], __version__)


if __name__ == "__main__":
    raise SystemExit(main())
