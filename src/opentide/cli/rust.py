"""The Rust command line, compiled into ``opentide._native``, run in this process.

``OPENTIDE_ENGINE=rust`` runs a ported command
(:data:`opentide.cli.engines.RUST_COMMANDS`) through :func:`run_in_process`:
the console script does so before Typer is imported
(:mod:`opentide.cli.launch`, UC-3.8b, #960), and the root callback for an
entry point that went through Typer (:func:`opentide.cli.engines.dispatch`).
``python -m opentide.cli.rust`` is the Rust side of ``OPENTIDE_ENGINE=compare``,
which runs each implementation as a child process of its own.
"""

from __future__ import annotations

import os
import sys

#: ``typing.TYPE_CHECKING`` without importing typing, which every Rust run
#: would pay for (UC-3.8b, #960); type checkers read it as True.
TYPE_CHECKING = False

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

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
    import json

    from opentide.cli.services.doctor import PLATFORM_SDKS, _importable

    status = {module: _importable(module) for names in PLATFORM_SDKS.values() for module in names}
    return json.dumps(
        {
            platform: [[module, status[module]] for module in names]
            for platform, names in PLATFORM_SDKS.items()
        }
    )


def _setup_wizard(argv: list[str]) -> bool:
    """Whether *argv* opens the ``setup`` wizard: ``setup`` with nothing after it but ``--path``."""
    rest = argv[argv.index("setup") + 1 :]
    while rest:
        if rest[0] in ("--path", "-C"):
            rest = rest[2:]
        elif rest[0].startswith("--path="):
            rest = rest[1:]
        else:
            return False
    return True


def mcp_server(argv: list[str]) -> str | None:
    """Whether the MCP server can start here, as JSON, for ``setup`` with MCP; else ``None``.

    The server is still Python's (``opentide mcp start``), so only this
    environment can say whether it imports; only a run that writes MCP
    configurations, or the wizard, which may, pays for the probe.
    """
    if "setup" not in argv:
        return None
    if not _setup_wizard(argv) and not any(arg == "mcp" or arg.startswith("--mcp") for arg in argv):
        return None
    import json

    from opentide.mcp_server.launcher import MCP_INSTALL_HINT, missing_requirements

    return json.dumps({"missing": missing_requirements(), "hint": MCP_INSTALL_HINT})


def run_in_process(argv: Sequence[str], env: Mapping[str, str] | None = None) -> int:
    """Run the Rust command line on *argv* in this process; its exit code.

    It runs with exactly the environment *env* (this process's when ``None``)
    and what it reads from this package (:data:`PYTHON_MODULES_ENV`,
    :data:`MCP_SERVER_ENV`), as a child process started with that environment
    would; this process's environment is put back when it returns. The
    engine releases the GIL while it runs and installs its own Ctrl-C handler:
    Ctrl-C ends the run with ``error: interrupted`` and 130, and a signal
    such as SIGTERM reaches the command itself (``serve`` exits 143).
    """
    from opentide import __version__
    from opentide._native import cli_main

    args = list(argv)
    run_env = dict(os.environ if env is None else env)
    modules = python_modules(args)
    if modules is not None:
        run_env[PYTHON_MODULES_ENV] = modules
    server = mcp_server(args)
    if server is not None:
        run_env[MCP_SERVER_ENV] = server
    # Flush what Python buffered before the engine writes to the same streams.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            stream.flush()
    saved = dict(os.environ)
    _set_environment(run_env)
    try:
        return cli_main(args, __version__)
    finally:
        _set_environment(saved)


def _set_environment(target: Mapping[str, str]) -> None:
    """Make this process's environment exactly *target*, the variables the engine reads included."""
    for name in [name for name in os.environ if name not in target]:
        del os.environ[name]
    for name, value in target.items():
        if os.environ.get(name) != value:
            os.environ[name] = value


def main() -> int:
    """Run the Rust command line on this process's arguments; its exit code."""
    return run_in_process(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
