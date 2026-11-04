"""``opentide explorer``: build or serve the corpus explorer through its npm package."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import structlog

from opentide.cli.services.generation import run_generate
from opentide.cli.ui.contract import USAGE_ERROR, USAGE_EXIT_CODE, USAGE_INVALID_VALUE
from opentide.export.explorer_package import (
    EXPLORER_PACKAGE,
    MIN_NODE_VERSION,
    explorer_package_spec,
    is_explorer_version,
    npx_explorer_args,
)

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

logger = structlog.get_logger("opentide.cli.services.explorer")

#: Replaces ``@opentide/explorer@<version>``: a mirror, a fork, or a
#: local tarball (``./opentide-explorer-0.5.1.tgz``).
PACKAGE_ENV = "OPENTIDE_EXPLORER_PACKAGE"
_BUNDLE = "explorer.bundle.json"
_NODE_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
_INSTALL_NODE = (
    "Install Node.js {minimum} or newer (https://nodejs.org) and make sure `node` and `npx` "
    "are on PATH."
)
#: How a server stopped with Ctrl-C reports itself: killed by SIGINT, or the
#: shell convention 128 + SIGINT when npx exits on the child's behalf.
_INTERRUPTED = frozenset({-2, 130})

#: How often the wait for npx returns to Python, so that a cancel raised in
#: this thread (``opentide serve`` raises one at the next bytecode) is seen.
_POLL_SECONDS = 0.2
#: How long npx and the package get to stop after an interrupt before they are killed.
_STOP_GRACE_SECONDS = 5.0

ExplorerCommand = Literal["build", "serve"]


class ExplorerToolchainError(Exception):
    """Node.js or npx is missing or too old to run the explorer package."""


@dataclass(frozen=True)
class NodeToolchain:
    """The ``npx`` executable to run, and the Node.js version found beside it."""

    npx: str
    node_version: str


def parse_node_version(text: str) -> tuple[int, int, int] | None:
    """``v22.11.0`` → ``(22, 11, 0)``; ``None`` for anything else."""
    match = _NODE_VERSION.match(text.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _minimum() -> str:
    return ".".join(str(part) for part in MIN_NODE_VERSION)


def find_node_toolchain() -> NodeToolchain:
    """Locate ``node`` and ``npx`` and check Node.js is recent enough."""
    advice = _INSTALL_NODE.format(minimum=_minimum())
    node = shutil.which("node")
    if node is None:
        raise ExplorerToolchainError(f"Node.js was not found on PATH. {advice}")
    try:
        done = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExplorerToolchainError(f"Could not run `{node} --version`: {exc}. {advice}") from exc
    reported = done.stdout.strip()
    version = parse_node_version(reported)
    if done.returncode != 0 or version is None:
        raise ExplorerToolchainError(
            f"`{node} --version` did not report a version ({reported or 'no output'}). {advice}"
        )
    if version[:2] < MIN_NODE_VERSION:
        raise ExplorerToolchainError(
            f"The explorer needs Node.js {_minimum()} or newer; {node} is {reported}. {advice}"
        )
    npx = shutil.which("npx")
    if npx is None:
        raise ExplorerToolchainError(
            f"npx was not found on PATH (Node.js {reported} is). It ships with npm; {advice}"
        )
    return NodeToolchain(npx=npx, node_version=reported)


def package_spec(version: str | None = None) -> str:
    """The npm package spec to run.

    ``OPENTIDE_EXPLORER_PACKAGE`` when set, else ``@opentide/explorer@<version>``,
    ``latest`` when *version* is ``None``. Raises ``ValueError`` for a version
    that is not one, and for a version given alongside the environment override,
    which would otherwise be dropped without a word.
    """
    override = os.environ.get(PACKAGE_ENV, "").strip()
    if override:
        if version is not None:
            raise ValueError(
                f"{PACKAGE_ENV} is set to {override}; unset it to choose a version "
                "with --version or --latest"
            )
        return override
    if version is not None and not is_explorer_version(version):
        raise ValueError(
            f"--version takes a version, range or dist-tag of {EXPLORER_PACKAGE} "
            f"(0.5.1, ^0.5, latest), not {version!r}"
        )
    return explorer_package_spec(version)


def explorer_argv(
    npx: str,
    command: ExplorerCommand,
    *,
    spec: str,
    exports_dir: Path,
    output: Path,
    base_path: str | None = None,
    port: int | None = None,
    host: str | None = None,
) -> list[str]:
    """The ``npx`` command line for ``opentide-explorer build|serve``."""
    argv = [
        npx,
        *npx_explorer_args(spec),
        command,
        "--exports-dir",
        str(exports_dir),
        "--output",
        str(output),
    ]
    if base_path:
        argv += ["--base-path", base_path]
    if port is not None:
        argv += ["--port", str(port)]
    if host:
        argv += ["--host", host]
    return argv


@contextmanager
def _termination_interrupts() -> Generator[None]:
    """SIGTERM and SIGHUP raise ``KeyboardInterrupt`` while npx runs, so it is stopped too.

    Only the main thread can install handlers; elsewhere (``opentide serve``)
    a cancel already arrives as ``KeyboardInterrupt``.
    """
    names = ("SIGTERM", "SIGHUP")
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def interrupt(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    previous = {
        number: signal.signal(number, interrupt)
        for number in (getattr(signal, name) for name in names if hasattr(signal, name))
    }
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _signal_group(process: subprocess.Popen[bytes], *, kill: bool) -> None:
    """Interrupt, or kill, every process npx started: npm, the shell, node."""
    if sys.platform == "win32":
        if not kill:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            # taskkill /T ends the whole tree; terminate() would end npx alone.
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                capture_output=True,
                timeout=30,
                check=False,
            )
        return
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL if kill else signal.SIGINT)


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Interrupt the package, then kill whatever is left once the grace period is up."""
    try:
        _signal_group(process, kill=False)
        process.wait(timeout=_STOP_GRACE_SECONDS)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        pass
    finally:
        # npx can exit before its child does: sweep the group either way.
        _signal_group(process, kill=True)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=_STOP_GRACE_SECONDS)


def run_package(argv: list[str], *, cwd: Path, stdout: int | None) -> int:
    """Run *argv* (npx) to the end and return its exit status.

    npx runs in a process group of its own, which an interrupt (Ctrl-C, SIGTERM,
    or a cancel from ``opentide serve``) stops as a whole before
    ``KeyboardInterrupt`` is raised again. Killing npx alone would leave the
    package's node process behind, still serving on its port. stdin is closed:
    nothing should be read from the terminal, or from ``opentide serve``'s
    request stream.
    """
    with _termination_interrupts():
        if sys.platform == "win32":
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        else:
            process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, start_new_session=True
            )
        try:
            while True:
                try:
                    return process.wait(timeout=_POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    continue
        except KeyboardInterrupt:
            _stop(process)
            raise


def _failure(message: str, **data: object) -> dict[str, object]:
    return {"message": message, "status": "failed", "_exit_code": 1, **data}


def run_explorer(
    cli: CliContext,
    command: ExplorerCommand,
    *,
    output: str | None = None,
    base_path: str | None = None,
    port: int | None = None,
    host: str | None = None,
    version: str | None = None,
) -> dict[str, object]:
    """Export the explorer bundle, then build or serve it with ``@opentide/explorer``.

    *version* picks the package release (``None`` runs ``latest``).
    """
    try:
        spec = package_spec(version)
    except ValueError as exc:
        # A bad --version, or one the environment override would drop: usage errors.
        return {
            **_failure(str(exc), error=str(exc)),
            "_exit_code": USAGE_EXIT_CODE,
            "_failure_code": USAGE_INVALID_VALUE if version else USAGE_ERROR,
            "_failure_argument": version,
        }
    try:
        toolchain = find_node_toolchain()
    except ExplorerToolchainError as exc:
        return _failure(str(exc), error=str(exc))

    generated = run_generate(cli, phase="explorer")
    if generated.get("status") == "failed":
        return generated

    from opentide.core.registry import Opentide

    exports_dir = Path(Opentide.Configurations.Global.Paths.Tide.exports).resolve()
    if not (exports_dir / _BUNDLE).is_file():
        message = f"`opentide generate explorer` wrote no {_BUNDLE} under {exports_dir}"
        return _failure(message, error=message)

    # A relative --output is the caller's path; the default sits in the repository.
    site = Path(output).expanduser().resolve() if output else cli.repo.resolve() / "out/explorer"
    argv = explorer_argv(
        toolchain.npx,
        command,
        spec=spec,
        exports_dir=exports_dir,
        output=site,
        base_path=base_path,
        port=port,
        host=host,
    )
    data: dict[str, object] = {
        "package": spec,
        "node": toolchain.node_version,
        "exports_dir": str(exports_dir),
        "output": str(site),
    }
    logger.info("explorer_npx", argv=argv)
    try:
        # With --json, stdout carries only the result document: the package's
        # progress goes to stderr instead.
        returncode = run_package(argv, cwd=cli.repo, stdout=2 if cli.json_output else None)
    except KeyboardInterrupt:
        # The package has been stopped. Stopping a server is how it ends; an
        # interrupted build is an interrupted command (exit 130).
        if command != "serve":
            raise
        return {"message": "Explorer server stopped", **data}
    except OSError as exc:
        message = f"Could not run {toolchain.npx}: {exc}"
        return _failure(message, error=message, **data)

    if command == "serve" and returncode in _INTERRUPTED:
        return {"message": "Explorer server stopped", **data}
    if returncode != 0:
        message = f"{spec} {command} exited with status {returncode}"
        return _failure(message, error=message, exit_status=returncode, **data)
    if command == "build":
        return {"message": f"Explorer built in {site}", **data}
    return {"message": "Explorer server stopped", **data}
