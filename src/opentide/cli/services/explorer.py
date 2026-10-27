"""``opentide explorer``: build or serve the corpus explorer through its npm package."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import structlog

from opentide.cli.services.generation import run_generate
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
#: local tarball (``./opentide-explorer-0.5.0.tgz``).
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
            f"(0.5.0, ^0.5, latest), not {version!r}"
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
        return _failure(str(exc), error=str(exc))
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
        "command": command,
        "package": spec,
        "node": toolchain.node_version,
        "exports_dir": str(exports_dir),
        "output": str(site),
    }
    logger.info("explorer_npx", argv=argv)
    try:
        # With --json, stdout carries only the result document: the package's
        # progress goes to stderr instead.
        done = subprocess.run(
            argv, cwd=cli.repo, stdout=2 if cli.json_output else None, check=False
        )
        returncode = done.returncode
    except KeyboardInterrupt:
        returncode = -2
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
