"""``opentide explorer build|serve`` with Node.js and npx mocked out."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

from opentide.cli.services import explorer as service
from opentide.cli.services.explorer import (
    ExplorerToolchainError,
    NodeToolchain,
    explorer_argv,
    find_node_toolchain,
    parse_node_version,
)

TOOLCHAIN = NodeToolchain(npx="/usr/bin/npx", node_version="v22.11.0")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("v22.11.0\n", (22, 11, 0)),
        ("20.19.1", (20, 19, 1)),
        ("v20.19.0-nightly", (20, 19, 0)),
        ("", None),
        ("node: command not found", None),
    ],
)
def test_parse_node_version(text: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_node_version(text) == expected


def _which(**found: str | None) -> Any:
    return lambda name: found.get(name)


def _node_reports(stdout: str, returncode: int = 0) -> MagicMock:
    return MagicMock(return_value=subprocess.CompletedProcess([], returncode, stdout, ""))


def test_toolchain_without_node_says_what_to_install() -> None:
    with (
        patch.object(service.shutil, "which", _which()),
        pytest.raises(ExplorerToolchainError, match=r"Node\.js was not found on PATH.*20\.19"),
    ):
        find_node_toolchain()


@pytest.mark.parametrize("version", ["v18.20.4", "v20.18.3", "v20.0.0"])
def test_toolchain_rejects_node_older_than_the_package_engines(version: str) -> None:
    with (
        patch.object(service.shutil, "which", _which(node="/bin/node", npx="/bin/npx")),
        patch.object(service.subprocess, "run", _node_reports(version)),
        pytest.raises(ExplorerToolchainError, match=rf"20\.19 or newer; /bin/node is {version}"),
    ):
        find_node_toolchain()


def test_toolchain_without_npx_is_an_error() -> None:
    with (
        patch.object(service.shutil, "which", _which(node="/bin/node")),
        patch.object(service.subprocess, "run", _node_reports("v22.1.0")),
        pytest.raises(ExplorerToolchainError, match="npx was not found on PATH"),
    ):
        find_node_toolchain()


def test_toolchain_with_an_unreadable_version_is_an_error() -> None:
    with (
        patch.object(service.shutil, "which", _which(node="/bin/node", npx="/bin/npx")),
        patch.object(service.subprocess, "run", _node_reports("", returncode=1)),
        pytest.raises(ExplorerToolchainError, match="did not report a version"),
    ):
        find_node_toolchain()


def test_toolchain_accepts_the_minimum_version() -> None:
    with (
        patch.object(service.shutil, "which", _which(node="/bin/node", npx="/bin/npx")),
        patch.object(service.subprocess, "run", _node_reports("v20.19.0\n")),
    ):
        assert find_node_toolchain() == NodeToolchain(npx="/bin/npx", node_version="v20.19.0")


def test_argv_runs_the_named_bin_of_the_package() -> None:
    argv = explorer_argv(
        "npx",
        "build",
        spec="@opentide/explorer@latest",
        exports_dir=Path("/repo/.opentide/exports"),
        output=Path("/repo/out/explorer"),
        base_path="/repo",
    )
    assert argv == [
        "npx",
        "--yes",
        "--package",
        "@opentide/explorer@latest",
        "opentide-explorer",
        "build",
        "--exports-dir",
        str(Path("/repo/.opentide/exports")),
        "--output",
        str(Path("/repo/out/explorer")),
        "--base-path",
        "/repo",
    ]


def test_serve_argv_adds_port_and_host() -> None:
    argv = explorer_argv(
        "npx", "serve", spec="s", exports_dir=Path("e"), output=Path("o"), port=0, host="0.0.0.0"
    )
    assert argv[-4:] == ["--port", "0", "--host", "0.0.0.0"]


@pytest.mark.parametrize(
    ("version", "spec"),
    [
        (None, "@opentide/explorer@latest"),
        ("latest", "@opentide/explorer@latest"),
        ("0.5.0", "@opentide/explorer@0.5.0"),
        ("0.5", "@opentide/explorer@0.5"),
        ("^0.5.1", "@opentide/explorer@^0.5.1"),
        ("next", "@opentide/explorer@next"),
        ("1.0.0-rc.1", "@opentide/explorer@1.0.0-rc.1"),
    ],
)
def test_package_spec_runs_latest_unless_a_version_is_named(
    monkeypatch: pytest.MonkeyPatch, version: str | None, spec: str
) -> None:
    monkeypatch.delenv(service.PACKAGE_ENV, raising=False)
    assert service.package_spec(version) == spec


@pytest.mark.parametrize("version", ["--foo", "../evil", "file:../x", "1.0 || 2", "", "a/b"])
def test_package_spec_refuses_what_is_not_a_version(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    monkeypatch.delenv(service.PACKAGE_ENV, raising=False)
    with pytest.raises(ValueError, match="--version takes a version"):
        service.package_spec(version)


def test_package_spec_takes_the_environment_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(service.PACKAGE_ENV, "./opentide-explorer-0.5.0.tgz")
    assert service.package_spec() == "./opentide-explorer-0.5.0.tgz"
    with pytest.raises(ValueError, match="unset it to choose a version"):
        service.package_spec("0.5.0")


@pytest.fixture
def no_generate(tide_corpus_repo: Path) -> Any:
    """Skip the export: write a bundle where `generate explorer` would."""
    exports = tide_corpus_repo / ".opentide" / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    (exports / "explorer.bundle.json").write_text("{}", encoding="utf-8")
    with patch.object(
        service, "run_generate", return_value={"message": "ok", "phase": "explorer"}
    ) as mock:
        yield mock


def _npx(returncode: int = 0) -> MagicMock:
    return MagicMock(return_value=returncode)


def test_build_reports_json_and_keeps_npx_output_off_stdout(
    invoke_cli, tide_corpus_repo: Path, no_generate: MagicMock
) -> None:
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", npx),
    ):
        result = invoke_cli("explorer", "build", "--base-path", "/corpus")
    payload = assert_json_ok(result)
    repo = tide_corpus_repo.resolve()
    exports = repo / ".opentide" / "exports"
    assert payload["command"] == "explorer build"
    assert payload["exports_dir"] == str(exports)
    assert payload["output"] == str(repo / "out" / "explorer")
    assert payload["node"] == "v22.11.0"
    no_generate.assert_called_once()
    argv = npx.call_args.args[0]
    assert argv[:5] == [
        "/usr/bin/npx",
        "--yes",
        "--package",
        payload["package"],
        "opentide-explorer",
    ]
    assert argv[argv.index("--exports-dir") + 1] == str(exports)
    assert argv[argv.index("--base-path") + 1] == "/corpus"
    assert npx.call_args.kwargs["cwd"] == repo
    assert npx.call_args.kwargs["stdout"] == 2


def test_build_without_json_lets_npx_print(
    invoke_cli, tide_corpus_repo: Path, no_generate: MagicMock
) -> None:
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", npx),
    ):
        result = invoke_cli("explorer", "build", json_output=False)
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "Explorer built in" in result.stdout
    assert npx.call_args.kwargs["stdout"] is None


def test_build_resolves_a_relative_output_against_the_working_directory(
    invoke_cli,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_generate: MagicMock,
) -> None:
    monkeypatch.chdir(tmp_path)
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", _npx()),
    ):
        payload = assert_json_ok(invoke_cli("explorer", "build", "--output", "site"))
    assert payload["output"] == str((tmp_path / "site").resolve())


def test_build_fails_when_npx_fails(invoke_cli, no_generate: MagicMock) -> None:
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", _npx(returncode=1)),
    ):
        result = invoke_cli("explorer", "build")
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert payload["exit_status"] == 1
    assert "build exited with status 1" in payload["error"]


def test_missing_node_fails_before_generating(invoke_cli) -> None:
    error = ExplorerToolchainError("Node.js was not found on PATH.")
    with (
        patch.object(service, "find_node_toolchain", side_effect=error),
        patch.object(service, "run_generate") as generate,
    ):
        result = invoke_cli("explorer", "build")
    assert result.exit_code == 1
    assert parse_cli_json(result)["error"] == "Node.js was not found on PATH."
    generate.assert_not_called()


def test_failed_export_is_the_command_result(invoke_cli) -> None:
    failed = {"message": "boom", "status": "failed", "phase": "explorer", "_exit_code": 1}
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_generate", return_value=failed),
        patch.object(service, "run_package", npx),
    ):
        result = invoke_cli("explorer", "build")
    assert result.exit_code == 1
    assert parse_cli_json(result)["phase"] == "explorer"
    npx.assert_not_called()


def test_serve_passes_port_and_host(invoke_cli, no_generate: MagicMock) -> None:
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", npx),
    ):
        payload = assert_json_ok(invoke_cli("explorer", "serve", "--port", "0", "--host", "::1"))
    argv = npx.call_args.args[0]
    assert argv[5] == "serve"
    assert argv[argv.index("--port") + 1] == "0"
    assert argv[argv.index("--host") + 1] == "::1"
    assert "--base-path" not in argv
    assert payload["message"] == "Explorer server stopped"


@pytest.mark.parametrize("stopped", [130, -2, KeyboardInterrupt()])
def test_serve_stopped_with_ctrl_c_succeeds(
    invoke_cli, no_generate: MagicMock, stopped: int | BaseException
) -> None:
    npx = (
        MagicMock(side_effect=stopped)
        if isinstance(stopped, BaseException)
        else _npx(returncode=stopped)
    )
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", npx),
    ):
        result = invoke_cli("explorer", "serve")
    assert json.loads(result.stdout)["ok"] is True
    assert result.exit_code == 0


def test_an_interrupted_build_is_an_interrupted_command(invoke_cli, no_generate: MagicMock) -> None:
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", MagicMock(side_effect=KeyboardInterrupt)),
    ):
        result = invoke_cli("explorer", "build")
    assert result.exit_code == 130
    assert "Explorer built" not in result.stdout


def test_serve_rejects_an_out_of_range_port(invoke_cli) -> None:
    result = invoke_cli("explorer", "serve", "--port", "70000")
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("flags", "spec"),
    [
        ((), "@opentide/explorer@latest"),
        (("--latest",), "@opentide/explorer@latest"),
        (("--version", "0.5.0"), "@opentide/explorer@0.5.0"),
    ],
)
def test_build_runs_the_requested_release(
    invoke_cli,
    monkeypatch: pytest.MonkeyPatch,
    no_generate: MagicMock,
    flags: tuple[str, ...],
    spec: str,
) -> None:
    monkeypatch.delenv(service.PACKAGE_ENV, raising=False)
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service, "run_package", npx),
    ):
        payload = assert_json_ok(invoke_cli("explorer", "build", *flags))
    assert payload["package"] == spec
    assert npx.call_args.args[0][3] == spec


def test_version_and_latest_together_are_a_usage_error(invoke_cli) -> None:
    with patch.object(service, "run_generate") as generate:
        result = invoke_cli("explorer", "serve", "--latest", "--version", "0.5.0")
    assert result.exit_code == 2
    payload = parse_cli_json(result)
    assert "not both" in payload["error"]
    assert payload["failure"]["code"] == "usage_error"
    generate.assert_not_called()


def test_a_bad_version_fails_before_node_or_export(invoke_cli, monkeypatch) -> None:
    monkeypatch.delenv(service.PACKAGE_ENV, raising=False)
    with (
        patch.object(service, "find_node_toolchain") as toolchain,
        patch.object(service, "run_generate") as generate,
    ):
        result = invoke_cli("explorer", "build", "--version", "file:../x")
    assert result.exit_code == 2
    payload = parse_cli_json(result)
    assert "--version takes a version" in payload["error"]
    assert payload["failure"]["code"] == "usage_invalid_value"
    assert payload["failure"]["argument"] == "file:../x"
    toolchain.assert_not_called()
    generate.assert_not_called()


# --------------------------------------------------------------------------
# run_package: a real process tree, as npx starts one (npm → sh → node)
# --------------------------------------------------------------------------

_TREE = """\
import pathlib, subprocess, sys, time
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
pathlib.Path(sys.argv[1]).write_text(str(grandchild.pid), encoding="utf-8")
pathlib.Path(sys.argv[2]).write_text(repr(sys.stdin.read()), encoding="utf-8")
grandchild.wait()
"""

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


def _alive(pid: int) -> bool:
    """Whether *pid* still runs; a zombie nobody has reaped yet does not count."""
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        try:
            return "\nState:\tZ" not in status.read_text(encoding="utf-8")
        except OSError:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for(path: Path, seconds: float = 30.0) -> str:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists() and (text := path.read_text(encoding="utf-8")):
            return text
        time.sleep(0.05)
    raise AssertionError(f"{path} was not written")


def _tree(tmp_path: Path) -> tuple[list[str], Path, Path]:
    script = tmp_path / "tree.py"
    script.write_text(_TREE, encoding="utf-8")
    pid_file, stdin_file = tmp_path / "grandchild.pid", tmp_path / "stdin.txt"
    return [sys.executable, str(script), str(pid_file), str(stdin_file)], pid_file, stdin_file


def _assert_stops(pid: int) -> None:
    deadline = time.monotonic() + 15
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(pid), "the package's child outlived the interrupt"


def test_run_package_returns_the_exit_status(tmp_path: Path) -> None:
    argv = [sys.executable, "-c", "import sys; sys.exit(3)"]
    assert service.run_package(argv, cwd=tmp_path, stdout=None) == 3


@posix_only
def test_a_cancel_in_the_command_thread_stops_the_whole_tree(tmp_path: Path) -> None:
    """``opentide serve`` cancels by raising KeyboardInterrupt in the command's thread.

    A thread blocked in ``waitpid`` never sees it, and killing npx alone leaves
    its node child serving on the port.
    """
    from opentide.cli.services.serve import _raise_in_thread

    argv, pid_file, stdin_file = _tree(tmp_path)
    raised: list[BaseException] = []

    def command() -> None:
        try:
            service.run_package(argv, cwd=tmp_path, stdout=None)
        except BaseException as exc:
            raised.append(exc)

    worker = threading.Thread(target=command)
    worker.start()
    grandchild = int(_wait_for(pid_file))
    # stdin is closed, never the terminal or serve's request stream.
    assert _wait_for(stdin_file) == "''"
    assert worker.ident is not None
    _raise_in_thread(worker.ident, KeyboardInterrupt)
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert len(raised) == 1
    assert isinstance(raised[0], KeyboardInterrupt)
    _assert_stops(grandchild)


@posix_only
def test_sigterm_stops_the_whole_tree(tmp_path: Path) -> None:
    argv, pid_file, _ = _tree(tmp_path)
    timer = threading.Thread(
        target=lambda: (_wait_for(pid_file), os.kill(os.getpid(), signal.SIGTERM))
    )
    previous = signal.getsignal(signal.SIGTERM)
    timer.start()
    with pytest.raises(KeyboardInterrupt):
        service.run_package(argv, cwd=tmp_path, stdout=None)
    timer.join()
    assert signal.getsignal(signal.SIGTERM) is previous
    _assert_stops(int(pid_file.read_text(encoding="utf-8")))
