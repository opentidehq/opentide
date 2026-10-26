"""``opentide explorer build|serve`` with Node.js and npx mocked out."""

from __future__ import annotations

import json
import subprocess
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
from opentide.export.explorer_package import explorer_package_spec

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


def test_argv_runs_the_named_bin_of_the_pinned_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(service.PACKAGE_ENV, raising=False)
    argv = explorer_argv(
        "npx",
        "build",
        exports_dir=Path("/repo/.opentide/exports"),
        output=Path("/repo/out/explorer"),
        base_path="/repo",
    )
    assert argv == [
        "npx",
        "--yes",
        "--package",
        explorer_package_spec(),
        "opentide-explorer",
        "build",
        "--exports-dir",
        str(Path("/repo/.opentide/exports")),
        "--output",
        str(Path("/repo/out/explorer")),
        "--base-path",
        "/repo",
    ]


def test_argv_takes_the_package_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(service.PACKAGE_ENV, "./opentide-explorer-0.5.0.tgz")
    argv = explorer_argv(
        "npx", "serve", exports_dir=Path("e"), output=Path("o"), port=0, host="0.0.0.0"
    )
    assert argv[3] == "./opentide-explorer-0.5.0.tgz"
    assert argv[-4:] == ["--port", "0", "--host", "0.0.0.0"]


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
    return MagicMock(return_value=subprocess.CompletedProcess([], returncode))


def test_build_reports_json_and_keeps_npx_output_off_stdout(
    invoke_cli, tide_corpus_repo: Path, no_generate: MagicMock
) -> None:
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service.subprocess, "run", npx),
    ):
        result = invoke_cli("explorer", "build", "--base-path", "/corpus")
    payload = assert_json_ok(result)
    repo = tide_corpus_repo.resolve()
    exports = repo / ".opentide" / "exports"
    assert payload["command"] == "build"
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
        patch.object(service.subprocess, "run", npx),
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
        patch.object(service.subprocess, "run", _npx()),
    ):
        payload = assert_json_ok(invoke_cli("explorer", "build", "--output", "site"))
    assert payload["output"] == str((tmp_path / "site").resolve())


def test_build_fails_when_npx_fails(invoke_cli, no_generate: MagicMock) -> None:
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service.subprocess, "run", _npx(returncode=1)),
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
        patch.object(service.subprocess, "run", npx),
    ):
        result = invoke_cli("explorer", "build")
    assert result.exit_code == 1
    assert parse_cli_json(result)["phase"] == "explorer"
    npx.assert_not_called()


def test_serve_passes_port_and_host(invoke_cli, no_generate: MagicMock) -> None:
    npx = _npx()
    with (
        patch.object(service, "find_node_toolchain", return_value=TOOLCHAIN),
        patch.object(service.subprocess, "run", npx),
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
        patch.object(service.subprocess, "run", npx),
    ):
        result = invoke_cli("explorer", "serve")
    assert json.loads(result.stdout)["ok"] is True
    assert result.exit_code == 0


def test_serve_rejects_an_out_of_range_port(invoke_cli) -> None:
    result = invoke_cli("explorer", "serve", "--port", "70000")
    assert result.exit_code == 2
