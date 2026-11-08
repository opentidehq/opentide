"""``OPENTIDE_ENGINE``: the dispatch between a command's implementations (#805).

No command has a Rust implementation yet, so the ``compare`` cases register
a deliberately divergent fake one (``fake_rust_engine.py``) in the dispatch
table and check that each kind of divergence fails the run with exit 70 and
``engine_mismatch``, with a diff report.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from opentide.cli import app, engines
from opentide.cli.engines import RustCommand

FAKE = Path(__file__).with_name("fake_rust_engine.py")
CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "tide_corpus"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    target = tmp_path / "ws"
    shutil.copytree(CORPUS, target)
    return target


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where diff reports go: ``$XDG_STATE_HOME/opentide/compare``."""
    home = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(home))
    monkeypatch.setattr(sys, "platform", "linux")
    return home / "opentide" / "compare"


def fake(mode: str) -> RustCommand:
    return RustCommand(launch=(sys.executable, str(FAKE), mode))


def invoke(args: list[str], engine: str | None) -> tuple[int, str, str]:
    env = {"OPENTIDE_ENGINE": engine} if engine is not None else {}
    result = CliRunner().invoke(app, args, env=env, catch_exceptions=False)
    return result.exit_code, result.stdout, result.stderr


def document(stdout: str) -> dict[str, Any]:
    parsed = json.loads(stdout)
    assert isinstance(parsed, dict)
    return parsed


def test_the_engine_is_python_unless_set() -> None:
    assert engines.requested({}) == "python"
    assert engines.requested({"OPENTIDE_ENGINE": "  "}) == "python"
    assert engines.requested({"OPENTIDE_ENGINE": "compare"}) == "compare"


def test_the_engine_is_read_per_process(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Read when the command runs, not when opentide is imported."""
    args = ["--json", "--repo", str(workspace), "validate"]
    assert invoke(args, "rust")[0] == 2
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    assert invoke(args, None)[0] != 2


def test_rust_on_a_command_without_rust_is_engine_unavailable(workspace: Path) -> None:
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "validate"], "rust")
    assert code == 2
    doc = document(stdout)
    assert doc["exit_code"] == 2
    assert doc["command"] == "validate"
    assert doc["failure"]["code"] == "engine_unavailable"
    assert doc["failure"]["argument"] == "OPENTIDE_ENGINE"
    assert "opentide validate has no Rust implementation yet" in doc["failure"]["message"]
    assert stdout.endswith("}\n") and stdout.count("\n") == 1


def test_rust_on_a_subcommand_names_its_path(workspace: Path) -> None:
    code, stdout, _ = invoke(
        ["--json", "--repo", str(workspace), "validate", "query", "--platform", "x"], "rust"
    )
    assert code == 2
    assert document(stdout)["command"] == "validate query"


def test_rust_without_json_is_one_error_line(workspace: Path) -> None:
    code, stdout, stderr = invoke(["--no-color", "--repo", str(workspace), "validate"], "rust")
    assert code == 2
    assert stdout == ""
    assert "error: opentide validate has no Rust implementation yet" in stderr


def test_an_unknown_engine_is_a_usage_error_with_a_suggestion(workspace: Path) -> None:
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "validate"], "Rust")
    assert code == 2
    failure = document(stdout)["failure"]
    assert failure["code"] == "usage_invalid_choice"
    assert failure["argument"] == "OPENTIDE_ENGINE"
    assert failure["suggestion"] == "rust"


@pytest.mark.parametrize("engine", [None, "", "python", "compare"])
def test_python_runs_where_rust_does_not_exist(workspace: Path, engine: str | None) -> None:
    """``compare`` on a command with no Rust implementation runs Python alone."""
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], engine)
    assert code == 0
    doc = document(stdout)
    assert doc["ok"] is True
    assert doc["failure"] is None


def test_rust_runs_the_rust_implementation(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("exit"))
    python = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "python")
    # The fake is a subprocess: its exit code is the run's, its output its own.
    code, _, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "rust")
    assert code == python[0] + 1


def test_compare_replays_python_when_both_agree(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(workspace)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("same"))
    args = ["--json", "--repo", str(workspace), "explain", "internal"]
    code, stdout, _ = invoke(args, "compare")
    assert code == 0
    doc = document(stdout)
    python = document(invoke(args, "python")[1])
    assert {**doc, "duration_ms": 0} == {**python, "duration_ms": 0}
    assert list(doc) == list(python)
    assert not state.exists()


@pytest.mark.parametrize(
    ("mode", "target", "kind"),
    [
        ("stdout", "stdout", "json_value"),
        ("key-order", "stdout", "json_key_order"),
        ("exit", "exit_code", "exit_code"),
        ("file", "file:fake-rust.txt", "file_extra"),
    ],
)
def test_compare_catches_a_divergent_fake_rust_command(
    workspace: Path,
    state: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    target: str,
    kind: str,
) -> None:
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake(mode))
    monkeypatch.chdir(workspace)
    before = sorted(path.name for path in workspace.iterdir())
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "compare")

    assert code == 70
    doc = document(stdout)
    assert doc["exit_code"] == 70
    assert doc["command"] == "explain"
    assert doc["failure"]["code"] == "engine_mismatch"
    reports = list(state.glob("*.json"))
    assert len(reports) == 1
    assert str(reports[0]) in doc["failure"]["message"]
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["command"] == "explain"
    assert report["equal"] is False
    assert (report["oracle"], report["candidate"]) == ("python", "rust")
    found = {(item["target"], item["kind"]) for item in report["differences"]}
    assert found == {(target, kind)}
    if os.name == "posix":
        assert reports[0].stat().st_mode & 0o777 == 0o600
    # Each implementation ran on its own copy: the workspace is as it was.
    assert sorted(path.name for path in workspace.iterdir()) == before


def test_compare_without_json_prints_one_error_line(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(workspace)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("stdout"))
    code, stdout, stderr = invoke(
        ["--no-color", "--repo", str(workspace), "explain", "internal"], "compare"
    )
    assert code == 70
    assert stdout == ""
    assert "error: The Python and Rust implementations of opentide explain differ" in stderr
    assert str(state) in stderr


def test_compare_normalises_the_workspace_path(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each side prints its own copy's path; both read as ``<WS>`` before comparing."""
    monkeypatch.chdir(workspace)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("info",), fake("same"))
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "info", "rules"], "compare")
    python_code, python_stdout, _ = invoke(
        ["--json", "--repo", str(workspace), "info", "rules"], "python"
    )
    assert code == python_code
    assert document(stdout)["command"] == document(python_stdout)["command"]
    assert not state.exists()


def test_arguments_are_mapped_into_the_copy(tmp_path: Path) -> None:
    original = (tmp_path / "ws").resolve()
    (original / "objects").mkdir(parents=True)
    copy = engines._Copy(original=original, root=tmp_path / "copy" / "ws")
    mapped = engines._map_args(
        [
            "--repo",
            str(original),
            "validate",
            "--file",
            str(original / "objects" / "a.yaml"),
            f"--output={original / 'out'}",
            "objects/b.yaml",
            "/elsewhere/c.yaml",
            "--",
            str(original / "d"),
        ],
        copy,
    )
    assert mapped == [
        "--repo",
        str(copy.root),
        "validate",
        "--file",
        str(copy.root / "objects" / "a.yaml"),
        f"--output={copy.root / 'out'}",
        "objects/b.yaml",
        "/elsewhere/c.yaml",
        "--",
        str(copy.root / "d"),
    ]


def test_changes_are_what_the_run_left_different(tmp_path: Path) -> None:
    original = tmp_path / "ws"
    original.mkdir()
    for name in ("same.txt", "rewritten.txt", "changed.txt", "deleted.txt"):
        (original / name).write_text(name, encoding="utf-8")
    root = tmp_path / "copy"
    shutil.copytree(original, root)
    copy = engines._Copy(original=original.resolve(), root=root)
    before = engines._snapshot(root)
    time.sleep(0.01)
    (root / "rewritten.txt").write_text("rewritten.txt", encoding="utf-8")
    (root / "changed.txt").write_text("other", encoding="utf-8")
    (root / "deleted.txt").unlink()
    (root / "new").mkdir()
    (root / "new" / "file.json").write_bytes(b"{}")
    assert engines._changes(copy, before) == [
        ("changed.txt", (root / "changed.txt").stat().st_mode & 0o7777, b"other"),
        ("deleted.txt", None, None),
        ("new/file.json", (root / "new" / "file.json").stat().st_mode & 0o7777, b"{}"),
    ]


def test_the_report_redacts_secret_arguments(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.context import CliContext

    ctx = CliContext(repo=workspace)
    written = engines._write_report(
        ctx,
        "share push",
        ["share", "push", "--api-key", "s3cr3t-value-1234567890"],
        {"equal": False, "differences": [], "omitted": 0, "approved": []},
    )
    text = Path(written).read_text(encoding="utf-8")
    assert "s3cr3t-value-1234567890" not in text
    assert json.loads(text)["argv"][:3] == ["share", "push", "--api-key"]


def test_help_is_printed_whatever_the_engine(workspace: Path) -> None:
    code, stdout, _ = invoke(["--repo", str(workspace), "validate", "--help"], "rust")
    assert code == 0
    assert "Usage" in stdout


def test_compare_refuses_to_run_outside_the_workspace(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Writes outside the workspace would escape both copies (review of #854)."""
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("file"))
    monkeypatch.chdir(tmp_path)
    code, stdout, _ = invoke(["--json", "--repo", "ws", "explain", "internal"], "compare")
    assert code == 2
    assert document(stdout)["failure"]["code"] == "usage_error"
    assert not (tmp_path / "fake-rust.txt").exists()

    monkeypatch.chdir(workspace)
    outside = str(tmp_path / "elsewhere.md")
    code, stdout, _ = invoke(
        ["--json", "--repo", str(workspace), "explain", "internal", f"--output={outside}"],
        "compare",
    )
    assert code == 2
    assert outside in document(stdout)["failure"]["message"]


def test_an_agreed_compare_is_the_python_run(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its output names the workspace, not a deleted copy, and its writes land in the workspace."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "file"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("info",), fake("file"))
    args = ["--json", "--repo", str(workspace), "info", "rules"]
    code, stdout, _ = invoke(args, "compare")
    python_code, python_stdout, _ = invoke(args, "python")
    assert code == python_code
    assert "opentide-compare-" not in stdout
    assert {**document(stdout), "duration_ms": 0} == {**document(python_stdout), "duration_ms": 0}
    assert (workspace / "fake-rust.txt").read_text(encoding="utf-8") == "written by the fake\n"
    assert not state.exists()


def test_compare_does_not_fail_on_wall_time(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``validate`` prints ``duration_ms`` and ``report.stats.wall_ms``, different in every run."""
    monkeypatch.chdir(workspace)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("validate",), fake("same"))
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "validate"], "compare")
    assert code != 70, stdout
    assert not state.exists()


@pytest.mark.skipif(os.name != "posix", reason="Unix sockets and symlinks")
def test_copies_skip_sockets_and_relink_absolute_links(tmp_path: Path) -> None:
    import socket

    workspace = tmp_path / "ws"
    (workspace / "site").mkdir(parents=True)
    (workspace / "docs").symlink_to(workspace / "site")
    (workspace / "out").symlink_to("/elsewhere")
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(workspace / "daemon.ipc"))
    try:
        copy = engines._copy_workspace(workspace, tmp_path / "scratch" / "python" / "ws")
    finally:
        server.close()
    assert not (copy.root / "daemon.ipc").exists()
    assert os.readlink(copy.root / "docs") == str(copy.root / "site")
    assert os.readlink(copy.root / "out") == "/elsewhere"


def test_a_link_never_equals_a_file(tmp_path: Path) -> None:
    root = tmp_path / "copy"
    root.mkdir()
    copy = engines._Copy(original=(tmp_path / "ws").resolve(), root=root)
    (root / "link").symlink_to("x")
    (root / "file").write_bytes(b"symlink:x")
    (root / "file").chmod(0o777)
    changes = {name: mode for name, mode, _ in engines._changes(copy, {})}
    assert changes["link"] != changes["file"]


def test_rust_mode_does_not_ignore_ctrl_c_for_the_child(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SIG_IGN survives exec; the parent must wait with a handler instead (review of #854)."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import signal, sys\n"
        "sys.exit(3 if signal.getsignal(signal.SIGINT) == signal.SIG_IGN else 0)\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(
        engines.RUST_COMMANDS, ("explain",), RustCommand(launch=(sys.executable, str(probe)))
    )
    code, _, _ = invoke(["--repo", str(workspace), "explain", "internal"], "rust")
    assert code == 0


def test_the_copy_path_maps_back_in_every_form(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "ws").mkdir(parents=True)
    linked = tmp_path / "linked"
    linked.symlink_to(real)
    copy = engines._Copy(original=(tmp_path / "w s").resolve(), root=linked / "ws")
    back = engines._back_to(copy, (tmp_path / "w s").resolve())
    workspace = str((tmp_path / "w s").resolve())
    assert back(str(linked / "ws").encode()) == workspace.encode()
    assert back(str(real / "ws").encode()) == workspace.encode()


def test_compare_refuses_relative_paths_that_leave_the_workspace(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("same"))
    monkeypatch.chdir(workspace)
    code, stdout, _ = invoke(
        ["--json", "--repo", str(workspace), "explain", "internal", "--output=../site"], "compare"
    )
    assert code == 2
    assert "../site" in document(stdout)["failure"]["message"]
    assert engines._outside(["objects/a.yaml", "./b", "x/../y"], workspace) is None
