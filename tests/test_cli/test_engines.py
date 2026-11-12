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

from opentide.cli import app, engine_defaults, engines
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


#: A command line with no Rust implementation: ``setup --plugin`` (``setup``
#: itself runs on Rust since UC-3.6, #828, and ``setup vscode`` since UC-3.6c,
#: #951; installing the skills and the plugin stays Python's).
UNPORTED = ("setup", "--plan", "--plugin")


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
    args = ["--json", "--repo", str(workspace), *UNPORTED]
    assert invoke(args, "rust")[0] == 2
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    assert invoke(args, None)[0] != 2


def test_rust_on_a_command_without_rust_is_engine_not_ported(workspace: Path) -> None:
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), *UNPORTED], "rust")
    assert code == 2
    doc = document(stdout)
    assert doc["exit_code"] == 2
    assert doc["command"] == "setup"
    assert doc["failure"]["code"] == "engine_not_ported"
    assert doc["failure"]["argument"] == "OPENTIDE_ENGINE"
    message = doc["failure"]["message"]
    assert "opentide setup with --plugin has no Rust implementation yet" in message
    assert stdout.endswith("}\n") and stdout.count("\n") == 1


def test_rust_on_a_subcommand_names_its_path(workspace: Path) -> None:
    code, stdout, _ = invoke(
        ["--json", "--repo", str(workspace), "validate", "query", "--platform", "x"], "rust"
    )
    assert code == 2
    assert document(stdout)["command"] == "validate query"


def test_rust_without_json_is_one_error_line(workspace: Path) -> None:
    code, stdout, stderr = invoke(["--no-color", "--repo", str(workspace), *UNPORTED], "rust")
    assert code == 2
    assert stdout == ""
    assert "error: opentide setup with --plugin has no Rust implementation yet" in stderr


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
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), *UNPORTED], engine)
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


def test_a_rust_command_that_requires_a_flag_covers_only_runs_with_it() -> None:
    command = RustCommand(launch=("x",), requires=("--dry-run",))
    assert command.covers(["deploy", "--strategy", "PREVIEW", "--dry-run"])
    assert not command.covers(["deploy", "--strategy", "PREVIEW"])
    # After ``--`` it is an argument, not the flag.
    assert not command.covers(["deploy", "--", "--dry-run"])
    assert RustCommand(launch=("x",)).covers(["info"])
    assert engines.RUST_COMMANDS[("deploy",)].requires == ("--dry-run",)
    # ``doctor`` reaches PyPI and the proxy without ``--offline``: that run stays Python's.
    doctor = engines.RUST_COMMANDS[("doctor",)]
    assert doctor.requires == ("--offline",)
    assert doctor.rules == ("host-git",)
    assert doctor.covers(["doctor", "--offline"])
    assert not doctor.covers(["doctor"])


def test_generate_is_rust_only_with_a_phase_named() -> None:
    """``generate <phase>`` runs on Rust; a bare ``generate`` (the full pipeline) stays Python's."""
    generate = engines.RUST_COMMANDS[("generate",)]
    assert generate.requires == ("schemas", "templates", "vocabs", "snippets")
    assert generate.covers(["generate", "schemas"])
    assert generate.covers(["generate", "templates", "vocabs"])
    assert generate.covers(["generate", "snippets", "--json"])
    assert not generate.covers(["generate"])
    assert not generate.covers(["generate", "--help"])
    # After ``--`` it is an argument, not a phase.
    assert not generate.covers(["generate", "--", "schemas"])
    # The named subcommands have their own entries, without requires.
    assert engines.RUST_COMMANDS[("generate", "docs")].requires == ()


def test_a_bare_generate_stays_python(workspace: Path) -> None:
    """``OPENTIDE_ENGINE=rust`` refuses a bare ``generate`` by name: it is not ported."""
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "generate"], "rust")
    assert code == 2
    doc = document(stdout)
    assert doc["command"] == "generate"
    assert doc["failure"]["code"] == "engine_not_ported"
    assert (
        "opentide generate without schemas or templates or vocabs or snippets "
        "has no Rust implementation yet" in doc["failure"]["message"]
    )
    # Unset, Python runs it: no refusal.
    assert engines.selected(("generate",), {}) == engines.PYTHON


def test_a_rust_command_that_refuses_a_flag_covers_only_runs_without_it() -> None:
    command = RustCommand(launch=("x",), refuses=("--live",))
    assert command.covers(["validate", "query", "--platform", "elastic"])
    assert not command.covers(["validate", "query", "--live", "--platform", "elastic"])
    # After ``--`` it is an argument, not the flag.
    assert command.covers(["validate", "query", "--", "--live"])
    assert command.uncovered("validate query", ["--live"]) == "validate query with --live"
    assert engines.RUST_COMMANDS[("setup",)].refuses == ("--skills", "--plugin")
    assert not engines.RUST_COMMANDS[("setup",)].covers(["setup", "--skills"])


def test_a_command_that_reaches_tenants_is_routed_by_the_platforms_it_names() -> None:
    """``query`` runs on Rust where every ``--platform`` it names has a Rust connector."""
    query = engines.RUST_COMMANDS[("query",)]
    assert query.platforms == engines.RUST_QUERY_PLATFORMS
    assert query.side_effects
    for platform in ("crowdstrike", "defender_for_endpoint", "elastic", "harfanglab"):
        assert query.covers(["query", "--platform", platform, "x"])
    assert query.covers(["query", "--platform=sentinel_one", "x"])
    # The SDK platforms (UC-4.3, #833).
    for platform in ("sentinel", "splunk", "carbon_black_cloud"):
        assert query.covers(["query", "--platform", platform, "x"])
    assert not query.covers(["query", "--platform", "sysdig", "x"])
    assert query.uncovered("query", ["--platform", "sysdig"]) == "query on sysdig"
    # Every platform it names counts; none named is the workspace's to say.
    assert not query.covers(["query", "--platform", "elastic", "--platform", "sysdig"])
    assert query.covers(["query", "--platform", "elastic", "--platform", "splunk"])
    assert not query.covers(["query", "x"])
    assert query.uncovered("query", ["x"]) == "query without --platform"
    # After ``--`` it is an argument, not the flag.
    assert not query.covers(["query", "--", "--platform", "elastic"])
    # A rule's query carries its tenants' exclusions: Python's.
    assert not query.covers(["query", "--platform", "elastic", "--rule", "x"])
    assert not query.covers(["query", "--platform", "elastic", "--file", "r.yaml"])


def test_validate_query_is_routed_by_platform_with_live_only() -> None:
    """Offline, every platform is Rust's; ``--live`` only where no tenant check is sent."""
    command = engines.RUST_COMMANDS[("validate", "query")]
    assert command.platform_scope == ("--live",)
    assert command.covers(["validate", "query", "--platform", "sentinel"])
    assert command.covers(["validate", "query"])
    for platform in ("crowdstrike", "harfanglab", "sysdig"):
        assert command.covers(["validate", "query", "--live", "--platform", platform])
    for platform in ("elastic", "defender_for_endpoint", "sentinel_one", "sentinel", "splunk"):
        assert not command.covers(["validate", "query", "--live", "--platform", platform])
    assert not command.covers(["validate", "query", "--live"])
    assert (
        command.uncovered("validate query", ["--live", "--platform", "elastic"])
        == "validate query --live on elastic"
    )
    uncovered = command.uncovered("validate query", ["--live"])
    assert uncovered == "validate query --live without --platform"


def test_rust_refuses_validate_query_live_and_compare_runs_python_alone(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``validate query --live`` on a tenant that checks queries stays Python's (#832)."""
    launch = (sys.executable, str(FAKE), "exit")
    monkeypatch.setitem(
        engines.RUST_COMMANDS,
        ("validate", "query"),
        RustCommand(
            launch=launch,
            platforms=engines.RUST_LIVE_VALIDATION_PLATFORMS,
            platform_scope=("--live",),
        ),
    )
    args = ["--json", "--repo", str(workspace), "validate", "query", "--live"]
    args += ["--platform", "elastic"]
    code, stdout, _ = invoke(args, "rust")
    doc = document(stdout)
    assert code == 2
    assert doc["failure"]["code"] == "engine_not_ported"
    assert (
        "opentide validate query --live on elastic has no Rust implementation yet"
        in (doc["failure"]["message"])
    )
    # compare never starts the (failing) fake: Python's answer is the result.
    python_code, python_stdout, _ = invoke(args, "python")
    code, stdout, _ = invoke(args, "compare")
    assert code == python_code
    assert document(stdout)["failure"] == document(python_stdout)["failure"]


def test_rust_refuses_a_query_on_a_platform_without_a_connector(workspace: Path) -> None:
    """``query --platform sysdig`` has no Rust query runner: refused, never half-run."""
    args = ["--json", "--repo", str(workspace), "query", "--platform", "sysdig", "T"]
    code, stdout, _ = invoke(args, "rust")
    doc = document(stdout)
    assert code == 2
    assert doc["failure"]["code"] == "engine_not_ported"
    assert "opentide query on sysdig has no Rust implementation yet" in doc["failure"]["message"]


def test_rust_output_reaches_a_stream_that_lives_in_memory(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Click's runner (or a host's capture) replaces stdout: the Rust run's document lands there."""
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("same"))
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "rust")
    assert code == 0
    assert document(stdout)["command"] == "explain"


def test_rust_reads_a_stdin_that_lives_in_memory(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Click's runner (or a host) replaces stdin: the Rust run reads what it holds."""
    echo = (sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())")
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), RustCommand(launch=echo))
    result = CliRunner().invoke(
        app,
        ["--json", "--repo", str(workspace), "explain", "internal"],
        input="given on stdin\n",
        env={"OPENTIDE_ENGINE": "rust"},
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert result.stdout == "given on stdin\n"


def test_rust_refuses_a_run_its_implementation_does_not_cover(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``deploy`` without ``--dry-run`` has no Rust implementation: refused by name."""
    monkeypatch.setitem(
        engines.RUST_COMMANDS, ("explain",), RustCommand(launch=("x",), requires=("--never",))
    )
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "rust")
    assert code == 2
    doc = document(stdout)
    assert doc["command"] == "explain"
    assert doc["failure"]["code"] == "engine_not_ported"
    assert (
        "opentide explain without --never has no Rust implementation yet"
        in doc["failure"]["message"]
    )


def test_compare_runs_python_alone_where_rust_does_not_cover_the_run(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A launch that would fail if it ran: compare must not start it.
    monkeypatch.setitem(
        engines.RUST_COMMANDS,
        ("explain",),
        RustCommand(launch=(sys.executable, str(FAKE), "exit"), requires=("--never",)),
    )
    args = ["--json", "--repo", str(workspace), "explain", "internal"]
    code, stdout, _ = invoke(args, "compare")
    assert code == 0
    assert document(stdout)["ok"] is True


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
    (root / "same.txt").chmod(0o600)  # V854-S-7: a mode change alone is a change
    assert engines._changes(copy, before) == [
        ("changed.txt", (root / "changed.txt").stat().st_mode & 0o7777, b"other"),
        ("deleted.txt", None, None),
        ("new/file.json", (root / "new" / "file.json").stat().st_mode & 0o7777, b"{}"),
        ("same.txt", 0o600, b"same.txt"),
    ]


def test_the_report_redacts_secret_arguments(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli.context import CliContext

    # V854-S-2: a difference's excerpts are redacted too: a secret from the
    # environment and a tenant named in the workspace's configuration.
    monkeypatch.setenv("SENTINEL_CLIENT_SECRET", "env-secret-value-0987654321")
    platforms = workspace / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True, exist_ok=True)
    (platforms / "sentinel.toml").write_text(
        '[[tenants]]\nname = "contoso-prod-tenant"\n', encoding="utf-8"
    )
    ctx = CliContext(repo=workspace)
    difference = {
        "target": "stdout",
        "kind": "bytes",
        "oracle": "token env-secret-value-0987654321 on contoso-prod-tenant",
        "candidate": "tenant contoso-prod-tenant",
    }
    written = engines._write_report(
        ctx,
        "share push",
        ["share", "push", "--api-key", "s3cr3t-value-1234567890"],
        {"equal": False, "differences": [difference], "omitted": 0, "approved": []},
    )
    text = Path(written).read_text(encoding="utf-8")
    for secret in ("s3cr3t-value-1234567890", "env-secret-value-0987654321", "contoso-prod-tenant"):
        assert secret not in text, secret
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


def test_compare_runs_python_alone_where_rust_refuses_the_input(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Rust run refused with ``engine_not_ported`` (``generate docs`` on CVE details) is no
    mismatch: the Python run is the result, its writes in the workspace, the refused run's not."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "file"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("info",), fake("refuse"))
    args = ["--json", "--repo", str(workspace), "info", "rules"]
    code, stdout, _ = invoke(args, "compare")
    python_code, python_stdout, _ = invoke(args, "python")
    assert code == python_code == 0
    assert {**document(stdout), "duration_ms": 0} == {**document(python_stdout), "duration_ms": 0}
    assert (workspace / "fake-rust.txt").read_text(encoding="utf-8") == "written by the fake\n"
    assert not state.exists()
    # Without the record, the same run is a mismatch: the refusal file is the signal.
    (workspace / "fake-rust.txt").unlink()
    monkeypatch.setattr(engines, "REFUSAL_ENV", "OPENTIDE_NOT_THE_REFUSAL_FILE")
    code, stdout, _ = invoke(args, "compare")
    assert code == 70
    assert document(stdout)["failure"]["code"] == "engine_mismatch"
    assert not (workspace / "fake-rust.txt").exists()


def test_rust_mode_shows_the_refusal(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``rust`` runs the Rust implementation alone: its refusal is the result, recorded nowhere."""
    monkeypatch.chdir(workspace)
    monkeypatch.delenv("OPENTIDE_ENGINE_REFUSAL", raising=False)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("info",), fake("refuse"))
    code, _, _ = invoke(["--json", "--repo", str(workspace), "info", "rules"], "rust")
    assert code == 2
    assert (workspace / "fake-rust.txt").exists()


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


def test_engine_unavailable_keeps_exit_1_and_its_meaning(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``engine_unavailable`` is the compiled engine not loading (exit 1), never the dispatch's."""
    from opentide import analysis

    def missing() -> None:
        raise analysis.EngineUnavailableError("hidden by the test")

    monkeypatch.setattr(analysis, "engine", missing)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("same"))
    monkeypatch.chdir(workspace)
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "compare")
    assert code == 1
    failure = document(stdout)["failure"]
    assert failure["code"] == "engine_unavailable"
    assert failure["message"].startswith("The opentide analysis engine does not load")
    page = Path(analysis.__file__).parent / "data" / "diagnostics" / "engine_unavailable.md"
    assert "OPENTIDE_ENGINE" not in page.read_text(encoding="utf-8")


def test_an_agreeing_compare_shows_the_python_run(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-S-1: equal after normalisation, different in every byte the user gets."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "raw-python"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("raw"))
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "compare")
    assert code == 0, stdout
    assert document(stdout)["duration_ms"] == 1
    assert (workspace / "marker.json").read_text(encoding="utf-8") == '{"duration_ms":1}\n'
    assert not state.exists()


def test_compare_normalises_the_week_before_the_run(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-A-2: date-times of yesterday (a default window) are the clock, as in the goldens."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "recent"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("recent"))
    for _ in range(3):  # each run picks its own second: a pass is never luck
        code, stdout, _ = invoke(
            ["--no-color", "--repo", str(workspace), "explain", "internal"], "compare"
        )
        assert code == 0, stdout
    assert not state.exists()


def test_compare_applies_the_commands_rules(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-I-3: a command that mints UUIDs compares equal with ``fresh-uuids``, not without."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "uuid"))
    args = ["--no-color", "--repo", str(workspace), "explain", "internal"]
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("uuid"))
    assert invoke(args, "compare")[0] == 70
    minting = RustCommand(launch=fake("uuid").launch, rules=("fresh-uuids",))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), minting)
    assert invoke(args, "compare")[0] == 0


def test_compare_refuses_a_command_with_side_effects(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-I-5: a tenant would be reached twice, and nothing would compare it."""
    monkeypatch.chdir(workspace)
    reaching = RustCommand(launch=fake("same").launch, side_effects=True)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), reaching)
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "compare")
    assert code == 2
    failure = document(stdout)["failure"]
    assert failure["code"] == "usage_error"
    assert "reaches outside the workspace" in failure["message"]


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_an_agreed_deletion_and_mode_change_reach_the_workspace(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-S-6: what both runs did to existing files is done to the workspace."""
    (workspace / "delete-me.txt").write_text("x", encoding="utf-8")
    (workspace / "chmod-me.txt").write_text("y", encoding="utf-8")
    (workspace / "chmod-me.txt").chmod(0o644)
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "mutate"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("mutate"))
    code, stdout, _ = invoke(
        ["--no-color", "--repo", str(workspace), "explain", "internal"], "compare"
    )
    assert code == 0, stdout
    assert not (workspace / "delete-me.txt").exists()
    assert (workspace / "chmod-me.txt").stat().st_mode & 0o777 == 0o600
    assert (workspace / "chmod-me.txt").read_text(encoding="utf-8") == "y"


@pytest.mark.skipif(os.name != "posix", reason="signals")
def test_an_agreed_signal_exit_is_128_plus_n(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V854-I-7: both runs end on SIGTERM: the command exits 143, as a shell reports it."""
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(engines, "python_launch", lambda: (sys.executable, str(FAKE), "sigterm"))
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("sigterm"))
    code, _, _ = invoke(["--no-color", "--repo", str(workspace), "explain", "internal"], "compare")
    assert code == 143


# --- per-command defaults and the escape hatch (plan §7, #822) -------------------------


def test_every_default_is_python_or_a_ported_rust_command() -> None:
    """A command flips to rust only once it has a Rust implementation to run."""
    for path, engine in engine_defaults.DEFAULT_ENGINES.items():
        assert engine in (engines.PYTHON, engines.RUST), path
        if engine == engines.RUST:
            assert path in engines.RUST_COMMANDS, path


def test_the_variable_wins_over_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("same"))
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    assert engines.selected(("explain",), {}) == "rust"
    assert engines.selected(("explain",), {"OPENTIDE_ENGINE": " "}) == "rust"
    assert engines.selected(("explain",), {"OPENTIDE_ENGINE": "python"}) == "python"
    assert engines.selected(("explain",), {"OPENTIDE_ENGINE": "compare"}) == "compare"
    assert engines.selected(("validate",), {}) == "python"
    assert engines.rust_command(("explain",), {}) is engines.RUST_COMMANDS[("explain",)]
    assert engines.rust_command(("explain",), {"OPENTIDE_ENGINE": "python"}) is None
    assert engines.rust_command(("explain",), {"OPENTIDE_ENGINE": "compare"}) is None


def test_a_host_runs_rust_only_for_a_run_its_implementation_covers() -> None:
    """``serve`` asks with the run's arguments: an uncovered run goes to the dispatcher."""
    rust = {"OPENTIDE_ENGINE": "rust"}
    doctor = engines.RUST_COMMANDS[("doctor",)]
    assert engines.rust_command(("doctor",), rust, ["doctor", "--offline"]) is doctor
    assert engines.rust_command(("doctor",), rust, ["doctor"]) is None
    assert engines.rust_command(("doctor",), rust, ["doctor", "--", "--offline"]) is None
    deploy = engines.RUST_COMMANDS[("deploy",)]
    assert engines.rust_command(("deploy",), rust, ["deploy", "--dry-run"]) is deploy
    assert engines.rust_command(("deploy",), rust, ["deploy"]) is None
    assert engines.rust_command(("info",), rust, ["info"]) is engines.RUST_COMMANDS[("info",)]


def test_a_rust_default_without_a_rust_implementation_runs_python(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # explain has a Rust implementation (UC-3.5): take it away for this test.
    monkeypatch.delitem(engines.RUST_COMMANDS, ("explain",))
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    assert engines.selected(("explain",), {}) == "python"
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], None)
    assert code == 0
    assert document(stdout)["failure"] is None


def test_the_root_reads_a_default_only_for_the_commands_it_names() -> None:
    defaults = engine_defaults.DEFAULT_ENGINES
    assert not engine_defaults.any_default(("explain", "internal"))
    defaults[("generate", "exports")] = "rust"
    try:
        assert engine_defaults.any_default(("generate", "exports", "objects"))
        assert not engine_defaults.any_default(("generate",))
        defaults[("generate", "exports")] = "python"
        assert not engine_defaults.any_default(("generate", "exports"))
    finally:
        del defaults[("generate", "exports")]


@pytest.mark.parametrize(
    ("engine", "delta"),
    [(None, 1), ("", 1), ("rust", 1), ("python", 0)],
)
def test_a_flipped_default_runs_rust_and_python_is_the_escape_hatch(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, engine: str | None, delta: int
) -> None:
    """Both settings of the switch: the default (rust once flipped) and ``python``."""
    args = ["--json", "--repo", str(workspace), "explain", "internal"]
    python = invoke(args, "python")[0]
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("exit"))
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    # The fake's exit code is one more than Python's: it tells who ran.
    assert invoke(args, engine)[0] == python + delta


def test_compare_still_compares_a_flipped_command(
    workspace: Path, state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(workspace)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), fake("exit"))
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    code, stdout, _ = invoke(["--json", "--repo", str(workspace), "explain", "internal"], "compare")
    assert code == 70
    assert document(stdout)["failure"]["code"] == "engine_mismatch"


def test_compare_running_python_alone_keeps_the_library_on_python(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``validate`` has no Rust CLI yet: under compare its run_validation is Python's, once."""
    from opentide.validation import engine as validation_engine

    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("the SDK's Rust validate ran inside a Python-only command")

    monkeypatch.setattr(validation_engine, "run_rust", refuse)
    monkeypatch.chdir(workspace)
    args = ["--json", "--repo", str(workspace), "validate"]
    expected = document(invoke(args, "python")[1])
    code, stdout, _ = invoke(args, "compare")
    doc = document(stdout)
    assert code == expected["exit_code"]
    assert doc["failure"] == expected["failure"]
    assert doc["report"]["issues"] == expected["report"]["issues"]


def test_hosts_run_under_any_engine_but_not_a_bad_one(workspace: Path) -> None:
    """``serve`` and ``mcp start`` apply the engine to what they run, not to themselves."""
    assert ("serve",) in engines.ENGINE_HOSTS
    assert ("mcp", "start") in engines.ENGINE_HOSTS
    # One server per editor session: compare runs the Python host alone.
    assert ("lsp", "start") in engines.ENGINE_HOSTS
    assert ("lsp", "start") in engines.RUST_COMMANDS
    # A full-screen UI cannot run twice: compare opens the Python one.
    assert ("tui",) in engines.ENGINE_HOSTS
    assert ("tui",) in engines.RUST_COMMANDS
    # serve's stdout is the protocol's: the refusal is a line on stderr.
    code, stdout, stderr = invoke(["--json", "--repo", str(workspace), "serve"], "Rust")
    assert (code, stdout) == (2, "")
    assert "OPENTIDE_ENGINE=Rust is not an engine" in stderr


@pytest.mark.parametrize(
    ("engine", "rust_runs"),
    [(None, False), ("python", False), ("compare", False), ("rust", True)],
)
def test_mcp_start_is_the_rust_server_under_rust_and_the_python_host_otherwise(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, engine: str | None, rust_runs: bool
) -> None:
    """``mcp start`` (UC-3.7, #829): ``rust`` serves from Rust; otherwise Python hosts.

    Under ``compare`` an MCP call answers with Python's result and records how
    Rust differs (#822), so the Python server is the host there too.
    """
    assert ("mcp", "start") in engines.RUST_COMMANDS
    monkeypatch.setitem(engines.RUST_COMMANDS, ("mcp", "start"), fake("exit"))
    served: list[bool] = []
    monkeypatch.setattr("opentide.mcp_server.launcher.main", lambda: served.append(True))
    code, _, _ = invoke(["--repo", str(workspace), "mcp", "start"], engine)
    assert served == ([] if rust_runs else [True])
    # The fake runs the Python server on an empty stdin (exit 0) and adds one.
    assert code == (1 if rust_runs else 0)
