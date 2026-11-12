"""``opentide.cli.launch:main``: the console script decides what runs before Typer (#960)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import typer.main

from opentide import __version__
from opentide._native import command_words
from opentide.cli import engine_defaults, engines, launch
from opentide.cli.engines import RUST_CLI, RustCommand
from opentide.cli.lazy import command_words as python_command_words
from opentide.cli.root import app

RUST = {"OPENTIDE_ENGINE": "rust"}


@pytest.fixture(autouse=True)
def _keep_the_process_as_it_was(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A run in this process records its launch environment and exports the workspace.

    Both outlive the test (``opentide serve`` starts each run from the launch
    environment): put them back.
    """
    import opentide.cli as cli_package

    monkeypatch.setattr(cli_package, "_launch_environment", None)
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


@pytest.mark.parametrize(
    "argv",
    [
        ["explain", "vocab_unknown"],
        ["--json", "explain", "vocab_unknown"],
        ["explain", "--json", "vocab_unknown"],
        ["--repo", "ws", "--no-color", "generate", "docs", "rules", "--json"],
        ["--repo=ws", "generate", "exports", "navigator"],
        ["generate", "schemas", "templates"],
        ["validate", "query", "--platform", "sentinel", "--live"],
        ["deploy", "--dry-run", "--all"],
        ["setup", "skills", "show", "x"],
        ["mcp", "start"],
        ["serve"],
        ["lsp", "start", "--debug"],
        ["rules", "unreviewed", "--older-than", "30d"],
        ["--proxy", "http://p:1", "info", "catalog"],
        ["validat"],
        ["--", "validate"],
        ["--bogus", "validate"],
        [],
    ],
)
def test_the_rust_tree_names_the_command_path_as_typer_does(argv: list[str]) -> None:
    group = typer.main.get_command(app)
    assert tuple(command_words(argv)) == python_command_words(group, argv)


def test_every_rust_command_path_is_a_path_of_the_rust_tree() -> None:
    for path in engines.RUST_COMMANDS:
        assert tuple(command_words(list(path))) == path


@pytest.mark.parametrize(
    "argv",
    [
        ["explain", "vocab_unknown"],
        ["--json", "--no-color", "--quiet", "--debug", "info"],
        ["--repo", ".", "--json", "validate"],
        ["--repo=.", "lint"],
        ["--data", "d", "--proxy", "http://p:1", "explain", "x"],
        ["deploy", "--dry-run", "--all"],
        ["doctor", "--offline"],
        ["doctor"],
        ["deploy", "migrate-state"],
        ["share", "push"],
        ["share", "--dry-run"],
        ["share", "targets"],
        ["generate", "extract", "defender"],
        ["generate", "extract", "elastic", "--space", "soc"],
        ["generate", "extract", "sentinel"],
        ["generate", "schemas"],
        ["serve"],
        ["mcp", "start"],
        ["setup", "--path", "missing", "--yes"],
        ["--repo", "missing", "setup", "env"],
        ["explain", "--", "--help"],
    ],
)
def test_rust_runs_what_the_dispatcher_would_give_it(argv: list[str]) -> None:
    assert launch.runs_on_rust(argv, RUST)


@pytest.mark.parametrize(
    ("argv", "why"),
    [
        (["explain", "vocab_unknown", "--help"], "help is the command tree's"),
        (["--help"], "help"),
        ([], "no command: the help"),
        (["--version"], "answered before the callback"),
        (["-V", "explain"], "answered before the callback"),
        (["--install-completion"], "Typer's own option"),
        (["--bogus", "explain", "x"], "a root option the root does not know"),
        (["--json=1", "explain", "x"], "a flag given a value"),
        (["--repo"], "a root option without its value"),
        (["--repo", "missing", "validate"], "the root refuses a --repo that is no folder"),
        (["--repo=missing", "validate"], "the same, written with ="),
        (["deploy", "--all"], "a deploy that sends to no named platform is Python's"),
        (["validate", "query", "--live"], "--live is Python's"),
        (["generate"], "the full pipeline"),
        (["setup", "--plugin", "x"], "setup with --plugin is Python's"),
        (["validat"], "no command: Click's suggestion"),
        (["tui-x"], "no command"),
    ],
)
def test_everything_else_goes_to_the_python_cli(argv: list[str], why: str) -> None:
    assert not launch.runs_on_rust(argv, RUST), why


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"OPENTIDE_ENGINE": ""},
        {"OPENTIDE_ENGINE": "python"},
        {"OPENTIDE_ENGINE": "compare"},
        {"OPENTIDE_ENGINE": "rsut"},
        {"OPENTIDE_ENGINE": "rust", "_OPENTIDE_COMPLETE": "bash_complete"},
    ],
)
def test_other_engines_and_completion_go_to_the_python_cli(env: dict[str, str]) -> None:
    assert not launch.runs_on_rust(["--json", "explain", "vocab_unknown"], env)


def test_a_flipped_default_runs_rust_and_python_is_the_escape_hatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    assert launch.runs_on_rust(["explain", "x"], {})
    assert not launch.runs_on_rust(["explain", "x"], {"OPENTIDE_ENGINE": "python"})
    assert not launch.runs_on_rust(["info"], {})


def test_a_stand_in_rust_command_goes_through_the_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the command line compiled in runs here; a stand-in runs as the dispatcher runs it."""
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), RustCommand(launch=("x",)))
    assert not launch.runs_on_rust(["explain", "x"], RUST)
    monkeypatch.setitem(engines.RUST_COMMANDS, ("explain",), RustCommand(launch=RUST_CLI))
    assert launch.runs_on_rust(["explain", "x"], RUST)


def test_a_failing_decision_hands_the_run_to_python(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(args: object, env: object) -> bool:
        raise RuntimeError("no tree")

    monkeypatch.setattr(launch, "runs_on_rust", broken)
    assert launch.main(["--version"]) == 0
    assert capsys.readouterr().out == f"opentide {__version__}\n"


def test_the_python_cli_exit_code_is_returned(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert launch.main(["--repo", str(missing), "--json", "info"]) == 2


def _run(
    argv: list[str], env: dict[str, str], cwd: Path, *command: str
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*command, *argv], cwd=cwd, env=env, capture_output=True, check=False, timeout=120
    )


def _environment(**extra: str) -> dict[str, str]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in {"OPENTIDE_ENGINE", "OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"}
    }
    env.update({"NO_COLOR": "1", **extra})
    return env


def _timeless(run: subprocess.CompletedProcess[bytes]) -> tuple[bytes, bytes]:
    return tuple(
        re.sub(rb'"duration_ms":\s*\d+', b'"duration_ms":0', out)
        for out in (run.stdout, run.stderr)
    )


@pytest.mark.parametrize("engine", [None, "python", "rust", "compare", "rsut"])
@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "explain", "vocab_unknown"],
        ["explain", "vocab_unknown"],
        ["--json", "deploy", "--all"],
        ["--json", "validate", "--bogus"],
        ["--repo", "missing", "--json", "validate"],
        ["--json", "info", "catalog"],
        ["--version"],
    ],
)
def test_the_console_script_answers_as_the_typer_entry_point(
    tmp_path: Path, engine: str | None, argv: list[str]
) -> None:
    """The console script prints and exits as ``opentide.cli:main``, the old script.

    Wall time (``duration_ms``) is the one thing two runs may not share.
    """
    env = _environment(**({} if engine is None else {"OPENTIDE_ENGINE": engine}))
    new = _run(argv, env, tmp_path, sys.executable, "-m", "opentide")
    old = _run(argv, env, tmp_path, sys.executable, "-c", "from opentide.cli import main; main()")
    assert (new.returncode, *_timeless(new)) == (old.returncode, *_timeless(old))
    if engine == "rust" and "explain" in argv:
        assert new.returncode == 0, new.stderr
    if engine == "rust" and "deploy" in argv:
        assert json.loads(new.stdout)["failure"]["code"] == "engine_not_ported"


_CHILDREN = """
import json, os, sys
from opentide import cli
from opentide.cli import rust

seen = []
original = rust.run_in_process


def spy(argv, env=None):
    seen.append((list(argv), (env or os.environ).get("OPENTIDE_ENGINE")))
    return original(argv, env)


rust.run_in_process = spy
import subprocess
spawned = []
real = subprocess.Popen.__init__


def record(self, args, *rest, **kwargs):
    spawned.append(args)
    real(self, args, *rest, **kwargs)


subprocess.Popen.__init__ = record
from opentide._native import main

code = main(sys.argv[1:])
sys.stdout.flush()
print(json.dumps({"code": code, "seen": seen, "spawned": [list(map(str, a)) for a in spawned],
                  "typer": "typer" in sys.modules}), file=sys.stderr)
"""


def test_a_rust_run_starts_no_child_and_loads_no_typer(tmp_path: Path) -> None:
    result = _run(
        ["--json", "explain", "vocab_unknown"],
        _environment(OPENTIDE_ENGINE="rust"),
        tmp_path,
        sys.executable,
        "-c",
        _CHILDREN,
    )
    report = json.loads(result.stderr.decode().strip().splitlines()[-1])
    assert report == {
        "code": 0,
        "seen": [[["--json", "explain", "vocab_unknown"], "rust"]],
        "spawned": [],
        "typer": False,
    }
    assert json.loads(result.stdout)["code"] == "vocab_unknown"


def test_a_flipped_default_runs_with_the_engine_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dispatcher started the Rust command line with ``OPENTIDE_ENGINE=rust``; so does this."""
    seen: list[str | None] = []
    monkeypatch.setitem(engine_defaults.DEFAULT_ENGINES, ("explain",), "rust")
    monkeypatch.delenv("OPENTIDE_ENGINE", raising=False)
    monkeypatch.setattr(
        "opentide.cli.rust.run_in_process",
        lambda argv, env=None: seen.append((env or {}).get("OPENTIDE_ENGINE")) or 0,
    )
    assert launch.main(["explain", "vocab_unknown"]) == 0
    assert seen == ["rust"]
    assert "OPENTIDE_ENGINE" not in os.environ


def test_the_engine_runs_in_the_environment_it_is_given_and_puts_this_one_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.cli import rust

    seen: dict[str, str | None] = {}

    def fake(argv: list[str], version: str) -> int:
        seen.update(
            engine=os.environ.get("OPENTIDE_ENGINE"),
            kept=os.environ.get("OPENTIDE_TEST_KEPT"),
            added=os.environ.get("OPENTIDE_TEST_ADDED"),
        )
        return 3

    monkeypatch.setattr("opentide._native.cli_main", fake)
    monkeypatch.setenv("OPENTIDE_TEST_KEPT", "here")
    before = dict(os.environ)
    code = rust.run_in_process(
        ["info"], {"OPENTIDE_ENGINE": "rust", "OPENTIDE_TEST_ADDED": "1", "PATH": "x"}
    )
    assert code == 3
    assert seen == {"engine": "rust", "kept": None, "added": "1"}
    assert dict(os.environ) == before


def test_without_the_engine_the_python_cli_answers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The console script falls back to the Python CLI when ``_native`` does not import."""
    from opentide.analysis import engine

    engine.cache_clear()
    monkeypatch.setitem(sys.modules, "opentide._native", None)
    monkeypatch.setattr(
        launch, "run", lambda argv=None: pytest.fail("the engine's path ran without the engine")
    )
    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    try:
        assert launch.main(["--json", "explain", "vocab_unknown"]) == 1
    finally:
        engine.cache_clear()
    assert json.loads(capsys.readouterr().out)["failure"]["code"] == "engine_unavailable"


def test_a_run_python_answers_alone_does_not_load_the_engine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "opentide._native", None)
    for env in ({}, RUST):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        assert launch.main(["--version"]) == 0
        assert capsys.readouterr().out == f"opentide {__version__}\n"


def test_with_the_engine_the_console_script_goes_through_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str] | None] = []
    monkeypatch.setattr("opentide._native.main", lambda argv=None: seen.append(argv) or 7)
    monkeypatch.setenv("OPENTIDE_ENGINE", "rust")
    assert launch.main(["info"]) == 7
    assert seen == [["info"]]
