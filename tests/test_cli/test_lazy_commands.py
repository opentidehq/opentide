"""Root commands load on demand; help, completion and --version import no engine."""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import typer.main
from typer.testing import CliRunner

import opentide.cli as cli_package
from opentide import __version__
from opentide.cli.commands import ROOT_COMMANDS
from opentide.cli.completion import INDEXED_OPTIONS
from opentide.cli.lazy import LazyTyperGroup

runner = CliRunner()

# Under GITHUB_ACTIONS (or FORCE_COLOR) Typer forces a terminal for help, so
# names arrive wrapped in SGR escapes even with NO_COLOR set.
_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _SGR.sub("", text)


# Modules a listing must not pull in: the engine, platforms, setup and the
# command modules themselves.
_ENGINE_PREFIXES = (
    "opentide.registry",
    "opentide.core.registry",
    "opentide.models",
    "opentide.platforms",
    "opentide.cli.services",
    "opentide.cli.setup_app",
    "opentide.cli.share_app",
    "opentide.cli.rules_app",
    "opentide.cli.mcp_app",
    "opentide.cli.commands.",
)

_LOADED_MODULES = """
import json
import re
import sys

from opentide.cli import main

sys.argv[0] = "opentide"  # completion reads _OPENTIDE_COMPLETE, named after the program

try:
    main()
except SystemExit:
    pass
sys.stdout.flush()
print("\\n" + json.dumps(sorted(sys.modules)), file=sys.stderr)
"""


def _modules_after(
    argv: list[str], *, cwd: str | None = None, **env: str
) -> tuple[subprocess.CompletedProcess[str], set]:
    """Run ``main()`` with *argv* in a fresh interpreter; return what it imported."""
    done = subprocess.run(
        [sys.executable, "-c", _LOADED_MODULES, *argv],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
        env={**os.environ, "NO_COLOR": "1", **env},
    )
    modules = set(json.loads(done.stderr.strip().splitlines()[-1]))
    return done, modules


def _engine_modules(modules: set) -> list[str]:
    return sorted(m for m in modules if m.startswith(_ENGINE_PREFIXES))


def _root() -> LazyTyperGroup:
    group = typer.main.get_command(cli_package.app)
    assert isinstance(group, LazyTyperGroup)
    return group


def _first_paragraph(text: str | None) -> str:
    return inspect.cleandoc(text or "").split("\n\n")[0]


@pytest.mark.parametrize("spec", ROOT_COMMANDS, ids=[spec.name for spec in ROOT_COMMANDS])
def test_index_entry_matches_the_command_it_loads(spec) -> None:
    """The index is what --help shows; it must say what the command says."""
    command = _root().get_command(None, spec.name)  # ty: ignore[invalid-argument-type]
    assert command is not None
    assert command.name == spec.name
    assert _first_paragraph(command.short_help or command.help) == spec.help
    assert command.hidden is spec.hidden
    # Typer leaves an unset panel as a falsy placeholder.
    assert (getattr(command, "rich_help_panel", None) or None) == spec.rich_help_panel


def test_root_help_from_the_index_matches_the_loaded_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same panels, order and text whether the listing reads the index or the commands."""
    env = {"NO_COLOR": "1", "COLUMNS": "100", "TERMINAL_WIDTH": "100"}
    from_index = runner.invoke(cli_package.app, ["--help"], env=env)
    monkeypatch.setattr(LazyTyperGroup, "_list_from_index", lambda self: contextlib.nullcontext())
    from_commands = runner.invoke(cli_package.app, ["--help"], env=env)
    assert from_index.exit_code == from_commands.exit_code == 0
    assert from_index.stdout == from_commands.stdout
    for spec in ROOT_COMMANDS:
        assert (f" {spec.name} " in _plain(from_index.stdout)) is not spec.hidden, spec.name


def test_unknown_command_still_suggests_the_closest_name() -> None:
    result = runner.invoke(cli_package.app, ["validat"])
    assert result.exit_code == 2
    assert "did you mean 'validate'?" in _plain(result.stderr)


def test_version_imports_neither_typer_nor_the_registry() -> None:
    done, modules = _modules_after(["--json", "--version"])
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"opentide {__version__}\n"
    for name in ("typer", "click", "rich", "structlog"):
        assert name not in modules, name
    assert _engine_modules(modules) == []


@pytest.mark.parametrize(
    "argv",
    [["--help"], ["--no-color", "--json", "--help"], []],
    ids=["help", "help-with-flags", "no-args"],
)
def test_root_help_imports_no_engine_module(argv: list[str]) -> None:
    done, modules = _modules_after(argv)
    assert "validate" in _plain(done.stdout), done.stderr
    assert _engine_modules(modules) == []


def test_home_screen_imports_no_engine_module(tmp_path) -> None:
    """Bare ``opentide`` for a person draws the home screen at the cost of ``--help``."""
    platforms = tmp_path / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "sentinel.toml").write_text(
        '[platform]\nenabled = true\n\n[[tenants]]\nname = "prod"\n', encoding="utf-8"
    )
    (tmp_path / "objects" / "rules").mkdir(parents=True)
    env = {"OPENTIDE_OUTPUT": "human", "OPENTIDE_REPO_ROOT": "", "OPENTIDE_TIDE_WORKSPACE": ""}
    done, modules = _modules_after([], cwd=str(tmp_path), **env)
    assert "Suggested next" in _plain(done.stdout), done.stdout + done.stderr
    assert "sentinel (1 tenant)" in _plain(done.stdout)
    assert _engine_modules(modules) == []


@pytest.mark.parametrize(
    "words",
    ["opentide ", "opentide de", "opentide --"],
    ids=["commands", "prefix", "options"],
)
def test_top_level_completion_imports_no_engine_module(words: str) -> None:
    done, modules = _modules_after(
        [],
        _OPENTIDE_COMPLETE="complete_bash",
        COMP_WORDS=words,
        COMP_CWORD="1",
    )
    assert done.stdout.strip() and "Usage" not in done.stdout, done.stdout + done.stderr
    assert _engine_modules(modules) == []


def _workspace(root: Path) -> Path:
    rules = root / "objects" / "rules"
    rules.mkdir(parents=True)
    (rules / "rule.yaml").write_text(
        "name: A rule\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n",
        encoding="utf-8",
    )
    platforms = root / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "splunk.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    return root


_COMPLETE_AND_REPORT = """
import json
import sys

from opentide.cli import main

sys.argv[0] = "opentide"
try:
    main()
except SystemExit:
    pass
sys.stdout.flush()
registry = sys.modules.get("opentide.core.registry")
built = bool(registry and registry.Opentide.is_initialised)
print("\\n" + json.dumps({"modules": sorted(sys.modules), "built": built}), file=sys.stderr)
"""


def _complete_bash(words: str, **env: str) -> tuple[str, set, bool]:
    """Complete *words* as bash would: the output, the modules loaded, whether the registry was built."""
    done = subprocess.run(
        [sys.executable, "-c", _COMPLETE_AND_REPORT],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "NO_COLOR": "1",
            "_OPENTIDE_COMPLETE": "complete_bash",
            "COMP_WORDS": words,
            "COMP_CWORD": str(len(words.split()) - (0 if words.endswith(" ") else 1)),
            **env,
        },
    )
    report = json.loads(done.stderr.strip().splitlines()[-1])
    return done.stdout, set(report["modules"]), report["built"]


_INDEXED = sorted(
    (" ".join(path), option) for path, options in INDEXED_OPTIONS.items() for option in options
)


@pytest.mark.parametrize(("command", "option"), _INDEXED, ids=[f"{c} {o}" for c, o in _INDEXED])
def test_completing_a_value_imports_no_engine_module(
    tmp_path: Path, command: str, option: str
) -> None:
    """Each completer answers from the index: not the command's module, not the engine.

    Completing a value costs what completing a command name does.
    """
    env = {"OPENTIDE_REPO_ROOT": str(_workspace(tmp_path))}
    _, baseline, _ = _complete_bash("opentide va", **env)
    output, modules, built = _complete_bash(f"opentide {command} {option} ", **env)
    assert output.strip()
    assert _engine_modules(modules) == []
    assert not any(name == "pydantic" or name.startswith("pydantic.") for name in modules)
    added = sorted(
        name
        for name in modules - baseline - {"opentide.data"}
        if name.split(".")[0] not in sys.stdlib_module_names
    )
    assert added == []
    assert built is False


def test_completing_after_an_unindexed_option_still_answers(tmp_path: Path) -> None:
    """A command line the index cannot read falls back to Click, which loads the command."""
    env = {"OPENTIDE_REPO_ROOT": str(_workspace(tmp_path))}
    output, modules, built = _complete_bash("opentide validate --check schema --uuid ", **env)
    assert output.split() == ["00000000-0000-4000-8003-000000000001"]
    assert "opentide.cli.commands.validate" in modules
    assert built is False


def test_completion_lists_the_visible_commands_in_order() -> None:
    done, _ = _modules_after(
        [], _OPENTIDE_COMPLETE="complete_bash", COMP_WORDS="opentide ", COMP_CWORD="1"
    )
    assert done.stdout.split() == [spec.name for spec in ROOT_COMMANDS if not spec.hidden]


def test_importing_the_cli_package_does_not_import_typer() -> None:
    """``opentide.ci`` imports ``opentide.cli.enums``, which runs this package first."""
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\nimport opentide.cli\nraise SystemExit('typer' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def test_running_a_command_loads_only_its_module() -> None:
    _, modules = _modules_after(["lint", "--help"])
    commands = sorted(m for m in modules if m.startswith("opentide.cli.commands."))
    assert commands == ["opentide.cli.commands.lint"]


def test_fast_version_flags_match_the_root_options() -> None:
    """``main()`` parses root options without Typer; its lists must not drift."""
    flags: set[str] = set()
    value_options: set[str] = set()
    for param in _root().params:
        opts = {*param.opts, *param.secondary_opts}
        if opts & {"--help", "--install-completion", "--show-completion"}:
            continue
        (flags if getattr(param, "is_flag", False) else value_options).update(opts)
    assert flags == cli_package._ROOT_FLAGS | cli_package._VERSION_FLAGS
    assert value_options == cli_package._ROOT_VALUE_OPTIONS


@pytest.mark.parametrize(
    "argv",
    [
        ["--version"],
        ["-V"],
        ["--json", "--version"],
        ["--version", "--json"],
        ["--repo", ".", "--debug", "-V"],
        ["--repo=.", "--version"],
        ["--version", "validate", "--bogus"],
        ["--version", "--", "validate"],
        ["--repo", "--version"],
        ["--bogus", "--version"],
        ["--version", "--bogus"],
        ["--help", "--version"],
        ["--json=1", "--version"],
        ["validate", "--version"],
        ["--repo"],
        ["--json"],
        [],
    ],
)
def test_fast_version_answers_exactly_when_typer_would(argv: list[str]) -> None:
    result = runner.invoke(cli_package.app, argv)
    typer_prints_version = result.exit_code == 0 and result.stdout == f"opentide {__version__}\n"
    assert cli_package._asks_only_for_version(argv) is typer_prints_version


_RUN_MAIN = "from opentide.cli import main\nraise SystemExit(main())"


@pytest.mark.skipif(sys.platform == "win32", reason="closes descriptor 1 with preexec_fn")
def test_version_without_stdout_exits_quietly() -> None:
    """A closed descriptor (``opentide --version >&-``) or ``pythonw``: exit 0, as Click did."""
    done = subprocess.run(
        [sys.executable, "-c", _RUN_MAIN, "--version"],
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        preexec_fn=lambda: os.close(1),
    )
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pipe semantics")
def test_version_into_a_closed_pipe_exits_1_without_a_traceback() -> None:
    """The reader is gone before anything is written: exit 1 and no traceback, as Click did."""
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        done = subprocess.run(
            [sys.executable, "-c", _RUN_MAIN, "--version"],
            stdout=write_end,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        os.close(write_end)
    assert done.returncode == 1
    assert done.stderr == ""
