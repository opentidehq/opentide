"""CLI E2E: argv shapes users actually type (issue #263).

Every command below is invoked in the shape the docs or a first user would use,
not only the one shape the implementation happened to support. Three product
bugs lived here: ``info coverage --technique`` (#257), parent callbacks running
for nested subcommands (#243), and ``--path`` vs positional ``PATH`` drift
across ``setup`` subcommands (#248).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_console_scripts import ScriptRunner
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


# --- info: option before and after the section argument (#257) ---------------


@pytest.mark.parametrize(
    "argv",
    [
        ("info", "--technique", "T1059", "coverage"),
        ("info", "coverage", "--technique", "T1059"),
    ],
    ids=["option-then-section", "section-then-option"],
)
def test_info_coverage_accepts_both_argv_orders(invoke_cli, corpus_rule_uuids, argv) -> None:
    payload = assert_json_ok(invoke_cli(*argv))
    coverage = payload["coverage"]
    assert coverage["technique"] == "T1059"
    assert corpus_rule_uuids["sentinel"] in coverage["rules"]


@pytest.mark.parametrize(
    "argv",
    [
        ("info", "--platform", "sentinel", "rules"),
        ("info", "rules", "--platform", "sentinel"),
    ],
    ids=["option-then-section", "section-then-option"],
)
def test_info_section_with_platform_option_both_orders(invoke_cli, argv) -> None:
    payload = assert_json_ok(invoke_cli(*argv))
    assert "rules" in payload


def test_info_usage_does_not_advertise_subcommands(invoke_cli) -> None:
    result = invoke_cli("info", "--help", json_output=False)
    assert result.exit_code == 0
    assert "COMMAND [ARGS]" not in result.stdout


# --- nested commands under invoke_without_command parents (#243) -------------


def test_deploy_metadata_does_not_run_the_deploy_callback(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``deploy metadata`` is a reserved stub; it must never reach a deployer."""
    deployer = MagicMock()

    class _MockDeployTide:
        @property
        def mdr(self) -> dict[str, MagicMock]:
            return {"sentinel": deployer}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)
    result = invoke_cli("deploy", "metadata", "--platform", "sentinel")
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["ok"] is False
    assert "not implemented" in payload["message"]
    deployer.deploy.assert_not_called()


def test_generate_inflight_prune_emits_one_document(invoke_cli) -> None:
    """The inflight group callback must not also run phase ``inflight``."""
    result = invoke_cli("generate", "inflight", "prune")
    payload = assert_json_ok(result)
    assert payload["phase"] == "inflight-prune"
    assert result.stdout.strip().count('"phase"') == 1


@pytest.mark.cli_smoke
@pytest.mark.script_launch_mode("subprocess")
def test_nested_parents_on_console_script(script_runner: ScriptRunner, tmp_path: Path) -> None:
    """Same two argv shapes through the installed binary, where stdout is real."""
    repo = tmp_path / "repo"
    env = os.environ.copy()
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env.pop("DEPLOYMENT_PLAN", None)
    setup = script_runner.run(
        [
            "opentide",
            "--json",
            "setup",
            "--yes",
            "--name",
            "Argv",
            "--platform",
            "sentinel",
            "--path",
            str(repo),
        ],
        env=env,
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr

    prune = script_runner.run(
        ["opentide", "--json", "--repo", str(repo), "generate", "inflight", "prune"],
        env=env,
        print_result=False,
    )
    assert prune.returncode == 0, prune.stdout + prune.stderr
    assert json.loads(prune.stdout.strip())["phase"] == "inflight-prune"

    metadata = script_runner.run(
        ["opentide", "--json", "--repo", str(repo), "deploy", "metadata", "--platform", "sentinel"],
        env=env,
        print_result=False,
    )
    assert metadata.returncode == 2, metadata.stdout + metadata.stderr
    assert json.loads(metadata.stdout.strip())["ok"] is False


# --- setup: --path/-C and --yes on every subcommand (#248) -------------------


SETUP_PATH_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("env", ()),
    ("hooks", ("--no-install",)),
    ("mcp", ("--cursor",)),
    ("platforms", ("--sentinel",)),
    ("vscode", ("--settings",)),
    ("repo", ("--name", "Argv Matrix")),
)


@pytest.mark.parametrize(("subcommand", "flags"), SETUP_PATH_COMMANDS)
@pytest.mark.parametrize("path_style", ["option", "short-option", "positional"])
def test_setup_subcommands_accept_path_option_and_positional(
    cli_runner, tmp_path: Path, subcommand: str, flags: tuple[str, ...], path_style: str
) -> None:
    from opentide.cli import app

    target = tmp_path / f"{subcommand}-{path_style}"
    target.mkdir(parents=True)
    path_argv = {
        "option": ["--path", str(target)],
        "short-option": ["-C", str(target)],
        "positional": [str(target)],
    }[path_style]
    result = cli_runner.invoke(
        app,
        ["--json", "--repo", str(target), "setup", subcommand, *flags, *path_argv, "--yes"],
        env={"OPENTIDE_REPO_ROOT": str(target), "PATH": os.environ.get("PATH", "")},
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert list(target.iterdir()), "setup subcommand wrote nothing to the requested path"


def test_setup_rejects_both_path_forms(cli_runner, tmp_path: Path) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(
        app,
        ["setup", "env", "--path", str(tmp_path), str(tmp_path), "--yes"],
    )
    assert result.exit_code == 2
    assert "not both" in (result.stdout + result.stderr)


def test_setup_rejects_an_explicit_dot_alongside_a_positional(cli_runner, tmp_path: Path) -> None:
    """``--path .`` is explicit even though it equals the default.

    Comparing against ``"."`` treated it as absent and silently wrote to the
    positional target instead of reporting two conflicting paths.
    """
    from opentide.cli import app

    other = tmp_path / "other"
    other.mkdir()
    result = cli_runner.invoke(
        app,
        ["setup", "env", str(other), "--path", ".", "--yes"],
    )
    assert result.exit_code == 2, result.stdout + result.stderr
    assert "not both" in (result.stdout + result.stderr)
    assert not list(other.iterdir()), "the conflicting positional target was written anyway"


# --- setup: the group's --path/--yes reach the subcommand ----------------------

GROUP_PATH_COMMANDS = (*SETUP_PATH_COMMANDS, ("ci", ("github",)))


def _error_text(result) -> str:
    """The usage error with Rich's panel borders and line wrapping removed."""
    text = ANSI_ESCAPE.sub("", result.stdout + result.stderr)
    return " ".join(text.replace("│", " ").split())


def _elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A working directory and a separate target, so a dropped --path is visible."""
    cwd = tmp_path / "cwd"
    target = tmp_path / "target"
    cwd.mkdir()
    target.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(cwd))
    return cwd, target


@pytest.mark.parametrize(("subcommand", "flags"), GROUP_PATH_COMMANDS)
@pytest.mark.parametrize("consent", ["subcommand-yes", "group-yes"])
def test_setup_group_path_and_yes_reach_the_subcommand(
    cli_runner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    subcommand: str,
    flags: tuple[str, ...],
    consent: str,
) -> None:
    """``setup --path T hooks`` returned from the group and configured the cwd.

    ``setup --yes env`` likewise dropped the consent and then failed with
    "Add --yes to confirm this write".
    """
    from opentide.cli import app

    cwd, target = _elsewhere(tmp_path, monkeypatch)
    group = ["--path", str(target)]
    tail = [*flags]
    if consent == "group-yes":
        group.append("--yes")
    else:
        tail.append("--yes")
    result = cli_runner.invoke(app, ["--json", "setup", *group, subcommand, *tail])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert list(target.iterdir()), f"setup {subcommand} ignored the group's --path"
    assert not list(cwd.iterdir()), f"setup {subcommand} wrote into the working directory"


def test_setup_group_path_reaches_nested_skills_commands(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from opentide.cli import app

    _, target = _elsewhere(tmp_path, monkeypatch)
    setup_module = importlib.import_module("opentide.cli.setup_app")
    seen: list[Path] = []

    def _discover(base: Path, **_kwargs):
        seen.append(base)
        return {"message": "0 skills", "skills": [], "source": "test", "count": 0}

    monkeypatch.setattr(setup_module, "discover_skills", _discover)
    for argv in (
        ["setup", "--path", str(target), "skills", "discover"],
        ["setup", "skills", "--path", str(target), "discover"],
    ):
        result = cli_runner.invoke(app, ["--json", *argv])
        assert result.exit_code == 0, result.stdout + result.stderr
    assert [path.resolve() for path in seen] == [target.resolve()] * 2


@pytest.mark.parametrize(
    "argv",
    [
        ["setup", "--ci", "github", "env", "--yes"],
        ["setup", "--name", "Ignored", "--no-staging", "hooks", "--yes"],
        ["setup", "skills", "--cursor", "discover"],
    ],
    ids=["ci", "name-and-negated-flag", "skills-target"],
)
def test_setup_group_options_a_subcommand_would_ignore_are_refused(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    from opentide.cli import app

    cwd, _ = _elsewhere(tmp_path, monkeypatch)
    result = cli_runner.invoke(app, argv)
    assert result.exit_code == 2, result.stdout + result.stderr
    assert "would be ignored" in _error_text(result)
    assert not list(cwd.iterdir()), "a refused command still wrote files"


def test_setup_group_and_subcommand_paths_must_agree(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.cli import app

    cwd, target = _elsewhere(tmp_path, monkeypatch)
    conflict = cli_runner.invoke(
        app, ["setup", "--path", str(target), "env", "--path", str(cwd), "--yes"]
    )
    assert conflict.exit_code == 2, conflict.stdout + conflict.stderr
    assert "different targets" in _error_text(conflict)
    assert not list(cwd.iterdir()) and not list(target.iterdir())

    same = cli_runner.invoke(
        app, ["setup", "--path", str(target), "env", str(target / "."), "--yes"]
    )
    assert same.exit_code == 0, same.stdout + same.stderr
    assert (target / ".env.example").is_file()


def test_document_subcommand_warns_once(cli_runner, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``document`` group callback must not add its own warning to a subcommand's."""
    from opentide import cli as cli_module

    monkeypatch.setattr(cli_module, "_emit_docs", lambda *_args, **_kwargs: None)
    result = cli_runner.invoke(cli_module.app, ["document", "rules"])
    assert result.exit_code == 0, result.stdout + result.stderr
    output = result.stdout + result.stderr
    assert output.count("DEPRECATED") == 1, output
    assert "generate docs rules" in output


def test_setup_positional_deprecation_keeps_json_parseable(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--json`` gets a structured log event, never a Rich ``DEPRECATED`` line."""
    import importlib

    from opentide import cli as cli_module

    # `opentide.cli.setup_app` the attribute is the Typer app; this is the module.
    setup_module = importlib.import_module("opentide.cli.setup_app")
    monkeypatch.setattr(
        setup_module,
        "discover_skills",
        lambda *_args, **_kwargs: {"message": "0 skills", "skills": []},
    )
    result = cli_runner.invoke(
        cli_module.app,
        ["--json", "setup", "skills", "discover", str(tmp_path)],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    parse_cli_json(result)
    assert "DEPRECATED" not in result.stdout + result.stderr
    assert "cli_command_deprecated" in result.stderr


@pytest.mark.parametrize(
    "subcommand",
    ["env", "hooks", "mcp", "platforms", "vscode", "repo", "skills"],
)
def test_setup_subcommands_expose_path_and_yes(cli_runner, subcommand: str) -> None:
    from opentide.cli import app

    result = cli_runner.invoke(app, ["setup", subcommand, "--help"])
    assert result.exit_code == 0
    # Rich styles option names (`-` and `-path` can land in separate SGR runs)
    # whenever TERM/FORCE_COLOR say colour is fine, so compare the plain text.
    help_text = ANSI_ESCAPE.sub("", result.stdout)
    assert "--path" in help_text, f"setup {subcommand} has no --path"
    assert "--yes" in help_text, f"setup {subcommand} has no --yes"
