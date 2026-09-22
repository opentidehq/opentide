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
