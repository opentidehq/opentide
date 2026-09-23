"""``setup ci <provider>`` and the one-shot ``setup --ci <provider>`` must agree.

#288: the one-shot form had no ``--default-branch``, and without ``origin/HEAD``
or ``init.defaultBranch`` both forms wrote ``main`` into the pipeline of a
repository whose only branch was ``trunk``.
"""

from __future__ import annotations

import importlib
import json
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml
from typer.main import get_command
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.setup.ci import CiSetupOptions

if TYPE_CHECKING:  # pragma: no cover - import only for annotations
    import click

runner = CliRunner()

ENTRY_POINTS = ("setup ci", "setup --ci")

_WORKFLOWS = {
    "github": ".github/workflows/opentide.yml",
    "gitlab": ".gitlab-ci.yml",
    "azure": "azure-pipelines.yml",
}

#: Every place a generated pipeline names a branch outside its trigger lists.
_BRANCH_REFERENCES = (
    re.compile(r"refs/heads/([A-Za-z0-9._/-]+)"),
    re.compile(r"git fetch origin ([A-Za-z0-9._/-]+)"),
    re.compile(r"origin/([A-Za-z0-9._/-]+)"),
    re.compile(r"HEAD:([A-Za-z0-9._/-]+)"),
)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _with_a_platform(repo: Path) -> Path:
    platforms = repo / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "sentinel.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    return repo


def _trunk_repo(tmp_path: Path) -> Path:
    """``git init -b trunk`` plus one commit: no remote, no other branch."""
    repo = tmp_path / "repo"
    _git(tmp_path, "init", "-q", "-b", "trunk", str(repo))
    _git(repo, "commit", "-q", "--allow-empty", "-m", "seed")
    return _with_a_platform(repo)


def _clone_on_trunk_of(tmp_path: Path, remote_default: str) -> Path:
    """A clone whose ``origin/HEAD`` is *remote_default*, with ``trunk`` checked out."""
    upstream = tmp_path / "upstream"
    _git(tmp_path, "init", "-q", "-b", remote_default, str(upstream))
    _git(upstream, "commit", "-q", "--allow-empty", "-m", "seed")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(upstream), str(clone))
    _git(clone, "checkout", "-qb", "trunk")
    return _with_a_platform(clone)


def _argv(entry: str, ci: str) -> list[str]:
    return ["setup", "ci", ci] if entry == "setup ci" else ["setup", "--ci", ci]


def _invoke(entry: str, ci: str, repo: Path, *extra: str) -> Result:
    return runner.invoke(
        app,
        ["--json", *_argv(entry, ci), "--path", str(repo), *extra, "--yes"],
        env={"OPENTIDE_REPO_ROOT": str(repo), "OPENTIDE_TIDE_WORKSPACE": str(repo)},
    )


def _setup(entry: str, ci: str, repo: Path, *extra: str) -> tuple[dict[str, Any], str]:
    """The CI result of one entry point and the pipeline it wrote."""
    result = _invoke(entry, ci, repo, *extra)
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    if entry == "setup --ci":
        [payload] = [step for step in payload["steps"] if step["step"] == "ci"]
    return payload, (repo / _WORKFLOWS[ci]).read_text(encoding="utf-8")


def _branches_named(ci: str, rendered: str) -> set[str]:
    named = {match for pattern in _BRANCH_REFERENCES for match in pattern.findall(rendered)}
    parsed = yaml.safe_load(rendered)
    if ci == "github":
        named.update(parsed[True]["push"]["branches"])
    elif ci == "azure":
        named.update(parsed["trigger"]["branches"]["include"])
        named.update(parsed["pr"]["branches"]["include"])
    return named


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("ci", ["github", "azure"])
def test_default_branch_flag_reaches_the_pipeline_from_both_entry_points(
    tmp_path: Path, git_home: Path, entry: str, ci: str
) -> None:
    repo = _trunk_repo(tmp_path)

    payload, rendered = _setup(entry, ci, repo, "--default-branch", "trunk")

    assert payload["default_branch"] == "trunk"
    assert _branches_named(ci, rendered) == {"trunk"}
    assert re.search(r"\bmain\b", rendered) is None


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("ci", ["github", "gitlab", "azure"])
def test_without_the_flag_the_checked_out_branch_is_targeted(
    tmp_path: Path, git_home: Path, entry: str, ci: str
) -> None:
    repo = _trunk_repo(tmp_path)

    payload, rendered = _setup(entry, ci, repo)

    if ci == "gitlab":
        assert payload["default_branch"] == "$CI_DEFAULT_BRANCH"
        assert _branches_named(ci, rendered) == set()
    else:
        assert payload["default_branch"] == "trunk"
        assert _branches_named(ci, rendered) == {"trunk"}
    assert re.search(r"\bmain\b", rendered) is None
    assert "warnings" not in payload


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("ci", ["github", "azure"])
def test_origin_head_wins_over_the_checked_out_branch(
    tmp_path: Path, git_home: Path, entry: str, ci: str
) -> None:
    clone = _clone_on_trunk_of(tmp_path, "development")

    payload, rendered = _setup(entry, ci, clone)

    assert payload["default_branch"] == "development"
    assert _branches_named(ci, rendered) == {"development"}


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("ci", ["github", "azure"])
def test_default_branch_flag_wins_over_every_detected_branch(
    tmp_path: Path, git_home: Path, entry: str, ci: str
) -> None:
    _git(git_home, "config", "--global", "init.defaultBranch", "master")
    clone = _clone_on_trunk_of(tmp_path, "development")

    payload, rendered = _setup(entry, ci, clone, "--default-branch", "release")

    assert payload["default_branch"] == "release"
    assert _branches_named(ci, rendered) == {"release"}


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_gitlab_ignores_the_default_branch_flag_from_both_entry_points(
    tmp_path: Path, git_home: Path, entry: str
) -> None:
    repo = _trunk_repo(tmp_path)

    payload, rendered = _setup(entry, "gitlab", repo, "--default-branch", "release")

    assert payload["default_branch"] == "$CI_DEFAULT_BRANCH"
    assert any("--default-branch is ignored" in w for w in payload["warnings"])
    assert "release" not in rendered


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_both_entry_points_refuse_a_default_branch_they_cannot_render(
    tmp_path: Path, git_home: Path, entry: str
) -> None:
    repo = _trunk_repo(tmp_path)

    result = _invoke(entry, "github", repo, "--default-branch", "main; id")

    assert result.exit_code == 2, result.stdout + result.stderr
    assert "--default-branch" in re.sub(r"\x1b\[[0-9;]*m", "", result.stderr)
    assert not (repo / _WORKFLOWS["github"]).exists()


def _command(*names: str) -> click.Command:
    """Walked by attribute, not ``isinstance``: Typer bundles its own Click copy."""
    command: Any = get_command(app)
    for name in names:
        command = command.commands[name]
    return command


def _options(command: click.Command) -> dict[str, click.Option]:
    return {
        param.name: param
        for param in command.params
        if param.param_type_name == "option" and param.name is not None
    }


def _declaration(option: click.Option) -> tuple[object, ...]:
    return (
        tuple(option.opts),
        tuple(option.secondary_opts),
        option.default,
        option.is_flag,
        option.multiple,
        option.type.name,
    )


#: ``setup ci`` options the one-shot ``setup --ci`` deliberately does not take.
_SETUP_CI_ONLY: dict[str, str] = {}

#: Options both forms take that pick the target or give consent; neither shapes the pipeline.
_NOT_CI_GENERATION = frozenset({"path", "yes"})

#: A non-default value for each ``setup ci`` option that is not a flag.
_SAMPLE_VALUES = {
    "promotion_target": "STAGING",
    "python_version": "3.11",
    "default_branch": "release",
}

_CI_GENERATION = sorted(
    set(_options(_command("setup", "ci"))) - _NOT_CI_GENERATION - set(_SETUP_CI_ONLY)
)


def test_setup_accepts_every_setup_ci_option() -> None:
    """A new ``setup ci`` option must also be declared on the one-shot ``setup --ci``.

    #288 was ``--default-branch`` added to one entry point only. Declarations
    are compared too, so a default changed on one side is caught here as well.
    """
    setup_ci, setup = _options(_command("setup", "ci")), _options(_command("setup"))
    assert set(_SETUP_CI_ONLY) <= set(setup_ci), "allow-list names an option setup ci lacks"

    shared = set(setup_ci) - set(_SETUP_CI_ONLY)
    assert sorted(shared - set(setup)) == [], "setup ci options missing from setup --ci"
    drifted = {
        name: (_declaration(setup_ci[name]), _declaration(setup[name]))
        for name in shared
        if _declaration(setup_ci[name]) != _declaration(setup[name])
    }
    assert drifted == {}


def test_every_setup_ci_value_option_has_a_sample() -> None:
    options = _options(_command("setup", "ci"))
    assert {name for name in _CI_GENERATION if not options[name].is_flag} == set(_SAMPLE_VALUES)


def _non_default_argv(option: click.Option) -> list[str]:
    if option.is_flag:
        return [option.secondary_opts[0] if option.default else option.opts[0]]
    assert option.name is not None
    return [option.opts[0], _SAMPLE_VALUES[option.name]]


@pytest.fixture
def ci_options_seen(monkeypatch: pytest.MonkeyPatch) -> list[CiSetupOptions]:
    """Record what each entry point hands to ``run_ci_setup`` instead of rendering it."""
    seen: list[CiSetupOptions] = []

    def _record(options: CiSetupOptions) -> dict[str, object]:
        seen.append(options)
        return {"message": "recorded", "files": []}

    for module in ("opentide.cli.setup_app", "opentide.cli.services.setup.orchestrator"):
        monkeypatch.setattr(importlib.import_module(module), "run_ci_setup", _record)
    return seen


@pytest.mark.parametrize("name", _CI_GENERATION)
def test_setup_ci_option_is_forwarded_by_both_entry_points(
    tmp_path: Path, ci_options_seen: list[CiSetupOptions], name: str
) -> None:
    """Accepted is not enough: ``setup --ci`` must pass the option on unchanged."""
    argv = _non_default_argv(_options(_command("setup", "ci"))[name])

    for entry, extra in (("setup ci", []), ("setup ci", argv), ("setup --ci", argv)):
        result = _invoke(entry, "github", tmp_path, *extra)
        assert result.exit_code == 0, result.stdout + result.stderr

    baseline, via_subcommand, via_one_shot = ci_options_seen
    assert via_subcommand != baseline, f"{argv} did not change the CI options"
    assert via_one_shot == via_subcommand
