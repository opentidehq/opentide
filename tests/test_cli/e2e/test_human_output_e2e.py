"""CLI E2E: human output carries what the JSON document carries (#292, #293).

Each command runs twice on the tutorial workspace, once with ``--json`` and once
without. The strings a reader acts on (messages, advice, severities, capability
names, section items) are taken from the JSON document and must appear verbatim
in the human output: Rich markup swallowed bracketed text, and some commands
printed a generic summary instead of the payload, while the JSON stayed correct.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.e2e.helpers import hidden_modules, write_tutorial_objects
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform, platform_label
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

#: Host variables that change what a command does or how it is rendered.
_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_DATA_ROOT",
    "DEPLOYMENT_PLAN",
    "INFLIGHT_PATHS",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "DEBUG",
    "NO_COLOR",
    "FORCE_COLOR",
    "PY_COLORS",
    "CLICOLOR_FORCE",
)

#: Envelope messages a command falls back to when it has nothing specific to say.
_GENERIC_MESSAGES = {"Completed successfully"}

_RULE = "00000000-0000-4000-8003-000000000001"
_THREAT = "00000000-0000-4000-8001-000000000001"
_OBJECTIVE = "00000000-0000-4000-8002-000000000001"
_RULE_FILE = Path("objects/rules/sentinel-kql-rule.yaml")

#: A string must appear in the output; a tuple must appear together on one line.
Expectation = str | tuple[str, ...]


@pytest.fixture(scope="module")
def _pristine_tutorial(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Scaffold the tutorial repo once; tests get a copy, never this tree."""
    repo = tmp_path_factory.mktemp("human-output") / "tutorial"
    run_repo_setup(
        RepoSetupOptions(
            path=repo,
            name="Tutorial Detections",
            org="Example Corp",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    write_tutorial_objects(repo)
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--json", "generate"], env=dict.fromkeys(_LEAKY_ENV)
    )
    assert result.exit_code == 0, result.output
    return repo


@pytest.fixture
def tutorial(_pristine_tutorial: Path, tmp_path: Path) -> Iterator[Path]:
    repo = tmp_path / "tutorial"
    shutil.copytree(_pristine_tutorial, repo)
    yield repo
    clear_runtime_caches()


def _run(repo: Path, *argv: str, json_output: bool) -> Result:
    clear_runtime_caches()
    head = ["--repo", str(repo), "--json" if json_output else "--no-color"]
    env = dict.fromkeys(_LEAKY_ENV) | {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
        "COLUMNS": "200",
    }
    return CliRunner().invoke(app, [*head, *argv], env=env)


def _human(repo: Path, *argv: str) -> str:
    return _run(repo, *argv, json_output=False).output


def _edit_rule(repo: Path, old: str, new: str) -> None:
    path = repo / _RULE_FILE
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _break_objective_reference(repo: Path) -> None:
    _edit_rule(
        repo, f"detection_model: {_OBJECTIVE}", f"detection_model: {_OBJECTIVE[:-12]}DEADBEEF0000"
    )


def _break_query(repo: Path) -> None:
    _edit_rule(repo, "| where EventID == 4688", '| where Account == "unterminated')


def _drop_author(repo: Path) -> None:
    _edit_rule(repo, "  author: Tutorial Author\n", "")


def _without_azure() -> AbstractContextManager[None]:
    return hidden_modules(
        "azure", purge=("opentide.extraction.sentinel_importer", "opentide.platforms.sentinel")
    )


# --------------------------------------------------------------------------
# The exact scenarios from the issues
# --------------------------------------------------------------------------


def test_info_summary_lists_each_platform_capability(tutorial: Path) -> None:
    """#292: the capability cell `[deploy, validate]` was parsed as a markup tag."""
    lines = _human(tutorial, "info").splitlines()
    assert any(
        "Microsoft Sentinel" in line and "enabled=True [deploy, validate]" in line for line in lines
    )
    assert any("CrowdStrike" in line and "enabled=False [deploy]" in line for line in lines)


def test_failing_validate_keeps_the_severity_tag(tutorial: Path) -> None:
    """#292: the panel printed ` detection_model: …` with the `[error]` tag gone."""
    _break_objective_reference(tutorial)
    assert "[error] detection_model: Unknown objective reference" in _human(
        tutorial, "validate", "--strict"
    )


def test_extract_without_sdk_names_the_extra(tutorial: Path) -> None:
    """#292: `install opentide[sentinel]` rendered as `install opentide`."""
    with _without_azure():
        output = _human(tutorial, "generate", "extract", "sentinel")
    assert "install opentide[sentinel]" in output


def test_live_validation_without_sdk_prints_the_advice(tutorial: Path) -> None:
    """#292: human `--live` printed the message and dropped the advice."""
    with _without_azure():
        output = _human(tutorial, "validate", "query", "--platform", "sentinel", "--live", "--wide")
    assert (
        "advice: install opentide[sentinel] (provides azure-identity, azure-monitor-query)"
        in output
    )


@pytest.mark.parametrize(
    ("argv", "rows"),
    [
        (("info", "rules"), ((_RULE, "Sentinel KQL Rule", "sentinel"),)),
        (("info", "threats"), ((_THREAT, "Simulated Actor"),)),
        (("info", "objectives"), ((_OBJECTIVE, "Credential Access Objective"),)),
        (
            ("info", "coverage", "--technique", "T1059"),
            (("Coverage for T1059: 1 rule",), (_RULE, "Sentinel KQL Rule", "sentinel")),
        ),
        (
            ("info", "--technique", "T1059", "coverage"),
            (("Coverage for T1059: 1 rule",), (_RULE, "Sentinel KQL Rule", "sentinel")),
        ),
    ],
    ids=["rules", "threats", "objectives", "coverage", "coverage-option-first"],
)
def test_info_sections_render_their_payload(
    tutorial: Path, argv: tuple[str, ...], rows: tuple[tuple[str, ...], ...]
) -> None:
    """#293: every section printed the plain `info` summary instead of its payload."""
    output = _human(tutorial, *argv)
    lines = output.splitlines()
    for row in rows:
        assert any(all(part in line for part in row) for line in lines), (row, output)
    assert output != _human(tutorial, "info")


def test_info_rejects_an_unknown_section(tutorial: Path) -> None:
    result = _run(tutorial, "info", "platforms", json_output=False)
    assert result.exit_code == 1
    assert "Unknown info section: platforms" in result.output


# --------------------------------------------------------------------------
# Human-vs-JSON parity
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    argv: tuple[str, ...]
    prepare: Callable[[Path], None] | None = None
    context: Callable[[], AbstractContextManager[None]] = nullcontext
    marks: tuple[pytest.MarkDecorator, ...] = ()


_CASES = {
    "info": Case(("info",)),
    "info-platform": Case(("info", "--platform", "sentinel")),
    "info-rules": Case(("info", "rules")),
    "info-threats": Case(("info", "threats")),
    "info-objectives": Case(("info", "objectives")),
    "info-coverage": Case(("info", "coverage", "--technique", "T1059")),
    "info-coverage-option-first": Case(("info", "--technique", "T1059", "coverage")),
    "info-coverage-no-rules": Case(("info", "coverage", "--technique", "T9999")),
    "info-unknown-section": Case(("info", "platforms")),
    "validate": Case(("validate", "--strict")),
    "validate-broken-reference": Case(("validate", "--strict"), _break_objective_reference),
    "validate-unknown-type": Case(("validate", "--type", "bogus")),
    "validate-query": Case(("validate", "query", "--platform", "sentinel")),
    "validate-query-broken": Case(("validate", "query", "--platform", "sentinel"), _break_query),
    "validate-query-disabled-platform": Case(("validate", "query", "--platform", "splunk")),
    "validate-query-unsupported": Case(("validate", "query", "--platform", "crowdstrike")),
    "validate-query-live-without-sdk": Case(
        ("validate", "query", "--platform", "sentinel", "--live", "--wide"),
        context=_without_azure,
    ),
    "validate-query-live-disabled-platform": Case(
        ("validate", "query", "--platform", "splunk", "--live", "--wide")
    ),
    "extract-without-sdk": Case(("generate", "extract", "sentinel"), context=_without_azure),
    "deploy-metadata-unimplemented": Case(("deploy", "metadata", "--platform", "sentinel")),
    "lint": Case(("lint",)),
    "lint-findings": Case(("lint",), _drop_author),
    "lint-findings-strict": Case(("lint", "--strict"), _drop_author),
}


def _info_expectations(payload: dict[str, Any]) -> list[Expectation]:
    """What each `info` view shows: the section asked for, else the summary table."""
    if "coverage" in payload:
        coverage = payload["coverage"]
        return [("Coverage for", coverage["technique"], str(coverage["count"])), *coverage["rules"]]
    sections = [key for key in ("rules", "threats", "objectives") if key in payload]
    if sections:
        return [uuid for key in sections for uuid in payload[key]]
    expected: list[Expectation] = [
        (family.capitalize(), str(count)) for family, count in payload["counts"].items()
    ]
    for plat in payload["platforms"]:
        caps = [name for name in ("deploy", "validate") if plat[f"can_{name}"]]
        expected.append(
            (
                platform_label(DetectionPlatform(plat["name"])),
                f"enabled={plat['enabled']}",
                f"[{', '.join(caps) or 'none'}]",
            )
        )
    return expected


def _load_bearing(payload: dict[str, Any]) -> list[Expectation]:
    """The strings in a result document that a human reader has to see."""
    expected: list[Expectation] = [
        payload[key]
        for key in ("message", "error", "detail", "advice")
        if isinstance(payload.get(key), str) and payload[key] not in _GENERIC_MESSAGES
    ]
    expected.extend(payload.get("warnings") or [])
    for issue in (payload.get("report") or {}).get("issues", []):
        expected.append((f"[{issue['severity']}]", issue["message"]))
    expected.extend(finding["message"] for finding in payload.get("findings") or [])
    if "counts" in payload and "platforms" in payload:
        expected.extend(_info_expectations(payload))
    return expected


def _missing(expected: list[Expectation], human: str) -> list[Expectation]:
    lines = [" ".join(line.split()) for line in human.splitlines()]
    flat = " ".join(human.split())
    return [
        item
        for item in expected
        if (
            " ".join(item.split()) not in flat
            if isinstance(item, str)
            else not any(all(part in line for part in item) for line in lines)
        )
    ]


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=name, marks=case.marks) for name, case in _CASES.items()],
)
def test_human_output_carries_the_json_payload(tutorial: Path, case: Case) -> None:
    if case.prepare is not None:
        case.prepare(tutorial)
    with case.context():
        machine = _run(tutorial, *case.argv, json_output=True)
        human = _run(tutorial, *case.argv, json_output=False)
    payload = json.loads(machine.stdout)
    expected = _load_bearing(payload)
    assert expected, f"{case.argv} carries nothing to compare"
    assert human.exit_code == machine.exit_code, human.output
    assert not _missing(expected, human.output), human.output
