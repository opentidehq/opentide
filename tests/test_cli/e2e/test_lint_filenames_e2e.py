"""CLI E2E: ``lint.toml`` ``[filenames]`` ``style`` and ``pattern`` (#699)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

STEM = "[SEN][AWS]Some rule[TenantA+TenantB]"
PATTERN = r"^\[(SEN|XDR)\]\[[^\]]+\].+\[[^\]]+\]$"
UUID_A = "00000000-0000-4000-8001-000000000001"
UUID_B = "11111111-1111-4111-8111-111111111111"


def _object(name: str, uuid: str = UUID_A) -> str:
    return (
        f"name: '{name}'\n"
        f"metadata:\n  uuid: {uuid}\n  schema: threat::1.0\n  author: SOC\n"
        "  organisation:\n    uuid: 00000000-0000-4000-8000-000000000001\n    name: Example\n"
    )


@pytest.fixture
def catalogue(tmp_path: Path) -> Path:
    (tmp_path / "objects" / "threats").mkdir(parents=True)
    return tmp_path


def _write(root: Path, filename: str, body: str) -> Path:
    path = root / "objects" / "threats" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _configure(root: Path, body: str) -> None:
    path = root / ".opentide" / "configurations" / "lint.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"[filenames]\n{body}\n", encoding="utf-8")


def _files(root: Path) -> list[str]:
    return sorted(path.name for path in (root / "objects" / "threats").iterdir())


def test_without_style_or_pattern_the_slug_convention_is_unchanged(
    invoke_cli, catalogue: Path
) -> None:
    _write(catalogue, "Simulated Actor.yaml", _object("Simulated Actor"))
    payload = parse_cli_json(invoke_cli("lint", "--check", "filenames", repo=catalogue))
    (finding,) = payload["findings"]
    assert finding["code"] == "filename_mismatch"
    assert finding["message"] == (
        "Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'"
    )
    assert_json_ok(invoke_cli("lint", "--check", "filenames", "--fix", repo=catalogue))
    assert _files(catalogue) == ["simulated-actor.yaml"]
    assert invoke_cli("lint", "--strict", repo=catalogue).exit_code == 0


def test_style_name_accepts_the_name_and_fixes_a_different_stem(
    invoke_cli, catalogue: Path
) -> None:
    _configure(catalogue, 'style = "name"')
    _write(catalogue, f"{STEM}.yaml", _object(STEM))
    assert_json_ok(invoke_cli("lint", "--strict", repo=catalogue))

    _write(catalogue, "some-rule.yaml", _object(STEM, UUID_B))
    strict = invoke_cli("lint", "--check", "filenames", "--strict", repo=catalogue)
    assert strict.exit_code == 1
    (finding,) = parse_cli_json(strict)["findings"]
    assert finding["code"] == "filename_mismatch"
    assert "does not match name" in finding["message"]
    assert finding["expected"] == f"objects/threats/{STEM}-11111111.yaml"

    fixed = assert_json_ok(invoke_cli("lint", "--check", "filenames", "--fix", repo=catalogue))
    assert fixed["fixed"] == 1
    assert _files(catalogue) == [f"{STEM}-11111111.yaml", f"{STEM}.yaml"]
    again = assert_json_ok(invoke_cli("lint", "--check", "filenames", "--fix", repo=catalogue))
    assert (again["count"], again["fixed"]) == (0, 0)


def test_style_name_human_output_says_the_stem_does_not_match_the_name(
    invoke_cli, catalogue: Path
) -> None:
    _configure(catalogue, 'style = "name"')
    _write(catalogue, "some-rule.yaml", _object(STEM))
    human = invoke_cli("lint", "--check", "filenames", repo=catalogue, json_output=False)
    assert "warning[filename_mismatch]" in human.output
    assert "does not match name" in human.output
    assert f"rename it to objects/threats/{STEM}.yaml" in human.output


def test_style_none_keeps_every_finding_but_the_stem_comparison(
    invoke_cli, catalogue: Path
) -> None:
    _configure(catalogue, 'style = "none"')
    _write(catalogue, "anything-goes.yaml", _object(STEM))
    _write(catalogue, "unnamed.yaml", "metadata: {}\n")
    _write(catalogue, "broken.yaml", "name: [unclosed\n")
    _write(catalogue, "team/nested.yaml", "name: Other\nmetadata: {}\n")
    payload = parse_cli_json(invoke_cli("lint", "--check", "filenames", repo=catalogue))
    assert sorted(item["code"] for item in payload["findings"]) == [
        "name_missing",
        "nested_object_file",
        "yaml_parse",
    ]
    assert_json_ok(invoke_cli("lint", "--check", "filenames", "--fix", repo=catalogue))
    assert "anything-goes.yaml" in _files(catalogue)


def test_pattern_findings_are_json_with_the_pattern_in_help(invoke_cli, catalogue: Path) -> None:
    _configure(catalogue, f"style = \"none\"\npattern = '{PATTERN}'")
    _write(catalogue, f"{STEM}.yaml", _object(STEM))
    _write(catalogue, "Some rule.yaml", _object("Some rule", UUID_B))
    result = invoke_cli("lint", "--check", "filenames", "--strict", repo=catalogue)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    (finding,) = payload["findings"]
    assert finding["code"] == "filename_pattern"
    assert finding["severity"] == "warning"
    assert finding["path"] == "objects/threats/Some rule.yaml"
    assert PATTERN in finding["help"]
    assert finding["explain"] == "opentide explain filename_pattern"
    assert "expected" not in finding
    assert payload["failure"]["code"] == "issues_found"
    # Nothing to rename: `lint --fix` is not offered.
    assert not [
        step for step in payload.get("next_actions", []) if step["command"].endswith("--fix")
    ]

    fixed = parse_cli_json(invoke_cli("lint", "--check", "filenames", "--fix", repo=catalogue))
    assert (fixed["count"], fixed["fixed"]) == (1, 0)
    assert _files(catalogue) == sorted([f"{STEM}.yaml", "Some rule.yaml"])


def test_pattern_human_output_shows_the_code_and_the_help(invoke_cli, catalogue: Path) -> None:
    _configure(catalogue, f"pattern = '{PATTERN}'\nseverity = \"error\"")
    _write(catalogue, "some-rule.yaml", _object("Some rule"))
    human = invoke_cli("lint", "--check", "filenames", repo=catalogue, json_output=False)
    assert "error[filename_pattern]" in human.output
    assert PATTERN in human.output
    explained = invoke_cli("explain", "filename_pattern", json_output=False)
    assert explained.exit_code == 0
    assert "[filenames].pattern" in explained.output


def test_pattern_sarif_report_carries_the_rule(invoke_cli, catalogue: Path, tmp_path: Path) -> None:
    _configure(catalogue, f"style = \"none\"\npattern = '{PATTERN}'")
    _write(catalogue, "some-rule.yaml", _object("Some rule"))
    out = tmp_path / "lint.sarif"
    invoke_cli(
        "lint", "--check", "filenames", "--format", "sarif", "--output", str(out), repo=catalogue
    )
    assert '"ruleId": "filename_pattern"' in out.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("body", "key"),
    [
        ('style = "camel"', "lint.toml [filenames].style"),
        ("pattern = 7", "lint.toml [filenames].pattern"),
        ('pattern = "(["', "lint.toml [filenames].pattern: invalid regular expression"),
    ],
)
def test_an_invalid_style_or_pattern_exits_2_naming_the_key(
    invoke_cli, catalogue: Path, body: str, key: str
) -> None:
    _write(catalogue, "simulated-actor.yaml", _object("Simulated Actor"))
    _configure(catalogue, body)
    result = invoke_cli("lint", repo=catalogue)
    assert result.exit_code == 2, result.output
    assert key in parse_cli_json(result)["message"]
    human = invoke_cli("lint", repo=catalogue, json_output=False)
    assert human.exit_code == 2
    assert key in human.output


def test_check_filenames_runs_a_disabled_check_with_its_convention(
    invoke_cli, catalogue: Path
) -> None:
    _configure(catalogue, 'enabled = false\nstyle = "name"')
    _write(catalogue, "some-rule.yaml", _object(STEM))
    assert "filenames" not in parse_cli_json(invoke_cli("lint", repo=catalogue))["checks"]
    payload = parse_cli_json(invoke_cli("lint", "--check", "filenames", repo=catalogue))
    assert [item["code"] for item in payload["findings"]] == ["filename_mismatch"]
