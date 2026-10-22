"""``lint.toml``: per-check ``enabled`` and ``severity``, and ``[metadata].required`` (#489)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import LintCheck
from opentide.cli.services.lint import run_lint
from opentide.core.lint_config import (
    CHECK_NAMES,
    DEFAULT_REQUIRED_METADATA,
    LintConfig,
    LintConfigError,
    load_lint_config,
    metadata_keys,
    parse_lint_config,
)

runner = CliRunner()

_BARE = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
"""


def _write_object(root: Path, filename: str, body: str = _BARE) -> None:
    dest = root / "objects" / "threats" / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8")


def _write_lint_toml(root: Path, text: str) -> None:
    dest = root / ".opentide" / "configurations" / "lint.toml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")


def test_check_names_match_the_cli_enum() -> None:
    assert tuple(item.value for item in LintCheck) == CHECK_NAMES


def test_bundled_defaults_reproduce_unconfigured_lint(tmp_path: Path) -> None:
    config = load_lint_config(tmp_path)
    assert config.required_metadata == DEFAULT_REQUIRED_METADATA == ("author", "organisation")
    assert config.enabled_checks() == ["filenames", "metadata"]
    assert all(config.check(name).severity is None for name in CHECK_NAMES)


def test_no_lint_table_parses_to_defaults() -> None:
    assert parse_lint_config(None) == LintConfig()


def test_workspace_required_replaces_the_default(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "tlp"]\n')
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["message"] == "Recommended metadata missing: author, tlp"


def test_empty_required_silences_the_metadata_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nrequired = []\n")
    result = run_lint(tmp_path)
    assert result["count"] == 0
    assert result["checks"] == ["filenames", "metadata"]


def test_required_counts_empty_lists_and_strings_as_missing(tmp_path: Path) -> None:
    body = _BARE + "  author: '  '\n  contributors: []\n  version: 1\n"
    _write_object(tmp_path, "simulated-actor.yaml", body)
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "contributors", "version"]\n')
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["message"] == "Recommended metadata missing: author, contributors"


def test_disabled_check_does_not_run(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nenabled = false\n")
    result = run_lint(tmp_path)
    assert result["checks"] == ["filenames"]
    assert [item["check"] for item in result["findings"]] == ["filenames"]


def test_check_flag_wins_over_a_disabled_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nenabled = false\n")
    result = run_lint(tmp_path, checks=[LintCheck.metadata])
    assert result["checks"] == ["metadata"]
    assert result["count"] == 1


def test_every_check_disabled_passes(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nenabled = false\n[filenames]\nenabled = false\n")
    result = run_lint(tmp_path, strict=True)
    assert result["checks"] == []
    assert result["status"] == "completed"


def test_severity_override_applies_to_each_finding_of_the_check(tmp_path: Path) -> None:
    _write_object(tmp_path, "Simulated Actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nseverity = "error"\n')
    findings = {item["check"]: item["severity"] for item in run_lint(tmp_path)["findings"]}
    assert findings == {"metadata": "error", "filenames": "warning"}


def test_explicit_config_argument_skips_the_workspace(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, "[metadata]\nrequired = []\n")
    config = parse_lint_config({"metadata": {"required": ["author"]}})
    (finding,) = run_lint(tmp_path, config=config)["findings"]
    assert finding["message"] == "Recommended metadata missing: author"


def test_metadata_keys_cover_every_schema() -> None:
    keys = metadata_keys()
    assert {"author", "organisation", "contributors", "schema", "reviewed"} <= set(keys)
    assert "schema_id" not in keys


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (
            {"metadata": {"required": ["author", "autor", "org"]}},
            r"lint\.toml \[metadata\]\.required: unknown metadata field\(s\) 'autor', 'org'\. "
            r"Known fields: uuid, schema, ",
        ),
        ({"metadata": {"required": "author"}}, r"required must be a list of metadata keys"),
        ({"metadatas": {}}, r"unknown check\(s\) 'metadatas'\. Known checks: filenames, metadata"),
        ({"metadata": {"requried": []}}, r"\[metadata\]: unknown key\(s\) 'requried'"),
        ({"filenames": {"required": []}}, r"\[filenames\]: unknown key\(s\) 'required'"),
        ({"filenames": {"enabled": "no"}}, r"\[filenames\]\.enabled must be true or false"),
        ({"filenames": {"severity": "fatal"}}, r"severity must be one of error, warning, info"),
        ({"filenames": True}, r"\[filenames\] must be a table"),
        (["metadata"], r"must hold tables"),
    ],
)
def test_bad_config_names_the_key(raw: object, match: str) -> None:
    with pytest.raises(LintConfigError, match=match):
        parse_lint_config(raw)


def test_unknown_required_field_fails_the_command(tmp_path: Path) -> None:
    _write_object(tmp_path, "simulated-actor.yaml")
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "owner"]\n')
    result = runner.invoke(app, ["--json", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "unknown metadata field(s) 'owner'" in payload["message"]


def test_unknown_required_field_fails_the_human_command(tmp_path: Path) -> None:
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["owner"]\n')
    result = runner.invoke(app, ["--no-color", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 2
    assert "unknown metadata field(s) 'owner'" in result.output


def test_required_skips_keys_the_object_schema_cannot_hold(tmp_path: Path) -> None:
    # ``reviewed`` exists only on rule::1.1 metadata; threat::1.0 forbids it,
    # so demanding it of a threat is a finding no author can fix.
    _write_object(tmp_path, "simulated-actor.yaml", _BARE + "  author: Jane\n")
    rule = tmp_path / "objects" / "rules" / "simulated-rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "name: Simulated Rule\nmetadata:\n"
        "  uuid: 00000000-0000-4000-8001-000000000002\n"
        "  schema: rule::1.1\n  author: Jane\n",
        encoding="utf-8",
    )
    _write_lint_toml(tmp_path, '[metadata]\nrequired = ["author", "reviewed"]\n')
    findings = run_lint(tmp_path)["findings"]
    assert [(item["path"], item["message"]) for item in findings] == [
        ("objects/rules/simulated-rule.yaml", "Recommended metadata missing: reviewed")
    ]
