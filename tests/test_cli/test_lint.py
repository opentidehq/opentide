"""Tests for ``opentide lint``."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import LintCheck
from opentide.cli.services.lint import run_lint

runner = CliRunner()

_THREAT = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
  author: SOC
  organisation: Example
"""


def _write_object(root: Path, family: str, filename: str, body: str) -> Path:
    dest = root / "objects" / family / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8")
    return dest


def test_lint_passes_matching_slug(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "simulated-actor.yaml", _THREAT)
    result = run_lint(tmp_path)
    assert result["count"] == 0
    assert result["_exit_code"] == 0


def test_lint_reports_filename_mismatch(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["expected"] == "objects/threats/simulated-actor.yaml"
    assert result["status"] == "issues"
    assert result["_exit_code"] == 0


def test_lint_strict_fails_on_findings(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], strict=True)
    assert result["status"] == "failed"
    assert result["_exit_code"] == 1


def test_lint_fix_renames_file(tmp_path: Path) -> None:
    src = _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert result["fixed"] == 1
    assert not src.exists()
    dest = tmp_path / "objects" / "threats" / "simulated-actor.yaml"
    assert dest.is_file()
    second = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert second["count"] == 0


def test_lint_fix_rewrites_metadata_path_when_the_filename_has_a_space(tmp_path: Path) -> None:
    """#353: a metadata finding kept the pre-rename path, so a second --fix looked stale."""
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
"""
    src = _write_object(tmp_path, "threats", "Simulated Actor.yaml", body)
    result = run_lint(tmp_path, fix=True)
    metadata = [item for item in result["findings"] if item["check"] == "metadata"]
    assert len(metadata) == 1
    assert metadata[0]["path"] == "objects/threats/simulated-actor.yaml"
    assert not src.exists()
    renamed = tmp_path / "objects" / "threats" / "simulated-actor.yaml"
    assert renamed.is_file()
    second = run_lint(tmp_path, fix=True)
    assert second["fixed"] == 0
    assert not (tmp_path / "objects" / "threats" / "simulated-actor-00000000.yaml").exists()
    assert all(
        item["path"] == "objects/threats/simulated-actor.yaml" for item in second["findings"]
    )


def test_lint_fix_collision_uses_uuid_suffix(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "simulated-actor.yaml", _THREAT)
    other = """\
name: Simulated Actor
metadata:
  uuid: 11111111-1111-4111-8111-111111111111
  schema: threat::1.0
"""
    _write_object(tmp_path, "threats", "other.yaml", other)
    result = run_lint(tmp_path, checks=[LintCheck.filenames], fix=True)
    assert (tmp_path / "objects" / "threats" / "simulated-actor.yaml").is_file()
    assert (tmp_path / "objects" / "threats" / "simulated-actor-11111111.yaml").is_file()
    assert result["fixed"] == 1


def test_lint_metadata_accepts_nested_organisation(tmp_path: Path) -> None:
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
  author: SOC
  organisation:
    uuid: 00000000-0000-4000-8000-000000000099
    name: Example Corp
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    result = run_lint(tmp_path, checks=[LintCheck.metadata])
    assert result["count"] == 0
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    result = run_lint(tmp_path, checks=[LintCheck.metadata])
    assert result["count"] == 1
    assert "author" in result["findings"][0]["message"]
    assert "organisation" in result["findings"][0]["message"]


def test_lint_check_filenames_skips_metadata(tmp_path: Path) -> None:
    body = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    result = run_lint(tmp_path, checks=[LintCheck.filenames])
    assert result["count"] == 0


def test_lint_cli_json(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "lint", "--check", "filenames"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["ok"] is True
    assert payload["status"] == "issues"


def test_lint_cli_human_lists_each_finding(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(app, ["--no-color", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 0, result.output
    assert (
        "[filenames/warning] objects/threats/Simulated Actor.yaml: Filename 'Simulated Actor.yaml'"
        " does not match slugify(name)='simulated-actor'"
    ) in result.output
    assert "ISSUES Catalogue lint found issues" in result.output


def test_lint_cli_human_names_the_renamed_file(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(app, ["--no-color", "--repo", str(tmp_path), "lint", "--fix"])
    assert result.exit_code == 0, result.output
    assert (
        "[filenames/warning] objects/threats/simulated-actor.yaml: Filename 'Simulated Actor.yaml'"
        " does not match slugify(name)='simulated-actor'"
        " (renamed from objects/threats/Simulated Actor.yaml)"
    ) in result.output


def test_lint_cli_strict(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    result = runner.invoke(
        app,
        ["--json", "--repo", str(tmp_path), "lint", "--check", "filenames", "--strict"],
    )
    assert result.exit_code == 1
    assert '"ok": false' in result.stdout


_NO_METADATA = """\
name: Simulated Actor
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  schema: threat::1.0
"""


def test_lint_metadata_finding_carries_uuid_severity_and_line(tmp_path: Path) -> None:
    """#488: a finding had only check, path and message, so it could not be triaged."""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", "# header\n" + _NO_METADATA)
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding == {
        "check": "metadata",
        "severity": "info",
        "path": "objects/threats/simulated-actor.yaml",
        "yaml_line": 2,
        "uuid": "00000000-0000-4000-8001-000000000001",
        "message": "Recommended metadata missing: author, organisation",
    }


def test_lint_metadata_finding_without_a_metadata_block_has_no_line(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "simulated-actor.yaml", "name: Simulated Actor\n")
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["yaml_line"] is None
    assert finding["uuid"] is None


def test_lint_filename_finding_carries_uuid_and_severity(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding == {
        "check": "filenames",
        "severity": "warning",
        "path": "objects/threats/Simulated Actor.yaml",
        "yaml_line": None,
        "uuid": "00000000-0000-4000-8001-000000000001",
        "expected": "objects/threats/simulated-actor.yaml",
        "message": "Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'",
    }


def test_lint_fixed_filename_finding_keeps_its_uuid(tmp_path: Path) -> None:
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _THREAT)
    (finding,) = run_lint(tmp_path, fix=True)["findings"]
    assert set(finding) == {
        "check",
        "severity",
        "path",
        "yaml_line",
        "uuid",
        "expected",
        "message",
        "fixed",
        "from",
    }
    assert finding["uuid"] == "00000000-0000-4000-8001-000000000001"
    assert finding["severity"] == "warning"


def test_lint_parse_error_is_an_error_without_uuid_or_line(tmp_path: Path) -> None:
    _write_object(tmp_path, "rules", "broken.yaml", "name: [unclosed\n")
    (finding,) = run_lint(tmp_path)["findings"]
    assert set(finding) == {"check", "severity", "path", "yaml_line", "uuid", "message"}
    assert finding["severity"] == "error"
    assert finding["uuid"] is None
    assert finding["yaml_line"] is None


def test_lint_unnamed_object_points_at_its_empty_name(tmp_path: Path) -> None:
    body = """\
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
name: ""
"""
    _write_object(tmp_path, "threats", "unnamed.yaml", body)
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding == {
        "check": "filenames",
        "severity": "error",
        "path": "objects/threats/unnamed.yaml",
        "yaml_line": 2,
        "uuid": "00000000-0000-4000-8001-000000000001",
        "message": "Object has no name; cannot check filename slug",
    }


def test_lint_cli_json_payload(tmp_path: Path) -> None:
    """Pin the ``--json lint`` document: one finding of each kind, in emitted order."""
    _write_object(tmp_path, "threats", "Simulated Actor.yaml", _NO_METADATA)
    _write_object(tmp_path, "rules", "broken.yaml", "- not a mapping\n")
    _write_object(tmp_path, "objectives", "unnamed.yaml", "metadata:\n  author: SOC\n")
    result = runner.invoke(app, ["--json", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "path": str(tmp_path.resolve()),
        "checks": ["filenames", "metadata"],
        "findings": [
            {
                "check": "metadata",
                "severity": "info",
                "path": "objects/threats/Simulated Actor.yaml",
                "yaml_line": 1,
                "uuid": "00000000-0000-4000-8001-000000000001",
                "message": "Recommended metadata missing: author, organisation",
            },
            {
                "check": "filenames",
                "severity": "warning",
                "path": "objects/threats/Simulated Actor.yaml",
                "yaml_line": None,
                "uuid": "00000000-0000-4000-8001-000000000001",
                "expected": "objects/threats/simulated-actor.yaml",
                "message": (
                    "Filename 'Simulated Actor.yaml' does not match slugify(name)='simulated-actor'"
                ),
            },
            {
                "check": "filenames",
                "severity": "error",
                "path": "objects/objectives/unnamed.yaml",
                "yaml_line": None,
                "uuid": None,
                "message": "Object has no name; cannot check filename slug",
            },
            {
                "check": "filenames",
                "severity": "error",
                "path": "objects/rules/broken.yaml",
                "yaml_line": None,
                "uuid": None,
                "message": "Could not parse object YAML: object YAML is not a mapping",
            },
        ],
        "count": 4,
        "fixed": 0,
        "ok": True,
        "status": "issues",
        "message": "Catalogue lint found issues",
    }
    assert list(payload["findings"][1]) == [
        "check",
        "severity",
        "path",
        "yaml_line",
        "uuid",
        "expected",
        "message",
    ]


def test_lint_cli_human_shows_severity_and_line(tmp_path: Path) -> None:
    """The human line carries the severity and a one-based ``path:line``, like validate."""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", _NO_METADATA)
    result = runner.invoke(app, ["--no-color", "--repo", str(tmp_path), "lint"])
    assert result.exit_code == 0, result.output
    assert (
        "[metadata/info] objects/threats/simulated-actor.yaml:2:"
        " Recommended metadata missing: author, organisation"
    ) in result.output


def test_lint_metadata_merged_from_an_anchor_has_no_line(tmp_path: Path) -> None:
    """A ``<<:`` merge key has no line of its own; lint must not crash on it."""
    body = """\
base: &base
  metadata:
    uuid: 00000000-0000-4000-8001-000000000001
<<: *base
name: Simulated Actor
"""
    _write_object(tmp_path, "threats", "simulated-actor.yaml", body)
    (finding,) = run_lint(tmp_path)["findings"]
    assert finding["check"] == "metadata"
    assert finding["yaml_line"] is None


def test_lint_object_built_only_from_a_merge_has_no_lines(tmp_path: Path) -> None:
    """With every key merged in, ruamel keeps no key lines for the mapping at all."""
    uuid = "00000000-0000-4000-8001-000000000001"
    _write_object(tmp_path, "threats", "a.yaml", f'<<: {{name: "", metadata: {{uuid: {uuid}}}}}\n')
    _write_object(tmp_path, "threats", "b.yaml", f"<<: {{name: B, metadata: {{uuid: {uuid}}}}}\n")
    findings = run_lint(tmp_path)["findings"]
    assert [(f["path"], f["check"], f["yaml_line"]) for f in findings] == [
        ("objects/threats/b.yaml", "metadata", None),
        ("objects/threats/a.yaml", "filenames", None),
    ]
