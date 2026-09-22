"""Unit tests for path-aware ``--file`` scoping and YAML parse issues (#240, #250)."""

from __future__ import annotations

from pathlib import Path

from opentide.validation.scope import ValidationScope
from opentide.validation.session import _scan_id_file, _yaml_parse_issues


def test_scope_matches_basename_target() -> None:
    scope = ValidationScope.narrow(files=frozenset({"rule.yaml"}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml")
    assert not scope.includes_object("uuid-2", "rule", file_name="other.yaml")


def test_scope_matches_repo_relative_target(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    rule = tmp_path / "objects" / "rules" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("name: x\n", encoding="utf-8")

    scope = ValidationScope.narrow(files=frozenset({"objects/rules/rule.yaml"}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml")


def test_scope_matches_absolute_target(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("name: x\n", encoding="utf-8")
    scope = ValidationScope.narrow(files=frozenset({str(rule)}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_scope_still_honours_object_types() -> None:
    scope = ValidationScope.narrow(files=frozenset({"objects/rules/rule.yaml"}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml")
    typed = ValidationScope.narrow(
        files=frozenset({"objects/rules/rule.yaml"}), types=frozenset({"threat"})
    )
    assert not typed.includes_object("uuid-1", "rule", file_name="rule.yaml")


def test_yaml_parse_issues_reported_for_full_scope() -> None:
    issues = _yaml_parse_issues(
        [{"path": "/repo/objects/rules/broken.yaml", "object_type": "rule", "error": "boom"}],
        ValidationScope.full(),
    )
    assert [issue.code for issue in issues] == ["yaml_parse"]
    assert issues[0].severity == "error"
    assert "boom" in issues[0].message


def test_yaml_parse_issues_respect_narrow_file_scope() -> None:
    errors = [{"path": "/repo/objects/rules/broken.yaml", "object_type": "rule", "error": "boom"}]
    matched = _yaml_parse_issues(errors, ValidationScope.narrow(files=frozenset({"broken.yaml"})))
    assert len(matched) == 1
    skipped = _yaml_parse_issues(errors, ValidationScope.narrow(files=frozenset({"other.yaml"})))
    assert skipped == []


def test_yaml_parse_issues_respect_narrow_type_scope() -> None:
    errors = [{"path": "/repo/objects/rules/broken.yaml", "object_type": "rule", "error": "boom"}]
    skipped = _yaml_parse_issues(errors, ValidationScope.narrow(types=frozenset({"threat"})))
    assert skipped == []


def test_scan_id_file_returns_none_for_unparseable_yaml(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [\n", encoding="utf-8")
    assert _scan_id_file((broken, "rule")) is None
