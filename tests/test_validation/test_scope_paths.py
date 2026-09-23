"""Unit tests for path-aware ``--file`` scoping and YAML parse issues (#240, #250)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.validation_support import assert_issues_point_at_their_objects

from opentide.validation.scope import ValidationScope
from opentide.validation.session import _IdScanParseError, _scan_id_file, _yaml_parse_issues


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


def test_a_path_target_never_matches_an_object_whose_path_is_unknown() -> None:
    """The basename fallback is what let a parent path select a nested twin (#297)."""
    scope = ValidationScope.narrow(files=frozenset({"objects/rules/rule.yaml"}))
    assert not scope.matches_file("rule.yaml")
    assert not scope.includes_object("uuid-1", "rule", file_name="rule.yaml")


def test_scope_matches_a_repo_relative_target_from_another_directory(tmp_path: Path) -> None:
    """``--repo`` and the working directory routinely differ."""
    rule = tmp_path / "objects" / "rules" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("name: x\n", encoding="utf-8")

    scope = ValidationScope.narrow(files=frozenset({"objects/rules/rule.yaml"}), roots=(tmp_path,))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_scope_resolves_a_repo_relative_target_against_the_workspace_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callers that pass no roots, like the MCP ``validation_report`` tool, still get the repo."""
    from opentide.core.root import get_repo_root

    repo = tmp_path / "repo"
    rule = repo / "objects" / "rules" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("name: x\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("OPENTIDE_TIDE_WORKSPACE", raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    get_repo_root.cache_clear()
    try:
        scope = ValidationScope.narrow(files=frozenset({"objects/rules/rule.yaml"}))
    finally:
        get_repo_root.cache_clear()
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_scope_matches_absolute_target(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yaml"
    rule.write_text("name: x\n", encoding="utf-8")
    scope = ValidationScope.narrow(files=frozenset({str(rule)}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_a_path_target_does_not_match_the_same_name_in_another_directory(tmp_path: Path) -> None:
    """The directory component has to mean something.

    Falling back to the basename unconditionally made ``--file`` validate
    whichever object happened to share the name, and a target that resolves
    nowhere at all matched too.
    """
    threat = tmp_path / "objects" / "threats" / "shared.yaml"
    threat.parent.mkdir(parents=True)
    threat.write_text("name: x\n", encoding="utf-8")

    scope = ValidationScope.narrow(
        files=frozenset({"objects/rules/shared.yaml"}), roots=(tmp_path,)
    )
    assert not scope.includes_object("uuid-1", "threat", file_name="shared.yaml", file_path=threat)


def test_a_target_that_resolves_nowhere_matches_nothing(tmp_path: Path) -> None:
    rule = tmp_path / "objects" / "rules" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("name: x\n", encoding="utf-8")

    scope = ValidationScope.narrow(files=frozenset({"/nowhere/at/all/rule.yaml"}))
    assert not scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_a_bare_basename_still_matches_a_known_path(tmp_path: Path) -> None:
    """Relaxing the fallback must not break the documented basename form."""
    rule = tmp_path / "objects" / "rules" / "rule.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text("name: x\n", encoding="utf-8")

    scope = ValidationScope.narrow(files=frozenset({"rule.yaml"}))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


def test_scope_still_honours_object_types(tmp_path: Path) -> None:
    rule = tmp_path / "objects" / "rules" / "rule.yaml"
    target = frozenset({"objects/rules/rule.yaml"})
    scope = ValidationScope.narrow(files=target, roots=(tmp_path,))
    assert scope.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)
    typed = ValidationScope.narrow(files=target, types=frozenset({"threat"}), roots=(tmp_path,))
    assert not typed.includes_object("uuid-1", "rule", file_name="rule.yaml", file_path=rule)


_NESTED_TWINS = (
    "objects/rules/twin.yaml",
    "objects/rules/team-a/twin.yaml",
    "objects/rules/team-a/emea/twin.yaml",
    "objects/rules/team-b/twin.yaml",
    "objects/threats/twin.yaml",
    "objects/threats/actors/apt/twin.yaml",
    "objects/objectives/access/twin.yaml",
)


@pytest.mark.parametrize("target", _NESTED_TWINS)
@pytest.mark.parametrize("form", ["repo-relative", "dot-relative", "absolute"])
def test_a_path_target_matches_only_its_own_file_among_same_named_twins(
    tmp_path: Path, target: str, form: str
) -> None:
    """Same basename at depth 1, 2 and 3, across object types (#297)."""
    written = {relative: tmp_path / relative for relative in _NESTED_TWINS}
    for path in written.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("name: x\n", encoding="utf-8")
    spelled = {
        "repo-relative": target,
        "dot-relative": f"./{target}",
        "absolute": str(tmp_path / target),
    }[form]
    scope = ValidationScope.narrow(files=frozenset({spelled}), roots=(tmp_path,))
    matched = {rel for rel, path in written.items() if scope.matches_file(path.name, path)}
    assert matched == {target}


def test_a_bare_basename_matches_the_same_name_at_every_depth(tmp_path: Path) -> None:
    scope = ValidationScope.narrow(files=frozenset({"twin.yaml"}), roots=(tmp_path,))
    for relative in _NESTED_TWINS:
        path = tmp_path / relative
        assert scope.matches_file(path.name, path), relative
    assert not scope.matches_file("other.yaml", tmp_path / "objects" / "rules" / "other.yaml")


def test_a_bare_basename_matches_by_the_path_when_no_name_is_given(tmp_path: Path) -> None:
    scope = ValidationScope.narrow(files=frozenset({"twin.yaml"}), roots=(tmp_path,))
    assert scope.matches_file(None, tmp_path / "objects" / "rules" / "deep" / "twin.yaml")
    assert not scope.matches_file(None, None)


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
    assert_issues_point_at_their_objects(matched)
    skipped = _yaml_parse_issues(errors, ValidationScope.narrow(files=frozenset({"other.yaml"})))
    assert skipped == []


def test_yaml_parse_issues_match_a_path_target_by_the_broken_files_own_path(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "objects" / "rules" / "team-a" / "broken.yaml"
    errors = [{"path": str(nested), "object_type": "rule", "error": "boom"}]
    parent = ValidationScope.narrow(
        files=frozenset({"objects/rules/broken.yaml"}), roots=(tmp_path,)
    )
    assert _yaml_parse_issues(errors, parent) == []
    own = ValidationScope.narrow(
        files=frozenset({"objects/rules/team-a/broken.yaml"}), roots=(tmp_path,)
    )
    assert [issue.file_path for issue in _yaml_parse_issues(errors, own)] == [nested]


def test_yaml_parse_issues_respect_narrow_type_scope() -> None:
    errors = [{"path": "/repo/objects/rules/broken.yaml", "object_type": "rule", "error": "boom"}]
    skipped = _yaml_parse_issues(errors, ValidationScope.narrow(types=frozenset({"threat"})))
    assert skipped == []


def test_scan_id_file_reports_unparseable_yaml(tmp_path: Path) -> None:
    """Returning ``None`` here turned a crash into silence.

    The indexer and the ID scan do not walk the same files, so "the index
    already reported it" was not true for ``*.debug.yaml`` and the file was
    dropped without any issue at all.
    """
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [\n", encoding="utf-8")
    result = _scan_id_file((broken, "rule"))
    assert isinstance(result, _IdScanParseError)
    assert result.meta_name == "rule"
    assert result.error
