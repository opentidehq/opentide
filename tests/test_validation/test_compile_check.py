"""``compile_issues``: what an offline compiler raises, as a validate error (#660)."""

from __future__ import annotations

from typing import Any

import pytest

from opentide.validation import compile_check


@pytest.fixture
def deploying(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compile_check, "_deploys", lambda status: status == "STAGING")


def _body(platform: str, status: str = "STAGING") -> dict[str, Any]:
    return {"configurations": {platform: {"status": status}}}


@pytest.mark.usefixtures("deploying")
def test_a_python_error_names_the_platform_not_the_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(platform: str, rule: object) -> dict[str, Any]:
        raise KeyError("index")

    monkeypatch.setattr("opentide.deployment.preview.compile_offline", fail)
    (issue,) = compile_check.compile_issues(object(), _body("elastic"), {"elastic"})
    assert issue.code == "compile_failed"
    assert issue.message.startswith("Elastic cannot compile this rule")
    assert "KeyError" not in issue.message
    assert issue.field_path == ("configurations", "elastic")
    assert issue.yaml_line is None


@pytest.mark.usefixtures("deploying")
def test_only_enabled_platforms_with_a_compiler_and_a_deploying_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled: list[str] = []
    monkeypatch.setattr(
        "opentide.deployment.preview.compile_offline",
        lambda platform, rule: compiled.append(platform) or {},
    )
    body = {
        "configurations": {
            "sentinel": {"status": "STAGING"},
            "elastic": {"status": "DESIGN"},
            "splunk": {"status": "STAGING"},
        }
    }
    assert compile_check.compile_issues(object(), body, {"sentinel", "elastic", "splunk"}) == []
    assert compiled == ["sentinel"]
    assert compile_check.compile_issues(object(), body, {"elastic", "splunk"}) == []
    assert compiled == ["sentinel"]


def test_an_unknown_status_is_left_to_the_schema_check() -> None:
    assert compile_check._deploys(None) is False
