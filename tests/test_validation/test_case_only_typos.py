"""A value that differs from an allowed one only in case or separators is the same word.

``tlp: AMBER`` got no suggestion (difflib compared case-sensitively and scored
it under the cutoff), and a platform ``status: design`` passed ``validate``
although deploy matches statuses by exact name and rejects it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide.core.registry import Opentide
from opentide.validation.field_vocab import (
    CONFIG_ENUM_RESOLVERS,
    validate_object_vocab_from_metaschema,
)
from opentide.validation.vocab_resolver import RuntimeEnumResolver, closest_value

TLP = ["clear", "green", "amber", "amber+strict", "red"]
SEVERITY = ["Informational", "Localised incident", "Substantial incident"]


@pytest.mark.parametrize(
    ("value", "allowed", "expected"),
    [
        ("AMBER", TLP, "amber"),
        ("Clear", TLP, "clear"),
        ("localised_incident", SEVERITY, "Localised incident"),
        ("LOCALISED-INCIDENT", SEVERITY, "Localised incident"),
        ("design", ["DESIGN", "DEVELOPMENT"], "DESIGN"),
        # Not the same word: still the closest, compared without case.
        ("AMBR", TLP, "amber"),
        ("clearr", TLP, "clear"),
        ("purple", TLP, None),
    ],
)
def test_closest_value(value: str, allowed: list[str], expected: str | None) -> None:
    assert closest_value(value, allowed) == expected


def test_the_same_word_wins_over_a_closer_spelling() -> None:
    """``amber+strict`` must not take ``AMBER``: the respelling is exact."""
    assert closest_value("AMBER", ["amber+strict", "amber"]) == "amber"


def test_the_runtime_resolver_suggests_across_case() -> None:
    resolver = RuntimeEnumResolver(
        {"tlp": Opentide.Vocabularies.Index["tlp"]}, object_types=("tlp",)
    )
    assert resolver.suggest("AMBER", "tlp") == "amber"
    assert resolver.suggest("Clear", "tlp") == "clear"


_RULE_SCHEMA: dict[str, Any] = {"properties": {"name": {"type": "string"}}}


def _rule(status: Any) -> dict[str, Any]:
    return {
        "name": "Rule",
        "metadata": {"schema": "rule::1.0"},
        "configurations": {"sentinel": {"status": status, "query": "x"}},
    }


@pytest.fixture
def statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        CONFIG_ENUM_RESOLVERS, "tide.config.statuses", lambda: ["DESIGN", "STAGING"]
    )


def _check(payload: dict[str, Any]) -> list:
    return validate_object_vocab_from_metaschema(
        payload, {"rule::1.0": _RULE_SCHEMA}, "rule", MagicMock(), object_uuid="u"
    )


@pytest.mark.usefixtures("statuses")
def test_a_platform_status_in_the_wrong_case_is_reported_with_its_spelling() -> None:
    issues = _check(_rule("design"))
    assert len(issues) == 1
    issue = issues[0]
    assert issue.code == "config_enum_unknown"
    assert issue.field_path == ("configurations", "sentinel", "status")
    assert issue.suggestion == "DESIGN"
    assert issue.context["setting"] == "statuses"


@pytest.mark.usefixtures("statuses")
def test_a_configured_platform_status_passes() -> None:
    assert _check(_rule("STAGING")) == []


def test_no_configured_status_leaves_the_field_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(CONFIG_ENUM_RESOLVERS, "tide.config.statuses", lambda: [])
    assert _check(_rule("anything")) == []
