"""Sentinel `alert.techniques` accepts the ATT&CK v18 ids Sentinel is aligned to (#686).

The list is Sentinel's own (`data/sentinel/attack-v18.json`), not the `att&ck`
vocabulary, which follows the current ATT&CK release.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

import pytest
import yaml
from pydantic import ValidationError
from pydantic.fields import FieldInfo
from tests.corpus_support import TIDE_CORPUS_ROOT

from opentide.models.platform_configs import SentinelAlert
from opentide.models.sentinel_attack import (
    SENTINEL_ATTACK_VERSION,
    SentinelTechnique,
    _data,
    check_sentinel_technique,
    sentinel_techniques,
)
from opentide.validation.pipeline import validate_raw_payload

CORPUS_SENTINEL_RULE = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"


def _error(techniques: list[str]) -> dict[str, Any]:
    with pytest.raises(ValidationError) as caught:
        SentinelAlert(techniques=techniques)
    (error,) = caught.value.errors()
    return dict(error)


def test_the_list_is_attack_18_1_across_the_three_matrices() -> None:
    techniques = sentinel_techniques()

    assert SENTINEL_ATTACK_VERSION == "18"
    assert _data()["attack"] == "18.1"
    assert _data()["domains"] == ["enterprise", "mobile", "ics"]
    assert len(techniques) == 898
    assert sum("." in key for key in techniques) == 522
    assert list(techniques) == sorted(techniques)
    assert techniques["T1556.009"] == "Modify Authentication Process: Conditional Access Policies"
    # Enterprise, Mobile and ICS ids, an id added in v17, and one v19 revoked.
    assert {"T1078", "T1456", "T0800", "T1667", "T1562.001"} <= set(techniques)
    # Added after v18.
    assert "T1685" not in techniques
    assert "T1696" not in techniques


def test_later_ids_are_disjoint_and_replace_only_v18_ids() -> None:
    later = _data()["later"]
    techniques = sentinel_techniques()

    assert later["attack"] == "20.0"
    assert not set(later["techniques"]) & set(techniques)
    for entry in later["techniques"].values():
        assert set(entry["replaces"]) <= set(techniques)
    assert later["techniques"]["T1685"]["replaces"] == ["T1562", "T1562.001", "T1562.006"]


def test_v18_techniques_and_sub_techniques_are_accepted() -> None:
    alert = SentinelAlert(techniques=["T1556", "T1556.009", "T1667", "T0800"])

    assert alert.techniques == ["T1556", "T1556.009", "T1667", "T0800"]


def test_an_id_newer_than_v18_names_the_v18_ids_it_replaced() -> None:
    error = _error(["T1685"])

    assert error["type"] == "sentinel_attack_technique"
    assert error["loc"] == ("techniques", 0)
    assert error["msg"] == (
        "'T1685' is not an ATT&CK v18 technique or sub-technique id, which is what Sentinel is "
        "aligned to; T1685 (Disable or Modify Tools) is newer than ATT&CK v18: use T1562 or "
        "T1562.001 or T1562.006, which it replaced"
    )


def test_an_id_newer_than_v18_without_a_predecessor_says_so() -> None:
    assert _error(["T1696"])["msg"].endswith(
        "T1696 (Anti-Automation Evasion) is newer than ATT&CK v18 and has no v18 equivalent"
    )


@pytest.mark.parametrize("typo", ["t1556.009", "T1556.09"])
def test_a_near_miss_suggests_the_v18_id(typo: str) -> None:
    assert _error([typo])["msg"].endswith(
        "did you mean T1556.009 (Modify Authentication Process: Conditional Access Policies)?"
    )


def test_an_id_retired_before_v18_names_its_replacement() -> None:
    """A string match would suggest T1608 (Stage Capabilities) for T1086."""
    assert _error(["T1086"])["msg"].endswith(
        "ATT&CK retired T1086 (PowerShell) before v18: use T1059.001, which replaced it"
    )


def test_an_id_retired_before_v18_without_a_replacement_says_so() -> None:
    assert _error(["T1064"])["msg"].endswith(
        "ATT&CK retired T1064 (Scripting) before v18 without a replacement"
    )


def test_retired_ids_are_not_v18_ids_and_point_at_v18_ids() -> None:
    retired = _data()["retired"]
    techniques = sentinel_techniques()

    assert not set(retired) & set(techniques)
    for entry in retired.values():
        assert set(entry["replaced_by"]) <= set(techniques)


def test_the_enum_is_built_when_a_schema_is_generated_not_at_import() -> None:
    """The 898-entry enum is a callable ``json_schema_extra``, run by schema generation."""
    (info,) = [meta for meta in get_args(SentinelTechnique)[1:] if isinstance(meta, FieldInfo)]

    assert callable(info.json_schema_extra)


def test_an_unrelated_value_has_no_suggestion() -> None:
    assert _error(["nonsense"])["msg"] == (
        "'nonsense' is not an ATT&CK v18 technique or sub-technique id, which is what Sentinel "
        "is aligned to"
    )


def test_check_returns_a_valid_id_unchanged() -> None:
    assert check_sentinel_technique("T1078.004") == "T1078.004"


def test_the_json_schema_offers_the_v18_ids_with_their_names() -> None:
    schema = SentinelAlert.model_json_schema()["properties"]["techniques"]
    (array,) = [branch for branch in schema["anyOf"] if branch.get("type") == "array"]
    items = array["items"]

    assert items["enum"] == list(sentinel_techniques())
    assert items["markdownEnumDescriptions"][items["enum"].index("T1556.009")] == (
        "**T1556.009** Modify Authentication Process: Conditional Access Policies"
    )


def _rule_with(techniques: list[str]) -> dict[str, Any]:
    data = yaml.safe_load(CORPUS_SENTINEL_RULE.read_text(encoding="utf-8"))
    data["configurations"]["sentinel"]["alert"]["techniques"] = techniques
    return data


def test_validate_rejects_a_rule_whose_sentinel_techniques_are_not_v18(
    tide_corpus_repo: Path,
) -> None:
    result = validate_raw_payload(_rule_with(["T1685"]), "rule")

    assert not result.ok
    (error,) = result.errors
    assert "('configurations', 'sentinel', 'alert', 'techniques', 0)" in error
    assert "use T1562 or T1562.001 or T1562.006" in error


def test_validate_accepts_v18_sentinel_techniques(tide_corpus_repo: Path) -> None:
    result = validate_raw_payload(_rule_with(["T1562.001"]), "rule")

    assert result.ok, result.errors


def test_the_rule_level_techniques_field_still_follows_the_vocabulary() -> None:
    """The constraint is the Sentinel block's: the rule's own `techniques` is not limited to v18."""
    from opentide.models.rule import DetectionRule

    field = DetectionRule.model_fields["techniques"]

    assert "enum" not in str(field.json_schema_extra or {})
    assert field.annotation == list[str]
