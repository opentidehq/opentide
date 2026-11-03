"""Promotion rewrites only ``configurations.<platform>.status``, over its exact characters."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest
import yaml

from opentide.mutation import promotion
from opentide.mutation.promotion import promote_block_statuses

_RULE = (
    "name: Rule\n"
    "description: |\n"
    "  Moves from STAGING; the configurations below say status: STAGING.\n"
    "status: STAGING\n"
    "configurations:\n"
    "  sentinel:\n"
    "    status: STAGING  # was STAGING before\n"
    "    alert:\n"
    "      status: STAGING\n"
    "  splunk:\n"
    "    status: 'STAGING'\n"
    "  elastic:\n"
    "    status: PRE-STAGING\n"
)


def test_only_each_block_status_moves() -> None:
    promoted = promote_block_statuses(_RULE, ["STAGING"], "PRODUCTION")
    assert promoted == (
        "name: Rule\n"
        "description: |\n"
        "  Moves from STAGING; the configurations below say status: STAGING.\n"
        "status: STAGING\n"
        "configurations:\n"
        "  sentinel:\n"
        "    status: PRODUCTION  # was STAGING before\n"
        "    alert:\n"
        "      status: STAGING\n"
        "  splunk:\n"
        "    status: PRODUCTION\n"
        "  elastic:\n"
        "    status: PRE-STAGING\n"
    )


def test_nothing_to_promote_returns_the_text_unchanged() -> None:
    assert promote_block_statuses(_RULE, ["DEVELOPMENT"], "PRODUCTION") is _RULE


def test_a_target_yaml_would_read_as_another_type_is_quoted() -> None:
    promoted = promote_block_statuses(_RULE, ["STAGING"], "yes")
    assert yaml.safe_load(promoted)["configurations"]["sentinel"]["status"] == "yes"


@pytest.mark.parametrize("bom", [False, True])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_the_file_keeps_its_line_endings_and_byte_order_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, newline: str, bom: bool
) -> None:
    monkeypatch.setattr(promotion, "PROMOTION_TARGET", "PRODUCTION")
    path = tmp_path / "rule.yaml"
    original = (codecs.BOM_UTF8 if bom else b"") + _RULE.replace("\n", newline).encode()
    path.write_bytes(original)
    promotion.PromoteMDR().edit_mdr_statuses(path, ["STAGING"])
    written = path.read_bytes()
    assert written.startswith(codecs.BOM_UTF8) is bom
    assert written.count(b"\r\n") == original.count(b"\r\n")
    assert written.count(b"PRODUCTION") == 2
    assert [p.name for p in tmp_path.iterdir()] == ["rule.yaml"]
