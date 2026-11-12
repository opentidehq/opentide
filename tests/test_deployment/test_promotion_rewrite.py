"""Promotion rewrites only ``configurations.<platform>.status``, over its exact characters."""

from __future__ import annotations

import codecs
import os
import stat
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


@pytest.mark.skipif(os.name == "nt", reason="Windows files have no permission bits to keep")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o755])
def test_the_promoted_file_keeps_its_permission_bits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    """mkstemp makes the rewritten file 0600: a committed 0644 rule came back owner-only (#987)."""
    monkeypatch.setattr(promotion, "PROMOTION_TARGET", "PRODUCTION")
    path = tmp_path / "rule.yaml"
    path.write_text(_RULE, encoding="utf-8")
    path.chmod(mode)
    promotion.PromoteMDR().edit_mdr_statuses(path, ["STAGING"])
    assert "status: PRODUCTION" in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert [p.name for p in tmp_path.iterdir()] == ["rule.yaml"]


@pytest.mark.parametrize(
    "configurations",
    [
        pytest.param(
            "  sentinel: {status: &s STAGING}\n  splunk: {status: *s}\n", id="anchor-and-alias"
        ),
        pytest.param(
            "  sentinel: &base {status: STAGING, query: q}\n  defender: {<<: *base}\n",
            id="merge-key",
        ),
    ],
)
def test_a_status_promotion_cannot_rewrite_alone_is_refused(configurations: str) -> None:
    from opentide.mutation.promotion import PromotionRefused

    with pytest.raises(PromotionRefused):
        promote_block_statuses("configurations:\n" + configurations, ["STAGING"], "PRODUCTION")


def _promote(monkeypatch: pytest.MonkeyPatch, files: list[Path]) -> None:
    monkeypatch.setattr(promotion, "DEBUG", False)
    monkeypatch.setattr(promotion, "PROMOTION_ENABLED", True)
    monkeypatch.setattr(promotion, "PROMOTION_TARGET", "PRODUCTION")
    monkeypatch.setattr(promotion, "VALID_STATUSES", ["STAGING", "PRODUCTION"])
    monkeypatch.setattr(promotion, "NON_PROMOTABLE_STATUSES", ["PRODUCTION"])
    promotion.PromoteMDR().promote(files)


def test_an_aliased_status_leaves_its_file_and_promotes_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plain = tmp_path / "a.yaml"
    plain.write_text(_RULE, encoding="utf-8")
    aliased = tmp_path / "b.yaml"
    aliased_text = (
        "name: B\nconfigurations:\n  sentinel: {status: &s STAGING}\n  splunk: {status: *s}\n"
    )
    aliased.write_text(aliased_text, encoding="utf-8")
    _promote(monkeypatch, [aliased, plain])
    assert aliased.read_text(encoding="utf-8") == aliased_text
    assert "status: PRODUCTION" in plain.read_text(encoding="utf-8")


def test_a_file_that_cannot_be_planned_fails_before_any_file_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Writing as it went, promotion left earlier files promoted for the write-back to commit."""
    first = tmp_path / "a.yaml"
    first.write_text(_RULE, encoding="utf-8")
    broken = tmp_path / "b.yaml"
    broken.write_text("name: B\nconfigurations:\n  sentinel:\n    status: STAGING\n", "utf-8")
    monkeypatch.setattr(
        promotion,
        "promote_block_statuses",
        lambda text, statuses, target: (
            (_ for _ in ()).throw(ValueError("boom"))
            if text.startswith("name: B")
            else text.replace("status: STAGING  #", "status: PRODUCTION  #")
        ),
    )
    with pytest.raises(ValueError, match=r"b\.yaml: cannot promote"):
        _promote(monkeypatch, [first, broken])
    assert first.read_text(encoding="utf-8") == _RULE
