"""Tests for UTC datetime helpers."""

from __future__ import annotations

from datetime import datetime, timezone

from opentide.core.time import format_utc_z, utc_now, utc_now_iso


def test_utc_now_is_timezone_aware() -> None:
    now = utc_now()
    assert now.tzinfo == timezone.utc


def test_utc_now_iso_ends_with_z() -> None:
    assert utc_now_iso().endswith("Z")
    assert "+00:00" not in utc_now_iso()


def test_format_utc_z_from_aware_datetime() -> None:
    dt = datetime(2026, 6, 25, 12, 30, 45, 123456, tzinfo=timezone.utc)
    assert format_utc_z(dt) == "2026-06-25T12:30:45.123Z"
