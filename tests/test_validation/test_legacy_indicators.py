"""Tests for legacy indicator validation helpers."""

from __future__ import annotations

import pytest

from opentide.validation.legacy import indicator_validation


def test_indicator_validation_accepts_valid_email() -> None:
    assert indicator_validation("email", "user@example.com", verbose=False) is True


def test_indicator_validation_rejects_invalid_email_quietly() -> None:
    assert indicator_validation("email", "not-an-email", verbose=False) is False


def test_indicator_validation_verbose_mode_returns_false_for_invalid_value() -> None:
    assert indicator_validation("domain", "not a domain", verbose=True) is False


def test_indicator_validation_unknown_type_raises() -> None:
    with pytest.raises(Exception, match="Invalid Type"):
        indicator_validation("hash::sha512", "deadbeef", verbose=False)
