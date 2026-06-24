"""Tests for legacy indicator validation."""

from __future__ import annotations

from opentide.validation.legacy import indicator_validation


def test_indicator_validation_accepts_email() -> None:
    assert indicator_validation("email", "user@example.com", verbose=False) is True


def test_indicator_validation_rejects_bad_ip() -> None:
    assert indicator_validation("ip", "999.999.999.999", verbose=False) is False


def test_indicator_validation_uuid() -> None:
    assert (
        indicator_validation(
            "uuid",
            "00000000-0000-4000-8000-000000000001",
            verbose=False,
        )
        is True
    )


def test_indicator_validation_url_and_domain() -> None:
    assert indicator_validation("url", "https://example.com/path", verbose=False) is True
    assert indicator_validation("domain", "example.com", verbose=False) is True


def test_indicator_validation_hashes() -> None:
    md5 = "a" * 32
    sha1 = "b" * 40
    sha256 = "c" * 64
    assert indicator_validation("hash::md5", md5, verbose=False) is True
    assert indicator_validation("hash::sha1", sha1, verbose=False) is True
    assert indicator_validation("hash::sha256", sha256, verbose=False) is True


def test_indicator_validation_ip_versions() -> None:
    assert indicator_validation("ip", "192.168.0.1", verbose=False) is True
    ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert indicator_validation("ip::v6", ipv6, verbose=False) is True
