"""The Rust supply-chain gates (#843) say what docs/internal/supply-chain.md says.

``deny.toml`` is what ``cargo deny check`` enforces on every pull request.
These tests keep it in step with ``about.toml`` (the licences each engine
release lists in THIRD-PARTY-LICENSES.html), and keep its exceptions explained.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]


def _toml(name: str) -> dict[str, Any]:
    return tomllib.loads((ROOT / name).read_text(encoding="utf-8"))


def test_deny_allows_the_licences_about_accepts() -> None:
    """One licence list: cargo-deny gates what cargo-about renders."""
    deny = _toml("deny.toml")["licenses"]
    about = _toml("about.toml")
    assert sorted(deny["allow"]) == sorted(about["accepted"])
    # The workspace's own licence, and EUPL-1.2's compatible set: no
    # copyleft licence (GPL, LGPL, MPL) slips in by being added to one file.
    assert "EUPL-1.2" in deny["allow"]
    assert not [lic for lic in deny["allow"] if "GPL" in lic or "MPL" in lic]


def test_every_advisory_exception_has_a_reason_and_an_issue() -> None:
    advisories = _toml("deny.toml")["advisories"]
    for entry in advisories.get("ignore", []):
        assert isinstance(entry, dict), f"{entry}: give `{{ id, reason }}`"
        assert entry.get("reason"), f"{entry['id']} has no reason"
        assert "#" in entry["reason"], f"{entry['id']}: name the follow-up issue"
    assert advisories["unmaintained"] == "all"
    assert advisories["yanked"] == "deny"


def test_openssl_is_banned_in_favour_of_rustls() -> None:
    banned = {entry["crate"] for entry in _toml("deny.toml")["bans"]["deny"]}
    assert {"openssl-sys", "openssl", "native-tls"} <= banned


def test_duplicates_and_sources_fail_unless_explained() -> None:
    deny = _toml("deny.toml")
    assert deny["bans"]["multiple-versions"] == "deny"
    for entry in deny["bans"].get("skip", []):
        assert isinstance(entry, dict) and entry.get("reason"), entry
    sources = deny["sources"]
    assert sources["unknown-registry"] == "deny"
    assert sources["unknown-git"] == "deny"
    assert sources["allow-registry"] == ["https://github.com/rust-lang/crates.io-index"]
