"""Docs must not say a platform's queries wait for ``OFFLINE_QUERY_LANGUAGES`` once they are in it.

#874 put CrowdStrike (CQL) in ``OFFLINE_QUERY_LANGUAGES``, so ``validate``, ``lint``,
``validate query`` and MCP ``validate_query`` report the ``cql_*`` codes offline. Two
Markdown files (``crates/opentide-cql/AGENTS.md`` and ``docs/engine/IMPORT.md``) still
said those commands did not report CQL "until CrowdStrike is in
``OFFLINE_QUERY_LANGUAGES``", which misleads both agents and readers.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from opentide.validation.query_platforms import OFFLINE_QUERY_LANGUAGES

ROOT = Path(__file__).resolve().parents[2]

#: ``until CrowdStrike is in `OFFLINE_QUERY_LANGUAGES```
_PENDING_CLAIM = re.compile(
    r"until\s+(\w[\w ]*?)\s+is\s+in\s+`OFFLINE_QUERY_LANGUAGES`", re.IGNORECASE
)


def _tracked_markdown() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "*.md"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return [ROOT / name for name in listed.split("\0") if name]


def _platform_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _offline_keys() -> set[str]:
    return {_platform_key(key) for key in OFFLINE_QUERY_LANGUAGES}


def test_crowdstrike_is_checked_offline() -> None:
    assert "crowdstrike" in _offline_keys()


def test_no_doc_says_an_offline_platform_is_still_pending() -> None:
    stale = [
        f"{path.relative_to(ROOT)}: {match.group(0)}"
        for path in _tracked_markdown()
        for match in _PENDING_CLAIM.finditer(path.read_text(encoding="utf-8"))
        if _platform_key(match.group(1)) in _offline_keys()
    ]
    assert stale == []
