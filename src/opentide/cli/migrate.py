"""Client migration helper — detect and rewrite legacy imports."""

from __future__ import annotations
import re
from pathlib import Path

_LEGACY_IMPORTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile("from Engines\\.modules\\.tide import DataTide"), "from opentide import OpenTide"),
    (re.compile("from Engines\\.modules\\.tide import OpenTide"), "from opentide import OpenTide"),
    (
        re.compile("from Engines\\.modules\\.tide import IndexTide"),
        "from opentide.core.index_manager import IndexManager",
    ),
    (re.compile("python Orchestration/validate\\.py"), "opentide validate"),
    (re.compile("python Orchestration/deploy\\.py"), "opentide deploy"),
    (re.compile("python Orchestration/generate\\.py"), "opentide generate"),
    (re.compile("python Orchestration/document\\.py"), "opentide document"),
)


def scan_repo(repo: Path) -> list[dict[str, str]]:
    """Return legacy patterns found in Python/shell files."""
    findings: list[dict[str, str]] = []
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in {".py", ".sh", ".yml", ".yaml", ".md"}:
            continue
        if any((part in path.parts for part in (".venv", "node_modules", ".git"))):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for pattern, replacement in _LEGACY_IMPORTS:
            if pattern.search(text):
                findings.append(
                    {
                        "file": str(path.relative_to(repo)),
                        "pattern": pattern.pattern,
                        "suggestion": replacement,
                    }
                )
    return findings


def apply_migrations(repo: Path) -> list[str]:
    """Rewrite known legacy patterns in place."""
    changed: list[str] = []
    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".sh", ".yml", ".yaml", ".md"}:
            continue
        if any((part in path.parts for part in (".venv", "node_modules", ".git"))):
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except Exception:
            continue
        updated = original
        for pattern, replacement in _LEGACY_IMPORTS:
            updated = pattern.sub(replacement, updated)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed.append(str(path.relative_to(repo)))
    return changed
