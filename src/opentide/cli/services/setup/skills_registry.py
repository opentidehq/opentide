"""Skills catalogue discovery from bundled manifest and optional remote refresh."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from opentide.package.paths import bundled_data_root

logger = structlog.get_logger("opentide.cli.services.setup.skills_registry")

_MANIFEST_PATH = bundled_data_root() / "skills" / "manifest.json"
_RAW_BASE = "https://raw.githubusercontent.com/OpenTideHQ/skills/{ref}/skills/{slug}/SKILL.md"
_FRONTMATTER_NAME = re.compile(r"^name:\s*(.+)$", re.MULTILINE)
_FRONTMATTER_DESC = re.compile(r"^description:\s*(.+)$", re.MULTILINE)


@dataclass(frozen=True)
class SkillEntry:
    name: str
    slug: str
    description: str

    def to_dict(self, *, installed: bool = False) -> dict[str, Any]:
        return {
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "installed": installed,
            "path": f".agents/skills/{self.slug}/",
        }


def _parse_manifest(data: dict[str, Any]) -> tuple[str, str, list[SkillEntry]]:
    source = str(data.get("source", "OpenTideHQ/skills"))
    ref = str(data.get("ref", "main"))
    skills: list[SkillEntry] = []
    for item in data.get("skills", []):
        if not isinstance(item, dict):
            continue
        slug = str(item.get("slug") or item.get("name", ""))
        name = str(item.get("name", slug))
        description = str(item.get("description", ""))
        if slug:
            skills.append(SkillEntry(name=name, slug=slug, description=description))
    return source, ref, skills


@lru_cache(maxsize=1)
def load_manifest(*, refresh: bool = False) -> tuple[str, str, list[SkillEntry]]:
    """Load skills manifest from bundle or refresh from GitHub."""
    if refresh:
        try:
            return _fetch_remote_manifest()
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            logger.warning("skills_manifest_refresh_failed", error=str(exc))
    if not _MANIFEST_PATH.is_file():
        return "OpenTideHQ/skills", "main", []
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return _parse_manifest(data)


def _fetch_remote_manifest() -> tuple[str, str, list[SkillEntry]]:
    """Build manifest by listing known slugs from bundled manifest and refreshing descriptions."""
    _, ref, bundled = _parse_manifest(json.loads(_MANIFEST_PATH.read_text(encoding="utf-8")))
    refreshed: list[SkillEntry] = []
    for entry in bundled:
        url = _RAW_BASE.format(ref=ref, slug=entry.slug)
        try:
            text = urllib.request.urlopen(url, timeout=15).read().decode("utf-8")
        except (urllib.error.URLError, OSError):
            refreshed.append(entry)
            continue
        name = entry.name
        description = entry.description
        if text.startswith("---"):
            _, fm, _ = text.split("---", 2)
            if m := _FRONTMATTER_NAME.search(fm):
                name = m.group(1).strip()
            if m := _FRONTMATTER_DESC.search(fm):
                description = m.group(1).strip()
        refreshed.append(SkillEntry(name=name, slug=entry.slug, description=description))
    return "OpenTideHQ/skills", ref, refreshed


def _installed_slugs(repo: Path) -> set[str]:
    skills_dir = repo / ".agents" / "skills"
    if not skills_dir.is_dir():
        return set()
    return {p.name for p in skills_dir.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}


def discover_skills(
    repo: Path,
    *,
    query: str | None = None,
    installed_only: bool = False,
    refresh: bool = False,
) -> dict[str, Any]:
    source, ref, entries = load_manifest(refresh=refresh)
    installed = _installed_slugs(repo)
    q = (query or "").strip().lower()
    filtered: list[SkillEntry] = []
    for entry in entries:
        is_installed = entry.slug in installed
        if installed_only and not is_installed:
            continue
        if (
            q
            and q not in entry.name.lower()
            and q not in entry.slug.lower()
            and q not in entry.description.lower()
        ):
            continue
        filtered.append(entry)
    return {
        "source": f"{source}@{ref}",
        "skills": [e.to_dict(installed=e.slug in installed) for e in filtered],
        "count": len(filtered),
    }


def show_skill(repo: Path, name: str, *, refresh: bool = False) -> dict[str, Any]:
    source, ref, entries = load_manifest(refresh=refresh)
    needle = name.strip().lower()
    for entry in entries:
        if entry.slug.lower() == needle or entry.name.lower() == needle:
            installed = entry.slug in _installed_slugs(repo)
            return {
                "source": f"{source}@{ref}",
                "skill": entry.to_dict(installed=installed),
                "install_hint": f"opentide setup skills --install {entry.slug} --generic --yes",
            }
    return {"error": f"skill not found: {name}", "source": f"{source}@{ref}"}
