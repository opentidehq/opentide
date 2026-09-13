"""Skills catalogue discovery from the live OpenTideHQ/skills manifest."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger("opentide.cli.services.setup.skills_registry")

_DEFAULT_SOURCE = "OpenTideHQ/skills"
_DEFAULT_REF = "main"
_CACHE_TTL_SECONDS = 30.0


class SkillsManifestError(RuntimeError):
    """Raised when the live OpenTideHQ/skills catalogue cannot be fetched."""


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


@dataclass(frozen=True)
class ManifestLoadResult:
    source: str
    ref: str
    entries: list[SkillEntry]
    manifest_source: str
    manifest_refreshed: bool


_manifest_cache: tuple[float, ManifestLoadResult] | None = None


def fetch_github_bytes(
    path: str,
    *,
    source: str = _DEFAULT_SOURCE,
    ref: str = _DEFAULT_REF,
) -> bytes | None:
    """Fetch raw file bytes from a public GitHub repository."""
    url = f"https://raw.githubusercontent.com/{source}/{ref}/{path}"
    request = urllib.request.Request(url)
    try:
        return urllib.request.urlopen(request, timeout=15).read()
    except (urllib.error.URLError, OSError):
        return None


def clear_manifest_cache() -> None:
    """Clear the in-process manifest TTL cache (for tests)."""
    global _manifest_cache
    _manifest_cache = None


def _normalise_source(raw: object) -> str:
    """Accept only the public OpenTideHQ/skills repo; ignore redirect attempts."""
    source = str(raw or _DEFAULT_SOURCE).strip()
    if source != _DEFAULT_SOURCE:
        logger.warning("skills_manifest_source_rejected", source=source, fallback=_DEFAULT_SOURCE)
        return _DEFAULT_SOURCE
    return source


def _parse_manifest(data: dict[str, Any]) -> tuple[str, str, list[SkillEntry]]:
    source = _normalise_source(data.get("source", _DEFAULT_SOURCE))
    ref = str(data.get("ref", _DEFAULT_REF)).strip() or _DEFAULT_REF
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


def _manifest_unavailable(*, ref: str = _DEFAULT_REF) -> SkillsManifestError:
    return SkillsManifestError(
        f"Could not fetch skills catalogue from {_DEFAULT_SOURCE}@{ref}. "
        "Check network access and that the skills repository is publicly reachable."
    )


def _fetch_remote_manifest(*, ref: str = _DEFAULT_REF) -> tuple[str, str, list[SkillEntry]] | None:
    payload = fetch_github_bytes("manifest.json", source=_DEFAULT_SOURCE, ref=ref)
    if payload is None:
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    source, manifest_ref, entries = _parse_manifest(data)
    return source, manifest_ref, entries


def load_manifest(*, refresh: bool = False) -> ManifestLoadResult:
    """Load the live skills catalogue. Never falls back to packaged skill trees."""
    global _manifest_cache
    now = time.monotonic()
    if not refresh and _manifest_cache is not None:
        cached_at, cached = _manifest_cache
        if now - cached_at < _CACHE_TTL_SECONDS:
            return cached

    remote = _fetch_remote_manifest()
    if remote is None:
        logger.error(
            "skills_manifest_remote_unavailable",
            source=_DEFAULT_SOURCE,
            ref=_DEFAULT_REF,
        )
        raise _manifest_unavailable()

    source, ref, entries = remote
    result = ManifestLoadResult(
        source=source,
        ref=ref,
        entries=entries,
        manifest_source="remote",
        manifest_refreshed=refresh,
    )
    _manifest_cache = (now, result)
    return result


def known_skill_slugs() -> set[str]:
    """Slugs from the live OpenTideHQ/skills catalogue."""
    return {entry.slug for entry in load_manifest().entries}


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
    manifest = load_manifest(refresh=refresh)
    installed = _installed_slugs(repo)
    q = (query or "").strip().lower()
    filtered: list[SkillEntry] = []
    for entry in manifest.entries:
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
        "source": f"{manifest.source}@{manifest.ref}",
        "manifest_source": manifest.manifest_source,
        "manifest_refreshed": manifest.manifest_refreshed,
        "skills": [e.to_dict(installed=e.slug in installed) for e in filtered],
        "count": len(filtered),
    }


def show_skill(repo: Path, name: str, *, refresh: bool = False) -> dict[str, Any]:
    manifest = load_manifest(refresh=refresh)
    needle = name.strip().lower()
    for entry in manifest.entries:
        if entry.slug.lower() == needle or entry.name.lower() == needle:
            installed = entry.slug in _installed_slugs(repo)
            return {
                "source": f"{manifest.source}@{manifest.ref}",
                "manifest_source": manifest.manifest_source,
                "manifest_refreshed": manifest.manifest_refreshed,
                "skill": entry.to_dict(installed=installed),
                "install_hint": f"opentide setup skills --install {entry.slug} --generic --yes",
            }
    return {
        "error": f"skill not found: {name}",
        "source": f"{manifest.source}@{manifest.ref}",
        "manifest_source": manifest.manifest_source,
        "manifest_refreshed": manifest.manifest_refreshed,
    }
