"""Skills catalogue discovery from remote manifest with bundled offline fallback."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from opentide.package.paths import bundled_data_root

logger = structlog.get_logger("opentide.cli.services.setup.skills_registry")

_MANIFEST_PATH = bundled_data_root() / "skills" / "manifest.json"
_DEFAULT_SOURCE = "OpenTideHQ/skills"
_DEFAULT_REF = "main"
_CACHE_TTL_SECONDS = 30.0
_manifest_cache: tuple[float, ManifestLoadResult] | None = None


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


def _bundled_ref_hint() -> str:
    if not _MANIFEST_PATH.is_file():
        return _DEFAULT_REF
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return str(data.get("ref", _DEFAULT_REF))


def _load_bundled_manifest() -> tuple[str, str, list[SkillEntry]]:
    if not _MANIFEST_PATH.is_file():
        return _DEFAULT_SOURCE, _DEFAULT_REF, []
    data = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    return _parse_manifest(data)


def _fetch_remote_manifest(
    *, ref_hint: str | None = None
) -> tuple[str, str, list[SkillEntry]] | None:
    ref = ref_hint or _bundled_ref_hint()
    payload = fetch_github_bytes("manifest.json", source=_DEFAULT_SOURCE, ref=ref)
    if payload is None:
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    source, manifest_ref, entries = _parse_manifest(data)
    return source, manifest_ref, entries


def load_manifest(*, refresh: bool = False) -> ManifestLoadResult:
    """Load skills manifest remote-first; fall back to bundled snapshot."""
    global _manifest_cache
    now = time.monotonic()
    if not refresh and _manifest_cache is not None:
        cached_at, cached = _manifest_cache
        if now - cached_at < _CACHE_TTL_SECONDS:
            return cached

    if refresh:
        remote = _fetch_remote_manifest()
        if remote is not None:
            source, ref, entries = remote
            result = ManifestLoadResult(
                source=source,
                ref=ref,
                entries=entries,
                manifest_source="remote",
                manifest_refreshed=True,
            )
            _manifest_cache = (now, result)
            return result
        logger.warning("skills_manifest_refresh_failed")
        source, ref, entries = _load_bundled_manifest()
        result = ManifestLoadResult(
            source=source,
            ref=ref,
            entries=entries,
            manifest_source="bundled",
            manifest_refreshed=False,
        )
        # Keep cache coherent with the fallback the caller just received.
        _manifest_cache = (now, result)
        return result

    remote = _fetch_remote_manifest()
    if remote is not None:
        source, ref, entries = remote
        result = ManifestLoadResult(
            source=source,
            ref=ref,
            entries=entries,
            manifest_source="remote",
            manifest_refreshed=False,
        )
        _manifest_cache = (now, result)
        return result

    logger.warning("skills_manifest_remote_unavailable", fallback="bundled")
    source, ref, entries = _load_bundled_manifest()
    result = ManifestLoadResult(
        source=source,
        ref=ref,
        entries=entries,
        manifest_source="bundled",
        manifest_refreshed=False,
    )
    _manifest_cache = (now, result)
    return result


def known_skill_slugs() -> set[str]:
    """Slugs from the active catalogue plus the bundled offline snapshot."""
    manifest = load_manifest()
    known = {entry.slug for entry in manifest.entries}
    _, _, bundled = _load_bundled_manifest()
    known.update(entry.slug for entry in bundled)
    return known


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
