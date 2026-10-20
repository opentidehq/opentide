"""Skills catalogue discovery from the live opentidehq/skills manifest."""

from __future__ import annotations

import json
import posixpath
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import structlog

logger = structlog.get_logger("opentide.cli.services.setup.skills_registry")

_DEFAULT_SOURCE = "opentidehq/skills"
_DEFAULT_REF = "main"
_CACHE_TTL_SECONDS = 30.0
_REF_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
_RAW_HOST = "raw.githubusercontent.com"
_API_HOST = "api.github.com"


class SkillsManifestError(RuntimeError):
    """Raised when the live opentidehq/skills catalogue cannot be fetched."""


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


#: Authoring skills that ship inside the wheel, under
#: ``data/setup/skills/authoring/<slug>/``. They install from the package with
#: no network access, so they must stay nameable and discoverable regardless of
#: what the remote catalogue happens to list.
#:
#: They were previously known only through the remote manifest. When
#: ``opentidehq/skills`` dropped three of them from ``manifest.json``, the CLI
#: began refusing ``--install opentide-detection-rule`` as an "unknown skill
#: slug" while still installing that very slug as part of its default starter
#: set -- and ``discover`` stopped listing skills the wheel contains.
BUNDLED_AUTHORING_ENTRIES: tuple[SkillEntry, ...] = (
    SkillEntry(
        name="Detection engineering",
        slug="detection-engineering",
        description="opentide's three object families: threats, objectives and rules.",
    ),
    SkillEntry(
        name="Detection objectives",
        slug="opentide-detection-objective",
        description="Author objectives as objective::1.0 YAML under objects/objectives/.",
    ),
    SkillEntry(
        name="Detection rules",
        slug="opentide-detection-rule",
        description="Author rules as rule::1.0 YAML under objects/rules/.",
    ),
    SkillEntry(
        name="Threats",
        slug="opentide-threat-vector",
        description="Author threats as threat::1.0 YAML under objects/threats/.",
    ),
)

#: Slugs of the above, for the install path's package/remote branch.
BUNDLED_AUTHORING_SKILLS = frozenset(entry.slug for entry in BUNDLED_AUTHORING_ENTRIES)


def _merge_bundled(entries: list[SkillEntry]) -> list[SkillEntry]:
    """Add bundled authoring skills the remote catalogue does not list.

    The remote entry wins for a slug both sides describe, so the catalogue
    stays authoritative for its own copy; a bundled skill absent upstream is
    appended rather than dropped.
    """
    seen = {entry.slug for entry in entries}
    merged = list(entries)
    merged.extend(entry for entry in BUNDLED_AUTHORING_ENTRIES if entry.slug not in seen)
    return merged


@dataclass(frozen=True)
class ManifestLoadResult:
    source: str
    ref: str
    entries: list[SkillEntry]
    manifest_source: str
    manifest_refreshed: bool


class _ManifestTtlCache:
    """In-process TTL cache for the live skills catalogue."""

    item: tuple[float, ManifestLoadResult] | None = None


_MANIFEST_CACHE = _ManifestTtlCache()


def ref_is_contained(ref: str) -> bool:
    """True when *ref* cannot climb out of the pinned skills repository."""
    parts = ref.split("/")
    return bool(parts) and all(
        part not in {".", ".."} and _REF_SEGMENT.fullmatch(part) is not None for part in parts
    )


def slug_is_contained(slug: str) -> bool:
    """True when *slug* is a single directory name under ``.agents/skills``."""
    return _SLUG.fullmatch(slug) is not None


def _normalise_ref(raw: object) -> str:
    """Keep a catalogue ref, or the default branch when it would escape the repo."""
    ref = str(raw or _DEFAULT_REF).strip() or _DEFAULT_REF
    if ref_is_contained(ref):
        return ref
    logger.warning("skills_manifest_ref_rejected", ref=ref, fallback=_DEFAULT_REF)
    return _DEFAULT_REF


def _contained_github_url(url: str, *, host: str, path_prefix: str, query: str = "") -> str | None:
    """Return *url* only when it stays on *host* under *path_prefix* after dot-segment removal."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != host:
        return None
    if parsed.username or parsed.password or parsed.fragment or parsed.query != query:
        return None
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        return None
    normalized = posixpath.normpath(parsed.path)
    if not normalized.startswith(path_prefix):
        return None
    return urlunsplit(("https", host, normalized, query, ""))


def _repo_file_path(path: str) -> str | None:
    """Reject absolute paths and parent segments in a catalogue file path."""
    if not path or path.startswith("/") or "\\" in path or any(char in path for char in "?#\r\n"):
        return None
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return path


def fetch_github_bytes(
    path: str,
    *,
    source: str = _DEFAULT_SOURCE,
    ref: str = _DEFAULT_REF,
) -> bytes | None:
    """Fetch raw file bytes from the pinned opentidehq/skills repository."""
    file_path = _repo_file_path(path)
    if source != _DEFAULT_SOURCE or not ref_is_contained(ref) or file_path is None:
        logger.warning("skills_download_url_rejected", source=source, ref=ref, path=path)
        return None
    url = _contained_github_url(
        f"https://{_RAW_HOST}/{source}/{ref}/{file_path}",
        host=_RAW_HOST,
        path_prefix=f"/{source}/",
    )
    if url is None:
        logger.warning("skills_download_url_rejected", source=source, ref=ref, path=path)
        return None
    request = urllib.request.Request(url)
    try:
        return urllib.request.urlopen(request, timeout=15).read()
    except (urllib.error.URLError, OSError):
        return None


def list_github_paths(
    prefix: str,
    *,
    source: str = _DEFAULT_SOURCE,
    ref: str = _DEFAULT_REF,
) -> list[str] | None:
    """List blob paths under *prefix* in a public GitHub tree.

    ``None`` means the tree could not be read. An empty list means the prefix
    has no blobs. A truncated tree is treated as unreadable so a skill is not
    installed with files missing.
    """
    folder_path = _repo_file_path(prefix.rstrip("/"))
    if source != _DEFAULT_SOURCE or not ref_is_contained(ref) or folder_path is None:
        logger.warning("skills_tree_url_rejected", source=source, ref=ref, prefix=prefix)
        return None
    folder = f"{folder_path}/"
    url = _contained_github_url(
        f"https://{_API_HOST}/repos/{source}/git/trees/{ref}?recursive=1",
        host=_API_HOST,
        path_prefix=f"/repos/{source}/",
        query="recursive=1",
    )
    if url is None:
        logger.warning("skills_tree_url_rejected", source=source, ref=ref, prefix=prefix)
        return None
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        payload = urllib.request.urlopen(request, timeout=15).read()
    except (urllib.error.URLError, OSError):
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or data.get("truncated") is True:
        return None
    tree = data.get("tree")
    if not isinstance(tree, list):
        return None
    paths: list[str] = []
    for item in tree:
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith(folder):
            continue
        if _repo_file_path(path[len(folder) :]) is None:
            logger.warning("skills_tree_path_rejected", path=path)
            return None
        paths.append(path)
    return sorted(paths)


def clear_manifest_cache() -> None:
    """Clear the in-process manifest TTL cache (for tests)."""
    _MANIFEST_CACHE.item = None


def _normalise_source(raw: object) -> str:
    """Accept only the public opentidehq/skills repo; ignore redirect attempts.

    GitHub owner and repo names are case-insensitive, and the catalogue manifest has
    spelled itself ``OpenTideHQ/skills`` as well as ``opentidehq/skills``, so the
    comparison ignores case and the result is always the canonical spelling.
    """
    source = str(raw or _DEFAULT_SOURCE).strip()
    if source.lower() != _DEFAULT_SOURCE.lower():
        logger.warning("skills_manifest_source_rejected", source=source, fallback=_DEFAULT_SOURCE)
    return _DEFAULT_SOURCE


def _parse_manifest(data: dict[str, Any]) -> tuple[str, str, list[SkillEntry]]:
    source = _normalise_source(data.get("source", _DEFAULT_SOURCE))
    ref = _normalise_ref(data.get("ref", _DEFAULT_REF))
    skills: list[SkillEntry] = []
    for item in data.get("skills", []):
        if not isinstance(item, dict):
            continue
        slug = str(item.get("slug") or item.get("name", "")).strip()
        if not slug_is_contained(slug):
            if slug:
                logger.warning("skills_manifest_slug_rejected", slug=slug)
            continue
        name = str(item.get("name", slug))
        description = str(item.get("description", ""))
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
    now = time.monotonic()
    cached = _MANIFEST_CACHE.item
    if not refresh and cached is not None:
        cached_at, result = cached
        if now - cached_at < _CACHE_TTL_SECONDS:
            return result

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
        entries=_merge_bundled(entries),
        manifest_source="remote",
        manifest_refreshed=refresh,
    )
    _MANIFEST_CACHE.item = (now, result)
    return result


def known_skill_slugs() -> set[str]:
    """Slugs from the live opentidehq/skills catalogue."""
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
