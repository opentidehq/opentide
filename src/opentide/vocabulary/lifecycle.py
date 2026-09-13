"""Per-key vocabulary lifecycle merge for upstream ingest (RFC 0003)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from opentide.generation.vocabulary import parse_semver

_SKIP = frozenset({"version", "removed"})
DEFAULT_VERSION = "1.0"


@dataclass(frozen=True)
class LifecycleResult:
    """Outcome of merging existing vocabulary keys with an upstream snapshot."""

    keys: tuple[dict[str, Any], ...]
    added: tuple[str, ...]
    updated: tuple[str, ...]
    removed: tuple[str, ...]
    backfilled: tuple[str, ...]
    introducing_version: str | None
    removal_version: str | None

    @property
    def dirty(self) -> bool:
        """Whether the merged document differs from the previous key set."""
        return bool(self.added or self.updated or self.removed or self.backfilled)

    @property
    def pin_contract(self) -> str | None:
        """New minor to pin when this merge added keys to an already-populated vocabulary.

        First fill of an empty file uses ``1.0`` and does not move pins.
        """
        if not self.added or self.introducing_version in (None, DEFAULT_VERSION):
            return None
        return self.introducing_version


def entry_identity(entry: Mapping[str, Any], key_field: str) -> str | None:
    """Return the stable identity for a vocabulary key, or None if missing."""
    value = entry.get(key_field)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def entry_version(entry: Mapping[str, Any]) -> tuple[int, int]:
    """Return ``(major, minor)`` for an entry, defaulting missing versions to 1.0."""
    raw = entry.get("version") or DEFAULT_VERSION
    return parse_semver(str(raw))


def format_version(major: int, minor: int) -> str:
    """Format a ``major.minor`` contract line."""
    return f"{major}.{minor}"


def _payload(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _canonical(value) for key, value in entry.items() if key not in _SKIP}


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    return value


def _index(entries: Sequence[Mapping[str, Any]], key_field: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        identity = entry_identity(entry, key_field)
        if identity is None:
            continue
        indexed[identity] = dict(entry)
    return indexed


def merge_vocab_keys(
    existing: Sequence[Mapping[str, Any]],
    upstream: Sequence[Mapping[str, Any]],
    *,
    key_field: str,
) -> LifecycleResult:
    """Merge *upstream* keys into *existing* with RFC 0003 per-key versions.

    - New identities get one introducing minor for this cycle (or ``1.0`` on first fill).
    - Identities that disappear receive ``removed`` at the next major.
    - Description/name/link/alias edits keep the existing ``version``.
    - Missing ``version`` on existing keys is backfilled to ``1.0``.
    """
    existing_index = _index(existing, key_field)
    upstream_index = _index(upstream, key_field)

    introducing_version: str | None = None
    new_ids = [identity for identity in upstream_index if identity not in existing_index]
    if new_ids:
        if existing_index:
            major, minor = max(entry_version(entry) for entry in existing_index.values())
            introducing_version = format_version(major, minor + 1)
        else:
            introducing_version = DEFAULT_VERSION

    version_points = [entry_version(entry) for entry in existing_index.values()]
    if introducing_version:
        version_points.append(parse_semver(introducing_version))
    removal_version = format_version(max((point[0] for point in version_points), default=1) + 1, 0)

    added: list[str] = []
    updated: list[str] = []
    removed: list[str] = []
    backfilled: list[str] = []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    for identity, old in existing_index.items():
        seen.add(identity)
        merged = dict(old)
        if not old.get("version"):
            merged["version"] = DEFAULT_VERSION
            backfilled.append(identity)
        else:
            merged["version"] = str(old["version"])

        if identity in upstream_index:
            incoming = dict(upstream_index[identity])
            incoming["version"] = merged["version"]
            revived = bool(old.get("removed"))
            incoming.pop("removed", None)
            if revived or _payload(incoming) != _payload(old):
                updated.append(identity)
            result.append(incoming)
            continue

        if not merged.get("removed"):
            merged["removed"] = removal_version
            removed.append(identity)
        result.append(merged)

    for identity, incoming in upstream_index.items():
        if identity in seen:
            continue
        entry = dict(incoming)
        entry["version"] = introducing_version or DEFAULT_VERSION
        entry.pop("removed", None)
        result.append(entry)
        added.append(identity)

    return LifecycleResult(
        keys=tuple(result),
        added=tuple(sorted(added)),
        updated=tuple(sorted(set(updated))),
        removed=tuple(sorted(removed)),
        backfilled=tuple(sorted(backfilled)),
        introducing_version=introducing_version,
        removal_version=removal_version if removed else None,
    )
