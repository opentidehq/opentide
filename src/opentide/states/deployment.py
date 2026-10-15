"""Deployment state shards at ``.opentide/states/deployment/<uuid>.json``.

Defender for Endpoint, SentinelOne and CrowdStrike address a deployed rule by
an id the vendor assigns at create time. That id is per tenant and is not
detection content, so it lives here rather than on the rule (RFC 0010,
``deployment.state::1.0``). One file per rule, committed to git: losing the
file loses the only handle on the remote rule, and the next deploy creates a
second one beside it.

Writers read the file, change one tenant entry, and write the rest back,
including root keys this version does not know. Output is UTF-8 JSON with
sorted keys, two-space indent and one trailing newline, so rewriting one
tenant does not reshuffle the others.
"""

from __future__ import annotations

import json
import os
import re
import uuid as uuid_module
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentide.core.root import OPENTIDE_DIR

SCHEMA_ID = "deployment.state::1.0"

#: Platforms whose deployer addresses the remote rule by a vendor-assigned id.
STATE_PLATFORMS: tuple[str, ...] = ("crowdstrike", "defender_for_endpoint", "sentinel_one")

#: Platforms whose external id is a canonical decimal integer, stored as a string.
INTEGER_ID_PLATFORMS: frozenset[str] = frozenset({"defender_for_endpoint", "sentinel_one"})

#: Platform-block keys that used to carry the vendor id on the rule.
LEGACY_MAP_KEYS: tuple[str, ...] = ("rule_id", "rule_id_bundle")
LEGACY_TENANT_PREFIX = "rule_id::"

#: The ignore line ``opentide setup`` writes, and the one an old workspace must adopt.
SHARING_IGNORE = f"{OPENTIDE_DIR}/states/sharing.jsonl"

_CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
_ROOT_KEYS = ("object_uuid", "platforms", "schema")


class DeploymentStateError(Exception):
    """A shard, or the rule it belongs to, cannot be used. ``code`` names the failure."""

    def __init__(self, code: str, message: str, **context: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


# --- paths -----------------------------------------------------------------


def states_dir(workspace: Path | None = None) -> Path:
    """``.opentide/states/`` for *workspace*."""
    from opentide.registry.discovery import discover_workspace

    root = workspace or discover_workspace()
    return root / OPENTIDE_DIR / "states"


def deployment_state_dir(workspace: Path | None = None) -> Path:
    """``.opentide/states/deployment/`` for *workspace*."""
    return states_dir(workspace) / "deployment"


def canonical_uuid(value: object) -> str:
    """``metadata.uuid`` in lowercase canonical form, as used for the shard file name."""
    try:
        return str(uuid_module.UUID(str(value).strip()))
    except (ValueError, AttributeError) as exc:
        raise DeploymentStateError(
            "deployment_state_shape",
            f"{value!r} is not a UUID, so it cannot name a deployment state shard",
            object_uuid=str(value),
        ) from exc


def shard_path(object_uuid: object, workspace: Path | None = None) -> Path:
    """Path of the shard for one rule."""
    return deployment_state_dir(workspace) / f"{canonical_uuid(object_uuid)}.json"


def tenant_key(tenant_name: object) -> str:
    """The tenant ``name`` with surrounding whitespace stripped."""
    return str(tenant_name).strip()


# --- external id values ----------------------------------------------------


def normalise_external_id(platform: str, value: object) -> str:
    """Return *value* as the shard stores it, or raise ``external_id_shape``.

    Integers become canonical decimal strings, so ``12345`` and ``"12345"`` are
    the same id. A Defender or SentinelOne string with a sign or leading zero is
    refused rather than rewritten to a different number. CrowdStrike ids are
    copied verbatim.
    """
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise DeploymentStateError(
            "external_id_shape",
            f"{platform} external id {value!r} is not a string or an integer",
            platform=platform,
        )
    if isinstance(value, int):
        if value < 0:
            raise DeploymentStateError(
                "external_id_shape",
                f"{platform} external id {value} is negative",
                platform=platform,
            )
        return str(value)
    if value.strip() == "":
        raise DeploymentStateError(
            "external_id_shape", f"{platform} external id is empty", platform=platform
        )
    if platform in INTEGER_ID_PLATFORMS and not _CANONICAL_DECIMAL.fullmatch(value):
        raise DeploymentStateError(
            "external_id_shape",
            f"{platform} external id {value!r} is not a canonical decimal integer "
            "(no sign, no leading zeroes)",
            platform=platform,
        )
    return value


# --- the shard -------------------------------------------------------------


@dataclass
class DeploymentState:
    """One rule's shard. A rule with no stored id has an empty ``platforms``."""

    path: Path
    object_uuid: str
    platforms: dict[str, dict[str, str]] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
    exists: bool = False

    @classmethod
    def load(cls, object_uuid: object, workspace: Path | None = None) -> DeploymentState:
        """Read and check the shard for *object_uuid*. A missing file is an empty state.

        Any other file in the directory that names the same rule (an uppercase
        or unhyphenated spelling, or a case-only duplicate) is
        ``deployment_state_uuid_mismatch``: a reader on a case-sensitive
        checkout would miss it and create a second remote rule, so the rule is
        refused instead.
        """
        canonical = canonical_uuid(object_uuid)
        path = shard_path(canonical, workspace)
        variants = [name for name in _names_for(path.parent, canonical) if name != path.name]
        if variants:
            raise DeploymentStateError(
                "deployment_state_uuid_mismatch",
                f"{path.parent} holds {', '.join(sorted(variants))} for rule {canonical}; "
                f"the only valid name is {path.name}. Merge the bindings into that file "
                "and delete the others",
                path=str(path),
            )
        if not _exact_entry(path):
            return cls(path=path, object_uuid=canonical)
        return cls.from_file(path, expected_uuid=canonical)

    @classmethod
    def from_file(cls, path: Path, *, expected_uuid: str | None = None) -> DeploymentState:
        """Parse one shard file, raising a ``deployment_state_*`` error when it is unusable.

        The file name must be ``<uuid>.json`` with ``<uuid>`` in lowercase
        canonical form, and ``object_uuid`` must equal it exactly.
        """
        stem = path.stem
        if path.suffix != ".json" or _canonical_or_none(stem) != stem:
            raise DeploymentStateError(
                "deployment_state_uuid_mismatch",
                f"{path} is not named <uuid>.json with a lowercase canonical uuid",
                path=str(path),
            )
        if expected_uuid is not None and stem != expected_uuid:
            raise DeploymentStateError(
                "deployment_state_uuid_mismatch",
                f"{path} is not the shard of rule {expected_uuid}",
                path=str(path),
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _shape(path, f"cannot be read as JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise _shape(path, "is not a JSON object")
        if payload.get("schema") != SCHEMA_ID:
            raise _shape(path, f"has schema {payload.get('schema')!r}, expected {SCHEMA_ID!r}")
        object_uuid = payload.get("object_uuid")
        if not isinstance(object_uuid, str):
            raise _shape(path, "has no string object_uuid")
        if object_uuid != stem:
            raise DeploymentStateError(
                "deployment_state_uuid_mismatch",
                f"{path} records object_uuid {object_uuid!r}, but its file name is {stem!r}",
                path=str(path),
            )
        platforms_raw = payload.get("platforms")
        if not isinstance(platforms_raw, dict):
            raise _shape(path, "has no platforms object")
        platforms: dict[str, dict[str, str]] = {}
        for platform, tenants in platforms_raw.items():
            if platform not in STATE_PLATFORMS:
                raise DeploymentStateError(
                    "deployment_state_platform",
                    f"{path} names platform {platform!r}; only "
                    f"{', '.join(STATE_PLATFORMS)} store external ids",
                    path=str(path),
                    platform=platform,
                )
            if not isinstance(tenants, dict):
                raise _shape(path, f"platforms.{platform} is not an object")
            entries: dict[str, str] = {}
            for tenant, external_id in tenants.items():
                if not isinstance(external_id, str):
                    raise _shape(
                        path,
                        f"platforms.{platform}.{tenant} is {type(external_id).__name__}, "
                        "not a string",
                    )
                if tenant.strip() == "":
                    raise _shape(path, f"platforms.{platform} has an empty tenant name")
                if tenant != tenant.strip():
                    raise _shape(
                        path,
                        f"platforms.{platform} tenant {tenant!r} has surrounding whitespace; "
                        f"the key must be the tenant name exactly ({tenant.strip()!r})",
                    )
                try:
                    normalise_external_id(platform, external_id)
                except DeploymentStateError as exc:
                    raise _shape(path, f"platforms.{platform}.{tenant}: {exc.message}") from exc
                entries[tenant] = external_id
            if entries:
                platforms[platform] = entries
        extra = {key: value for key, value in payload.items() if key not in _ROOT_KEYS}
        return cls(
            path=path, object_uuid=object_uuid, platforms=platforms, extra=extra, exists=True
        )

    def get(self, platform: str, tenant_name: object) -> str | None:
        """The stored id for one platform and tenant, if any."""
        return self.platforms.get(platform, {}).get(tenant_key(tenant_name))

    def set(self, platform: str, tenant_name: object, external_id: object) -> str:
        """Bind one tenant. Returns the id as stored."""
        if platform not in STATE_PLATFORMS:
            raise DeploymentStateError(
                "deployment_state_platform",
                f"{platform} does not store external ids in deployment state",
                platform=platform,
            )
        tenant = tenant_key(tenant_name)
        if not tenant:
            raise DeploymentStateError(
                "external_id_shape", f"{platform} tenant name is empty", platform=platform
            )
        stored = normalise_external_id(platform, external_id)
        self.platforms.setdefault(platform, {})[tenant] = stored
        return stored

    def remove(self, platform: str, tenant_name: object) -> str | None:
        """Drop one tenant, then the platform when it has none left. Returns the old id."""
        tenants = self.platforms.get(platform)
        if not tenants:
            return None
        removed = tenants.pop(tenant_key(tenant_name), None)
        if not tenants:
            del self.platforms[platform]
        return removed

    def bindings(self) -> Iterator[tuple[str, str, str]]:
        """Every ``(platform, tenant, external_id)``."""
        for platform, tenants in self.platforms.items():
            for tenant, external_id in tenants.items():
                yield platform, tenant, external_id

    def render(self) -> str:
        """The file content: sorted keys, two-space indent, one trailing newline."""
        payload: dict[str, Any] = dict(self.extra)
        payload["schema"] = SCHEMA_ID
        payload["object_uuid"] = self.object_uuid
        payload["platforms"] = self.platforms
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def save(self) -> None:
        """Write the shard durably, or remove the file when ``platforms`` is empty."""
        if not self.platforms:
            if self.path.exists():
                self.path.unlink()
                _fsync_directory(self.path.parent)
            self.exists = False
            return
        write_durable(self.path, self.render())
        self.exists = True


def _canonical_or_none(value: str) -> str | None:
    try:
        return canonical_uuid(value)
    except DeploymentStateError:
        return None


def _shard_entries(directory: Path) -> list[str]:
    """File names directly in *directory* that look like shards (``*.json``, any case)."""
    try:
        names = os.listdir(directory)
    except (FileNotFoundError, NotADirectoryError):
        return []
    return [name for name in names if name.lower().endswith(".json")]


def _names_for(directory: Path, canonical: str) -> list[str]:
    """Every shard-like file name in *directory* that canonicalises to *canonical*."""
    return [
        name
        for name in _shard_entries(directory)
        if _canonical_or_none(name[: -len(".json")]) == canonical
    ]


def _exact_entry(path: Path) -> bool:
    """*path* exists under exactly this spelling, also on a case-insensitive filesystem."""
    return path.name in _shard_entries(path.parent) and path.is_file()


def scan_deployment_states(workspace: Path | None = None) -> list[DeploymentStateError]:
    """Check every ``*.json`` under ``.opentide/states/deployment/``, orphans included.

    Shards outlive their rules on purpose, so a shard whose rule was removed
    is still the only handle on a remote rule and must stay readable. Files
    in subdirectories, or whose names are not the canonical ``<uuid>.json``,
    are ``deployment_state_uuid_mismatch``, and so is a valid shard that
    another file names the same rule as.
    """
    root = deployment_state_dir(workspace)
    if not root.is_dir():
        return []
    errors: list[DeploymentStateError] = []
    by_uuid: dict[str, list[Path]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not path.name.lower().endswith(".json"):
            continue
        if path.parent != root:
            errors.append(
                DeploymentStateError(
                    "deployment_state_uuid_mismatch",
                    f"{path} is not directly in {root}; deploy never reads it",
                    path=str(path),
                )
            )
            continue
        canonical = _canonical_or_none(path.name[: -len(".json")])
        if canonical is not None:
            by_uuid.setdefault(canonical, []).append(path)
        try:
            DeploymentState.from_file(path)
        except DeploymentStateError as error:
            errors.append(error)
    # A misspelt name is reported above; also flag the valid file it shadows.
    for canonical, paths in sorted(by_uuid.items()):
        valid = root / f"{canonical}.json"
        if len(paths) > 1 and valid in paths:
            names = ", ".join(path.name for path in paths)
            errors.append(
                DeploymentStateError(
                    "deployment_state_uuid_mismatch",
                    f"{names} all name rule {canonical}; keep only {valid.name}",
                    path=str(valid),
                )
            )
    return errors


def _shape(path: Path, detail: str) -> DeploymentStateError:
    return DeploymentStateError("deployment_state_shape", f"{path} {detail}", path=str(path))


def write_durable(path: Path, text: str) -> None:
    """Replace *path* atomically and flush it to disk before returning."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o7777 if path.exists() else None
    temporary = path.with_name(f".{path.name}.tmp")
    with open(temporary, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    if mode is not None:
        os.chmod(temporary, mode)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Persist a rename or unlink. Not every platform can open a directory."""
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def record_external_id(
    object_uuid: object,
    platform: str,
    tenant_name: object,
    external_id: object,
    workspace: Path | None = None,
) -> str:
    """Read the shard, bind one tenant, write the rest back. Returns the stored id."""
    state = DeploymentState.load(object_uuid, workspace)
    stored = state.set(platform, tenant_name, external_id)
    state.save()
    return stored


def forget_external_id(
    object_uuid: object,
    platform: str,
    tenant_name: object,
    workspace: Path | None = None,
) -> str | None:
    """Remove one tenant entry; the platform and the file go when they are empty."""
    state = DeploymentState.load(object_uuid, workspace)
    removed = state.remove(platform, tenant_name)
    if removed is not None:
        state.save()
    return removed


# --- legacy keys on the rule -----------------------------------------------


def is_legacy_external_id_key(key: object) -> bool:
    """``rule_id``, ``rule_id_bundle`` or ``rule_id::<tenant>``."""
    return isinstance(key, str) and (key in LEGACY_MAP_KEYS or key.startswith(LEGACY_TENANT_PREFIX))


def legacy_external_id_keys(rule: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every ``(platform, key)`` that still carries a vendor id at a platform block root."""
    configurations = rule.get("configurations")
    if not isinstance(configurations, Mapping):
        return []
    found: list[tuple[str, str]] = []
    for platform, block in configurations.items():
        if not isinstance(block, Mapping):
            continue
        for key in block:
            if is_legacy_external_id_key(key):
                found.append((str(platform), str(key)))
    return found


# --- git ignore ------------------------------------------------------------


@dataclass(frozen=True)
class IgnoreRule:
    """The ignore line that hides the deployment state directory from git."""

    pattern: str
    source: str | None = None
    line: int | None = None

    def describe(self) -> str:
        where = f"{self.source}:{self.line}: " if self.source and self.line else ""
        return f"{where}{self.pattern}"


_PROBE = "00000000-0000-4000-8000-000000000000.json"


def _git_top(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def deployment_state_ignore(workspace: Path | None = None) -> IgnoreRule | None:
    """Return the git ignore rule that excludes ``.opentide/states/deployment/``, if any.

    The check uses git's own ignore semantics (``.gitignore`` files, the
    repository's ``info/exclude`` and ``core.excludesFile``), so a parent
    directory ignore such as ``.opentide/states/`` hides the shards even
    though it never names them.
    """
    from dulwich.ignore import IgnoreFilterManager

    from opentide.registry.discovery import discover_workspace

    root = (workspace or discover_workspace()).resolve()
    top = _git_top(root) or root
    manager = None
    if (top / ".git").exists():
        try:
            from dulwich.repo import Repo

            with Repo(str(top)) as repo:
                manager = IgnoreFilterManager.from_repo(repo)
        except Exception:
            manager = None
    if manager is None:
        manager = IgnoreFilterManager(str(top), [], False)

    prefix = root.relative_to(top).as_posix()
    prefix = "" if prefix == "." else prefix + "/"
    chain = [
        f"{prefix}{OPENTIDE_DIR}/",
        f"{prefix}{OPENTIDE_DIR}/states/",
        f"{prefix}{OPENTIDE_DIR}/states/deployment/",
        f"{prefix}{OPENTIDE_DIR}/states/deployment/{_PROBE}",
    ]
    if not (manager.is_ignored(chain[2]) or manager.is_ignored(chain[3])):
        return None
    for probe in chain:
        if not manager.is_ignored(probe):
            continue
        positive = [p for p in manager.find_matching(probe) if not _negated(p)]
        if positive:
            pattern = _pattern_text(positive[-1])
            source, line = _locate_pattern(top, probe, pattern)
            return IgnoreRule(pattern=pattern, source=source, line=line)
    return IgnoreRule(pattern=f"{OPENTIDE_DIR}/states/deployment/")


def _pattern_text(pattern: object) -> str:
    raw = getattr(pattern, "pattern", pattern)
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)


def _negated(pattern: object) -> bool:
    return _pattern_text(pattern).startswith("!")


def _locate_pattern(top: Path, probe: str, pattern: str) -> tuple[str | None, int | None]:
    candidates = [top / ".gitignore"]
    parts = probe.rstrip("/").split("/")[:-1]
    for depth in range(1, len(parts) + 1):
        candidates.append(top.joinpath(*parts[:depth]) / ".gitignore")
    candidates.append(top / ".git" / "info" / "exclude")
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, text in enumerate(lines, start=1):
            if text.strip() == pattern:
                return candidate.relative_to(top).as_posix(), number
    return None, None


def ignored_message(rule: IgnoreRule) -> str:
    """Explain the refusal and name the replacement ignore line."""
    return (
        f"git ignores {OPENTIDE_DIR}/states/deployment/ ({rule.describe()}). "
        "Deployment state shards must be committed, or the next deploy creates a "
        f"second remote rule. Replace that ignore line with {SHARING_IGNORE} "
        "so only the sharing cache is ignored."
    )
