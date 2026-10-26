"""Load ``sharing.toml`` and merge integration blocks by name.

``_deep_merge`` replaces every list. A later layer that only restates ``name``
and ``enabled`` would drop ``url``, ``api_key``, and ``max_tlp``. Sharing
therefore loads its own file and merges each integration array by ``name``.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.core.files import resolve_configurations
from opentide.core.root import get_data_root, get_repo_root
from opentide.models.configuration.sharing import MispIntegration
from opentide.registry.discovery import client_configurations_dir, discover_workspace
from opentide.sharing.constants import (
    API_KEY_ENV_PATTERN,
    DEFAULT_OBJECT_TYPES,
    DEFAULT_RULE_STATUSES,
    INTEGRATION_MISP,
    KNOWN_INTEGRATIONS,
    REDACTION_MARKER,
    SHARING_CONFIG_NAME,
    TLP_ORDER,
)

_API_KEY_RE = re.compile(API_KEY_ENV_PATTERN)
_Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class SharingIssue:
    """One configuration finding. Messages never contain a secret."""

    code: str
    message: str
    severity: _Severity = "error"
    block: str | None = None
    integration: str | None = None
    field_name: str | None = None
    #: Where the finding is, as `(layer, index)`: the position of the layer in
    #: the merge order, and of the block in that layer's array (`None` for a
    #: top-level key). For a merged block, the layer that set *field_name*.
    location: tuple[int, int | None] | None = None
    #: Every `(layer, index)` the block appears at, in merge order.
    occurrences: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class MispBlock:
    """One merged ``[[misp]]`` destination.

    ``api_key`` is the resolved secret. It is omitted from ``repr`` and must
    not be logged, printed, or written into a report.
    """

    name: str
    url: str
    max_tlp: str
    api_key: str | None = field(repr=False, compare=False)
    api_key_env: str | None
    api_key_literal: bool
    api_key_unset: bool
    enabled: bool = False
    object_types: tuple[str, ...] = DEFAULT_OBJECT_TYPES
    rule_statuses: tuple[str, ...] = DEFAULT_RULE_STATUSES
    organisation_uuid: str | None = None
    publish: bool = False
    verify_ssl: bool = True

    def resolved_api_key(self) -> str | None:
        """Return the secret for the HTTP client, or ``None`` when unset."""
        if self.api_key_unset or not self.api_key:
            return None
        return self.api_key


@dataclass(frozen=True)
class SharingConfig:
    """Merged sharing configuration and the findings raised while loading it."""

    blocks: tuple[MispBlock, ...] = ()
    issues: tuple[SharingIssue, ...] = ()
    source: Path | None = None

    @property
    def errors(self) -> tuple[SharingIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[SharingIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")

    @property
    def ok(self) -> bool:
        return not self.errors


def load_sharing(workspace: Path | None = None) -> SharingConfig:
    """Load and merge sharing configuration for *workspace*."""
    workspace = (workspace or discover_workspace()).resolve()
    documents, structural, source = _read_layers(workspace)
    merged = merge_sharing_documents(
        documents,
        status_names=_deployment_status_names(workspace),
        tlp_names=_tlp_names(),
    )
    issues = structural + merged.issues
    blocks = () if any(issue.severity == "error" for issue in issues) else merged.blocks
    return SharingConfig(blocks=blocks, issues=issues, source=source)


def merge_sharing_documents(
    layers: Sequence[Mapping[str, Any]],
    *,
    status_names: frozenset[str],
    tlp_names: tuple[str, ...],
) -> SharingConfig:
    """Merge already-parsed sharing documents. Later layers win by block name.

    A layer error (an unknown top-level key, a duplicate name) does not stop
    the other blocks from being checked: the blocks a duplicate involves are
    left out of the merge, and every other block still reports its findings.
    Any error leaves `blocks` empty.
    """
    issues: list[SharingIssue] = []
    known: dict[str, list[_Located]] = {name: [] for name in sorted(KNOWN_INTEGRATIONS)}

    for layer_index, layer in enumerate(layers):
        arrays: dict[str, list[_Located]] = {}
        for key, value in layer.items():
            if not _is_table_array(value):
                issues.append(
                    SharingIssue(
                        code="unknown_key",
                        message=(
                            f"Unknown key {key!r}. "
                            f"The only sharing integration is [[{INTEGRATION_MISP}]]."
                        ),
                        field_name=str(key),
                        location=(layer_index, None),
                    )
                )
                continue
            arrays[str(key)] = [
                _Located(layer_index, index, table) for index, table in enumerate(value)
            ]
            if key not in KNOWN_INTEGRATIONS:
                issues.append(
                    SharingIssue(
                        code="unknown_connector",
                        severity="warning",
                        message=f"Unknown sharing integration {key!r} was skipped.",
                        integration=str(key),
                        field_name=str(key),
                        location=(layer_index, None),
                    )
                )
        duplicated = _reject_duplicate_names(arrays, issues)
        for integration in known:
            known[integration].extend(
                item for item in arrays.get(integration, []) if item.name not in duplicated
            )

    blocks: list[MispBlock] = []
    for merged in _merge_named(known[INTEGRATION_MISP], INTEGRATION_MISP, issues):
        block, block_issues = _misp_block(merged, status_names=status_names, tlp_names=tlp_names)
        issues.extend(block_issues)
        if block is not None:
            blocks.append(block)
    if any(issue.severity == "error" for issue in issues):
        blocks = []
    return SharingConfig(blocks=tuple(blocks), issues=tuple(issues))


@dataclass(frozen=True)
class _Located:
    """A block table and where it was written."""

    layer: int
    index: int
    table: Mapping[str, Any]

    @property
    def name(self) -> str | None:
        name = self.table.get("name")
        return name if isinstance(name, str) else None


@dataclass
class _Merged:
    """A block merged across layers, with the layer and index that set each key."""

    raw: dict[str, Any]
    provenance: dict[str, tuple[int, int]]
    occurrences: list[tuple[int, int]]

    def location(self, field_name: str | None) -> tuple[int, int | None]:
        if field_name is not None and field_name in self.provenance:
            return self.provenance[field_name]
        return self.occurrences[-1]


def _read_layers(
    workspace: Path,
) -> tuple[list[dict[str, Any]], tuple[SharingIssue, ...], Path | None]:
    issues: list[SharingIssue] = []
    documents: list[dict[str, Any]] = []
    source: Path | None = None
    for directory in _configuration_directories(workspace):
        if (directory / "sharing").is_dir():
            issues.append(
                SharingIssue(
                    code="sharing_directory",
                    message=(
                        f"{directory / 'sharing'} is not a sharing configuration. "
                        "Use a single sharing.toml file."
                    ),
                )
            )
        path = directory / SHARING_CONFIG_NAME
        if not path.is_file():
            continue
        source = path
        document, issue = _read_document(path)
        if issue is not None:
            issues.append(issue)
            continue
        if document:
            documents.append(document)
    return documents, tuple(issues), source


def _configuration_directories(workspace: Path) -> list[Path]:
    """Bundled, workspace, optional fixture overlay, then parent instance."""
    directories = [get_data_root() / "configurations"]
    client = client_configurations_dir(workspace)
    directories.append(client)
    workspace_env = os.environ.get("OPENTIDE_TIDE_WORKSPACE")
    if workspace_env:
        directories.append(get_repo_root() / "tests/fixtures/generation/configurations")
    else:
        parent = workspace.parent / ".opentide" / "configurations"
        if parent.is_dir() and parent != client:
            directories.append(parent)
    return directories


def _read_document(path: Path) -> tuple[dict[str, Any] | None, SharingIssue | None]:
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return None, SharingIssue(
            code="config_parse",
            message=f"Could not read {path.name}: {exc.__class__.__name__}",
        )
    if not isinstance(loaded, dict):
        return None, SharingIssue(
            code="unknown_key",
            message=f"{path.name} must be a TOML table of integration arrays.",
        )
    return loaded, None


def _deployment_status_names(workspace: Path) -> frozenset[str]:
    deployment = resolve_configurations(workspace).get("deployment", {})
    statuses = deployment.get("statuses", [])
    names: set[str] = set()
    if isinstance(statuses, list):
        for entry in statuses:
            if isinstance(entry, Mapping) and isinstance(entry.get("name"), str):
                names.add(entry["name"])
    return frozenset(names)


def _tlp_names() -> tuple[str, ...]:
    path = get_data_root() / "vocabulary" / "tlp.vocab.toml"
    if not path.is_file():
        return TLP_ORDER
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return TLP_ORDER
    keys = document.get("keys")
    if not isinstance(keys, list):
        return TLP_ORDER
    names = tuple(
        str(item["name"]) for item in keys if isinstance(item, Mapping) and item.get("name")
    )
    return names or TLP_ORDER


def _is_table_array(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, Mapping) for item in value)


def _reject_duplicate_names(
    arrays: Mapping[str, Sequence[_Located]], issues: list[SharingIssue]
) -> set[str]:
    """One `duplicate_name` per block that shares its name with another block of the layer.

    That covers a name repeated in one array and a name used by two
    integrations. Returns the duplicated names, which the merge leaves out.
    """
    owners: dict[str, list[tuple[str, _Located]]] = {}
    for integration, items in arrays.items():
        for item in items:
            if item.name is not None:
                owners.setdefault(item.name, []).append((integration, item))
    duplicated: set[str] = set()
    for name, users in owners.items():
        if len(users) < 2:
            continue
        duplicated.add(name)
        where = ", ".join(f"[[{integration}]] #{item.index + 1}" for integration, item in users)
        for integration, item in users:
            issues.append(
                SharingIssue(
                    code="duplicate_name",
                    message=f"Name {name!r} is used by more than one block in one layer: {where}.",
                    block=name,
                    integration=integration,
                    field_name="name",
                    location=(item.layer, item.index),
                    occurrences=tuple((other.layer, other.index) for _i, other in users),
                )
            )
    return duplicated


def _merge_named(
    items: Sequence[_Located], integration: str, issues: list[SharingIssue]
) -> list[_Merged]:
    merged: dict[str, _Merged] = {}
    order: list[str] = []
    for item in items:
        name = item.name
        if name is None:
            issues.append(
                SharingIssue(
                    code="missing_field",
                    message=f"A [[{integration}]] block is missing name.",
                    integration=integration,
                    field_name="name",
                    location=(item.layer, item.index),
                )
            )
            continue
        current = merged.get(name)
        if current is None:
            current = _Merged(raw={}, provenance={}, occurrences=[])
            merged[name] = current
            order.append(name)
        current.occurrences.append((item.layer, item.index))
        for key, value in item.table.items():
            current.raw[key] = value
            current.provenance[str(key)] = (item.layer, item.index)
    return [merged[name] for name in order]


#: Code of an invalid value, by the key it was found on (the spec checker's codes).
_FIELD_CODES = {
    "name": "name_invalid",
    "url": "url_invalid",
    "max_tlp": "max_tlp_unknown",
    "organisation_uuid": "organisation_uuid_invalid",
    "object_types": "object_type_unknown",
    "rule_statuses": "rule_status_unknown",
}


def _misp_block(
    merged: _Merged,
    *,
    status_names: frozenset[str],
    tlp_names: tuple[str, ...],
) -> tuple[MispBlock | None, list[SharingIssue]]:
    """Validate one merged block with `MispIntegration`, then check what the schema cannot."""
    raw = merged.raw
    name = raw.get("name")
    block_name = name if isinstance(name, str) else None
    found: list[tuple[str, str, object]] = []
    try:
        model: MispIntegration | None = MispIntegration.model_validate(dict(raw))
    except ValidationError as exc:
        model = None
        found.extend(_model_findings(exc, raw))
    if model is not None and model.max_tlp not in tlp_names:
        found.append(("max_tlp_unknown", "max_tlp", None))
    statuses = raw.get("rule_statuses")
    if isinstance(statuses, list):
        found.extend(
            ("rule_status_unknown", "rule_statuses", item)
            for item in statuses
            if isinstance(item, str) and item and item not in status_names
        )
    api_key, api_env, literal, unset = _api_key(raw.get("api_key"))
    if literal:
        found.append(("api_key_literal", "api_key", None))
    issues = [
        _issue(code, field_name, block_name, merged, entry) for code, field_name, entry in found
    ]
    if model is None or any(issue.severity == "error" for issue in issues):
        return None, issues
    return (
        MispBlock(
            name=model.name,
            url=model.url.rstrip("/"),
            max_tlp=model.max_tlp,
            api_key=None if unset else api_key,
            api_key_env=api_env,
            api_key_literal=literal,
            api_key_unset=unset,
            enabled=model.enabled,
            object_types=tuple(model.object_types),
            rule_statuses=tuple(model.rule_statuses),
            organisation_uuid=model.organisation_uuid,
            publish=model.publish,
            verify_ssl=model.verify_ssl,
        ),
        issues,
    )


def _issue(
    code: str, field_name: str, block: str | None, merged: _Merged, entry: object = None
) -> SharingIssue:
    """A finding on *field_name*. *entry* is a list item, never a secret."""
    where = f"[[{INTEGRATION_MISP}]] block {block!r}"
    messages = {
        "missing_field": f"{where} is missing {field_name}.",
        "unknown_key": f"Unknown key {field_name!r} in {where}.",
        "name_invalid": (
            "Block name must be 1–64 characters of lowercase letters, "
            "digits, hyphen, and underscore."
        ),
        "url_invalid": f"{where} url must be an http(s) URL.",
        "max_tlp_unknown": f"{where} max_tlp is not a tlp vocabulary name.",
        "organisation_uuid_invalid": (
            f"{where} organisation_uuid must be a 36-character hex UUID (8-4-4-4-12)."
        ),
        "object_type_unknown": f"{where} object_types entry {entry!r} is unknown.",
        "rule_status_unknown": f"{where} rule_statuses entry {entry!r} is unknown.",
        "api_key_literal": (
            f"{where} api_key is a literal. "
            f"Use ${{ENV_VAR}}. The value was replaced with {REDACTION_MARKER}."
        ),
    }
    message = messages.get(code, f"{where} {field_name} has an invalid value.")
    return SharingIssue(
        code=code,
        message=message,
        severity="warning" if code == "api_key_literal" else "error",
        block=block,
        integration=INTEGRATION_MISP,
        field_name=field_name,
        location=merged.location(field_name),
        occurrences=tuple(merged.occurrences),
    )


def _model_findings(exc: ValidationError, raw: Mapping[str, Any]) -> list[tuple[str, str, object]]:
    """`(code, key, entry)` per `MispIntegration` error. Inputs are never echoed.

    A value of the wrong type takes its key's spec code, as the spec checker
    reports it (`object_types = "rule"` is `object_type_unknown`); an empty
    required string is `missing_field`, except `name`, which the name rule
    covers.
    """
    found: list[tuple[str, str, object]] = []
    for err in exc.errors(include_url=False):
        loc = err.get("loc", ())
        if not loc:
            continue
        field_name = str(loc[0])
        kind = str(err.get("type", ""))
        if kind == "extra_forbidden":
            code = "unknown_key"
        elif kind == "missing" or (raw.get(field_name) == "" and field_name != "name"):
            code = "missing_field"
        else:
            code = _FIELD_CODES.get(field_name, "invalid_value")
        entry = None
        items = raw.get(field_name)
        if (
            code in {"object_type_unknown", "rule_status_unknown"}
            and len(loc) > 1
            and isinstance(items, list)
            and isinstance(loc[1], int)
            and loc[1] < len(items)
        ):
            entry = items[loc[1]]
        found.append((code, field_name, entry))
    return found


def _api_key(value: object) -> tuple[str | None, str | None, bool, bool]:
    """Return `(secret, env name, literal, unset)`.

    The committed value must be exactly `${NAME}`: surrounding whitespace
    makes it a literal. The secret is never put in an issue.
    """
    if not isinstance(value, str) or not value:
        return None, None, False, True
    match = _API_KEY_RE.fullmatch(value)
    if match is None:
        return value, None, True, False
    env_name = match.group(1)
    secret = os.environ.get(env_name)
    if secret is None or secret == "":
        return None, env_name, False, True
    return secret, env_name, False, False
