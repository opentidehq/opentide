"""Issues for configuration TOML files, in the shape `issues_from_pydantic` returns.

`configuration_file_issues` is what an editor calls for an open file under
`.opentide/configurations/`. Client files are partial overrides, so the file
is merged onto the layers before it (the bundled file by default) and the
model's required keys apply to that merge, never to the file alone. Checks a
JSON Schema cannot state (a status name, an asset name, the file name) run
beside the model and return the same records.
"""

from __future__ import annotations

import copy
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ValidationError

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.models.configuration import configuration_file_key, configuration_files
from opentide.models.configuration.deployment import DeploymentConfiguration
from opentide.models.configuration.loading import model_errors
from opentide.models.visibility import VisibilityConfig
from opentide.validation.issues import ValidationIssue

#: `ValidationIssue.object_type` of every configuration finding.
CONFIGURATION_OBJECT_TYPE = "configuration"

#: Codes this module emits, besides the `sharing-config` codes.
MISSING_FIELD = "missing_field"
UNKNOWN_KEY = "unknown_key"
SCHEMA_VALIDATION = "schema_validation"
PROMOTION_TARGET_UNKNOWN = "promotion_target_unknown"
ASSET_UNKNOWN = "asset_unknown"
IDENTIFIER_MISMATCH = "identifier_mismatch"
NOT_A_CONFIGURATION_FILE = "not_a_configuration_file"
CONFIG_PARSE = "config_parse"


def _issue(
    code: str,
    field_path: Sequence[str],
    message: str,
    *,
    severity: str = "error",
    file_path: Path | None = None,
    context: dict[str, Any] | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        severity="warning" if severity == "warning" else "error",
        object_type=CONFIGURATION_OBJECT_TYPE,
        file_path=file_path,
        field_path=tuple(field_path),
        message=message,
        context=context or {},
    )


def issues_from_configuration_error(
    exc: ValidationError, document: Mapping[str, Any], *, file_path: Path | None = None
) -> list[ValidationIssue]:
    """One issue per model error on *document*. The offending value is never repeated."""
    issues: list[ValidationIssue] = []
    for field_path, kind, message in model_errors(exc, document):
        if kind == "missing":
            code, message = MISSING_FIELD, "Required key is missing."
        elif kind == "extra_forbidden":
            code, message = UNKNOWN_KEY, "Unknown key."
        else:
            code, message = SCHEMA_VALIDATION, message or "Invalid value."
        issues.append(_issue(code, field_path, message, file_path=file_path))
    return issues


# --- Cross-field checks ----------------------------------------------------------------


def deployment_cross_issues(
    config: DeploymentConfiguration, *, file_path: Path | None = None
) -> list[ValidationIssue]:
    """`promotion.promotion_target` names a status of the merged file."""
    target = config.promotion.promotion_target
    if target in config.status_names():
        return []
    return [
        _issue(
            PROMOTION_TARGET_UNKNOWN,
            ("promotion", "promotion_target"),
            f"promotion_target {target!r} is not a [[statuses]] name.",
            file_path=file_path,
            context={"value": target},
        )
    ]


def visibility_cross_issues(
    config: VisibilityConfig, *, file_path: Path | None = None
) -> list[ValidationIssue]:
    """Log source and detector `assets` name an `[[assets]]` entry of the merged file."""
    known = {asset.name for asset in config.assets or []}
    issues: list[ValidationIssue] = []
    for table, entry, items in (
        ("logsources", "logsource", config.logsources or []),
        ("detectors", "detector", config.detectors or []),
    ):
        for index, item in enumerate(items):
            for position, asset in enumerate(item.assets or []):
                if asset in known:
                    continue
                issues.append(
                    _issue(
                        ASSET_UNKNOWN,
                        (table, str(index), "assets", str(position)),
                        f"{entry} {item.name!r} names asset {asset!r}, which [[assets]] "
                        "does not declare.",
                        file_path=file_path,
                        context={"entry": entry, "name": item.name, "asset": asset},
                    )
                )
    return issues


def platform_identifier_issues(
    document: Mapping[str, Any], *, file_stem: str, file_path: Path | None = None
) -> list[ValidationIssue]:
    """`[platform] identifier` matches the file name stem when both are set."""
    platform = document.get("platform")
    identifier = platform.get("identifier") if isinstance(platform, Mapping) else None
    if not isinstance(identifier, str) or not identifier or not file_stem:
        return []
    if identifier == file_stem:
        return []
    return [
        _issue(
            IDENTIFIER_MISMATCH,
            ("platform", "identifier"),
            f"identifier {identifier!r} does not match the file name {file_stem}.toml.",
            file_path=file_path,
            context={"value": identifier, "file_stem": file_stem},
        )
    ]


# --- Sharing ---------------------------------------------------------------------------


def sharing_issues(
    layers: Sequence[Mapping[str, Any]],
    *,
    status_names: Iterable[str],
    tlp_names: Sequence[str] | None = None,
    sharing_directory: bool = False,
    partial: bool = False,
    file_path: Path | None = None,
) -> list[ValidationIssue]:
    """Every `sharing-config` finding for *layers*, merged by block name in order.

    *partial* checks a layer on its own: a block may restate only `name` and
    the keys it changes, so a missing required key is not reported.
    """
    from opentide.sharing.config import merge_sharing_documents
    from opentide.sharing.constants import TLP_ORDER

    merged = merge_sharing_documents(
        layers,
        status_names=frozenset(status_names),
        tlp_names=tuple(tlp_names or TLP_ORDER),
    )
    issues: list[ValidationIssue] = []
    if sharing_directory:
        issues.append(
            _issue(
                "sharing_directory",
                (),
                "configurations/sharing/ is not a sharing configuration. "
                "Use a single sharing.toml file.",
                file_path=file_path,
            )
        )
    for finding in merged.issues:
        if partial and finding.code == MISSING_FIELD and finding.field_name != "name":
            continue
        issues.append(
            _issue(
                finding.code,
                tuple(
                    part
                    for part in (finding.integration, finding.block, finding.field_name)
                    if part is not None
                ),
                finding.message,
                severity=finding.severity,
                file_path=file_path,
                context={
                    key: value
                    for key, value in (
                        ("integration", finding.integration),
                        ("block", finding.block),
                    )
                    if value is not None
                },
            )
        )
    return issues


# --- One configuration file ------------------------------------------------------------


def _deep_merge(target: dict[str, Any], layer: Mapping[str, Any]) -> None:
    """Scalars replace, tables merge, arrays replace (configuration spec)."""
    for key, value in layer.items():
        current = target.get(key)
        if isinstance(current, dict) and isinstance(value, Mapping):
            _deep_merge(current, value)
        else:
            target[key] = copy.deepcopy(value)


def merge_layers(layers: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Merge configuration layers in order, as `resolve_configurations` does."""
    merged: dict[str, Any] = {}
    for layer in layers:
        _deep_merge(merged, layer)
    return merged


def bundled_layer(file_key: str) -> dict[str, Any]:
    """The bundled document for a router key, or `{}` when none ships."""
    from opentide.core.root import get_data_root

    if "*" in file_key:
        return {}
    path = get_data_root() / "configurations" / file_key
    if not path.is_file():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def bundled_status_names() -> frozenset[str]:
    """Status names of the bundled `deployment.toml`."""
    statuses = bundled_layer("deployment.toml").get("statuses", [])
    return frozenset(
        str(entry["name"])
        for entry in statuses
        if isinstance(entry, Mapping) and isinstance(entry.get("name"), str)
    )


def _model_issues(
    model: type[BaseModel],
    merged: Mapping[str, Any],
    *,
    partial: bool,
    file_path: Path | None,
) -> tuple[BaseModel | None, list[ValidationIssue]]:
    try:
        return model.model_validate(dict(merged)), []
    except ValidationError as exc:
        issues = issues_from_configuration_error(exc, merged, file_path=file_path)
        if partial:
            issues = [issue for issue in issues if issue.code != MISSING_FIELD]
        return None, issues


def configuration_file_issues(
    path: str | Path,
    document: Mapping[str, Any],
    *,
    earlier_layers: Sequence[Mapping[str, Any]] | None = None,
    later_layers: Sequence[Mapping[str, Any]] = (),
    status_names: Iterable[str] | None = None,
    sharing_directory: bool = False,
    partial: bool = False,
) -> list[ValidationIssue]:
    """Issues for one configuration file, as `{code, field_path, severity}` records.

    *path* routes the file (`deployment.toml`, `platforms/sentinel.toml`,
    `sharing.toml`, ...); it may be absolute. *document* is the parsed file.
    *earlier_layers* default to the bundled file of the same name; pass the
    workspace file when checking a parent instance. *status_names* are the
    merged `deployment.toml` statuses, which `sharing.toml` `rule_statuses`
    must name (default: the bundled statuses). *partial* skips required-key
    checks, for a layer checked without the layers it overrides.
    """
    file_path = Path(path) if not isinstance(path, Path) else path
    file_key = configuration_file_key(PurePosixPath(file_path.as_posix()))
    if file_key is None:
        return [
            _issue(
                NOT_A_CONFIGURATION_FILE,
                (),
                f"{file_path.name} is not a configuration file opentide reads.",
                severity="warning",
                file_path=file_path,
            )
        ]
    if earlier_layers is None:
        earlier_layers = [bundled_layer(file_key)]
    layers = [*earlier_layers, document, *later_layers]

    if file_key == "sharing.toml":
        names = bundled_status_names() if status_names is None else frozenset(status_names)
        return sharing_issues(
            layers,
            status_names=names,
            sharing_directory=sharing_directory,
            partial=partial,
            file_path=file_path,
        )

    merged = merge_layers(layers)
    model, issues = _model_issues(
        configuration_files()[file_key], merged, partial=partial, file_path=file_path
    )
    if isinstance(model, DeploymentConfiguration):
        issues.extend(deployment_cross_issues(model, file_path=file_path))
    elif isinstance(model, VisibilityConfig):
        issues.extend(visibility_cross_issues(model, file_path=file_path))
    if file_key.startswith("platforms/"):
        issues.extend(
            platform_identifier_issues(document, file_stem=file_path.stem, file_path=file_path)
        )
    return issues


def configuration_text_issues(path: str | Path, text: str, **kwargs: Any) -> list[ValidationIssue]:
    """`configuration_file_issues` for unparsed TOML text, as an editor buffer holds it."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return [
            _issue(
                CONFIG_PARSE,
                (),
                f"Not valid TOML: {exc.__class__.__name__}.",
                file_path=Path(path),
            )
        ]
    return configuration_file_issues(path, document, **kwargs)


__all__ = [
    "CONFIGURATION_OBJECT_TYPE",
    "bundled_layer",
    "configuration_file_issues",
    "configuration_text_issues",
    "deployment_cross_issues",
    "issues_from_configuration_error",
    "merge_layers",
    "platform_identifier_issues",
    "sharing_issues",
    "visibility_cross_issues",
]
