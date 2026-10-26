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

from opentide.models.configuration import (
    GENERIC_PLATFORM_FILE,
    configuration_file_key,
    configuration_files,
)
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
    """Log source and detector `assets` name an `[[assets]]` entry of the merged file.

    A warning: the loader logs an unknown asset and goes on.
    """
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
                        severity="warning",
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
    checked_layer: int | None = None,
    file_path: Path | None = None,
) -> list[ValidationIssue]:
    """Every `sharing-config` finding for *layers*, merged by block name in order.

    With *checked_layer* (the index of the open file in *layers*), a field
    path points into that file: `("misp", "<index>", "<key>")`. A finding
    on a block the file does not hold has an empty path, and its context
    names the block and layer. Without it, the path is
    `(integration, block name, key)`, as `validate --check sharing-config`
    prints it. *partial* checks a layer on its own: a block may restate only
    `name` and the keys it changes, so a missing required key is not
    reported.
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
        context: dict[str, Any] = {
            key: value
            for key, value in (("integration", finding.integration), ("block", finding.block))
            if value is not None
        }
        if finding.location is not None:
            context["layer"], context["index"] = finding.location
        issues.append(
            _issue(
                finding.code,
                _sharing_field_path(finding, checked_layer),
                finding.message,
                severity=finding.severity,
                file_path=file_path,
                context=context,
            )
        )
    return issues


def _sharing_field_path(finding: Any, checked_layer: int | None) -> tuple[str, ...]:
    if checked_layer is None:
        return tuple(
            part
            for part in (finding.integration, finding.block, finding.field_name)
            if part is not None
        )
    location = finding.location
    if location is not None and location[1] is None:
        # A top-level key.
        return (finding.field_name,) if location[0] == checked_layer else ()
    candidates = [location] if location is not None else []
    candidates.extend(reversed(finding.occurrences))
    for layer, index in candidates:
        if layer == checked_layer and index is not None:
            path = [finding.integration, str(index)]
            if finding.field_name is not None:
                path.append(finding.field_name)
            return tuple(path)
    return ()


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


#: Bundled files opentide reads that have no model (out of the configuration spec).
_UNMODELLED_FILES = frozenset({"resources.toml"})
_RESPONDERS = "responders"


def _posix(path: str | Path) -> PurePosixPath:
    return PurePosixPath(str(path).replace("\\", "/"))


def _platform_key(document: Mapping[str, Any], stem: str) -> str:
    """Router key the loader would file a platform document under.

    `resolve_configurations` keys a platform file by `platform.identifier`,
    then `tide.identifier`, then the file name stem.
    """
    for table in ("platform", "tide"):
        section = document.get(table)
        identifier = section.get("identifier") if isinstance(section, Mapping) else None
        if isinstance(identifier, str) and identifier:
            return configuration_file_key(f"platforms/{identifier}.toml") or GENERIC_PLATFORM_FILE
    return configuration_file_key(f"platforms/{stem}.toml") or GENERIC_PLATFORM_FILE


def _workspace_status_names(path: PurePosixPath) -> frozenset[str] | None:
    """Status names of merged `deployment.toml` for the workspace *path* sits in."""
    parts = path.parts
    if ".opentide" not in parts or not path.is_absolute():
        return None
    root = parts.index(".opentide")
    configurations = Path(*parts[: root + 1]) / "configurations"
    layers: list[Mapping[str, Any]] = [bundled_layer("deployment.toml")]
    client = configurations / "deployment.toml"
    try:
        if client.is_file():
            layers.append(tomllib.loads(client.read_text(encoding="utf-8")))
    except (OSError, ValueError, RecursionError):
        return None
    statuses = merge_layers(layers).get("statuses", [])
    if not isinstance(statuses, list):
        return None
    return frozenset(
        str(entry["name"])
        for entry in statuses
        if isinstance(entry, Mapping) and isinstance(entry.get("name"), str)
    )


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
    must name (default: the workspace's, read from an absolute *path*, else
    the bundled ones). *partial* skips required-key checks, for a layer
    checked without the layers it overrides.
    """
    file_path = Path(path) if not isinstance(path, Path) else path
    posix = _posix(path)
    try:
        return _file_issues(
            posix,
            file_path,
            document,
            earlier_layers=earlier_layers,
            later_layers=later_layers,
            status_names=status_names,
            sharing_directory=sharing_directory,
            partial=partial,
        )
    except RecursionError:
        return [_too_deep(file_path)]


def _too_deep(file_path: Path) -> ValidationIssue:
    return _issue(CONFIG_PARSE, (), "The document is nested too deeply.", file_path=file_path)


def _file_issues(
    posix: PurePosixPath,
    file_path: Path,
    document: Mapping[str, Any],
    *,
    earlier_layers: Sequence[Mapping[str, Any]] | None,
    later_layers: Sequence[Mapping[str, Any]],
    status_names: Iterable[str] | None,
    sharing_directory: bool,
    partial: bool,
) -> list[ValidationIssue]:
    parts = posix.parts
    if len(parts) >= 3 and parts[-2] == "sharing" and parts[-3] == "configurations":
        return [
            _issue(
                "sharing_directory",
                (),
                "configurations/sharing/ is not a sharing configuration. "
                "Use a single sharing.toml file.",
                file_path=file_path,
            )
        ]
    file_key = configuration_file_key(posix)
    if file_key is not None and file_key.startswith("platforms/"):
        file_key = _platform_key(document, posix.stem)
    if file_key is None:
        known = posix.name in _UNMODELLED_FILES
        return [
            _issue(
                NOT_A_CONFIGURATION_FILE,
                (),
                f"{posix.name} has no configuration model; it is not checked."
                if known
                else f"{posix.name} is not a configuration file opentide reads.",
                severity="warning",
                file_path=file_path,
            )
        ]
    if earlier_layers is None:
        earlier_layers = [bundled_layer(file_key)]
    layers = [*earlier_layers, document, *later_layers]

    if file_key == "sharing.toml":
        names = frozenset(status_names) if status_names is not None else None
        if names is None:
            names = _workspace_status_names(posix) or bundled_status_names()
        return sharing_issues(
            layers,
            status_names=names,
            sharing_directory=sharing_directory,
            partial=partial,
            checked_layer=len(earlier_layers),
            file_path=file_path,
        )

    merged = merge_layers(layers)
    model, issues = _model_issues(
        configuration_files()[file_key], merged, partial=partial, file_path=file_path
    )
    if file_key == "deployment.toml":
        issues = [_responder_tolerance(issue) for issue in issues]
        if model is None:
            model = _deployment_without_responders(merged)
    if isinstance(model, DeploymentConfiguration):
        issues.extend(deployment_cross_issues(model, file_path=file_path))
    elif isinstance(model, VisibilityConfig):
        issues.extend(visibility_cross_issues(model, file_path=file_path))
    if file_key.startswith("platforms/") or file_key == GENERIC_PLATFORM_FILE:
        issues.extend(
            platform_identifier_issues(document, file_stem=posix.stem, file_path=file_path)
        )
    return issues


def _responder_tolerance(issue: ValidationIssue) -> ValidationIssue:
    """A bad `[[responders]]` entry is a warning: the loader skips or keeps it and goes on."""
    path = issue.field_path
    if len(path) >= 2 and path[0] == _RESPONDERS and path[1].isdigit():
        return issue.model_copy(update={"severity": "warning"})
    return issue


def _deployment_without_responders(merged: Mapping[str, Any]) -> DeploymentConfiguration | None:
    """The model the cross checks need when only `[[responders]]` entries failed."""
    try:
        return DeploymentConfiguration.model_validate(
            {key: value for key, value in merged.items() if key != _RESPONDERS}
        )
    except ValidationError:
        return None


def configuration_text_issues(path: str | Path, text: str, **kwargs: Any) -> list[ValidationIssue]:
    """`configuration_file_issues` for unparsed TOML text, as an editor buffer holds it."""
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError) as exc:
        return [
            _issue(
                CONFIG_PARSE,
                (),
                f"Not valid TOML: {exc.__class__.__name__}.",
                file_path=Path(path),
            )
        ]
    return configuration_file_issues(path, document, **kwargs)


# --- Every merged file of a workspace (validate --check configuration) -----------------


def workspace_configuration_issues(
    configs: Mapping[str, Any] | None = None,
) -> list[ValidationIssue]:
    """Validate each merged configuration document the CLI reads, as `validate` reports it.

    The same models the load path uses, over the merged documents, so a file
    `deploy` or `generate docs` would refuse fails `validate` first. Each
    issue's context names the file; the field path is a key path into the
    merged document. Sharing has its own check (`sharing-config`); a platform
    plugin's file is its own.
    """
    from opentide.core.files import resolve_configurations
    from opentide.models.configuration.platforms import PLATFORM_CONFIGURATION_MODELS

    if configs is None:
        configs = resolve_configurations()
    documents: list[tuple[str, type[BaseModel], Any]] = []
    paths_key = "paths" if "paths" in configs else "global"
    for key, file_key in (
        (paths_key, f"{paths_key}.toml"),
        ("deployment", "deployment.toml"),
        ("schema", "schema.toml"),
        ("visibility", "visibility.toml"),
        ("documentation", "documentation.toml"),
    ):
        if key in configs:
            documents.append((file_key, configuration_files()[file_key], configs[key]))
    platforms = configs.get("platforms") or configs.get("systems") or {}
    if isinstance(platforms, Mapping):
        for identifier, document in sorted(platforms.items()):
            model = PLATFORM_CONFIGURATION_MODELS.get(str(identifier))
            if model is not None:
                documents.append((f"platforms/{identifier}.toml", model, document))

    issues: list[ValidationIssue] = []
    for file_key, model, document in documents:
        if not isinstance(document, Mapping):
            issues.append(
                _issue(
                    SCHEMA_VALIDATION,
                    (),
                    f"{file_key}: the file must be a TOML table.",
                    context={"file": file_key},
                )
            )
            continue
        if file_key == "visibility.toml" and not document:
            continue
        found, validated = _workspace_document_issues(file_key, model, document)
        issues.extend(found)
        if isinstance(validated, DeploymentConfiguration):
            found = deployment_cross_issues(validated)
        elif isinstance(validated, VisibilityConfig):
            found = visibility_cross_issues(validated)
        else:
            found = []
        issues.extend(_named(issue, file_key) for issue in found)
    return issues


def _workspace_document_issues(
    file_key: str, model: type[BaseModel], document: Mapping[str, Any]
) -> tuple[list[ValidationIssue], BaseModel | None]:
    try:
        validated, found = _model_issues(model, document, partial=False, file_path=None)
    except RecursionError:
        return [_named(_too_deep(Path(file_key)), file_key)], None
    if file_key == "deployment.toml":
        found = [_responder_tolerance(issue) for issue in found]
        if validated is None:
            validated = _deployment_without_responders(document)
    return [_named(issue, file_key) for issue in found], validated


def _named(issue: ValidationIssue, file_key: str) -> ValidationIssue:
    return issue.model_copy(
        update={
            "message": f"{file_key}: {issue.message}",
            "context": {**issue.context, "file": file_key},
            "file_path": None,
        }
    )


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
    "workspace_configuration_issues",
]
