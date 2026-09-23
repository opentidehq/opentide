"""The ``[promotion]`` override that ``setup ci`` writes for ``opentide deploy``."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import tomli_w
import typer

from opentide.core.files import resolve_configurations
from opentide.core.root import get_data_root
from opentide.registry.discovery import client_configurations_dir

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

logger = structlog.get_logger("opentide.cli.services.setup.promotion")

_FLAGS = {"enabled": "--promotion/--no-promotion", "promotion_target": "--promotion-target"}


@dataclass(frozen=True)
class PromotionOverride:
    """``[promotion]`` keys ``deploy`` must read from a repository's ``deployment.toml``."""

    path: Path
    table: dict[str, object]
    #: The file's new content; ``None`` when it already sets *table*.
    content: str | None


def _shown(target: Path, path: Path) -> str:
    return path.relative_to(target).as_posix()


def _assignments(table: dict[str, object]) -> str:
    return ", ".join(tomli_w.dumps({key: value}).strip() for key, value in table.items())


def _read(target: Path, path: Path, hint: list[str]) -> tuple[str, dict[str, Any]]:
    if not path.is_file():
        return "", {}
    text = path.read_text(encoding="utf-8")
    try:
        return text, tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise typer.BadParameter(
            f"{_shown(target, path)} is not valid TOML ({exc}); fix it, then re-run setup.",
            param_hint=hint,
        ) from exc


def _check_status(target: Path, status: str) -> None:
    """``deploy`` refuses a target that the merged ``deployment.toml`` does not define."""
    try:
        deployment = resolve_configurations(target).get("deployment", {})
    except tomllib.TOMLDecodeError as exc:
        raise typer.BadParameter(
            f"cannot read the statuses of {target}: {exc}", param_hint=[_FLAGS["promotion_target"]]
        ) from exc
    statuses = [str(entry.get("name")) for entry in deployment.get("statuses", [])]
    if status not in statuses:
        raise typer.BadParameter(
            f"{status!r} is not a status in this repository's deployment.toml; "
            f"use one of: {', '.join(statuses)}",
            param_hint=[_FLAGS["promotion_target"]],
        )


def _append(existing: str, table: dict[str, object]) -> str:
    block = tomli_w.dumps({"promotion": table})
    if not existing or existing.endswith("\n\n"):
        return existing + block
    return existing + ("\n" if existing.endswith("\n") else "\n\n") + block


def promotion_defaults() -> dict[str, object]:
    """The bundled ``[promotion]`` table ``deploy`` uses when a repository sets none."""
    bundled = get_data_root() / "configurations" / "deployment.toml"
    table = tomllib.loads(bundled.read_text(encoding="utf-8"))["promotion"]
    if not isinstance(table, dict):
        raise typer.BadParameter("bundled deployment.toml has no [promotion] table")
    return table


def effective_promotion(target: Path) -> dict[str, object]:
    """``[promotion]`` as ``deploy`` will read it: the repository table over the bundled defaults."""
    defaults = promotion_defaults()
    try:
        deployment = resolve_configurations(target).get("deployment", {})
    except tomllib.TOMLDecodeError:
        return defaults
    current = deployment.get("promotion") if isinstance(deployment, dict) else None
    if not isinstance(current, dict):
        return defaults
    return {**defaults, **{key: current[key] for key in defaults if key in current}}


def plan_promotion_override(
    target: Path, *, enabled: bool | None, promotion_target: str | None
) -> PromotionOverride | None:
    """What ``.opentide/configurations/deployment.toml`` needs so ``deploy`` promotes as asked.

    ``None`` means the flag was omitted, so that key is left as the repository
    configures it. An explicit value that already matches writes nothing. An
    explicit value that disagrees with an existing ``[promotion]`` table is
    refused: tomli-w cannot rewrite it without dropping comments.
    """
    defaults = promotion_defaults()
    requested: dict[str, object] = {
        key: value
        for key, value in (("enabled", enabled), ("promotion_target", promotion_target))
        if value is not None
    }
    if not requested:
        return None
    hint = [_FLAGS[key] for key in requested]
    path = client_configurations_dir(target) / "deployment.toml"
    existing, parsed = _read(target, path, hint)
    if promotion_target is not None:
        _check_status(target, promotion_target)
    current = parsed.get("promotion")
    if current is None:
        table = {key: value for key, value in requested.items() if value != defaults.get(key)}
        if not table:
            return None
        return PromotionOverride(path, table, _append(existing, table))
    if isinstance(current, dict) and all(
        current.get(key, defaults.get(key)) == value for key, value in requested.items()
    ):
        return PromotionOverride(path, requested, None)
    raise typer.BadParameter(
        f"{_shown(target, path)} already has a [promotion] table, which setup does not "
        f"rewrite. Set {_assignments(requested)} in it, or delete it and re-run setup.",
        param_hint=hint,
    )


def write_promotion_override(target: Path, override: PromotionOverride) -> list[str]:
    """Write *override*; returns the path written, relative to *target*."""
    if override.content is None:
        return []
    override.path.parent.mkdir(parents=True, exist_ok=True)
    override.path.write_text(override.content, encoding="utf-8")
    shown = _shown(target, override.path)
    logger.debug("ci_promotion_configured", detail=shown, promotion=override.table)
    return [shown]
