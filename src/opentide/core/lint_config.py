"""The ``[lint]`` configuration: which checks run, at what severity, and what they demand.

Read from ``lint.toml`` through :func:`opentide.core.files.resolve_configurations`,
so a workspace overrides the bundled defaults in ``.opentide/configurations/lint.toml``
like any other configuration file. Template generation reads the same
``metadata.required`` so a scaffolded object shows every key lint asks for.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

#: How much a finding matters. ``--strict`` still fails on any finding.
Severity = Literal["error", "warning", "info"]

SEVERITIES: tuple[Severity, ...] = ("error", "warning", "info")

#: Check names, in the order ``opentide lint`` runs them by default.
CHECK_NAMES: tuple[str, ...] = ("filenames", "metadata", "placeholders", "queries")

#: How ``[filenames]`` derives the file stem an object should have from its ``name``.
FilenameStyle = Literal["slug", "name", "none"]

FILENAME_STYLES: tuple[FilenameStyle, ...] = ("slug", "name", "none")

#: ``metadata.required`` when nothing configures it (the behaviour before #489).
DEFAULT_REQUIRED_METADATA: tuple[str, ...] = ("author", "organisation")

_COMMON_KEYS = frozenset({"enabled", "severity"})
_CHECK_KEYS: dict[str, frozenset[str]] = {
    "filenames": _COMMON_KEYS | {"style", "pattern"},
    "metadata": _COMMON_KEYS | {"required"},
    "placeholders": _COMMON_KEYS,
    "queries": _COMMON_KEYS,
}

_SOURCE = "lint.toml"


class LintConfigError(ValueError):
    """A ``lint.toml`` value opentide cannot use; the message names the key."""


@dataclass(frozen=True)
class CheckConfig:
    """Settings shared by every check."""

    enabled: bool = True
    severity: Severity | None = None


@dataclass(frozen=True)
class FilenameConfig:
    """The ``[filenames]`` convention: how a stem derives from ``name``, and what it must match.

    The defaults are the convention before it was configurable: the stem is
    ``slugify(name)`` and nothing else is demanded of it.
    """

    style: FilenameStyle = "slug"
    #: Compiled from ``pattern``; the whole stem must match it (``re.fullmatch``).
    pattern: re.Pattern[str] | None = None

    def stem_for(self, name: str) -> str | None:
        """The stem an object called *name* should have, or ``None`` when none is expected."""
        return expected_stem(name, self.style)


@dataclass(frozen=True)
class LintConfig:
    """Resolved lint settings. The defaults reproduce lint before it was configurable."""

    checks: Mapping[str, CheckConfig] = field(default_factory=dict)
    required_metadata: tuple[str, ...] = DEFAULT_REQUIRED_METADATA
    filenames: FilenameConfig = field(default_factory=FilenameConfig)

    def check(self, name: str) -> CheckConfig:
        return self.checks.get(name, CheckConfig())

    def enabled_checks(self) -> list[str]:
        return [name for name in CHECK_NAMES if self.check(name).enabled]


#: Control characters, which no file system takes in a name (Windows rejects them outright).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def expected_stem(name: str, style: FilenameStyle) -> str | None:
    """The file stem ``style`` asks for an object called *name*.

    ``"slug"`` is ``slugify(name)``. ``"name"`` is the name itself less what a
    file name cannot hold (:func:`opentide.core.files.safe_file_name`), control
    characters, and the spaces and dots around it: Windows silently drops a
    trailing space or dot, and a leading dot hides the file on Unix, so the
    stem would not be the one written. ``None`` when ``"none"`` compares no stem,
    or when nothing of the name is left to name a file after.
    """
    if style == "none":
        return None
    if style == "slug":
        from opentide.documentation.markdown.links import slugify

        return slugify(name)
    from opentide.core.files import safe_file_name

    stem = _CONTROL_CHARACTERS.sub("", safe_file_name(name)).strip(" .")
    return stem or None


def metadata_keys() -> tuple[str, ...]:
    """Every YAML key an object's ``metadata`` block can hold, across schemas."""
    from opentide.models.metadata import ObjectMetadata, RuleMetadata

    keys: list[str] = []
    for model in (ObjectMetadata, RuleMetadata):
        for name, info in model.model_fields.items():
            key = info.alias or name
            if key not in keys:
                keys.append(key)
    return tuple(keys)


def parse_lint_config(raw: object, *, source: str = _SOURCE) -> LintConfig:
    """Validate the merged ``[lint]`` tables and return them as a :class:`LintConfig`.

    Raises :class:`LintConfigError` naming the offending key: an unknown check
    table, an unknown key in a table, a wrong type, or a ``metadata.required``
    entry that is not a metadata key.
    """
    if raw is None:
        return LintConfig()
    if not isinstance(raw, Mapping):
        raise LintConfigError(f"{source} must hold tables, one per check")
    unknown_checks = sorted(str(key) for key in raw if key not in _CHECK_KEYS)
    if unknown_checks:
        raise LintConfigError(
            f"{source}: unknown check(s) {_quoted(unknown_checks)}. "
            f"Known checks: {', '.join(CHECK_NAMES)}"
        )
    checks: dict[str, CheckConfig] = {}
    required = DEFAULT_REQUIRED_METADATA
    filenames = FilenameConfig()
    for name in CHECK_NAMES:
        table = raw.get(name)
        if table is None:
            continue
        where = f"{source} [{name}]"
        if not isinstance(table, Mapping):
            raise LintConfigError(f"{where} must be a table")
        unknown_keys = sorted(str(key) for key in table if key not in _CHECK_KEYS[name])
        if unknown_keys:
            raise LintConfigError(
                f"{where}: unknown key(s) {_quoted(unknown_keys)}. "
                f"Known keys: {', '.join(sorted(_CHECK_KEYS[name]))}"
            )
        enabled = table.get("enabled", True)
        if not isinstance(enabled, bool):
            raise LintConfigError(f"{where}.enabled must be true or false, got {enabled!r}")
        severity = table.get("severity")
        if severity is not None and severity not in SEVERITIES:
            raise LintConfigError(
                f"{where}.severity must be one of {', '.join(SEVERITIES)}, got {severity!r}"
            )
        checks[name] = CheckConfig(enabled=enabled, severity=cast("Severity | None", severity))
        if name == "metadata" and "required" in table:
            required = _required_metadata(table["required"], where=where)
        if name == "filenames":
            filenames = _filename_config(table, where=where)
    return LintConfig(checks=checks, required_metadata=required, filenames=filenames)


def _filename_config(table: Mapping[str, object], *, where: str) -> FilenameConfig:
    style = table.get("style", "slug")
    if style not in FILENAME_STYLES:
        raise LintConfigError(
            f"{where}.style must be one of {', '.join(FILENAME_STYLES)}, got {style!r}"
        )
    pattern: re.Pattern[str] | None = None
    if "pattern" in table:
        raw = table["pattern"]
        if not isinstance(raw, str):
            raise LintConfigError(f"{where}.pattern must be a string, got {raw!r}")
        if not raw:
            raise LintConfigError(f"{where}.pattern must not be empty")
        try:
            pattern = re.compile(raw)
        except re.error as exc:
            raise LintConfigError(
                f"{where}.pattern: invalid regular expression '{raw}': {exc}"
            ) from exc
    return FilenameConfig(style=cast("FilenameStyle", style), pattern=pattern)


def _required_metadata(value: object, *, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise LintConfigError(f"{where}.required must be a list of metadata keys")
    known = metadata_keys()
    unknown = [item for item in value if item not in known]
    if unknown:
        raise LintConfigError(
            f"{where}.required: unknown metadata field(s) {_quoted(unknown)}. "
            f"Known fields: {', '.join(known)}"
        )
    return tuple(dict.fromkeys(value))


def _quoted(names: list[str]) -> str:
    return ", ".join(repr(name) for name in names)


def load_lint_config(workspace: Path | None = None) -> LintConfig:
    """Resolve ``lint.toml`` (bundled, then workspace, then parent instance) for *workspace*."""
    from opentide.core.files import resolve_configurations

    return parse_lint_config(resolve_configurations(workspace).get("lint"))
