"""The workspace's configuration as ``opentide tui`` shows it: read, not as TOML (#776).

Each file (``deployment.toml``, ``lint.toml``, ``documentation.toml``,
``sharing.toml`` and each ``platforms/*.toml``) is shown by section, each
setting with its effective value (the bundled file, the workspace's and the
parent instance merged, as every command reads them), whether the workspace
sets it, and what it does: the description its JSON Schema
(:mod:`opentide.generation.configuration_schemas`) gives, else the bundled
file's comment above it. Options the workspace does not set are listed with
their descriptions too. Platforms read as cards: enabled or not, and each
tenant's strategies, credentials and the rules that reach it.

**No credential value is ever returned.** A value under a tenant's ``setup``
table, or under a key that names a secret (``key``, ``token``, ``password``…),
is replaced: a ``$NAME`` or ``${NAME}`` reference by its variable name and
whether the environment sets it, as ``opentide doctor`` reports it; anything
else by :data:`HIDDEN`. The raw file is redacted the same way, line by line.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

__all__ = [
    "HIDDEN",
    "ConfigFile",
    "ConfigFinding",
    "ConfigurationView",
    "Credential",
    "PlatformCard",
    "Setting",
    "TenantCard",
    "load_configuration_view",
    "redact_toml",
]

#: What a hidden value reads as. Never the value, its length or a part of it.
HIDDEN = "•••• hidden"
#: A key whose value is a secret wherever it is.
SECRET_KEY = re.compile(
    r"(secret|token|password|passwd|passphrase|api[_-]?key|private[_-]?key|credential|"
    r"auth|^key$|_key$|cookie|session)",
    re.IGNORECASE,
)
#: The tables whose every value is a credential or tenant secret.
SECRET_TABLES = frozenset({"setup"})
#: ``scheme://user:password@host``: the user part is hidden too.
_USERINFO = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s\"']+@")

#: The files the tab shows, in order; platform files follow.
FILES = ("deployment.toml", "lint.toml", "documentation.toml", "sharing.toml")
_MERGED_KEYS = {
    "deployment.toml": "deployment",
    "lint.toml": "lint",
    "documentation.toml": "documentation",
    "sharing.toml": "sharing",
}


@dataclass(frozen=True)
class Setting:
    """One value of a configuration file, as the tab shows it."""

    #: The key path in the file (``tenants.0.setup.api_key``).
    path: str
    key: str
    #: The effective value, shown: redacted when it is a secret.
    shown: str
    #: Whether the workspace's file sets it (else it is the bundled default).
    set_here: bool
    description: str = ""
    secret: bool = False
    #: For a secret that is a ``$NAME`` reference: the variable, and whether it is set.
    variable: str | None = None
    variable_set: bool | None = None


@dataclass(frozen=True)
class ConfigFinding:
    code: str
    severity: str
    message: str
    field_path: tuple[str, ...]


@dataclass(frozen=True)
class ConfigFile:
    """One configuration file."""

    key: str
    #: The workspace's file, when it has one.
    path: Path | None
    settings: tuple[Setting, ...]
    #: ``(path, description)`` of options the schema defines that nothing sets.
    unset: tuple[tuple[str, str], ...] = ()
    findings: tuple[ConfigFinding, ...] = ()
    #: The workspace's file, redacted (:func:`redact_toml`); ``None`` without one.
    raw: str | None = None


@dataclass(frozen=True)
class Credential:
    """One ``setup`` key of a tenant: never its value."""

    key: str
    variable: str | None
    #: Whether the variable is set; ``None`` for a literal (shown as :data:`HIDDEN`).
    is_set: bool | None
    #: A switch (``ssl = true``), which is no credential and is shown.
    flag: bool | None = None


@dataclass(frozen=True)
class TenantCard:
    name: str
    strategies: tuple[str, ...]
    manual: bool
    credentials: tuple[Credential, ...]
    #: Rules a deploy run reaches this tenant with, as ``deploy`` plans them.
    rules: tuple[str, ...]


@dataclass(frozen=True)
class PlatformCard:
    platform: str
    enabled: bool
    tenants: tuple[TenantCard, ...]
    #: Rules with a block for this platform.
    rules: tuple[str, ...]


@dataclass(frozen=True)
class ConfigurationView:
    files: tuple[ConfigFile, ...] = ()
    platforms: tuple[PlatformCard, ...] = ()
    #: Why the configuration could not be read, when it could not.
    problem: str | None = None
    environ: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False)


def _is_secret(parts: Sequence[str]) -> bool:
    keys = [part for part in parts if not part.isdigit()]
    return any(part in SECRET_TABLES for part in keys[:-1]) or bool(
        keys and SECRET_KEY.search(keys[-1])
    )


def _shown(value: Any, parts: Sequence[str], environ: Mapping[str, str]) -> Setting:
    from opentide.core.environment import env_reference

    path = ".".join(parts)
    key = parts[-1] if parts else ""
    # A switch (`ssl = true`) is no credential: it is shown as it is.
    if _is_secret(parts) and not isinstance(value, bool):
        variable = env_reference(value) if isinstance(value, str) else None
        if variable is not None:
            is_set = bool(environ.get(variable))
            return Setting(
                path, key, f"${{{variable}}} ({'set' if is_set else 'unset'})", False,
                secret=True, variable=variable, variable_set=is_set,
            )  # fmt: skip
        return Setting(path, key, HIDDEN, False, secret=True)
    return Setting(path, key, _format(value), False)


def _format(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _USERINFO.sub(lambda m: f"{m.group(1)}{HIDDEN}@", value)
    if isinstance(value, (list, tuple)) and all(
        not isinstance(item, (Mapping, list, tuple)) for item in value
    ):
        return ", ".join(_format(item) for item in value) or "[]"
    return str(value)


def _leaves(value: Any, parts: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _leaves(item, (*parts, str(key)))
    elif isinstance(value, (list, tuple)) and any(isinstance(i, Mapping) for i in value):
        for index, item in enumerate(value):
            yield from _leaves(item, (*parts, str(index)))
    else:
        yield parts, value


def _has(document: Any, parts: Sequence[str]) -> bool:
    node = document
    for part in parts:
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False
    return True


def _schema_descriptions(file_key: str) -> dict[str, str]:
    """``dotted path → description`` from the file's JSON Schema (list items as ``*``)."""
    from opentide.generation.configuration_schemas import generate_configuration_schema

    try:
        schema = generate_configuration_schema(file_key)
    except (KeyError, LookupError, ValueError):
        return {}
    definitions = schema.get("$defs") or {}
    found: dict[str, str] = {}

    def resolve(node: Mapping[str, Any]) -> Mapping[str, Any]:
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            return definitions.get(ref.rsplit("/", 1)[-1], node)
        for key in ("anyOf", "oneOf", "allOf"):
            for option in node.get(key) or ():
                if isinstance(option, Mapping) and (option.get("$ref") or option.get("properties")):
                    return resolve(option)
        return node

    def walk(node: Mapping[str, Any], prefix: str, depth: int) -> None:
        if depth > 8:
            return
        node = resolve(node)
        for name, child in (node.get("properties") or {}).items():
            if not isinstance(child, Mapping):
                continue
            path = f"{prefix}.{name}" if prefix else str(name)
            description = child.get("description") or resolve(child).get("description")
            if isinstance(description, str):
                found[path] = " ".join(description.split())
            resolved = resolve(child)
            walk(resolved, path, depth + 1)
            items = resolved.get("items")
            if isinstance(items, Mapping):
                walk(items, f"{path}.*", depth + 1)

    walk(schema, "", 0)
    return found


def _comment_descriptions(text: str | None) -> dict[str, str]:
    """``dotted path → the comment above it`` in a bundled file (``lint.toml`` has no schema)."""
    if not text:
        return {}
    found: dict[str, str] = {}
    comments: list[str] = []
    table: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            # A commented-out key is an example, not a description.
            if body and not re.match(r"^[\w.\-\"]+\s*=", body) and not body.startswith("["):
                comments.append(body)
            continue
        header = re.match(r"^\[\[?([^\]]+)\]\]?$", line)
        if header:
            table = [part.strip() for part in header.group(1).split(".")]
            if comments:
                found[".".join(table)] = " ".join(comments)
            comments = []
            continue
        assignment = re.match(r"^([\w\-]+)\s*=", line)
        if assignment and comments:
            found[".".join([*table, assignment.group(1)])] = " ".join(comments)
        if line:
            comments = []
    return found


def _description(descriptions: Mapping[str, str], parts: Sequence[str]) -> str:
    starred = ".".join("*" if part.isdigit() else part for part in parts)
    plain = ".".join(part for part in parts if not part.isdigit())
    return descriptions.get(starred) or descriptions.get(plain) or ""


def _bundled_text(file_key: str) -> str | None:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / file_key
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def redact_toml(text: str, environ: Mapping[str, str] | None = None) -> str:
    """*text* with every secret value replaced, as the raw view shows it.

    A value under a ``setup`` table (``[tenants.setup]``, or ``setup = {…}``
    inline) or under a secret-named key is replaced by its variable reference
    and whether it is set, or by :data:`HIDDEN`; a multi-line string there is
    replaced whole. Comments and layout stay.
    """
    from opentide.core.environment import env_reference

    environ = os.environ if environ is None else environ
    out: list[str] = []
    table: list[str] = []
    skipping: str | None = None
    for line in text.splitlines(keepends=True):
        if skipping is not None:
            if skipping in line:
                skipping = None
            continue
        stripped = line.strip()
        header = re.match(r"^\[\[?([^\]]+)\]\]?", stripped)
        if header:
            table = [part.strip().strip('"') for part in header.group(1).split(".")]
            out.append(line)
            continue
        match = re.match(r"^(\s*)([\w\-\"'.]+?)(\s*=\s*)(.*?)(\r?\n)?$", line)
        if not match or stripped.startswith("#"):
            out.append(line)
            continue
        indent, key, equals, value, newline = match.groups()
        # A dotted key (`setup.api_key = …`) is a path under the table.
        names = [part.strip().strip("\"'") for part in key.split(".")]
        parts = [*table, *names]
        if value.strip() in ("true", "false") or not _is_secret(
            [*parts, "x"] if names[-1] in SECRET_TABLES else parts
        ):
            out.append(_USERINFO.sub(lambda m: f"{m.group(1)}{HIDDEN}@", line))
            continue
        for quote in ('"""', "'''"):
            if value.startswith(quote) and value.count(quote) == 1:
                skipping = quote
        # An array or inline value that goes on below: hide its lines too.
        if value.lstrip().startswith("[") and value.count("[") > value.count("]"):
            skipping = "]"
        reference = None
        try:
            parsed = tomllib.loads(f"v = {value}")["v"]
            reference = env_reference(parsed) if isinstance(parsed, str) else None
        except tomllib.TOMLDecodeError:
            parsed = None
        if reference is not None:
            state = "set" if environ.get(reference) else "unset"
            shown = f'"${{{reference}}}"  # {state}'
        else:
            shown = f'"{HIDDEN}"'
        out.append(f"{indent}{key}{equals}{shown}{newline or ''}")
    return "".join(out)


def _file(
    file_key: str,
    merged: Any,
    workspace_dir: Path | None,
    findings: Sequence[ConfigFinding],
    environ: Mapping[str, str],
) -> ConfigFile:
    path = workspace_dir / file_key if workspace_dir is not None else None
    own: Any = {}
    raw = None
    if path is not None and path.is_file():
        try:
            text = path.read_text(encoding="utf-8-sig")
            raw = redact_toml(text, environ)
            own = tomllib.loads(text)
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            own = {}
    else:
        path = None
    schema_key = "platforms/*.toml" if file_key.startswith("platforms/") else file_key
    descriptions = {
        **_comment_descriptions(_bundled_text(file_key)),
        **_schema_descriptions(file_key if file_key != "lint.toml" else schema_key),
    }
    settings: list[Setting] = []
    for parts, value in _leaves(merged if isinstance(merged, Mapping) else {}):
        shown = _shown(value, parts, environ)
        settings.append(
            Setting(
                shown.path,
                shown.key,
                shown.shown,
                _has(own, parts),
                _description(descriptions, parts),
                shown.secret,
                shown.variable,
                shown.variable_set,
            )
        )
    present = {".".join("*" if p.isdigit() else p for p in s.path.split(".")) for s in settings}
    present |= {".".join(p for p in s.path.split(".") if not p.isdigit()) for s in settings}
    prefixes = {p.rsplit(".", n)[0] for p in present for n in range(1, p.count(".") + 1)}
    unset = tuple(
        (path_key, text)
        for path_key, text in sorted(descriptions.items())
        if path_key not in present
        and path_key not in prefixes
        and (path_key.rsplit(".", 1)[0] in prefixes | present if "." in path_key else True)
        and not _is_secret(path_key.split("."))
    )
    return ConfigFile(file_key, path, tuple(settings), unset, tuple(findings), raw)


def _findings(configs: Mapping[str, Any]) -> dict[str, list[ConfigFinding]]:
    from opentide.validation.configuration import workspace_configuration_issues

    found: dict[str, list[ConfigFinding]] = {}
    try:
        issues = workspace_configuration_issues(configs)
    except Exception:  # the checks are validate's: the tab shows what it can
        return found
    for issue in issues:
        context = getattr(issue, "context", None) or {}
        file_key = str(context.get("file") or "")
        found.setdefault(file_key, []).append(
            ConfigFinding(
                code=str(issue.code),
                severity=str(issue.severity),
                message=str(issue.message),
                field_path=tuple(str(part) for part in issue.field_path or ()),
            )
        )
    return found


def _platform_cards(
    configs: Mapping[str, Any], rules: Mapping[str, Any], environ: Mapping[str, str]
) -> list[PlatformCard]:
    from opentide.cli.services.catalog import _status_strategies
    from opentide.core.environment import env_reference
    from opentide.core.object_fields import as_body
    from opentide.models.deployment_enums import StatusStrategy, deployed_by

    strategies = _status_strategies(configs.get("deployment") or {})
    platforms = configs.get("platforms") or {}
    cards: list[PlatformCard] = []
    for platform, document in sorted(platforms.items()):
        if not isinstance(document, Mapping):
            continue
        platform_section = document.get("platform")
        enabled = bool(
            (platform_section or {}).get("enabled")
            if isinstance(platform_section, Mapping)
            else document.get("enabled")
        )
        with_block: list[tuple[str, Mapping[str, Any]]] = []
        for uuid, rule in rules.items():
            blocks = as_body(rule).get("configurations")
            block = blocks.get(platform) if isinstance(blocks, Mapping) else None
            if isinstance(block, Mapping):
                with_block.append((uuid, block))
        tenants: list[TenantCard] = []
        for index, tenant in enumerate(document.get("tenants") or ()):
            if not isinstance(tenant, Mapping):
                continue
            name = str(tenant.get("name") or f"tenant {index + 1}")
            accepted = tuple(str(s).upper() for s in tenant.get("strategies") or ())
            manual = tenant.get("manual") is True
            setup = tenant.get("setup") if isinstance(tenant.get("setup"), Mapping) else {}
            credentials = []
            for key, value in setup.items():
                variable = env_reference(value)
                credentials.append(
                    Credential(
                        str(key),
                        variable,
                        None if variable is None else bool(environ.get(variable)),
                        value if isinstance(value, bool) else None,
                    )
                )
            reaching: list[str] = []
            for uuid, block in with_block:
                if block.get("enabled") is False:
                    continue
                listed = [str(t) for t in block.get("tenants") or ()]
                if listed:
                    if name in listed:
                        reaching.append(uuid)
                    continue
                if manual:
                    continue
                status = str(block.get("status") or "")
                strategy = strategies.get(status)
                if strategy is None or strategy not in StatusStrategy.__members__:
                    continue
                runs = deployed_by(StatusStrategy[strategy])
                if any(run.name in accepted for run in runs):
                    reaching.append(uuid)
            tenants.append(TenantCard(name, accepted, manual, tuple(credentials), tuple(reaching)))
        cards.append(
            PlatformCard(
                platform=str(platform),
                enabled=enabled,
                tenants=tuple(tenants),
                rules=tuple(uuid for uuid, _ in with_block),
            )
        )
    return cards


def load_configuration_view(
    root: Path | None,
    rules: Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
) -> ConfigurationView:
    """The tab's content for the workspace at *root*, its *rules* bodies by UUID."""
    from opentide.core.files import resolve_configurations

    environ = dict(os.environ if environ is None else environ)
    try:
        configs = resolve_configurations(root)
    except Exception as exc:  # validate reports the file; the tab says why
        return ConfigurationView(problem=f"The configuration could not be read: {exc}")
    workspace_dir = None if root is None else root / ".opentide" / "configurations"
    findings = _findings(configs)
    files = [
        _file(
            key, configs.get(_MERGED_KEYS[key]) or {}, workspace_dir, findings.get(key, ()), environ
        )
        for key in FILES
    ]
    for platform, document in sorted((configs.get("platforms") or {}).items()):
        key = f"platforms/{platform}.toml"
        files.append(_file(key, document, workspace_dir, findings.get(key, ()), environ))
    return ConfigurationView(
        files=tuple(files),
        platforms=tuple(_platform_cards(configs, rules, environ)),
        environ=environ,
    )
