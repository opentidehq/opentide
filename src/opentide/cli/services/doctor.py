"""Checks for ``opentide doctor``: the installation, the workspace, and its integrations.

Every check has a stable ``code`` (documented in ``docs/cli/doctor.md``), a
``status`` (``pass``, ``warn``, ``fail`` or ``skip``), a one-line ``message``
and, when something is wrong, a ``fix``. A check never prints a secret: a
tenant's credentials are reported as set or unset by variable name, and a
proxy URL is shown without its user and password.

Network checks (PyPI, the proxy) use short timeouts, honour ``--proxy``,
``HTTPS_PROXY`` and ``NO_PROXY``, and become a warning when offline.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import structlog
from rich.console import Console
from rich.text import Text

from opentide.cli.enums import McpHost
from opentide.cli.services.setup.mcp import MCP_OUTPUT_PATHS
from opentide.cli.ui.glyphs import glyph

logger = structlog.get_logger("opentide.cli.services.doctor")

Status = Literal["pass", "warn", "fail", "skip"]

#: Oldest Python opentide supports (``requires-python``).
MIN_PYTHON = (3, 10)
#: Seconds for each network call: connect, then read.
NETWORK_TIMEOUT = 3.0
PYPI_URL = "https://pypi.org/pypi/opentide/json"
UPGRADE_COMMAND = "pip install --upgrade opentide"
REINSTALL_COMMAND = "pip install --force-reinstall opentide"

#: ``failure.code`` when at least one check failed.
CHECKS_FAILED = "doctor_checks_failed"

#: The import each platform's live calls need. Platforms that talk to their
#: API over plain HTTPS need ``requests`` only.
PLATFORM_SDKS: dict[str, tuple[str, ...]] = {
    "sentinel": ("azure.identity", "azure.monitor.query", "requests"),
    "defender_for_endpoint": ("requests",),
    "splunk": ("splunklib.client",),
    "sentinel_one": ("requests",),
    "crowdstrike": ("requests",),
    "harfanglab": ("requests",),
    "carbon_black_cloud": ("cbc_sdk",),
    "elastic": ("requests",),
}

#: How the checklist names each host ``opentide setup mcp`` writes for; the
#: files themselves are :data:`~opentide.cli.services.setup.mcp.MCP_OUTPUT_PATHS`.
MCP_HOST_LABELS: dict[McpHost, str] = {
    McpHost.vscode: "VS Code",
    McpHost.cursor: "Cursor",
    McpHost.claude_code: "Claude Code",
    McpHost.generic: "generic",
}

_PROXY_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")


@dataclass(frozen=True)
class Check:
    """One line of the checklist."""

    code: str
    status: Status
    message: str
    fix: str | None = None
    #: What the check is about when it repeats per item: a platform, a tenant.
    subject: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "fix": self.fix,
            "subject": self.subject,
        }


@dataclass(frozen=True)
class DoctorContext:
    """What the checks read. Tests build one by hand."""

    workspace: Path
    #: The workspace came from ``--repo`` or ``OPENTIDE_REPO_ROOT`` rather than discovery.
    workspace_explicit: bool = False
    offline: bool = False
    env: Mapping[str, str] | None = None

    @property
    def environ(self) -> Mapping[str, str]:
        return os.environ if self.env is None else self.env


# --------------------------------------------------------------------------- helpers


#: What :func:`redact_url` returns for a URL it cannot take apart.
UNPARSEABLE_URL = "<unparseable proxy URL>"


def proxy_endpoint(url: str) -> tuple[str, str, int | None] | None:
    """Scheme, host and port of a proxy URL, or ``None`` when it cannot be parsed.

    The credentials are cut off at the *last* ``@`` before anything is parsed:
    a password may hold an unencoded ``/``, ``#`` or ``?``, which would make
    ``urlsplit`` end the host early and read part of the password as the port.
    """
    try:
        scheme, separator, rest = url.strip().partition("://")
        if not separator:
            scheme, rest = "http", url.strip()
        host_port = rest.rpartition("@")[2]
        for delimiter in "/?#":
            host_port = host_port.split(delimiter, 1)[0]
        parts = urlsplit(f"{scheme}://{host_port}")
        host = parts.hostname or ""
        port = parts.port
    except Exception:
        return None
    if not scheme.isalnum():
        return None
    return scheme, host, port


def redact_url(url: str) -> str:
    """*url* without its user and password: ``http://proxy:8080``. Never raises."""
    endpoint = proxy_endpoint(url)
    if endpoint is None:
        return UNPARSEABLE_URL
    scheme, host, port = endpoint
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}{f':{port}' if port else ''}"


def shown_path(path: Path, base: Path | None = None) -> str:
    """*path* relative to the current directory, as every path opentide prints.

    ``./`` is the current directory itself, and ``../..`` a folder above it.
    A path elsewhere is relative to *base* (the workspace) when inside it,
    otherwise absolute.
    """
    resolved = path.resolve()
    cwd = Path.cwd().resolve()
    if resolved == cwd:
        return "./"
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        pass
    if cwd.is_relative_to(resolved):
        return Path(os.path.relpath(resolved, cwd)).as_posix()
    if base is not None and resolved.is_relative_to(base.resolve()):
        return resolved.relative_to(base.resolve()).as_posix()
    return str(resolved)


def _version_key(text: str) -> Any:
    try:
        from packaging.version import Version

        return Version(text)
    except Exception:
        return tuple(int(part) if part.isdigit() else 0 for part in text.split(".")[:3])


def _run_git(workspace: Path, *args: str) -> str | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        done = subprocess.run(
            [git, *args],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _configurations(ctx: DoctorContext) -> dict[str, Any]:
    from opentide.core.files import resolve_configurations

    return resolve_configurations(ctx.workspace)


def _enabled_platforms(configs: Mapping[str, Any]) -> list[str]:
    from opentide.platforms.enabled import SYSTEM_KEYS

    systems = configs.get("systems") or {}
    enabled: list[str] = []
    for system in SYSTEM_KEYS:
        config = systems.get(system) or {}
        for block in ("platform", "tide"):
            section = config.get(block)
            if isinstance(section, Mapping) and section.get("enabled") is True:
                enabled.append(system)
                break
    return enabled


# --------------------------------------------------------------------------- checks


def check_python(ctx: DoctorContext) -> list[Check]:
    version = ".".join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] < MIN_PYTHON:
        minimum = ".".join(str(part) for part in MIN_PYTHON)
        return [
            Check(
                "python_version",
                "fail",
                f"Python {version} is older than {minimum}, the oldest opentide supports",
                f"install opentide under Python {minimum} or newer",
            )
        ]
    return [Check("python_version", "pass", f"Python {version}")]


def check_opentide_version(ctx: DoctorContext) -> list[Check]:
    from opentide import __version__

    return [Check("opentide_version", "pass", f"opentide {__version__}")]


def fetch_latest_version(timeout: float = NETWORK_TIMEOUT) -> str:
    """The newest opentide release on PyPI. Raises on any network or format error."""
    import requests

    response = requests.get(PYPI_URL, timeout=(timeout, timeout))
    response.raise_for_status()
    version = response.json()["info"]["version"]
    if not isinstance(version, str) or not version:
        raise ValueError("PyPI returned no version")
    return version


def check_latest_version(ctx: DoctorContext) -> list[Check]:
    from opentide import __version__

    if ctx.offline:
        return [Check("opentide_latest", "skip", "Not checked: --offline")]
    try:
        latest = fetch_latest_version()
    except Exception as exc:
        return [
            Check(
                "opentide_latest",
                "warn",
                f"Could not ask PyPI for the latest release ({type(exc).__name__})",
                "check the network or --proxy, or pass --offline to skip network checks",
            )
        ]
    if _version_key(latest) > _version_key(__version__):
        return [
            Check(
                "opentide_latest",
                "warn",
                f"opentide {latest} is available; {__version__} is installed",
                UPGRADE_COMMAND,
            )
        ]
    return [Check("opentide_latest", "pass", f"No newer release on PyPI than {__version__}")]


def check_workspace(ctx: DoctorContext) -> list[Check]:
    from opentide.core.root import OPENTIDE_DIR

    root = ctx.workspace
    shown = shown_path(root)
    how = (
        "set by --repo or OPENTIDE_REPO_ROOT"
        if ctx.workspace_explicit
        else "found from the current directory"
    )
    if (root / OPENTIDE_DIR).is_dir():
        return [Check("workspace", "pass", f"Workspace {shown} has {OPENTIDE_DIR}/ ({how})")]
    if (root / "objects").is_dir():
        return [
            Check(
                "workspace",
                "warn",
                f"Workspace {shown} has objects/ but no {OPENTIDE_DIR}/ ({how})",
                f"opentide setup repo --path {shown}",
            )
        ]
    return [
        Check(
            "workspace",
            "fail",
            f"No workspace at {shown}: no {OPENTIDE_DIR}/ or objects/ there or above it",
            f"opentide setup --path {shown}, or run from inside a workspace",
        )
    ]


def check_git(ctx: DoctorContext) -> list[Check]:
    if shutil.which("git") is None:
        return [
            Check(
                "git",
                "warn",
                "git is not on PATH; changed-object detection and hooks need it",
                "install git",
            )
        ]
    version = (_run_git(ctx.workspace, "--version") or "git").removeprefix("git version ")
    found = _run_git(ctx.workspace, "rev-parse", "--show-toplevel")
    if found is None:
        workspace = shown_path(ctx.workspace)
        return [
            Check("git", "pass", f"git {version}"),
            Check(
                "git_repository",
                "warn",
                f"{workspace} is not in a git repository",
                f"git init {workspace}",
            ),
        ]
    top = shown_path(Path(found))
    remote_head = _run_git(ctx.workspace, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
    checks = [Check("git", "pass", f"git {version}")]
    if remote_head:
        branch = remote_head.removeprefix("refs/remotes/origin/")
        checks.append(Check("git_repository", "pass", f"Repository {top}, default branch {branch}"))
        return checks
    has_origin = _run_git(ctx.workspace, "remote", "get-url", "origin") is not None
    if has_origin:
        checks.append(
            Check(
                "git_repository",
                "warn",
                f"Repository {top}: default branch unknown, origin/HEAD is not set",
                "git remote set-head origin --auto",
            )
        )
    else:
        current = _run_git(ctx.workspace, "branch", "--show-current") or "detached HEAD"
        checks.append(
            Check(
                "git_repository",
                "pass",
                f"Repository {top} has no origin remote; on {current}",
            )
        )
    return checks


_TOML_POSITION = re.compile(r"\s*\(at (?:line (?P<line>\d+), column \d+|end of document)\)\s*$")


def _configuration_files(workspace: Path) -> list[Path]:
    """The workspace's configuration TOMLs, and its parent instance's, in load order."""
    from opentide.registry.discovery import client_configurations_dir

    folders = [
        client_configurations_dir(workspace),
        workspace.parent / ".opentide" / "configurations",
    ]
    files: list[Path] = []
    for folder in dict.fromkeys(folders):
        if folder.is_dir():
            files.extend(
                path
                for path in sorted(folder.rglob("*.toml"))
                if not any(
                    part.startswith((".", "__")) for part in path.relative_to(folder).parts[:-1]
                )
            )
    return files


def _toml_problem(path: Path) -> tuple[int | None, str] | None:
    """Line and reason *path* does not parse, or ``None`` when it does.

    The reason is the parser's description only (``Invalid value``), never
    the text around it, which may hold a credential.
    """
    from opentide.core.files import tomllib

    try:
        tomllib.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        return None, "it is not UTF-8"
    except OSError as exc:
        return None, f"it cannot be read ({type(exc).__name__})"
    except tomllib.TOMLDecodeError as exc:
        message = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        position = _TOML_POSITION.search(message)
        line = position.group("line") if position else None
        reason = message[: position.start()] if position else message
        return (int(line) if line else None), reason
    return None


def check_configuration(ctx: DoctorContext) -> list[Check]:
    """The merged configuration loads; when it does not, which file and line breaks it."""
    files = _configuration_files(ctx.workspace)
    try:
        _configurations(ctx)
    except Exception as exc:
        for path in files:
            problem = _toml_problem(path)
            if problem is None:
                continue
            line, reason = problem
            shown = shown_path(path, ctx.workspace)
            where = f"{shown} line {line}" if line else shown
            return [
                Check(
                    "configuration",
                    "fail",
                    f"{where} is not valid TOML: {reason}",
                    f"fix {where}; the checks that read the configuration are skipped until then",
                )
            ]
        logger.debug("doctor_configuration_failed", exc_info=True)
        return [
            Check(
                "configuration",
                "fail",
                f"The configuration does not load ({type(exc).__name__})",
                "re-run with --debug for the traceback",
            )
        ]
    if not files:
        return [Check("configuration", "pass", "No workspace configuration: the defaults apply")]
    return [
        Check(
            "configuration",
            "pass",
            f"{len(files)} configuration file{'s load' if len(files) != 1 else ' loads'}",
        )
    ]


def check_templates(ctx: DoctorContext) -> list[Check]:
    from opentide.generation.pydantic_skeleton import render_model_template
    from opentide.models.object_types import CORE_OBJECT_TYPES
    from opentide.models.schema_registry import identifiers_for_families, resolve_model
    from opentide.registry.artifacts import template_artifact_name
    from opentide.registry.paths import resolve_workspace_paths

    paths = resolve_workspace_paths(_configurations(ctx), workspace=ctx.workspace)
    folder = Path(paths["templates"])
    missing: list[str] = []
    stale: list[str] = []
    for schema_id in identifiers_for_families(CORE_OBJECT_TYPES):
        target = folder / template_artifact_name(schema_id)
        if not target.is_file():
            missing.append(target.name)
            continue
        expected = render_model_template(resolve_model(schema_id), schema_id=schema_id)
        if target.read_text(encoding="utf-8") != expected:
            stale.append(target.name)
    fix = "opentide generate templates schemas snippets"
    if missing:
        return [
            Check(
                "templates_fresh",
                "warn",
                f"{len(missing)} template(s) missing: {', '.join(missing)}",
                fix,
            )
        ]
    if stale:
        return [
            Check(
                "templates_fresh",
                "warn",
                f"{len(stale)} template(s) differ from what this version generates: "
                f"{', '.join(stale)}",
                fix,
            )
        ]
    return [Check("templates_fresh", "pass", "Templates match the installed version")]


def check_schemas(ctx: DoctorContext) -> list[Check]:
    from opentide.models.object_types import CORE_OBJECT_TYPES
    from opentide.models.schema_registry import identifiers_for_families
    from opentide.registry.artifacts import schema_artifact_name
    from opentide.registry.paths import resolve_workspace_paths, workspace_config

    configs = _configurations(ctx)
    paths = resolve_workspace_paths(configs, workspace=ctx.workspace)
    folder = Path(paths["json_schemas"])
    names = [schema_artifact_name(item) for item in identifiers_for_families(CORE_OBJECT_TYPES)]
    artifacts = (workspace_config(configs).get("artifacts") or {}).get("schemas") or {}
    names.extend(str(artifacts[key]) for key in ("router", "visibility") if artifacts.get(key))
    missing = [name for name in dict.fromkeys(names) if not (folder / name).is_file()]
    if missing:
        return [
            Check(
                "schemas_fresh",
                "warn",
                f"{len(missing)} schema(s) this version generates are missing: "
                f"{', '.join(missing)}",
                "opentide generate schemas",
            )
        ]
    return [
        Check(
            "schemas_fresh",
            "pass",
            f"Every schema this version generates is present ({len(names)})",
        )
    ]


def check_platforms(ctx: DoctorContext) -> list[Check]:
    enabled = _enabled_platforms(_configurations(ctx))
    if not enabled:
        return [
            Check(
                "platforms_enabled",
                "warn",
                "No platform is enabled; rules validate but nothing deploys",
                "opentide setup platforms --sentinel (or another platform)",
            )
        ]
    return [Check("platforms_enabled", "pass", f"Enabled: {', '.join(enabled)}")]


def _importable(module: str) -> str | None:
    """``None`` when *module* imports, else why not."""
    import importlib

    try:
        importlib.import_module(module)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def check_platform_sdks(ctx: DoctorContext) -> list[Check]:
    checks: list[Check] = []
    for platform in _enabled_platforms(_configurations(ctx)):
        failures = [
            (module, reason)
            for module in PLATFORM_SDKS.get(platform, ())
            if (reason := _importable(module)) is not None
        ]
        if failures:
            module, reason = failures[0]
            checks.append(
                Check(
                    "platform_sdk",
                    "fail",
                    f"{platform}: cannot import {module} ({reason})",
                    REINSTALL_COMMAND,
                    subject=platform,
                )
            )
        else:
            modules = ", ".join(PLATFORM_SDKS.get(platform, ())) or "no SDK needed"
            checks.append(
                Check("platform_sdk", "pass", f"{platform}: {modules} import", subject=platform)
            )
    return checks


def _placeholders(value: Any) -> Iterable[str]:
    """``$NAME`` references anywhere in a tenant's setup."""
    if isinstance(value, str) and value.startswith("$") and len(value) > 1:
        yield value[1:]
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _placeholders(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _placeholders(item)


def check_credentials(ctx: DoctorContext) -> list[Check]:
    """Per configured tenant: are the variables its setup names set? Never their values."""
    from opentide.platforms.enabled import platform_config_path

    configs = _configurations(ctx)
    systems = configs.get("systems") or {}
    environ = ctx.environ
    checks: list[Check] = []
    for platform in _enabled_platforms(configs):
        tenants = (systems.get(platform) or {}).get("tenants")
        tenants = [tenant for tenant in tenants or () if isinstance(tenant, Mapping)]
        if not tenants:
            checks.append(
                Check(
                    "credentials",
                    "skip",
                    f"{platform}: no tenant configured",
                    f"add a [[tenants]] entry in {platform_config_path(platform)}",
                    subject=platform,
                )
            )
            continue
        for index, tenant in enumerate(tenants, start=1):
            name = str(tenant.get("name") or f"tenant {index}")
            subject = f"{platform}/{name}"
            variables = list(dict.fromkeys(_placeholders(tenant.get("setup") or {})))
            unset = [variable for variable in variables if not environ.get(variable)]
            if unset:
                checks.append(
                    Check(
                        "credentials",
                        "warn",
                        f"{subject}: {len(unset)} of {len(variables)} variables unset: "
                        f"{', '.join(unset)}",
                        f"set {', '.join(unset)} in the environment (or a .env file you load)",
                        subject=subject,
                    )
                )
            elif variables:
                checks.append(
                    Check(
                        "credentials",
                        "pass",
                        f"{subject}: all {len(variables)} variables set",
                        subject=subject,
                    )
                )
            else:
                checks.append(
                    Check(
                        "credentials",
                        "pass",
                        f"{subject}: setup names no environment variable",
                        subject=subject,
                    )
                )
    return checks


def _bypasses_proxy(host: str, no_proxy: str) -> bool:
    for entry in (item.strip().lower() for item in no_proxy.split(",")):
        if not entry:
            continue
        if entry == "*":
            return True
        entry = entry.lstrip(".")
        if host == entry or host.endswith(f".{entry}"):
            return True
    return False


def connect(host: str, port: int, timeout: float = NETWORK_TIMEOUT) -> None:
    """Open and close a TCP connection. Raises ``OSError`` when it cannot."""
    with socket.create_connection((host, port), timeout=timeout):
        pass


def check_proxy(ctx: DoctorContext) -> list[Check]:
    environ = ctx.environ
    url = next((environ[name] for name in _PROXY_VARIABLES if environ.get(name)), None)
    if url is None:
        return [Check("proxy", "skip", "No proxy set (--proxy, HTTPS_PROXY)")]
    shown = redact_url(url)
    no_proxy = environ.get("NO_PROXY") or environ.get("no_proxy") or ""
    note = "; pypi.org bypasses it (NO_PROXY)" if _bypasses_proxy("pypi.org", no_proxy) else ""
    if ctx.offline:
        return [Check("proxy", "skip", f"Proxy {shown} not checked: --offline")]
    endpoint = proxy_endpoint(url)
    if endpoint is None or not endpoint[1]:
        return [
            Check(
                "proxy",
                "fail",
                f"Proxy {shown} has no host" if endpoint else "The proxy URL cannot be parsed",
                "pass --proxy http://host:port",
            )
        ]
    scheme, host, port = endpoint
    try:
        connect(host, port or (443 if scheme == "https" else 80))
    except (OSError, ValueError) as exc:
        return [
            Check(
                "proxy",
                "fail",
                f"Cannot connect to proxy {shown} ({type(exc).__name__})",
                "check --proxy, OPENTIDE_PROXY or HTTPS_PROXY, and that the proxy is up",
            )
        ]
    return [Check("proxy", "pass", f"Proxy {shown} accepts connections{note}")]


def _read_json(path: Path) -> Any:
    from opentide.cli.services.setup.vscode import _strip_jsonc

    try:
        return json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def check_vscode(ctx: DoctorContext) -> list[Check]:
    from opentide.cli.services.setup.vscode import build_yaml_schema_mappings, snippet_file_rel

    checks: list[Check] = []
    settings = ctx.workspace / ".vscode" / "settings.json"
    if not settings.is_file():
        checks.append(
            Check(
                "vscode_settings",
                "skip",
                "No .vscode/settings.json: editors get no schema completion",
                "opentide setup vscode",
            )
        )
    else:
        data = _read_json(settings)
        schemas = data.get("yaml.schemas") if isinstance(data, dict) else None
        expected = build_yaml_schema_mappings(workspace=ctx.workspace)
        if not isinstance(schemas, dict):
            checks.append(
                Check(
                    "vscode_settings",
                    "warn",
                    ".vscode/settings.json maps no yaml.schemas"
                    if data is not None
                    else ".vscode/settings.json is not valid JSON",
                    "opentide setup vscode",
                )
            )
        elif all(schemas.get(key) == value for key, value in expected.items()):
            checks.append(
                Check("vscode_settings", "pass", ".vscode/settings.json maps the object schemas")
            )
        else:
            checks.append(
                Check(
                    "vscode_settings",
                    "warn",
                    ".vscode/settings.json does not map objects to " + ", ".join(sorted(expected)),
                    "opentide setup vscode",
                )
            )
    snippets = snippet_file_rel(workspace=ctx.workspace)
    if (ctx.workspace / snippets).is_file():
        checks.append(Check("vscode_snippets", "pass", f"Snippets in {snippets}"))
    else:
        checks.append(
            Check(
                "vscode_snippets",
                "skip",
                f"No snippets at {snippets}",
                "opentide generate snippets",
            )
        )
    return checks


def _opentide_server(data: Any) -> Mapping[str, Any] | None:
    if not isinstance(data, Mapping):
        return None
    for key in ("servers", "mcpServers"):
        servers = data.get(key)
        if isinstance(servers, Mapping):
            for server in servers.values():
                if not isinstance(server, Mapping):
                    continue
                args = server.get("args")
                if isinstance(args, list) and args[-2:] == ["mcp", "start"]:
                    return server
    return None


def check_mcp(ctx: DoctorContext) -> list[Check]:
    hosts: list[str] = []
    #: Files that exist but configure no opentide server: often a host's own
    #: file listing other servers only (``.mcp.json`` in Claude Code).
    without: list[str] = []
    commands: set[str] = set()
    for host, relative in MCP_OUTPUT_PATHS.items():
        path = ctx.workspace / relative
        if not path.is_file():
            continue
        server = _opentide_server(_read_json(path))
        if server is None:
            without.append(relative)
            continue
        hosts.append(MCP_HOST_LABELS[host])
        commands.add(str(server.get("command") or ""))
    setup = "opentide setup mcp --vscode (or --cursor, --claude-code, --generic)"
    if not hosts:
        if without:
            return [
                Check(
                    "mcp_config",
                    "warn",
                    f"{', '.join(without)} has no opentide server running 'mcp start'",
                    setup,
                )
            ]
        return [
            Check(
                "mcp_config",
                "skip",
                "No MCP configuration: agents in editors cannot call opentide tools",
                setup,
            )
        ]
    configured = f"MCP configured for {', '.join(hosts)}"
    if without:
        configured += f" ({', '.join(without)} has no opentide server)"
    unresolved = sorted(
        command for command in commands if command and shutil.which(command) is None
    )
    if unresolved:
        return [
            Check(
                "mcp_config",
                "warn",
                f"{configured}, but {', '.join(unresolved)} is not on PATH for the editor to start",
                "put opentide on PATH, or set the full path as the server command",
            )
        ]
    return [Check("mcp_config", "pass", configured)]


#: In the order the checklist prints.
CHECKS: tuple[Callable[[DoctorContext], list[Check]], ...] = (
    check_python,
    check_opentide_version,
    check_latest_version,
    check_workspace,
    check_git,
    check_configuration,
    check_templates,
    check_schemas,
    check_platforms,
    check_platform_sdks,
    check_credentials,
    check_proxy,
    check_vscode,
    check_mcp,
)

#: The documented code (or codes) each check reports, used when it cannot run.
CHECK_CODES: dict[Callable[[DoctorContext], list[Check]], tuple[str, ...]] = {
    check_python: ("python_version",),
    check_opentide_version: ("opentide_version",),
    check_latest_version: ("opentide_latest",),
    check_workspace: ("workspace",),
    check_git: ("git", "git_repository"),
    check_configuration: ("configuration",),
    check_templates: ("templates_fresh",),
    check_schemas: ("schemas_fresh",),
    check_platforms: ("platforms_enabled",),
    check_platform_sdks: ("platform_sdk",),
    check_credentials: ("credentials",),
    check_proxy: ("proxy",),
    check_vscode: ("vscode_settings", "vscode_snippets"),
    check_mcp: ("mcp_config",),
}

#: Checks that read the merged configuration: skipped when it does not load.
NEEDS_CONFIGURATION = frozenset(
    {
        check_templates,
        check_schemas,
        check_platforms,
        check_platform_sdks,
        check_credentials,
        check_vscode,
    }
)


def _name(check: Callable[[DoctorContext], list[Check]]) -> str:
    return str(getattr(check, "__name__", "check"))


def _codes(check: Callable[[DoctorContext], list[Check]]) -> tuple[str, ...]:
    return CHECK_CODES.get(check) or (_name(check).removeprefix("check_"),)


def _guarded(check: Callable[[DoctorContext], list[Check]], ctx: DoctorContext) -> list[Check]:
    """A check that raises reports a failure instead of stopping the checklist.

    The message names the exception type only: its text can quote what the
    check was reading, such as part of a proxy password.
    """
    try:
        return check(ctx)
    except Exception as exc:
        logger.debug("doctor_check_raised", check=_name(check), exc_info=True)
        return [
            Check(
                code,
                "fail",
                f"The check itself failed ({type(exc).__name__})",
                "re-run with --debug for the traceback, and report it if it persists",
            )
            for code in _codes(check)
        ]


def run_doctor(
    ctx: DoctorContext, checks: Sequence[Callable[[DoctorContext], list[Check]]] | None = None
) -> dict[str, Any]:
    """Run every check and build the ``CommandResult`` payload."""
    results: list[Check] = []
    configuration_failed = False
    for check in CHECKS if checks is None else checks:
        if configuration_failed and check in NEEDS_CONFIGURATION:
            results.extend(
                Check(code, "skip", "Not checked: the configuration does not load")
                for code in _codes(check)
            )
            continue
        outcome = _guarded(check, ctx)
        if check is check_configuration:
            configuration_failed = any(item.status == "fail" for item in outcome)
        results.extend(outcome)
    counts = {
        status: sum(1 for item in results if item.status == status)
        for status in ("pass", "warn", "fail", "skip")
    }
    failed, warned, passed, skipped = counts["fail"], counts["warn"], counts["pass"], counts["skip"]

    def plural(count: int, word: str) -> str:
        return f"{count} {word}{'s' if count != 1 else ''}"

    rest = [f"{passed} passed"]
    if failed:
        headline, status = f"{plural(failed, 'check')} failed", "failed"
        if warned:
            rest.append(plural(warned, "warning"))
    elif warned:
        headline, status = plural(warned, "warning"), "issues"
    else:
        headline, status = f"{plural(passed, 'check')} passed", "completed"
        rest = []
    if skipped:
        rest.append(f"{skipped} skipped")
    separator = f" {glyph('separator')} "
    message = separator.join([headline, ", ".join(rest)]) if rest else headline
    payload: dict[str, Any] = {
        "message": message,
        "status": status,
        "checks": [item.to_dict() for item in results],
        "_summary": {
            "checks": len(results),
            "passed": passed,
            "warnings": warned,
            "failed": failed,
            "skipped": counts["skip"],
        },
    }
    if failed:
        payload["_exit_code"] = 1
        payload["_failure_code"] = CHECKS_FAILED
    return payload


_GLYPHS: dict[str, tuple[str, str]] = {
    "pass": ("ok", "green"),
    "warn": ("warning", "yellow"),
    "fail": ("failed", "red"),
    # Not the plan's "disable" glyph ``-``: a skipped check is not applicable.
    "skip": ("skip", "dim"),
}


def render_checks(console: Console, checks: Sequence[Mapping[str, Any]]) -> None:
    """One line per check, with its fix underneath when there is something to do."""
    from opentide.cli.ui.render import print_line

    encoding = console.encoding or "utf-8"
    for check in checks:
        name, style = _GLYPHS.get(str(check["status"]), ("warning", "yellow"))
        line = Text()
        line.append(glyph(name, encoding=encoding), style=f"bold {style}")
        line.append(" ")
        line.append(str(check["message"]))
        line.append(f" {glyph('separator', encoding=encoding)} {check['code']}", style="dim")
        print_line(console, line, hang=2)
        if check.get("fix") and check["status"] in ("warn", "fail", "skip"):
            hint = Text("  ")
            hint.append(f"{glyph('next', encoding=encoding)} ", style="bold cyan")
            hint.append(str(check["fix"]), style="dim" if check["status"] == "skip" else "")
            print_line(console, hint, hang=4)
