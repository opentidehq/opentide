"""What an unexpected exception prints, and the redacted crash log it leaves.

:func:`handle_crash` is called by the console script (:func:`opentide.cli.main`)
for an exception no command handled. It prints ``error[internal]: <Type>:
<message>``, the crash log's path and a pre-filled GitHub issue link on
stderr, the traceback too under ``--debug``, and returns exit code 1. In
``json`` mode stdout carries the one JSON document, with ``failure.code``
``internal`` and ``failure.crash_log``. In ``mcp`` mode stdout belongs to
JSON-RPC and is never written.

The crash log goes to the platform's state or log directory, never into the
repository. Everything written, on stderr, stdout or in the log, goes through
a :class:`Redactor` first: proxy and URL credentials, bearer tokens, values
of environment variables and configuration keys named like a secret, and the
tenant names and hosts of ``.opentide/configurations/platforms/*.toml``.

Standard library only (Rich, structlog and the output stack load lazily, if
at all), so a crash in any of them can still be reported.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import re
import shlex
import sys
import traceback
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlencode, urlsplit

from opentide.cli.ui.contract import INTERNAL, INTERRUPTED_EXIT_CODE, SCHEMA_VERSION, Failure
from opentide.cli.ui.mode import OutputMode, elapsed_ms, get_mode, json_indent

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

#: Exit code of a crash: the command failed.
CRASH_EXIT_CODE = 1

#: Crash logs kept in the log directory; older ones are deleted.
KEEP_CRASH_LOGS = 10

ISSUES_URL = "https://github.com/opentidehq/opentide/issues/new"

REDACTED = "***"

#: A name holding one of these (any case) names a secret: ``SPLUNK_TOKEN``,
#: ``client_secret``, ``api_key``, ``Authorization``, ``password``.
_SECRET_WORDS = ("token", "secret", "passw", "authorization", "credential", "cookie", "apikey")
#: ...and so does a name with a part that ends in ``key`` (``api_key``,
#: ``privateKey``), but not ``KeyError``.
_SECRET_SUFFIXES = ("key", "keys")
_SECRET_PARTS = frozenset({"pass", "auth"})

#: Configuration keys whose value identifies a tenant: its address, its ids,
#: the Azure resource group or the Splunk app it lives in.
_IDENTIFYING_WORDS = (
    "tenant",
    "url",
    "host",
    "domain",
    "workspace",
    "subscription",
    "endpoint",
    "group",
    "resource",
)
_IDENTIFYING_PARTS = frozenset(
    {
        "id",
        "org",
        "organization",
        "account",
        "server",
        "instance",
        "project",
        "client",
        "site",
        "app",
    }
)

_BOOLEAN_LITERALS = frozenset({"true", "false", "yes", "no", "on", "off", "none", "null"})
#: Shorter values are not searched for in free text: too many false matches.
_MIN_SECRET_LENGTH = 6
_MIN_IDENTIFIER_LENGTH = 3
#: A number this long is an id (a SentinelOne account id), not a port or a count.
_MIN_NUMERIC_LENGTH = 6

#: Environment variables a crash log lists (values redacted).
_LOGGED_ENV_PREFIXES = ("OPENTIDE_",)
_PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")

_URL_CREDENTIALS = re.compile(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]*://)[^\s/?#@]+@")
#: ``Authorization`` / ``Proxy-Authorization``, whatever the scheme (``Token``,
#: ``ApiKey``, ``ApiToken``, ``Splunk``, ...): everything up to the end of the
#: line, or the closing quote of a quoted value.
_AUTH_FIELD = re.compile(
    r"""(?i)(?P<key>\b(?:proxy-)?authorization)(?P<sep>["']?\s*[:=]\s*)"""
    r"""(?P<value>"[^"\n]*"|'[^'\n]*'|[^\n"']*)"""
)
#: A ``Bearer`` or ``Basic`` credential outside a header field.
_AUTH_SCHEME = re.compile(
    r"(?i)\b(?P<scheme>bearer\s+)[A-Za-z0-9\-._~+/]+=*|\b(?P<basic>basic\s+)[A-Za-z0-9+/]{8,}={0,2}"
)
_TOKEN_SHAPES = re.compile(
    r"\bgh[pousr]_[A-Za-z0-9]{20,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bglpat-[A-Za-z0-9_-]{20,}"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
#: ``key=value``, ``key: value``, ``"key": "value"``. The value is a lookahead,
#: so a key that names no secret (``https:`` in a URL, ``conn:``) consumes only
#: itself and a secret pair right after it is still found.
_ASSIGNMENT = re.compile(
    r"""(?P<key>[A-Za-z_][\w.-]*)(?P<sep>["']?\s*[:=]\s*)"""
    r"""(?=(?P<value>"[^"\n]*"|'[^'\n]*'|[^\s"',;&)}\]]+))"""
)
_ENV_REFERENCE = re.compile(r"^\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?$")


def is_secret_name(name: str) -> bool:
    """Whether a variable, option or key called *name* holds a secret."""
    lowered = name.lower()
    if any(word in lowered for word in _SECRET_WORDS):
        return True
    parts = [part for part in re.split(r"[^a-z0-9]+", lowered) if part]
    return any(part in _SECRET_PARTS or part.endswith(_SECRET_SUFFIXES) for part in parts)


#: Splunk apps every deployment has: they name no tenant, and ``search`` as a
#: whole word would blank every ``opentide.search`` in a traceback.
_BUILTIN_SPLUNK_APPS = frozenset({"search", "launcher", "splunkenterprisesecuritysuite"})
_BUILTIN_SPLUNK_APP_PREFIXES = ("sa-", "da-", "ta-", "splunk_")


def _is_builtin_splunk_app(key: str, value: str) -> bool:
    """Whether *value*, under an ``app`` key, is a built-in Splunk app (any case)."""
    if "app" not in re.split(r"[^a-z0-9]+", key.lower()):
        return False
    name = value.strip().lower()
    return name in _BUILTIN_SPLUNK_APPS or name.startswith(_BUILTIN_SPLUNK_APP_PREFIXES)


def _identifies_tenant(key: str) -> bool:
    lowered = key.lower()
    if any(word in lowered for word in _IDENTIFYING_WORDS):
        return True
    return any(part in _IDENTIFYING_PARTS for part in re.split(r"[^a-z0-9]+", lowered))


def _meaningful(value: str, minimum: int) -> bool:
    value = value.strip()
    if value.isdigit():
        return len(value) >= _MIN_NUMERIC_LENGTH
    return len(value) >= minimum and value.lower() not in _BOOLEAN_LITERALS and value != REDACTED


class Redactor:
    """Removes credentials and tenant identifiers from text.

    *secrets* are replaced wherever they occur; *identifiers* (tenant names,
    hosts, ids) only as whole words, so ``prod`` does not eat ``production``.
    Patterns catch the rest: URL credentials, ``Bearer``/``Basic`` values,
    well-known token shapes and ``key=value`` / ``"key": "value"`` pairs whose
    key names a secret.
    """

    def __init__(self, secrets: Iterable[str] = (), identifiers: Iterable[str] = ()) -> None:
        self.secrets = sorted(
            {value.strip() for value in secrets if _meaningful(value, _MIN_SECRET_LENGTH)},
            key=len,
            reverse=True,
        )
        self.identifiers = sorted(
            {value.strip() for value in identifiers if _meaningful(value, _MIN_IDENTIFIER_LENGTH)},
            key=len,
            reverse=True,
        )
        self._identifier_pattern = (
            re.compile(
                r"(?<![\w-])(?:"
                + "|".join(re.escape(value) for value in self.identifiers)
                + r")(?![\w-])"
            )
            if self.identifiers
            else None
        )

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, REDACTED)
        if self._identifier_pattern is not None:
            text = self._identifier_pattern.sub(REDACTED, text)
        text = _URL_CREDENTIALS.sub(rf"\g<scheme>{REDACTED}@", text)
        text = _AUTH_FIELD.sub(_redact_value, text)
        text = _AUTH_SCHEME.sub(_redact_auth_scheme, text)
        text = _TOKEN_SHAPES.sub(REDACTED, text)
        return _redact_assignments(text)

    def argv(self, argv: Sequence[str]) -> list[str]:
        """*argv* with the value of every option named like a secret replaced."""
        redacted: list[str] = []
        hide_next = False
        for token in argv:
            if hide_next:
                redacted.append(REDACTED)
                hide_next = False
                continue
            if token.startswith("-") and token != "--":
                name, separator, _ = token.partition("=")
                if is_secret_name(name.lstrip("-")):
                    if separator:
                        token = f"{name}={REDACTED}"
                    else:
                        hide_next = True
            redacted.append(self(token))
        return redacted


def _redact_auth_scheme(match: re.Match[str]) -> str:
    return (match["scheme"] or match["basic"]) + REDACTED


def _masked(value: str) -> str:
    quote = value[0] if value[:1] in ("'", '"') else ""
    return f"{quote}{REDACTED}{quote}"


def _redact_value(match: re.Match[str]) -> str:
    return f"{match['key']}{match['sep']}{_masked(match['value'])}"


def _redact_assignments(text: str) -> str:
    """Mask the value of every ``key=value`` pair whose key names a secret."""
    parts: list[str] = []
    position = 0
    for match in _ASSIGNMENT.finditer(text):
        # A pair inside a value already masked, or a key that is no secret.
        if match.start() < position or not is_secret_name(match["key"]):
            continue
        value = match["value"]
        parts += [text[position : match.end()], _masked(value)]
        position = match.end() + len(value)
    return "".join([*parts, text[position:]])


def _url_secrets(value: str) -> tuple[list[str], list[str]]:
    """The password, and the host, in a URL-shaped *value*."""
    if "://" not in value:
        return [], []
    try:
        parts = urlsplit(value.strip())
        host = parts.hostname
        password = parts.password
    except ValueError:
        return [], []
    return ([password] if password else []), ([host] if host else [])


def _expand(value: str, env: Mapping[str, str]) -> str:
    """A ``$NAME`` / ``${NAME}`` configuration value, read from *env*."""
    match = _ENV_REFERENCE.match(value.strip())
    return env.get(match["name"], "") if match else value


def _walk(
    node: object,
    env: Mapping[str, str],
    secrets: list[str],
    identifiers: list[str],
    *,
    tenant: bool,
) -> None:
    if isinstance(node, list):
        for item in node:
            _walk(item, env, secrets, identifiers, tenant=tenant)
        return
    if not isinstance(node, Mapping):
        return
    for key, value in node.items():
        key = str(key)
        if isinstance(value, (Mapping, list)):
            _walk(value, env, secrets, identifiers, tenant=tenant or key == "tenants")
            continue
        if isinstance(value, int) and not isinstance(value, bool):
            # ``account_id = 1234567890123456789``: _meaningful keeps long ones only.
            if tenant and _identifies_tenant(key):
                identifiers.append(str(value))
            continue
        if not isinstance(value, str):
            continue
        value = _expand(value, env)
        passwords, hosts = _url_secrets(value)
        secrets.extend(passwords)
        if is_secret_name(key):
            secrets.append(value)
        elif tenant and (key == "name" or _identifies_tenant(key)):
            if not _is_builtin_splunk_app(key, value):
                identifiers.append(value)
            identifiers.extend(hosts)


def workspace_redactor(
    workspaces: Iterable[Path] = (), *, env: Mapping[str, str] | None = None
) -> Redactor:
    """A :class:`Redactor` for this environment and these workspaces' platform tenants.

    Secrets are the values of environment variables named like a secret and
    the passwords of proxy URLs. Each workspace's
    ``.opentide/configurations/platforms/*.toml`` (and the older ``systems/``)
    adds its secret values and, for every ``[[tenants]]`` entry, its name and
    the values of its address and id keys, ``$VARIABLE`` references resolved.
    ``.opentide/configurations/sharing.toml`` does the same for every sharing
    destination (a MISP block's name, URL and API key).
    """
    env = os.environ if env is None else env
    secrets: list[str] = []
    identifiers: list[str] = []
    for name, value in env.items():
        passwords, _ = _url_secrets(value)
        secrets.extend(passwords)
        if is_secret_name(name):
            secrets.append(value)
    seen: set[Path] = set()
    for workspace in workspaces:
        configurations = workspace / ".opentide" / "configurations"
        # (file, whether every block in it is a destination like a tenant)
        files: list[tuple[Path, bool]] = [(configurations / "sharing.toml", True)]
        for folder in ("platforms", "systems"):
            try:
                files += [
                    (path, False) for path in sorted((configurations / folder).glob("*.toml"))
                ]
            except OSError:
                continue
        for path, destinations in files:
            try:
                resolved = path.resolve()
                if resolved in seen or not path.is_file():
                    continue
                seen.add(resolved)
                document = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                continue
            _walk(document, env, secrets, identifiers, tenant=destinations)
    return Redactor(secrets, identifiers)


def crash_log_dir(
    *,
    env: Mapping[str, str] | None = None,
    platform_name: str | None = None,
    home: Path | None = None,
) -> Path:
    """Where crash logs go: the platform's per-user state or log directory.

    ``$XDG_STATE_HOME/opentide`` (``~/.local/state/opentide`` when unset or
    not absolute) on Linux and other Unix systems, ``~/Library/Logs/opentide``
    on macOS, ``%LOCALAPPDATA%\\opentide\\logs`` on Windows.
    """
    env = os.environ if env is None else env
    platform_name = sys.platform if platform_name is None else platform_name
    home = Path.home() if home is None else home
    if platform_name == "win32":
        local = env.get("LOCALAPPDATA", "")
        base = Path(local) if local else home / "AppData" / "Local"
        directory = base / "opentide" / "logs"
    elif platform_name == "darwin":
        directory = home / "Library" / "Logs" / "opentide"
    else:
        state = env.get("XDG_STATE_HOME", "")
        base = Path(state) if state and Path(state).is_absolute() else home / ".local" / "state"
        directory = base / "opentide"
    if not directory.is_absolute():
        # No home directory: "~" stays as it is, and a relative path would put
        # the log under the current directory, the repository more often than not.
        raise RuntimeError("no home directory to keep crash logs in")
    return directory


def write_crash_log(
    text: str,
    directory: Path,
    *,
    keep: int = KEEP_CRASH_LOGS,
    now: datetime | None = None,
) -> Path:
    """Write *text* to a new ``crash-<time>-<pid>.log`` in *directory*; keep the last *keep*.

    The directory is created private (0700) and each log is 0600.
    """
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        directory.chmod(0o700)
    now = now or datetime.now(timezone.utc)
    path = directory / f"crash-{now:%Y%m%dT%H%M%S%f}Z-{os.getpid()}.log"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    # The names sort by time: the stamp has a fixed width.
    for old in sorted(directory.glob("crash-*.log"))[:-keep]:
        with contextlib.suppress(OSError):
            old.unlink()
    return path


def _version() -> str:
    try:
        from opentide import __version__
    except Exception:
        return "unknown"
    return __version__


def system_facts() -> dict[str, str]:
    """The opentide version, Python and OS that go into an issue."""
    return {
        "opentide": _version(),
        "python": f"{platform.python_version()} ({platform.python_implementation()})",
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }


def issue_url(command: str, facts: Mapping[str, str] | None = None) -> str:
    """A new-issue link pre-filled with the version, Python, OS and command path.

    Never argument values or paths: *command* is the command path alone
    (``validate query``). The link stays well under GitHub's length limits.
    """
    facts = facts or system_facts()
    shown = f"opentide {command}".strip()[:120]
    body = "\n".join(
        [
            "### What happened",
            "",
            "<!-- What you ran and what you expected. -->",
            "",
            "### Environment",
            "",
            f"- opentide: {facts['opentide']}",
            f"- Python: {facts['python']}",
            f"- OS: {facts['os']}",
            f"- Command: `{shown}`",
            "",
            "### Crash log",
            "",
            "<!-- Attach the crash log opentide printed. Credentials, tokens and "
            "tenant names are redacted; read it before you attach it. -->",
        ]
    )
    return f"{ISSUES_URL}?{urlencode({'title': f'Crash in {shown}', 'body': body})}"


def _active_context() -> Any:
    """The running command's ``CliContext``, if the root callback got that far."""
    try:
        from opentide.cli.context import _cli_context
    except Exception:
        return None
    return _cli_context.get()


def _workspaces(context: Any, env: Mapping[str, str]) -> list[Path]:
    candidates: list[Path] = []
    repo = getattr(context, "repo", None)
    if isinstance(repo, Path):
        candidates.append(repo)
    for name in ("OPENTIDE_TIDE_WORKSPACE", "OPENTIDE_REPO_ROOT"):
        if env.get(name):
            candidates.append(Path(env[name]))
    with contextlib.suppress(OSError):
        candidates.append(Path.cwd())
    return candidates


def _debug_requested(options: Sequence[str], context: Any, env: Mapping[str, str]) -> bool:
    if context is not None and getattr(context, "debug", False):
        return True
    if "--debug" in options:
        return True
    try:
        from opentide.core.runtime import debug_requested
    except Exception:
        return False
    return debug_requested(env)


def _crash_mode(options: Sequence[str], words: Sequence[str]) -> OutputMode:
    """The mode to report in, from the raw command line first.

    ``get_mode()`` knows about ``mcp start`` only once ``LazyTyperGroup.main``
    has run; a crash before that (importing the root app) must still leave
    the JSON-RPC stdout alone, whatever ``--json`` or ``OPENTIDE_OUTPUT`` say.
    """
    if tuple(words[:2]) == ("mcp", "start"):
        return OutputMode.MCP
    mode = get_mode()
    if "--json" in options and mode is not OutputMode.MCP:
        return OutputMode.JSON
    return mode


def crash_log_text(
    error: BaseException,
    *,
    argv: Sequence[str],
    command: str,
    mode: OutputMode,
    env: Mapping[str, str],
    redactor: Redactor,
    facts: Mapping[str, str],
) -> str:
    """The crash log: what ran, where, the relevant environment, and the traceback."""
    variables = sorted(
        name
        for name in env
        if name.startswith(_LOGGED_ENV_PREFIXES) or name.upper() in _PROXY_VARIABLES
    )
    lines = [
        "opentide crash log",
        "",
        f"time: {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
        f"opentide: {facts['opentide']}",
        f"python: {facts['python']}",
        f"os: {facts['os']}",
        f"command: {f'opentide {command}'.strip()}",
        f"arguments: {shlex.join(redactor.argv(argv))}",
        f"output mode: {mode.value}",
        "",
        "environment:",
        *(f"  {name}={REDACTED if is_secret_name(name) else env[name]}" for name in variables),
        "",
        "".join(traceback.format_exception(type(error), error, error.__traceback__)).rstrip(),
        "",
    ]
    return redactor("\n".join(lines))


def _is_terminal(stream: TextIO | None) -> bool:
    try:
        return stream is not None and stream.isatty()
    except (AttributeError, ValueError):
        return False


def _write(stream: TextIO | None, text: str) -> None:
    if stream is None:
        return
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass


def _summary(error: BaseException) -> str:
    name = type(error).__name__
    try:
        message = str(error).strip().splitlines()
    except Exception:
        return f"{name}: (its message could not be read)"
    return f"{name}: {message[0]}" if message else name


def handle_crash(
    error: BaseException,
    *,
    argv: Sequence[str],
    command: str = "",
    words: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
    log_dir: Path | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Report *error*, which no command handled, and return the exit code (1).

    *argv* is the command line without the program name; *command* the
    command path it named (``generate docs rules``), which alone goes into
    the issue link; *words* the leading words of *argv* read without Typer,
    for a crash before the command could be resolved.
    """
    env = os.environ if env is None else env
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    # Until the message is redacted, the type is all that may be printed.
    summary = type(error).__name__
    try:
        options = list(argv[: list(argv).index("--")] if "--" in argv else argv)
        context = _active_context()
        debug = _debug_requested(options, context, env)
        mode = _crash_mode(options, words or command.split())
        redactor = workspace_redactor(_workspaces(context, env), env=env)
        if context is not None and getattr(context, "proxy", None):
            passwords, _ = _url_secrets(str(context.proxy))
            redactor = Redactor([*redactor.secrets, *passwords], redactor.identifiers)
        summary = redactor(_summary(error))
        facts = system_facts()
        log_path: Path | None = None
        log_problem = ""
        try:
            text = crash_log_text(
                error,
                argv=argv,
                command=command,
                mode=mode,
                env=env,
                redactor=redactor,
                facts=facts,
            )
            log_path = write_crash_log(text, log_dir or crash_log_dir(env=env))
        except Exception as problem:
            # Still report the error, and in json mode still print the document.
            log_problem = f"{type(problem).__name__}: {problem}"

        if debug:
            trace = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            _write(err, redactor(trace))
        lines = [f"error[{INTERNAL}]: {summary}"]
        if log_path is not None:
            lines.append(
                f"  note: crash log, with credentials and tenant names redacted: {log_path}"
            )
        else:
            lines.append(f"  note: no crash log written: {redactor(log_problem)}")
        link = issue_url(command, facts)
        links = env.get("OPENTIDE_LINKS", "").strip().lower() != "none"
        if mode is OutputMode.HUMAN and links and _is_terminal(err):
            # The pre-filled link is about 800 characters, 8 rows at 100
            # columns: a person at a terminal clicks the short text instead.
            link = f"\x1b]8;;{link}\x1b\\{ISSUES_URL}\x1b]8;;\x1b\\"
        lines.append(f"  help: this is a bug in opentide; report it: {link}")
        if not debug:
            lines.append("  help: add --debug to see the traceback")
        _write(err, "\n".join(lines) + "\n")

        if mode is OutputMode.JSON:
            failure = Failure(
                code=INTERNAL,
                message=summary,
                crash_log=None if log_path is None else str(log_path),
            )
            _write(out, _json_text(_document(summary, failure, command)))
    except Exception:
        # Reporting must not crash in turn; say the least that is still true.
        _write(err, f"error[{INTERNAL}]: {summary}\n")
    return CRASH_EXIT_CODE


def _json_text(document: Mapping[str, Any]) -> str:
    """*document* as every other ``--json`` run prints it: compact in a pipe, one newline."""
    try:
        from opentide.cli.output import document_text
    except Exception:
        # The output stack itself may be what failed to import.
        indent = 2 if json_indent() else None
        return json.dumps(document, indent=indent, ensure_ascii=False, default=str) + "\n"
    return document_text(document)


def _document(summary: str, failure: Failure, command: str) -> dict[str, Any]:
    payload = {"error": summary, "ok": False, "status": "failed", "message": summary}
    try:
        from opentide.cli.output import envelope
    except Exception:
        # The output stack itself may be what failed to import.
        return {
            **payload,
            "schema_version": SCHEMA_VERSION,
            "command": command,
            "duration_ms": elapsed_ms(),
            "exit_code": CRASH_EXIT_CODE,
            "summary": {},
            "next_actions": [],
            "failure": failure.to_dict(),
        }
    return envelope(payload, exit_code=CRASH_EXIT_CODE, failure=failure, command=command)


def report_interrupt(stderr: TextIO | None = None) -> int:
    """One line for Ctrl-C, no traceback; returns exit code 130."""
    _write(sys.stderr if stderr is None else stderr, "error: interrupted\n")
    return INTERRUPTED_EXIT_CODE
