"""Unexpected exceptions: ``error[internal]``, a redacted crash log and an issue link."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import typer

import opentide.cli as cli_package
from opentide.cli.lazy import command_words
from opentide.cli.root import app
from opentide.cli.ui.contract import INTERNAL
from opentide.cli.ui.crash import (
    KEEP_CRASH_LOGS,
    REDACTED,
    Redactor,
    crash_log_dir,
    handle_crash,
    is_secret_name,
    issue_url,
    workspace_redactor,
    write_crash_log,
)
from opentide.cli.ui.mode import OutputMode

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

FACTS = {"opentide": "1.2.3", "python": "3.12.1 (CPython)", "os": "Linux 6.1 (x86_64)"}

PLATFORM_TOML = """\
[platform]
enabled = true
identifier = "elastic"

[[tenants]]
name = "acme-prod"
description = "Production cluster"
[tenants.setup]
ssl = true
url = "https://kibana.acme-soc.example:5601"
space = "staging"
api_key = "$ELASTIC_PROD_API_KEY"
workspace_id = "3f2c9a71-0000-4000-8000-0000000000aa"
"""


def _plain(text: str) -> str:
    return _ANSI.sub("", text)


@pytest.fixture
def state_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point every platform's log location into *tmp_path*; return the one in use."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    return crash_log_dir()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    platforms = root / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "elastic.toml").write_text(PLATFORM_TOML, encoding="utf-8")
    (root / "objects").mkdir()
    return root


def _crash_in_info(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    """Make ``opentide info`` raise *error* from inside the command."""

    def explode(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr("opentide.cli.services.info.collect_info", explode)


def _run_main(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["opentide", *argv])
    with pytest.raises(SystemExit) as raised:
        cli_package.main()
    code = raised.value.code
    return code if isinstance(code, int) else (0 if code is None else 1)


def _logs(directory: Path) -> list[Path]:
    return sorted(directory.glob("crash-*.log")) if directory.is_dir() else []


# Redaction


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("SPLUNK_TOKEN", True),
        ("client_secret", True),
        ("azure_client_secret", True),
        ("api_key", True),
        ("ELASTIC_PROD_API_KEY", True),
        ("privateKey", True),
        ("Authorization", True),
        ("password", True),
        ("MISP_PASSWD", True),
        ("KeyError", False),
        ("PWD", False),
        ("url", False),
        ("workspace_id", False),
    ],
)
def test_secret_names(name: str, secret: bool) -> None:
    assert is_secret_name(name) is secret


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        ("proxy http://alice:hunter22@proxy.corp:8080 refused", "alice:hunter22"),
        ("https://ghuser@github.com/org/repo.git", "ghuser"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payloadpart.signaturepart", "eyJhbG"),
        ("headers={'Authorization': 'Bearer abcdef123456'}", "abcdef123456"),
        ("POST /api?token=s3cr3tvalue&x=1", "s3cr3tvalue"),
        ('{"client_secret": "very-secret-value"}', "very-secret-value"),
        ("api_key = 'k-1234567890'", "k-1234567890"),
        ("password=hunter2", "hunter2"),
        ("pushed with ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdef"),
    ],
)
def test_redactor_patterns(text: str, leaked: str) -> None:
    redacted = Redactor()(text)
    assert leaked not in redacted
    assert REDACTED in redacted


def test_proxy_credentials_keep_scheme_and_host() -> None:
    assert (
        Redactor()("via http://user:pass@proxy.corp:3128 failed")
        == "via http://***@proxy.corp:3128 failed"
    )


def test_redactor_leaves_ordinary_text_alone() -> None:
    text = "KeyError: 'name'\n  File \"/src/opentide/core/files.py\", line 12, in load"
    assert Redactor()(text) == text


def test_environment_secret_values_are_redacted_anywhere(tmp_path: Path) -> None:
    env = {"SPLUNK_TOKEN": "tok-9f8e7d6c5b", "TOKENIZERS_PARALLELISM": "false", "PWD": "/work"}
    redactor = workspace_redactor([tmp_path], env=env)
    redacted = redactor("splunk rejected tok-9f8e7d6c5b at /work: false")
    assert "tok-9f8e7d6c5b" not in redacted
    # Booleans and ordinary variables are not secrets, wherever they appear.
    assert "/work" in redacted
    assert redacted.endswith("false")


def test_tenant_identifiers_and_secrets_from_platform_configuration(workspace: Path) -> None:
    env = {"ELASTIC_PROD_API_KEY": "ZWxhc3RpYy1wcm9kLWtleQ=="}
    redactor = workspace_redactor([workspace], env=env)
    text = (
        "tenant acme-prod: GET https://kibana.acme-soc.example:5601/api failed "
        "(kibana.acme-soc.example) with ApiKey ZWxhc3RpYy1wcm9kLWtleQ== "
        "for 3f2c9a71-0000-4000-8000-0000000000aa in space staging; acme-production is another"
    )
    redacted = redactor(text)
    for leaked in (
        "acme-prod:",
        "kibana.acme-soc.example",
        "ZWxhc3RpYy1wcm9kLWtleQ==",
        "3f2c9a71-0000-4000-8000-0000000000aa",
    ):
        assert leaked not in redacted
    # Whole words only, and keys that do not identify a tenant are kept.
    assert "acme-production" in redacted
    assert "space staging" in redacted


def test_unreadable_platform_configuration_is_skipped(tmp_path: Path) -> None:
    platforms = tmp_path / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "broken.toml").write_text("[[tenants]\nname = ", encoding="utf-8")
    assert workspace_redactor([tmp_path], env={})("plain text") == "plain text"


def test_secret_option_values_are_redacted_in_argv() -> None:
    argv = ["--proxy", "http://u:p@proxy:8080", "share", "push", "--api-key", "abc", "--token=xyz"]
    assert Redactor().argv(argv) == [
        "--proxy",
        "http://***@proxy:8080",
        "share",
        "push",
        "--api-key",
        REDACTED,
        f"--token={REDACTED}",
    ]


# Location


def test_log_dir_linux_follows_xdg_state_home(tmp_path: Path) -> None:
    env = {"XDG_STATE_HOME": str(tmp_path / "state")}
    assert crash_log_dir(env=env, platform_name="linux", home=tmp_path) == (
        tmp_path / "state" / "opentide"
    )


@pytest.mark.parametrize("value", ["", "relative/state"])
def test_log_dir_linux_default_when_xdg_unset_or_relative(tmp_path: Path, value: str) -> None:
    env = {"XDG_STATE_HOME": value} if value else {}
    assert crash_log_dir(env=env, platform_name="linux", home=tmp_path) == (
        tmp_path / ".local" / "state" / "opentide"
    )


def test_log_dir_macos(tmp_path: Path) -> None:
    env = {"XDG_STATE_HOME": str(tmp_path / "state")}
    assert crash_log_dir(env=env, platform_name="darwin", home=tmp_path) == (
        tmp_path / "Library" / "Logs" / "opentide"
    )


def test_log_dir_windows(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path / "Local")}
    assert crash_log_dir(env=env, platform_name="win32", home=tmp_path) == (
        tmp_path / "Local" / "opentide" / "logs"
    )
    assert crash_log_dir(env={}, platform_name="win32", home=tmp_path) == (
        tmp_path / "AppData" / "Local" / "opentide" / "logs"
    )


def test_log_dir_is_never_relative() -> None:
    """With no home directory, ``~`` stays as it is: never write under the current directory."""
    with pytest.raises(RuntimeError, match="no home directory"):
        crash_log_dir(env={}, platform_name="linux", home=Path("~"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_log_dir_and_log_are_private(tmp_path: Path) -> None:
    directory = tmp_path / "state" / "opentide"
    path = write_crash_log("log", directory)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8") == "log"


def test_only_the_last_logs_are_kept(tmp_path: Path) -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    written = [
        write_crash_log(f"log {index}", tmp_path, now=start + timedelta(seconds=index))
        for index in range(KEEP_CRASH_LOGS + 3)
    ]
    assert _logs(tmp_path) == written[-KEEP_CRASH_LOGS:]


# Issue link


def test_issue_url_carries_only_version_python_os_and_command() -> None:
    url = issue_url("generate docs rules", FACTS)
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == (
        "https://github.com/opentidehq/opentide/issues/new"
    )
    query = parse_qs(parts.query)
    assert set(query) == {"title", "body"}
    assert query["title"] == ["Crash in opentide generate docs rules"]
    body = query["body"][0]
    for fact in (
        "1.2.3",
        "3.12.1 (CPython)",
        "Linux 6.1 (x86_64)",
        "`opentide generate docs rules`",
    ):
        assert fact in body
    assert "/" not in body.replace("`opentide generate docs rules`", "")
    # GitHub rejects new-issue links past about 8 KB.
    assert len(url) < 2000


def test_issue_url_caps_a_long_command_path() -> None:
    assert len(issue_url("word " * 500, FACTS)) < 2000


# The handler


def test_handle_crash_survives_an_unwritable_log_dir(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    out, err = _Capture(), _Capture()
    code = handle_crash(
        ValueError("boom"), argv=["info"], command="info", log_dir=blocker / "logs",
        env={}, stdout=out, stderr=err,
    )  # fmt: skip
    assert code == 1
    assert out.getvalue() == ""
    assert err.getvalue().startswith("error[internal]: ValueError: boom\n")
    assert "no crash log written" in err.getvalue()


@pytest.mark.parametrize(
    ("mode", "terminal", "short"),
    [
        (OutputMode.HUMAN, True, True),
        (OutputMode.HUMAN, False, False),
        (OutputMode.PLAIN, True, False),
        (OutputMode.AGENT, True, False),
    ],
)
def test_a_person_at_a_terminal_gets_a_short_issue_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: OutputMode, terminal: bool, short: bool
) -> None:
    """The pre-filled link was about 800 characters, 8 rows of the terminal
    (post-merge end-to-end run). Elsewhere it stays whole, to copy or open."""
    monkeypatch.setattr("opentide.cli.ui.crash.get_mode", lambda: mode)
    out, err = _Capture(), _Capture(terminal=terminal)
    handle_crash(
        ValueError("boom"), argv=["info"], command="info", log_dir=tmp_path / "logs",
        env={}, stdout=out, stderr=err,
    )  # fmt: skip
    (line,) = [text for text in err.getvalue().splitlines() if "report it:" in text]
    full = issue_url("info")
    if short:
        assert line.endswith(
            f"\x1b]8;;{full}\x1b\\https://github.com/opentidehq/opentide/issues/new\x1b]8;;\x1b\\"
        )
        assert len(line) - len(full) < 160
    else:
        assert line.endswith(f"report it: {full}")


class _Capture:
    def __init__(self, *, terminal: bool = False) -> None:
        self.parts: list[str] = []
        self.terminal = terminal

    def isatty(self) -> bool:
        return self.terminal

    def write(self, text: str) -> int:
        self.parts.append(text)
        return len(text)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return "".join(self.parts)


def test_crash_in_a_command_reports_on_stderr_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, RuntimeError("index exploded"))
    assert _run_main(monkeypatch, "--no-color", "info") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    err = _plain(captured.err)
    assert err.startswith("error[internal]: RuntimeError: index exploded\n")
    assert "Traceback" not in err
    assert "add --debug to see the traceback" in err
    [log] = _logs(state_dirs)
    assert str(log) in err
    issue = re.search(r"https://github\.com/\S+", err)
    assert issue is not None
    assert parse_qs(urlsplit(issue[0]).query)["title"] == ["Crash in opentide info"]
    text = log.read_text(encoding="utf-8")
    assert "command: opentide info" in text
    assert "Traceback (most recent call last):" in text
    assert "RuntimeError: index exploded" in text


def test_debug_prints_the_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, RuntimeError("index exploded"))
    assert _run_main(monkeypatch, "--no-color", "info", "--debug") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    err = _plain(captured.err)
    assert "Traceback (most recent call last):" in err
    assert "in explode" in err
    # The error line comes last, under the traceback, where it is read.
    assert err.index("Traceback") < err.index("error[internal]: RuntimeError: index exploded")
    assert "add --debug" not in err


def test_json_mode_prints_one_document_with_the_crash_log(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, RuntimeError("index exploded"))
    assert _run_main(monkeypatch, "info", "--json") == 1
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["ok"] is False
    assert document["status"] == "failed"
    assert document["exit_code"] == 1
    assert document["command"] == "info"
    assert document["error"] == "RuntimeError: index exploded"
    failure = document["failure"]
    assert failure["code"] == INTERNAL
    assert failure["message"] == "RuntimeError: index exploded"
    [log] = _logs(state_dirs)
    assert failure["crash_log"] == str(log)
    # The person reading the terminal still gets the message, on stderr.
    assert "error[internal]: RuntimeError: index exploded" in _plain(captured.err)


def test_crash_output_and_log_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state_dirs: Path,
    workspace: Path,
) -> None:
    monkeypatch.setenv("ELASTIC_PROD_API_KEY", "ZWxhc3RpYy1wcm9kLWtleQ==")
    monkeypatch.setenv("OPENTIDE_SHARE_TOKEN", "share-token-123456")
    _crash_in_info(
        monkeypatch,
        ConnectionError(
            "acme-prod at https://kibana.acme-soc.example:5601 via "
            "http://bob:hunter22@proxy.corp:3128 refused key ZWxhc3RpYy1wcm9kLWtleQ== "
            "and share-token-123456; Authorization: Bearer abcdefghijkl"
        ),
    )
    code = _run_main(
        monkeypatch,
        "--repo", str(workspace),
        "--proxy", "http://bob:hunter22@proxy.corp:3128",
        "--json", "info", "--debug",
    )  # fmt: skip
    assert code == 1
    captured = capsys.readouterr()
    [log] = _logs(state_dirs)
    for text in (captured.out, captured.err, log.read_text(encoding="utf-8")):
        for leaked in (
            "hunter22",
            "bob:",
            "acme-prod",
            "kibana.acme-soc.example",
            "ZWxhc3RpYy1wcm9kLWtleQ==",
            "share-token-123456",
            "abcdefghijkl",
        ):
            assert leaked not in text, (leaked, text)
    assert "http://***@proxy.corp:3128" in log.read_text(encoding="utf-8")
    assert "OPENTIDE_SHARE_TOKEN=***" in log.read_text(encoding="utf-8")


def test_mcp_mode_never_writes_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    import opentide.mcp_server.launcher as launcher

    def explode() -> None:
        raise RuntimeError("transport failed")

    monkeypatch.setattr(launcher, "main", explode)
    assert _run_main(monkeypatch, "mcp", "start") == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error[internal]: RuntimeError: transport failed" in _plain(captured.err)
    assert len(_logs(state_dirs)) == 1


def test_ctrl_c_in_a_command_exits_130_with_one_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, KeyboardInterrupt())
    assert _run_main(monkeypatch, "--no-color", "info") == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _plain(captured.err) == "error: interrupted\n"
    assert _logs(state_dirs) == []


def test_ctrl_c_while_loading_exits_130_with_one_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    import opentide.cli.context as context_module

    def interrupted(*, no_color: bool) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(context_module, "sync_typer_rendering", interrupted)
    assert _run_main(monkeypatch, "info") == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: interrupted\n"
    assert _logs(state_dirs) == []


@pytest.mark.parametrize(
    ("raised", "expected"),
    [(SystemExit(4), 4), (typer.Exit(3), 3)],
)
def test_exits_are_not_crashes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state_dirs: Path,
    raised: BaseException,
    expected: int,
) -> None:
    _crash_in_info(monkeypatch, raised)
    assert _run_main(monkeypatch, "--no-color", "info") == expected
    assert "error[internal]" not in capsys.readouterr().err
    assert _logs(state_dirs) == []


def test_usage_errors_are_not_crashes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    assert _run_main(monkeypatch, "--json", "valdate") == 2
    document = json.loads(capsys.readouterr().out)
    assert document["failure"]["code"] == "usage_unknown_command"
    assert document["failure"]["crash_log"] is None
    assert _logs(state_dirs) == []


def test_click_exceptions_from_a_command_are_not_crashes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    from typer import _click

    _crash_in_info(monkeypatch, _click.exceptions.FileError("x.yaml", hint="missing"))
    assert _run_main(monkeypatch, "--no-color", "info") == 1
    assert "error[internal]" not in capsys.readouterr().err
    assert _logs(state_dirs) == []


def test_crash_in_a_console_script_process(tmp_path: Path) -> None:
    """A real process: stdout holds the JSON document alone, stderr the message."""
    script = textwrap.dedent(
        """
        import sys
        import opentide.cli.services.info as info_service

        def explode(*args, **kwargs):
            raise RuntimeError("index exploded")

        info_service.collect_info = explode
        from opentide.cli import main
        sys.argv = ["opentide", "--json", "info"]
        main()
        """
    )
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "LOCALAPPDATA": str(tmp_path / "local"),
    }
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert done.returncode == 1, done.stderr
    document = json.loads(done.stdout)
    assert document["failure"]["code"] == INTERNAL
    assert Path(document["failure"]["crash_log"]).is_file()
    assert "error[internal]: RuntimeError: index exploded" in _plain(done.stderr)
    assert "Traceback" not in done.stderr


# The command path


@pytest.mark.parametrize(
    ("argv", "words"),
    [
        (["generate", "docs", "rules", "--json"], ("generate", "docs", "rules")),
        (["--repo", "/tmp/x", "validate", "query", "--platform", "splunk"], ("validate", "query")),
        (["validate", "--json", "query"], ("validate", "query")),
        (["info", "rules"], ("info",)),
        (["--json"], ()),
        (["nosuchcommand", "secret-value"], ()),
    ],
)
def test_command_words_name_commands_never_values(argv: list[str], words: tuple[str, ...]) -> None:
    assert command_words(typer.main.get_command(app), argv) == words


@pytest.mark.parametrize(
    ("argv", "words"),
    [
        (["--json", "mcp", "start"], ("mcp", "start")),
        (["mcp", "--json", "start"], ("mcp", "start")),
        (["--repo", "/x", "--proxy=http://p", "mcp", "start", "extra"], ("mcp", "start")),
        (["validate", "--type", "rule"], ("validate",)),
        (["--", "mcp", "start"], ()),
    ],
)
def test_raw_command_words_need_no_typer(argv: list[str], words: tuple[str, ...]) -> None:
    assert cli_package._raw_command_words(argv) == words


# Combined strings, every Authorization scheme


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # requests' HTTPError text: the URL's ``https:`` must not hide the query token.
        (
            "401 Client Error: Unauthorized for url: "
            "https://splunk.example:8089/services/search?token=abcd1234secret&output_mode=json",
            "401 Client Error: Unauthorized for url: "
            "https://splunk.example:8089/services/search?token=***&output_mode=json",
        ),
        (
            "GET https://api.example/v1?api_key=abcd1234secret failed",
            "GET https://api.example/v1?api_key=*** failed",
        ),
        ("conn: password=abcd1234secret", "conn: password=***"),
        ("host:443 password=abcd1234secret", "host:443 password=***"),
        (
            "mode=fast, token=abcd1234secret; user: bob secret: 's3cr3t value'",
            "mode=fast, token=***; user: bob secret: '***'",
        ),
        (
            "proxy http://bob:pw@proxy:3128 then https://h/x?sig=1&access_token=zzz9 KeyError: x",
            "proxy http://***@proxy:3128 then https://h/x?sig=1&access_token=*** KeyError: x",
        ),
    ],
)
def test_secret_pairs_after_other_pairs_are_redacted(text: str, expected: str) -> None:
    assert Redactor()(text) == expected


def test_secret_url_query_in_argv_is_redacted() -> None:
    argv = ["validate", "--technique", "https://h/x?token=SECRETVALUE&page=2"]
    assert Redactor().argv(argv) == ["validate", "--technique", "https://h/x?token=***&page=2"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Token hlab1234key", "Authorization: ***"),
        ("Authorization: ApiKey abcd1234secret==", "Authorization: ***"),
        ("Authorization: ApiToken s1tok3nvalue99", "Authorization: ***"),
        ("Authorization: Splunk 0f0e0d0c-aaaa", "Authorization: ***"),
        ("Authorization: Bearer eyJabc.def.ghi", "Authorization: ***"),
        ("Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: ***"),
        ("authorization=Digest username=bob, response=6629fae4", "authorization=***"),
        (
            "{'Authorization': 'ApiToken s1tok3nvalue99', 'Accept': 'json'}",
            "{'Authorization': '***', 'Accept': 'json'}",
        ),
        ('{"Authorization": "Token hlab1234key", "x": 1}', '{"Authorization": "***", "x": 1}'),
        (
            "X-Request-Id: 1\nAuthorization: ApiKey k3y==\nHost: h",
            "X-Request-Id: 1\nAuthorization: ***\nHost: h",
        ),
    ],
)
def test_every_authorization_scheme_is_redacted(text: str, expected: str) -> None:
    assert Redactor()(text) == expected


# Tenants from the shipped templates

_SHIPPED_PLATFORMS = Path(cli_package.__file__).parents[1] / "data" / "configurations" / "platforms"


def _enable_tenants(template: str, values: dict[str, str]) -> str:
    """A shipped platform template with its sample tenant uncommented and filled in."""
    lines: list[str] = []
    active = False
    for line in template.splitlines():
        if re.match(r"^# ?\[\[tenants\]\]", line):
            active = True
        elif active and not line.strip():
            active = False
        if active:
            line = re.sub(r"^# ?", "", line)
            key = line.split("=", 1)[0].strip()
            if key in values:
                line = f"{key} = {values[key]}"
        lines.append(line)
    return "\n".join(lines) + "\n"


_TEMPLATE_ENV = {
    "AZURE_WORKSPACE_ID": "6f1d2c3b-1111-4222-8333-944455556666",
    "AZURE_TENANT_ID": "0a1b2c3d-1111-4222-8333-944455556667",
    "AZURE_SUBSCRIPTION_ID": "9e8d7c6b-1111-4222-8333-944455556668",
    "AZURE_CLIENT_ID": "1f2e3d4c-1111-4222-8333-944455556669",
    "AZURE_CLIENT_SECRET": "azure-client-secret-value",
    "SENTINEL_ONE_API_TOKEN": "s1-api-token-value",
    "SPLUNK_URL": "https://splunk.acme.example",
    "SPLUNK_TOKEN": "splunk-token-value",
    "SPLUNK_APP": "acme_detections",
    "MISP_INTERNAL_API_KEY": "misp-api-key-value",
}


@pytest.fixture
def template_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Sentinel, SentinelOne and Splunk tenants from the shipped templates, and a MISP block."""
    root = tmp_path / "templated"
    platforms = root / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (root / "objects").mkdir()
    filled = {
        "sentinel": {
            "name": '"acme-sentinel-prod"',
            "resource_group": '"rg-acme-soc-prod"',
            "workspace_name": '"acmesocws"',
        },
        "sentinel_one": {
            "name": '"acme-s1-eu"',
            "url": '"https://acme-eu.sentinelone.example"',
            "account_id": "1234567890123456789",
        },
        "splunk": {"name": '"acme-splunk"'},
    }
    for platform, values in filled.items():
        template = (_SHIPPED_PLATFORMS / f"{platform}.toml").read_text(encoding="utf-8")
        (platforms / f"{platform}.toml").write_text(
            _enable_tenants(template, values), encoding="utf-8"
        )
    (root / ".opentide" / "configurations" / "sharing.toml").write_text(
        "[[misp]]\n"
        'name = "misp-internal"\n'
        "enabled = true\n"
        'url = "https://misp.internal.example.org"\n'
        'api_key = "${MISP_INTERNAL_API_KEY}"\n',
        encoding="utf-8",
    )
    for name, value in _TEMPLATE_ENV.items():
        monkeypatch.setenv(name, value)
    return root


_TEMPLATE_LEAKS = (
    "rg-acme-soc-prod",
    "acmesocws",
    "acme-sentinel-prod",
    "acme-s1-eu",
    "acme-eu.sentinelone.example",
    "1234567890123456789",
    "acme-splunk",
    "splunk.acme.example",
    "acme_detections",
    "misp-internal",
    "misp.internal.example.org",
    *_TEMPLATE_ENV.values(),
)


def _template_crash_text() -> str:
    env = _TEMPLATE_ENV
    return (
        f"/subscriptions/{env['AZURE_SUBSCRIPTION_ID']}/resourceGroups/rg-acme-soc-prod"
        f"/providers/Microsoft.OperationalInsights/workspaces/acmesocws tenant "
        f"{env['AZURE_TENANT_ID']} client {env['AZURE_CLIENT_ID']} workspace "
        f"{env['AZURE_WORKSPACE_ID']} secret {env['AZURE_CLIENT_SECRET']}; "
        "acme-sentinel-prod failed; S1 account 1234567890123456789 at "
        "https://acme-eu.sentinelone.example (acme-s1-eu) with s1-api-token-value; "
        "acme-splunk https://splunk.acme.example:8089/servicesNS/nobody/acme_detections "
        "splunk-token-value; MISP misp-internal https://misp.internal.example.org/events "
        "key misp-api-key-value; port 8089 and count 42 stay"
    )


def test_tenant_identifiers_from_the_shipped_templates_are_redacted(
    template_workspace: Path,
) -> None:
    redacted = workspace_redactor([template_workspace])(_template_crash_text())
    for leaked in _TEMPLATE_LEAKS:
        assert leaked not in redacted, (leaked, redacted)
    # Short numbers are ports and counts, not ids.
    assert "port 8089 and count 42 stay" in redacted


def test_a_crash_in_a_templated_workspace_leaks_nothing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state_dirs: Path,
    template_workspace: Path,
) -> None:
    _crash_in_info(monkeypatch, ConnectionError(_template_crash_text()))
    assert (
        _run_main(monkeypatch, "--repo", str(template_workspace), "--json", "info", "--debug") == 1
    )
    captured = capsys.readouterr()
    [log] = _logs(state_dirs)
    for text in (captured.out, captured.err, log.read_text(encoding="utf-8")):
        for leaked in _TEMPLATE_LEAKS:
            assert leaked not in text, (leaked, text)


# Crashes before the mode is known, and in the handler itself


@pytest.mark.parametrize("argv", [["--json", "mcp", "start"], ["mcp", "start"]])
def test_an_early_crash_under_mcp_start_never_writes_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state_dirs: Path,
    argv: list[str],
) -> None:
    """A crash before LazyTyperGroup.main resolves the mode, with OPENTIDE_OUTPUT=json too."""
    import opentide.cli.context as context_module

    def explode(*, no_color: bool) -> None:
        raise RuntimeError("early failure")

    monkeypatch.setenv("OPENTIDE_OUTPUT", "json")
    monkeypatch.setattr(context_module, "sync_typer_rendering", explode)
    assert _run_main(monkeypatch, *argv) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error[internal]: RuntimeError: early failure" in captured.err
    assert len(_logs(state_dirs)) == 1


def test_an_early_crash_under_json_prints_the_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    import opentide.cli.context as context_module

    def explode(*, no_color: bool) -> None:
        raise RuntimeError("early failure")

    monkeypatch.setattr(context_module, "sync_typer_rendering", explode)
    assert _run_main(monkeypatch, "--json", "info") == 1
    document = json.loads(capsys.readouterr().out)
    assert document["failure"]["code"] == INTERNAL
    assert document["command"] == "info"


class _UnprintableError(Exception):
    def __str__(self) -> str:
        raise ZeroDivisionError("no message for you")


def test_an_exception_whose_str_raises_is_still_reported(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, _UnprintableError())
    assert _run_main(monkeypatch, "--no-color", "info") == 1
    err = _plain(capsys.readouterr().err)
    assert err.startswith("error[internal]: _UnprintableError: (its message could not be read)\n")
    assert "Traceback" not in err
    assert len(_logs(state_dirs)) == 1


@pytest.mark.parametrize("failure", [RuntimeError("handler broke"), KeyboardInterrupt()])
def test_a_failing_handler_exits_1_without_a_chained_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: BaseException,
) -> None:
    import opentide.cli.ui.crash as crash_module

    def broken(*args: object, **kwargs: object) -> int:
        raise failure

    _crash_in_info(monkeypatch, RuntimeError("token=abcd1234secret"))
    monkeypatch.setattr(crash_module, "handle_crash", broken)
    monkeypatch.setattr(sys, "argv", ["opentide", "--no-color", "info"])
    with pytest.raises(SystemExit) as raised:
        cli_package.main()
    assert raised.value.code == 1
    # Python prints neither the cause nor the context of this exit.
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True
    assert "abcd1234secret" not in capsys.readouterr().err


def test_the_fallback_prints_only_the_type(monkeypatch: pytest.MonkeyPatch) -> None:
    import opentide.cli.ui.crash as crash_module

    def broken(*args: object, **kwargs: object) -> object:
        raise RuntimeError("context lookup failed")

    monkeypatch.setattr(crash_module, "_active_context", broken)
    out, err = _Capture(), _Capture()
    code = crash_module.handle_crash(
        ValueError("password=abcd1234secret"), argv=["info"], env={}, stdout=out, stderr=err
    )
    assert code == 1
    assert err.getvalue() == "error[internal]: ValueError\n"
    assert out.getvalue() == ""


def test_json_document_is_utf8_with_one_trailing_newline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state_dirs: Path
) -> None:
    _crash_in_info(monkeypatch, RuntimeError("boom été"))
    assert _run_main(monkeypatch, "--json", "info") == 1
    out = capsys.readouterr().out
    assert "boom été" in out
    assert out.endswith("}\n")
    assert not out.endswith("\n\n")
    assert json.loads(out)["error"] == "RuntimeError: boom été"


@pytest.mark.parametrize(("indent", "lines"), [(None, 1), ("0", 1), ("2", None)])
def test_json_document_is_indented_like_every_other_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state_dirs: Path,
    indent: str | None,
    lines: int | None,
) -> None:
    """A crash document follows ``OPENTIDE_JSON_INDENT`` and is one line in a pipe (#629)."""
    if indent is None:
        monkeypatch.delenv("OPENTIDE_JSON_INDENT", raising=False)
    else:
        monkeypatch.setenv("OPENTIDE_JSON_INDENT", indent)
    _crash_in_info(monkeypatch, RuntimeError("index exploded"))
    assert _run_main(monkeypatch, "--json", "info") == 1
    out = capsys.readouterr().out
    assert json.loads(out)["failure"]["code"] == INTERNAL
    if lines is None:
        assert out.count("\n") > 1
        assert out.startswith('{\n  "')
    else:
        assert out.count("\n") == lines


def test_python_dash_m_opentide_reports_a_crash(tmp_path: Path) -> None:
    """``python -m opentide`` goes through ``main()`` too: one internal envelope, exit 1."""
    script = textwrap.dedent(
        """
        import runpy
        import sys
        import opentide.cli.services.info as info_service

        def explode(*args, **kwargs):
            raise RuntimeError("index exploded")

        info_service.collect_info = explode
        sys.argv = ["opentide", "--json", "info"]
        runpy.run_module("opentide", run_name="__main__", alter_sys=True)
        """
    )
    env = {
        **os.environ,
        "HOME": str(tmp_path),
        "USERPROFILE": str(tmp_path),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "LOCALAPPDATA": str(tmp_path / "local"),
    }
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert done.returncode == 1, done.stderr
    document = json.loads(done.stdout)
    assert document["exit_code"] == 1
    assert document["failure"]["code"] == INTERNAL
    assert Path(document["failure"]["crash_log"]).is_file()
    assert "Traceback" not in done.stderr


def _splunk_app_workspace(root: Path, app: str) -> Path:
    platforms = root / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "splunk.toml").write_text(
        f'[[tenants]]\nname = "acme-splunk"\n[tenants.setup]\napp = "{app}"\n',
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize(
    "app",
    [
        "search",
        "Search",
        "launcher",
        "SplunkEnterpriseSecuritySuite",
        "SA-ThreatIntelligence",
        "DA-ESS-EndpointProtection",
        "TA-windows",
        "ta-nix",
        "splunk_monitoring_console",
        "Splunk_SA_CIM",
    ],
)
def test_built_in_splunk_apps_are_not_redacted(tmp_path: Path, app: str) -> None:
    redactor = workspace_redactor([_splunk_app_workspace(tmp_path, app)], env={})
    text = f"app {app} failed in opentide.search for acme-splunk"
    assert redactor(text) == f"app {app} failed in opentide.search for ***"


@pytest.mark.parametrize("app", ["acme_detections", "SOC-Content", "tasks-acme"])
def test_custom_splunk_apps_are_redacted(tmp_path: Path, app: str) -> None:
    redactor = workspace_redactor([_splunk_app_workspace(tmp_path, app)], env={})
    assert redactor(f"/servicesNS/nobody/{app}/saved/searches") == (
        "/servicesNS/nobody/***/saved/searches"
    )


def test_built_in_app_names_count_only_under_an_app_key(tmp_path: Path) -> None:
    """A tenant named ``search`` is still a tenant name."""
    platforms = tmp_path / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "splunk.toml").write_text('[[tenants]]\nname = "launcher"\n', encoding="utf-8")
    assert workspace_redactor([tmp_path], env={})("tenant launcher") == "tenant ***"
