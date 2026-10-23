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
    import opentide.cli.commands.info as info_command

    def explode(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(info_command, "collect_info", explode)


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


class _Capture:
    def __init__(self) -> None:
        self.parts: list[str] = []

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
        import opentide.cli.commands.info as info_command

        def explode(*args, **kwargs):
            raise RuntimeError("index exploded")

        info_command.collect_info = explode
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
