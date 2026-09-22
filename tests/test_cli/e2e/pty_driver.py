"""Drive the ``opentide`` console script on a real pseudo-terminal.

``CliRunner`` never presents a TTY, so ``require_interactive`` short-circuits
and the Questionary wizard is unreachable under pytest. That blind spot is why
#255 (``--json setup`` prints a Rich panel, prompts, and *then* JSON) and #177
never failed CI. Everything here spawns the installed entry point under a PTY
via :mod:`pexpect`.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import pexpect
import pytest

#: prompt_toolkit queries the terminal for the cursor position and blocks on the
#: reply; a bare PTY never answers.
PTY_ENV = {
    "PROMPT_TOOLKIT_NO_CPR": "1",
    "TERM": "xterm-256color",
    "COLUMNS": "120",
    "LINES": "40",
}

#: VT100 escapes plus the private-mode and OSC sequences prompt_toolkit emits.
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")

ENTER = "\r"
SPACE = " "


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def requires_pty() -> None:
    """Skip when the platform cannot give us a terminal."""
    if not hasattr(os, "openpty"):
        pytest.skip("platform has no pty support")
    if shutil.which("opentide") is None:
        pytest.skip("opentide console script is not on PATH")


def clean_env(repo: Path | None = None) -> dict[str, str]:
    """A terminal session without the OpenTide exports fixtures normally set."""
    env = os.environ.copy()
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE", "DEPLOYMENT_PLAN"):
        env.pop(name, None)
    env.update(PTY_ENV)
    if repo is not None:
        env["OPENTIDE_REPO_ROOT"] = str(repo)
    return env


@dataclass
class PtyRun:
    """The outcome of one PTY session."""

    output: str
    exit_status: int | None

    @property
    def clean(self) -> str:
        return strip_ansi(self.output).replace("\r\n", "\n")


class PtySession:
    """A spawned ``opentide`` process attached to a PTY."""

    def __init__(self, args: list[str], *, env: dict[str, str], cwd: Path, timeout: int) -> None:
        self.child = pexpect.spawn(
            "opentide",
            args,
            env=env,
            cwd=str(cwd),
            timeout=timeout,
            encoding="utf-8",
            codec_errors="replace",
            dimensions=(40, 120),
        )
        self._log: list[str] = []

    def expect(self, pattern: str) -> None:
        """Wait for *pattern* in the (ANSI-stripped) stream, or fail with context."""
        try:
            self.child.expect(pattern)
        except (pexpect.EOF, pexpect.TIMEOUT) as exc:  # pragma: no cover - diagnostics
            self._log.append(self.child.before or "")
            raise AssertionError(
                f"never saw {pattern!r} on the terminal.\n"
                f"--- transcript ---\n{strip_ansi(''.join(self._log))}"
            ) from exc
        self._log.append((self.child.before or "") + (self.child.after or ""))

    def send(self, keys: str) -> None:
        self.child.send(keys)

    def finish(self) -> PtyRun:
        self.child.expect(pexpect.EOF)
        self._log.append(self.child.before or "")
        self.child.close()
        return PtyRun(output="".join(self._log), exit_status=self.child.exitstatus)


def run_on_pty(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = 60,
) -> PtyRun:
    """Run to completion with no input, e.g. to prove a guard fires.

    A short timeout on purpose: the regression these tests guard against is a
    wizard that waits for keystrokes forever, and that should fail fast.
    """
    session = PtySession(args, env=env or clean_env(), cwd=cwd, timeout=timeout)
    return session.finish()
