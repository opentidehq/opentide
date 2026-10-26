"""CLI E2E: Ctrl-C at the setup wizard's first prompt prints one line and exits 130.

questionary printed ``Cancelled by user`` and #640's handler adds
``error: interrupted``; with both merged a person must see the second only
(D25). A real pseudo-terminal, so the wizard runs as it does for a person.
"""

from __future__ import annotations

import os
import pty
import re
import select
import signal
import sys
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.cli_e2e,
    pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX pseudo-terminal"),
]

_ANSI = re.compile(r"\x1b\[[0-9;?<>=]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_DROP = ("CI", "GITHUB_ACTIONS", "CLAUDECODE", "AI_AGENT", "NO_COLOR", "OPENTIDE_OUTPUT")


def test_ctrl_c_in_the_wizard_prints_exactly_one_line(tmp_path: Path) -> None:
    env = {key: value for key, value in os.environ.items() if key not in _DROP}
    env |= {"TERM": "xterm-256color", "COLUMNS": "100", "LINES": "30"}
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child process
        os.chdir(tmp_path)
        os.execvpe(sys.executable, [sys.executable, "-m", "opentide", "setup"], env)
    out = b""
    sent = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if b"\x1b[6n" in chunk:  # prompt_toolkit asks for the cursor position
                os.write(fd, b"\x1b[1;1R")
        if not sent and b"Repository name" in out:
            time.sleep(0.5)
            os.write(fd, b"\x03")
            sent = True
    else:  # pragma: no cover - a hang is the failure
        os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    text = _ANSI.sub("", out.decode("utf-8", "replace"))
    assert sent, text
    assert os.waitstatus_to_exitcode(status) == 130, text
    assert text.count("error: interrupted") == 1, text
    assert "Cancelled by user" not in text
    assert "Traceback" not in text
    # Nothing follows the line: no outcome, no next steps.
    assert text.rstrip().endswith("error: interrupted"), text[-300:]
