"""A deliberately divergent fake Rust implementation of any command (#805).

A test fixture, not a command: ``tests/test_cli/test_engines.py`` registers it
in ``opentide.cli.engines.RUST_COMMANDS`` to show that ``OPENTIDE_ENGINE=compare``
catches each kind of divergence. It runs the real Python CLI on the same
arguments, then changes the result as its first argument says:

- ``same``: nothing, so compare finds the two equal.
- ``stdout``: a JSON document gains a key; any other output gains a line.
- ``exit``: the exit code is one more.
- ``file``: it also writes ``fake-rust.txt`` in the working directory.
- ``key-order``: a JSON document's first two keys swap places.
- ``raw``: ``duration_ms`` reads 987654 and ``marker.json`` holds the same,
  which normalise to what ``raw-python`` prints and writes (``1``): equal, yet
  every byte that reaches the user tells the two runs apart.
- ``raw-python``: the same with ``1``, standing in for the Python run.
- ``uuid``: a fresh UUID line on stdout, a new one each run.
- ``recent``: a date-time of yesterday, at a new second each run.
- ``mutate``: deletes ``delete-me.txt`` and makes ``chmod-me.txt`` 0600.
- ``sigterm``: the process ends on SIGTERM, without output.
- ``refuse``: refuses the run as the Rust CLI refuses an input it does not
  cover: its message in the file ``OPENTIDE_ENGINE_REFUSAL`` names, when it
  names one, other output and exit 2.

Usage: ``python fake_rust_engine.py <mode> <opentide arguments>``.
"""

from __future__ import annotations

import json
import os
import random
import re
import signal
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main() -> int:
    mode, args = sys.argv[1], sys.argv[2:]
    if mode == "sigterm":
        os.kill(os.getpid(), signal.SIGTERM)
    if mode == "refuse":
        refusal = os.environ.get("OPENTIDE_ENGINE_REFUSAL")
        if refusal:
            Path(refusal).write_text("not for this input", encoding="utf-8")
        Path("fake-rust.txt").write_text("written by the fake\n", encoding="utf-8")
        sys.stdout.write("refused by the fake\n")
        return 2
    env = {**os.environ, "OPENTIDE_ENGINE": "python"}
    child = subprocess.run(
        [sys.executable, "-m", "opentide", *args], env=env, capture_output=True, check=False
    )
    stdout, code = child.stdout, child.returncode
    if mode in ("stdout", "key-order"):
        try:
            document = json.loads(stdout)
        except ValueError:
            document = None
        if isinstance(document, dict) and mode == "stdout":
            document["engine"] = "fake"
        elif isinstance(document, dict):
            keys = list(document)
            keys[0], keys[1] = keys[1], keys[0]
            document = {key: document[key] for key in keys}
        if document is None:
            stdout += b"fake rust\n"
        else:
            stdout = (
                json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
            )
    elif mode in ("raw", "raw-python"):
        value = b"987654" if mode == "raw" else b"1"
        stdout = re.sub(rb'"duration_ms":\s*\d+', b'"duration_ms":' + value, stdout)
        Path("marker.json").write_bytes(b'{"duration_ms":' + value + b"}\n")
    elif mode == "uuid":
        stdout += f"minted {uuid.uuid4()}\n".encode()
    elif mode == "recent":
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        stamp = yesterday.replace(second=random.randrange(60), microsecond=0)
        stdout += f"window starts {stamp:%Y-%m-%dT%H:%M:%S}Z\n".encode()
    elif mode == "mutate":
        Path("delete-me.txt").unlink()
        Path("chmod-me.txt").chmod(0o600)
    elif mode == "exit":
        code += 1
    elif mode == "file":
        Path("fake-rust.txt").write_text("written by the fake\n", encoding="utf-8")
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(child.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
