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

Usage: ``python fake_rust_engine.py <mode> <opentide arguments>``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    mode, args = sys.argv[1], sys.argv[2:]
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
    elif mode == "exit":
        code += 1
    elif mode == "file":
        Path("fake-rust.txt").write_text("written by the fake\n", encoding="utf-8")
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(child.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
