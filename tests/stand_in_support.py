"""Stand-in tenants on loopback for the SDK's tenant operations (UC-5.2b, #837).

:func:`stand_in` starts one of ``tests/cassettes/<name>/tenant.py`` (the stand-ins
``cargo xtask cassettes record`` records the connectors against) in a child process
on a free loopback port, and stops it on exit. Nothing reaches a real host.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

CASSETTES = Path(__file__).resolve().parent / "cassettes"
#: The API token the SentinelOne stand-in accepts (``S1_API_TOKEN``).
S1_TOKEN = "s1-stand-in-token"


@contextmanager
def stand_in(name: str, env: dict[str, str]) -> Iterator[str]:
    """Runs the stand-in *name* with *env* added to its environment; yields its URL."""
    process = subprocess.Popen(
        [sys.executable, str(CASSETTES / name / "tenant.py")],
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, **env},
    )
    try:
        assert process.stdout is not None
        port = int(process.stdout.readline().strip())
        yield f"http://127.0.0.1:{port}"
    finally:
        process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


@contextmanager
def sentinel_one() -> Iterator[str]:
    """The SentinelOne stand-in (``tests/cassettes/sentinel_one/tenant.py``); its URL."""
    with stand_in("sentinel_one", {"S1_API_TOKEN": S1_TOKEN}) as url:
        yield url
