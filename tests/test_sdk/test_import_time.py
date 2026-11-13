"""``import opentide`` stays light (UC-5.2, #837): 30 ms or less, and none of the SDK's weight.

The SDK (``opentide.Workspace``), the engine (``opentide._native``) and the
registry load on first use: the console script's start and ``--version`` pay
for none of them.
"""

from __future__ import annotations

import subprocess
import sys

#: The budget #837 sets for ``import opentide``, in microseconds.
BUDGET_US = 30_000

_LOADED = """
import sys
import opentide
heavy = ("opentide.sdk", "opentide._native", "opentide.analysis", "opentide.models", "json")
print(",".join(name for name in heavy if name in sys.modules))
"""


def _python(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, check=True)


def test_importing_opentide_loads_neither_the_sdk_nor_the_engine() -> None:
    assert _python("-c", _LOADED).stdout.strip() == ""


def test_importing_opentide_takes_30_ms_or_less() -> None:
    _python("-c", "import opentide")  # compile the bytecode first
    # -X importtime: "import time: self [us] | cumulative | name", one line per module.
    lines = _python("-X", "importtime", "-c", "import opentide").stderr.splitlines()
    cumulative = {
        line.rsplit("|", 1)[1].strip(): int(line.split("|")[1])
        for line in lines
        if line.startswith("import time:") and line.split("|")[1].strip().isdigit()
    }
    assert cumulative["opentide"] <= BUDGET_US, cumulative
