"""Registry builds safely when triggered from an unguarded entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import yaml

# The `opentide` console script imports the CLI at module scope, which builds the
# registry, and pip-generated scripts have no `if __name__ == "__main__"` guard. Any
# process pool in the build path therefore breaks under the `spawn` start method:
# children re-import the entry point and recurse. Forced here because CI runs Linux,
# which defaults to `fork` and would hide the regression.
_BUILD_SCRIPT = """
import multiprocessing

multiprocessing.set_start_method("spawn", force=True)

from opentide.registry.builder import build_registry

index = build_registry()
print("INDEXED", len(index["objects"]["rule"]))
"""


def _rule(name: str) -> dict[str, object]:
    return {
        "uuid": str(uuid4()),
        "name": name,
        "metadata": {"schema": "rule::1.0", "tlp": "TLP:CLEAR", "version": "1.0.0"},
    }


def test_build_registry_from_unguarded_entry_point(tmp_path: Path) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    (tmp_path / ".opentide" / "framework" / "schemas").mkdir(parents=True)

    # More than four objects: the removed process pool only engaged above that count,
    # which is why the existing small-corpus tests never caught the crash.
    rule_count = 6
    for idx in range(rule_count):
        (rules / f"rule-{idx}.yaml").write_text(
            yaml.safe_dump(_rule(f"rule-{idx}")), encoding="utf-8"
        )

    script = tmp_path / "entry_point.py"
    script.write_text(_BUILD_SCRIPT, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "OPENTIDE_TIDE_WORKSPACE": str(tmp_path.resolve())},
    )

    assert result.returncode == 0, result.stderr
    assert f"INDEXED {rule_count}" in result.stdout
