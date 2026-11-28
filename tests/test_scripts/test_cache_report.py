"""scripts/cache_report.py: the Actions caches summed per ref and family (#841)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
_MODULE = ROOT / "scripts" / "cache_report.py"
_spec = importlib.util.spec_from_file_location("cache_report", _MODULE)
assert _spec and _spec.loader
cache_report = importlib.util.module_from_spec(_spec)
# A dataclass looks its module up in sys.modules while the module runs.
sys.modules["cache_report"] = cache_report
_spec.loader.exec_module(cache_report)

TOOLCHAIN = "ba95573921faa1a91960ce70c797b89c7ed461e5b11658dd43ecf4caa6eca270"


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (
            f"sccache-engine-dev-ubuntu-latest-1-{TOOLCHAIN}-2026-W46",
            "sccache-engine-dev-ubuntu-latest-1",
        ),
        (f"sccache-full-set-Linux-{TOOLCHAIN}-2026-W46", "sccache-full-set-Linux"),
        (f"sccache-release-macOS-ARM64-{TOOLCHAIN}-2026-W46", "sccache-release-macOS-ARM64"),
        ("v0-rust-fuzz-Linux-x64-1a2b3c4d-0123456789abcdef", "v0-rust-fuzz-Linux-x64"),
        (
            "setup-uv-1-x86_64-unknown-linux-gnu-3.12-0f1e2d3c4b5a69788796a5b4",
            "setup-uv-1-x86_64-unknown-linux-gnu-3.12",
        ),
        ("no-hash-here", "no-hash-here"),
    ],
)
def test_a_family_is_the_key_without_its_hashes(key: str, expected: str) -> None:
    assert cache_report.family(key) == expected


def _line(ref: str, key: str, size_mb: int, used: str = "2026-11-14T05:00:00Z") -> str:
    return json.dumps(
        {
            "id": 1,
            "ref": ref,
            "key": key,
            "size_in_bytes": size_mb * 1024**2,
            "last_accessed_at": used,
            "created_at": "2026-11-14T03:00:00Z",
        }
    )


def test_the_report_sums_per_ref_and_family() -> None:
    lines = [
        _line("refs/heads/integration/unified-core", f"sccache-lint-{TOOLCHAIN}-2026-W46", 300),
        _line(
            "refs/heads/integration/unified-core",
            f"sccache-lint-{TOOLCHAIN}-2026-W45",
            200,
            "2026-11-01T00:00:00Z",
        ),
        _line("refs/heads/train/catchup-0.28", f"sccache-lint-{TOOLCHAIN}-2026-W46", 1000),
        "",
    ]
    text = cache_report.report(cache_report.parse(lines))
    assert "3 caches, 1,500 MB of the 10,240 MB GitHub keeps (15%)" in text
    # Per ref, largest first.
    train = text.index("| `refs/heads/train/catchup-0.28` | 1 | 1,000 MB | 67% |")
    integration = text.index("| `refs/heads/integration/unified-core` | 2 | 500 MB | 33% |")
    assert train < integration
    # Two weeks of one family on one ref sum to one row, with its latest use.
    assert (
        "| `refs/heads/integration/unified-core` | `sccache-lint` | 2 | 500 MB | 33% | "
        "2026-11-14T05:00:00Z |" in text
    )
    assert f"`sccache-lint-{TOOLCHAIN}-2026-W45`" in text


def test_no_caches_is_a_report_too() -> None:
    assert "0 caches, 0 MB" in cache_report.report([])


def test_the_workflow_reads_the_caches_and_runs_no_pull_requests_code() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "cache-report.yml").read_text(encoding="utf-8")
    )
    # PyYAML reads the key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"schedule", "workflow_dispatch", "push"}
    # A push runs it only where it lands: a base branch, and a change to the report.
    assert triggers["push"]["branches"] == ["development", "integration/unified-core"]
    assert set(triggers["push"]["paths"]) == {
        ".github/workflows/cache-report.yml",
        "scripts/cache_report.py",
    }
    assert workflow["permissions"] == {"contents": "read"}
    (job,) = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    run = "\n".join(str(step.get("run", "")) for step in job["steps"])
    assert "actions/caches" in run and "scripts/cache_report.py" in run
    assert "$GITHUB_STEP_SUMMARY" in run
