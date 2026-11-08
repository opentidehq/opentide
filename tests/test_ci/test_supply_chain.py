"""The Rust supply-chain gates (#843) say what docs/internal/supply-chain.md says.

``deny.toml`` is what ``cargo deny check`` enforces on every pull request.
These tests keep it in step with ``about.toml`` (the licences each engine
release lists in THIRD-PARTY-LICENSES.html), and keep its exceptions explained.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]


def _toml(name: str) -> dict[str, Any]:
    return tomllib.loads((ROOT / name).read_text(encoding="utf-8"))


def test_deny_allows_the_licences_about_accepts() -> None:
    """One licence list: cargo-deny gates what cargo-about renders."""
    deny = _toml("deny.toml")["licenses"]
    about = _toml("about.toml")
    assert sorted(deny["allow"]) == sorted(about["accepted"])
    # The workspace's own licence, and EUPL-1.2's compatible set: no
    # copyleft licence (GPL, LGPL, MPL) slips in by being added to one file.
    assert "EUPL-1.2" in deny["allow"]
    assert not [lic for lic in deny["allow"] if "GPL" in lic or "MPL" in lic]


def test_every_advisory_exception_has_a_reason_and_an_issue() -> None:
    advisories = _toml("deny.toml")["advisories"]
    for entry in advisories.get("ignore", []):
        assert isinstance(entry, dict), f"{entry}: give `{{ id, reason }}`"
        assert entry.get("reason"), f"{entry['id']} has no reason"
        assert "#" in entry["reason"], f"{entry['id']}: name the follow-up issue"
    assert advisories["unmaintained"] == "all"
    assert advisories["yanked"] == "deny"


def test_openssl_is_banned_in_favour_of_rustls() -> None:
    banned = {entry["crate"] for entry in _toml("deny.toml")["bans"]["deny"]}
    assert {"openssl-sys", "openssl", "native-tls"} <= banned


def test_duplicates_and_sources_fail_unless_explained() -> None:
    deny = _toml("deny.toml")
    assert deny["bans"]["multiple-versions"] == "deny"
    for entry in deny["bans"].get("skip", []):
        assert isinstance(entry, dict) and entry.get("reason"), entry
    sources = deny["sources"]
    assert sources["unknown-registry"] == "deny"
    assert sources["unknown-git"] == "deny"
    assert sources["allow-registry"] == ["https://github.com/rust-lang/crates.io-index"]


# --- The workflows that run the gates -------------------------------------

import importlib.util  # noqa: E402 -- the workflow tests' own imports
import json  # noqa: E402
from types import ModuleType  # noqa: E402

import yaml  # noqa: E402

WORKFLOWS = ROOT / ".github" / "workflows"


def _workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> set[str]:
    # PyYAML reads the `on:` key as True.
    on = workflow.get("on", workflow.get(True))
    return set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on)


def _audit() -> ModuleType:
    spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts/engine/audit.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cargo_deny_gates_every_pull_request_at_a_pinned_version() -> None:
    ci = _workflow("ci.yml")
    assert "pull_request" in _triggers(ci)
    steps = ci["jobs"]["deny"]["steps"]
    installs = [s for s in steps if "taiki-e/install-action" in s.get("uses", "")]
    assert installs and installs[0]["with"]["tool"] == "cargo-deny@0.20.2"
    assert installs[0]["with"]["fallback"] == "none"
    runs = " ".join(s.get("run", "") for s in steps)
    assert "cargo deny --config deny.toml --locked check" in runs
    assert "--manifest-path fuzz/Cargo.toml" in runs
    # Every other Cargo workspace in the repository has its own deny step.
    lockfiles = sorted(
        str(p.parent.relative_to(ROOT))
        for p in ROOT.glob("**/Cargo.lock")
        if not {"target", "node_modules", ".git"} & set(p.relative_to(ROOT).parts)
    )
    for workspace in lockfiles:
        if workspace != ".":
            assert f"--manifest-path {workspace}/Cargo.toml" in runs, workspace
    assert ci["jobs"]["deny"]["permissions"] == {"contents": "read"}


def test_only_the_scheduled_audit_may_write_issues() -> None:
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        scopes = [workflow.get("permissions") or {}] + [
            job.get("permissions") or {} for job in workflow["jobs"].values()
        ]
        writes_issues = any(
            s == "write-all" or (isinstance(s, dict) and s.get("issues") == "write") for s in scopes
        )
        if path.name == "rust-audit.yml":
            assert writes_issues
            assert _triggers(workflow) == {"schedule", "workflow_dispatch"}
            assert workflow["permissions"] == {"contents": "read"}
            jobs = workflow["jobs"]
            assert jobs["audit"]["permissions"] == {"contents": "read"}
            assert jobs["issue"]["permissions"] == {"issues": "write"}
            # The job that holds the token checks out and builds nothing.
            issue_steps = jobs["issue"]["steps"]
            assert not [s for s in issue_steps if "actions/checkout" in s.get("uses", "")]
            assert not [s for s in issue_steps if "cargo " in s.get("run", "")]
        else:
            assert not writes_issues, f"{path.name} writes issues"


def test_the_audit_issue_title_is_the_scripts() -> None:
    audit = _audit()
    issue = _workflow("rust-audit.yml")["jobs"]["issue"]["steps"][-1]
    assert issue["env"]["TITLE"] == audit.ISSUE_TITLE


def test_the_nightly_fuzz_runs_every_target_ten_minutes() -> None:
    targets = sorted(p.stem for p in (ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    job = _workflow("engine-fuzz.yml")["jobs"]["fuzz"]
    assert sorted(job["strategy"]["matrix"]["target"]) == targets
    assert "'600'" in json.dumps(job["steps"])
    assert any("upload-artifact" in s.get("uses", "") for s in job["steps"])


def test_the_audit_reads_deny_tomls_exceptions_and_renders_findings() -> None:
    audit = _audit()
    deny = (ROOT / "deny.toml").read_text(encoding="utf-8")
    ids = audit.ignored_advisories(deny)
    assert ids == [e["id"] for e in _toml("deny.toml")["advisories"]["ignore"]]
    report = {
        "lockfile": {"dependency-count": 1},
        "vulnerabilities": {
            "found": True,
            "count": 1,
            "list": [
                {
                    "advisory": {
                        "id": "RUSTSEC-0000-0001",
                        "title": "a | b <x>",
                        "url": "https://x",
                    },
                    "package": {"name": "crate", "version": "1.0.0"},
                    "versions": {"patched": [">=1.0.1"]},
                }
            ],
        },
        "warnings": {
            "unmaintained": [
                {
                    "advisory": {"id": "RUSTSEC-0000-0002", "title": "gone"},
                    "package": {"name": "old", "version": "0.1.0"},
                }
            ]
        },
    }
    body = audit.render({"Cargo.lock": report})
    assert "**2 advisories.**" in body
    assert "[RUSTSEC-0000-0001](https://x)" in body
    assert "a \\| b &lt;x&gt;" in body
    assert "&gt;=1.0.1" in body and "none published" in body
    # Advisory text cannot mention, link or embed.
    hostile = dict(report)
    hostile["vulnerabilities"] = {
        "list": [
            {
                "advisory": {
                    "id": "X",
                    "title": "@octocat ![i](https://t/p) [l](https://e) `c`",
                    "url": "javascript:alert(1)",
                },
                "package": {"name": "a", "version": "1"},
            }
        ]
    }
    body = audit.render({"Cargo.lock": hostile})
    assert "@octocat" not in body
    assert "![i](" not in body and "[l](" not in body and "`c`" not in body
    assert "javascript:" not in body
    piped = dict(report)
    piped["vulnerabilities"] = {
        "list": [
            {
                "advisory": {"id": "Y", "title": "t", "url": "https://x|y\nz"},
                "package": {"name": "a", "version": "1"},
            }
        ]
    }
    assert "](https://x|y" not in audit.render({"Cargo.lock": piped})
    long = dict(report)
    long["vulnerabilities"] = {"list": report["vulnerabilities"]["list"] * 2000}
    cut = audit.render({"Cargo.lock": long}, "https://github.com/o/r/actions/runs/1")
    assert len(cut) <= audit.BODY_LIMIT + 200
    assert cut.rstrip().endswith("Run: https://github.com/o/r/actions/runs/1")
    with pytest.raises(ValueError):
        audit.findings({"database": {}})
