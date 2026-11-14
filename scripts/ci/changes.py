"""What a CI run must check: ci.yml's `changes` job (.github/AGENTS.md, "The PR gate").

A pull request is checked where it changed: the files it touches map to the
jobs that test them, and a change in a workspace crate to that crate and every
crate that depends on it (its reverse dependencies, read from ``cargo
metadata``). A push to a base branch, the nightly and Run workflow check
everything. A file this script does not know marks everything: an unknown
path fails open, never closed.

Usage (ci.yml sets the environment)::

    python scripts/ci/changes.py              # writes to $GITHUB_OUTPUT
    python scripts/ci/changes.py --explain    # the same, printed, for a person

Environment:

- ``EVENT``: the event that started the run (``pull_request``, ``push``,
  ``schedule``, ``workflow_dispatch``);
- ``SCOPE``: Run workflow's ``scope`` input (``full``, ``nightly``, ``release``);
- ``BASE_SHA`` and ``HEAD_SHA``: a pull request's base and head commits;
- ``BASE_REF``, ``HEAD_REF`` and ``LABELS`` (a JSON list of label names): a
  pull request's base and head branches and labels, which say whether it is a
  release pull request.

The standard library only: the job runs it before anything is installed.
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

#: The areas a change can touch, each a job (or a set of jobs) of ci.yml.
AREAS = (
    "pylint",  # ruff, ty, the sdist: a Python file changed
    "ci",  # actionlint and tests/test_ci: a workflow or the CI contracts changed
    "skills",  # the agent skills' validation
    "rust",  # the build, the Rust tests, engine lint
    "python",  # the wheel and the Python job: the Python surface changed
    "docs",  # docs validation
    "node",  # the Node package
    "wasi",  # the WASI command line
    "grammars",  # grammars regenerate
    "textmate",  # TextMate grammars
    "gitlab",  # GitLab CI lint
    "facade",  # the facade crate's every feature and semver checks
    "deny",  # cargo deny
)

#: Paths whose change marks everything: the toolchain, the lockfile, the
#: workspace's shared configuration, CI itself.
EVERYTHING = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/*",
    ".config/*",
    "clippy.toml",
    "rustfmt.toml",
    ".github/workflows/*",
    ".github/actions/*",
    ".github/actionlint.yaml",
    "scripts/ci/*",
    "scripts/ci-local.sh",
)

#: (pattern, areas, crates) for the paths outside a workspace crate, first
#: match wins. ``crates`` is a tuple of package names, or ``ALL`` for every
#: crate of the workspace.
ALL = ("*",)
RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    # Documentation: validated, with the docs tests that need no wheel; a
    # docs-only pull request runs nothing else (the push runs everything).
    ("docs/*", ("docs",), ()),
    ("README.md", ("docs",), ()),
    ("CONTRIBUTING.md", ("docs",), ()),
    ("AGENTS.md", ("docs",), ()),
    ("CLAUDE.md", ("docs",), ()),
    ("CHANGELOG.md", ("docs",), ()),
    # Agent skills: scripts/engine/validate-skills.sh.
    (".agents/*", ("skills",), ()),
    (".claude/*", ("skills",), ()),
    # GitLab CI lint's own inputs (with opentide-cli's renderer, below).
    ("scripts/install-gitlab-ci-linters.sh", ("gitlab",), ()),
    ("tests/test_ci/test_gitlab_pipeline_lint.py", ("gitlab", "pylint"), ()),
    # The CI contracts and the docs tests run without a wheel; the two docs
    # tests that run the command line and the SDK need it.
    ("tests/test_ci/*", ("ci", "pylint"), ()),
    ("tests/test_docs/test_docs_commands_golden.py", ("python", "docs", "pylint"), ()),
    ("tests/test_docs/test_sdk_snippets.py", ("python", "docs", "pylint"), ()),
    ("tests/test_docs/*", ("docs", "pylint"), ()),
    # The Python surface: the package, its tests, its build.
    ("src/opentide/data/*", ("python",), ALL),
    ("src/opentide/schemas/*", ("python",), ALL),
    ("src/opentide/_native/*", ("python", "pylint"), ALL),
    ("src/opentide/*", ("python", "pylint"), ()),
    ("tests/*.py", ("python", "pylint"), ()),
    # Test data outside a crate: fixtures, corpora, cassettes, goldens, which
    # the crates' tests read as well.
    ("tests/*", ("python",), ALL),
    ("pyproject.toml", ("python", "pylint"), ()),
    ("uv.lock", ("python", "pylint"), ()),
    ("hatch_build.py", ("python", "pylint"), ()),
    (".pre-commit-config.yaml", ("pylint",), ()),
    # The scripts a gate job runs: the docs job's and the grammars job's.
    ("scripts/validate-docs.sh", ("docs",), ()),
    ("scripts/engine/check-grammars.sh", ("grammars",), ()),
    # The engine's scripts (the invariants, the WASI build, the release).
    ("scripts/engine/build-wasm.sh", ("wasi",), ()),
    ("scripts/engine/*.py", ("pylint",), ALL),
    ("scripts/engine/*", (), ALL),
    ("scripts/build/*", ("python", "pylint"), ()),
    ("scripts/*.py", ("python", "pylint"), ()),
    ("scripts/*.sh", ("ci",), ()),
    # What the engine compiles in, and its hosts.
    ("grammars/*", ("grammars",), ("opentide-syntax",)),
    ("highlights/test/*", ("textmate",), ()),
    ("highlights/*", ("textmate",), ALL),
    ("editors/*", ("textmate",), ()),
    ("packages/*", ("wasi",), ()),
    ("data/*", (), ALL),
    # The WASI shims of memmap2 and filetime (vendor/README.md).
    ("vendor/*", ("deny", "wasi"), ALL),
    ("crates/testdata/*", (), ALL),
    ("crates/*.md", ("docs",), ()),
    ("fuzz/*", ("deny",), ()),
    ("deny.toml", ("deny",), ()),
    ("publishing/*", ("deny", "python"), ()),
    ("about.toml", ("deny",), ()),
    ("about.hbs", ("deny",), ()),
    ("licenses/*", ("deny",), ()),
    ("LICENSE", (), ()),
    ("NOTICE", (), ()),
    (".gitignore", (), ()),
    (".gitattributes", (), ()),
    # .github/AGENTS.md and the rest: the CI contracts read them.
    (".github/*", ("ci",), ()),
)

#: Paths inside crates that run a specialised job. Only the paths a job is
#: about run it (a change below a crate runs that crate's reverse
#: dependencies' tests, not every job that builds it): the push to the base
#: branch runs every job.
CRATE_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # The Python surface in Rust: the binding, and the facade's public API it
    # re-exports. Any other crate's change is the Rust tests' (the maintainer:
    # no wheel, no pytest for a Rust-only change on a pull request).
    ("bindings/python/*", ("python",)),
    ("crates/opentide/src/*", ("python",)),
    # A Python file inside a crate.
    ("*.py", ("pylint",)),
    # The facade's public API: every feature, rustdoc, cargo semver-checks.
    ("crates/opentide/*", ("facade",)),
    # The Node package.
    ("bindings/node/*", ("node",)),
    # The WASI crate and the WASI shims of the crates that have one.
    ("crates/opentide-wasm/*", ("wasi",)),
    ("crates/*wasi*", ("wasi",)),
    ("crates/opentide-cli/src/render/ci.rs", ("gitlab",)),
    ("crates/opentide-cli/src/commands/setup/*", ("gitlab",)),
    ("crates/*/Cargo.toml", ("deny",)),
    ("bindings/*/Cargo.toml", ("deny",)),
    ("xtask/Cargo.toml", ("deny",)),
)

#: The facade's features and opentide-schema's `python`, which the tests build
#: with (the facade crate's job builds every feature).
FEATURES: Mapping[str, str] = {
    "opentide": "opentide/analysis,opentide/cli,opentide/connectors,opentide/lsp,"
    "opentide/plugins,opentide/python,opentide/queries",
    "opentide-schema": "opentide-schema/python",
}

#: The Rust test partitions: two when the heavy crates are affected, one
#: otherwise (a run of the light crates takes well under a minute).
HEAVY_CRATES = frozenset({"opentide-cli", "opentide-analysis", "opentide-lsp", "xtask", "opentide"})


@dataclass
class Plan:
    """What a run checks."""

    mode: str
    release: bool = False
    areas: set[str] = field(default_factory=set)
    crates: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)

    def outputs(self, workspace: Iterable[str]) -> dict[str, str]:
        """The `changes` job's outputs."""
        members = sorted(workspace)
        crates = sorted(self.crates)
        everything = set(crates) == set(members)
        rust = "rust" in self.areas or bool(crates)
        python = "python" in self.areas
        out = {
            "mode": self.mode,
            "release": _bool(self.release),
            "crates": " ".join(crates),
            "packages": "--workspace" if everything else " ".join(f"-p {c}" for c in crates),
            "features": _features(crates),
            "partitions": json.dumps([1, 2] if (everything or HEAVY_CRATES & set(crates)) else [1]),
            "rust": _bool(rust),
            "python": _bool(python),
            "build": _bool(rust or python or "gitlab" in self.areas or "node" in self.areas),
            # The lint job: its steps read pylint, ci, skills and rust.
            "lint": _bool(rust or bool(self.areas & {"pylint", "ci", "skills"})),
        }
        for area in AREAS:
            if area not in {"rust", "python"}:
                out[area] = _bool(area in self.areas)
        return out


def _bool(value: bool) -> str:
    return "true" if value else "false"


def _features(crates: Iterable[str]) -> str:
    chosen = [FEATURES[c] for c in sorted(crates) if c in FEATURES]
    return f"--features {','.join(chosen)}" if chosen else ""


def _matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/*"):
        return path.startswith(pattern[:-1])
    return fnmatch.fnmatchcase(path, pattern)


def workspace_graph(metadata: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Each member's directory (relative to the repository) and its reverse dependencies.

    Every kind of dependency counts (normal, dev, build): a crate whose tests
    use a changed crate is affected too.
    """
    root = str(metadata["workspace_root"]).rstrip("/") + "/"
    members = set(metadata["workspace_members"])
    dirs: dict[str, str] = {}
    rdeps: dict[str, set[str]] = {}
    packages = [p for p in metadata["packages"] if p["id"] in members]
    names = {p["name"] for p in packages}
    for package in packages:
        manifest = str(package["manifest_path"])
        dirs[package["name"]] = manifest.removeprefix(root).rsplit("/", 1)[0]
        rdeps.setdefault(package["name"], set())
    for package in packages:
        for dep in package["dependencies"]:
            if dep.get("path") and dep["name"] in names and dep["name"] != package["name"]:
                rdeps[dep["name"]].add(package["name"])
    return dirs, rdeps


def reverse_closure(crates: Iterable[str], rdeps: Mapping[str, set[str]]) -> set[str]:
    """The crates and everything that depends on them, transitively."""
    seen = set(crates)
    stack = list(seen)
    while stack:
        for parent in rdeps.get(stack.pop(), ()):
            if parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return seen


def owning_crate(path: str, dirs: Mapping[str, str]) -> str | None:
    """The workspace member whose directory holds *path* (the deepest one)."""
    best: tuple[int, str] | None = None
    for name, directory in dirs.items():
        if (
            directory
            and path.startswith(directory + "/")
            and (best is None or len(directory) > best[0])
        ):
            best = (len(directory), name)
    return best[1] if best else None


def everything(plan: Plan, members: Iterable[str], reason: str) -> Plan:
    """Mark every area and every crate."""
    plan.areas.update(AREAS)
    plan.crates.update(members)
    plan.reasons.append(reason)
    return plan


def plan_for_paths(
    paths: Iterable[str], dirs: Mapping[str, str], rdeps: Mapping[str, set[str]]
) -> Plan:
    """What a pull request that changes *paths* must check."""
    plan = Plan(mode="pr")
    members = list(dirs)
    changed: set[str] = set()
    for path in paths:
        if any(_matches(path, pattern) for pattern in EVERYTHING):
            return everything(plan, members, f"{path}: shared configuration, everything runs")
        crate = owning_crate(path, dirs)
        if crate is not None:
            changed.add(crate)
            plan.areas.add("rust")
            for pattern, areas in CRATE_PATHS:
                if _matches(path, pattern):
                    plan.areas.update(areas)
            plan.reasons.append(f"{path}: crate {crate}")
            continue
        for pattern, areas, crates in RULES:
            if _matches(path, pattern):
                plan.areas.update(areas)
                if crates == ALL:
                    changed.update(members)
                else:
                    changed.update(crates)
                plan.reasons.append(f"{path}: {pattern}")
                break
        else:
            return everything(plan, members, f"{path}: no rule, everything runs")
    plan.crates = reverse_closure(changed, rdeps)
    if plan.crates:
        plan.areas.add("rust")
    return plan


def is_release_pr(base_ref: str, head_ref: str, labels: Iterable[str]) -> bool:
    """A pull request into development from integration/unified-core or a
    release/* branch, or one labelled `release`."""
    if "release" in labels:
        return True
    return base_ref == "development" and (
        head_ref == "integration/unified-core" or head_ref.startswith("release/")
    )


def cargo_metadata() -> Mapping[str, Any]:
    """``cargo metadata --no-deps``: the members and their path dependencies,
    without resolving or fetching anything."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def changed_paths(base: str, head: str) -> list[str] | None:
    """The files a pull request changes (base...head), or None when git cannot tell."""
    result = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", f"{base}...{head}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


def plan_run(env: Mapping[str, str], metadata: Mapping[str, Any]) -> Plan:
    """The plan for this run, from its environment."""
    dirs, rdeps = workspace_graph(metadata)
    members = list(dirs)
    event = env.get("EVENT", "")
    scope = env.get("SCOPE", "") or "full"
    if event == "pull_request":
        # toJSON of a missing list is `null`.
        labels = json.loads(env.get("LABELS", "[]") or "[]") or []
        release = is_release_pr(env.get("BASE_REF", ""), env.get("HEAD_REF", ""), labels)
        paths = changed_paths(env.get("BASE_SHA", ""), env.get("HEAD_SHA", ""))
        if paths is None:
            plan = everything(
                Plan(mode="pr"), members, "git cannot read the change: everything runs"
            )
        else:
            plan = plan_for_paths(paths, dirs, rdeps)
        if release:
            # A release pull request checks everything, then the packages.
            plan = everything(plan, members, "a release pull request: everything runs")
        plan.release = release
        return plan
    if event == "schedule" or (event == "workflow_dispatch" and scope == "nightly"):
        return everything(Plan(mode="nightly"), members, f"{event}: the nightly")
    plan = everything(Plan(mode="full"), members, f"{event}: everything, Linux")
    plan.release = event == "workflow_dispatch" and scope == "release"
    return plan


def main(argv: list[str]) -> int:
    metadata = cargo_metadata()
    plan = plan_run(os.environ, metadata)
    dirs, _ = workspace_graph(metadata)
    outputs = plan.outputs(dirs)
    lines = [f"{key}={value}" for key, value in outputs.items()]
    if "--explain" in argv or not os.environ.get("GITHUB_OUTPUT"):
        print("\n".join(plan.reasons[:200]))
        print("\n".join(lines))
    else:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write("### What this run checks\n\n```\n" + "\n".join(lines) + "\n```\n")
                handle.write("\n<details><summary>Why</summary>\n\n```\n")
                handle.write("\n".join(plan.reasons[:500]) + "\n```\n</details>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
