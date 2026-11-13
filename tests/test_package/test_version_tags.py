"""opentide's version comes from its own `vX.Y.Z` tags, never the engine's.

hatch-vcs (setuptools-scm) derives the version from `git describe`. The engine
released from this repository with `engine-vX.Y.Z` tags (engine-release.yml)
until the release train (publish.yml) gave everything one `vX.Y.Z`; those tags
remain, and setuptools-scm's defaults (`git describe --tags --match *[0-9]*`, a tag
regex that drops any `word-` prefix) read the nearest of those as opentide's
version: a clone whose nearest tag is `engine-v9.9.9` built opentide 9.9.9.
pyproject.toml's `[tool.hatch.version.raw-options]` describes and parses `v`
tags only. Reported by UC-X.1 (#858).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


def _version_config() -> dict[str, Any]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["tool"]["hatch"]["version"]


def test_only_v_tags_are_described_and_parsed() -> None:
    config = _version_config()
    assert config["source"] == "vcs"
    raw = config["raw-options"]
    command = raw["git_describe_command"]
    assert command[:2] == ["git", "describe"]
    assert command[command.index("--match") + 1] == "v[0-9]*"
    regex = re.compile(raw["tag_regex"])
    for tag, version in [("v0.23.0", "0.23.0"), ("v1.2.3rc1", "1.2.3rc1"), ("v10.0.0", "10.0.0")]:
        match = regex.match(tag)
        assert match is not None, tag
        assert match.group("version") == version
    for tag in ["engine-v9.9.9", "engine-v0.11.1-rc.1", "9.9.9", "release-1.0.0"]:
        assert regex.match(tag) is None, tag


def _git(repo: Path, *args: str) -> None:
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


def _toml_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    # A literal string: the regex's backslashes stay as they are.
    assert "'" not in str(value)
    return f"'{value}'"


@pytest.mark.cli_e2e
def test_a_nearer_engine_tag_is_not_opentides_version(tmp_path: Path) -> None:
    """The build backend's own answer, in a repository whose nearest tag is the engine's."""
    uvx = shutil.which("uvx")
    if uvx is None or shutil.which("git") is None:
        pytest.skip("needs uvx and git")
    raw = _version_config()["raw-options"]
    options = "\n".join(f"{key} = {_toml_value(value)}" for key, value in raw.items())
    repo = tmp_path / "repo"
    (repo / "src" / "pkg").mkdir(parents=True)
    (repo / "src" / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        f"""[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[project]
name = "pkg"
dynamic = ["version"]

[tool.hatch.version]
source = "vcs"

[tool.hatch.version.raw-options]
{options}

[tool.hatch.build.targets.wheel]
packages = ["src/pkg"]
""",
        encoding="utf-8",
    )
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "opentide 0.23.0")
    _git(repo, "tag", "v0.23.0")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "an engine release")
    _git(repo, "tag", "engine-v9.9.9")
    done = subprocess.run(
        [uvx, "--quiet", "--from", "hatch", "--with", "hatch-vcs", "hatch", "version"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    version = done.stdout.strip().splitlines()[-1]
    # One commit past v0.23.0: the next development version, not 9.9.9.
    assert version.startswith("0.23.1.dev1"), version
