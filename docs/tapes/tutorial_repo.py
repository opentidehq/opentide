"""Build the tutorial's repository for a tape, off camera.

The tapes in this directory record the CLI against the repository that
``docs/usage/tutorial.md`` builds. A tape cannot type three YAML files, so it
runs this script while hidden::

    python3 docs/tapes/tutorial_repo.py DIR              # write the objects only
    python3 docs/tapes/tutorial_repo.py DIR --setup --generate --commit
    python3 docs/tapes/tutorial_repo.py DIR --setup --generate --state dangling-reference

The objects are read from the tutorial page itself, by the same helper the docs
golden test uses, so a tape never shows objects the page does not.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE = Path("objects", "rules", "sentinel-kql-rule.yaml")

#: The edits ``--state`` makes, named like ``REPO_STATES`` in
#: ``tests/test_docs/test_docs_commands_golden.py``.
STATES: dict[str, tuple[Path, str, str]] = {
    # Tutorial step 7: the rule's objective does not exist.
    "dangling-reference": (
        RULE,
        "detection_model: 00000000-0000-4000-8002-000000000001",
        "detection_model: 00000000-0000-4000-8002-DEADBEEF0000",
    ),
}

#: Tutorial step 1, with the same answers.
SETUP = (
    "setup",
    "--yes",
    "--name",
    "Tutorial Detections",
    "--org",
    "Example Corp",
    "--platform",
    "sentinel",
    "--path",
)


def _opentide(*args: str, cwd: Path | None = None) -> None:
    exe = shutil.which("opentide")
    if exe is None:
        raise SystemExit("opentide is not on PATH; run `uv sync` and add .venv/bin to PATH")
    # Plain output: nothing here is on camera, and a failure should read cleanly.
    subprocess.run([exe, "--no-color", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def _git(repo: Path, *args: str) -> None:
    # A runner has no git identity, and the tapes never show this commit.
    identity = ("-c", "user.name=opentide docs", "-c", "user.email=docs@opentide.invalid")
    subprocess.run(["git", *identity, *args], cwd=repo, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repo", type=Path, help="the repository directory")
    parser.add_argument("--setup", action="store_true", help="scaffold it as in tutorial step 1")
    parser.add_argument("--generate", action="store_true", help="run `opentide generate` after")
    parser.add_argument("--state", choices=sorted(STATES), help="break it as a docs sample does")
    parser.add_argument("--commit", action="store_true", help="commit it to git on `main`")
    args = parser.parse_args(argv)

    repo: Path = args.repo.resolve()
    if args.setup:
        _opentide(*SETUP, str(repo))

    sys.path.insert(0, str(ROOT))
    from tests.test_cli.e2e.helpers import write_tutorial_objects

    write_tutorial_objects(repo)
    if args.generate:
        _opentide("generate", cwd=repo)
    if args.state:
        path, old, new = STATES[args.state]
        target = repo / path
        text = target.read_text(encoding="utf-8")
        if old not in text:
            raise SystemExit(f"{path} no longer contains {old!r}; update STATES")
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
    if args.commit:
        _git(repo, "init", "--quiet", "--initial-branch", "main")
        _git(repo, "add", "--all")
        _git(repo, "commit", "--quiet", "--message", "Tutorial detections")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
