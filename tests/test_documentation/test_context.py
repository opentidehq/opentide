from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from opentide.documentation.context import resolve_flavor
from opentide.documentation.types import DocumentFlavor

_CI_VARIABLES = ("TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "CI")


@pytest.fixture(autouse=True)
def _no_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def _repo(tmp_path: Path, origin: str | None) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    if origin is not None:
        subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", origin], check=True)
    return tmp_path


def test_resolve_flavor_github_actions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert resolve_flavor(root=_repo(tmp_path, None)) is DocumentFlavor.github


def test_resolve_flavor_gitlab_ci(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITLAB_CI", "true")
    assert resolve_flavor(root=_repo(tmp_path, None)) is DocumentFlavor.gitlab


def test_resolve_flavor_azure_pipelines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TF_BUILD", "True")
    assert resolve_flavor(root=_repo(tmp_path, None)) is DocumentFlavor.azure_devops


def test_another_ci_is_not_read_as_gitlab(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Jenkins and CircleCI set only CI; that used to select the GitLab flavor."""
    monkeypatch.setenv("CI", "true")
    assert resolve_flavor(root=_repo(tmp_path, None)) is DocumentFlavor.generic


@pytest.mark.parametrize(
    ("origin", "flavor"),
    [
        ("https://github.com/org/detections.git", DocumentFlavor.github),
        ("git@github.com:org/detections.git", DocumentFlavor.github),
        ("https://github.example.com/org/detections", DocumentFlavor.github),
        ("https://gitlab.com/org/detections.git", DocumentFlavor.gitlab),
        ("ssh://git@gitlab.example.org:2222/org/detections.git", DocumentFlavor.gitlab),
        ("https://dev.azure.com/org/project/_git/detections", DocumentFlavor.azure_devops),
        ("org@vs-ssh.visualstudio.com:v3/org/project/detections", DocumentFlavor.azure_devops),
        ("git@ssh.dev.azure.com:v3/org/project/detections", DocumentFlavor.azure_devops),
        ("https://git.example.com/detections.git", DocumentFlavor.generic),
    ],
)
def test_a_local_run_follows_the_origin_remote(
    tmp_path: Path, origin: str, flavor: DocumentFlavor
) -> None:
    assert resolve_flavor(root=_repo(tmp_path, origin)) is flavor


def test_without_a_remote_or_repository_the_configured_default_applies(tmp_path: Path) -> None:
    assert resolve_flavor(default="gitlab", root=_repo(tmp_path, None)) is DocumentFlavor.gitlab
    plain = tmp_path / "plain"
    plain.mkdir()
    assert resolve_flavor(root=plain) is DocumentFlavor.generic


def test_ci_beats_the_remote_and_the_override_beats_everything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repo(tmp_path, "https://gitlab.com/org/detections.git")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert resolve_flavor(root=root) is DocumentFlavor.github
    assert resolve_flavor(override="generic", root=root) is DocumentFlavor.generic
