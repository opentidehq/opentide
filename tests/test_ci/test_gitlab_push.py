"""GitLab write-backs push where ``OPENTIDE_PUSH_URL`` says, and can push and sign over SSH.

They could only push with ``CI_JOB_TOKEN`` over HTTPS, which needs job-token
push rights and a CA the job image trusts. The runner checks out from a
token-less ``origin`` and rewrites that prefix itself, so a project-level
``insteadOf`` to an SSH URL had no effect.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from opentide.ci.gitlab import render_gitlab
from opentide.ci.inflight import (
    GITLAB_PUSH,
    GITLAB_PUSH_URL,
    GITLAB_SSH_NO_KNOWN_HOSTS,
    GITLAB_SSH_NOT_A_FILE,
    gitlab_push_setup,
)
from opentide.ci.models import CiRenderOptions

_GIT = shutil.which("git")
_BASH = shutil.which("bash") or "bash"
pytestmark = pytest.mark.skipif(_GIT is None or _BASH == "bash", reason="needs git and bash")

_SECRET_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key-but-secret\n"


def _bash(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_BASH, "-eo", "pipefail", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def _base_env(**extra: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GIT_", "OPENTIDE_PUSH"))
    }
    env.update(
        {
            "CI_JOB_TOKEN": "job-token-value",
            "CI_SERVER_HOST": "gitlab.example.com",
            "CI_PROJECT_PATH": "detections/catalogue",
            "CI_DEFAULT_BRANCH": "main",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": extra.pop("HOME", env.get("HOME", "/tmp")),
        }
    )
    env.update(extra)
    return env


def _repo(path: Path) -> Path:
    path.mkdir()
    for args in (
        ("init", "-q", "-b", "main"),
        ("config", "user.email", "t@example.com"),
        ("config", "user.name", "t"),
        ("commit", "-q", "--allow-empty", "-m", "seed"),
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


def _config(repo: Path, key: str) -> str:
    done = subprocess.run(
        ["git", "config", "--local", "--get", key], cwd=repo, capture_output=True, text=True
    )
    return done.stdout.strip()


# --- Where the push goes ----------------------------------------------------------------


def test_the_push_defaults_to_the_job_token(tmp_path: Path) -> None:
    done = _bash(f"printf %s {GITLAB_PUSH_URL}", tmp_path, _base_env())
    assert (
        done.stdout
        == "https://gitlab-ci-token:job-token-value@gitlab.example.com/detections/catalogue.git"
    )


def test_opentide_push_url_replaces_the_job_token_url(tmp_path: Path) -> None:
    env = _base_env(OPENTIDE_PUSH_URL="git@gitlab.example.com:detections/catalogue.git")
    done = _bash(f"printf %s {GITLAB_PUSH_URL}", tmp_path, env)
    assert done.stdout == "git@gitlab.example.com:detections/catalogue.git"


def test_the_write_back_pushes_to_opentide_push_url(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    work = _repo(tmp_path / "work")
    done = _bash(GITLAB_PUSH, work, _base_env(OPENTIDE_PUSH_URL=str(remote)))
    assert done.returncode == 0, done.stderr
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True, check=True
    ).stdout
    pushed = subprocess.run(
        ["git", "rev-parse", "main"], cwd=remote, capture_output=True, text=True, check=True
    ).stdout
    assert pushed == head


def _pushing_jobs() -> dict[str, dict]:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"], inflight=True, sharing=True)
    parsed = yaml.safe_load(render_gitlab(options))
    return {
        name: job
        for name, job in parsed.items()
        if isinstance(job, dict) and "git push" in "\n".join(job.get("script", []))
    }


def test_every_write_back_uses_the_push_url_and_the_ssh_setup() -> None:
    jobs = _pushing_jobs()
    assert set(jobs) == {"deploy_production", "inflight_shards", "inflight_prune"}
    for name, job in jobs.items():
        script = job["script"]
        text = "\n".join([*script, *job.get("after_script", [])])
        pushes = [line for line in text.splitlines() if "git push" in line]
        assert pushes, name
        assert all(GITLAB_PUSH_URL in line for line in pushes), (name, pushes)
        # The setup comes before any commit, so the commits are signed.
        setup = script.index(gitlab_push_setup() + "\n")
        first_commit = next(i for i, line in enumerate(script) if "git commit" in line)
        assert setup < first_commit, name


def test_no_script_echoes_a_secret() -> None:
    options = CiRenderOptions(ci="gitlab", platforms=["sentinel"], inflight=True, sharing=True)
    parsed = yaml.safe_load(render_gitlab(options))
    secrets = ("$CI_JOB_TOKEN", "${CI_JOB_TOKEN}", "$OPENTIDE_PUSH_URL", "${OPENTIDE_PUSH_URL")
    for name, job in parsed.items():
        if not isinstance(job, dict):
            continue
        for key in ("before_script", "script", "after_script"):
            for line in "\n".join(job.get(key, [])).splitlines():
                assert "set -x" not in line, (name, line)
                if line.lstrip().startswith(("echo", "printf")):
                    assert not any(secret in line for secret in secrets), (name, line)


# --- SSH --------------------------------------------------------------------------------


def _stub_bin(tmp_path: Path, *, with_ssh: bool) -> Path:
    """A PATH with git and chmod, a recording apt-get, and ssh-keygen only if asked."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("git", "chmod"):
        found = shutil.which(tool)
        assert found
        (bin_dir / tool).symlink_to(found)
    stubs = {"apt-get": f'echo "$@" > {tmp_path / "apt-get.args"}\n'}
    if with_ssh:
        stubs["ssh-keygen"] = "exit 0\n"
    for tool, body in stubs.items():
        path = bin_dir / tool
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)
    return bin_dir


def _key_files(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "OPENTIDE_PUSH_SSH_KEY"
    key.write_text(_SECRET_KEY, encoding="utf-8")
    key.chmod(0o644)
    hosts = tmp_path / "OPENTIDE_PUSH_SSH_KNOWN_HOSTS"
    hosts.write_text("gitlab.example.com ssh-ed25519 AAAA\n", encoding="utf-8")
    return key, hosts


def test_without_a_key_the_setup_changes_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    done = _bash(gitlab_push_setup(), repo, _base_env())
    assert done.returncode == 0, done.stderr
    assert done.stdout == done.stderr == ""
    assert _config(repo, "core.sshCommand") == ""
    assert _config(repo, "commit.gpgsign") == ""


def test_a_key_pushes_and_signs_with_strict_host_checking(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    key, hosts = _key_files(tmp_path)
    env = _base_env(
        OPENTIDE_PUSH_SSH_KEY=str(key),
        OPENTIDE_PUSH_SSH_KNOWN_HOSTS=str(hosts),
        PATH=str(_stub_bin(tmp_path, with_ssh=True)),
    )
    done = _bash(gitlab_push_setup(), repo, env)
    assert done.returncode == 0, done.stderr
    command = _config(repo, "core.sshCommand")
    assert command == (
        f'ssh -i "{key}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes '
        f'-o UserKnownHostsFile="{hosts}"'
    )
    assert _config(repo, "gpg.format") == "ssh"
    assert _config(repo, "user.signingkey") == str(key)
    assert _config(repo, "commit.gpgsign") == "true"
    # ssh refuses a private key others can read.
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert "secret" not in done.stdout + done.stderr
    # ssh-keygen was there, so nothing was installed.
    assert not (tmp_path / "apt-get.args").exists()


def test_a_key_installs_openssh_when_the_image_has_none(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    key, hosts = _key_files(tmp_path)
    env = _base_env(
        OPENTIDE_PUSH_SSH_KEY=str(key),
        OPENTIDE_PUSH_SSH_KNOWN_HOSTS=str(hosts),
        PATH=str(_stub_bin(tmp_path, with_ssh=False)),
    )
    done = _bash(gitlab_push_setup(), repo, env)
    assert done.returncode == 0, done.stderr
    args = (tmp_path / "apt-get.args").read_text(encoding="utf-8")
    assert "install" in args and "openssh-client" in args


def test_a_key_without_known_hosts_refuses(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    key, _ = _key_files(tmp_path)
    env = _base_env(OPENTIDE_PUSH_SSH_KEY=str(key), PATH=str(_stub_bin(tmp_path, with_ssh=True)))
    done = _bash(gitlab_push_setup(), repo, env)
    assert done.returncode == 1
    assert GITLAB_SSH_NO_KNOWN_HOSTS in done.stderr
    assert _config(repo, "core.sshCommand") == ""


def test_a_key_given_as_text_not_a_file_refuses(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    env = _base_env(OPENTIDE_PUSH_SSH_KEY=_SECRET_KEY, PATH=str(_stub_bin(tmp_path, with_ssh=True)))
    done = _bash(gitlab_push_setup(), repo, env)
    assert done.returncode == 1
    assert GITLAB_SSH_NOT_A_FILE in done.stderr
    assert "secret" not in done.stdout + done.stderr
