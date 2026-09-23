"""Every ``CiSetupOptions`` field must change what ``setup ci`` writes.

#307: ``--no-promotion`` and ``--promotion-target`` were accepted, forwarded to
the renderers and ignored, so setup exited ``OK`` and ``deploy`` still promoted
to ``PRODUCTION``. A parity test (accepted + forwarded) cannot see that.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from opentide.cli.enums import CiPlatform
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup

#: Fields with no output of their own, and why.
_NO_OUTPUT_OF_THEIR_OWN = {
    "path": "picks the directory; the files under it are what is compared",
    "yes": "consent to write, asked for by the CLI before run_ci_setup runs",
}

#: A non-default value for each field that is not a flag.
_SAMPLES: dict[str, object] = {
    "ci": CiPlatform.gitlab,
    "promotion": False,
    "promotion_target": "STAGING",
    "python_version": "3.11",
    "default_branch": "release",
}

_FIELDS = {field.name: field for field in dataclasses.fields(CiSetupOptions)}
_SHAPING = sorted(set(_FIELDS) - set(_NO_OUTPUT_OF_THEIR_OWN))


def _sample(name: str) -> object:
    default = _FIELDS[name].default
    return not default if isinstance(default, bool) else _SAMPLES[name]


@pytest.fixture(autouse=True)
def _no_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Branch detection must not find a global ``init.defaultBranch`` equal to a sample."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _written(target: Path, options: CiSetupOptions) -> dict[str, bytes]:
    """Every file under *target* after ``run_ci_setup``, by relative path."""
    platforms = target / ".opentide" / "configurations" / "platforms"
    platforms.mkdir(parents=True)
    (platforms / "sentinel.toml").write_text("[platform]\nenabled = true\n", encoding="utf-8")
    run_ci_setup(dataclasses.replace(options, path=target, yes=True))
    return {
        path.relative_to(target).as_posix(): path.read_bytes()
        for path in sorted(target.rglob("*"))
        if path.is_file()
    }


def test_every_ci_setup_option_has_a_sample_or_a_reason() -> None:
    assert set(_NO_OUTPUT_OF_THEIR_OWN) <= set(_FIELDS), "allow-list names a field that is gone"
    valued = {name for name in _SHAPING if not isinstance(_FIELDS[name].default, bool)}
    assert valued == set(_SAMPLES)
    assert all(_sample(name) != _FIELDS[name].default for name in _SHAPING)


@pytest.mark.parametrize("name", _SHAPING)
def test_ci_setup_option_changes_what_setup_writes(tmp_path: Path, name: str) -> None:
    baseline = _written(tmp_path / "default", CiSetupOptions())

    written = _written(tmp_path / name, CiSetupOptions(**{name: _sample(name)}))

    changed = sorted(
        p for p in baseline.keys() | written.keys() if baseline.get(p) != written.get(p)
    )
    assert changed, (
        f"{name}={_sample(name)!r} is accepted but changes no pipeline "
        "or .opentide/configurations file"
    )
