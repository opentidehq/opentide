"""Deployment plan resolution for local CLI (issue #164)."""

from __future__ import annotations

import pytest

from opentide.models.deployment_enums import DeploymentStrategy


def test_load_from_environment_defaults_to_full_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEPLOYMENT_PLAN", raising=False)
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.FULL


def test_load_from_environment_defaults_to_full_when_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "  ")
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.FULL


def test_load_from_environment_accepts_named_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "staging")
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.STAGING


def test_load_from_environment_rejects_python_none_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "None")
    with pytest.raises(ValueError, match="Unsupported deployment plan"):
        DeploymentStrategy.load_from_environment()


def test_load_from_environment_rejects_unknown_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "CANARY")
    with pytest.raises(ValueError, match="CANARY"):
        DeploymentStrategy.load_from_environment()
