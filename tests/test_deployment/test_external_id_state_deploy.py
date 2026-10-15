"""Deploy reads and writes vendor rule ids through deployment state shards (RFC 0010 §5).

Every vendor client is mocked. "No HTTP" is asserted as "the client class was
never instantiated": the services authenticate in their constructor.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS, clear_runtime_caches

from opentide.deployment.external_ids import plan_external_id, record_created
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.states.deployment import DeploymentStateError, record_external_id, shard_path

DEFENDER = CORPUS_RULE_UUIDS["defender_for_endpoint"]
SENTINEL_ONE = CORPUS_RULE_UUIDS["sentinel_one"]
CROWDSTRIKE = CORPUS_RULE_UUIDS["crowdstrike"]
HARFANGLAB = CORPUS_RULE_UUIDS["harfanglab"]


@pytest.fixture(autouse=True)
def _deployment_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


def _rule_file(repo: Path, uuid: str) -> Path:
    for path in (repo / "objects" / "rules").glob("*.yaml"):
        if uuid in path.read_text(encoding="utf-8"):
            return path
    raise AssertionError(f"no corpus rule {uuid}")


def _edit_block(
    repo: Path, uuid: str, platform: str, *, status: str | None, extra: str = ""
) -> Path:
    """Rewrite the rule before the registry loads it."""
    path = _rule_file(repo, uuid)
    text = path.read_text(encoding="utf-8")
    if status is not None:
        text = text.replace("status: STAGING", f"status: {status}")
    if extra:
        text = text.replace(f"  {platform}:\n", f"  {platform}:\n    {extra}\n", 1)
    path.write_text(text, encoding="utf-8")
    # The fixtures may already have built the object index; read the edit.
    clear_runtime_caches()
    return path


def _route(module: Any, monkeypatch: pytest.MonkeyPatch, tenant: Any) -> None:
    """Send every rule to one tenant, without the platform toml."""

    def tide_deployment(deployment: list[Any], system: Any, strategy: Any) -> Any:
        del system, strategy
        return SimpleNamespace(rule_deployment=[SimpleNamespace(tenant=tenant, rules=deployment)])

    monkeypatch.setattr(module, "TideDeployment", tide_deployment)


def _service(module: Any, monkeypatch: pytest.MonkeyPatch, name: str) -> MagicMock:
    service_class = MagicMock(name=name)
    monkeypatch.setattr(module, name, service_class)
    return service_class


def _shard(repo: Path, uuid: str) -> dict[str, Any] | None:
    path = shard_path(uuid, repo)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _failed() -> bool:
    return bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))


# --- Defender for Endpoint ---------------------------------------------------


@pytest.fixture
def defender(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., MagicMock]:
    from opentide.platforms.defender_for_endpoint import deployer as module

    _route(module, monkeypatch, SimpleNamespace(name="contoso"))
    service_class = _service(module, monkeypatch, "DefenderForEndpointService")
    service_class.return_value.create_detection_rule.return_value = 12345

    def run() -> MagicMock:
        module.DefenderForEndpointDeploy().deploy([DEFENDER], DeploymentStrategy.FULL)
        return service_class

    return run


def test_defender_create_writes_the_returned_id_to_the_shard(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    rule = _rule_file(tide_corpus_repo, DEFENDER)
    before = rule.read_text(encoding="utf-8")

    service_class = defender()

    service = service_class.return_value
    service.create_detection_rule.assert_called_once()
    service.update_detection_rule.assert_not_called()
    assert _shard(tide_corpus_repo, DEFENDER) == {
        "object_uuid": DEFENDER,
        "platforms": {"defender_for_endpoint": {"contoso": "12345"}},
        "schema": "deployment.state::1.0",
    }
    assert rule.read_text(encoding="utf-8") == before
    assert not _failed()


def _spy_logger(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    from opentide.deployment import external_ids

    spy = MagicMock(wraps=external_ids.logger)
    monkeypatch.setattr(external_ids, "logger", spy)
    return spy


def _events(method: MagicMock) -> list[str]:
    return [call.args[0] for call in method.call_args_list]


def test_a_recorded_id_is_logged_at_the_default_console_level(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CI log is the last copy of an id whose runner is gone (console default: WARNING)."""
    spy = _spy_logger(monkeypatch)

    defender()

    assert "external_id_recorded" in _events(spy.warning)
    assert "external_id_recorded" not in _events(spy.info)
    call = spy.warning.call_args_list[_events(spy.warning).index("external_id_recorded")]
    assert call.kwargs["external_id"] == "12345"


def test_defender_update_uses_the_shard_id(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 777, tide_corpus_repo)

    service = defender().return_value

    service.create_detection_rule.assert_not_called()
    service.update_detection_rule.assert_called_once()
    assert service.update_detection_rule.call_args.args[1] == "777"
    assert _shard(tide_corpus_repo, DEFENDER)["platforms"] == {
        "defender_for_endpoint": {"contoso": "777"}
    }


def test_defender_disablement_is_an_update_that_keeps_the_entry(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    _edit_block(tide_corpus_repo, DEFENDER, "defender_for_endpoint", status="DISABLED")
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 777, tide_corpus_repo)

    service = defender().return_value

    service.update_detection_rule.assert_called_once()
    sent = service.update_detection_rule.call_args.args[0]
    assert sent.isEnabled is False
    assert _shard(tide_corpus_repo, DEFENDER) is not None


def test_defender_delete_removes_the_entry_and_the_file(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    _edit_block(tide_corpus_repo, DEFENDER, "defender_for_endpoint", status="REMOVED")
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 777, tide_corpus_repo)

    service = defender().return_value

    service.delete_detection_rule.assert_called_once_with("777")
    assert not shard_path(DEFENDER, tide_corpus_repo).exists()


def test_defender_delete_keeps_other_tenants(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    _edit_block(tide_corpus_repo, DEFENDER, "defender_for_endpoint", status="REMOVED")
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 777, tide_corpus_repo)
    record_external_id(DEFENDER, "defender_for_endpoint", "fabrikam", 888, tide_corpus_repo)

    defender()

    assert _shard(tide_corpus_repo, DEFENDER)["platforms"] == {
        "defender_for_endpoint": {"fabrikam": "888"}
    }


@pytest.mark.parametrize("status", ["REMOVED", "DISABLED"])
def test_defender_deletion_without_entry_is_an_external_id_missing_warning_with_no_http(
    tide_corpus_repo: Path,
    defender: Callable[[], MagicMock],
    status: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retiring a rule that never reached this tenant warns; it must not fail the run."""
    _edit_block(tide_corpus_repo, DEFENDER, "defender_for_endpoint", status=status)
    spy = _spy_logger(monkeypatch)

    service_class = defender()

    service_class.assert_not_called()
    assert not _failed()
    assert os.environ.get("DEPLOYMENT_WARNING_RAISED") == "1"
    assert _events(spy.warning) == ["external_id_missing"]
    assert _events(spy.error) == []
    assert _shard(tide_corpus_repo, DEFENDER) is None
    with pytest.raises(DeploymentStateError) as caught:
        plan_external_id(
            object_uuid=DEFENDER,
            platform="defender_for_endpoint",
            tenant_name="contoso",
            status=status,
        )
    assert caught.value.code == "external_id_missing"
    assert "nothing is known to exist on that tenant" in caught.value.message
    assert "removed by hand" in caught.value.message


@pytest.mark.parametrize(
    "legacy",
    [
        "rule_id::contoso: 7590",
        "rule_id:\n      contoso: 7590",
        "rule_id_bundle:\n      contoso: 7590",
    ],
)
def test_defender_legacy_key_is_external_id_in_rule_with_no_http(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock], legacy: str
) -> None:
    _edit_block(tide_corpus_repo, DEFENDER, "defender_for_endpoint", status=None, extra=legacy)
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 7590, tide_corpus_repo)

    service_class = defender()

    service_class.assert_not_called()
    assert _failed()
    with pytest.raises(DeploymentStateError) as caught:
        plan_external_id(
            object_uuid=DEFENDER,
            platform="defender_for_endpoint",
            tenant_name="contoso",
            status="STAGING",
        )
    assert caught.value.code == "external_id_in_rule"


def test_defender_legacy_key_on_another_block_still_refuses(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    path = _rule_file(tide_corpus_repo, DEFENDER)
    text = path.read_text(encoding="utf-8").rstrip("\n")
    path.write_text(
        text + "\n  harfanglab:\n    status: DESIGN\n    rule_id_bundle:\n      hl: abc\n",
        encoding="utf-8",
    )
    clear_runtime_caches()

    defender().assert_not_called()
    assert _failed()


def test_defender_create_refused_while_shards_are_gitignored(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    (tide_corpus_repo / ".gitignore").write_text(".opentide/states/\n", encoding="utf-8")

    defender().assert_not_called()

    assert _failed()
    assert _shard(tide_corpus_repo, DEFENDER) is None


def test_defender_update_with_gitignored_shard_runs_and_warns(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    (tide_corpus_repo / ".gitignore").write_text(".opentide/states/\n", encoding="utf-8")
    record_external_id(DEFENDER, "defender_for_endpoint", "contoso", 777, tide_corpus_repo)

    service = defender().return_value

    service.update_detection_rule.assert_called_once()
    assert not _failed()
    assert os.environ.get("DEPLOYMENT_WARNING_RAISED")


def test_defender_mismatched_shard_creates_nothing(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    path = shard_path(DEFENDER, tide_corpus_repo)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema": "deployment.state::1.0",
                "object_uuid": CORPUS_RULE_UUIDS["sentinel"],
                "platforms": {},
            }
        ),
        encoding="utf-8",
    )

    defender().assert_not_called()
    assert _failed()


def test_defender_misspelt_shard_name_creates_nothing(
    tide_corpus_repo: Path, defender: Callable[[], MagicMock]
) -> None:
    """An unhyphenated (or, on Linux, uppercase) file is missed by name: refuse, never create."""
    path = shard_path(DEFENDER, tide_corpus_repo)
    path.parent.mkdir(parents=True)
    path.with_name(DEFENDER.replace("-", "") + ".json").write_text(
        json.dumps(
            {
                "schema": "deployment.state::1.0",
                "object_uuid": DEFENDER,
                "platforms": {"defender_for_endpoint": {"contoso": "7"}},
            }
        ),
        encoding="utf-8",
    )

    defender().assert_not_called()
    assert _failed()
    assert not path.exists()


def test_defender_shard_write_failure_reports_the_id_and_keeps_the_rule(
    tide_corpus_repo: Path,
    defender: Callable[[], MagicMock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentide.deployment import external_ids

    def broken(*args: object, **kwargs: object) -> str:
        raise OSError("disk full")

    monkeypatch.setattr(external_ids, "record_external_id", broken)

    service = defender().return_value

    service.create_detection_rule.assert_called_once()
    service.delete_detection_rule.assert_not_called()
    assert _failed()
    with pytest.raises(DeploymentStateError) as caught:
        record_created(
            object_uuid=DEFENDER,
            platform="defender_for_endpoint",
            tenant_name="contoso",
            external_id=12345,
        )
    assert caught.value.code == "deployment_state_write_failed"
    assert "12345" in caught.value.message


# --- SentinelOne and CrowdStrike ----------------------------------------------


@pytest.fixture
def sentinel_one(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[], MagicMock]:
    from opentide.platforms.sentinel_one import deployer as module

    _route(module, monkeypatch, SimpleNamespace(name=" s1-prod "))
    monkeypatch.setattr(module.SentinelOneDeploy, "compile_deployment", lambda *a, **k: "payload")
    service_class = _service(module, monkeypatch, "SentinelOneService")
    service_class.return_value.create_update_detection_rule.return_value = 4242

    def run() -> MagicMock:
        module.SentinelOneDeploy().deploy([SENTINEL_ONE], DeploymentStrategy.FULL)
        return service_class

    return run


def test_sentinel_one_create_then_update_round_trip(
    tide_corpus_repo: Path, sentinel_one: Callable[[], MagicMock]
) -> None:
    service = sentinel_one().return_value
    service.create_update_detection_rule.assert_called_once_with("payload")
    assert _shard(tide_corpus_repo, SENTINEL_ONE)["platforms"] == {
        "sentinel_one": {"s1-prod": "4242"}
    }

    service.reset_mock()
    sentinel_one()
    service.create_update_detection_rule.assert_called_once_with("payload", 4242)


def test_sentinel_one_delete_passes_an_integer_and_drops_the_file(
    tide_corpus_repo: Path, sentinel_one: Callable[[], MagicMock]
) -> None:
    _edit_block(tide_corpus_repo, SENTINEL_ONE, "sentinel_one", status="REMOVED")
    record_external_id(SENTINEL_ONE, "sentinel_one", "s1-prod", 4242, tide_corpus_repo)

    sentinel_one().return_value.delete_detection_rule.assert_called_once_with(rule_id=4242)
    assert not shard_path(SENTINEL_ONE, tide_corpus_repo).exists()


@pytest.fixture
def crowdstrike(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[], MagicMock]:
    from opentide.platforms.crowdstrike import deployer as module

    _route(module, monkeypatch, SimpleNamespace(name="falcon-prod"))
    monkeypatch.setattr(module.CrowdstrikeDeploy, "compile_deployment", lambda *a, **k: "payload")
    service_class = _service(module, monkeypatch, "CrowdstrikeService")
    service_class.return_value.create_detection_rule.return_value = (
        "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22"
    )

    def run() -> MagicMock:
        module.CrowdstrikeDeploy().deploy([CROWDSTRIKE], DeploymentStrategy.FULL)
        return service_class

    return run


def test_crowdstrike_create_stores_the_id_verbatim(
    tide_corpus_repo: Path, crowdstrike: Callable[[], MagicMock]
) -> None:
    crowdstrike()
    assert _shard(tide_corpus_repo, CROWDSTRIKE)["platforms"] == {
        "crowdstrike": {"falcon-prod": "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22"}
    }


def test_crowdstrike_update_and_delete_use_the_shard(
    tide_corpus_repo: Path, crowdstrike: Callable[[], MagicMock]
) -> None:
    record_external_id(CROWDSTRIKE, "crowdstrike", "falcon-prod", "00ab", tide_corpus_repo)
    service = crowdstrike().return_value
    service.update_detection_rule.assert_called_once_with(rule="payload", rule_id="00ab")


def test_crowdstrike_legacy_bundle_is_refused_with_no_http(
    tide_corpus_repo: Path, crowdstrike: Callable[[], MagicMock]
) -> None:
    _edit_block(
        tide_corpus_repo,
        CROWDSTRIKE,
        "crowdstrike",
        status=None,
        extra="rule_id_bundle:\n      falcon-prod: abc",
    )
    crowdstrike().assert_not_called()
    assert _failed()
    assert _shard(tide_corpus_repo, CROWDSTRIKE) is None


# --- HarfangLab never stored an id, but the key is still refused ---------------


def test_harfanglab_legacy_bundle_is_refused_before_the_client(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from opentide.platforms.harfanglab import deployer as module

    _edit_block(
        tide_corpus_repo, HARFANGLAB, "harfanglab", status=None, extra="rule_id::hl-prod: abc"
    )
    _route(
        module, monkeypatch, SimpleNamespace(name="hl-prod", setup=SimpleNamespace(type="Sigma"))
    )
    service_class = _service(module, monkeypatch, "HarfangLabService")

    module.HarfangLabDeploy().deploy([HARFANGLAB], DeploymentStrategy.FULL)

    service_class.return_value.create_or_update_sigma_rule.assert_not_called()
    assert _failed()
    assert _shard(tide_corpus_repo, HARFANGLAB) is None
