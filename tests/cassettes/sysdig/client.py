"""The Sysdig scenario's client: the Python deployer, rule by rule, as deploy runs it.

The tide corpus's Sysdig rule (``rule-0013-sysdig-falco.yaml``), loaded and
compiled by the oracle, goes through ``SysdigDeploy.deploy_api`` on one
tenant: created (and added to the tenant's runtime policy), updated, renamed,
disabled (taken out of the policy), deleted; a recorded rule the tenant no
longer holds is created again, or forgotten when it is to be disabled; then
a policy the tenant does not have, a rule the tenant will not compile, and a
token the tenant refuses. Each step's outcome (the deployment state and the
flags the deployer raises) is printed, one JSON line each, for the Rust
test's expectations (``crates/opentide-connectors/tests/sysdig.rs``).
Recorded by ``cargo xtask cassettes record``; the oracle's own modules,
unpatched.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

CORPUS = Path("tests/fixtures/tide_corpus/current").resolve()
RULE_FILE = "rule-0013-sysdig-falco.yaml"
UUID = "00000000-0000-4000-8003-0000005d1a90"
ROOT = Path(tempfile.mkdtemp(prefix="sysdig-cassette-"))
shutil.copytree(CORPUS / "Configurations", ROOT / ".opentide" / "configurations")
(ROOT / "objects" / "rules").mkdir(parents=True)
shutil.copy(CORPUS / "Objects" / "Detection Rules" / RULE_FILE, ROOT / "objects" / "rules")
os.environ["OPENTIDE_REPO_ROOT"] = str(ROOT)
os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(ROOT)
for flag in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED", "CI"):
    os.environ.pop(flag, None)
os.chdir(ROOT)

import yaml  # noqa: E402 -- the workspace is set before opentide loads
from opentide.models.system_config import ConfigurationModels  # noqa: E402

from opentide.deployment.external_ids import ExternalIdAction  # noqa: E402
from opentide.loading.rule_loader import load_rule_from_dict  # noqa: E402
from opentide.platforms.sysdig.client import SysdigClient, SysdigTenantError  # noqa: E402
from opentide.platforms.sysdig.deployer import SysdigDeploy  # noqa: E402
from opentide.states.deployment import shard_path  # noqa: E402

Tenant = ConfigurationModels.Systems.Sysdig.Tenant
DOCUMENT = yaml.safe_load((ROOT / "objects" / "rules" / RULE_FILE).read_text(encoding="utf-8"))


def rule(status: str = "STAGING", name: str | None = None) -> Any:
    data = copy.deepcopy(DOCUMENT)
    data["configurations"]["sysdig"]["status"] = status
    if name is not None:
        data["name"] = name
    return load_rule_from_dict(data, file=ROOT / "objects" / "rules" / RULE_FILE)


def tenant(policies: list[str] | None = None) -> Any:
    import dataclasses

    values = {field.name: None for field in dataclasses.fields(Tenant.Setup)} | {
        "ssl": True,
        "url": "https://sysdig-tenant.invalid/",
        "api_token": os.environ["SYSDIG_SECURE_API_TOKEN"],
        "policies": ["opentide managed detections"] if policies is None else policies,
        "tags": ["team-blue"],
    }
    return Tenant(name="staging", description="", setup=Tenant.Setup(**values))


def recorded() -> str | None:
    """The rule's deployment-state shard, as written."""
    path = shard_path(UUID, ROOT)
    return path.read_text(encoding="utf-8") if path.exists() else None


def step(label: str, action: ExternalIdAction, **kwargs: Any) -> None:
    for flag in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        os.environ.pop(flag, None)
    target = tenant(kwargs.pop("policies", None))
    client = SysdigClient(
        target.setup.url, target.setup.api_token, tenant=target.name, verify_ssl=True
    )
    outcome: dict[str, Any] = {"step": label}
    try:
        SysdigDeploy().deploy_api(rule(**kwargs), client, target, action)
    except SysdigTenantError as error:
        outcome["tenant_error"] = str(error)
    outcome["state"] = recorded()
    outcome["error"] = bool(os.environ.get("DEPLOYMENT_ERROR_RAISED"))
    outcome["warning"] = bool(os.environ.get("DEPLOYMENT_WARNING_RAISED"))
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def main() -> None:
    step("create", ExternalIdAction("create"))
    step("update", ExternalIdAction("update", "42"))
    step("rename", ExternalIdAction("update", "42"), name="Sysdig Falco Rule (renamed)")
    step(
        "disable",
        ExternalIdAction("update", "42"),
        status="DISABLED",
        name="Sysdig Falco Rule (renamed)",
    )
    step(
        "delete",
        ExternalIdAction("delete", "42"),
        status="REMOVED",
        name="Sysdig Falco Rule (renamed)",
    )
    step("recreate", ExternalIdAction("update", "42"))
    step("disable-missing", ExternalIdAction("update", "99"), status="DISABLED")
    step(
        "missing-policy",
        ExternalIdAction("create"),
        policies=["opentide managed detections", "No such policy"],
    )
    step("rejected", ExternalIdAction("create"), name="Rejected rule")
    step("refused-token", ExternalIdAction("update", "401"))


if __name__ == "__main__":
    main()
