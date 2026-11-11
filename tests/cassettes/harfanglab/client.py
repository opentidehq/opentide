"""The HarfangLab scenarios' client: the Python implementation, as deploy and query run it.

``deploy``: the deployer's client (``HarfangLabService``): a Sigma rule created
(its ``PUT`` is a 404, then ``POST``), updated and disabled (``PUT``) and
deleted, a YARA file created and deleted, then refusals: a 400, a 403 and a
delete of a rule the tenant does not hold. ``query``: the telemetry runner
(``HarfangLabQueryRunner``) on a source with filters (quoted, a Windows
path), a 400, a gateway's HTML page, and a query it refuses before any
request. Each outcome is printed, one JSON line each, for the Rust tests'
expectations (``crates/opentide-connectors/tests/harfanglab.rs``). Recorded by
``cargo xtask cassettes record``; the oracle's own modules, but for the
registry lookup its constructor cannot make (see :func:`service`).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from opentide.models.system_config import ConfigurationModels as C

from opentide.platforms.harfanglab import client
from opentide.platforms.harfanglab.client import SigmaRule, YaraRule
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow

RULE_ID = "00000000-0000-4000-8003-000000000007"
WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, 0, 250000, tzinfo=timezone.utc),
)
SIGMA_CONTENT = (
    "title: 'Mimikatz: sekurlsa — Ünïcode'\n"
    "id: 00000000-0000-4000-8003-000000000007\n"
    "status: experimental\n"
    "logsource:\n"
    "    category: process_creation\n"
    "    product: windows\n"
    "detection:\n"
    "    selection:\n"
    "        CommandLine|contains:\n"
    "            - sekurlsa\n"
    "    condition: selection\n"
    "level: high\n"
)
YARA_CONTENT = (
    'import "pe"\n\nrule harfanglab_yara_loader {\n    meta:\n'
    '        id = "00000000-0000-4000-8003-000000000008"\n    strings:\n'
    '        $a = "loader"\n    condition:\n        $a\n}'
)


def service(kind: str) -> Any:
    """``HarfangLabService`` for a tenant of *kind*.

    Its constructor reads the platform's identifier from the registry as
    ``Systems.HarfangLab``, which the registry looks up as ``harfang_lab`` and
    never finds (``AttributeError``): the oracle's HarfangLab deploy and query
    stop there before any request. The stand-in registry gives the constructor
    that identifier, as ``tests/test_platforms/test_tenant_tls.py`` does; every
    request below is the oracle's own.
    """
    platform = SimpleNamespace(platform=SimpleNamespace(identifier="harfanglab"))
    registry = SimpleNamespace(
        Configurations=SimpleNamespace(Systems=SimpleNamespace(HarfangLab=platform))
    )
    with patch.object(client, "Opentide", registry):
        return client.HarfangLabService(tenant(kind))


def tenant(kind: str) -> Any:
    setup = C.Systems.HarfangLab.Tenant.Setup(
        ssl=True,
        type=kind,
        url="https://hl-tenant.invalid/",
        api_token=os.environ["HARFANGLAB_API_TOKEN"],
        source_id="src-0001",
    )
    return C.Systems.HarfangLab.Tenant(name="hl", description="", setup=setup)


def sigma(name: str, *, enabled: bool = True) -> SigmaRule:
    return SigmaRule(
        name=name,
        content=SIGMA_CONTENT,
        source_id="src-0001",
        enabled=enabled,
        global_state="block" if enabled else "disabled",
        hl_status="testing",
        block_on_agent=enabled,
        quarantine_on_agent=False,
        rule_confidence_override="strong",
        rule_level_override="high",
    )


def yara(name: str) -> YaraRule:
    return YaraRule(
        name=name,
        content=YARA_CONTENT,
        source_id="src-0001",
        global_state="alert",
        hl_status="stable",
        rule_confidence_override="moderate",
        rule_level_override="critical",
    )


def emit(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def attempt(action: Any) -> None:
    try:
        action()
    except Exception as error:
        emit({"error": type(error).__name__, "message": str(error)})
    else:
        emit({"ok": True})


def deploy() -> None:
    sigma_service = service("Sigma")
    attempt(lambda: sigma_service.create_or_update_sigma_rule(sigma("Mimikatz: sekurlsa"), RULE_ID))
    created = "sigma-1"
    attempt(lambda: sigma_service.create_or_update_sigma_rule(sigma("Mimikatz: sekurlsa"), created))
    attempt(
        lambda: sigma_service.create_or_update_sigma_rule(
            sigma("Mimikatz: sekurlsa", enabled=False), created
        )
    )
    attempt(lambda: sigma_service.delete_sigma_rule(created))
    attempt(lambda: sigma_service.create_or_update_sigma_rule(sigma("Rejected rule"), RULE_ID))
    attempt(lambda: sigma_service.create_or_update_sigma_rule(sigma("Forbidden rule"), RULE_ID))
    attempt(lambda: sigma_service.delete_sigma_rule("sigma-missing"))
    yara_service = service("YARA")
    attempt(
        lambda: yara_service.create_or_update_yara_rule(yara("HarfangLab YARA Loader"), RULE_ID)
    )
    attempt(lambda: yara_service.delete_yara_rule(RULE_ID))
    attempt(lambda: yara_service.create_or_update_yara_rule(yara("Rejected YARA"), RULE_ID))
    attempt(lambda: yara_service.delete_yara_rule("yara-missing"))


def query() -> None:
    from opentide.platforms.harfanglab.runner import HarfangLabQueryRunner

    runner = HarfangLabQueryRunner()
    built = service("Sigma")
    for text, kwargs in (
        (
            r"Processes process_name=cmd.exe 'commandline__icontains=a b' "
            r'image_name="C:\Windows\System32\cmd.exe" parent_name=*~x@y',
            {"limit": 1},
        ),
        ("dns requested_name=example.org", {"limit": 10, "timeout": 30.0}),
        ("processes process_name=broken.exe", {}),
        ("processes process_name=gateway.exe", {}),
        ("registry key=x", {}),
        ("processes 'unclosed", {}),
    ):
        request = QueryRequest(platform="harfanglab", text=text, window=WINDOW, **kwargs)
        try:
            with patch.object(client, "HarfangLabService", lambda _tenant: built):
                result = runner.run(request, tenant("Sigma"))
        except QueryRefused as error:
            emit({"refused": error.message, "detail": error.detail})
            continue
        emit(
            {
                "columns": [column.name for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
                "language": result.language,
            }
        )


if __name__ == "__main__":
    {"deploy": deploy, "query": query}[sys.argv[1]]()
