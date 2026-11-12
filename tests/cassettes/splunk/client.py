"""The Python Splunk client, driven through each scenario (UC-4.3).

splunklib, on opentide's urllib handler.

``cargo xtask cassettes record splunk/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (each saved search's settings, the queries, the windows)
for the Rust connector's tests (``crates/opentide-connectors/tests/splunk.rs``),
which must send what this sent, byte for byte. Each step's outcome is printed, one
JSON line each, for those tests' expectations.

Scenarios:

- ``deploy``: the tide corpus's Splunk rule through ``SplunkDeploy.deploy_mdr``:
  created (looked up, 404; created; its settings in two updates), deployed again
  (found; updated), retired (``REMOVED``: found, deleted), retired again (absent).
- ``query``: ``opentide query``'s runner: one-shot searches over a fixed window:
  rows past the limit, a query that starts with a command, Splunk's warnings, an
  ``ERROR`` message, a refusal (400), rows without a field list, a gateway's page.
- ``validate``: ``validate query --live``'s check (``search/v2/parser``): two
  queries it parses, a parse error, the gateway's 307 ``Network Error``, a
  gateway's 504 page.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORPUS = Path("tests/fixtures/tide_corpus/current").resolve()
RULE_FILE = "rule-0003-splunk-spl.yaml"
UUID = "00000000-0000-4000-8003-000000000003"
ROOT = Path(tempfile.mkdtemp(prefix="splunk-cassette-"))
shutil.copytree(CORPUS / "Configurations", ROOT / ".opentide" / "configurations")
(ROOT / "objects" / "rules").mkdir(parents=True)
shutil.copy(CORPUS / "Objects" / "Detection Rules" / RULE_FILE, ROOT / "objects" / "rules")
os.environ["OPENTIDE_REPO_ROOT"] = str(ROOT)
os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(ROOT)
os.chdir(ROOT)

import yaml  # noqa: E402 -- the workspace is set before opentide loads
from opentide.models.system_config import ConfigurationModels as C  # noqa: E402

from opentide.loading.rule_loader import load_rule_from_dict  # noqa: E402
from opentide.platforms.splunk import client as splunk_client  # noqa: E402
from opentide.platforms.splunk import runner as splunk_runner  # noqa: E402
from opentide.platforms.splunk.deployer import SplunkDeploy  # noqa: E402
from opentide.platforms.transport import GatewayTimeoutError  # noqa: E402
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow  # noqa: E402

DOCUMENT = yaml.safe_load((ROOT / "objects" / "rules" / RULE_FILE).read_text(encoding="utf-8"))
WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, 0, 250000, tzinfo=timezone.utc),
)
CHECK_WINDOW = TimeWindow(
    datetime(2026, 10, 27, 7, 59, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
QUERIES: list[dict[str, Any]] = [
    {"text": "index=main sourcetype=WinEventLog:Security EventCode=4688", "limit": 2},
    {"text": '| makeresults count=3 | eval host="ws-é"', "limit": 100},
    {"text": "search index=missing_index", "limit": 100},
    {"text": "index=main | lookup errors x", "limit": 100},
    {"text": "index=main | badcommand", "limit": 100},
    {"text": "index=main nofields", "limit": 100},
    {"text": "index=main gateway", "limit": 100},
]
CHECKS = [
    "index=main EventCode=4688 | stats count by host",
    "| tstats count where index=main by host",
    "index=main |badcommand",
    "index=main |unreachable",
    "index=main |gateway",
]
STEPS = [("create", "STAGING"), ("update", "STAGING"), ("delete", "REMOVED"), ("absent", "REMOVED")]


def _tenant() -> Any:
    setup = C.Systems.Splunk.Tenant.Setup(
        ssl=True,
        url="splunk.invalid",
        port=8089,
        app="search",
        token=os.environ.get("SPLUNK_TOKEN", "fixture"),
        enterprise_security=False,
    )
    return C.Systems.Splunk.Tenant(name="splunk", description="", setup=setup)


def _rule(status: str) -> Any:
    data = copy.deepcopy(DOCUMENT)
    data["configurations"]["splunk"]["status"] = status
    return load_rule_from_dict(data, file=ROOT / "objects" / "rules" / RULE_FILE)


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="splunk", text=text, window=window, limit=limit)


def _print(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def deploy() -> None:
    tenant = _tenant()
    deployer = SplunkDeploy()
    deployer.use_tenant(tenant)
    service = splunk_client.connect_splunk(
        host=tenant.setup.url,
        port=tenant.setup.port,
        token=tenant.setup.token,
        app=tenant.setup.app,
        ssl_enabled=tenant.setup.ssl,
    )
    for label, status in STEPS:
        done = deployer.deploy_mdr(data=_rule(status), service=service, tenant_config=tenant)
        _print({"step": label, "deployed": done})


def query() -> None:
    runner = splunk_runner.SplunkQueryRunner()
    tenant = _tenant()
    for item in QUERIES:
        try:
            result = runner.run(_request(item["text"], WINDOW, item["limit"]), tenant)
        except (QueryRefused, GatewayTimeoutError) as error:
            _print(
                {
                    "error": type(error).__name__,
                    "message": str(error),
                    "detail": getattr(error, "detail", None),
                }
            )
            continue
        _print(
            {
                "columns": [column.name for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
                "warnings": list(result.warnings),
                "sent": result.sent,
            }
        )


def validate() -> None:
    runner = splunk_runner.SplunkQueryRunner()
    tenant = _tenant()
    for text in CHECKS:
        try:
            found = runner.check(_request(text, CHECK_WINDOW, 1), tenant)
        except (QueryRefused, GatewayTimeoutError) as error:
            _print(
                {
                    "error": type(error).__name__,
                    "message": str(error),
                    "detail": getattr(error, "detail", None),
                }
            )
            continue
        _print({"warnings": list(found.warnings)})


def fixture(path: str) -> None:
    applied: list[dict[str, Any]] = []

    def capture(self: Any, **kwargs: Any) -> None:
        kwargs.pop("service")
        applied.append(kwargs)

    tenant = _tenant()
    deployer = SplunkDeploy()
    deployer.use_tenant(tenant)
    SplunkDeploy._apply_saved_search = capture  # type: ignore[method-assign]
    for _, status in STEPS:
        deployer.deploy_mdr(data=_rule(status), service=None, tenant_config=tenant)
    document = {
        "deploy": applied,
        "query": {
            "window": [WINDOW.start.isoformat(), WINDOW.end.isoformat()],
            "queries": QUERIES,
        },
        "validate": {
            "window": [CHECK_WINDOW.start.isoformat(), CHECK_WINDOW.end.isoformat()],
            "queries": CHECKS,
        },
    }
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        json.dump(document, out, indent=2, ensure_ascii=False)
        out.write("\n")


def main() -> int:
    scenario = sys.argv[1]
    if scenario == "fixture":
        fixture(sys.argv[2])
    else:
        {"deploy": deploy, "query": query, "validate": validate}[scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
