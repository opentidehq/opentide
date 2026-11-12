"""The Python Carbon Black Cloud client (cbc_sdk), driven through each scenario (UC-4.3).

``cargo xtask cassettes record carbon_black/<scenario>`` runs this with the oracle's
interpreter (the frozen Python implementation) behind the recording proxy, against
``tenant.py``. ``python client.py fixture <path>`` writes, instead, the inputs the
scenarios give the client (each rule's report fields, the queries, the windows) for
the Rust connector's tests (``crates/opentide-connectors/tests/carbon_black.rs``),
which must send what this sent, byte for byte. Each step's outcome is printed, one
JSON line each, for those tests' expectations.

The SDK stamps a report with ``int(time.time())`` when it is built or updated; the
deploy scenario fixes that clock at :data:`NOW`, as the Rust test passes it.

Scenarios:

- ``deploy``: the tide corpus's Carbon Black rule through ``_deploy_to_org`` on the
  watchlist ``opentide``: a new report (created, then added to the watchlist), the
  same rule again (its IOC replaced, the report updated), a second rule sharing the
  other rule's report (its IOC added, the tags merged), that rule retired (its IOC
  removed, the report kept), the first rule retired (its report deleted), a rule
  whose watchlist the org does not hold.
- ``query``: ``opentide query``'s runner: a process search validated, started,
  polled until it completes and read with one row past the limit; a search that
  finds nothing; one the validation refuses; one the tenant forbids (403).
- ``validate``: ``validate query --live``'s check (``search_validation``): a query it
  accepts and one it refuses.
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
RULE_FILE = "rule-0005-carbon-black-lucene.yaml"
ROOT = Path(tempfile.mkdtemp(prefix="cbc-cassette-"))
shutil.copytree(CORPUS / "Configurations", ROOT / ".opentide" / "configurations")
(ROOT / "objects" / "rules").mkdir(parents=True)
shutil.copy(CORPUS / "Objects" / "Detection Rules" / RULE_FILE, ROOT / "objects" / "rules")
os.environ["OPENTIDE_REPO_ROOT"] = str(ROOT)
os.environ["OPENTIDE_TIDE_WORKSPACE"] = str(ROOT)
os.chdir(ROOT)

import cbc_sdk.enterprise_edr.threat_intelligence as threat_intelligence  # noqa: E402
import yaml  # noqa: E402 -- the workspace is set before opentide loads
from opentide.models.system_config import ConfigurationModels as C  # noqa: E402

from opentide.loading.rule_loader import load_rule_from_dict  # noqa: E402
from opentide.platforms.carbon_black import runner as cbc_runner  # noqa: E402
from opentide.platforms.carbon_black.client import CarbonBlackCloudService  # noqa: E402
from opentide.platforms.carbon_black.deployer import CarbonBlackCloudDeploy  # noqa: E402
from opentide.query.models import QueryRefused, QueryRequest, TimeWindow  # noqa: E402

RULE_PATH = ROOT / "objects" / "rules" / RULE_FILE
DOCUMENT = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
NOW = 1793088000
WINDOW = TimeWindow(
    datetime(2026, 10, 26, 8, 0, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
CHECK_WINDOW = TimeWindow(
    datetime(2026, 10, 27, 7, 59, tzinfo=timezone.utc),
    datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc),
)
QUERIES: list[dict[str, Any]] = [
    {"text": "process_name:cmd.exe AND device_name:ws-*", "limit": 2},
    {"text": "process_name:x", "limit": 100},
    {"text": "process_name:(cmd.exe", "limit": 100},
    {"text": "process_name:denied.exe", "limit": 100},
]
CHECKS = ["process_name:cmd.exe AND netconn_count:[1 TO *]", "process_name:(cmd.exe"]
#: (label, status, uuid, name, report, watchlist): each deploy step.
STEPS: list[tuple[str, str, str, str, str | None, str | None]] = [
    (
        "create",
        "STAGING",
        "00000000-0000-4000-8003-000000000005",
        "Carbon Black Lucene Rule",
        None,
        None,
    ),
    (
        "update",
        "STAGING",
        "00000000-0000-4000-8003-000000000005",
        "Carbon Black Lucene Rule",
        None,
        None,
    ),
    (
        "shared",
        "PRODUCTION",
        "00000000-0000-4000-8003-0000000000c5",
        "Carbon Black shared — Ünïcode",
        "Another rule",
        None,
    ),
    (
        "retire-shared",
        "REMOVED",
        "00000000-0000-4000-8003-0000000000c5",
        "Carbon Black shared — Ünïcode",
        "Another rule",
        None,
    ),
    (
        "retire",
        "DISABLED",
        "00000000-0000-4000-8003-000000000005",
        "Carbon Black Lucene Rule",
        None,
        None,
    ),
    (
        "missing-watchlist",
        "STAGING",
        "00000000-0000-4000-8003-000000000005",
        "Carbon Black Lucene Rule",
        None,
        "absent",
    ),
]


class _Clock:
    """``time`` for the SDK's report stamps: :data:`NOW`."""

    @staticmethod
    def time() -> float:
        return float(NOW)


def _tenant() -> Any:
    setup = C.Systems.CarbonBlackCloud.Tenant.Setup(
        ssl=True,
        url="https://cbc.invalid",
        org_key="ORGKEY01",
        token=os.environ.get("CBC_TOKEN", "fixture"),
        watchlist="opentide",
    )
    return C.Systems.CarbonBlackCloud.Tenant(name="cbc", description="", setup=setup)


def _rule(status: str, uuid: str, name: str, report: str | None, watchlist: str | None) -> Any:
    data = copy.deepcopy(DOCUMENT)
    data["metadata"]["uuid"] = uuid
    data["name"] = name
    # Without a detection model the tags are the status and the block's own:
    # the technique lookup is the catalogue's, not the tenant's.
    data.pop("detection_model", None)
    block = data["configurations"]["carbon_black_cloud"]
    block["status"] = status
    if report:
        block["report"] = report
        block["tags"] = ["shared"]
    if watchlist:
        block["watchlist"] = watchlist
    return load_rule_from_dict(data, file=RULE_PATH)


def _request(text: str, window: TimeWindow, limit: int) -> QueryRequest:
    return QueryRequest(platform="carbon_black_cloud", text=text, window=window, limit=limit)


def _print(outcome: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(outcome, ensure_ascii=False) + "\n")


def deploy() -> None:
    threat_intelligence.time = _Clock  # type: ignore[assignment]
    tenant = _tenant()
    deployer = CarbonBlackCloudDeploy()
    service = CarbonBlackCloudService(tenant).service
    for label, status, uuid, name, report, watchlist in STEPS:
        try:
            deployer.deploy_mdr(
                data=_rule(status, uuid, name, report, watchlist),
                service=service,
                tenant_config=tenant,
            )
            _print({"step": label})
        except RuntimeError as error:
            _print({"step": label, "error": str(error)})


def query() -> None:
    runner = cbc_runner.CarbonBlackQueryRunner()
    tenant = _tenant()
    for item in QUERIES:
        try:
            result = runner.run(_request(item["text"], WINDOW, item["limit"]), tenant)
        except QueryRefused as error:
            _print(
                {"error": type(error).__name__, "message": error.message, "detail": error.detail}
            )
            continue
        except Exception as error:
            _print({"error": type(error).__name__, "message": str(error)})
            continue
        _print(
            {
                "columns": [column.name for column in result.columns],
                "rows": list(result.rows),
                "truncated": result.truncated,
            }
        )


def validate() -> None:
    runner = cbc_runner.CarbonBlackQueryRunner()
    tenant = _tenant()
    for text in CHECKS:
        try:
            runner.check(_request(text, CHECK_WINDOW, 1), tenant)
        except QueryRefused as error:
            _print({"error": error.message, "detail": error.detail})
            continue
        _print({"valid": True})


def fixture(path: str) -> None:
    steps = []
    for label, status, uuid, name, report, watchlist in STEPS:
        rule = _rule(status, uuid, name, report, watchlist)
        steps.append(
            {
                "label": label,
                "status": status,
                "uuid": uuid,
                "name": name,
                "description": rule.description,
                "query": rule.platform_configs().carbon_black_cloud.query,
                "report": report,
                "watchlist": watchlist or "opentide",
                "tags": ["shared"] if report else None,
                "alert_severity": rule.alert_severity,
            }
        )
    document = {
        "now": NOW,
        "deploy": steps,
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
