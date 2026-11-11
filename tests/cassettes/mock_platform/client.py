"""The Python client of the harness's sample connector (UC-4.1, #831).

A deploy as the platforms' clients send one: a ``TenantSession`` with
urllib3 retries mounted, JSON headers and a bearer token, then look the rule up,
create it, update it, disable it, and read a rule that is not there. The Rust
sample connector (``crates/opentide-connectors/tests/harness.rs``) must send
these requests byte for byte. Recorded by ``cargo xtask cassettes record``.
"""

from __future__ import annotations

import os
import sys

from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from opentide.platforms.transport import TenantSession

BASE = "https://mock-tenant.invalid"

RULE = {
    "rule_id": "5f1c3a2e-0b7d-4c1e-9a58-2f6d7e8c9b01",
    "name": "Encoded PowerShell — Ünïcode",
    "enabled": True,
    "query": 'process where process.name == "powershell.exe" and process.args : "-enc*"',
    "tags": ["attack.t1059.001", "opentide"],
    "severity": 73,
    "risk": 0.5,
    "references": None,
}


def main() -> int:
    session = TenantSession(verify=True)
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False,
        allowed_methods=["GET", "PUT", "PATCH", "POST"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update(
        {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['MOCK_PLATFORM_TOKEN']}",
        }
    )
    found = session.get(f"{BASE}/api/v1/rules", params={"rule_id": RULE["rule_id"]})
    found.raise_for_status()
    if found.json()["data"]:
        return 1
    created = session.post(f"{BASE}/api/v1/rules", json=RULE)
    created.raise_for_status()
    remote = created.json()["id"]
    updated = session.put(
        f"{BASE}/api/v1/rules/{remote}", json={**RULE, "description": "Tuned: 2 exclusions"}
    )
    updated.raise_for_status()
    disabled = session.patch(f"{BASE}/api/v1/rules/{remote}", json={"enabled": False})
    disabled.raise_for_status()
    missing = session.get(f"{BASE}/api/v1/rules/r-404")
    sys.stdout.write(f"{remote} {missing.status_code}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
