"""HTTP client for the Sysdig Secure runtime API (sysdig-1.0, Deploy: api).

Custom Falco rules live at ``/api/secure/rules`` and runtime policies at
``/api/v2/policies``: the endpoints Sysdig's own Terraform provider uses. The
Public (Next-Gen) API has no custom rule or policy write.
"""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from opentide.platforms.transport import TenantSession

RULES = "/api/secure/rules"
POLICIES = "/api/v2/policies"


class SysdigTenantError(RuntimeError):
    """The tenant refused the credentials (401/403): no rule on it can deploy."""


class SysdigApiError(RuntimeError):
    """A Sysdig request failed for this rule only."""

    def __init__(self, action: str, response: requests.Response | None = None) -> None:
        self.status_code = response.status_code if response is not None else None
        if response is None:
            super().__init__(action)
        else:
            super().__init__(f"{action}: HTTP {response.status_code}: {api_error(response)}")


def api_error(response: requests.Response) -> str:
    """Sysdig's error message from a body, else the raw text."""
    try:
        body = response.json()
    except ValueError:
        return response.text
    if isinstance(body, dict):
        for key in ("message", "error", "errors"):
            if body.get(key):
                return str(body[key])
    return response.text


class SysdigClient:
    """Rules and policies on one Sysdig Secure tenant."""

    def __init__(
        self,
        url: str,
        api_token: str,
        *,
        tenant: str,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self.url = url.rstrip("/")
        self.tenant = tenant
        self.timeout = timeout
        self.session = TenantSession(verify=verify_ssl)
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,
            allowed_methods=["GET", "PUT", "DELETE", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_token}",
            }
        )

    def _send(self, method: str, path: str, action: str, **kwargs: Any) -> requests.Response:
        response = self.session.request(method, f"{self.url}{path}", timeout=self.timeout, **kwargs)
        if response.status_code in (401, 403):
            raise SysdigTenantError(
                f"Tenant {self.tenant} refused the API token: HTTP {response.status_code}: "
                f"{api_error(response)}"
            )
        return response

    @staticmethod
    def _json(response: requests.Response, action: str) -> Any:
        if response.status_code >= 300:
            raise SysdigApiError(action, response)
        try:
            return response.json()
        except ValueError as exc:
            raise SysdigApiError(action, response) from exc

    # --- rules ---------------------------------------------------------------

    def create_rule(self, body: dict[str, Any]) -> dict[str, Any]:
        action = "create rule"
        return dict(self._json(self._send("POST", RULES, action, json=body), action))

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        """The rule, or ``None`` when Sysdig no longer has it (404)."""
        action = f"read rule {rule_id}"
        response = self._send("GET", f"{RULES}/{rule_id}", action)
        if response.status_code == 404:
            return None
        return dict(self._json(response, action))

    def update_rule(self, rule_id: str, body: dict[str, Any]) -> dict[str, Any]:
        action = f"update rule {rule_id}"
        return dict(self._json(self._send("PUT", f"{RULES}/{rule_id}", action, json=body), action))

    def delete_rule(self, rule_id: str) -> None:
        """Delete the rule. A rule already gone (404) is not an error."""
        action = f"delete rule {rule_id}"
        response = self._send("DELETE", f"{RULES}/{rule_id}", action)
        if response.status_code != 404 and response.status_code >= 300:
            raise SysdigApiError(action, response)

    # --- policies ------------------------------------------------------------

    def list_policies(self) -> list[dict[str, Any]]:
        action = "list policies"
        body = self._json(self._send("GET", POLICIES, action), action)
        if isinstance(body, dict):  # some versions wrap the list
            body = body.get("policies", body.get("data", []))
        if not isinstance(body, list):
            raise SysdigApiError(f"{action}: the response is not a list of policies")
        return [policy for policy in body if isinstance(policy, dict)]

    def update_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        action = f"update policy {policy.get('name')!r}"
        response = self._send("PUT", f"{POLICIES}/{policy['id']}", action, json=policy)
        return dict(self._json(response, action))
