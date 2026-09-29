"""HTTP client for Kibana Detection Engine API."""

from __future__ import annotations

from typing import Any

import requests
import structlog
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = structlog.get_logger(__name__)


class ElasticSecurityClient:
    """HTTP client communicating with Kibana's Detection Engine REST API."""

    def __init__(
        self,
        kibana_url: str,
        api_key: str = "",
        space: str = "default",
        verify_ssl: bool = True,
        timeout: int = 30,
        proxy: str | None = None,
    ) -> None:
        self.kibana_url = kibana_url.rstrip("/")
        self.api_key = api_key
        self.space = space or "default"
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.proxy = proxy

        if self.space and self.space != "default":
            self.base_url = f"{self.kibana_url}/s/{self.space}"
        else:
            self.base_url = self.kibana_url

        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}

        # Retries with backoff for 429, 500, 502, 503, 504
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        headers = {
            "kbn-xsrf": "true",
            "Accept": "application/json",
            "elastic-api-version": "2023-10-31",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        self.session.headers.update(headers)

    def _url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint}"

    def url_for(self, endpoint: str) -> str:
        """Return full Kibana URL for *endpoint*, accounting for space."""
        return self._url(endpoint)

    def import_rules(
        self,
        ndjson_data: str | bytes,
        overwrite: bool = True,
        overwrite_exceptions: bool = False,
        overwrite_action_connectors: bool = False,
    ) -> dict[str, Any]:
        """Import detection rules via multipart/form-data NDJSON upload."""
        url = self._url("/api/detection_engine/rules/_import")
        params = {
            "overwrite": str(overwrite).lower(),
            "overwrite_exceptions": str(overwrite_exceptions).lower(),
            "overwrite_action_connectors": str(overwrite_action_connectors).lower(),
        }
        payload_bytes = ndjson_data.encode("utf-8") if isinstance(ndjson_data, str) else ndjson_data

        files = {
            "file": ("rules.ndjson", payload_bytes, "application/x-ndjson"),
        }
        resp = self.session.post(url, params=params, files=files, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def patch_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Update specific rule fields (such as enabled: false) via PATCH."""
        url = self._url("/api/detection_engine/rules")
        resp = self.session.patch(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        """Delete a rule by stable rule_id."""
        url = self._url("/api/detection_engine/rules")
        resp = self.session.delete(url, params={"rule_id": rule_id}, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def export_rules(
        self,
        rule_ids: list[str] | None = None,
        exclude_export_details: bool = True,
    ) -> bytes:
        """Export detection rules as NDJSON."""
        if rule_ids:
            url = self._url("/api/detection_engine/rules/_export")
            params = {"exclude_export_details": str(exclude_export_details).lower()}
            body: dict[str, Any] = {"objects": [{"rule_id": rid} for rid in rule_ids]}
            resp = self.session.post(url, params=params, json=body, timeout=self.timeout)
            resp.raise_for_status()
            return resp.content

        url = self._url("/api/detection_engine/rules/_bulk_action")
        body = {"action": "export", "query": ""}
        resp = self.session.post(url, json=body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.content

    def find_rules(
        self,
        page: int = 1,
        per_page: int = 100,
        sort_field: str = "name",
        sort_order: str = "asc",
    ) -> dict[str, Any]:
        """List rules with pagination."""
        url = self._url("/api/detection_engine/rules/_find")
        params = {
            "page": page,
            "per_page": per_page,
            "sort_field": sort_field,
            "sort_order": sort_order,
        }
        resp = self.session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def preview_rule(
        self,
        payload: dict[str, Any],
        invocation_count: int = 1,
        timeframe_end: str | None = None,
    ) -> dict[str, Any]:
        """Execute a rule preview to test query and configuration."""
        url = self._url("/api/detection_engine/rules/_preview")
        preview_body = dict(payload)
        preview_body.setdefault("invocationCount", invocation_count)
        if not timeframe_end:
            from datetime import datetime, timezone

            timeframe_end = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        preview_body.setdefault("timeframeEnd", timeframe_end)

        resp = self.session.post(url, json=preview_body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
