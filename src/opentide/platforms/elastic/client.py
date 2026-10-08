"""HTTP client for Kibana Detection Engine REST API and Elasticsearch."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests
import structlog
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = structlog.get_logger(__name__)


class ElasticClient:
    """HTTP client communicating with Kibana Detection Engine API and Elasticsearch."""

    def __init__(
        self,
        url: str,
        elasticsearch_url: str = "",
        api_key: str = "",
        space: str = "default",
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self.kibana_url = url.rstrip("/")
        self.elasticsearch_url = elasticsearch_url.rstrip("/")
        self.api_key = api_key
        self.space = space or "default"
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if self.space and self.space != "default":
            self.kibana_base = f"{self.kibana_url}/s/{self.space}"
        else:
            self.kibana_base = self.kibana_url

        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Retries with exponential backoff for 429, 500, 502, 503, 504
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "elastic-api-version": "2023-10-31",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        self.session.headers.update(headers)

    def _kibana_url(self, endpoint: str) -> str:
        return f"{self.kibana_base}{endpoint}"

    def _es_url(self, endpoint: str) -> str:
        return f"{self.elasticsearch_url}{endpoint}"

    # --- Kibana Detection Engine operations ---

    def get_rule(self, rule_id: str) -> requests.Response:
        """Fetch a rule by stable rule_id."""
        url = self._kibana_url("/api/detection_engine/rules")
        return self.session.get(url, params={"rule_id": rule_id}, timeout=self.timeout)

    def create_rule(self, payload: dict[str, Any]) -> requests.Response:
        """Create a new detection rule."""
        url = self._kibana_url("/api/detection_engine/rules")
        headers = {"kbn-xsrf": "true"}
        return self.session.post(url, json=payload, headers=headers, timeout=self.timeout)

    def update_rule(self, payload: dict[str, Any]) -> requests.Response:
        """Update an existing detection rule via PUT."""
        url = self._kibana_url("/api/detection_engine/rules")
        headers = {"kbn-xsrf": "true"}
        rule_id = payload.get("rule_id")
        params = {"rule_id": rule_id} if rule_id else None
        return self.session.put(
            url, json=payload, params=params, headers=headers, timeout=self.timeout
        )

    def delete_rule(self, rule_id: str) -> requests.Response:
        """Delete a detection rule by stable rule_id."""
        url = self._kibana_url("/api/detection_engine/rules")
        headers = {"kbn-xsrf": "true"}
        return self.session.delete(
            url, params={"rule_id": rule_id}, headers=headers, timeout=self.timeout
        )

    def preview_rule(
        self,
        payload: dict[str, Any],
        invocation_count: int = 1,
        timeframe_end: str | None = None,
    ) -> requests.Response:
        """Execute a rule preview to test query and configuration."""
        url = self._kibana_url("/api/detection_engine/rules/_preview")
        headers = {"kbn-xsrf": "true"}
        preview_body = dict(payload)
        preview_body["invocationCount"] = invocation_count
        if not timeframe_end:
            from datetime import datetime, timezone

            timeframe_end = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        preview_body["timeframeEnd"] = timeframe_end
        return self.session.post(url, json=preview_body, headers=headers, timeout=self.timeout)

    def find_rules(
        self,
        page: int = 1,
        per_page: int = 100,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        """List rules with pagination."""
        url = self._kibana_url("/api/detection_engine/rules/_find")
        params: dict[str, Any] = {
            "page": page,
            "per_page": per_page,
        }
        if filter_query:
            params["filter"] = filter_query
        resp = self.session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def find_managed(self, tag: str = "OpenTide") -> list[dict[str, Any]]:
        """List rules managed by OpenTide using the tag filter."""
        url = self._kibana_url("/api/detection_engine/rules/_find")
        resp = self.session.get(
            url,
            params={"filter": f'alert.attributes.tags:"{tag}"', "per_page": 1000},
            timeout=self.timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", [])
        return []

    def get_data_view(self, data_view_id: str) -> dict[str, Any] | None:
        """Retrieve a Kibana Data View by id."""
        url = self._kibana_url(f"/api/data_views/data_view/{data_view_id}")
        resp = self.session.get(url, timeout=self.timeout)
        if resp.status_code == 200:
            return resp.json()
        return None

    # --- Elasticsearch operations ---

    def esql_query(self, query: str) -> requests.Response:
        """Execute an ES|QL query against Elasticsearch _query API."""
        url = self._es_url("/_query")
        return self.session.post(url, json={"query": query}, timeout=self.timeout)

    def resolve_index(self, pattern: str) -> requests.Response:
        """Resolve index patterns via Elasticsearch _resolve/index API."""
        encoded_pattern = quote(pattern, safe="")
        url = self._es_url(
            f"/_resolve/index/{encoded_pattern}?ignore_unavailable=true&allow_no_indices=true"
        )
        return self.session.get(url, timeout=self.timeout)

    def field_caps(self, sources: str, fields: list[str]) -> requests.Response:
        """Retrieve field capabilities from Elasticsearch _field_caps API."""
        encoded_sources = quote(sources, safe=",*-_")
        fields_param = quote(",".join(fields), safe=",*-_.")
        url = self._es_url(
            f"/{encoded_sources}/_field_caps?fields={fields_param}&ignore_unavailable=true&allow_no_indices=true"
        )
        return self.session.get(url, timeout=self.timeout)
