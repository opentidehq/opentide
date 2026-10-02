"""MISP HTTP subset, spoken through PyMISP.

``PyMISP`` prepares every request: ``Authorization`` carries the key, the
timeout is 30 seconds, and TLS verification follows the block. The stock
constructor also calls the instance and logs error bodies, so this module
builds the session itself and classifies responses without recording them.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import requests

from opentide.sharing.constants import (
    OPENTIDE_TEMPLATE_UUID,
    REDACTION_MARKER,
    REQUEST_TIMEOUT_SECONDS,
    SEARCH_PAGE_SIZE,
)

_GALAXY_ATTACK = "mitre-attack-pattern"
_GALAXY_ACTOR = "threat-actor"
_PAGE_CAP = 1000


class MispCallError(Exception):
    """A destination failure whose message is a fixed reason, never a body or key."""

    def __init__(self, kind: str, reason: str, *, status: int | None = None) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class RemoteEvent:
    """One MISP Event normalised from ``events/view`` or ``events/add``."""

    event_id: int | None
    event_uuid: str
    orgc_uuid: str | None
    published: bool
    opentide_uuids: tuple[str, ...]
    event_attribute_count: int
    objects: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class TemplateView:
    """The ``opentide`` object template as the instance reports it."""

    found: bool
    version: int | None
    relations: frozenset[str]
    type_values: frozenset[str] | None


@dataclass(frozen=True)
class GalaxyCluster:
    """Fields the connector needs from one galaxy cluster. Nothing is written back."""

    uuid: str
    value: str
    external_ids: tuple[str, ...]
    synonyms: tuple[str, ...]
    ref_tails: tuple[str, ...]


class MispClient(Protocol):
    """The HTTP subset sharing::misp::1.0 uses. Tests supply a fake."""

    def get_version(self) -> str: ...

    def current_organisation_uuid(self) -> str: ...

    def object_template(self) -> TemplateView: ...

    def search_opentide_events(self, object_uuid: str) -> list[RemoteEvent]: ...

    def add_event(self, event: Mapping[str, Any]) -> RemoteEvent: ...

    def edit_event(self, event_id: str, event: Mapping[str, Any]) -> RemoteEvent: ...

    def publish_event(self, event_id: str) -> None: ...

    def unpublish_event(self, event_id: str) -> None: ...

    def delete_event(self, event_id: str) -> None: ...

    def galaxy_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]: ...


class PyMispClient:
    """PyMISP-backed client for one ``[[misp]]`` block."""

    def __init__(self, url: str, api_key: str, *, verify_ssl: bool = True) -> None:
        self._api = _open_pymisp(url, api_key, verify_ssl=verify_ssl)
        self._clusters: dict[str, tuple[GalaxyCluster, ...]] = {}
        self._lock = threading.Lock()

    def get_version(self) -> str:
        payload = self._request("GET", "servers/getVersion")
        version = payload.get("version") if isinstance(payload, dict) else None
        if not isinstance(version, str) or not version:
            raise MispCallError("connectivity", "connectivity_failed")
        return version

    def current_organisation_uuid(self) -> str:
        payload = self._request("GET", "users/view/me")
        org_uuid = _organisation_uuid(payload)
        if org_uuid is None:
            raise MispCallError("other", "organisation_uuid_unverified")
        return org_uuid

    def object_template(self) -> TemplateView:
        try:
            payload = self._request("GET", f"objectTemplates/view/{OPENTIDE_TEMPLATE_UUID}")
        except MispCallError as exc:
            if exc.status == 404:
                return TemplateView(False, None, frozenset(), None)
            raise
        return _template_view(payload)

    def search_opentide_events(self, object_uuid: str) -> list[RemoteEvent]:
        found: list[RemoteEvent] = []
        seen: set[str] = set()
        page = 1
        previous: tuple[str, ...] = ()
        while page <= _PAGE_CAP:
            payload = self._request(
                "POST",
                "events/restSearch",
                {
                    "returnFormat": "json",
                    "object_name": "opentide",
                    "value": object_uuid,
                    "page": page,
                    "limit": SEARCH_PAGE_SIZE,
                },
            )
            batch = _event_nodes(payload)
            identities: list[str] = []
            for node in batch:
                remote = _remote_event(node)
                if remote is None:
                    continue
                identities.append(remote.event_uuid)
                if remote.event_uuid in seen:
                    continue
                seen.add(remote.event_uuid)
                full = self._view(remote)
                if full is not None:
                    found.append(full)
            signature = tuple(identities)
            if len(batch) < SEARCH_PAGE_SIZE or signature == previous:
                break
            previous = signature
            page += 1
        return found

    def add_event(self, event: Mapping[str, Any]) -> RemoteEvent:
        payload = self._request("POST", "events/add", dict(event))
        remote = _remote_event(payload)
        if remote is None:
            raise MispCallError("rejected", "remote_rejected")
        return remote

    def edit_event(self, event_id: str, event: Mapping[str, Any]) -> RemoteEvent:
        payload = self._request("POST", f"events/edit/{event_id}", dict(event))
        remote = _remote_event(payload)
        if remote is None:
            raise MispCallError("rejected", "remote_update_rejected")
        return remote

    def publish_event(self, event_id: str) -> None:
        self._request("POST", f"events/publish/{event_id}", {})

    def unpublish_event(self, event_id: str) -> None:
        self._request("POST", f"events/unpublish/{event_id}", {})

    def delete_event(self, event_id: str) -> None:
        try:
            self._request("DELETE", f"events/{event_id}")
        except MispCallError as exc:
            if exc.status == 404:
                return
            raise

    def galaxy_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]:
        with self._lock:
            cached = self._clusters.get(galaxy)
            if cached is not None:
                return cached
        loaded = self._load_clusters(galaxy)
        with self._lock:
            self._clusters[galaxy] = loaded
        return loaded

    def _view(self, remote: RemoteEvent) -> RemoteEvent | None:
        ident = str(remote.event_id) if remote.event_id is not None else remote.event_uuid
        try:
            payload = self._request("GET", f"events/view/{ident}")
        except MispCallError as exc:
            if exc.status == 404:
                return None
            raise
        return _remote_event(payload)

    def _load_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]:
        collected: list[GalaxyCluster] = []
        page = 1
        previous: tuple[str, ...] = ()
        while page <= _PAGE_CAP:
            payload = self._request(
                "POST",
                "galaxy_clusters/restSearch",
                {"returnFormat": "json", "galaxy": galaxy, "page": page, "limit": SEARCH_PAGE_SIZE},
            )
            batch = _event_nodes(payload)
            identities: list[str] = []
            for node in batch:
                cluster = _cluster(node, galaxy)
                if cluster is None:
                    continue
                identities.append(cluster.uuid)
                collected.append(cluster)
            signature = tuple(identities)
            if len(batch) < SEARCH_PAGE_SIZE or signature == previous:
                break
            previous = signature
            page += 1
        return tuple(collected)

    def _request(
        self,
        method: str,
        path: str,
        data: Mapping[str, Any] | None = None,
    ) -> Any:
        try:
            response = self._api._prepare_request(method, path, data=dict(data) if data else None)
        except requests.RequestException as exc:
            raise MispCallError("connectivity", "connectivity_failed") from exc
        return _decode(response)


def _load_pymisp() -> tuple[Any, str]:
    """Import PyMISP only when a destination is contacted.

    Importing ``pymisp`` logs ``pymisp loaded properly`` at debug. Doing that
    from the CLI package paints ANSI onto ``--help``, usage errors, and JSON.
    """
    pymisp_logger = logging.getLogger("pymisp")
    previous = pymisp_logger.level
    # The package logs "loaded properly" at import. Silence that line only.
    pymisp_logger.setLevel(logging.WARNING)
    try:
        from pymisp import PyMISP
        from pymisp import __version__ as pymisp_version
    finally:
        pymisp_logger.setLevel(previous)
    return PyMISP, pymisp_version


def _open_pymisp(url: str, api_key: str, *, verify_ssl: bool) -> Any:
    """Session setup from ``PyMISP.__init__`` without its connectivity probe."""
    PyMISP, pymisp_version = _load_pymisp()
    api = PyMISP.__new__(PyMISP)
    root = url if url.endswith("/") else f"{url}/"
    api.root_url = root
    api.key = api_key.strip()
    api.ssl = verify_ssl
    api.proxies = None
    api.cert = None
    api.auth = None
    api.timeout = REQUEST_TIMEOUT_SECONDS
    session = requests.Session()
    session.headers["Authorization"] = api.key
    session.headers["User-Agent"] = f"PyMISP {pymisp_version} - opentide"
    # Name-mangled session from PyMISP.__init__; set without calling the probe.
    object.__setattr__(api, "_PyMISP__session", session)
    api.global_pythonify = False
    logger = logging.getLogger("pymisp")
    logger.addFilter(_Redact(api.key))
    return api


class _Redact(logging.Filter):
    """Drop the API key if PyMISP debug logging includes prepared headers."""

    def __init__(self, secret: str) -> None:
        super().__init__()
        self._secret = secret

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secret and self._secret in record.getMessage():
            record.msg = record.getMessage().replace(self._secret, REDACTION_MARKER)
            record.args = ()
        return True


def _decode(response: requests.Response) -> Any:
    status = response.status_code
    if status in {401, 403}:
        raise MispCallError("authentication", "authentication_failed", status=status)
    if status == 404:
        raise MispCallError("other", "not_found", status=404)
    if status >= 500:
        raise MispCallError("connectivity", "connectivity_failed", status=status)
    text = response.text or ""
    if status >= 400:
        if _too_large(text):
            raise MispCallError("attribute_too_large", "attribute_too_large", status=status)
        raise MispCallError("rejected", "remote_rejected", status=status)
    if not text.strip():
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MispCallError("connectivity", "connectivity_failed") from exc
    if isinstance(payload, dict) and "errors" in payload:
        rendered = json.dumps(payload["errors"])
        if _too_large(rendered):
            raise MispCallError("attribute_too_large", "attribute_too_large")
        code = _error_status(payload["errors"])
        if code in {401, 403}:
            raise MispCallError("authentication", "authentication_failed", status=code)
        raise MispCallError("rejected", "remote_rejected", status=code)
    if isinstance(payload, dict) and isinstance(payload.get("response"), (dict, list)):
        return payload["response"]
    return payload


def _too_large(text: str) -> bool:
    folded = text.casefold()
    return "too long" in folded or "too large" in folded or "maximum length" in folded


def _error_status(errors: object) -> int | None:
    if isinstance(errors, (list, tuple)) and errors and isinstance(errors[0], int):
        return errors[0]
    return None


def _organisation_uuid(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    org = payload.get("Organisation")
    if isinstance(org, dict) and isinstance(org.get("uuid"), str):
        return org["uuid"]
    user = payload.get("User")
    if isinstance(user, dict):
        nested = user.get("Organisation")
        if isinstance(nested, dict) and isinstance(nested.get("uuid"), str):
            return nested["uuid"]
    return None


def _event_nodes(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("Event"), dict):
        return [payload]
    response = payload.get("response", payload)
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        if isinstance(response.get("Event"), dict):
            return [response]
        values = [value for value in response.values() if isinstance(value, dict)]
        if values:
            return values
    return []


def _remote_event(payload: Any) -> RemoteEvent | None:
    if not isinstance(payload, dict):
        return None
    event = payload.get("Event", payload)
    if not isinstance(event, dict):
        return None
    event_uuid = event.get("uuid")
    if not isinstance(event_uuid, str) or not event_uuid:
        return None
    orgc = event.get("Orgc")
    orgc_uuid = orgc.get("uuid") if isinstance(orgc, dict) else None
    if not isinstance(orgc_uuid, str):
        orgc_uuid = None
    return RemoteEvent(
        event_id=_integer(event.get("id")),
        event_uuid=event_uuid,
        orgc_uuid=orgc_uuid,
        published=_flag(event.get("published")),
        opentide_uuids=_opentide_uuids(event.get("Object")),
        event_attribute_count=_count(event.get("Attribute")),
        objects=_object_dicts(event.get("Object")),
    )


def _opentide_uuids(objects: object) -> tuple[str, ...]:
    found: list[str] = []
    for obj in _object_dicts(objects):
        attributes = obj.get("Attribute")
        if not isinstance(attributes, list):
            continue
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            relation = attribute.get("object_relation")
            value = attribute.get("value")
            if relation == "uuid" and isinstance(value, str):
                found.append(value)
    return tuple(found)


def _object_dicts(objects: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(objects, list):
        return ()
    return tuple(obj for obj in objects if isinstance(obj, dict))


def _template_view(payload: Any) -> TemplateView:
    if not isinstance(payload, dict):
        return TemplateView(False, None, frozenset(), None)
    root = payload.get("ObjectTemplate", payload)
    if not isinstance(root, dict):
        return TemplateView(False, None, frozenset(), None)
    elements = root.get("ObjectTemplateElement")
    if not isinstance(elements, list):
        elements = root.get("attributes")
    relations: set[str] = set()
    type_values: frozenset[str] | None = None
    if isinstance(elements, list):
        for element in elements:
            if not isinstance(element, dict):
                continue
            relation = element.get("object_relation")
            if isinstance(relation, str):
                relations.add(relation)
            if relation == "opentide-type":
                type_values = _values_list(element.get("values_list"))
    return TemplateView(True, _integer(root.get("version")), frozenset(relations), type_values)


def _values_list(value: object) -> frozenset[str] | None:
    if isinstance(value, list):
        return frozenset(item for item in value if isinstance(item, str))
    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(loaded, list):
            return frozenset(item for item in loaded if isinstance(item, str))
    return None


def _cluster(node: Any, galaxy: str) -> GalaxyCluster | None:
    if not isinstance(node, dict):
        return None
    raw = node.get("GalaxyCluster", node)
    if not isinstance(raw, dict):
        return None
    galaxy_node = node.get("Galaxy")
    if not isinstance(galaxy_node, dict):
        galaxy_node = raw.get("Galaxy")
    if isinstance(galaxy_node, dict):
        kind = galaxy_node.get("type") or galaxy_node.get("name")
        if isinstance(kind, str) and kind != galaxy:
            return None
    uuid = raw.get("uuid")
    value = raw.get("value")
    if not isinstance(uuid, str) or not isinstance(value, str):
        return None
    meta = raw.get("meta") or raw.get("meta_fields") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return GalaxyCluster(
        uuid=uuid,
        value=value,
        external_ids=_strings(meta.get("external_id")),
        synonyms=_strings(meta.get("synonyms")),
        ref_tails=tuple(_ref_tail(item) for item in _strings(meta.get("refs"))),
    )


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _ref_tail(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    return path.rsplit("/", 1)[-1]


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _count(value: object) -> int:
    if isinstance(value, list):
        return len(value)
    return 0


def _flag(value: object) -> bool:
    if isinstance(value, str):
        return value == "1" or value.lower() == "true"
    return bool(value)


# Re-exported so callers can name the galaxies without importing constants twice.
GALAXY_ATTACK = _GALAXY_ATTACK
GALAXY_ACTOR = _GALAXY_ACTOR
