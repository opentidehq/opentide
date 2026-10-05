"""PyMISP transport: auth header, DELETE, paging, and redacted failures."""

from __future__ import annotations

import json
import logging

import pytest
import requests

from opentide.sharing.client import MispCallError, PyMispClient
from opentide.sharing.constants import REDACTION_MARKER


class _Scripted:
    def __init__(self, responses: list[tuple[int, object]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, object]] = []

    def _prepare_request(self, method: str, path: str, data: object = None) -> requests.Response:
        self.calls.append((method, path, data))
        status, payload = self.responses.pop(0)
        response = requests.Response()
        response.status_code = status
        if isinstance(payload, bytes):
            response._content = payload
        elif payload is None:
            response._content = b""
        else:
            response._content = json.dumps(payload).encode()
        response.url = f"https://misp.example/{path}"
        response.headers["Content-Type"] = "application/json"
        return response


def _client(scripted: _Scripted) -> PyMispClient:
    client = PyMispClient.__new__(PyMispClient)
    client._api = scripted  # type: ignore[assignment]
    client._clusters = {}
    client._lock = __import__("threading").Lock()
    return client


def test_authorization_header_is_not_in_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str] = {}

    def fake_send(
        self: requests.Session,
        prepared: requests.PreparedRequest,
        **_kwargs: object,
    ) -> requests.Response:
        captured["url"] = prepared.url or ""
        captured["authorization"] = prepared.headers.get("Authorization", "")
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"version":"2.4.214"}'
        response.url = prepared.url
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr(requests.Session, "send", fake_send)
    client = PyMispClient("https://misp.example/base", "super-secret", verify_ssl=True)
    assert client.get_version() == "2.4.214"
    assert captured["authorization"] == "super-secret"
    assert "super-secret" not in captured["url"]
    assert captured["url"] == "https://misp.example/base/servers/getVersion"


def test_auth_failure_hides_the_body_and_the_key() -> None:
    scripted = _Scripted([(401, {"message": "nope super-secret", "key": "super-secret"})])
    client = _client(scripted)
    with pytest.raises(MispCallError) as caught:
        client.get_version()
    assert caught.value.kind == "authentication"
    assert str(caught.value) == "authentication_failed"
    assert "super-secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_delete_uses_the_spec_method_and_ignores_404() -> None:
    scripted = _Scripted([(200, {"saved": True}), (404, {"message": "gone"})])
    client = _client(scripted)
    client.delete_event("42")
    client.delete_event("42")
    assert scripted.calls[0][0] == "DELETE"
    assert scripted.calls[0][1] == "events/42"


def test_search_pages_until_a_short_page_and_views_each_hit() -> None:
    event = {
        "Event": {
            "id": "7",
            "uuid": "11111111-1111-4111-8111-111111111111",
            "published": False,
            "Orgc": {"uuid": "00000000-0000-4000-8aaa-000000000001"},
            "Attribute": [],
            "Object": [
                {
                    "name": "opentide",
                    "Attribute": [{"object_relation": "uuid", "value": "tide-uuid"}],
                }
            ],
        }
    }
    page = [event for _ in range(100)]
    scripted = _Scripted(
        [
            (200, page),
            (200, event),
            (200, [event]),
            (200, event),
        ]
    )
    client = _client(scripted)
    found = client.search_opentide_events("tide-uuid")
    assert len(found) == 1
    assert found[0].event_id == 7
    assert found[0].opentide_uuids == ("tide-uuid",)
    assert scripted.calls[0][1] == "events/restSearch"
    body = scripted.calls[0][2]
    assert isinstance(body, dict)
    assert body["value"] == "tide-uuid"
    assert body["object_name"] == "opentide"
    assert scripted.calls[1][0] == "GET"
    assert scripted.calls[1][1] == "events/view/7"


def test_attribute_too_large_does_not_echo_the_document() -> None:
    scripted = _Scripted([(400, {"message": "value is too long: name: secret-doc"})])
    client = _client(scripted)
    with pytest.raises(MispCallError) as caught:
        client.add_event({"Event": {"info": "x"}})
    assert caught.value.reason == "attribute_too_large"
    assert "secret-doc" not in str(caught.value)


def test_pymisp_debug_log_redacts_the_key(caplog: pytest.LogCaptureFixture) -> None:
    client = PyMispClient.__new__(PyMispClient)
    from opentide.sharing.client import _open_pymisp

    _open_pymisp("https://misp.example/", "super-secret", verify_ssl=True)
    logger = logging.getLogger("pymisp")
    with caplog.at_level(logging.DEBUG, logger="pymisp"):
        logger.debug("Authorization super-secret")
    assert "super-secret" not in caplog.text
    assert REDACTION_MARKER in caplog.text
    logger.debug("connected")
    assert client is not None


def test_version_and_organisation_shapes() -> None:
    empty = _client(_Scripted([(200, {"version": ""}), (200, [])]))
    with pytest.raises(MispCallError) as missing:
        empty.get_version()
    assert missing.value.reason == "connectivity_failed"
    with pytest.raises(MispCallError):
        empty.get_version()

    org = _client(
        _Scripted(
            [
                (200, {"Organisation": {"uuid": "org-1"}}),
                (200, {"User": {"Organisation": {"uuid": "org-2"}}}),
                (200, {"User": {}}),
                (200, []),
            ]
        )
    )
    assert org.current_organisation_uuid() == "org-1"
    assert org.current_organisation_uuid() == "org-2"
    with pytest.raises(MispCallError) as unverified:
        org.current_organisation_uuid()
    assert unverified.value.reason == "organisation_uuid_unverified"
    with pytest.raises(MispCallError):
        org.current_organisation_uuid()


def test_template_view_and_missing_template() -> None:
    from opentide.sharing.constants import OPENTIDE_TEMPLATE_UUID

    template = {
        "ObjectTemplate": {
            "version": "5",
            "ObjectTemplateElement": [
                "skip",
                {"object_relation": "name"},
                {
                    "object_relation": "opentide-type",
                    "values_list": '["threat", "rule", 1]',
                },
            ],
        }
    }
    client = _client(
        _Scripted(
            [
                (404, {"message": "missing"}),
                (503, {"message": "down"}),
                (200, template),
                (200, []),
                (200, {"ObjectTemplate": {"version": True, "attributes": []}}),
                (200, {"ObjectTemplate": "nope"}),
                (
                    200,
                    {
                        "attributes": [
                            {"object_relation": "opentide-type", "values_list": "not-json"},
                            {"object_relation": "opentide-type", "values_list": '{"a": 1}'},
                            {"object_relation": "opentide-type", "values_list": ["threat", 1]},
                        ]
                    },
                ),
            ]
        )
    )
    assert client.object_template().found is False
    with pytest.raises(MispCallError) as down:
        client.object_template()
    assert down.value.kind == "connectivity"
    viewed = client.object_template()
    assert viewed.found is True
    assert viewed.version == 5
    assert "name" in viewed.relations
    assert viewed.type_values == frozenset({"threat", "rule"})
    assert client.object_template().found is False
    bare = client.object_template()
    assert bare.version is None
    assert bare.relations == frozenset()
    assert client.object_template().found is False
    unparsed = client.object_template()
    assert unparsed.type_values == frozenset({"threat"})
    assert any(OPENTIDE_TEMPLATE_UUID in call[1] for call in client._api.calls)


def test_add_edit_publish_and_rejected_payloads() -> None:
    event = {"Event": {"id": 3, "uuid": "11111111-1111-4111-8111-111111111111"}}
    client = _client(
        _Scripted(
            [
                (200, event),
                (200, {"saved": True}),
                (200, {}),
                (200, {"Event": {}}),
                (200, event),
                (200, []),
                (500, {"message": "nope"}),
            ]
        )
    )
    created = client.add_event({"Event": {"info": "x"}})
    assert created.event_id == 3
    client.publish_event("3")
    client.unpublish_event("3")
    with pytest.raises(MispCallError) as rejected:
        client.add_event({"Event": {}})
    assert rejected.value.reason == "remote_rejected"
    assert client.edit_event("3", {"Event": {"uuid": created.event_uuid}}).event_id == 3
    with pytest.raises(MispCallError) as update:
        client.edit_event("3", {"Event": {}})
    assert update.value.reason == "remote_update_rejected"
    with pytest.raises(MispCallError) as delete_failed:
        client.delete_event("3")
    assert delete_failed.value.kind == "connectivity"


def test_search_skips_a_missing_view_and_stops_on_a_repeated_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("opentide.sharing.client.SEARCH_PAGE_SIZE", 1)
    monkeypatch.setattr("opentide.sharing.client._PAGE_CAP", 3)
    event = {
        "uuid": "11111111-1111-4111-8111-111111111111",
        "id": None,
        "published": "true",
        "Object": [{"Attribute": "nope"}, {"Attribute": ["skip", {"object_relation": "other"}]}],
    }
    client = _client(
        _Scripted(
            [
                (200, ["skip", event]),
                (404, {"message": "gone"}),
                (200, [event]),
            ]
        )
    )
    assert client.search_opentide_events("tide") == []
    assert client._api.calls[1][1].endswith(event["uuid"])


def test_search_views_until_the_page_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("opentide.sharing.client.SEARCH_PAGE_SIZE", 1)
    monkeypatch.setattr("opentide.sharing.client._PAGE_CAP", 1)
    first = {"Event": {"id": 1, "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "published": 0}}
    client = _client(_Scripted([(200, {"response": first}), (200, first)]))
    found = client.search_opentide_events("tide")
    assert len(found) == 1
    assert found[0].published is False
    assert len(client._api.calls) == 2


def test_response_wrappers_errors_and_transport_failures() -> None:
    client = _client(
        _Scripted(
            [
                (403, {"message": "denied"}),
                (200, None),
                (200, b"{"),
                (200, {"errors": ["value too long"]}),
                (200, {"errors": [401, "nope"]}),
                (200, {"errors": ["nope"]}),
                (400, {"message": "bad request"}),
                (200, {"response": [{"id": "8", "uuid": "u-8", "published": "1", "Orgc": []}]}),
                (200, {"id": "abc", "uuid": "u-8", "published": "1"}),
            ]
        )
    )
    with pytest.raises(MispCallError) as denied:
        client.get_version()
    assert denied.value.status == 403
    with pytest.raises(MispCallError):
        client.get_version()
    with pytest.raises(MispCallError) as invalid:
        client.get_version()
    assert invalid.value.__cause__ is not None
    with pytest.raises(MispCallError) as huge:
        client.add_event({"Event": {}})
    assert huge.value.reason == "attribute_too_large"
    with pytest.raises(MispCallError) as authed:
        client.get_version()
    assert authed.value.kind == "authentication"
    with pytest.raises(MispCallError) as rejected:
        client.get_version()
    assert rejected.value.reason == "remote_rejected"
    with pytest.raises(MispCallError) as bad:
        client.get_version()
    assert bad.value.reason == "remote_rejected"
    found = client.search_opentide_events("tide")
    assert found[0].event_id is None
    assert found[0].published is True
    assert found[0].orgc_uuid is None

    class Boom:
        def _prepare_request(
            self,
            method: str,
            path: str,
            data: object = None,
        ) -> requests.Response:
            raise requests.ConnectionError("down")

    offline = _client(Boom())  # type: ignore[arg-type]
    with pytest.raises(MispCallError) as connectivity:
        offline.get_version()
    assert connectivity.value.reason == "connectivity_failed"
    assert connectivity.value.__cause__ is not None


def test_galaxy_clusters_page_filter_and_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("opentide.sharing.client.SEARCH_PAGE_SIZE", 2)
    good = {
        "GalaxyCluster": {
            "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "value": "Alpha",
            "meta": json.dumps(
                {
                    "external_id": "T1059",
                    "synonyms": ["Alias"],
                    "refs": ["https://attack.mitre.org/techniques/T1059", "T1003"],
                }
            ),
            "Galaxy": {"name": "mitre-attack-pattern"},
        }
    }
    other = {
        "uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "value": "Beta",
        "Galaxy": {"type": "other"},
        "meta": {"external_id": ["T1000"], "refs": "https://example.test/T1000"},
    }
    broken_meta = {
        "uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "value": "Gamma",
        "meta": "{",
    }
    client = _client(
        _Scripted(
            [
                (200, [good, other]),
                (200, [broken_meta, "skip"]),
                (
                    200,
                    [
                        {
                            "uuid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                            "value": "Delta",
                            "meta": 1,
                        }
                    ],
                ),
            ]
        )
    )
    loaded = client.galaxy_clusters("mitre-attack-pattern")
    assert [cluster.value for cluster in loaded] == ["Alpha", "Gamma", "Delta"]
    assert loaded[0].external_ids == ("T1059",)
    assert loaded[0].ref_tails == ("T1059", "T1003")
    assert loaded[1].external_ids == ()
    again = client.galaxy_clusters("mitre-attack-pattern")
    assert again == loaded
    assert len(client._api.calls) == 3


def test_event_node_shapes_and_a_failed_view(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.sharing.client import _event_nodes

    wrapped = {"response": {"Event": {"uuid": "nested"}}}
    assert _event_nodes(wrapped)[0]["Event"]["uuid"] == "nested"
    assert _event_nodes({"response": {"a": {"uuid": "x"}, "b": 1}})
    assert _event_nodes({"response": [{"uuid": "x"}]})[0]["uuid"] == "x"
    assert _event_nodes({"response": "nope"}) == []
    from opentide.sharing.client import _cluster, _remote_event

    assert _remote_event({"Event": []}) is None
    assert _cluster({"GalaxyCluster": "nope"}, "mitre-attack-pattern") is None
    assert _cluster({"uuid": 1, "value": "x"}, "mitre-attack-pattern") is None
    assert _event_nodes("nope") == []

    monkeypatch.setattr("opentide.sharing.client.SEARCH_PAGE_SIZE", 1)
    event = {"Event": {"id": 9, "uuid": "99999999-9999-4999-8999-999999999999"}}
    client = _client(_Scripted([(200, [event]), (500, {"message": "down"})]))
    with pytest.raises(MispCallError) as failed:
        client.search_opentide_events("tide")
    assert failed.value.kind == "connectivity"
