"""Which errors mean a tenant could not be reached, and which still propagate."""

from __future__ import annotations

import socket
import ssl
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest
import requests
from cbc_sdk import errors as cbc_errors

from opentide.platforms.transport import (
    TenantUnreachableError,
    reaching_tenant,
    transport_error,
)


def _failed_request(url: str) -> requests.ConnectionError:
    return requests.ConnectionError("Connection refused", request=requests.Request("POST", url))


@pytest.mark.parametrize(
    "error",
    [
        URLError(ConnectionRefusedError(111, "Connection refused")),
        requests.ConnectionError("Connection refused"),
        requests.exceptions.ProxyError("Unable to connect to proxy"),
        requests.exceptions.SSLError("certificate verify failed"),
        requests.ReadTimeout("read timed out"),
        ConnectionResetError(104, "Connection reset by peer"),
        TimeoutError("timed out"),
        socket.gaierror(-2, "Name or service not known"),
        ssl.SSLCertVerificationError("certificate verify failed"),
    ],
    ids=lambda error: type(error).__name__,
)
def test_a_network_failure_is_a_transport_error(error: Exception) -> None:
    assert transport_error(error) is error


@pytest.mark.parametrize(
    "error",
    [
        ValueError("bad query"),
        KeyError("tenant"),
        TypeError("legacy signature"),
        FileNotFoundError(2, "No such file"),
        HTTPError("https://splunk.test", 401, "Unauthorized", Message(), None),
        requests.HTTPError("500 Server Error"),
    ],
    ids=lambda error: type(error).__name__,
)
def test_anything_else_is_not(error: Exception) -> None:
    assert transport_error(error) is None


def test_a_carbon_black_wrapper_is_unwrapped() -> None:
    inner = requests.ConnectionError("Connection refused")
    wrapped = cbc_errors.ConnectionError("network connection error", original_exception=inner)
    assert transport_error(wrapped) is inner
    assert (
        transport_error(cbc_errors.TimeoutError(original_exception=requests.ReadTimeout()))
        is not None
    )


def test_a_carbon_black_configuration_error_is_not_a_transport_error() -> None:
    """The SDK raises the same ``ConnectionError`` for a bad URL, with nothing wrapped."""
    assert transport_error(cbc_errors.ConnectionError("No API token provided")) is None


def test_reaching_tenant_names_the_tenant_host_and_error() -> None:
    error = URLError(ConnectionRefusedError(111, "Connection refused"))
    with (
        pytest.raises(TenantUnreachableError) as caught,
        reaching_tenant("splunk", "prod", "splunk.test:8089"),
    ):
        raise error
    assert (caught.value.platform, caught.value.tenant, caught.value.host) == (
        "splunk",
        "prod",
        "splunk.test:8089",
    )
    assert caught.value.error is error
    assert str(caught.value) == (
        "Cannot reach splunk tenant 'prod' at splunk.test:8089: "
        "<urlopen error [Errno 111] Connection refused>"
    )


def test_reaching_tenant_names_the_host_the_request_failed_on() -> None:
    """Elastic has two hosts; the failed request says which, without credentials or path."""
    failed = _failed_request("https://user:secret@es.test:9200/_query?format=json")
    with (
        pytest.raises(TenantUnreachableError) as caught,
        reaching_tenant("elastic", "prod", "https://kibana.test"),
    ):
        raise failed
    assert caught.value.host == "https://es.test:9200"


def test_reaching_tenant_leaves_other_errors_alone() -> None:
    with pytest.raises(KeyError), reaching_tenant("splunk", "prod", "splunk.test:8089"):
        raise KeyError("programming error")


# --------------------------------------------------------------------------
# A read timeout is one slow query; a connect failure is an unreachable tenant
# --------------------------------------------------------------------------


def _read_timeout_after_retries() -> requests.ConnectionError:
    """What ``requests`` raises when urllib3's retries end on a read timeout (Elastic)."""
    import urllib3.exceptions

    inner = urllib3.exceptions.ReadTimeoutError(None, "/_query", "Read timed out.")
    return requests.ConnectionError(urllib3.exceptions.MaxRetryError(None, "/_query", inner))


def _azure(kind: str) -> Exception:
    from azure.core.exceptions import ServiceRequestError, ServiceResponseTimeoutError

    if kind == "response":
        read = requests.ReadTimeout("Read timed out.")
        return ServiceResponseTimeoutError(read, error=read)
    refused = requests.ConnectionError("Connection refused")
    return ServiceRequestError(refused, error=refused)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(requests.ReadTimeout("Read timed out."), id="requests-ReadTimeout"),
        pytest.param(TimeoutError("The read operation timed out"), id="urlopen-read"),
        pytest.param(_read_timeout_after_retries(), id="requests-retries-exhausted"),
        pytest.param(_azure("response"), id="azure-ServiceResponseTimeoutError"),
        pytest.param(
            cbc_errors.TimeoutError(original_exception=requests.ReadTimeout()),
            id="cbc-TimeoutError-read",
        ),
    ],
)
def test_a_read_timeout_is_one(error: Exception) -> None:
    from opentide.platforms.transport import read_timeout

    assert read_timeout(error) is not None
    assert transport_error(error) is not None


def test_a_gateway_page_is_a_read_timeout() -> None:
    from opentide.platforms.transport import GatewayTimeoutError, read_timeout

    error = GatewayTimeoutError("HTTP 504 Gateway Timeout", status=504, elapsed=61.0)
    assert read_timeout(error) is error
    assert (error.status, error.elapsed) == (504, 61.0)


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(requests.ConnectTimeout("connect timed out"), id="requests-ConnectTimeout"),
        pytest.param(URLError(TimeoutError("timed out")), id="urlopen-connect-timeout"),
        pytest.param(requests.ConnectionError("Connection refused"), id="requests-refused"),
        pytest.param(requests.exceptions.SSLError("certificate verify failed"), id="tls"),
        pytest.param(requests.exceptions.ProxyError("Unable to connect"), id="proxy"),
        pytest.param(socket.gaierror(-2, "Name or service not known"), id="dns"),
        pytest.param(
            cbc_errors.TimeoutError(original_exception=requests.ConnectTimeout()),
            id="cbc-TimeoutError-connect",
        ),
        pytest.param(_azure("request"), id="azure-ServiceRequestError"),
        pytest.param(ValueError("bad query"), id="not-a-network-error"),
        pytest.param(
            HTTPError("https://splunk.test", 504, "Gateway Timeout", Message(), None),
            id="http-status",
        ),
    ],
)
def test_a_connect_failure_or_anything_else_is_not_a_read_timeout(error: Exception) -> None:
    from opentide.platforms.transport import read_timeout

    assert read_timeout(error) is None


def test_azure_connection_errors_are_transport_errors() -> None:
    """Sentinel's SDK wraps the ``requests`` error; it used to be reported as a query failure."""
    error = _azure("request")
    assert isinstance(transport_error(error), requests.ConnectionError)


def test_an_unreachable_tenant_after_timeouts_says_so() -> None:
    error = TenantUnreachableError(
        "splunk",
        "Default",
        "splunk.test:443",
        TimeoutError("timed out"),
        reason="3 queries in a row got no answer",
        timeouts=3,
    )
    assert str(error) == (
        "Cannot reach splunk tenant 'Default' at splunk.test:443: 3 queries in a row got no answer"
    )
    assert error.timeouts == 3


# --------------------------------------------------------------------------
# An answer that is not the API's: its status, its page, a gateway's reading
# --------------------------------------------------------------------------

_GATEWAY_PAGE = b"<html><head><title>504 Gateway Time-out</title></head><body/></html>"


@pytest.mark.parametrize("status", [502, 503, 504])
def test_a_gateway_status_names_the_gateway_and_not_the_url(status: int) -> None:
    from opentide.platforms.transport import describe_answer

    text = describe_answer(status, _GATEWAY_PAGE, content_type="text/html")

    assert text.startswith(f"HTTP {status} with an HTML page titled '504 Gateway Time-out'")
    assert "gateway or proxy in front of the tenant" in text
    assert "the url and port are not at fault" in text


def test_a_slow_page_is_read_as_a_gateway_and_a_quick_one_is_not() -> None:
    from opentide.platforms.transport import describe_answer

    slow = describe_answer(200, b"<!DOCTYPE html><html></html>", elapsed=45.2)
    quick = describe_answer(200, b"<!DOCTYPE html><html></html>", elapsed=0.3)

    assert slow == (
        "HTTP 200 with an HTML page: it came after 45s, as from a gateway or proxy in front "
        "of the tenant that stopped waiting for it"
    )
    assert quick == "HTTP 200 with an HTML page"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"", "HTTP 500 with an empty body"),
        (
            b"upstream  connect\nerror",
            "HTTP 500 with a body that is not JSON ('upstream connect error')",
        ),
    ],
)
def test_other_bodies_are_described(body: bytes, expected: str) -> None:
    from opentide.platforms.transport import describe_answer

    assert describe_answer(500, body) == expected


def test_not_json_detail_reads_a_requests_response() -> None:
    from datetime import timedelta

    from opentide.platforms.transport import not_json_detail

    page = requests.Response()
    page.status_code = 504
    page._content = _GATEWAY_PAGE
    page.headers["Content-Type"] = "text/html"
    page.elapsed = timedelta(seconds=60)
    answer = requests.Response()
    answer.status_code = 400
    answer._content = b'{"error": "bad"}'

    detail = not_json_detail(page)
    assert detail is not None and detail.startswith("HTTP 504 with an HTML page titled")
    assert not_json_detail(answer) is None
