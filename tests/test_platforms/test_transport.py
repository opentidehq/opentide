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
