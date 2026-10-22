"""A local HTTPS stand-in for a Splunk management port and other platform APIs.

It serves a self-signed certificate, as an on-premises Splunk often does, and
answers the endpoints opentide calls the way Splunk does: ``server/info``,
``search/parser`` (``|badcommand`` is a parse error, ``|unreachable`` a 307
"Network Error") and ``saved/searches``,
where an argument the REST handler does not know is refused with HTTP 400
``Argument "<name>" is not supported by this handler.`` and a ``DELETE``
removes the saved search.
"""

from __future__ import annotations

import datetime
import http.server
import json
import socket
import ssl
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

SAVED_SEARCHES = "/servicesNS/nobody/search/saved/searches/"
_SERVER_INFO = "/services/server/info"

#: savedsearches.conf spellings the saved/searches REST handler refuses; the
#: endpoint takes ``alert_type``, ``alert_comparator`` and ``alert_threshold``.
CONF_ONLY_ARGUMENTS = frozenset({"counttype", "relation", "quantity"})


@dataclass
class SplunkStandIn:
    port: int
    saved_searches: dict[str, dict[str, str]] = field(default_factory=dict)
    requests: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)

    def posted(self, name: str) -> dict[str, str]:
        """Every argument POSTed to the saved search *name*, merged in order."""
        merged: dict[str, str] = {}
        for method, path, args in self.requests:
            if method == "POST" and urllib.parse.unquote_plus(path) == SAVED_SEARCHES + name:
                merged.update(args)
        return merged


def _entry(name: str, content: dict[str, str]) -> str:
    keys = "".join(f'<s:key name="{key}">{value}</s:key>' for key, value in content.items())
    path = SAVED_SEARCHES + urllib.parse.quote(name)
    return (
        f"<entry><title>{name}</title><id>https://localhost{path}</id>"
        f'<link href="{path}" rel="alternate"/>'
        f'<content type="text/xml"><s:dict>{keys}'
        '<s:key name="eai:acl"><s:dict><s:key name="app">search</s:key>'
        '<s:key name="owner">nobody</s:key><s:key name="sharing">app</s:key>'
        "</s:dict></s:key></s:dict></content></entry>"
    )


def _feed(*entries: str) -> bytes:
    return (
        '<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest">'
        + "".join(entries)
        + "</feed>"
    ).encode()


def _handler(state: SplunkStandIn) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self, status: int, body: bytes, content_type: str = "text/xml") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve(self) -> None:
            url = urllib.parse.urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode() if length else url.query
            args = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
            state.requests.append((self.command, url.path, args))
            path = urllib.parse.unquote_plus(url.path)

            if self.command == "POST" and path.endswith(("/oauth2/token", "/oauth2/v2.0/token")):
                # CrowdStrike answers 201, Entra ID 200.
                status = 201 if path.endswith("/oauth2/token") else 200
                return self._reply(status, b'{"access_token": "token"}', "application/json")
            if path == _SERVER_INFO:
                info = {"version": "9.3.0", "instance_type": "download", "serverName": "stand-in"}
                return self._reply(200, _feed(_entry("server-info", info)))
            if path.endswith(("/search/parser", "/search/v2/parser")):
                if "|unreachable" in args.get("q", ""):
                    # What a gateway in front of Splunk answers when the search head times out.
                    return self._reply(307, b"Network Error", "text/plain")
                if "|badcommand" in args.get("q", ""):
                    message = {"messages": [{"type": "FATAL", "text": "Unknown search command"}]}
                    return self._reply(400, json.dumps(message).encode(), "application/json")
                return self._reply(200, b'{"commands": []}', "application/json")

            if not path.startswith(SAVED_SEARCHES):
                return self._reply(404, b"")
            name = path.removeprefix(SAVED_SEARCHES)
            if self.command == "POST":
                refused = sorted(set(args) & CONF_ONLY_ARGUMENTS)
                if refused:
                    message = f'Argument "{refused[0]}" is not supported by this handler.'
                    body = (
                        f'<response><messages><msg type="ERROR">{message}</msg>'
                        "</messages></response>"
                    )
                    return self._reply(400, body.encode())
                if not name:
                    name = args.pop("name")
                    state.saved_searches[name] = {}
                    status = 201
                elif name not in state.saved_searches:
                    return self._reply(404, b"")
                else:
                    status = 200
                state.saved_searches[name].update(args)
                return self._reply(status, _feed(_entry(name, state.saved_searches[name])))
            if self.command == "DELETE":
                if state.saved_searches.pop(name, None) is None:
                    return self._reply(404, b"")
                return self._reply(200, _feed())
            if name in state.saved_searches:
                return self._reply(200, _feed(_entry(name, state.saved_searches[name])))
            return self._reply(404, b"")

        do_GET = do_POST = do_DELETE = _serve

        def log_message(self, *args: object) -> None:
            pass

    return Handler


def _self_signed(directory: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@contextmanager
def serve_splunk(directory: Path) -> Iterator[SplunkStandIn]:
    """Serve a stand-in on a free ``127.0.0.1`` port; its certificate names ``localhost``."""
    cert, key = _self_signed(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
    state = SplunkStandIn(port=server.server_address[1])
    server.RequestHandlerClass = _handler(state)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


#: What a TLS-inspecting corporate proxy answers for a host its policy refuses.
BLOCK_PAGE = b"""<!DOCTYPE html>
<html>
<head>
<title>Access denied by policy</title>
<meta charset="utf-8">
</head>
<body><p>This site is blocked.<br></body>
</html>
"""


@dataclass
class InterceptingProxy:
    port: int
    tunnels: int = 0


def _serve_block_page(directory: Path) -> http.server.ThreadingHTTPServer:
    cert, key = _self_signed(directory)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)

    class Handler(http.server.BaseHTTPRequestHandler):
        def _serve(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(BLOCK_PAGE)))
            self.end_headers()
            self.wfile.write(BLOCK_PAGE)

        do_GET = do_POST = do_DELETE = _serve

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@contextmanager
def serve_block_page(directory: Path) -> Iterator[int]:
    """An HTTPS server that answers every path with :data:`BLOCK_PAGE`; yields its port."""
    server = _serve_block_page(directory)
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def serve_intercepting_proxy(directory: Path) -> Iterator[InterceptingProxy]:
    """A proxy that accepts every ``CONNECT`` and answers it with :data:`BLOCK_PAGE`.

    The tunnel ends at its own TLS server, as a TLS-inspecting proxy does,
    so a client that does not verify certificates reads the block page.
    """
    page = _serve_block_page(directory)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    state = InterceptingProxy(port=listener.getsockname()[1])
    stop = threading.Event()

    def pipe(source: socket.socket, sink: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for end in (source, sink):
                with suppress(OSError):
                    end.shutdown(socket.SHUT_RDWR)

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except OSError:
                continue
            client.settimeout(5)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    break
                head += chunk
            if not head.startswith(b"CONNECT "):
                client.close()
                continue
            state.tunnels += 1
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            client.settimeout(None)
            upstream = socket.create_connection(("127.0.0.1", page.server_address[1]))
            threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
            threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        thread.join()
        listener.close()
        page.shutdown()
        page.server_close()
