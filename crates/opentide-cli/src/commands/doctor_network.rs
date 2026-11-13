//! `doctor`'s network checks (UC-4.4, #834; `check_latest_version` and
//! `check_proxy` of `cli/services/doctor.py`): the newest opentide release
//! on PyPI, and whether the proxy accepts a connection. `--offline` skips
//! both, as before.
//!
//! A failure is named as the oracle names it, by the Python exception
//! `requests` or `socket` raises for it (`ProxyError`,
//! `ConnectionRefusedError`): the checklist's message carries that name.

use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, TenantLabel};
use tokio_util::sync::CancellationToken;

/// `NETWORK_TIMEOUT`: seconds each network check may take to connect, and
/// then to read.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

/// Where the newest release is read (`PYPI_URL`).
pub const PYPI_URL: &str = "https://pypi.org/pypi/opentide/json";

/// The fix a newer release names (`UPGRADE_COMMAND`).
pub const UPGRADE_COMMAND: &str = "pip install --upgrade opentide";

/// Why the newest release could not be read: the Python exception's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed(pub &'static str);

/// The Python exception `requests` raises for `error` on a request whose
/// route is `proxied` (`requests.exceptions`' names).
pub fn request_error_name(error: &ConnectorError, proxied: bool) -> &'static str {
    match error {
        ConnectorError::Unreachable { reason, .. } => {
            let reason = reason.to_ascii_lowercase();
            if reason.contains("certificate") || reason.contains("tls") || reason.contains("ssl") {
                "SSLError"
            } else if proxied {
                "ProxyError"
            } else if reason.contains("timed out") || reason.contains("timeout") {
                "ConnectTimeout"
            } else {
                "ConnectionError"
            }
        }
        ConnectorError::Timeout { .. } => "ReadTimeout",
        ConnectorError::Setup { .. } => "InvalidURL",
        _ => "ConnectionError",
    }
}

/// The version in PyPI's answer (`response.json()["info"]["version"]`), or
/// the exception reading it raises.
pub fn version_of(status: u16, body: &[u8]) -> Result<String, Failed> {
    if status >= 400 {
        return Err(Failed("HTTPError"));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| Failed("JSONDecodeError"))?;
    let info = match &parsed {
        serde_json::Value::Object(map) => map.get("info").ok_or(Failed("KeyError"))?,
        serde_json::Value::Array(_) | serde_json::Value::String(_) => {
            return Err(Failed("TypeError"));
        }
        _ => return Err(Failed("TypeError")),
    };
    let version = match info {
        serde_json::Value::Object(map) => map.get("version").ok_or(Failed("KeyError"))?,
        serde_json::Value::Array(_) | serde_json::Value::String(_) => {
            return Err(Failed("TypeError"));
        }
        _ => return Err(Failed("TypeError")),
    };
    match version {
        serde_json::Value::String(text) if !text.is_empty() => Ok(text.clone()),
        _ => Err(Failed("ValueError")),
    }
}

/// The newest opentide release on PyPI (`fetch_latest_version`), through
/// the proxy and CA bundles the environment names.
pub fn fetch_latest(env: &Environment, proxy: Option<&str>) -> Result<String, Failed> {
    let settings = HttpSettings {
        timeout: NETWORK_TIMEOUT,
        ..HttpSettings::default()
    };
    let label = TenantLabel::new("pypi", "pypi.org");
    let client =
        HttpClient::new(&label, &settings, env, proxy).map_err(|_| Failed("InvalidURL"))?;
    let proxied = url::Url::parse(PYPI_URL)
        .ok()
        .and_then(|url| client.route(&url))
        .is_some();
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                opentide_connectors::runtime::block_on(async {
                    let cancel = CancellationToken::new();
                    let request = client
                        .request(opentide_connectors::transport::Method::GET, PYPI_URL)
                        .build()
                        .map_err(|_| Failed("InvalidURL"))?;
                    let answer = client
                        .send(request, &cancel)
                        .await
                        .map_err(|error| Failed(request_error_name(&error, proxied)))?;
                    let status = answer.status().as_u16();
                    let body = client
                        .bytes(answer, &cancel)
                        .await
                        .map_err(|error| Failed(request_error_name(&error, proxied)))?;
                    version_of(status, &body)
                })
                .unwrap_or(Err(Failed("RuntimeError")))
            })
            .join()
            .unwrap_or(Err(Failed("RuntimeError")))
    })
}

/// Whether `latest` is a newer release than `installed` (PEP 440, as
/// `packaging.version.Version` orders them; a version PEP 440 cannot read
/// compares by its first three dotted numbers).
pub fn newer(latest: &str, installed: &str) -> bool {
    use std::str::FromStr as _;
    match (
        pep440_rs::Version::from_str(latest),
        pep440_rs::Version::from_str(installed),
    ) {
        (Ok(latest), Ok(installed)) => latest > installed,
        _ => loose_key(latest) > loose_key(installed),
    }
}

/// `tuple(int(part) if part.isdigit() else 0 for part in text.split(".")[:3])`.
fn loose_key(text: &str) -> Vec<u128> {
    text.split('.')
        .take(3)
        .map(|part| {
            if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                part.parse().unwrap_or(u128::MAX)
            } else {
                0
            }
        })
        .collect()
}

/// The Python exception `socket.create_connection` raises for `error`.
pub fn socket_error_name(error: &std::io::Error) -> &'static str {
    match error.kind() {
        ErrorKind::ConnectionRefused => "ConnectionRefusedError",
        ErrorKind::ConnectionReset => "ConnectionResetError",
        ErrorKind::ConnectionAborted => "ConnectionAbortedError",
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "TimeoutError",
        ErrorKind::PermissionDenied => "PermissionError",
        ErrorKind::InvalidInput => "ValueError",
        _ => "OSError",
    }
}

/// Opens and closes a TCP connection to `host:port` (`connect`): each
/// address the name resolves to in turn, as `socket.create_connection`
/// tries them; the last address's error when none accepts.
///
/// # Errors
///
/// The name does not resolve (`gaierror`), or no address accepts: the
/// Python exception's name.
pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<(), &'static str> {
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| "gaierror")?
        .collect();
    if addresses.is_empty() {
        return Err("gaierror");
    }
    let mut last = "OSError";
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) => last = socket_error_name(&error),
        }
    }
    Err(last)
}

/// The scheme, host and port of a proxy URL (`proxy_endpoint`), the
/// credentials cut off at the last `@`; `None` when it cannot be parsed.
pub fn proxy_endpoint(url: &str) -> Option<(String, String, Option<u16>)> {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("http", url),
    };
    if scheme.is_empty() || !scheme.chars().all(char::is_alphanumeric) {
        return None;
    }
    let host_port = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
    let host_port = host_port.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = split_host_port(host_port)?;
    Some((scheme.to_owned(), host, port))
}

/// `urlsplit`'s `hostname` (lowercase, IPv6 without brackets) and `port`.
fn split_host_port(text: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port),
            None if after.is_empty() => None,
            None => return None,
        };
        (host.to_owned(), port)
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (text.to_owned(), None),
        }
    };
    let port = match port {
        None | Some("") => None,
        Some(port) => {
            if !port.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            Some(port.parse::<u16>().ok()?)
        }
    };
    Some((host.to_lowercase(), port))
}

/// Whether `NO_PROXY` sends requests to `host` direct (`_bypasses_proxy`).
pub fn bypasses_proxy(host: &str, no_proxy: &str) -> bool {
    no_proxy
        .split(',')
        .map(|entry| entry.trim().to_lowercase())
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            if entry == "*" {
                return true;
            }
            let entry = entry.trim_start_matches('.');
            host == entry || host.ends_with(&format!(".{entry}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_as_pep_440_does() {
        assert!(newer("0.24.0", "0.23.0"));
        assert!(!newer("0.23.0", "0.23.0"));
        assert!(newer("0.24.0", "0.24.0rc1"));
        assert!(!newer("0.24.0rc1", "0.24.0"));
        assert!(newer("1.0", "0.99.99"));
        // Neither reads as PEP 440: the loose key.
        assert!(newer("2.x.y", "1.x.y"));
        assert!(!newer("x", "y"));
    }

    #[test]
    fn pypi_answers_read_as_python_reads_them() {
        assert_eq!(
            version_of(200, br#"{"info": {"version": "1.2.3"}}"#),
            Ok("1.2.3".to_owned())
        );
        assert_eq!(version_of(503, b""), Err(Failed("HTTPError")));
        assert_eq!(version_of(200, b"<html>"), Err(Failed("JSONDecodeError")));
        assert_eq!(version_of(200, b"{}"), Err(Failed("KeyError")));
        assert_eq!(version_of(200, br#"{"info": {}}"#), Err(Failed("KeyError")));
        assert_eq!(version_of(200, b"[]"), Err(Failed("TypeError")));
        assert_eq!(version_of(200, br#"{"info": 1}"#), Err(Failed("TypeError")));
        assert_eq!(
            version_of(200, br#"{"info": []}"#),
            Err(Failed("TypeError"))
        );
        assert_eq!(
            version_of(200, br#"{"info": {"version": ""}}"#),
            Err(Failed("ValueError"))
        );
        assert_eq!(
            version_of(200, br#"{"info": {"version": 3}}"#),
            Err(Failed("ValueError"))
        );
    }

    #[test]
    fn request_errors_take_requests_names() {
        let unreachable = |reason: &str| ConnectorError::Unreachable {
            platform: "pypi".into(),
            tenant: "pypi.org".into(),
            address: "https://pypi.org".into(),
            reason: reason.into(),
        };
        assert_eq!(
            request_error_name(&unreachable("connection refused"), true),
            "ProxyError"
        );
        assert_eq!(
            request_error_name(&unreachable("connection refused"), false),
            "ConnectionError"
        );
        assert_eq!(
            request_error_name(&unreachable("operation timed out"), false),
            "ConnectTimeout"
        );
        assert_eq!(
            request_error_name(&unreachable("invalid peer certificate"), true),
            "SSLError"
        );
        let timeout = ConnectorError::Timeout {
            platform: "pypi".into(),
            tenant: "pypi.org".into(),
            address: "https://pypi.org".into(),
            seconds: 3,
        };
        assert_eq!(request_error_name(&timeout, false), "ReadTimeout");
        assert_eq!(
            request_error_name(&ConnectorError::Cancelled, false),
            "ConnectionError"
        );
        let setup = ConnectorError::Setup {
            platform: "pypi".into(),
            tenant: "pypi.org".into(),
            message: "bad".into(),
        };
        assert_eq!(request_error_name(&setup, false), "InvalidURL");
    }

    #[test]
    fn socket_errors_take_pythons_names() {
        let named = |kind: ErrorKind| socket_error_name(&std::io::Error::from(kind));
        assert_eq!(
            named(ErrorKind::ConnectionRefused),
            "ConnectionRefusedError"
        );
        assert_eq!(named(ErrorKind::ConnectionReset), "ConnectionResetError");
        assert_eq!(
            named(ErrorKind::ConnectionAborted),
            "ConnectionAbortedError"
        );
        assert_eq!(named(ErrorKind::TimedOut), "TimeoutError");
        assert_eq!(named(ErrorKind::PermissionDenied), "PermissionError");
        assert_eq!(named(ErrorKind::InvalidInput), "ValueError");
        assert_eq!(named(ErrorKind::Other), "OSError");
    }

    #[test]
    fn a_listening_port_accepts_and_a_closed_one_refuses() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(connect("127.0.0.1", port, NETWORK_TIMEOUT), Ok(()));
        drop(listener);
        assert_eq!(
            connect("127.0.0.1", port, NETWORK_TIMEOUT),
            Err("ConnectionRefusedError")
        );
    }

    #[test]
    fn proxy_urls_split_as_urlsplit_does() {
        assert_eq!(
            proxy_endpoint("http://user:p/a#ss@Proxy.Example:8080/x"),
            Some(("http".into(), "proxy.example".into(), Some(8080)))
        );
        assert_eq!(
            proxy_endpoint("proxy:3128"),
            Some(("http".into(), "proxy".into(), Some(3128)))
        );
        assert_eq!(
            proxy_endpoint("https://[::1]:443"),
            Some(("https".into(), "::1".into(), Some(443)))
        );
        assert_eq!(
            proxy_endpoint("https://[::1]"),
            Some(("https".into(), "::1".into(), None))
        );
        assert_eq!(proxy_endpoint("http://host:99999"), None);
        assert_eq!(proxy_endpoint("http://host:8x"), None);
        assert_eq!(proxy_endpoint("http://[::1"), None);
        assert_eq!(proxy_endpoint("http://[::1]x"), None);
        assert_eq!(proxy_endpoint("ht tp://host"), None);
        assert_eq!(
            proxy_endpoint("http://"),
            Some(("http".into(), String::new(), None))
        );
    }

    #[test]
    fn no_proxy_entries_match_hosts_and_their_subdomains() {
        assert!(bypasses_proxy("pypi.org", "localhost, .pypi.org"));
        assert!(bypasses_proxy("files.pypi.org", "pypi.org"));
        assert!(bypasses_proxy("pypi.org", "*"));
        assert!(!bypasses_proxy("pypi.org", "example.org,,"));
        assert!(!bypasses_proxy("notpypi.org", "pypi.org"));
    }
}
