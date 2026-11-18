//! `doctor`'s network checks (UC-4.4, #834): the newest opentide release on
//! PyPI, and whether the proxy accepts a connection. `--offline` skips both,
//! as before. A failure is named by what went wrong: the HTTP client's
//! error, PyPI's status or answer, or the operating system's error for the
//! proxy's connection.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use opentide_connectors::proxy::ProxySettings;
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, TenantLabel};
use tokio_util::sync::CancellationToken;

/// `NETWORK_TIMEOUT`: seconds each network check may take to connect, and
/// then to read.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

/// Where the newest release is read (`PYPI_URL`).
pub const PYPI_URL: &str = "https://pypi.org/pypi/opentide/json";

/// The fix a newer release names (`UPGRADE_COMMAND`).
pub const UPGRADE_COMMAND: &str = "pip install --upgrade opentide";

/// Why the newest release could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failed {
    /// A build with no network of its own (the WASI build outside an
    /// `opentide serve` whose client makes its requests).
    NoNetwork,
    /// What went wrong, in words.
    Problem(String),
}

impl Failed {
    fn problem(text: impl Into<String>) -> Self {
        Self::Problem(text.into())
    }
}

/// The version in PyPI's answer (`info.version`), or why it cannot be read.
pub fn version_of(status: u16, body: &[u8]) -> Result<String, Failed> {
    if status >= 400 {
        return Err(Failed::problem(format!("PyPI answered HTTP {status}")));
    }
    let parsed: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| Failed::problem(format!("PyPI's answer is not JSON: {error}")))?;
    match parsed.pointer("/info/version") {
        Some(serde_json::Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        _ => Err(Failed::problem("PyPI's answer has no `info.version`")),
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
    let client = HttpClient::new(&label, &settings, env, proxy).map_err(|error| match error {
        ConnectorError::NetworkUnavailable { .. } => Failed::NoNetwork,
        other => Failed::problem(other.to_string()),
    })?;
    let stopped = || Failed::problem("the request stopped unexpectedly");
    opentide_connectors::runtime::sync_call(|| {
        opentide_connectors::runtime::block_on(async {
            let cancel = CancellationToken::new();
            let request = client
                .request(opentide_connectors::transport::Method::GET, PYPI_URL)
                .build()
                .map_err(|error| Failed::problem(error.to_string()))?;
            let answer = client
                .send(request, &cancel)
                .await
                .map_err(|error| Failed::problem(error.to_string()))?;
            let status = answer.status().as_u16();
            let body = client
                .bytes(answer, &cancel)
                .await
                .map_err(|error| Failed::problem(error.to_string()))?;
            version_of(status, &body)
        })
        .unwrap_or_else(|_| Err(stopped()))
    })
    .unwrap_or_else(|_| Err(stopped()))
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

/// The first three dotted parts of `text` as numbers, a part that is not
/// one as 0.
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

/// Opens and closes a TCP connection to `host:port`: each address the name
/// resolves to in turn; the last address's error when none accepts.
///
/// # Errors
///
/// The name does not resolve, or no address accepts: what went wrong, in
/// the operating system's words.
pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {host}: {error}"))?
        .collect();
    let mut last = format!("cannot resolve {host}: no address");
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) => last = error.to_string(),
        }
    }
    Err(last)
}

/// The proxy `doctor` tests, as the connectors choose it ([`ProxySettings`]
/// from the run's environment and `--proxy`): the one their `https://`
/// requests go through (PyPI's, and nearly every tenant's), else the one of
/// their `http://` requests, with `true` when only those use it. `None` when
/// no proxy is set. `no_proxy` does not change the choice: it sends some
/// hosts direct, not every request.
pub fn proxy_to_test(env: &Environment, proxy: Option<&str>) -> Option<(String, bool)> {
    let settings = ProxySettings::from_env(env, proxy);
    match (settings.https, settings.http) {
        (Some(https), _) => Some((https, false)),
        (None, Some(http)) => Some((http, true)),
        (None, None) => None,
    }
}

/// Whether a request to *url* goes direct by `no_proxy` (else `NO_PROXY`),
/// asked of the connectors' own proxy settings, so the route `doctor`
/// reports is the one its requests take.
pub fn bypasses_proxy(env: &Environment, proxy: Option<&str>, url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|url| ProxySettings::from_env(env, proxy).bypassed(&url))
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
    fn pypi_answers_name_what_is_wrong() {
        assert_eq!(
            version_of(200, br#"{"info": {"version": "1.2.3"}}"#),
            Ok("1.2.3".to_owned())
        );
        assert_eq!(
            version_of(503, b""),
            Err(Failed::problem("PyPI answered HTTP 503"))
        );
        let Err(Failed::Problem(text)) = version_of(200, b"<html>") else {
            panic!("HTML read as a version");
        };
        assert!(text.starts_with("PyPI's answer is not JSON: "), "{text}");
        let unread = Err(Failed::problem("PyPI's answer has no `info.version`"));
        for body in [
            &b"{}"[..],
            br#"{"info": {}}"#,
            b"[]",
            br#"{"info": 1}"#,
            br#"{"info": []}"#,
            br#"{"info": {"version": ""}}"#,
            br#"{"info": {"version": 3}}"#,
        ] {
            assert_eq!(version_of(200, body), unread, "{body:?}");
        }
    }

    #[test]
    fn a_listening_port_accepts_and_a_closed_one_refuses() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(connect("127.0.0.1", port, NETWORK_TIMEOUT), Ok(()));
        drop(listener);
        let refused = connect("127.0.0.1", port, NETWORK_TIMEOUT).unwrap_err();
        assert!(refused.to_lowercase().contains("refused"), "{refused}");
        let unresolved = connect("name.invalid", 80, NETWORK_TIMEOUT).unwrap_err();
        assert!(
            unresolved.starts_with("cannot resolve name.invalid: "),
            "{unresolved}"
        );
    }

    /// The scheme, host and port the proxy check connects to.
    fn endpoint(url: &str) -> Option<(String, String, Option<u16>)> {
        let parsed = opentide_connectors::proxy::parse(url).ok()?;
        Some((
            parsed.scheme().to_owned(),
            parsed.host_str()?.to_owned(),
            parsed.port_or_known_default(),
        ))
    }

    #[test]
    fn proxy_urls_parse_as_the_connectors_read_them() {
        assert_eq!(
            endpoint("http://user:p%2Fa%23ss@Proxy.Example:8080/x"),
            Some(("http".into(), "proxy.example".into(), Some(8080)))
        );
        assert_eq!(
            endpoint("proxy:3128"),
            Some(("http".into(), "proxy".into(), Some(3128)))
        );
        assert_eq!(
            endpoint("https://[::1]:8443"),
            Some(("https".into(), "[::1]".into(), Some(8443)))
        );
        assert_eq!(
            endpoint("https://[::1]"),
            Some(("https".into(), "[::1]".into(), Some(443)))
        );
        for unparsed in [
            "http://host:99999",
            "http://host:8x",
            "http://[::1",
            "http://[::1]x",
            "ht tp://host",
            "http://",
        ] {
            assert!(
                opentide_connectors::proxy::parse(unparsed).is_err(),
                "{unparsed}"
            );
        }
    }

    #[test]
    fn no_proxy_entries_match_hosts_their_subdomains_and_address_ranges() {
        let direct = |no_proxy: &str, url: &str| {
            let env = Environment::from_pairs([("NO_PROXY", no_proxy)]);
            bypasses_proxy(&env, Some("http://proxy:3128"), url)
        };
        assert!(direct("localhost, .pypi.org", PYPI_URL));
        assert!(direct("pypi.org", "https://files.pypi.org/x"));
        assert!(direct("*", PYPI_URL));
        assert!(!direct("example.org,,", PYPI_URL));
        assert!(!direct("pypi.org", "https://notpypi.org/x"));
        // A CIDR entry covers the addresses in its range, as reqwest reads it.
        assert!(direct("10.0.0.0/8", "https://10.1.2.3:8089/x"));
        assert!(!direct("10.0.0.0/8", "https://11.1.2.3:8089/x"));
        // The lower-case spelling wins, as the connectors read it.
        let env = Environment::from_pairs([("no_proxy", "example.org"), ("NO_PROXY", "pypi.org")]);
        assert!(!bypasses_proxy(&env, None, PYPI_URL));
    }
}
