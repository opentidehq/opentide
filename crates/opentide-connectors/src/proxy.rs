//! The proxy a request goes through, from `--proxy` / `OPENTIDE_PROXY` and
//! the standard variables (documented in docs/usage/configuration.md).
//!
//! The precedence, for each scheme: `--proxy`, then `OPENTIDE_PROXY`, then
//! the scheme's variable (`https_proxy` for `https://` URLs, `http_proxy`
//! for `http://` ones), then `all_proxy`; of each variable the lower-case
//! spelling is read first, then the upper-case one, as curl reads them.
//! `no_proxy` (else `NO_PROXY`) lists the hosts that go direct, whatever
//! the proxy came from. The variables are read from the run's
//! [`Environment`], not the process's, so each tenant's client is built from
//! what the command was given.

use hyper_util::client::proxy::matcher::Matcher;

use crate::Environment;

/// The proxies of a run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxySettings {
    /// The proxy of `https://` requests.
    pub https: Option<String>,
    /// The proxy of `http://` requests.
    pub http: Option<String>,
    /// The hosts that go direct (`no_proxy`'s list).
    pub no_proxy: Option<String>,
}

impl ProxySettings {
    /// The proxies *env* names, with *explicit* (`--proxy`, then
    /// `OPENTIDE_PROXY`) in place of the scheme variables when given.
    pub fn from_env(env: &Environment, explicit: Option<&str>) -> Self {
        let explicit = explicit
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| env.get("OPENTIDE_PROXY"));
        let all = env.first(&["all_proxy", "ALL_PROXY"]);
        let scheme = |lower: &str, upper: &str| {
            explicit
                .or_else(|| env.first(&[lower, upper]))
                .or(all)
                .map(str::to_owned)
        };
        Self {
            https: scheme("https_proxy", "HTTPS_PROXY"),
            http: scheme("http_proxy", "HTTP_PROXY"),
            no_proxy: env.first(&["no_proxy", "NO_PROXY"]).map(str::to_owned),
        }
    }

    /// The proxy *url* goes through, as `scheme://host[:port]` without
    /// credentials; `None` when it goes direct: no proxy for its scheme, or
    /// its host in `no_proxy` (`*`, a host or an IP address, a CIDR range, a
    /// domain and its subdomains), as the transport reads the list.
    pub fn route(&self, url: &url::Url) -> Option<String> {
        let proxy = match url.scheme() {
            "https" => self.https.as_deref(),
            "http" => self.http.as_deref(),
            _ => None,
        }?;
        if self.bypassed(url) {
            return None;
        }
        redact(proxy)
    }

    /// The proxy *url* goes through, as configured (its credentials
    /// included), for a transport that hands the route to its host; `None`
    /// when it goes direct.
    pub fn proxy_for(&self, url: &url::Url) -> Option<String> {
        let proxy = match url.scheme() {
            "https" => self.https.as_deref(),
            "http" => self.http.as_deref(),
            _ => None,
        }?;
        if self.bypassed(url) {
            return None;
        }
        Some(if proxy.contains("://") {
            proxy.to_owned()
        } else {
            format!("http://{proxy}")
        })
    }

    /// Whether `no_proxy` sends *url* direct: `*`, a host or an IP address,
    /// a CIDR range such as `10.0.0.0/8`, a domain and its subdomains, as the
    /// proxy matcher of reqwest's transport reads them; and an entry with a
    /// port (`splunk.internal:8089`, `[fd00::7]:8089`) for that port only,
    /// as curl and Go's `httpproxy` read it.
    pub fn bypassed(&self, url: &url::Url) -> bool {
        let Some(list) = self.no_proxy.as_deref() else {
            return false;
        };
        let Some(destination) = destination(url) else {
            return false;
        };
        let list = for_port(list, url.port_or_known_default());
        // The matcher answers for the list alone: its proxy is a stand-in
        // that always parses, so `None` means the list sends *url* direct.
        Matcher::builder()
            .all("http://proxy.invalid")
            .no(&list)
            .build()
            .intercept(&destination)
            .is_none()
    }

    /// The reqwest proxy: each request goes through its scheme's proxy
    /// unless [`bypassed`](Self::bypassed) sends it direct, so the transport
    /// and `doctor` read `no_proxy` the same way.
    #[cfg(not(target_os = "wasi"))]
    pub fn proxies(&self) -> Result<Vec<reqwest::Proxy>, crate::transport::SetupError> {
        let mut parsed = [None, None];
        for (slot, url) in parsed.iter_mut().zip([&self.https, &self.http]) {
            if let Some(url) = url {
                *slot = Some(
                    parse(url).map_err(|reason| crate::transport::SetupError::Proxy { reason })?,
                );
            }
        }
        if parsed.iter().all(Option::is_none) {
            return Ok(Vec::new());
        }
        let [https, http] = parsed;
        let settings = self.clone();
        Ok(vec![reqwest::Proxy::custom(move |url| {
            let proxy = match url.scheme() {
                "https" => https.as_ref(),
                "http" => http.as_ref(),
                _ => None,
            }?;
            (!settings.bypassed(url)).then(|| proxy.clone())
        })])
    }
}

/// *url*'s scheme and authority, as the matcher reads a destination.
fn destination(url: &url::Url) -> Option<http::Uri> {
    let host = url.host_str()?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    http::Uri::builder()
        .scheme(url.scheme())
        .authority(authority)
        .path_and_query("/")
        .build()
        .ok()
}

/// *list* for a request to *port*: an entry with a port is its host when the
/// port is the request's, and is left out when it is not; every other entry
/// is kept as written.
fn for_port(list: &str, port: Option<u16>) -> String {
    list.split(',')
        .map(str::trim)
        .filter_map(|entry| match split_port(entry) {
            Some((host, entry_port)) => (Some(entry_port) == port).then_some(host),
            None => Some(entry),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// *entry*'s host and port when it names one: `host:8089` or
/// `[fd00::7]:8089`, never a bare IPv6 address (`fd00::7`) nor a CIDR range.
fn split_port(entry: &str) -> Option<(&str, u16)> {
    let (host, port) = entry.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if let Some(inner) = host.strip_prefix('[') {
        return Some((inner.strip_suffix(']')?, port));
    }
    (!host.is_empty() && !host.contains([':', '/'])).then_some((host, port))
}

/// A proxy URL as the transport reads it: one written without a scheme
/// (`proxy.internal:8080`) is an HTTP proxy.
///
/// A URL whose text after its host holds an `@` is refused. Either its user
/// or password has an unencoded `/`, `?`, `#` or `\`, so a URL parser ends
/// the host there and reads part of the password as the host
/// (`http://user:p@ss/w#rd@proxy:8080` would name the host `ss`), or it is a
/// path, which a proxy URL has no use for. Telling the two apart would be a
/// guess, and guessing wrong would hand a piece of the password to the
/// wrong host.
///
/// # Errors
///
/// Why the text is not a proxy URL, in words that never repeat any part of
/// it.
pub fn parse(proxy: &str) -> Result<url::Url, String> {
    let proxy = proxy.trim();
    let (scheme, rest) = proxy.split_once("://").unwrap_or(("http", proxy));
    // The URL standard ends the authority at the first of these; any `@`
    // after it is a user or password that was not percent-encoded.
    if rest
        .split_once(['/', '?', '#', '\\'])
        .is_some_and(|(_, after)| after.contains('@'))
    {
        return Err(
            "an `@` follows a `/`, `?`, `#` or `\\`: if it ends a user or password, \
             percent-encode those characters in it (`%2F`, `%3F`, `%23`, `%5C`, and \
             `%40` for `@`); no path is needed"
                .to_owned(),
        );
    }
    url::Url::parse(&format!("{scheme}://{rest}")).map_err(|error| error.to_string())
}

/// *proxy* as `scheme://host[:port]`, without its user and password; `None`
/// when it is not a proxy URL ([`parse`]), so that no part of it is shown.
pub fn redact(proxy: &str) -> Option<String> {
    parse(proxy)
        .ok()
        .map(|parsed| crate::error::origin(&parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(https: Option<&str>, http: Option<&str>, no_proxy: Option<&str>) -> ProxySettings {
        ProxySettings {
            https: https.map(str::to_owned),
            http: http.map(str::to_owned),
            no_proxy: no_proxy.map(str::to_owned),
        }
    }

    fn route(settings: &ProxySettings, url: &str) -> Option<String> {
        settings.route(&url::Url::parse(url).ok()?)
    }

    #[test]
    fn a_request_names_the_proxy_of_its_scheme_without_credentials() {
        let proxies = settings(
            Some("http://user:secret@proxy.corp:3128"),
            Some("gateway.corp:8080"),
            None,
        );
        assert_eq!(
            route(&proxies, "https://splunk.example.com:8089/services"),
            Some("http://proxy.corp:3128".to_owned())
        );
        // A proxy written without a scheme is an HTTP proxy.
        assert_eq!(
            route(&proxies, "http://splunk.example.com/x"),
            Some("http://gateway.corp:8080".to_owned())
        );
        assert_eq!(route(&proxies, "ftp://files.example.com/x"), None);
        assert_eq!(
            route(
                &settings(None, Some("gateway.corp:8080"), None),
                "https://a.example.com"
            ),
            None
        );
        // A proxy that is not a URL is not shown.
        assert_eq!(
            route(
                &settings(Some("http://[proxy"), None, None),
                "https://a.example.com"
            ),
            None
        );
    }

    #[test]
    fn a_proxy_whose_password_would_be_read_as_its_host_is_refused_unshown() {
        // The last `@` ends the user info; encoded characters are fine.
        for (proxy, shown) in [
            ("http://al1ce:Qz7k@Wm4r@proxy:8080", "http://proxy:8080"),
            ("http://al1ce:Qz7k%2FWm4r@proxy:8080", "http://proxy:8080"),
            ("http://al1ce:Qz7k:Wm4r@proxy:8080/", "http://proxy:8080"),
            ("al1ce:Qz7k%40Wm4r@proxy:3128", "http://proxy:3128"),
        ] {
            assert_eq!(redact(proxy).as_deref(), Some(shown), "{proxy}");
        }
        // An unencoded `/`, `?`, `#` or `\` would end the host inside the
        // password: refused, in words that repeat none of it.
        for proxy in [
            "http://al1ce:Qz7k@ss/Wm4r#x@proxy:8080",
            "http://al1ce:Qz7k/Wm4r@proxy:8080",
            "http://al1ce:Qz7k?Wm4r@proxy:8080",
            "http://al1ce:Qz7k#Wm4r@proxy:8080",
            "http://al1ce:Qz7k\\Wm4r@proxy:8080",
            "al1ce:Qz7k/Wm4r@proxy:8080",
        ] {
            assert_eq!(redact(proxy), None, "{proxy}");
            let reason = parse(proxy).unwrap_err();
            for fragment in ["al1ce", "Qz7k", "Wm4r", "proxy"] {
                assert!(!reason.contains(fragment), "{reason}");
            }
            let proxies = settings(Some(proxy), None, None);
            assert_eq!(route(&proxies, "https://a.example.com"), None);
            #[cfg(not(target_os = "wasi"))]
            {
                let refused = proxies.proxies().unwrap_err();
                let text = refused.to_string();
                assert!(
                    matches!(
                        &refused,
                        crate::transport::SetupError::Proxy { reason }
                            if reason.starts_with("an `@` follows")
                    ),
                    "{refused:?}"
                );
                assert!(
                    text.starts_with("the proxy is not a proxy URL: an `@` follows"),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn no_proxy_sends_a_host_or_its_domain_direct() {
        let proxies = settings(
            Some("http://proxy.corp:3128"),
            None,
            Some(" .Example.com , other.org:8089,, 10.0.0.7"),
        );
        let direct = |url: &str| route(&proxies, url).is_none();
        assert!(direct("https://splunk.example.com:8089/x"));
        assert!(direct("https://example.com/x"));
        assert!(direct("https://10.0.0.7:8089/x"));
        // An entry with a port covers its host on that port only, as curl
        // and Go's `httpproxy` read it; a lookalike domain: through the proxy.
        assert!(direct("https://other.org:8089/x"));
        assert!(!direct("https://other.org/x"));
        assert!(!direct("https://other.org:8090/x"));
        assert!(!direct("https://notexample.com/x"));
        assert!(!direct("https://example.com.evil.net/x"));
        let everything = settings(Some("http://proxy.corp:3128"), None, Some("*"));
        assert_eq!(route(&everything, "https://any.where/x"), None);
    }

    #[test]
    fn a_no_proxy_port_is_the_requests_own_or_its_schemes_default() {
        let proxies = settings(
            Some("http://proxy.corp:3128"),
            Some("http://proxy.corp:3128"),
            Some("secure.corp:443, plain.corp:80, [fd00::7]:8089, fd00::9, .corp.example:8089"),
        );
        let direct = |url: &str| route(&proxies, url).is_none();
        assert!(direct("https://secure.corp/x"));
        assert!(!direct("http://secure.corp/x"));
        assert!(direct("http://plain.corp/x"));
        assert!(!direct("https://plain.corp/x"));
        assert!(direct("https://[fd00::7]:8089/x"));
        assert!(!direct("https://[fd00::7]/x"));
        // A bare IPv6 address is no host and port.
        assert!(direct("https://[fd00::9]:8089/x"));
        assert!(direct("https://splunk.corp.example:8089/x"));
        assert!(!direct("https://splunk.corp.example/x"));
        assert_eq!(for_port("a:1, b, c:2", Some(1)), "a,b");
        assert_eq!(split_port("10.0.0.0/8"), None);
        assert_eq!(split_port("fd00::7"), None);
        assert_eq!(split_port("host:http"), None);
    }

    #[test]
    fn a_proxy_url_with_an_at_after_its_host_is_refused_naming_both_readings() {
        let reason = parse("http://proxy.corp:3128/p@th").unwrap_err();
        assert!(reason.contains("no path is needed"), "{reason}");
        assert!(
            !reason.contains("p@th") && !reason.contains("proxy.corp"),
            "{reason}"
        );
    }

    #[test]
    fn no_proxy_cidr_ranges_send_their_addresses_direct() {
        let proxies = settings(
            Some("http://proxy.corp:3128"),
            Some("http://proxy.corp:3128"),
            Some("10.0.0.0/8, fd00::/8"),
        );
        let direct = |url: &str| route(&proxies, url).is_none();
        assert!(direct("https://10.1.2.3:8089/x"));
        assert!(direct("http://10.255.0.1/x"));
        assert!(direct("https://[fd00::7]:8089/x"));
        assert!(!direct("https://11.0.0.1/x"));
        assert!(!direct("https://[fe80::1]/x"));
        assert!(!direct("https://splunk.example.com/x"));
        let handed = url::Url::parse("https://10.1.2.3/x").map(|url| proxies.proxy_for(&url));
        assert_eq!(handed, Ok(None));
    }

    #[test]
    fn an_at_after_the_authority_is_refused_in_multi_byte_text() {
        assert!(parse("http://é😀/a@b").is_err());
        assert!(parse("é😀?@").is_err());
        assert!(parse("http://user@proxy.example:8080/é😀").is_ok());
    }
}
