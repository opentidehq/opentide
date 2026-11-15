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

    /// Whether `no_proxy` sends *url* direct, as reqwest decides it: the
    /// list is read by the proxy matcher reqwest's transport uses (`*`, a
    /// host or an IP address, a CIDR range such as `10.0.0.0/8`, a domain and
    /// its subdomains; an entry with a port matches no host).
    pub fn bypassed(&self, url: &url::Url) -> bool {
        let Some(list) = self.no_proxy.as_deref() else {
            return false;
        };
        let Some(destination) = destination(url) else {
            return false;
        };
        // The matcher answers for the list alone: its proxy is a stand-in
        // that always parses, so `None` means the list sends *url* direct.
        Matcher::builder()
            .all("http://proxy.invalid")
            .no(list)
            .build()
            .intercept(&destination)
            .is_none()
    }

    /// The reqwest proxies, each with the `no_proxy` list.
    #[cfg(not(target_os = "wasi"))]
    pub fn proxies(&self) -> Result<Vec<reqwest::Proxy>, String> {
        let no_proxy = || {
            self.no_proxy
                .as_deref()
                .and_then(reqwest::NoProxy::from_string)
        };
        let mut proxies = Vec::new();
        for url in [&self.https, &self.http].into_iter().flatten() {
            parse(url).map_err(|_| invalid(url))?;
        }
        if let Some(url) = &self.https {
            proxies.push(
                reqwest::Proxy::https(url.as_str())
                    .map_err(|_| invalid(url))?
                    .no_proxy(no_proxy()),
            );
        }
        if let Some(url) = &self.http {
            proxies.push(
                reqwest::Proxy::http(url.as_str())
                    .map_err(|_| invalid(url))?
                    .no_proxy(no_proxy()),
            );
        }
        Ok(proxies)
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

#[cfg(not(target_os = "wasi"))]
/// The message for a proxy URL that is not one, without its credentials.
fn invalid(url: &str) -> String {
    match parse(url) {
        Ok(parsed) => format!("{} is not a proxy URL", crate::error::origin(&parsed)),
        Err(reason) => format!("the proxy is not a proxy URL: {reason}"),
    }
}

/// A proxy URL as the transport reads it: one written without a scheme
/// (`proxy.internal:8080`) is an HTTP proxy.
///
/// A URL whose text after its host holds an `@` is refused: its user or
/// password has an unencoded `/`, `?`, `#` or `\`, so a URL parser ends
/// the host there and reads part of the password as the host
/// (`http://user:p@ss/w#rd@proxy:8080` would name the host `ss`). Reading it
/// any other way would be a guess, and sending the request would hand that
/// piece of the password to the wrong host.
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
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    if rest[end..].contains('@') {
        return Err(
            "its user or password holds an unencoded `/`, `?`, `#` or `\\`: \
             percent-encode them (`%2F`, `%3F`, `%23`, `%5C`, and `%40` for `@`)"
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
        // A proxy written without a scheme is an HTTP proxy, as urllib reads it.
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
                assert!(
                    refused.starts_with("the proxy is not a proxy URL: its user or password"),
                    "{refused}"
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
        // An entry with a port matches no host (the transport reads the list
        // so); a lookalike domain: through the proxy.
        assert!(!direct("https://other.org:8089/x"));
        assert!(!direct("https://other.org/x"));
        assert!(!direct("https://notexample.com/x"));
        assert!(!direct("https://example.com.evil.net/x"));
        let everything = settings(Some("http://proxy.corp:3128"), None, Some("*"));
        assert_eq!(route(&everything, "https://any.where/x"), None);
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
}
