//! The proxy a request goes through, from `--proxy` / `OPENTIDE_PROXY` and
//! the standard variables.
//!
//! As Python reads them (`urllib.request.getproxies_environment`, which
//! `requests` uses): the lower-case spelling wins over the upper-case one,
//! `https_proxy` serves `https://` URLs and `http_proxy` `http://` ones,
//! `all_proxy` serves both when neither is set, and `no_proxy` lists the
//! hosts that go direct. `--proxy` (or `OPENTIDE_PROXY`) replaces both
//! `http_proxy` and `https_proxy`, as the Python CLI's `apply_environment`
//! exports it to all four spellings.

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
    /// its host in `no_proxy` (`urllib.request.proxy_bypass_environment`:
    /// `*`, a host, a domain suffix, an optional `:port`).
    pub fn route(&self, url: &url::Url) -> Option<String> {
        let proxy = match url.scheme() {
            "https" => self.https.as_deref(),
            "http" => self.http.as_deref(),
            _ => None,
        }?;
        if self.bypassed(url) {
            return None;
        }
        let shown = if proxy.contains("://") {
            proxy.to_owned()
        } else {
            format!("http://{proxy}")
        };
        let parsed = url::Url::parse(&shown).ok()?;
        Some(crate::error::origin(&parsed))
    }

    /// Whether `no_proxy` sends *url* direct.
    fn bypassed(&self, url: &url::Url) -> bool {
        let Some(list) = self.no_proxy.as_deref() else {
            return false;
        };
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let with_port = url
            .port()
            .map_or_else(|| host.clone(), |port| format!("{host}:{port}"));
        list.split(',')
            .map(|entry| entry.trim().to_ascii_lowercase())
            .filter(|entry| !entry.is_empty())
            .any(|entry| {
                if entry == "*" {
                    return true;
                }
                let entry = entry.trim_start_matches('.');
                [host.as_str(), with_port.as_str()].iter().any(|candidate| {
                    *candidate == entry || candidate.ends_with(&format!(".{entry}"))
                })
            })
    }

    /// The reqwest proxies, each with the `no_proxy` list.
    pub fn proxies(&self) -> Result<Vec<reqwest::Proxy>, String> {
        let no_proxy = || {
            self.no_proxy
                .as_deref()
                .and_then(reqwest::NoProxy::from_string)
        };
        let mut proxies = Vec::new();
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

/// The message for a proxy URL that is not one, without its credentials.
fn invalid(url: &str) -> String {
    let shown = url::Url::parse(url)
        .map(|parsed| crate::error::origin(&parsed))
        .unwrap_or_else(|_| "the proxy".to_owned());
    format!("{shown} is not a proxy URL")
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
    fn no_proxy_sends_a_host_its_domain_or_its_port_direct() {
        let proxies = settings(
            Some("http://proxy.corp:3128"),
            None,
            Some(" .Example.com , other.org:8089,, "),
        );
        let direct = |url: &str| route(&proxies, url).is_none();
        assert!(direct("https://splunk.example.com:8089/x"));
        assert!(direct("https://example.com/x"));
        assert!(direct("https://other.org:8089/x"));
        // The same host on another port, a lookalike domain: through the proxy.
        assert!(!direct("https://other.org/x"));
        assert!(!direct("https://notexample.com/x"));
        assert!(!direct("https://example.com.evil.net/x"));
        let everything = settings(Some("http://proxy.corp:3128"), None, Some("*"));
        assert_eq!(route(&everything, "https://any.where/x"), None);
    }
}
