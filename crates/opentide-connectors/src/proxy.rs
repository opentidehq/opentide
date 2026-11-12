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
