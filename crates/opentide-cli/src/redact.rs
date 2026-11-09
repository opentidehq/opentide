//! Credentials and tenant identifiers out of everything the CLI writes about
//! itself: crash logs, the crash report, log lines (plan §3 invariant 9).
//!
//! What is redacted is opentide's own rule set (`cli/ui/crash.py` in the
//! oracle): secret-named environment variables and configuration keys, proxy
//! and URL passwords, `Authorization` values, `Bearer` and `Basic`
//! credentials, well-known token shapes, `key=value` pairs whose key names a
//! secret, and the names, hosts and ids of the tenants and sharing
//! destinations of `.opentide/configurations/`. The patterns run on the
//! `regex` crate; the two the oracle wrote with look-around (a whole-word
//! identifier, a pair's value) are matched here by checking the neighbouring
//! characters instead.

use crate::env::Env;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// What a redacted value becomes.
pub const REDACTED: &str = "***";

const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "passw",
    "authorization",
    "credential",
    "cookie",
    "apikey",
];
const SECRET_SUFFIXES: &[&str] = &["key", "keys"];
const SECRET_PARTS: &[&str] = &["pass", "auth"];
const IDENTIFYING_WORDS: &[&str] = &[
    "tenant",
    "url",
    "host",
    "domain",
    "workspace",
    "subscription",
    "endpoint",
    "group",
    "resource",
];
const IDENTIFYING_PARTS: &[&str] = &[
    "id",
    "org",
    "organization",
    "account",
    "server",
    "instance",
    "project",
    "client",
    "site",
    "app",
];
const BOOLEAN_LITERALS: &[&str] = &["true", "false", "yes", "no", "on", "off", "none", "null"];
const MIN_SECRET_LENGTH: usize = 6;
const MIN_IDENTIFIER_LENGTH: usize = 3;
const MIN_NUMERIC_LENGTH: usize = 6;
const BUILTIN_SPLUNK_APPS: &[&str] = &["search", "launcher", "splunkenterprisesecuritysuite"];
const BUILTIN_SPLUNK_APP_PREFIXES: &[&str] = &["sa-", "da-", "ta-", "splunk_"];

struct Patterns {
    url_credentials: Regex,
    auth_field: Regex,
    auth_scheme: Regex,
    token_shapes: Regex,
    assignment_key: Regex,
    assignment_value: Regex,
    env_reference: Regex,
    parts: Regex,
}

#[expect(
    clippy::expect_used,
    reason = "the patterns are literals, checked by every test that redacts"
)]
fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        url_credentials: Regex::new(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]*://)[^\s/?#@]+@")
            .expect("pattern"),
        auth_field: Regex::new(
            r#"(?i)(?P<key>\b(?:proxy-)?authorization)(?P<sep>["']?\s*[:=]\s*)(?P<value>"[^"\n]*"|'[^'\n]*'|[^\n"']*)"#,
        )
        .expect("pattern"),
        auth_scheme: Regex::new(
            r"(?i)\b(?P<scheme>bearer\s+)[A-Za-z0-9\-._~+/]+=*|\b(?P<basic>basic\s+)[A-Za-z0-9+/]{8,}={0,2}",
        )
        .expect("pattern"),
        token_shapes: Regex::new(concat!(
            r"\bgh[pousr]_[A-Za-z0-9]{20,}",
            r"|\bgithub_pat_[A-Za-z0-9_]{20,}",
            r"|\bglpat-[A-Za-z0-9_-]{20,}",
            r"|\bxox[abprs]-[A-Za-z0-9-]{10,}",
            r"|\bAKIA[0-9A-Z]{16}\b",
            r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        ))
        .expect("pattern"),
        assignment_key: Regex::new(r#"(?P<key>[A-Za-z_][\w.-]*)(?P<sep>["']?\s*[:=]\s*)"#)
            .expect("pattern"),
        assignment_value: Regex::new(r#"^(?:"[^"\n]*"|'[^'\n]*'|[^\s"',;&)}\]]+)"#)
            .expect("pattern"),
        env_reference: Regex::new(r"^\$\{?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}?$").expect("pattern"),
        parts: Regex::new(r"[^a-z0-9]+").expect("pattern"),
    })
}

fn parts(lowered: &str) -> Vec<&str> {
    patterns()
        .parts
        .split(lowered)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Whether a variable, option or key called `name` holds a secret.
pub fn is_secret_name(name: &str) -> bool {
    let lowered = name.to_lowercase();
    if SECRET_WORDS.iter().any(|word| lowered.contains(word)) {
        return true;
    }
    parts(&lowered).iter().any(|part| {
        SECRET_PARTS.contains(part) || SECRET_SUFFIXES.iter().any(|suffix| part.ends_with(suffix))
    })
}

fn identifies_tenant(key: &str) -> bool {
    let lowered = key.to_lowercase();
    IDENTIFYING_WORDS.iter().any(|word| lowered.contains(word))
        || parts(&lowered)
            .iter()
            .any(|part| IDENTIFYING_PARTS.contains(part))
}

fn is_builtin_splunk_app(key: &str, value: &str) -> bool {
    if !parts(&key.to_lowercase()).contains(&"app") {
        return false;
    }
    let name = value.trim().to_lowercase();
    BUILTIN_SPLUNK_APPS.contains(&name.as_str())
        || BUILTIN_SPLUNK_APP_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn meaningful(value: &str, minimum: usize) -> bool {
    let value = value.trim();
    if !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()) {
        return value.len() >= MIN_NUMERIC_LENGTH;
    }
    value.chars().count() >= minimum
        && !BOOLEAN_LITERALS.contains(&value.to_lowercase().as_str())
        && value != REDACTED
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// Removes credentials and tenant identifiers from text.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    /// Replaced wherever they occur, longest first.
    pub secrets: Vec<String>,
    /// Replaced as whole words only (`prod` does not eat `production`), longest first.
    pub identifiers: Vec<String>,
}

fn longest_first(values: impl IntoIterator<Item = String>, minimum: usize) -> Vec<String> {
    let mut out: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| meaningful(value, minimum))
        .collect();
    out.sort();
    out.dedup();
    out.sort_by_key(|value| std::cmp::Reverse(value.len()));
    out
}

impl Redactor {
    /// A redactor of these secrets and identifiers.
    pub fn new(
        secrets: impl IntoIterator<Item = String>,
        identifiers: impl IntoIterator<Item = String>,
    ) -> Redactor {
        Redactor {
            secrets: longest_first(secrets, MIN_SECRET_LENGTH),
            identifiers: longest_first(identifiers, MIN_IDENTIFIER_LENGTH),
        }
    }

    /// `text` redacted.
    ///
    /// A secret is replaced as written and as Rust's `{:?}` writes it
    /// (`"` and `\` escaped, controls as `\n` or `\u{..}`), so a value a
    /// Debug field quoted before it got here is caught too.
    pub fn redact(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for secret in &self.secrets {
            text = text.replace(secret.as_str(), REDACTED);
            let escaped = secret.escape_debug().to_string();
            if escaped != *secret {
                text = text.replace(escaped.as_str(), REDACTED);
            }
        }
        if !self.identifiers.is_empty() {
            text = self.redact_identifiers(&text);
        }
        let p = patterns();
        text = p
            .url_credentials
            .replace_all(&text, format!("${{scheme}}{REDACTED}@").as_str())
            .into_owned();
        text = p
            .auth_field
            .replace_all(&text, |caps: &regex::Captures<'_>| {
                format!("{}{}{}", &caps["key"], &caps["sep"], masked(&caps["value"]))
            })
            .into_owned();
        text = p
            .auth_scheme
            .replace_all(&text, |caps: &regex::Captures<'_>| {
                let scheme = caps
                    .name("scheme")
                    .or_else(|| caps.name("basic"))
                    .map_or("", |m| m.as_str());
                format!("{scheme}{REDACTED}")
            })
            .into_owned();
        text = p.token_shapes.replace_all(&text, REDACTED).into_owned();
        redact_assignments(&text)
    }

    fn redact_identifiers(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        let mut previous: Option<char> = None;
        while index < text.len() {
            let rest = &text[index..];
            let found = if previous.is_some_and(is_word) {
                None
            } else {
                self.identifiers.iter().find(|identifier| {
                    rest.starts_with(identifier.as_str())
                        && !rest[identifier.len()..].chars().next().is_some_and(is_word)
                })
            };
            if let Some(identifier) = found {
                out.push_str(REDACTED);
                index += identifier.len();
                previous = identifier.chars().last();
                continue;
            }
            let Some(c) = rest.chars().next() else { break };
            out.push(c);
            index += c.len_utf8();
            previous = Some(c);
        }
        out
    }

    /// `argv` with the value of every option named like a secret replaced.
    pub fn argv(&self, argv: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(argv.len());
        let mut hide_next = false;
        for token in argv {
            if hide_next {
                out.push(REDACTED.to_owned());
                hide_next = false;
                continue;
            }
            let mut token = token.clone();
            if token.starts_with('-') && token != "--" {
                let (name, has_value) = match token.split_once('=') {
                    Some((name, _)) => (name.to_owned(), true),
                    None => (token.clone(), false),
                };
                if is_secret_name(name.trim_start_matches('-')) {
                    if has_value {
                        token = format!("{name}={REDACTED}");
                    } else {
                        hide_next = true;
                    }
                }
            }
            out.push(self.redact(&token));
        }
        out
    }

    /// This redactor with `secrets` added.
    #[must_use]
    pub fn with_secrets(&self, secrets: impl IntoIterator<Item = String>) -> Redactor {
        Redactor::new(
            self.secrets.iter().cloned().chain(secrets),
            self.identifiers.clone(),
        )
    }
}

fn masked(value: &str) -> String {
    match value.chars().next() {
        Some(quote @ ('\'' | '"')) => format!("{quote}{REDACTED}{quote}"),
        _ => REDACTED.to_owned(),
    }
}

fn redact_assignments(text: &str) -> String {
    let p = patterns();
    let mut out = String::with_capacity(text.len());
    let mut position = 0;
    let mut search = 0;
    while let Some(caps) = p.assignment_key.captures_at(text, search) {
        let whole = caps.get(0).map_or(0..0, |m| m.range());
        // The value is a lookahead in the oracle's pattern: the next search
        // starts after the key and separator (never empty: the key is not).
        search = whole.end;
        if whole.start < position || !is_secret_name(&caps["key"]) {
            continue;
        }
        let Some(value) = p.assignment_value.find(&text[whole.end..]) else {
            continue;
        };
        out.push_str(&text[position..whole.end]);
        out.push_str(&masked(value.as_str()));
        position = whole.end + value.end();
        search = search.max(position);
        if search >= text.len() {
            break;
        }
    }
    out.push_str(&text[position..]);
    out
}

/// The password (as written, percent escapes kept) and the host of a
/// URL-shaped value.
pub fn url_secrets(value: &str) -> (Vec<String>, Vec<String>) {
    if !value.contains("://") {
        return (Vec::new(), Vec::new());
    }
    let Ok(url) = url::Url::parse(value.trim()) else {
        return (Vec::new(), Vec::new());
    };
    let password = url.password().map(str::to_owned).into_iter().collect();
    let host = url
        .host_str()
        .map(|host| host.trim_matches(['[', ']']).to_lowercase())
        .into_iter()
        .collect();
    (password, host)
}

fn expand(value: &str, env: &Env) -> String {
    match patterns().env_reference.captures(value.trim()) {
        Some(caps) => env.get(&caps["name"]).unwrap_or_default().to_owned(),
        None => value.to_owned(),
    }
}

fn walk(
    node: &toml::Value,
    env: &Env,
    secrets: &mut Vec<String>,
    identifiers: &mut Vec<String>,
    tenant: bool,
) {
    match node {
        toml::Value::Array(items) => {
            for item in items {
                walk(item, env, secrets, identifiers, tenant);
            }
        }
        toml::Value::Table(table) => {
            for (key, value) in table {
                match value {
                    toml::Value::Table(_) | toml::Value::Array(_) => {
                        walk(value, env, secrets, identifiers, tenant || key == "tenants");
                    }
                    toml::Value::Integer(number) => {
                        if tenant && identifies_tenant(key) {
                            identifiers.push(number.to_string());
                        }
                    }
                    toml::Value::String(text) => {
                        let text = expand(text, env);
                        let (passwords, hosts) = url_secrets(&text);
                        secrets.extend(passwords);
                        if is_secret_name(key) {
                            secrets.push(text);
                        } else if tenant && (key == "name" || identifies_tenant(key)) {
                            if !is_builtin_splunk_app(key, &text) {
                                identifiers.push(text);
                            }
                            identifiers.extend(hosts);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// A redactor for this environment and these workspaces' tenants and sharing
/// destinations.
pub fn workspace_redactor(workspaces: &[PathBuf], env: &Env) -> Redactor {
    let mut secrets = Vec::new();
    let mut identifiers = Vec::new();
    for (name, value) in env.iter() {
        secrets.extend(url_secrets(value).0);
        if is_secret_name(name) {
            secrets.push(value.to_owned());
        }
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    for workspace in workspaces {
        let configurations = workspace.join(".opentide").join("configurations");
        let mut files: Vec<(PathBuf, bool)> = vec![(configurations.join("sharing.toml"), true)];
        if let Ok(read) = std::fs::read_dir(configurations.join("platforms")) {
            let mut platforms: Vec<PathBuf> = read
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
                .collect();
            platforms.sort();
            files.extend(platforms.into_iter().map(|path| (path, false)));
        }
        for (path, destinations) in files {
            let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
            if seen.contains(&resolved) || !path.is_file() {
                continue;
            }
            seen.push(resolved);
            let Some(document) = read_toml(&path) else {
                continue;
            };
            walk(&document, env, &mut secrets, &mut identifiers, destinations);
        }
    }
    Redactor::new(secrets, identifiers)
}

fn read_toml(path: &Path) -> Option<toml::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    text.parse::<toml::Table>().ok().map(toml::Value::Table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_redact_secret_names() {
        for name in [
            "SPLUNK_TOKEN",
            "client_secret",
            "api_key",
            "Authorization",
            "password",
            "privateKey",
            "x-auth",
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        for name in ["KeyError", "path", "OPENTIDE_REPO_ROOT", "keyboard"] {
            assert!(!is_secret_name(name), "{name}");
        }
    }

    #[test]
    fn framework_redact_patterns() {
        let redactor = Redactor::default();
        assert_eq!(
            redactor.redact("http://user:hunter22@proxy:8080"),
            "http://***@proxy:8080"
        );
        assert_eq!(
            redactor.redact("Authorization: Bearer abc.def"),
            "Authorization: ***"
        );
        assert_eq!(redactor.redact("sent bearer abcdef123"), "sent bearer ***");
        assert_eq!(redactor.redact("basic QWxhZGRpbjpvcGVu"), "basic ***");
        assert_eq!(
            redactor.redact("token ghp_abcdefghijklmnopqrstuvwxyz"),
            "token ***"
        );
        assert_eq!(redactor.redact("api_key=s3cr3t&x=1"), "api_key=***&x=1");
        assert_eq!(
            redactor.redact(r#"{"password": "pw"}"#),
            r#"{"password": "***"}"#
        );
        assert_eq!(
            redactor.redact("https://host token=abc"),
            "https://host token=***"
        );
        assert_eq!(redactor.redact("conn: ok"), "conn: ok");
        assert_eq!(redactor.redact("a=b"), "a=b");
    }

    #[test]
    fn framework_redact_identifiers_as_whole_words() {
        let redactor = Redactor::new(
            Vec::new(),
            vec!["prod".to_owned(), "acme.example".to_owned()],
        );
        assert_eq!(
            redactor.redact("prod production acme.example x"),
            "*** production *** x"
        );
        assert_eq!(redactor.redact("my-prod prod_1 prod"), "my-prod prod_1 ***");
        let secrets = Redactor::new(
            vec!["hunter22".to_owned(), "x".to_owned(), "true".to_owned()],
            vec![],
        );
        assert_eq!(secrets.secrets, vec!["hunter22".to_owned()]);
        assert_eq!(secrets.redact("pw hunter22!"), "pw ***!");
        assert_eq!(
            secrets
                .with_secrets(["abcdefg".to_owned()])
                .redact("abcdefg"),
            "***"
        );
        let numbers = Redactor::new(vec!["12345".into(), "1234567".into()], vec![]);
        assert_eq!(numbers.secrets, vec!["1234567".to_owned()]);
    }

    #[test]
    fn framework_redact_argv() {
        let redactor = Redactor::default();
        let argv: Vec<String> = [
            "--api-key",
            "abc",
            "--token=xyz",
            "--",
            "--password",
            "x",
            "plain",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(
            redactor.argv(&argv),
            vec![
                "--api-key",
                "***",
                "--token=***",
                "--",
                "--password",
                "***",
                "plain"
            ]
        );
    }

    #[test]
    fn framework_redact_url_secrets() {
        assert_eq!(
            url_secrets("http://u:p%40ss@Proxy.Example:8080"),
            (vec!["p%40ss".to_owned()], vec!["proxy.example".to_owned()])
        );
        assert_eq!(url_secrets("no url"), (vec![], vec![]));
        assert_eq!(url_secrets("://"), (vec![], vec![]));
    }

    #[test]
    fn framework_redact_workspace_tenants_and_env() {
        let dir = std::env::temp_dir().join(format!("opentide-cli-redact-{}", std::process::id()));
        let platforms = dir.join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("sentinel.toml"),
            "[[tenants]]\nname = \"contoso-prod\"\nworkspace_id = \"$WS_ID\"\naccount_id = 1234567890\nclient_secret = \"supersecret\"\nurl = \"https://splunk.contoso.example\"\napp = \"search\"\n",
        )
        .unwrap();
        std::fs::write(platforms.join("broken.toml"), "not = [toml").unwrap();
        std::fs::write(
            dir.join(".opentide/configurations/sharing.toml"),
            "[misp]\nname = \"misp-main\"\nurl = \"https://misp.example\"\n",
        )
        .unwrap();
        let env = Env::from_pairs([
            ("WS_ID", "0000-1111-2222"),
            ("SPLUNK_TOKEN", "tok-123456"),
            ("HTTPS_PROXY", "http://u:proxypass@proxy"),
        ]);
        let redactor = workspace_redactor(&[dir.clone(), dir.clone()], &env);
        let text = "contoso-prod 0000-1111-2222 1234567890 supersecret splunk.contoso.example \
                    tok-123456 proxypass misp-main misp.example search";
        let redacted = redactor.redact(text);
        assert_eq!(redacted, "*** *** *** *** *** *** *** *** *** search");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
