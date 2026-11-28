# opentide-connectors — agent guide

The connector framework (plan D-8, [ADR 0008](../../docs/internal/adr/0008-connectors-in-rust.md),
UC-4.1 [#831](https://github.com/opentidehq/opentide/issues/831)): everything opentide sends to a
tenant or to the network goes through it, but a platform plugin's own requests. UC-4.2 to UC-4.4
implement the platforms on it; UC-4.5 adds the Python plugin hook to its registry (`plugin.rs`; the
host is `bindings/python/src/plugins.rs`, the plugin API `src/opentide/plugins.py`).

| Module | What |
|--------|------|
| `http.rs` | `HttpClient`: one client per tenant, from that tenant's `HttpSettings` (TLS, CA bundle, timeout, retries, requests in flight), the run's environment and its proxies, on the build's `Transport` or the one the run installed; `request` builds a `RequestBuilder`, `send` retries, holds the in-flight limit and cancels, `bytes` reads an answer; failures map to `ConnectorError` |
| `transport.rs` | The wire under `HttpClient`: the `Transport` trait (a whole `Request` in, a whole `Response` or a `TransportFailure` out), opentide's own `Request`, `RequestBuilder`, `Response` and `http`'s `Method`, `StatusCode` and headers, never reqwest's; `ReqwestTransport` (reqwest on rustls, every target but WASI, the default) and `install` (a run's own transport: `opentide serve` asks its client to fetch, for the WASI build) |
| `tls.rs` | rustls on ring: the system's roots plus the CA bundles `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and the tenant's own; `verify = false` accepts any certificate and is never turned back on by an exported bundle |
| `proxy.rs` | `--proxy`/`OPENTIDE_PROXY`, then `https_proxy`/`HTTPS_PROXY`, `http_proxy`/`HTTP_PROXY`, `all_proxy`, with `no_proxy`; lower case wins, as urllib reads them |
| `retry.rs` | `RetryPolicy`: the one policy every retrying connector mounts (`standard`: 3 retries, 0.5 s doubling); a connection never made (DNS, refused, the proxy, the connect timeout) is retried for any method; a 408/429/502/503/504 answer for idempotent requests only (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`, unless the request is marked otherwise with `Request::set_idempotent`); a read timeout, a refused certificate and any other failure never; `Retry-After` on 429/503 at most 120 s |
| `credentials.rs` | `$NAME`/`${NAME}` (opentide-workspace's `env_reference`), the 0.21.0 `$text` reading, placeholders for runs that send nothing; `Secret` prints `***`; `keys(PlatformId)`: the client and setup keys a runner checks for unset placeholders |
| `tenant.rs` | `Tenant` from a `setup` table: `ssl` words and `$VAR`, every other value a credential; `TenantLabel`; `configured`: a resolved configuration's tenants of a platform as `(name, setup)`; `default_host(PlatformId)`: where a tenant without a URL is reported unreachable |
| `tenant_codes.rs` |
| `error.rs` | `ConnectorError` and its `failure.code`; messages name `scheme://host[:port]` only, never a path, query or credential |
| `plugin.rs` | Platform plugins (UC-4.5, #835): `PluginHost` (the Python binding is the one host), `with_plugins` (the built-in platforms, then the plugins; a plugin never replaces a built-in), `unavailable` (what a host-less command line says) |
| `connector.rs` | `Deployer`, `LiveValidator`, `QueryRunner`, `Sharer` and `StateMigrator` (deprecated: nothing implements or calls them, removed in 2.0, #1961), `ConfigurationCheck` (a plugin's own check of its rule block), `Platform` and the `Registry`; the query types every runner shares: `QueryRequest`, `QueryOutcome`, `QueryColumn`, `TimeWindow`, `LiveCheck`, `flatten`, `columns_of`, `kql_with_limit`; `lib.rs`'s `builtin()` registers the fourteen built-in platforms and `http_settings(platform, timeout)` picks each one's client settings |
| `runtime.rs` | `block_on` (a runtime per call, for the synchronous CLI), `fan_out` over tenants (bounded, ordered, cancellable), `cancel_when` (Ctrl-C) |
| `progress.rs` | `tenant` progress events (`OPENTIDE_PROGRESS=json`) |
| `answer.rs` | `Answer`: a tenant's answer read whole (status, type, bytes, time to headers), `exchange`; `describe_answer` for one that is not the API's JSON (a gateway's page), quoting its title or body with Rust's `{:?}` |
| `text.rs` | `json_text`: a JSON value from an answer as text, where a client puts it into a message or a text field (a string as it is, anything else as its compact JSON) |
| `encode.rs` | Query strings and form bodies as `requests` encodes them (`quote_plus`), through `percent-encoding`; `quote(text, safe)` for a path |
| `token.rs` |
| `entra.rs` |
| `crowdstrike.rs` | CrowdStrike (UC-4.2): its own OAuth2 token endpoint on the shared `TokenCache`, correlation rules, Next-Gen SIEM query jobs stopped when the runner stops waiting |
| `harfanglab.rs` | HarfangLab (UC-4.2): Sigma rules (`PUT`, `POST` on a 404), YARA files, telemetry searches (`shlex` words) |
| `sysdig.rs` | Sysdig (UC-4.2): Falco rules and runtime policies, `deploy_rule` with the deployment-state change it makes |
| `splunk.rs` | Splunk (UC-4.3, #833): the Python Splunk client's requests on opentide's urllib handler: saved searches (`_apply_saved_search`: looked up, created, set in two updates, deleted), one-shot searches, `search/parser`, the `server/info` reads that choose the v1 or v2 search endpoints; an HTML page in place of the API is a gateway's (`ConnectorError::Gateway`) or a proxy's |
| `carbon_black.rs` | Carbon Black Cloud (UC-4.3): cbc_sdk's requests: watchlist reports (`_deploy_to_org`), process searches (validated, started, polled, read in pages), `search_validation`; the SDK's error texts |
| `sentinel.rs` | Sentinel (UC-4.3): ARM `alertRules` (create or replace, delete, list with `nextLink`: the listing `generate extract sentinel` reads, UC-4.4e), the Entra sign-in (`entra.rs`, one token per tenant and scope: ARM's, Log Analytics'), Log Analytics queries as one REST call |
| `defender.rs`, `elastic.rs`, `sentinel_one.rs` | The platforms of UC-4.2b (#832): client, deploy calls, live check (`LiveValidator`) and query runner (`QueryRunner`) of each, request for request, on the shared query types (UC-4.2c); Elastic's Elasticsearch checks, rule preview, query text and advisories. Elastic has no `Deployer`: its deploy takes the rule's block (`deploy_rule`). The listings `generate extract` reads (UC-4.4b): Defender's `list_rules`, Elastic's `find_rules` |
| `misp.rs` | MISP's REST API, the subset `opentide share` speaks (UC-4.4b, #834): `MispClient` on `HttpClient` (the key in `Authorization`, JSON both ways, 30 s, TLS per block), the `Misp` trait the CLI's engine calls, answers classified into `MispCallError` with a fixed reason, never a body |

## Place

domain, tier 2 (`xtask/layers.toml`): it builds on `opentide-workspace` and on
`opentide-compile` (its ordered `Json` for bodies and rows; the platforms send the bodies it
compiles). `opentide-cli` uses it (`setup skills`, `query` on every platform with a runner,
UC-4.2c and UC-4.3, and `validate query --live` through each `LiveValidator`, Elastic's rule
checks through `Elastic::checks` and `preview_rule`, and `deploy` that sends through each platform's deploy calls, UC-4.6),
and the facade's `connectors` feature wraps its traits (`opentide::connectors`).

## Invariants

- **One HTTP client crate for the workspace: reqwest 0.13**, on rustls with ring (no aws-lc-rs:
  its C build and OpenSSL licence), HTTP/1.1, no system proxy lookup. `deny.toml` bans OpenSSL.
- **Per tenant, never the first tenant's** (#742): every setting comes from the tenant's own
  `HttpSettings` and the environment the caller passes (`Environment`), never from the process
  environment directly, so two tenants, or two runs in one process, never share a proxy, CA or
  credential by accident.
- **No secret in a message, a log or a `Debug`**: `Secret` prints `***`; `error::describe` drops
  the URL from every reqwest error before reading it. Add a test to `tests/framework.rs` when an
  error gains a field.
- **A body is bytes**: `DeployRequest.body` is what `opentide-compile` wrote, so key order and
  layout reach the platform unchanged (serde_json's `Value` sorts keys; the workspace does not turn
  on `preserve_order`).
- **Bodies are serde_json's compact JSON**: a body is data, never a copy of `json.dumps`'
  layout. A string a platform reads as JSON is serde_json's too.
- **Proven against recorded HTTP**: a connector's requests are compared, in order, with the
  cassette recorded from the Python client: a JSON body as the same data (key order, spacing and
  escapes are layout; `opentide_cassette::replay::same_body`), any other body byte for byte (`opentide-cassette`,
  `tests/cassettes/`, `cargo xtask cassettes`). `tests/harness.rs` is the pattern.

## Platforms

Each platform is a module with its client (the requests), its `Platform` (the traits it
implements: no `LiveValidator` where the API cannot check a query) and `http_defaults()` (the
timeout and retries its Python client mounts). A cassette scenario per platform and operation
(`tests/cassettes/<platform>/`, a `tenant.py` stand-in built from what the Python tests mock and a
`client.py` that drives opentide 0.23.0's own client or deployer) is replayed by
`tests/<platform>.rs`, which also asserts the outcomes `client.py` printed when it recorded.

A query runner (`QueryRunner`) saves no search or rule, and stops an asynchronous search it stops
waiting for where the API can (CrowdStrike). An Elastic rule preview is the one write: its alerts
land in the preview index. Both `opentide query` with `kuery` and
`validate query --platform elastic --live`, which previews every rule, make one.

A new platform also needs a platform skill in [opentidehq/skills](https://github.com/opentidehq/skills),
whose `coverage.json` CI checks against `opentide --json info` daily; a platform the skills do not
cover fails that check and opens an issue there (the root `AGENTS.md`, definition of done item 5).

## Tests

`cargo nextest run -p opentide-connectors framework harness crowdstrike harfanglab sysdig`: `tests/framework.rs` (TLS, CA,
proxy, `no_proxy`, `--proxy`, timeouts and retries with tenants of different settings in one
run; credentials; redaction; fan-out, cancellation, progress; bodies) and `tests/harness.rs` (the
sample connector against `tests/cassettes/mock-platform/deploy.json`; a changed value fails; no
credential in any cassette).

`cargo nextest run -p opentide-connectors defender elastic sentinel_one splunk carbon_black sentinel`: each platform against its
cassettes (`tests/cassettes/<platform>/<scenario>.json`, recorded from opentide 0.23.0 against the stand-in tenant
`tenant.py` beside them), the inputs the Python client was given in `tests/fixtures/<platform>.json` (written by
`client.py fixture`; Splunk's deploy steps by `cargo run -p opentide-connectors --example splunk_client -- fixture`, and its `splunk/deploy` cassette is recorded from that example, #1657); a changed value fails.

The SDK platforms (UC-4.3) are recorded from the SDKs themselves: the stand-in tenants answer as
the SDK expects (Splunk's Atom feeds, cbc_sdk's search jobs, MSAL's OpenID configuration), and
`client.py` fixes what the SDK draws at random (cbc_sdk's report stamp, MSAL's and azure-core's
request ids), as the Rust tests pass the same values. A key the redaction treats as a secret (`code`,
`token_endpoint`) reads `REDACTED` in a replayed answer: the tests expect it.
