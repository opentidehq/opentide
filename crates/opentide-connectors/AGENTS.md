# opentide-connectors — agent guide

The connector framework (plan D-8, [ADR 0008](../../docs/internal/adr/0008-connectors-in-rust.md),
UC-4.1 [#831](https://github.com/opentidehq/opentide/issues/831)): everything opentide sends to a
tenant or to the network goes through it. UC-4.2 to UC-4.4 implement the platforms on it; UC-4.5
adds the Python plugin hook to its registry.

| Module | What | Python it replaces |
|--------|------|--------------------|
| `http.rs` | `HttpClient`: one reqwest client per tenant, from that tenant's `HttpSettings` (TLS, CA bundle, timeout, retries, requests in flight) and the run's environment; `send` retries and cancels, `bytes` reads an answer | `platforms/transport.py` `TenantSession`, each client's `HTTPAdapter(max_retries=Retry(...))` |
| `tls.rs` | rustls on ring: the system's roots plus the CA bundles `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and the tenant's own; `verify = false` accepts any certificate and is never turned back on by an exported bundle | `tenant_tls_verify`, `merge_environment_settings` |
| `proxy.rs` | `--proxy`/`OPENTIDE_PROXY`, then `https_proxy`/`HTTPS_PROXY`, `http_proxy`/`HTTP_PROXY`, `all_proxy`, with `no_proxy`; lower case wins, as urllib reads them | `CliContext.apply_environment`, `urllib.request.getproxies_environment` |
| `retry.rs` | `RetryPolicy`: urllib3's `Retry(total, backoff_factor, status_forcelist, allowed_methods)`, the waits scheduled by backon, `Retry-After` on 413/429/503 | urllib3 `Retry` |
| `credentials.rs` | `$NAME`/`${NAME}` (opentide-workspace's `env_reference`), the 0.21.0 `$text` reading, placeholders for runs that send nothing; `Secret` prints `***` | `core/environment.py` `fetch_config_envvar`, `defer_missing_envvars` |
| `tenant.rs` | `Tenant` from a `setup` table: `ssl` words and `$VAR`, every other value a credential; `TenantLabel` | `platforms/config.py` `_tenant_ssl`, `transport.tenant_tls_verify` |
| `error.rs` | `ConnectorError` and its `failure.code`; messages name `scheme://host[:port]` only, never a path, query or credential | `transport.py` `TenantUnreachableError`, `reaching_tenant` |
| `connector.rs` | `Deployer`, `LiveValidator`, `QueryRunner`, `Sharer`, `StateMigrator`, `Platform` and the `Registry`; the query types every runner shares: `QueryRequest`, `QueryOutcome`, `QueryColumn`, `TimeWindow`, `LiveCheck`, `flatten`, `columns_of`, `kql_with_limit`; `lib.rs`'s `builtin()` registers the six platforms | `platforms/base.py`, `registry.py`, `query/models.py`, `query/runner.py` |
| `runtime.rs` | `block_on` (a runtime per call, for the synchronous CLI), `fan_out` over tenants (bounded, ordered, cancellable), `cancel_when` (Ctrl-C) | the query and deploy loops |
| `progress.rs` | `tenant` progress events (`OPENTIDE_PROGRESS=json`) | `core/progress_events.py` `tenant` |
| `body.rs` | `python_json`: a body as `json.dumps` writes it (`, ` and `: `, ASCII escapes), through a serde_json formatter | `requests`' `json=` |
| `answer.rs` | `Answer`: a tenant's answer read whole (status, type, bytes, time to headers), `exchange`; `describe_answer` for one that is not the API's JSON (a gateway's page), quoting as Python's `repr` | `transport.py` `describe_answer`, `not_json_detail` |
| `python.rs` | Python's `str` and `repr` of a parsed JSON value, as the clients interpolate a body into a message | `repr()`, `str()` |
| `encode.rs` | Query strings and form bodies as `requests` encodes them (`quote_plus`), through `percent-encoding`; `quote(text, safe)` for a path | `urllib.parse.urlencode`, `quote` |
| `crowdstrike.rs` | CrowdStrike (UC-4.2): the OAuth2 token (once per tenant for a deploy), correlation rules, Next-Gen SIEM query jobs stopped when the runner stops waiting | `platforms/crowdstrike/` |
| `harfanglab.rs` | HarfangLab (UC-4.2): Sigma rules (`PUT`, `POST` on a 404), YARA files, telemetry searches (`shlex` words) | `platforms/harfanglab/` |
| `sysdig.rs` | Sysdig (UC-4.2): Falco rules and runtime policies, `deploy_rule` with the deployment-state change it makes | `platforms/sysdig/client.py`, `deployer.py` |
| `defender.rs`, `elastic.rs`, `sentinel_one.rs` | The platforms of UC-4.2b (#832): client, deploy calls, live check (`LiveValidator`) and query runner (`QueryRunner`) of each, request for request, on the shared query types (UC-4.2c); Elastic's Elasticsearch checks, rule preview, query text and advisories. Elastic has no `Deployer`: its deploy takes the rule's block (`deploy_rule`) | `platforms/<platform>/` |

## Place

domain, tier 2 (`xtask/layers.toml`): it builds on `opentide-workspace` and on
`opentide-compile` (its ordered `Json` for bodies and rows; the platforms send the bodies it
compiles). `opentide-cli` uses it (`setup skills`, and `query` on the platforms with a runner, UC-4.2c);
`deploy` routes to the platforms once every platform is ported.

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
- **Proven against recorded HTTP**: a connector's requests are compared, byte for byte and in
  order, with the cassette recorded from the Python client (`opentide-cassette`,
  `tests/cassettes/`, `cargo xtask cassettes`). `tests/harness.rs` is the pattern.

## Platforms

Each platform is a module with its client (the requests), its `Platform` (the traits it
implements: no `LiveValidator` where the API cannot check a query) and `http_defaults()` (the
timeout and retries its Python client mounts). A cassette scenario per platform and operation
(`tests/cassettes/<platform>/`, a `tenant.py` stand-in built from what the Python tests mock and a
`client.py` that drives the oracle's own client or deployer) is replayed by
`tests/<platform>.rs`, which also asserts the outcomes `client.py` printed when it recorded.

## Tests

`cargo nextest run -p opentide-connectors framework harness crowdstrike harfanglab sysdig`: `tests/framework.rs` (TLS, CA,
proxy, `no_proxy`, `--proxy`, timeouts and retries with tenants of different settings in one
run; credentials; redaction; fan-out, cancellation, progress; bodies) and `tests/harness.rs` (the
sample connector against `tests/cassettes/mock-platform/deploy.json`; one byte off fails; no
credential in any cassette).

`cargo nextest run -p opentide-connectors defender elastic sentinel_one`: each platform against its
cassettes (`tests/cassettes/<platform>/<scenario>.json`, recorded from the oracle against the stand-in tenant
`tenant.py` beside them), the inputs the Python client was given in `tests/fixtures/<platform>.json` (written by
`client.py fixture`); one byte off fails.
