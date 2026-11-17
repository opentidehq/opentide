# opentide-cassette — agent guide

The recorded-HTTP harness (plan §5.4 "HTTP", UC-4.1 [#831](https://github.com/opentidehq/opentide/issues/831)):
how a Rust connector is proven to send what the Python client sends. Test tooling, never shipped
(`publish = false`).

| Module | What |
|--------|------|
| `cassette.rs` | The format: `tests/cassettes/<scenario>.json`, the interactions in order (method, URL, headers, body; status, headers, body) and their SHA-256 `digest`, which a hand edit breaks |
| `redact.rs` | Normalisation: transport headers and `Accept: */*` left out, secret headers keep their scheme (`Bearer REDACTED`), URL user info and secret query values, secret JSON keys and form fields replaced in place (the rest of the body's bytes kept), known secret values anywhere |
| `proxy.rs` | `Proxy`: a loopback HTTP proxy that answers `CONNECT` with a certificate for the host from a CA made for the run, then records (forwarding to the network or to a local stand-in tenant) or replays (handing the request to a `Replay`) |
| `replay.rs` | `Replay`: a wiremock server serving the cassette's answers in order, in whole passes; `verify` lists every request that differs from the recorded one, by the matching rules below |
| `tls.rs` | `TestCa`: rcgen, a leaf per host with the extensions Python 3.13's strict verification wants |

## Place

foundation, tier 0 (`xtask/layers.toml`): no workspace crate. `opentide-connectors`' and
`opentide-cli`'s tests and xtask (`cargo xtask cassettes`, the snapshot cases with a cassette) use it.

## Matching

A replayed request matches the recorded one when it means the same, whatever bytes its HTTP library
writes (`replay.rs`, `differences`):

| Part | Compared as |
|------|-------------|
| Method | equal |
| Order | the requests in the order recorded, in whole passes; a client may leave out only an `optional` request: a `POST` to an OAuth2 token endpoint (`…/oauth2/token`, `…/oauth2/v2.0/token`) repeating an earlier recorded one of the same pass (same URL and body), which a client that keeps its token until it nearly expires does not send. The first sign-in of every pass is never optional: each pass signs in at least once |
| URL (`same_url`) | the same scheme, user info, host, port and fragment; the path's segments percent-decoded (`%7E` = `~`, `%2f` = `%2F`, an encoded `/` stays in its segment); the query as decoded form fields (`+` = `%20` = space), names in any order, a repeated name's values in the order sent |
| Headers | equal after redaction, leaving out on both sides `IDENTITY_HEADERS`: the client library's name, version, OS, CPU and telemetry (MSAL's `x-client-*`, `x-ms-lib-capability`) and its per-request ids (`client-request-id`, `return-client-request-id`, `x-ms-client-request-id`). Authorization, `Content-Type`, `Accept` and every other header are compared by value |
| Form body (recorded `Content-Type: application/x-www-form-urlencoded`) | decoded fields, as the query (`same_form`); a value is text: `True` is not `true` |
| JSON body (`same_body`) | the same data: key order, spacing, escapes and a JSON document held in a string are layout; values, types, key sets and array order are not |
| Any other body | byte for byte |

`IDENTITY_HEADERS` lists only headers that say nothing to the platform. Adding one that
authenticates, negotiates content or selects an API version is a review failure, as is widening
`redact.rs`.

## Invariants

- **A cassette is recorded, never written.** A scenario's client is recorded through `Proxy` in
  record mode (the cassettes here were recorded from the frozen Python CLI by `cargo xtask
  cassettes record`, retired with the oracle in #1142);
  `cargo xtask cassettes check` fails on a digest that does not match, on anything redaction would
  still change, and on a scenario without its cassette. Scenarios are `tests/cassettes/scenarios.toml`.
- **The client is never patched.** Recording and replay are a proxy: whatever HTTP library the
  client uses (`requests`, `urllib`, reqwest), it is configured as a user configures it, through
  the proxy variables and a CA bundle.
- **Normalisation hides only what the client does not choose** (its library's headers) **and
  secrets.** Widening `redact.rs` to make a difference go away is a review failure, as for the
  snapshots' normaliser.
