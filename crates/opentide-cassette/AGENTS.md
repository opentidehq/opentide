# opentide-cassette — agent guide

The recorded-HTTP harness (plan §5.4 "HTTP", UC-4.1 [#831](https://github.com/opentidehq/opentide/issues/831)):
how a Rust connector is proven to send what the Python client sends. Test tooling, never shipped
(`publish = false`).

| Module | What |
|--------|------|
| `cassette.rs` | The format: `tests/cassettes/<scenario>.json`, the interactions in order (method, URL, headers, body; status, headers, body) and their SHA-256 `digest`, which a hand edit breaks |
| `redact.rs` | Normalisation: transport headers and `Accept: */*` left out, secret headers keep their scheme (`Bearer REDACTED`), URL user info and secret query values, secret JSON keys and form fields replaced in place (the rest of the body's bytes kept), known secret values anywhere |
| `proxy.rs` | `Proxy`: a loopback HTTP proxy that answers `CONNECT` with a certificate for the host from a CA made for the run, then records (forwarding to the network or to a local stand-in tenant) or replays (handing the request to a `Replay`) |
| `replay.rs` | `Replay`: a wiremock server serving the cassette's answers in order, in whole passes; `verify` lists every request that differs from the recorded one |
| `tls.rs` | `TestCa`: rcgen, a leaf per host with the extensions Python 3.13's strict verification wants |

## Place

foundation, tier 0 (`xtask/layers.toml`): no workspace crate. `opentide-connectors`' and
`opentide-cli`'s tests and xtask (`cargo xtask cassettes`, cassette golden cases) use it.

## Invariants

- **A cassette is recorded, never written.** `cargo xtask cassettes record <scenario>` records the
  oracle (the frozen Python CLI of `tests/golden/ORACLE`) through `Proxy` in record mode;
  `cargo xtask cassettes check` fails on a digest that does not match, on anything redaction would
  still change, and on a scenario without its cassette. Scenarios are `tests/cassettes/scenarios.toml`.
- **The client is never patched.** Recording and replay are a proxy: whatever HTTP library the
  client uses (`requests`, `urllib`, reqwest), it is configured as a user configures it, through
  the proxy variables and a CA bundle.
- **Normalisation hides only what the client does not choose** (its library's headers) **and
  secrets.** Widening `redact.rs` to make a difference go away is a review failure, as for the
  goldens' normaliser.
