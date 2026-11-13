# opentide-connectors

The tenant connectors of [opentide](https://opentide.org): one HTTP client per tenant (TLS, CA bundles, proxy, timeouts, retries), credentials, cancellation and progress, and the platforms built on them, which `opentide query`, `opentide validate query --live` and `opentide deploy` send through.

Internal to opentide, with no stability promise: depend on [`opentide`](https://docs.rs/opentide), the opentide Rust SDK, instead (its `connectors` feature: `opentide::connectors`, and `plugins` for the platform plugin host).

Licensed under the [EUPL-1.2](https://github.com/opentidehq/opentide/blob/development/LICENSE).
