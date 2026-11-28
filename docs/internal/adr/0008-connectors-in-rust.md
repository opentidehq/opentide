---
title: "0008: Connectors are Rust"
description: "Decision D-8 of the unified core: the platform connectors are Rust (tokio + reqwest), and third-party platforms keep a Python plugin hook."
---

# 0008: Connectors are Rust

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-07 (the plan's decision), recorded 2026-11-08 |
| Decision | D-8 |
| Issues | UC-4.1 [#831](https://github.com/opentidehq/opentide/issues/831) to UC-4.5 [#835](https://github.com/opentidehq/opentide/issues/835) |

## Context

The connectors are the tenant clients of the nine platforms: deploy, live validation, query runners, MISP sharing and state migration. They are about 17,000 lines of Python under `platforms/`, `sharing/`, `extraction/` and `query/` (plan §6). Six of the nine platforms already use plain `requests`, and the other three wrap REST APIs. For Azure, opentide uses only `ClientSecretCredential`, which the Rust crate `azure_identity` 1.0 covers.

## Decision

Connectors are Rust (tokio + reqwest). Third-party platforms keep a Python plugin hook.

## Consequences

- **A new domain crate.** `opentide-connectors` holds the tenant clients over tokio and reqwest: deploy, live validation, query runners, MISP and migrate-state (plan §4). The engine crates stay free of `async` and `tokio` (the [`rust-engine`](../../../.agents/skills/rust-engine/SKILL.md) skill).
- **The security posture does not move.** Invariant 9 of plan §3 holds: no secret in logs, JSON, crash logs or webviews; TLS and CA settings per tenant; proxies from `OPENTIDE_PROXY` and the standard variables; nothing deploys on a dry run. UC-4.1 builds per-tenant TLS, CA, proxy and timeouts, credentials, cancellation and progress into the framework.
- **Proven against recorded HTTP.** The HTTP of each connector is recorded from the Python client as cassettes: method, URL, headers (with secrets redacted) and body. The Rust client must produce them byte for byte, replayed with wiremock (plan §5.4). UC-4.2 to UC-4.4 add live parity.
- **Authentication.** `azure_identity` 1.0 has ClientSecret, ClientCertificate, ManagedIdentity, WorkloadIdentity and AzureCli. It has no DeviceCode or InteractiveBrowser, which opentide does not use (plan §10).
- **Third-party platforms.** UC-4.5 adds the Python platform plugin hook. Its exit criterion: a third-party plugin runs from Rust.
- **Runtime dependencies.** With the connectors ported, the wheel's last third-party runtime dependencies go (plan §11's target: 0).

## Evidence

- Plan: [§1 Decisions](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#1-decisions), [§3 Invariants](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants), [§4 Target architecture](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#4-target-architecture), [§5 Correctness strategy](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy) (5.4, HTTP), [§6 Work plan](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#6-work-plan) (Phase 4), [§10 Risks](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#10-risks).
- Issues [#831](https://github.com/opentidehq/opentide/issues/831) (framework and cassettes), [#832](https://github.com/opentidehq/opentide/issues/832), [#833](https://github.com/opentidehq/opentide/issues/833), [#834](https://github.com/opentidehq/opentide/issues/834), [#835](https://github.com/opentidehq/opentide/issues/835) (plugin hook).
