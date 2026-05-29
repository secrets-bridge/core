<p align="center">
  <a href="https://github.com/secrets-bridge"><img src="https://raw.githubusercontent.com/secrets-bridge/.github/main/profile/logo.svg" alt="Secrets Bridge" width="520" /></a>
</p>

<p align="center">
  <b>The brain behind your secrets.</b><br/>
  Unified secrets control plane for cloud-native teams.<br/>
  <a href="https://secrets-bridge.io">secrets-bridge.io</a> · <a href="https://github.com/secrets-bridge">all repos</a>
</p>

---
# core

Core Go module for the [Secrets Bridge](https://github.com/secrets-bridge)
platform.

This module hosts the provider abstraction, the synchronization engine, and
the shared types used by the API, worker, agent, and controller services.

## Packages

- `providers` — the `Provider` interface and registry. Providers expose a
  metadata plane (safe to log and cache) and a value plane (sensitive,
  never logged).
- `sync` — placeholder for the reconciliation engine that copies secrets
  between providers.
- `types` — placeholder for cross-cutting value types shared across the
  module.

## Secret handling

Secret *values* are confidential. They must never be logged, embedded in
error messages, serialized to telemetry, or exposed outside an explicit
`GetValue` / `PutValue` call. `providers.SecretValue` redacts itself under
`%v` and `%#v` to make accidental disclosure harder, but callers are still
responsible for treating the underlying bytes with care.
