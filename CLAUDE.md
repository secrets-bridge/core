# CLAUDE.md: secrets-bridge/core

Instructions for Claude Code and contributors working in this repo. For the whole platform, see https://secrets-bridge.io.

## What this repo is

The shared, infra-free Go library of Secrets Bridge. It defines the provider interface, the provider connectors and shared types. `api`, `worker`, `agent` and `controller` import it.

Secrets Bridge is a secrets control plane: it governs access to secrets held in external providers without storing the values. The control plane handles metadata; only the agent touches values.

## Layout

| Path | Purpose |
|---|---|
| `providers/provider.go` | `Provider` interface with a metadata/value split, plus `SecretRef`, `SecretMetadata`, `SecretValue`, `SecretVersion`, `PutOptions`, `ProviderScope` and the `Registry` |
| `providers/awssecretsmanager` | AWS Secrets Manager connector (default credential chain, optional `roleArn`, `endpoint` override for LocalStack) |
| `providers/vault` | HashiCorp Vault KV v2 connector (Kubernetes auth by default, token auth for dev) |
| `sync` | Sync engine used by the controller and agent |
| `types` | Shared types |

The interface split:

```go
GetMetadata(ctx, ref)  // safe for the control plane, discovery, controller
ListMetadata(ctx, scope)
GetValue(ctx, ref)     // agent only
PutValue(ctx, ref, value, opts) // agent only
```

## Build and test

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
golangci-lint run
go mod tidy   # CI fails if this produces a diff
```

## Rules for this repo

- **Infra-free.** No database driver, no Redis client, no HTTP framework. Anything that needs Postgres or Redis belongs in `api`.
- **Never log or return a secret value.** `SecretValue.String()` and `GoString()` return `<redacted>`; keep it that way and never put `SecretValue` bytes in an error message.
- Provider-specific auth stays inside its own package.
- New connectors follow the existing shape: `providers/<kind>/<kind>.go` with tests, a small interface over the SDK client so tests can inject a fake, an exported `Kind` and `Register(*providers.Registry)` (no `init()`), and not-found errors mapped to `providers.ErrNotFound`.
- Interface changes affect every Go repo. Open an issue first and coordinate the follow-up PRs.

## Contributing

Feature branch off `main`, conventional commits (`feat:`, `fix:`, `docs:`, `test:`), small PRs, CI green, then open a PR for maintainer review. Never push to `main`.

This repo is public. Keep account IDs, hostnames, cluster names, real secret paths and company names out of code, commits, PRs and issues. Use placeholders such as `123456789012` and `vault.example.com`.
