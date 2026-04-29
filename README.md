# Lattice-ID

Lattice-ID is a NATS-native OIDC provider for wasmCloud, backed by JetStream KV.

Runs as a standard wasmCloud workload alongside your applications — no extra database, no separate infrastructure. Lattice-ID uses [lattice-db](https://github.com/Taika-3D-Oy/lattice-db) for all persistent state via NATS JetStream KV.

## Maintainer notes

Lattice-ID uses [lattice-db](https://github.com/Taika-3D-Oy/lattice-db) for all persistent state. lattice-db runs as a separate wasmCloud workload and provides NATS KV with CAS semantics over request/reply messaging (`wasmcloud:messaging`).

All deployment files exist solely for testing and validating Lattice-ID locally.

## Status

**v1.3.0**

- Full OIDC/OAuth2 compliance (authorization code + PKCE, client credentials, device flow, refresh token rotation)
- Security hardening: CSRF protection, refresh token absolute lifetime cap, account lockout, rate limiting, consent screen
- GDPR: user data export (`GET /api/users/:id/export`) and erasure (`DELETE /api/users/:id`)
- Backchannel logout (RFC 8613), RP-initiated logout (OIDC RP-Initiated Logout 1.0)
- Multi-region design: [MULTI_REGION.md](MULTI_REGION.md)

## Workspace Layout

- `oidc-gateway`: HTTP OIDC surface, management API, and embedded admin UI serving
- `password-hasher`: Argon2id worker (SIMD-accelerated)
- `email-worker`: email delivery (log for dev, AWS SES for production)
- `abuse-protection`: rate limiting and account lockout
- `key-manager`: RSA signing key persistence
- `region-authority`: home-region lookup for multi-region deployments
- `admin-ui`: optional Leptos admin UI (builds separately with Trunk)
- `admin-ui/host`: WASI component that embeds the admin UI dist and serves via the gateway

## Prerequisites

- Rust nightly with the `wasm32-wasip3` target
- `wash` (stock upstream wasmCloud CLI)
- `kind`, `kubectl`, `helm` for local Kubernetes clusters
- `docker` for the local OCI registry
- `curl` and `python3` for integration tests
- `trunk` if you want the admin UI
- Access to [lattice-db](https://github.com/Taika-3D-Oy/lattice-db) OCI images on GHCR (default: `ghcr.io/taika-3d-oy/lattice-db/storage-service:latest`)

```bash
rustup target add wasm32-wasip3
```

## Local Development

Lattice-ID requires lattice-db for persistent storage, which means it runs on
a Kind cluster with the wasmCloud operator — not standalone via `wash dev`.

### Deploy a local cluster

```bash
bash deploy/deploy-local.sh
```

This script:

- Creates a Kind cluster with a local OCI registry
- Installs the wasmCloud operator via Helm
- Deploys a standalone NATS JetStream data-plane (`nats-data`)
- Builds and pushes lattice-id wasm components
- Deploys lattice-db from GHCR (override with `LATTICE_DB_IMAGE=...`)
- Deploys both as WorkloadDeployments
- Exposes the HTTP gateway on `http://localhost:8000`

Other commands:

```bash
bash deploy/deploy-local.sh rebuild   # rebuild + redeploy components
bash deploy/deploy-local.sh teardown  # destroy the cluster
bash deploy/deploy-local.sh status    # show cluster status
```

## Bootstrap Behavior

The `deploy/workloaddeployment-local.yaml` manifest includes a `bootstrap_hook`
that promotes the first registered user to superadmin automatically.

When the bootstrap hook promotes a superadmin (`set_superadmin(true)`), the
gateway also creates the built-in `lid-admin` OAuth client so the admin UI is
immediately usable without any manual client registration.

To restrict bootstrap to a specific email, edit the inline Rhai hook:

```yaml
bootstrap_hook: |
  if user.email == "you@example.com" {
    set_superadmin(true);
    log("Bootstrap: promoted " + user.email);
  }
```

## Build And Check

```bash
cargo build --workspace --target wasm32-wasip3
cargo test --workspace
```

The `admin-ui` crate is excluded from the root workspace and builds separately.

## Integration Tests

Integration tests run against a live Kind cluster. The test runner resets the
cluster state (NATS data + lattice-db) before each test to ensure a clean slate.

### Run all tests

```bash
bash tests/run_cluster_tests.sh
```

### Run a single test

```bash
bash tests/run_cluster_tests.sh authority    # filter by name
```

### Skip reset (use existing state)

```bash
bash tests/run_cluster_tests.sh --no-reset
```

### Test coverage

| Script | Coverage |
|--------|----------|
| `integration_authority` | auth code flow, refresh, introspection, claims, replay detection |
| `integration_protocol` | invalid tokens, malformed JWTs, missing PKCE, unregistered redirect_uri, wrong code_verifier |
| `integration_hooks` | Rhai hook CRUD, dry-run, set_superadmin, set_claim |
| `integration_mfa` | TOTP setup, verification, recovery codes |
| `integration_isolation` | tenant isolation and role boundaries |
| `integration_rate_limit` | brute-force protection and lockout |
| `integration_hardening` | error handling, refresh token rotation, absolute lifetime cap |
| `integration_restart` | workload restart resilience and state recovery |
| `integration_new_features` | client_credentials, device flow, ES256 signing, `/version` |
| `integration_account` | CSRF protection, consent screen (allow/deny/state), first_party flag, GDPR export+delete |
| `integration_logout` | RP-initiated logout, open-redirect protection, prompt=none/login/consent, /healthz, /readyz |
| `integration_backchannel` | backchannel logout_token delivery and validation (RFC 8613) |
| `integration_social_mock` | Google OIDC social login with mock IdP |
| `integration_two_region` | cross-region user lookup, redirect, tenant/client replication |

## Features

**OIDC / OAuth2**
- Authorization Code flow with PKCE (S256)
- Client Credentials grant (confidential clients)
- Device Authorization grant (RFC 8628)
- Refresh token rotation with replay detection and 90-day absolute lifetime cap
- Backchannel Logout (RFC 8613) with signed `logout_token`
- RP-Initiated Logout (OIDC RP-Initiated Logout 1.0) with open-redirect protection
- `prompt=none/login/consent`, `max_age`, `id_token_hint`, `login_hint`, `claims` parameter
- RS256 and per-client ES256 ID token signing
- Token introspection (RFC 7662)

**Security**
- CSRF tokens on all account self-service mutations
- Consent screen for third-party clients (`first_party` flag to opt out)
- Account lockout after configurable failure threshold
- IP-based rate limiting via abuse-protection component
- Refresh token absolute lifetime cap (configurable, default 90 days)
- PKCE enforced for all public clients

**Identity & Access**
- Passkeys (WebAuthn) for passwordless authentication
- TOTP-based MFA with recovery codes
- Google OIDC social login (generic OIDC federation supported)
- Self-service account management (password change, email update, passkey enrollment)
- Email verification and invitation flows
- Multi-tenant with per-membership roles (`tenant_id`, `role` claims)

**Operations**
- GDPR: data export (`GET /api/users/:id/export`) and erasure (`DELETE /api/users/:id`)
- Audit log entries in a dedicated KV bucket
- Rhai scripting hooks for custom authorization logic and claim injection
- `/healthz` (liveness) and `/readyz` (readiness with KV + key checks)
- Prometheus-format metrics at `/metrics`
- Embedded admin UI served at `/admin`
- Multi-region deployment with cross-region user routing
- Configurable lattice-db instance isolation (`ldb_instance` config, matches `LDB_INSTANCE` on the storage-service)
- Session consistency tokens (lattice-db 1.6.0) — read-your-write guarantees across replicas via `x-lid-consistency` header and `__lid_cr` HttpOnly cookie
- AWS SES email delivery for production, log provider for development

## Important Docs

- [INTEGRATION.md](INTEGRATION.md): integrating an application with Lattice-ID
- [K8S_DEV.md](K8S_DEV.md): Kubernetes-based development flow, email delivery configuration
- [MULTI_REGION.md](MULTI_REGION.md): two-region architecture and deployment notes

## License

Apache-2.0
