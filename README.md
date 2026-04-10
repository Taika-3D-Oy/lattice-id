# Lattice-ID

Lattice-ID is a NATS-native OIDC provider for wasmCloud, backed by JetStream KV.

This repository is still alpha. The short version is: use the README to get a local dev environment running, and use the linked docs for security, scaling, and multi-region details.

## Maintainer notes

Lattice-ID currently depends on custom host plugins for:

- NATS KV with CAS
- in-memory KV used as a cache

For internal testing those were adapted from `wasi:keyvalue`.

This currently means you need a custom `wash` and runtime fork to develop and test Lattice-ID.

All deployment files exist solely for testing and validating Lattice-ID locally.

## Status

- OIDC/OAuth implementation is substantial, but the project is not yet production-hardened.
- The current security review is in [SECURITY_AUDIT_2026-04-09.md](SECURITY_AUDIT_2026-04-09.md).
- Compliance details are in [OIDC_COMPLIANCE_AUDIT.md](OIDC_COMPLIANCE_AUDIT.md).
- Multi-region design is in [MULTI_REGION.md](MULTI_REGION.md).

## Workspace Layout

- `oidc-gateway`: HTTP OIDC surface and management API
- `core-service`: signing keys, coordination, metrics
- `password-hasher`: Argon2 worker
- `email-worker`: email delivery adapters
- `abuse-protection`: rate limiting and lockout support
- `key-manager`: key persistence helpers
- `region-authority`: home-region lookup support
- `admin-ui`: optional local admin UI served by Trunk

## Prerequisites

- Rust with the `wasm32-wasip2` target
- the custom Taika3D `wash` build from `https://github.com/Taika-3D-Oy/wasmCloud`
- `trunk` if you want the admin UI
- `curl` and `python3` for integration tests

```bash
rustup target add wasm32-wasip2
```

## Custom `wash` Requirement

Lattice-ID does not work with stock upstream `wash`.

Local development depends on custom `wash-runtime` plugins for these interfaces:

- `taika3d:lid/keyvalue-nats-cas`
- `taika3d:lid/keyvalue-in-memory`

Those plugins are wired into the Taika3D fork of `wasmCloud`, including the filesystem-backed fallback used by `wash dev` in this repo.


```bash
git clone https://github.com/Taika-3D-Oy/wasmCloud
cd wasmCloud
cargo install --path crates/wash --force
export PATH="$HOME/.cargo/bin:$PATH"
```

The important part is that the custom binary is first on your `PATH`; otherwise `wash dev` will fail when it tries to bind the `taika3d:lid` host interfaces from `.wash/config.yaml`.

## Local Development

### Fast path

```bash
./dev.sh start
```

That script:

- starts `wash dev` on `http://localhost:8000`
- starts the admin UI on `http://localhost:8091`
- waits until discovery is serving

Useful commands:

```bash
./dev.sh stop
./dev.sh reset
```

### Manual path

```bash
cargo build --workspace --target wasm32-wasip2
wash dev --non-interactive
```

For the admin UI in a second terminal:

```bash
cd admin-ui
trunk serve
```

## Bootstrap Behavior

The default `.wash/config.yaml` runs in dev mode and includes a bootstrap hook that promotes the first registered user to superadmin.

If you want to restrict that to a specific email during local work, edit `.wash/config.yaml`:

```yaml
bootstrap_hook: |
  if user.email == "you@example.com" {
    set_superadmin(true);
    log("Bootstrap: promoted " + user.email);
  }
```

## Build And Check

```bash
cargo build --workspace --target wasm32-wasip2
cargo test --workspace
```

The `admin-ui` crate is excluded from the root workspace and builds separately.

## Integration Tests

Most integration tests boot their own `wash dev` instance and expect a clean local environment.

Run one test:

```bash
bash tests/integration_authority.sh
```

Run the single-region suite:

```bash
for t in tests/integration_*.sh; do
  [[ "$t" == *two_region* ]] && continue
  bash "$t" || break
done
```

Run the multi-region test:

```bash
bash tests/integration_two_region.sh
```

Test coverage by script:

- `tests/integration_authority.sh`: authorization code flow, refresh, token validation
- `tests/integration_protocol.sh`: discovery, PKCE, scopes, claims behavior
- `tests/integration_hooks.sh`: Rhai post-login and post-registration hooks
- `tests/integration_mfa.sh`: TOTP setup, verification, recovery codes
- `tests/integration_isolation.sh`: tenant isolation and role boundaries
- `tests/integration_hardening.sh`: malformed input and edge cases
- `tests/integration_rate_limit.sh`: brute-force protection and lockout
- `tests/integration_restart.sh`: persistence across restarts
- `tests/integration_social_mock.sh`: mocked Google OAuth flow
- `tests/integration_two_region.sh`: cross-region lookup and config sync
- `tests/stress_authority.sh`: crude concurrency stress

## Important Docs

- [INTEGRATION.md](INTEGRATION.md): integrating an application with Lattice-ID
- [K8S_DEV.md](K8S_DEV.md): Kubernetes-based development flow
- [MULTI_REGION.md](MULTI_REGION.md): two-region architecture and deployment notes
- [SECURITY_AUDIT_2026-04-09.md](SECURITY_AUDIT_2026-04-09.md): current security review and outstanding issues
- [SCALABILITY_ANALYSIS.md](SCALABILITY_ANALYSIS.md): throughput and capacity notes
- [OIDC_COMPLIANCE_AUDIT.md](OIDC_COMPLIANCE_AUDIT.md): protocol compliance details

## License

Apache-2.0
