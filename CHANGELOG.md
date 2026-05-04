# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.3] - 2026-05-05

### Security

- **Fail-fast on missing KMS config**: `vault.rs` no longer falls back to a
  hardcoded development seed when `kms_endpoint` is absent. The component now
  panics at startup with a descriptive error unless either `kms_endpoint`
  (production) or `kms_dev_seed + dev_mode=true` (development) is explicitly
  configured. Using `kms_dev_seed` while `dev_mode=false` is also rejected so a
  misconfigured deployment cannot silently use a weak key.

- **HMAC-peppered email index**: All email-keyed KV entries
  (`email:{hash}` in the user-idx store) now use `HMAC-SHA256(lowercase_email,
  pepper)` as the key instead of the plaintext email address. The pepper is
  supplied via the `email_pepper` config key (32+ random bytes). Without the
  pepper, an attacker with NATS read access cannot enumerate or rainbow-table
  user emails. Deployments must set `email_pepper`; a warning is logged and
  operation continues without HMAC if the config key is absent so existing dev
  environments keep working. **Migration note**: existing records in
  `user-idx` use plaintext keys and will become unreachable after deploying this
  change; a one-time reindex or fresh deployment is required.

- **Hashed client secrets**: `OidcClient.client_secret` now stores
  `HMAC-SHA256(raw_secret, client_secret_pepper)` rather than the raw 32-byte
  hex value. The raw secret is returned exactly once at client creation. Token
  endpoint verification recomputes the HMAC before the constant-time compare.
  Configure via `client_secret_pepper`. Existing confidential clients must be
  rotated after deploying this change.

- **Rate-limit `/internal/lookup`**: Cross-region email-hash lookups are now
  limited to 60 requests per minute per source IP using the existing abuse
  protection component. Exceeding the limit returns `429 Too Many Requests`.
  This prevents an authenticated-but-malicious peer region from enumerating
  email hashes at high speed.

## [1.5.2] - 2026-05-04

### Fixed

- **Admin UI wasm-opt CI fix**: Trunk's bundled wasm-opt does not enable
  bulk-memory operations, causing a `wasm-validator` error on the `memory.copy`
  instructions emitted by Rust's `wasm32-unknown-unknown` target. `data-wasm-opt`
  is now set to `"0"` so Trunk skips its built-in pass; a dedicated CI step
  installs `binaryen` from apt and runs `wasm-opt --enable-bulk-memory -Oz`
  on the built wasm files before they are bundled into the host component.

## [1.5.1] - 2026-05-04

### Fixed

- **Admin UI SPA routing**: Added `base="/admin"` to the Leptos `<Router>` so
  all routes are correctly scoped under `/admin/`. Previously, navigating to e.g.
  `/admin/tenants` and refreshing would serve raw API JSON (or trigger the
  user-facing passkeys/account UI for conflicting paths). All sidebar `<A>` hrefs
  and in-view back-links updated to match.
- **Admin route prefix check**: Gateway handler now matches `/admin` exactly or
  `/admin/*`, preventing paths like `/administer` from being caught by the SPA
  fallback.
- **Admin asset cache-control**: Hashed-filename detection now requires the hash
  suffix to be exactly 16 lowercase hex digits (matching Trunk's actual output),
  avoiding a 1-year immutable cache for any file that merely has a hyphen in its
  name.
- **Admin UI wasm-opt**: Trunk's wasm-opt was explicitly disabled (`"0"`) in
  `index.html`; changed to `"z"` (optimize for size). Expected to reduce the wasm
  bundle significantly on next build.
- **Admin host MIME types**: Added `jpg/jpeg`, `gif`, `webp`, `ico`, `woff`,
  `woff2`, `txt`, and source maps (`.map`) to the content-type table. `text/html`
  and `text/css` now include `charset=utf-8`.

## [1.5.0] - 2026-05-03

### Changed

- **Removed satellite components**: `abuse-protection`, `key-manager`,
  `region-authority`, and `crypto-vault` are no longer separate crates. Their
  functionality has been consolidated into `oidc-gateway` (rate limiting, key
  management, region lookup, and encryption all run inline via TCP to lattice-db).
- **Co-located lattice-db service**: All deployment manifests now include
  lattice-db as a co-located service inside the WorkloadDeployment (TCP on
  `127.0.0.1:4080`). Separate `latticedb-{region}.yaml` manifests removed.
- **Workspace reduced**: From 7 crates to 3 (`oidc-gateway`, `password-hasher`,
  `email-worker`). `admin-ui` remains excluded (separate build).
- **CI publish**: Only builds and pushes `oidc-gateway`, `password-hasher`,
  `email-worker`, and `admin-ui-host`.

## [1.4.1] - 2026-05-02

### Fixed

- **TCP client EOF handling**: Fixed `drop(tx)` closing write stream before response
  was read, and added `Complete(0)` EOF detection to prevent infinite read loops in
  all five service clients (oidc-gateway, key-manager, abuse-protection,
  region-authority, crypto-vault).
- **Public endpoint performance**: JWKS, OpenID configuration, version, and healthz
  endpoints no longer make a rate-limit TCP call on every request.
- **CORS origin fast-path**: `allowed_origin()` checks issuer origin directly before
  calling `list_clients()`, avoiding N+1 TCP calls on every XHR response.
- Removed debug logging added during diagnosis.

## [1.4.0] - 2026-04-30

### Changed

- **Switched lattice-db communication from NATS to localhost TCP** — all
  components that talk to lattice-db now connect to `127.0.0.1:4080` (the
  co-located lattice-db service) via `wasi:sockets/types` instead of
  `wasmcloud:messaging/consumer` over NATS request/reply.
  - Wire protocol: 4-byte big-endian length prefix + JSON body with `_op` field.
  - Eliminates NATS round-trip overhead; reads hit the local cache via virtual
    pipes (sub-millisecond latency).
  - Updated components: oidc-gateway, key-manager, abuse-protection,
    region-authority, crypto-vault.
  - oidc-gateway retains NATS messaging for metrics publish.

## [1.3.2] - 2026-04-30

### Fixed

- **Double-login race condition** — submitting the login form twice (e.g. via
  double-click during the 2+ second bcrypt verification) could issue two
  separate authorization codes for the same session, causing downstream
  consistency errors.
  - **Backend:** `complete_login` now consumes the auth session atomically via
    a CAS delete (`consume_auth_session`). A concurrent second request finds the
    session already gone and receives a clear error rather than issuing a
    duplicate code.
  - **Frontend:** the Sign In and Verify (MFA) buttons are disabled and relabelled
    (*Signing in…* / *Verifying…*) immediately on form submit, preventing
    double-clicks from reaching the server at all.

## [1.3.1] - 2026-04-29

### Fixed

- **Admin UI OAuth client** — added `{issuer}/admin/callback` to the
  `lid-admin` redirect URIs so the admin SPA callback works when served
  under the `/admin` path.

## [1.3.0] - 2026-04-29

### Added

- **Session consistency tokens (lattice-db 1.6.0)** — all five components now
  track per-table revision watermarks within each request. Read operations
  inject `consistency.min_revision` and write responses update the map from
  `session.revisions`. This provides read-your-write guarantees even when NATS
  queue groups route successive requests to different lattice-db replicas.

- **Consistency propagation for browsers and API clients** — the oidc-gateway
  emits an `x-lid-consistency` response header and a `__lid_cr` HttpOnly cookie
  containing session revisions JSON. Inbound requests seed the consistency
  context from the header (preferred, for API clients) or cookie (automatic for
  browsers). Backward compatible: missing context falls back to eventual reads.

- **CORS headers updated** — `x-lid-consistency` added to
  `access-control-allow-headers` and `access-control-expose-headers`.

- **New integration test** `tests/integration_consistency.sh` — verifies
  header/cookie emission, round-trip, and backward compatibility.

### Changed

- **Deploy scripts pin lattice-db to `v1.6.0`** — `LATTICE_DB_IMAGE` default
  updated from `:v1.5.0` to `:v1.6.0` in `deploy-local.sh` and
  `deploy-two-region.sh`.

- **lattice-db workload manifests** — added `LDB_CONSISTENCY_WATCHER_WAIT_STEPS`
  and `LDB_CONSISTENCY_WATCHER_WAIT_STEP_SECS` environment variables (defaults:
  `2` and `1`) to `latticedb-eu.yaml`, `latticedb-us.yaml`, `deploy-local.sh`,
  and `deploy-two-region.sh`.

### Fixed

- **crypto-vault** — `ldb.set` corrected to `ldb.put` to match the documented
  lattice-db protocol.

## [1.2.1] - 2026-04-29

### Fixed

- **Bootstrap now creates the `lid-admin` OAuth client** — when the first
  superadmin is promoted via the bootstrap hook, the gateway ensures the
  `lid-admin` client exists so the admin UI can log in immediately. Previously
  the client was only created lazily in dev mode, which meant production
  deployments required an extra request before the admin UI worked.

### Removed

- `kv_prefix` config key from `workloaddeployment-local-prod.yaml` — this
  leftover key was removed for consistency with the 1.2.0 migration.

## [1.2.0] - 2026-04-23

### Changed

- **Migrated to lattice-db 1.2.0** — replaced the old per-request `_partition` /
  `ldb_tenant` scheme with lattice-db's new `LDB_INSTANCE` deploy-time isolation.
  All five components (`oidc-gateway`, `key-manager`, `abuse-protection`,
  `crypto-vault`, `region-authority`) no longer inject `"_partition"` into every
  request; isolation is now fully handled by the storage-service with
  `LDB_INSTANCE=lid` set in its deployment manifest.

- **Configurable lattice-db instance prefix** (`ldb_instance` config key) — the
  NATS subject prefix used by all components when communicating with lattice-db
  is now read from the `ldb_instance` wasmCloud config value (defaults to
  `"lid"`). This must match the `LDB_INSTANCE` environment variable set on the
  lattice-db storage-service. All deployment manifests set `ldb_instance: "lid"`
  explicitly.

- **Deploy scripts pin lattice-db to `v1.2.0`** — `LATTICE_DB_IMAGE` default
  updated from `:latest` to `:v1.2.0` in `deploy-local.sh` and
  `deploy-two-region.sh`.

### Removed

- `ldb_tenant` config key — replaced by `ldb_instance` / `LDB_INSTANCE`.
- `kv_prefix` config key from `oidc-gateway` and satellite components — KV
  bucket names are now derived entirely from `LDB_INSTANCE` on the server side.
  The `kv_prefix` key in `crypto-vault` and two-region EU/US manifests is also
  removed.

## [1.1.0] - 2026-04-22

### Added

- **`create_tenant(id, name, display_name)` Rhai function** available in all
  hook scripts (bootstrap hook, `post-registration`, `post-login`).  
  Allows the bootstrap hook to create the first tenant and enroll the founding
  user in a single script, without requiring a separate API call after
  bootstrapping:

  ```rhai
  if user.email == "founder@acme.com" {
      set_superadmin(true);
      create_tenant("acme", "acme", "Acme Inc.");
      add_to_tenant("acme", "owner");
      log("Bootstrap: created acme tenant + promoted owner");
  }
  ```

  The function validates the tenant id at call time (lowercase alphanumeric,
  internal hyphens allowed, 2–63 chars, no leading/trailing hyphen) and is
  idempotent — if the tenant already exists the call is silently skipped, so
  hooks are safe to re-run. Tenant creation is applied *before*
  `add_to_tenant` memberships within the same outcome, so create + join works
  atomically in a single hook invocation. Each creation is recorded as a
  `hook_create_tenant` audit event.

## [1.0.0] - 2026-04-22

### Added

- Initial release — NATS-native OIDC identity provider for wasmCloud.
- Rhai scripting hooks (`post-login`, `post-registration`, bootstrap hook)
  with `set_superadmin`, `add_to_tenant`, `set_claim`, `deny`, and `log`.
- Multi-region active-active deployment via wasmCloud.
- Admin UI (Leptos/WASM) for user, tenant, hook, and OIDC client management.
- WebAuthn / passkey, TOTP, and password authentication.
- RFC 8628 Device Authorization Grant.
- Abuse-protection and rate-limiting component.
- Crypto-vault component for key management.

[1.2.1]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Taika-3D-Oy/lattice-id/releases/tag/v1.0.0
