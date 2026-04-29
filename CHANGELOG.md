# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
