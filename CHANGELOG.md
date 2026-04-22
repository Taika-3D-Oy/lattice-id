# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/Taika-3D-Oy/lattice-id/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Taika-3D-Oy/lattice-id/releases/tag/v1.0.0
