# Multi-Region Architecture

## Overview

Lattice-ID runs in two (or more) regions, each with its own NATS cluster.
Regions are completely independent — no NATS federation or leaf nodes.
Cross-region communication uses HTTP via internal endpoints.

Users are bound to a single region for data residency (GDPR / HIPAA).
When a user hits the wrong region, the system discovers the correct one
and redirects the browser.

## Data Residency

### Region-Local KV Buckets (NOT replicated)

| Bucket | Contents | Why local |
|--------|----------|-----------|
| `lid-users` | Email, name, password hash, TOTP secrets, recovery codes | PII / PHI |
| `lid-sessions` | Auth codes, refresh tokens, consumed markers, MFA pending, lockout, maintenance timestamps | Tied to user identity |
| `lid-audit` | Audit events with actor_id, target_id | References user IDs |
| `lid-user-idx` | email → user_id mapping | PII (email in key) |
| `lid-memberships` | user_id ↔ tenant_id links | Links users to orgs |
| `lid-keys` | RSA signing key pairs (per-region) | Each region is its own OIDC issuer |
| `lid-abuse-rate-limits` | Rate limit windows | Per-region tracking |

### Replicated KV Buckets (synced via HTTP)

| Bucket | Contents | Why safe to replicate | Sync mechanism |
|--------|----------|-----------------------|----------------|
| `lid-tenants` | Org name, status, display name | No PII — org metadata only | core-service periodic HTTP sync |
| `lid-clients` | OIDC client_id, redirect_uris, grant_types, hooks, IdPs, settings | No PII — app config only | core-service periodic HTTP sync |

### Cross-Region HTTP Endpoints

| Endpoint | Method | Request | Response | PII? |
|----------|--------|---------|----------|------|
| `/internal/lookup` | GET | `?hash=sha256(email)` | `{ found, region }` | No — pseudonymized hash only |
| `/internal/config` | GET | (none) | `{ clients, tenants }` | No — app config only |

All `/internal/*` requests must carry a matching `X-Internal-Auth` header.
Regions share that secret via `internal_auth_secret` in `wasi:config/store`.

## Compliance Assessment

### GDPR

- **Data residency**: All PII stays in the originating region's NATS cluster.
  User records, sessions, audit logs, and email indexes never cross region boundaries.
- **Cross-region lookup**: Uses `sha256(email)`, a one-way hash. No raw email, name,
  or other PII crosses regions. The response contains only a boolean and
  a region identifier.
- **Right to erasure**: Delete user from region-local KV. Hashed cache entries in
  other regions expire via TTL (1 hour). No PII in replicated buckets.
- **JWTs**: Contain email and name per OIDC spec. These are issued to the user's
  browser and never stored in cross-region KV.
- **Email messages**: Sent via `lattice-id:notify/email` WIT interface to the
  region-local email-worker. Email addresses do not cross regions.

### HIPAA

- **PHI isolation**: If user records contain health-related data, it remains in
  the region-local NATS cluster behind access controls.
- **Audit trail**: Region-local audit logs capture all access events.
- **Signing keys**: Per-region, never leave the originating NATS cluster.

### Future Security Hardening (separate from multi-region)

- Remove raw email from audit log `details` field (use user_id only)
- Encrypt TOTP secrets and recovery codes at rest
- Add audit log retention/rotation policy
- Consider removing email/name from access_token (keep in id_token only)
- NATS TLS mandatory between all nodes

## Architecture

```
                      auth.example.com
                      (Route53 / CloudFront geolocation)
                     ┌──────────┴──────────┐
                     ▼                      ▼
          eu.auth.example.com       us.auth.example.com
          (ALB / Ingress)           (ALB / Ingress)
          ┌──────┬──────┐           ┌──────┐
          ▼      ▼      ▼           ▼      ▼
     oidc-gw  oidc-gw  oidc-gw  oidc-gw  oidc-gw
     (FRA-1)  (FRA-2)  (AMS-1)  (IAD-1)  (IAD-2)
          │      │      │           │      │
          └──────┼──────┘           └──────┘
                 │                      │
        core-svc(FRA) core-svc(AMS)  core-svc(IAD)
                 │                      │
          ┌──────┘                      └──────┐
          ▼                                    ▼
    NATS Cluster (EU)     HTTP /internal/   NATS Cluster (US)
    ┌─────────────────┐   lookup + config   ┌─────────────────┐
    │ lid-users    ✗  │ ◄────────────────► │ lid-users    ✗  │
    │ lid-sessions ✗  │                    │ lid-sessions ✗  │
    │ lid-audit    ✗  │                    │ lid-audit    ✗  │
    │ lid-user-idx ✗  │                    │ lid-user-idx ✗  │
    │ lid-members  ✗  │                    │ lid-members  ✗  │
    │ lid-keys     ✗  │                    │ lid-keys     ✗  │
    │                 │                    │                 │
    │ lid-tenants  ⟷  │  ← HTTP sync →    │ lid-tenants  ⟷  │
    │ lid-clients  ⟷  │                    │ lid-clients  ⟷  │
    └─────────────────┘                    └─────────────────┘

    ✗ = region-local only
    ⟷ = synced via HTTP (/internal/config, every 5 min)
```

## Component Roles

### oidc-gateway (stateless, N replicas per workload)

- Full OIDC authority: /authorize, /login, /token, /userinfo, /register, /api/*
- Signs JWTs locally (loads keys from key-manager component via WIT)
- Uses revision-based CAS (taika3d:lid/kv swap) for auth code consumption and refresh token rotation
- On login miss: queries region-authority (local NATS KV) then remote regions via HTTP `/internal/lookup`
- On lookup hit: redirects browser to correct region's authorize endpoint
- Exposes `/internal/lookup` (email hash existence check) and `/internal/config` (clients + tenants export)
- Requires `internal_auth_secret` on all cross-region `/internal/*` requests

### core-service (1 per workload, in-memory state)

- **Key rotation**: Generates RSA-2048 keys, persists to `lid-keys` using CAS
  (get_revision → swap). Multiple instances safely coordinate.
- **Rate limiting**: In-memory sliding window. Per-instance approximate — acceptable.
- **Metrics**: In-memory Prometheus counters. Scraped per-workload.
- **GC**: Garbage-collects expired sessions, codes, tokens (every 10 min, CAS-guarded).
- **Config sync**: Fetches clients + tenants from remote regions via HTTP
  `/internal/config` (every 5 min, CAS-guarded). Writes to local KV.
- **CAS task claiming**: Periodic tasks use `try_claim_task()` — stores last-run
  timestamp in `lid-sessions` under `maintenance:{task_name}`. Only one instance
  across all replicas wins the CAS race per interval.

### region-authority (stateless WIT component)

- Checks local `lid-user-idx` NATS KV for email hash existence
- Uses `lid-authority-cache` (in-memory) as read-through cache
- Called by oidc-gateway before HTTP fallback to remote regions
- No PII in request or response

### email-worker (1 per workload)

- Receives email send requests via `lattice-id:notify/email` WIT interface
- Delivers via HTTP API or logs (dev mode)
- Region-local only — email addresses never leave the region

### password-hasher (1 per workload)

- Argon2id hashing via `lattice-id:crypto/password` WIT interface
- Stateless computation, region-local

## Cross-Region Login Flow

```
1. User (EU citizen in US) visits https://auth.example.com/authorize?...
2. Route53 geo-routes to us.auth.example.com
3. US oidc-gateway shows login page
4. User submits: email=alice@corp.fi, password=***
5. US oidc-gateway: store::get_user_by_email("alice@corp.fi") → None
6. US oidc-gateway: service_client::lookup_region(sha256("alice@corp.fi"))
7. US gateway: checks in-memory cache → miss
8. US gateway: calls region-authority (local NATS KV) → miss
9. US gateway: HTTP GET to EU /internal/lookup?hash=abc...
10. EU gateway: checks lid-user-idx → found
11. EU gateway: replies { found: true, region: "eu" }
12. US gateway: caches sha256 → "eu" (1h TTL), returns to login flow
13. US oidc-gateway: builds redirect URL preserving all OIDC params
    302 → https://eu.auth.example.com/authorize?client_id=X&...&login_hint=alice@corp.fi
14. Browser follows redirect to EU
15. EU oidc-gateway shows login page (email pre-filled from login_hint)
16. User enters password → EU authenticates → auth code → redirect to app
```

## Key Rotation with CAS (Multiple Core-Services)

```
Every 60 seconds, each core-service instance:
1. get_revision("lid-keys", "signing_keys") → (exported_keys, revision)
2. Import keys from KV (pick up any other instance's rotation)
3. If current key age >= 24h:
   a. Generate new RSA-2048 key pair
   b. Retire old key (48h grace period for verification)
   c. Export new key store
   d. swap("lid-keys", "signing_keys", new_export, revision)
   e. If swap fails → another instance rotated first → go to step 1
   f. If swap succeeds → log rotation, continue
4. If no rotation needed → update in-memory keys from KV (adopt remote rotations)
```

## Implementation Summary

| # | Component | What | File(s) |
|---|-----------|------|---------|
| 1 | oidc-gateway | `/internal/lookup` endpoint (email hash check) | oidc-gateway/src/lib.rs |
| 2 | oidc-gateway | `/internal/config` endpoint (export clients + tenants) | oidc-gateway/src/lib.rs |
| 3 | oidc-gateway | `lookup_region()` with 3-tier lookup (cache → authority → HTTP) | oidc-gateway/src/service_client.rs |
| 4 | oidc-gateway | Cross-region redirect on login miss | oidc-gateway/src/login.rs |
| 5 | core-service | CAS-guarded GC + config sync background tasks | core-service/src/main.rs, store.rs |
| 6 | core-service | `try_claim_task()` distributed leader election | core-service/src/store.rs |
| 7 | core-service | `sync_remote_config()` HTTP fetch + KV upsert | core-service/src/store.rs |
| 8 | region-authority | Local NATS KV lookup with in-memory cache | region-authority/src/lib.rs |
| 9 | key-manager | Per-region RSA key generation + CAS rotation | key-manager/src/lib.rs |
| 10 | Config | `region_id`, `region_domains`, `region_internal_urls` | wasi:config/store |

## Scaling

- **Within a region**: Add workloads (each = N gateways + 1 core-service).
  All workloads share the same regional NATS KV. CAS prevents conflicts.
  Periodic tasks (GC, config sync) are CAS-guarded — only one instance runs
  each task per interval regardless of replica count.
- **Across regions**: Deploy independent NATS clusters. Configure
  `region_internal_urls` with each region's HTTP endpoint and configure the
  same `internal_auth_secret` in every region. core-service syncs config
  automatically via `/internal/config`.
- **Rate limiting**: Per abuse-protection component instance (approximate). Acceptable for
  abuse prevention. Can move to KV-based `bucket.increment()` later for
  global accuracy.
