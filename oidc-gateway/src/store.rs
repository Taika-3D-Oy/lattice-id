use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Cached config values (initialized once per request via init_config)
thread_local! {
    static CONFIG_CACHE: RefCell<Option<OidcConfigCache>> = const { RefCell::new(None) };
}

// ── Session consistency tracking (lattice-db 1.6.0) ─────────────────────────
// Tracks per-table revision watermarks within a single request lifetime.
// Reads inject `consistency.min_revision`; write responses update the map
// from `session.revisions`.
thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

/// Seed session revisions from an external source (e.g. inbound consistency cookie/header).
pub fn seed_session_revisions(revisions: HashMap<String, u64>) {
    SESSION_REVISIONS.with(|sr| {
        let mut map = sr.borrow_mut();
        for (table, rev) in revisions {
            let entry = map.entry(table).or_insert(0);
            if rev > *entry {
                *entry = rev;
            }
        }
    });
}

/// Export current session revisions so the gateway can propagate them to the caller.
pub fn get_session_revisions() -> HashMap<String, u64> {
    SESSION_REVISIONS.with(|sr| sr.borrow().clone())
}

struct OidcConfigCache {
    ldb_instance: String,
    lockout_threshold: Option<String>,
    lockout_duration_secs: Option<String>,
    keys_bucket: Option<String>,
    tenant_bucket: Option<String>,
    region_id: Option<String>,
    internal_auth_secret: Option<String>,
    region_domains: Option<String>,
    region_internal_urls: Option<String>,
    issuer_url: Option<String>,
    dev_mode: Option<String>,
    require_email_verification: Option<String>,
    allow_registration: Option<String>,
    bootstrap_hook: Option<String>,
    refresh_absolute_max_secs: Option<String>,
}

/// Must be called once at startup / per request to load config values.
pub async fn init_config() {
    let ldb_instance = config_value_async("ldb_instance")
        .await
        .unwrap_or_else(|| "lid".to_string());
    let lockout_threshold = config_value_async("lockout_threshold").await;
    let lockout_duration_secs = config_value_async("lockout_duration_secs").await;
    let keys_bucket = config_value_async("keys_bucket").await;
    let tenant_bucket = config_value_async("tenant_bucket").await;
    let region_id = config_value_async("region_id").await;
    let internal_auth_secret = config_value_async("internal_auth_secret").await;
    let region_domains = config_value_async("region_domains").await;
    let region_internal_urls = config_value_async("region_internal_urls").await;
    let issuer_url = config_value_async("issuer_url").await;
    let dev_mode = config_value_async("dev_mode").await;
    let require_email_verification = config_value_async("require_email_verification").await;
    let allow_registration = config_value_async("allow_registration").await;
    let bootstrap_hook = config_value_async("bootstrap_hook").await;
    let refresh_absolute_max_secs = config_value_async("refresh_absolute_max_secs").await;

    CONFIG_CACHE.with(|c| {
        *c.borrow_mut() = Some(OidcConfigCache {
            ldb_instance,
            lockout_threshold,
            lockout_duration_secs,
            keys_bucket,
            tenant_bucket,
            region_id,
            internal_auth_secret,
            region_domains,
            region_internal_urls,
            issuer_url,
            dev_mode,
            require_email_verification,
            allow_registration,
            bootstrap_hook,
            refresh_absolute_max_secs,
        });
    });
}

fn with_config<T>(f: impl FnOnce(&OidcConfigCache) -> T) -> T {
    CONFIG_CACHE.with(|c| {
        let borrow = c.borrow();
        let cfg = borrow.as_ref().expect("init_config() not called");
        f(cfg)
    })
}

async fn config_value_async(key: &str) -> Option<String> {
    crate::bindings::wasi::config::store::get(key.to_string())
        .await
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn config_value(key: &str) -> Option<String> {
    with_config(|c| match key {
        "ldb_instance" => Some(c.ldb_instance.clone()),
        "lockout_threshold" => c.lockout_threshold.clone(),
        "lockout_duration_secs" => c.lockout_duration_secs.clone(),
        "keys_bucket" => c.keys_bucket.clone(),
        "tenant_bucket" => c.tenant_bucket.clone(),
        "region_id" => c.region_id.clone(),
        "internal_auth_secret" => c.internal_auth_secret.clone(),
        "region_domains" => c.region_domains.clone(),
        "region_internal_urls" => c.region_internal_urls.clone(),
        "issuer_url" => c.issuer_url.clone(),
        "dev_mode" => c.dev_mode.clone(),
        "require_email_verification" => c.require_email_verification.clone(),
        "allow_registration" => c.allow_registration.clone(),
        "bootstrap_hook" => c.bootstrap_hook.clone(),
        "refresh_absolute_max_secs" => c.refresh_absolute_max_secs.clone(),
        _ => None,
    })
}

/// Maximum absolute lifetime of a refresh token family (regardless of rotation).
/// Default: 90 days. Configurable via `refresh_absolute_max_secs`.
pub fn refresh_absolute_max_secs() -> u64 {
    config_value("refresh_absolute_max_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(86400 * 90) // 90 days
}

// Task 2.7: Configurable account lockout policy
fn max_login_failures() -> u32 {
    config_value("lockout_threshold")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

fn lockout_duration() -> u64 {
    config_value("lockout_duration_secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(900) // 15 minutes
}

// ── Data types ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
    pub status: String,
    pub created_at: u64,
    #[serde(default)]
    pub superadmin: bool,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub recovery_codes: Vec<String>,
    #[serde(default)]
    pub passkey_credentials: Vec<PasskeyCredential>,
}

/// A stored WebAuthn/passkey credential (ES256 / P-256).
#[derive(Serialize, Deserialize, Clone)]
pub struct PasskeyCredential {
    /// Base64url-encoded credential ID.
    pub credential_id: String,
    /// Base64url-encoded COSE public key (uncompressed P-256).
    pub public_key: String,
    /// Signature counter for clone detection.
    pub sign_count: u32,
    /// Human-readable label (e.g. "MacBook Touch ID").
    pub name: String,
    /// Unix timestamp of registration.
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AuthSession {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub scope: String,
    pub nonce: String,
    #[serde(default)]
    pub max_age: Option<u64>,
    #[serde(default)]
    pub acr_values: Vec<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    #[serde(default)]
    pub hinted_user_id: Option<String>,
    #[serde(default)]
    pub hinted_email: Option<String>,
    pub created_at: u64,
    /// Whether a consent screen must be shown before the auth code is issued.
    #[serde(default)]
    pub needs_consent: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AuthCode {
    pub user_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub auth_time: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    /// Custom claims injected by Rhai hooks (key-value pairs).
    #[serde(default)]
    pub extra_claims: Vec<(String, String)>,
    pub expires_at: u64,
    /// OAuth2 state param, carried through consent flow.
    #[serde(default)]
    pub state: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RefreshEntry {
    pub user_id: String,
    pub client_id: String,
    pub expires_at: u64,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub auth_time: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub requested_id_token_claims: Vec<String>,
    #[serde(default)]
    pub requested_userinfo_claims: Vec<String>,
    /// Unix timestamp when this refresh token family was originally issued.
    /// Carried forward on every rotation to enforce an absolute lifetime cap.
    #[serde(default)]
    pub issued_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct OidcClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub name: String,
    #[serde(default)]
    pub theme: Option<ClientTheme>,
    /// OIDC Back-Channel Logout URI (RFC 8613).
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// If true, the `sid` claim will be included in the logout token.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// JWS algorithm used to sign id_tokens for this client. "RS256" (default) or "ES256".
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    /// First-party clients skip the consent screen. Defaults to false.
    /// The built-in `lid-admin` and `lid-default` clients are implicitly first-party.
    #[serde(default)]
    pub first_party: bool,
}

impl Default for OidcClient {
    fn default() -> Self {
        OidcClient {
            client_id: String::new(),
            client_secret: None,
            redirect_uris: Vec::new(),
            grant_types: Vec::new(),
            name: "Unknown".to_string(),
            theme: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            id_token_signed_response_alg: None,
            first_party: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientTheme {
    pub app_name: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub primary_color: Option<String>,
    #[serde(default)]
    pub background_color: Option<String>,
}

/// External identity provider configuration (Google, GitHub, any OIDC provider).
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityProvider {
    pub id: String,
    pub provider_type: String, // "google", "generic-oidc", etc.
    pub client_id: String,
    pub client_secret: String,
    pub enabled: bool,
    /// OIDC discovery URL (e.g. https://example.com/.well-known/openid-configuration).
    /// Required for generic OIDC providers; optional for Google (uses hardcoded defaults).
    #[serde(default)]
    pub discovery_url: Option<String>,
    /// Human-readable display name shown on the login button.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Links an external social identity to a Lattice-ID user.
#[derive(Serialize, Deserialize)]
pub struct SocialIdentity {
    pub provider: String,
    pub provider_sub: String,
    pub user_id: String,
    pub email: String,
    pub linked_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Membership {
    pub tenant_id: String,
    pub user_id: String,
    pub role: String, // "owner", "admin", "manager", "member"
    pub joined_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Invitation {
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub token: String,
    pub invited_by: String,
    pub expires_at: u64,
}

/// RFC 8628 Device Authorization Grant — device code record.
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceCode {
    /// Opaque device verification code given to the device.
    pub device_code: String,
    /// Short user-facing code the user types at the verification URI.
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: u64,
    /// "pending" | "approved" | "denied"
    pub status: String,
    /// Set when status = "approved".
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginAttempts {
    pub failures: u32,
    pub locked_until: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuditEvent {
    pub event_type: String,
    pub actor_id: String,
    pub target_id: String,
    pub details: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub value: T,
    pub expires_at: u64,
}

/// A Rhai scripting hook — Auth0-style "Action" that runs at lifecycle points.
#[derive(Serialize, Deserialize, Clone)]
pub struct Hook {
    pub id: String,
    pub name: String,
    /// "post-login" or "post-registration"
    pub trigger: String,
    /// Rhai source code
    pub script: String,
    pub enabled: bool,
    /// Execution order (lower runs first)
    pub priority: i32,
    pub created_at: u64,
    /// Monotonically incrementing version (1 = initial, +1 per update)
    #[serde(default = "default_version")]
    pub version: u32,
    /// SHA-256 hex digest of the script content
    #[serde(default)]
    pub script_hash: String,
    /// Who last modified this hook (actor user_id)
    #[serde(default)]
    pub updated_by: String,
    /// Timestamp of last modification
    #[serde(default)]
    pub updated_at: u64,
}

fn default_version() -> u32 {
    1
}

/// Immutable snapshot of a hook version, stored for audit trail.
#[derive(Serialize, Deserialize, Clone)]
pub struct HookVersion {
    pub hook_id: String,
    pub version: u32,
    pub name: String,
    pub trigger: String,
    pub script: String,
    pub script_hash: String,
    pub enabled: bool,
    pub priority: i32,
    pub changed_by: String,
    pub changed_at: u64,
}

/// Compute SHA-256 hex digest of a string.
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Helpers ─────────────────────────────────────────────────

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_alphanumeric(n: usize) -> String {
    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let limit = 256 - (256 % charset.len()); // = 252; reject >= 252 to avoid modulo bias
    let mut result = String::with_capacity(n);
    let mut buf = [0u8; 1];
    while result.len() < n {
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        let b = buf[0] as usize;
        if b < limit {
            result.push(charset[b % charset.len()] as char);
        }
    }
    result
}

// Component instances are fresh per request — config loaded once via init_config.
/// Check if an email hash exists in this region's user-idx store.
pub async fn email_hash_exists(email_hash: &str) -> Result<bool, String> {
    let key = format!("email:{}", email_hash);
    kv_exists(&store_name("user-idx"), &key).await
}

/// Normalize an email address for cross-region lookup.
pub fn sanitize_email_for_lookup(email: &str) -> String {
    email.to_lowercase()
}

/// Shared secret for authenticating cross-region `/internal/*` HTTP requests.
pub fn internal_auth_secret() -> Option<String> {
    config_value("internal_auth_secret")
}

/// This instance's region identifier (e.g., "us", "eu"). Empty = single-region.
pub fn region_id() -> Option<String> {
    config_value("region_id")
}

/// Get the base URL for a remote region.
pub fn region_domain(region: &str) -> Option<String> {
    let json_str = config_value("region_domains")?;
    let map: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    map.get(region)?
        .as_str()
        .map(|s| s.trim_end_matches('/').to_string())
}

/// Get internal URLs for all regions.
pub fn region_internal_urls() -> Vec<(String, String)> {
    let json_str = match config_value("region_internal_urls") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&json_str).unwrap_or_default();
    map.into_iter().collect()
}

fn store_name(suffix: &str) -> String {
    suffix.to_string()
}

fn users_store() -> String {
    store_name("users")
}
fn user_idx_store() -> String {
    store_name("user-idx")
}
fn sessions_store() -> String {
    store_name("sessions")
}
fn clients_store() -> String {
    config_value("client_bucket").unwrap_or_else(|| store_name("clients"))
}
pub fn clients_store_name() -> String {
    clients_store()
}
fn tenants_store() -> String {
    config_value("tenant_bucket").unwrap_or_else(|| store_name("tenants"))
}
pub fn tenants_store_name() -> String {
    tenants_store()
}
fn memberships_store() -> String {
    store_name("memberships")
}
fn audit_store() -> String {
    store_name("audit")
}

// ── TTL constants (seconds) ─────────────────────────────────

const TTL_AUTH_CODE: u64 = 300; // 5 min
const TTL_AUTH_SESSION: u64 = 600; // 10 min
const TTL_REFRESH_TOKEN: u64 = 86400 * 30; // 30 days
const TTL_CONSUMED_MARKER: u64 = 86400 * 30; // 30 days
const TTL_REVOCATION_MARKER: u64 = 86400 * 30; // 30 days
const TTL_MFA_PENDING: u64 = 300; // 5 min
const TTL_ACCOUNT_SESSION: u64 = 1800; // 30 min
const TTL_PASSKEY_CHALLENGE: u64 = 300; // 5 min
const TTL_LOCKOUT: u64 = 3600; // 1 hour (generous buffer over default 15 min lock)
const TTL_INVITATION: u64 = 86400 * 7; // 7 days
const TTL_AUDIT: u64 = 86400 * 90; // 90 days

// ── lattice-db via wasmcloud:messaging (sync, host-managed NATS) ──

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

const LDB_TIMEOUT_MS: u32 = 5000;

/// Build a lattice-db NATS subject from the configured instance prefix.
/// Reads `ldb_instance` from the cached config (defaults to `"lid"`).
fn ldb_subject(op: &str) -> String {
    let instance = config_value("ldb_instance").unwrap_or_else(|| "lid".to_string());
    format!("{instance}.{op}")
}

/// Send a JSON request to lattice-db via the host's NATS connection.
/// Automatically injects `consistency.min_revision` for table-scoped reads
/// and extracts `session.revisions` from responses (lattice-db ≥ 1.6.0).
async fn ldb_request(
    subject: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    // Inject consistency context when the payload targets a specific table.
    let payload = if let Some(table) = payload.get("table").and_then(|t| t.as_str()) {
        let min_rev = SESSION_REVISIONS.with(|sr| sr.borrow().get(table).copied());
        if let Some(rev) = min_rev {
            let mut p = payload.clone();
            p.as_object_mut().unwrap().insert(
                "consistency".to_string(),
                serde_json::json!({ "min_revision": rev }),
            );
            p
        } else {
            payload.clone()
        }
    } else {
        payload.clone()
    };

    let body = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;
    let resp = crate::bindings::wasmcloud::messaging::consumer::request(
        subject.to_string(),
        body,
        LDB_TIMEOUT_MS,
    )
    .await?;
    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("parse response: {e}"))?;
    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }

    // Merge session revisions from the response (lattice-db 1.6.0+).
    if let Some(session) = val.get("session").and_then(|s| s.as_object())
        && let Some(revisions) = session.get("revisions").and_then(|r| r.as_object())
    {
        SESSION_REVISIONS.with(|sr| {
            let mut map = sr.borrow_mut();
            for (table, rev_val) in revisions {
                if let Some(rev) = rev_val.as_u64() {
                    let entry = map.entry(table.clone()).or_insert(0);
                    if rev > *entry {
                        *entry = rev;
                    }
                }
            }
        });
    }

    // Backward-compatible fallback: infer from single-table write responses.
    if let (Some(table), Some(revision)) = (
        payload.get("table").and_then(|t| t.as_str()),
        val.get("revision").and_then(|v| v.as_u64()),
    ) {
        SESSION_REVISIONS.with(|sr| {
            let mut map = sr.borrow_mut();
            let entry = map.entry(table.to_string()).or_insert(0);
            if revision > *entry {
                *entry = revision;
            }
        });
    }

    Ok(val)
}

/// Check if a lattice-db error indicates "not found".
fn is_not_found(e: &str) -> bool {
    e.contains("not found")
}

async fn kv_get<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<T>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let val = serde_json::from_slice(&bytes).map_err(|e| format!("deserialize: {e}"))?;
            Ok(Some(val))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

async fn kv_get_raw(store_name: &str, key: &str) -> Result<Option<Vec<u8>>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            Ok(Some(bytes))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

/// Get a value along with its revision (for CAS).
async fn kv_get_revision<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<(T, u64)>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let val = serde_json::from_slice(&bytes).map_err(|e| format!("deserialize: {e}"))?;
            let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(Some((val, revision)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub async fn kv_set<T: Serialize>(store_name: &str, key: &str, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    ldb_request(&ldb_subject("put"), &payload).await?;
    Ok(())
}

async fn kv_set_raw(store_name: &str, key: &str, value: &[u8]) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    ldb_request(&ldb_subject("put"), &payload).await?;
    Ok(())
}

async fn kv_set_with_ttl(
    store_name: &str,
    key: &str,
    value: &[u8],
    ttl_secs: u64,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request(&ldb_subject("put"), &payload).await?;
    Ok(())
}

async fn kv_set_ttl<T: Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    ttl_secs: u64,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request(&ldb_subject("put"), &payload).await?;
    Ok(())
}

async fn kv_set_raw_ttl(
    store_name: &str,
    key: &str,
    value: &[u8],
    ttl_secs: u64,
) -> Result<(), String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "ttl_seconds": ttl_secs });
    ldb_request(&ldb_subject("put"), &payload).await?;
    Ok(())
}

pub async fn kv_delete(store_name: &str, key: &str) -> Result<(), String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    ldb_request(&ldb_subject("delete"), &payload).await?;
    Ok(())
}

// ── Encrypted KV helpers (envelope encryption via crypto-vault) ──────────────

/// First envelope byte values ≥ this constant are not JSON (which starts with
/// `{` = 0x7B or `[` = 0x5B).  Anything ≤ this is treated as legacy plaintext
/// to support zero-downtime migration from unencrypted to encrypted records.
const ENVELOPE_VERSION_MAX_MIGRATION: u8 = 100;

/// Write a value serialised as JSON and then envelope-encrypted.
/// `context` is the AAD/binding string: convention is "{bucket}:{key-prefix}".
#[allow(dead_code)]
pub(crate) async fn kv_set_encrypted<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    context: &str,
) -> Result<(), String> {
    let json_bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let envelope = crate::service_client::vault_encrypt(context, &json_bytes).await?;
    kv_set_raw(store_name, key, &envelope).await
}

/// Read an envelope-encrypted value, deserialise the plaintext as JSON.
#[allow(dead_code)]
pub(crate) async fn kv_get_encrypted<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
    context: &str,
) -> Result<Option<T>, String> {
    let Some(envelope) = kv_get_raw(store_name, key).await? else {
        return Ok(None);
    };
    let plaintext = crate::service_client::vault_decrypt(context, &envelope).await?;
    let val = serde_json::from_slice(&plaintext).map_err(|e| format!("deserialize: {e}"))?;
    Ok(Some(val))
}

/// Read a value that may be stored either as legacy plaintext JSON or as an
/// encrypted envelope.  Supports zero-downtime migration: plaintext records are
/// returned as-is; encrypted records are decrypted transparently.
///
/// Detection heuristic: if the first byte is `{` (0x7B) or `[` (0x5B) or any
/// printable ASCII (≥ 0x20) the record is treated as legacy plaintext JSON.
/// Envelope records always start with a version byte < `ENVELOPE_VERSION_MAX_MIGRATION`.
#[allow(dead_code)]
pub(crate) async fn kv_get_maybe_encrypted<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
    context: &str,
) -> Result<Option<T>, String> {
    let Some(raw) = kv_get_raw(store_name, key).await? else {
        return Ok(None);
    };
    let first = raw.first().copied().unwrap_or(0);
    let is_plaintext = first >= ENVELOPE_VERSION_MAX_MIGRATION;
    let plaintext_bytes: Vec<u8> = if is_plaintext {
        raw
    } else {
        crate::service_client::vault_decrypt(context, &raw).await?
    };
    let val = serde_json::from_slice(&plaintext_bytes).map_err(|e| format!("deserialize: {e}"))?;
    Ok(Some(val))
}

async fn kv_list_keys(store_name: &str) -> Result<Vec<String>, String> {
    let mut all_keys = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut payload = serde_json::json!({ "table": store_name });
        if let Some(ref c) = cursor {
            payload["cursor"] = serde_json::Value::String(c.clone());
        }
        let resp = ldb_request(&ldb_subject("keys"), &payload).await?;
        if let Some(keys) = resp.get("keys").and_then(|v| v.as_array()) {
            for k in keys {
                if let Some(s) = k.as_str() {
                    all_keys.push(s.to_string());
                }
            }
        }
        match resp.get("next_cursor").and_then(|v| v.as_str()) {
            Some(c) if !c.is_empty() => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    Ok(all_keys)
}

async fn kv_exists(store_name: &str, key: &str) -> Result<bool, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    let resp = ldb_request(&ldb_subject("exists"), &payload).await?;
    Ok(resp
        .get("exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Atomically swap a value if the revision matches.
async fn kv_cas_swap<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    revision: u64,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "revision": revision });
    let resp = ldb_request(&ldb_subject("cas"), &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically swap a value if the revision matches, with TTL.
async fn kv_cas_swap_ttl<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    revision: u64,
    ttl_secs: u64,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64, "revision": revision, "ttl_seconds": ttl_secs });
    let resp = ldb_request(&ldb_subject("cas"), &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically create a key only if it doesn't exist.
async fn kv_cas_create<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
) -> Result<u64, String> {
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = B64.encode(&bytes);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    let resp = ldb_request(&ldb_subject("create"), &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically create a raw key only if it doesn't exist.
async fn kv_cas_create_raw(store_name: &str, key: &str, value: &[u8]) -> Result<u64, String> {
    let value_b64 = B64.encode(value);
    let payload = serde_json::json!({ "table": store_name, "key": key, "value": value_b64 });
    let resp = ldb_request(&ldb_subject("create"), &payload).await?;
    Ok(resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Atomically delete a key only if the revision matches.
async fn kv_cas_delete(store_name: &str, key: &str, revision: u64) -> Result<(), String> {
    let payload = serde_json::json!({ "table": store_name, "key": key, "revision": revision });
    ldb_request(&ldb_subject("cas_delete"), &payload).await?;
    Ok(())
}

/// Get a raw value with its revision for CAS operations.
#[allow(dead_code)]
async fn kv_get_raw_revision(
    store_name: &str,
    key: &str,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    let payload = serde_json::json!({ "table": store_name, "key": key });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(Some((bytes, revision)))
        }
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(format!("get {key}: {e}")),
    }
}

pub async fn kv_cache_get<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    match kv_get_raw(&store_name("cache"), key).await? {
        Some(bytes) => {
            let cached: CacheEntry<T> =
                serde_json::from_slice(&bytes).map_err(|e| format!("cache deserialize: {e}"))?;
            if cached.expires_at > unix_now() {
                Ok(Some(cached.value))
            } else {
                let _ = kv_delete(&store_name("cache"), key).await;
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

pub async fn kv_cache_set<T: Serialize>(key: &str, value: &T, ttl_secs: u64) -> Result<(), String> {
    let entry = CacheEntry {
        value,
        expires_at: unix_now() + ttl_secs,
    };
    let bytes = serde_json::to_vec(&entry).map_err(|e| format!("cache serialize: {e}"))?;
    kv_set_with_ttl(&store_name("cache"), key, &bytes, ttl_secs).await
}

// ── User operations ─────────────────────────────────────────

pub async fn create_user(user: &User) -> Result<(), String> {
    // Store user record first (random UUID key, no conflict risk)
    let mut u = user.clone();
    if u.status == "active" && !u.superadmin && crate::require_email_verification() {
        u.status = "pending".to_string();
    }
    kv_set(&users_store(), &format!("user:{}", u.id), &u).await?;

    // Atomically create email → user_id index (fails if email already taken)
    let email_key = format!("email:{}", u.email.to_lowercase());
    match kv_cas_create_raw(&user_idx_store(), &email_key, u.id.as_bytes()).await {
        Ok(_) => Ok(()),
        Err(e) if e.contains("already exists") => {
            // Roll back user record
            let _ = kv_delete(&users_store(), &format!("user:{}", u.id)).await;
            Err("email already registered".into())
        }
        Err(e) => Err(e),
    }
}

pub async fn get_user(id: &str) -> Result<Option<User>, String> {
    kv_get(&users_store(), &format!("user:{id}")).await
}

/// Get a user with its KV revision for CAS updates.
pub async fn get_user_cas(id: &str) -> Result<Option<(User, u64)>, String> {
    kv_get_revision(&users_store(), &format!("user:{id}")).await
}

/// Update a user with CAS — fails with "revision mismatch" if another
/// writer changed the record since it was read.
pub async fn update_user_cas(user: &User, revision: u64) -> Result<u64, String> {
    kv_cas_swap(&users_store(), &format!("user:{}", user.id), user, revision).await
}

/// Read-modify-write a user with automatic CAS retry.
/// The `modify` closure receives a mutable user and returns Ok(true) to
/// commit the change, Ok(false) to skip (no-op), or Err to abort.
pub async fn update_user_rmw<F>(user_id: &str, mut modify: F) -> Result<(), String>
where
    F: FnMut(&mut User) -> Result<bool, String>,
{
    const MAX_RETRIES: usize = 5;
    for attempt in 0..MAX_RETRIES {
        let (mut user, revision) = get_user_cas(user_id).await?.ok_or("user not found")?;
        if !modify(&mut user)? {
            return Ok(()); // no change needed
        }
        match update_user_cas(&user, revision).await {
            Ok(_) => return Ok(()),
            Err(e) if e.contains("revision mismatch") && attempt < MAX_RETRIES - 1 => {
                continue; // retry
            }
            Err(e) => return Err(e),
        }
    }
    Err("update_user_rmw: too many retries".into())
}

/// Legacy non-CAS update — only use for fields where races are harmless.
#[allow(dead_code)]
pub async fn update_user(user: &User) -> Result<(), String> {
    kv_set(&users_store(), &format!("user:{}", user.id), user).await
}

/// Permanently delete a user and all associated first-party data (GDPR Art. 17).
/// Caller is responsible for revoking active sessions before calling this.
pub async fn delete_user(user_id: &str) -> Result<(), String> {
    // Fetch user to get email for index removal
    let user = match kv_get::<User>(&users_store(), &format!("user:{user_id}")).await? {
        Some(u) => u,
        None => return Ok(()), // already gone
    };

    // Remove email → user_id index
    let _ = kv_delete(
        &user_idx_store(),
        &format!("email:{}", user.email.to_lowercase()),
    )
    .await;

    // Remove user record
    kv_delete(&users_store(), &format!("user:{user_id}")).await?;

    // Remove all tenant memberships for this user
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name).await.unwrap_or_default();
    for key in keys {
        // Forward keys: tenant:{tid}:user:{uid}
        // Reverse keys: user:{uid}:tenant:{tid}
        if key.contains(&format!(":user:{user_id}")) || key.starts_with(&format!("user:{user_id}:"))
        {
            let _ = kv_delete(&store_name, &key).await;
        }
    }

    Ok(())
}

pub async fn get_superadmin_flag() -> Result<Option<bool>, String> {
    kv_get(&sessions_store(), "meta:has_superadmin").await
}

/// Atomically set the superadmin flag — only the first writer wins.
pub async fn set_superadmin_flag(val: bool) -> Result<(), String> {
    match kv_cas_create(&sessions_store(), "meta:has_superadmin", &val).await {
        Ok(_) => Ok(()),
        Err(e) if e.contains("already exists") => Ok(()), // another replica set it first
        Err(e) => Err(e),
    }
}

pub async fn list_users() -> Result<Vec<User>, String> {
    let store_name = users_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut users = Vec::new();
    for key in keys {
        if key.starts_with("user:")
            && let Some(u) = kv_get::<User>(&store_name, &key).await?
        {
            users.push(u);
        }
    }
    Ok(users)
}

pub async fn get_user_by_email(email: &str) -> Result<Option<User>, String> {
    let email_lower = email.to_lowercase();

    // Check with region-authority where this user lives.
    // If authority says user is remote, return None so the caller can
    // attempt a cross-region redirect.  Otherwise (local or unknown),
    // fall through to the local KV lookup.
    let lookup = crate::bindings::taika3d::lid::authority::lookup(&email_lower)
        .map_err(|e| format!("authority lookup failed: {}", e))?;

    match lookup.region.as_deref() {
        Some(r) if r != "local" && lookup.found => {
            // User is known to be in a remote region
            Ok(None)
        }
        _ => {
            // User is local, or authority doesn't know — check local KV
            let email_key = format!("email:{}", email_lower);
            match kv_get_raw(&user_idx_store(), &email_key).await? {
                Some(bytes) => {
                    let user_id = String::from_utf8_lossy(&bytes);
                    get_user(&user_id).await
                }
                None => Ok(None),
            }
        }
    }
}

// ── Auth session operations ─────────────────────────────────

pub async fn save_auth_session(session_id: &str, session: &AuthSession) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("session:{session_id}"),
        session,
        TTL_AUTH_SESSION,
    )
    .await
}

pub async fn get_auth_session(session_id: &str) -> Result<Option<AuthSession>, String> {
    kv_get(&sessions_store(), &format!("session:{session_id}")).await
}

pub async fn delete_auth_session(session_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("session:{session_id}")).await
}

// ── Google OAuth CSRF state ─────────────────────────────────

pub async fn save_google_csrf(csrf_token: &str, session_id: &str) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("gcsrf:{csrf_token}"),
        &session_id.to_string(),
        600,
    )
    .await
}

pub async fn consume_google_csrf(csrf_token: &str) -> Result<Option<String>, String> {
    let key = format!("gcsrf:{csrf_token}");
    // Atomically read with revision and delete in one CAS operation
    match kv_get_revision::<String>(&sessions_store(), &key).await? {
        Some((session_id, revision)) => {
            match kv_cas_delete(&sessions_store(), &key, revision).await {
                Ok(()) => Ok(Some(session_id)),
                Err(e) if e.contains("revision mismatch") => {
                    // Another replica already consumed it
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
        None => Ok(None),
    }
}

// ── Auth code operations ────────────────────────────────────

pub async fn save_auth_code(code: &str, auth_code: &AuthCode) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("code:{code}"),
        auth_code,
        TTL_AUTH_CODE,
    )
    .await
}

#[allow(dead_code)]
pub async fn get_auth_code(code: &str) -> Result<Option<AuthCode>, String> {
    kv_get(&sessions_store(), &format!("code:{code}")).await
}

/// Get auth code with revision for CAS consumption.
pub async fn get_auth_code_cas(code: &str) -> Result<Option<(AuthCode, u64)>, String> {
    kv_get_revision(&sessions_store(), &format!("code:{code}")).await
}

/// Atomically consume an auth code (CAS swap to consumed marker).
pub async fn consume_auth_code(code: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap_ttl(
        &sessions_store(),
        &format!("code:{code}"),
        &consumed,
        revision,
        TTL_AUTH_CODE,
    )
    .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn delete_auth_code(code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("code:{code}")).await
}

// ── Refresh token operations ────────────────────────────────

#[allow(dead_code)]
pub async fn save_refresh_token(token_hash: &str, entry: &RefreshEntry) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("refresh:{token_hash}"),
        entry,
        TTL_REFRESH_TOKEN,
    )
    .await?;
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        &[1],
        TTL_REFRESH_TOKEN,
    )
    .await
}

pub async fn get_refresh_token(token_hash: &str) -> Result<Option<RefreshEntry>, String> {
    kv_get(&sessions_store(), &format!("refresh:{token_hash}")).await
}

/// Get refresh token with revision for CAS consumption.
pub async fn get_refresh_token_cas(
    token_hash: &str,
) -> Result<Option<(RefreshEntry, u64)>, String> {
    match kv_get_revision(&sessions_store(), &format!("refresh:{token_hash}")).await {
        Ok(v) => Ok(v),
        Err(e) if e.starts_with("deserialize:") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically consume a refresh token (CAS swap to consumed marker).
pub async fn consume_refresh_token(token_hash: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap_ttl(
        &sessions_store(),
        &format!("refresh:{token_hash}"),
        &consumed,
        revision,
        TTL_CONSUMED_MARKER,
    )
    .await?;
    Ok(())
}

/// Mark a consumed refresh token hash so replay can be detected.
pub async fn mark_refresh_consumed(token_hash: &str, user_id: &str) -> Result<(), String> {
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("consumed:{token_hash}"),
        user_id.as_bytes(),
        TTL_CONSUMED_MARKER,
    )
    .await
}

/// Check if a refresh token hash was previously consumed (replay detection).
pub async fn get_consumed_refresh(token_hash: &str) -> Result<Option<String>, String> {
    match kv_get_raw(&sessions_store(), &format!("consumed:{token_hash}")).await? {
        Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
        None => Ok(None),
    }
}

pub async fn delete_refresh_token(token_hash: &str) -> Result<(), String> {
    if let Ok(Some(entry)) = get_refresh_token(token_hash).await {
        let _ = kv_delete(
            &sessions_store(),
            &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        )
        .await;
    }
    kv_delete(&sessions_store(), &format!("refresh:{token_hash}")).await
}

/// Revoke all sessions for a user.
pub async fn revoke_user_sessions(user_id: &str) -> Result<(), String> {
    let key = format!("revoked:user:{user_id}");
    kv_set_raw_ttl(
        &sessions_store(),
        &key,
        &unix_now().to_be_bytes(),
        TTL_REVOCATION_MARKER,
    )
    .await
}

/// Check if a user's sessions have been revoked.
pub async fn is_user_revoked(user_id: &str, iat: u64) -> Result<bool, String> {
    let key = format!("revoked:user:{user_id}");
    match kv_get_raw(&sessions_store(), &key).await? {
        Some(bytes) if bytes.len() == 8 => {
            let revoked_at = u64::from_be_bytes(bytes.try_into().unwrap());
            Ok(iat < revoked_at)
        }
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

/// Delete all refresh tokens for a given user.
pub async fn delete_user_refresh_tokens(user_id: &str) -> Result<u32, String> {
    let store_name = sessions_store();
    let prefix = format!("refresh_idx:{user_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut count = 0u32;
    for key in keys {
        if key.starts_with(&prefix) {
            let token_hash = key.strip_prefix(&prefix).unwrap_or("");
            if !token_hash.is_empty() {
                let _ = kv_delete(&store_name, &format!("refresh:{token_hash}")).await;
                let _ = kv_delete(&store_name, &key).await;
                count += 1;
            }
        }
    }
    revoke_user_sessions(user_id).await?;
    Ok(count)
}

// ── OIDC client operations ──────────────────────────────────

pub async fn get_client(client_id: &str) -> Result<Option<OidcClient>, String> {
    kv_get(&clients_store(), &format!("client:{client_id}")).await
}

pub async fn save_client(client: &OidcClient) -> Result<(), String> {
    kv_set(
        &clients_store(),
        &format!("client:{}", client.client_id),
        client,
    )
    .await
}

pub async fn list_clients() -> Result<Vec<OidcClient>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut clients = Vec::new();
    for key in keys {
        if key.starts_with("client:")
            && let Some(c) = kv_get::<OidcClient>(&store_name, &key).await?
        {
            clients.push(c);
        }
    }
    Ok(clients)
}

// ── Tenant operations ───────────────────────────────────────

pub async fn create_tenant(tenant: &Tenant) -> Result<(), String> {
    let key = format!("tenant:{}", tenant.id);
    let store_name = tenants_store();
    if kv_get::<Tenant>(&store_name, &key).await?.is_some() {
        return Err("tenant already exists".into());
    }
    kv_set(&store_name, &key, tenant).await
}

pub async fn get_tenant(id: &str) -> Result<Option<Tenant>, String> {
    kv_get(&tenants_store(), &format!("tenant:{id}")).await
}

pub async fn delete_tenant(id: &str) -> Result<(), String> {
    kv_delete(&tenants_store(), &format!("tenant:{id}")).await
}

pub async fn list_tenants() -> Result<Vec<Tenant>, String> {
    let store_name = tenants_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut tenants = Vec::new();
    for key in keys {
        if key.starts_with("tenant:")
            && let Some(t) = kv_get::<Tenant>(&store_name, &key).await?
        {
            tenants.push(t);
        }
    }
    Ok(tenants)
}

// ── Membership operations ───────────────────────────────────

pub async fn add_membership(m: &Membership) -> Result<(), String> {
    let store_name = memberships_store();
    let fwd = format!("tenant:{}:user:{}", m.tenant_id, m.user_id);
    kv_set(&store_name, &fwd, m).await?;
    let rev = format!("user:{}:tenant:{}", m.user_id, m.tenant_id);
    kv_set_raw(&store_name, &rev, m.role.as_bytes()).await
}

pub async fn get_membership(tenant_id: &str, user_id: &str) -> Result<Option<Membership>, String> {
    kv_get(
        &memberships_store(),
        &format!("tenant:{tenant_id}:user:{user_id}"),
    )
    .await
}

pub async fn remove_membership(tenant_id: &str, user_id: &str) -> Result<(), String> {
    let store_name = memberships_store();
    kv_delete(&store_name, &format!("tenant:{tenant_id}:user:{user_id}")).await?;
    kv_delete(&store_name, &format!("user:{user_id}:tenant:{tenant_id}")).await
}

pub async fn list_tenant_members(tenant_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("tenant:{tenant_id}:user:");
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut members = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(m) = kv_get::<Membership>(&store_name, &key).await?
        {
            members.push(m);
        }
    }
    Ok(members)
}

pub async fn list_user_tenants(user_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("user:{user_id}:tenant:");
    let keys = kv_list_keys(&memberships_store()).await?;
    let mut memberships = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            let tenant_id = key.strip_prefix(&prefix).unwrap_or("");
            if let Some(m) = get_membership(tenant_id, user_id).await? {
                memberships.push(m);
            }
        }
    }
    Ok(memberships)
}

// ── Invitation operations ───────────────────────────────────

pub async fn save_invitation(inv: &Invitation) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("invite:{}", inv.token),
        inv,
        TTL_INVITATION,
    )
    .await
}

pub async fn get_invitation(token: &str) -> Result<Option<Invitation>, String> {
    kv_get(&sessions_store(), &format!("invite:{token}")).await
}

pub async fn delete_invitation(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("invite:{token}")).await
}

// ── Account lockout operations ──────────────────────────────

pub async fn is_account_locked(user_id: &str) -> Result<bool, String> {
    match kv_get::<LoginAttempts>(&sessions_store(), &format!("lockout:{user_id}")).await? {
        Some(a) if a.locked_until > unix_now() => Ok(true),
        _ => Ok(false),
    }
}

/// Record a failed login. Returns true if the account is now locked.
pub async fn record_failed_login(user_id: &str) -> Result<bool, String> {
    let store_name = sessions_store();
    let key = format!("lockout:{user_id}");

    const MAX_RETRIES: usize = 5;
    for attempt in 0..MAX_RETRIES {
        let (mut attempts, revision) =
            match kv_get_revision::<LoginAttempts>(&store_name, &key).await? {
                Some((a, r)) => (a, r),
                None => (
                    LoginAttempts {
                        failures: 0,
                        locked_until: 0,
                    },
                    0,
                ),
            };

        if attempts.locked_until > 0 && attempts.locked_until <= unix_now() {
            attempts.failures = 0;
            attempts.locked_until = 0;
        }

        attempts.failures += 1;
        let locked = if attempts.failures >= max_login_failures() {
            attempts.locked_until = unix_now() + lockout_duration();
            true
        } else {
            false
        };

        let result = if revision == 0 {
            // First failure — atomic create
            let bytes = serde_json::to_vec(&attempts).map_err(|e| format!("serialize: {e}"))?;
            let value_b64 = B64.encode(&bytes);
            let payload = serde_json::json!({
                "table": store_name, "key": key, "value": value_b64,
                "ttl_seconds": TTL_LOCKOUT,
            });
            ldb_request(&ldb_subject("create"), &payload).await
        } else {
            // Existing counter — CAS update
            kv_cas_swap_ttl(&store_name, &key, &attempts, revision, TTL_LOCKOUT)
                .await
                .map(|_| serde_json::Value::Null)
        };

        match result {
            Ok(_) => return Ok(locked),
            Err(e)
                if (e.contains("revision mismatch") || e.contains("already exists"))
                    && attempt < MAX_RETRIES - 1 =>
            {
                continue; // retry
            }
            Err(e) => return Err(format!("record_failed_login: {e}")),
        }
    }
    Err("record_failed_login: too many retries".into())
}

pub async fn clear_login_attempts(user_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("lockout:{user_id}")).await
}

// ── Audit log operations ────────────────────────────────────

pub async fn log_audit(
    event_type: &str,
    actor_id: &str,
    target_id: &str,
    details: &str,
) -> Result<(), String> {
    let now = unix_now();
    let rand = random_hex(4);
    let key = format!("audit:{now}:{rand}");
    let event = AuditEvent {
        event_type: event_type.to_string(),
        actor_id: actor_id.to_string(),
        target_id: target_id.to_string(),
        details: details.to_string(),
        timestamp: now,
    };
    kv_set_ttl(&audit_store(), &key, &event, TTL_AUDIT).await
}

pub async fn list_audit_events(
    actor_id: Option<&str>,
    target_id: Option<&str>,
    event_type: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
) -> Result<Vec<AuditEvent>, String> {
    let store_name = audit_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut events = Vec::new();

    for key in keys {
        if key.starts_with("audit:")
            && let Some(event) = kv_get::<AuditEvent>(&store_name, &key).await?
        {
            if let Some(actor) = actor_id
                && event.actor_id != actor
            {
                continue;
            }
            if let Some(target) = target_id
                && event.target_id != target
            {
                continue;
            }
            if let Some(kind) = event_type
                && event.event_type != kind
            {
                continue;
            }
            if let Some(lower) = since
                && event.timestamp < lower
            {
                continue;
            }
            if let Some(upper) = until
                && event.timestamp > upper
            {
                continue;
            }
            events.push(event);
        }
    }

    events.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.event_type.cmp(&right.event_type))
    });
    if events.len() > limit {
        events.truncate(limit);
    }

    Ok(events)
}

/// Ensure a default OIDC client exists for development/testing.
pub async fn ensure_default_client() -> Result<(), String> {
    let default_id = "default";
    if get_client(default_id).await?.is_some() {
        return Ok(());
    }
    let client = OidcClient {
        client_id: default_id.to_string(),
        client_secret: None,
        redirect_uris: vec![
            "http://localhost:8090/callback".to_string(),
            "http://localhost:3000/callback".to_string(),
        ],
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        name: "Default Dev Client".to_string(),
        theme: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        id_token_signed_response_alg: None,
        first_party: true,
    };
    kv_set(&clients_store(), &format!("client:{default_id}"), &client).await
}

/// Register the Lattice-ID Admin UI OIDC client.
pub async fn ensure_admin_client(issuer: &str, dev_mode: bool) -> Result<(), String> {
    let admin_id = "lid-admin";
    // Always rewrite the admin client so redirect URIs stay in sync with the
    // configured issuer (e.g. after switching from :8000 to port 80).
    let existing_secret = get_client(admin_id).await?.and_then(|c| c.client_secret);
    let mut redirect_uris = vec![
        format!("{issuer}/"),
        format!("{issuer}/callback"),
        format!("{issuer}/admin"),
        format!("{issuer}/admin/"),
    ];

    if dev_mode {
        for port in &["8000", "8090", "8091"] {
            redirect_uris.push(format!("http://localhost:{port}/"));
            redirect_uris.push(format!("http://localhost:{port}/callback"));
        }
        // Also register portless localhost variants for port-80 local dev
        redirect_uris.push("http://localhost/admin".to_string());
        redirect_uris.push("http://localhost/admin/".to_string());
        redirect_uris.push("http://localhost/".to_string());
        redirect_uris.push("http://localhost/callback".to_string());
    }
    let client = OidcClient {
        client_id: admin_id.to_string(),
        client_secret: existing_secret,
        redirect_uris,
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        name: "Lattice-ID Admin".to_string(),
        theme: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        id_token_signed_response_alg: None,
        first_party: true,
    };
    kv_set(&clients_store(), &format!("client:{admin_id}"), &client).await
}

// ── Identity provider operations ────────────────────────────

pub async fn save_identity_provider(idp: &IdentityProvider) -> Result<(), String> {
    kv_set(&clients_store(), &format!("idp:{}", idp.id), idp).await
}

pub async fn get_identity_provider(id: &str) -> Result<Option<IdentityProvider>, String> {
    kv_get(&clients_store(), &format!("idp:{id}")).await
}

pub async fn get_identity_provider_by_type(
    provider_type: &str,
) -> Result<Option<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    for key in keys {
        if key.starts_with("idp:")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key).await?
            && idp.provider_type == provider_type
            && idp.enabled
        {
            return Ok(Some(idp));
        }
    }
    Ok(None)
}

pub async fn list_identity_providers() -> Result<Vec<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut providers = Vec::new();
    for key in keys {
        if key.starts_with("idp:")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key).await?
        {
            providers.push(idp);
        }
    }
    Ok(providers)
}

pub async fn delete_identity_provider(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("idp:{id}")).await
}

// ── Social identity operations ──────────────────────────────

pub async fn save_social_identity(si: &SocialIdentity) -> Result<(), String> {
    let key = format!("social:{}:{}", si.provider, si.provider_sub);
    kv_set(&user_idx_store(), &key, si).await
}

pub async fn get_social_identity(
    provider: &str,
    provider_sub: &str,
) -> Result<Option<SocialIdentity>, String> {
    kv_get(
        &user_idx_store(),
        &format!("social:{provider}:{provider_sub}"),
    )
    .await
}

// ── MFA pending session ─────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct MfaPending {
    pub user_id: String,
    pub session_id: String,
    #[serde(default)]
    pub primary_amr: Vec<String>,
    pub expires_at: u64,
    #[serde(default)]
    pub remote_ip: String,
}

pub async fn save_mfa_pending(mfa_token: &str, pending: &MfaPending) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("mfa:{mfa_token}"),
        pending,
        TTL_MFA_PENDING,
    )
    .await
}

pub async fn get_mfa_pending(mfa_token: &str) -> Result<Option<MfaPending>, String> {
    kv_get(&sessions_store(), &format!("mfa:{mfa_token}")).await
}

pub async fn delete_mfa_pending(mfa_token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("mfa:{mfa_token}")).await
}

// ── Passkey challenges ──────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub challenge: String,
    pub purpose: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub session_id: String,
    pub expires_at: u64,
}

pub async fn save_passkey_challenge(
    token: &str,
    challenge: &PasskeyChallenge,
) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("passkey:{token}"),
        challenge,
        TTL_PASSKEY_CHALLENGE,
    )
    .await
}

/// Atomically consume a passkey challenge — returns None if already consumed
/// by another replica.
pub async fn consume_passkey_challenge(token: &str) -> Result<Option<PasskeyChallenge>, String> {
    let key = format!("passkey:{token}");
    match kv_get_revision::<PasskeyChallenge>(&sessions_store(), &key).await? {
        Some((challenge, revision)) => {
            match kv_cas_delete(&sessions_store(), &key, revision).await {
                Ok(()) => Ok(Some(challenge)),
                Err(e) if e.contains("revision mismatch") => Ok(None),
                Err(e) => Err(e),
            }
        }
        None => Ok(None),
    }
}

pub async fn get_passkey_challenge(token: &str) -> Result<Option<PasskeyChallenge>, String> {
    kv_get(&sessions_store(), &format!("passkey:{token}")).await
}

pub async fn delete_passkey_challenge(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("passkey:{token}")).await
}

// ── Passkey credential index ────────────────────────────────

pub async fn index_passkey_credential(credential_id: &str, user_id: &str) -> Result<(), String> {
    kv_set_raw(
        &user_idx_store(),
        &format!("passkey:{credential_id}"),
        user_id.as_bytes(),
    )
    .await
}

pub async fn unindex_passkey_credential(credential_id: &str) -> Result<(), String> {
    kv_delete(&user_idx_store(), &format!("passkey:{credential_id}")).await
}

pub async fn get_user_by_passkey(credential_id: &str) -> Result<Option<User>, String> {
    match kv_get_raw(&user_idx_store(), &format!("passkey:{credential_id}")).await? {
        Some(bytes) => {
            let user_id = String::from_utf8_lossy(&bytes);
            get_user(&user_id).await
        }
        None => Ok(None),
    }
}

// ── Account sessions (cookie-based, for /account pages) ─────

#[derive(Serialize, Deserialize)]
pub struct AccountSession {
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// CSRF token embedded in every account management form.
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn save_account_session(token: &str, session: &AccountSession) -> Result<(), String> {
    kv_set_ttl(
        &sessions_store(),
        &format!("acct:{token}"),
        session,
        TTL_ACCOUNT_SESSION,
    )
    .await
}

pub async fn get_account_session(token: &str) -> Result<Option<AccountSession>, String> {
    kv_get(&sessions_store(), &format!("acct:{token}")).await
}

pub async fn delete_account_session(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("acct:{token}")).await
}

// ── Known IPs (suspicious login detection) ──────────────────

const MAX_KNOWN_IPS: usize = 20;

#[derive(Serialize, Deserialize)]
struct KnownIps {
    ips: Vec<String>,
}

pub async fn check_and_record_ip(user_id: &str, ip: &str) -> bool {
    if ip.is_empty() || ip == "unknown" {
        return false;
    }
    let key = format!("known_ips:{user_id}");
    let store = sessions_store();
    let mut entry: KnownIps = kv_get(&store, &key)
        .await
        .ok()
        .flatten()
        .unwrap_or(KnownIps { ips: Vec::new() });

    if entry.ips.iter().any(|existing| existing == ip) {
        return false;
    }

    entry.ips.push(ip.to_string());
    if entry.ips.len() > MAX_KNOWN_IPS {
        entry.ips.remove(0);
    }
    let _ = kv_set(&store, &key, &entry).await;
    true
}

// ── Hook operations ─────────────────────────────────────────

pub async fn save_hook(hook: &Hook) -> Result<(), String> {
    kv_set(&clients_store(), &format!("hook:{}", hook.id), hook).await
}

pub async fn get_hook(id: &str) -> Result<Option<Hook>, String> {
    kv_get(&clients_store(), &format!("hook:{id}")).await
}

pub async fn list_hooks() -> Result<Vec<Hook>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name).await?;
    let mut hooks = Vec::new();
    for key in keys {
        if key.starts_with("hook:")
            && let Some(hook) = kv_get::<Hook>(&store_name, &key).await?
        {
            hooks.push(hook);
        }
    }
    Ok(hooks)
}

pub async fn delete_hook(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("hook:{id}")).await
}

pub async fn save_hook_version(ver: &HookVersion) -> Result<(), String> {
    let key = format!("hookver:{}:{:06}", ver.hook_id, ver.version);
    kv_set(&audit_store(), &key, ver).await
}

pub async fn list_hook_versions(hook_id: &str) -> Result<Vec<HookVersion>, String> {
    let store_name = audit_store();
    let prefix = format!("hookver:{hook_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut versions = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(ver) = kv_get::<HookVersion>(&store_name, &key).await?
        {
            versions.push(ver);
        }
    }
    versions.sort_by_key(|v| v.version);
    Ok(versions)
}

// ── Runtime settings ────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
pub struct RuntimeSettings {
    #[serde(default)]
    pub allow_registration: bool,
}

const SETTINGS_KEY: &str = "settings:global";

pub async fn get_runtime_settings() -> RuntimeSettings {
    kv_get::<RuntimeSettings>(&clients_store(), SETTINGS_KEY)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub async fn save_runtime_settings(settings: &RuntimeSettings) -> Result<(), String> {
    kv_set(&clients_store(), SETTINGS_KEY, settings).await
}

// ── Device Authorization Grant (RFC 8628) ───────────────────

const TTL_DEVICE_CODE: u64 = 300; // 5 minutes

pub async fn save_device_code(dc: &DeviceCode) -> Result<(), String> {
    // Indexed by both device_code (for polling) and user_code (for user entry).
    kv_set_ttl(
        &sessions_store(),
        &format!("device:{}", dc.device_code),
        dc,
        TTL_DEVICE_CODE,
    )
    .await?;
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("device_user_code:{}", dc.user_code.to_uppercase()),
        dc.device_code.as_bytes(),
        TTL_DEVICE_CODE,
    )
    .await
}

pub async fn get_device_code(device_code: &str) -> Result<Option<DeviceCode>, String> {
    kv_get(&sessions_store(), &format!("device:{device_code}")).await
}

/// Look up a device code by its short user_code.  Returns the DeviceCode if found.
pub async fn get_device_code_by_user_code(user_code: &str) -> Result<Option<DeviceCode>, String> {
    let key = format!("device_user_code:{}", user_code.to_uppercase());
    let Some(device_code_bytes) = kv_get_raw(&sessions_store(), &key).await? else {
        return Ok(None);
    };
    let device_code = String::from_utf8(device_code_bytes)
        .map_err(|_| "invalid device code bytes".to_string())?;
    kv_get(&sessions_store(), &format!("device:{device_code}")).await
}

pub async fn update_device_code_status(
    device_code: &str,
    status: &str,
    user_id: Option<&str>,
) -> Result<(), String> {
    if let Some(mut dc) = get_device_code(device_code).await? {
        dc.status = status.to_string();
        dc.user_id = user_id.map(String::from);
        let remaining_ttl = dc.expires_at.saturating_sub(unix_now());
        kv_set_ttl(
            &sessions_store(),
            &format!("device:{device_code}"),
            &dc,
            remaining_ttl.max(1),
        )
        .await?;
    }
    Ok(())
}

pub async fn delete_device_code(device_code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("device:{device_code}")).await
}

// ── Generic OIDC social login CSRF ──────────────────────────

/// Save a CSRF token → session_id mapping for generic social login flows.
pub async fn save_social_csrf(csrf_token: &str, session_id: &str) -> Result<(), String> {
    kv_set_raw_ttl(
        &sessions_store(),
        &format!("social_csrf:{csrf_token}"),
        session_id.as_bytes(),
        600,
    )
    .await
}

/// Consume and return the session_id for a generic social login CSRF token.
pub async fn consume_social_csrf(csrf_token: &str) -> Result<Option<String>, String> {
    let key = format!("social_csrf:{csrf_token}");
    match kv_get_raw(&sessions_store(), &key).await? {
        Some(bytes) => {
            let _ = kv_delete(&sessions_store(), &key).await;
            Ok(Some(
                String::from_utf8(bytes).map_err(|_| "invalid csrf bytes".to_string())?,
            ))
        }
        None => Ok(None),
    }
}

/// Return the unique client_ids that have active refresh tokens for a user.
/// Used to determine which clients to notify for backchannel logout.
pub async fn list_user_client_ids(user_id: &str) -> Result<Vec<String>, String> {
    let store_name = sessions_store();
    let prefix = format!("refresh_idx:{user_id}:");
    let keys = kv_list_keys(&store_name).await?;
    let mut client_ids = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            let token_hash = key.strip_prefix(&prefix).unwrap_or("");
            if !token_hash.is_empty()
                && let Ok(Some(entry)) =
                    kv_get::<RefreshEntry>(&store_name, &format!("refresh:{token_hash}")).await
                && !client_ids.contains(&entry.client_id)
            {
                client_ids.push(entry.client_id);
            }
        }
    }
    Ok(client_ids)
}
