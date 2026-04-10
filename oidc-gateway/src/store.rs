use crate::bindings::taika3d::lid::keyvalue_nats_cas as kv;
use crate::bindings::taika3d::lid::keyvalue_in_memory as cache_kv;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const SIGNING_KEYS_KEY: &str = "signing_keys";

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

/// External identity provider configuration (Google, GitHub, etc.)
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityProvider {
    pub id: String,
    pub provider_type: String, // "google", "github", etc.
    pub client_id: String,
    pub client_secret: String,
    pub enabled: bool,
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

fn default_version() -> u32 { 1 }

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

fn config_value(key: &str) -> Option<String> {
    crate::bindings::wasi::config::store::get(key)
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

// Component instances are fresh per request — no caching possible.
fn store_prefix() -> String {
    config_value("kv_prefix").unwrap_or_else(|| "lid".to_string())
}

/// Check if an email hash exists in this region's user-idx store.
/// Used by the /internal/lookup endpoint for cross-region queries.
pub fn email_hash_exists(email_hash: &str) -> Result<bool, String> {
    let store_name = store_name("user-idx");
    let key = sanitize_key(&format!("email:{}", email_hash));
    let store = kv::open(&store_name).map_err(|e| format!("open idx: {e:?}"))?;
    store.exists(&key).map_err(|e| format!("exists: {e:?}"))
}

pub fn core_service_auth_key() -> Option<String> {
    config_value("core_service_auth_key")
}

/// Shared secret for authenticating cross-region `/internal/*` HTTP requests.
/// Config key: `internal_auth_secret`.
pub fn internal_auth_secret() -> Option<String> {
    config_value("internal_auth_secret")
}

/// This instance's region identifier (e.g., "us", "eu"). Empty = single-region.
pub fn region_id() -> Option<String> {
    config_value("region_id")
}

/// Get the base URL for a remote region (e.g., "https://eu.auth.example.com").
/// Config key: `region_domains` — JSON object: `{"eu": "https://eu.auth.example.com", "us": "..."}`.
pub fn region_domain(region: &str) -> Option<String> {
    let json_str = config_value("region_domains")?;
    let map: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    map.get(region)?.as_str().map(|s| s.trim_end_matches('/').to_string())
}

/// Get internal (pod-reachable) URLs for all regions.
/// Config key: `region_internal_urls` — JSON object: `{"eu": "http://10.0.0.1:30950", ...}`.
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
    format!("{}-{suffix}", store_prefix())
}

fn users_store() -> String { store_name("users") }
fn user_idx_store() -> String { store_name("user-idx") }
fn sessions_store() -> String { store_name("sessions") }
fn clients_store() -> String { store_name("clients") }
fn keys_store() -> String {
    config_value("keys_bucket").unwrap_or_else(|| store_name("keys"))
}
fn tenants_store() -> String {
    config_value("tenant_bucket").unwrap_or_else(|| store_name("tenants"))
}
fn memberships_store() -> String { store_name("memberships") }
fn audit_store() -> String { store_name("audit") }
fn cache_store() -> String { "lid-cache".to_string() }

/// Sanitize a key for NATS JetStream KV compatibility.
/// NATS KV keys only allow: A-Z, a-z, 0-9, '-', '_', '/', '=', '.' (middle only).
/// File-backed KV (wash dev) interprets '/' as directory separator, so we avoid it.
/// We replace ':' with '--' and '@' with '_at_'.
fn sanitize_key(key: &str) -> String {
    key.replace(':', "--").replace('@', "_at_")
}

/// Sanitize an email for cross-region lookup (same transform as internal KV keys).
pub fn sanitize_email_for_lookup(email: &str) -> String {
    sanitize_key(email)
}

fn kv_get<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<T>, String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let safe_key = sanitize_key(key);
    match store.get(&safe_key).map_err(|e| format!("get {key}: {e:?}"))? {
        Some(entry) => {
            let val = serde_json::from_slice(&entry.value).map_err(|e| format!("deserialize: {e}"))?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

fn kv_set<T: Serialize>(store_name: &str, key: &str, value: &T) -> Result<(), String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let safe_key = sanitize_key(key);
    store
        .set(&safe_key, &bytes)
        .map_err(|e| format!("set {key}: {e:?}"))?;
    Ok(())
}

fn kv_set_raw(store_name: &str, key: &str, value: &[u8]) -> Result<(), String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let safe_key = sanitize_key(key);
    store
        .set(&safe_key, value)
        .map_err(|e| format!("set {key}: {e:?}"))?;
    Ok(())
}

fn kv_delete(store_name: &str, key: &str) -> Result<(), String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let safe_key = sanitize_key(key);
    store
        .delete(&safe_key)
        .map_err(|e| format!("delete {key}: {e:?}"))
}

fn kv_list_keys(store_name: &str) -> Result<Vec<String>, String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let mut all_keys = Vec::new();
    let mut cursor = None;
    loop {
        let resp = store
            .list_keys(cursor)
            .map_err(|e| format!("list keys: {e:?}"))?;
        all_keys.extend(resp.keys);
        match resp.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    Ok(all_keys)
}

pub fn kv_cache_get<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>, String> {
    let store = cache_kv::open(&cache_store()).map_err(|e| format!("open cache: {e:?}"))?;
    let safe_key = sanitize_key(key);
    match store.get(&safe_key).map_err(|e| format!("cache get {key}: {e:?}"))? {
        Some(entry) => {
            let cached: CacheEntry<T> = serde_json::from_slice(&entry.value)
                .map_err(|e| format!("cache deserialize: {e}"))?;
            if cached.expires_at > unix_now() {
                Ok(Some(cached.value))
            } else {
                let _ = store.delete(&safe_key);
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

pub fn kv_cache_set<T: Serialize>(key: &str, value: &T, ttl_secs: u64) -> Result<(), String> {
    let store = cache_kv::open(&cache_store()).map_err(|e| format!("open cache: {e:?}"))?;
    let entry = CacheEntry {
        value,
        expires_at: unix_now() + ttl_secs,
    };
    let bytes = serde_json::to_vec(&entry).map_err(|e| format!("cache serialize: {e}"))?;
    let safe_key = sanitize_key(key);
    store.set(&safe_key, &bytes).map_err(|e| format!("cache set {key}: {e:?}"))?;
    Ok(())
}

// ── CAS (compare-and-swap) helpers ──────────────────────────

/// Get a value and its revision (for subsequent CAS swap).
pub fn kv_get_revision<T: serde::de::DeserializeOwned>(
    store_name: &str,
    key: &str,
) -> Result<Option<(T, u64)>, String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let safe_key = sanitize_key(key);
    match store.get(&safe_key).map_err(|e| format!("get {key}: {e:?}"))? {
        Some(entry) => {
            let val =
                serde_json::from_slice(&entry.value).map_err(|e| format!("deserialize: {e}"))?;
            Ok(Some((val, entry.revision)))
        }
        None => Ok(None),
    }
}

/// Atomically swap a value if the revision matches.
/// Returns Err("revision-mismatch") on conflict.
pub fn kv_cas_swap<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
    revision: u64,
) -> Result<u64, String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let safe_key = sanitize_key(key);
    store.swap(&safe_key, &bytes, revision)
        .map_err(|e| format!("{e:?}"))
}

/// Atomically create a key only if it doesn't exist.
/// Returns Err containing "key-exists" on conflict.
#[allow(dead_code)]
pub fn kv_cas_create<T: serde::Serialize>(
    store_name: &str,
    key: &str,
    value: &T,
) -> Result<u64, String> {
    let store = kv::open(store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let bytes = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    let safe_key = sanitize_key(key);
    store.create(&safe_key, &bytes)
        .map_err(|e| format!("{e:?}"))
}

// ── User operations ─────────────────────────────────────────

pub fn create_user(user: &User) -> Result<(), String> {
    // Check email uniqueness via index
    if get_user_by_email(&user.email)?.is_some() {
        return Err("email already registered".into());
    }
    // Store user
    let mut u = user.clone();
    if u.status == "active" && !u.superadmin && crate::require_email_verification() {
        u.status = "pending".to_string();
    }
    kv_set(&users_store(), &format!("user:{}", u.id), &u)?;
    // Store email → user_id index
    let email_key = format!("email:{}", u.email.to_lowercase());
    kv_set_raw(&user_idx_store(), &email_key, u.id.as_bytes())
}

pub fn get_user(id: &str) -> Result<Option<User>, String> {
    kv_get(&users_store(), &format!("user:{id}"))
}

pub fn update_user(user: &User) -> Result<(), String> {
    kv_set(&users_store(), &format!("user:{}", user.id), user)
}

pub fn list_users() -> Result<Vec<User>, String> {
    let store_name = users_store();
    let keys = kv_list_keys(&store_name)?;
    let mut users = Vec::new();
    for key in keys {
        if key.starts_with("user--")
            && let Some(u) = kv_get::<User>(&store_name, &key)?
        {
            users.push(u);
        }
    }
    Ok(users)
}

pub fn get_user_by_email(email: &str) -> Result<Option<User>, String> {
    let email_hash = sanitize_key(&email.to_lowercase());
    
    // Check with region-authority where this user lives
    let lookup = crate::bindings::taika3d::lid::authority::lookup(&email_hash)
        .map_err(|e| format!("authority lookup failed: {}", e))?;

    if !lookup.found {
        return Ok(None);
    }

    match lookup.region.as_deref() {
        Some("local") | None => {
            // User is in this region, continue local lookup
            let email_key = sanitize_key(&format!("email:{}", email_hash));
            let store_name = user_idx_store();
            let store = kv::open(&store_name).map_err(|e| format!("open idx: {e:?}"))?;
            match store
                .get(&email_key)
                .map_err(|e| format!("get idx: {e:?}"))?
            {
                Some(entry) => {
                    let user_id = String::from_utf8_lossy(&entry.value);
                    get_user(&user_id)
                }
                None => Ok(None),
            }
        }
        Some(_target_region) => {
            // User is in another region — return None so the login handler
            // can perform the cross-region redirect via lookup_region().
            Ok(None)
        }
    }
}

// ── Auth session operations ─────────────────────────────────

pub fn save_auth_session(session_id: &str, session: &AuthSession) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("session:{session_id}"), session)
}

pub fn get_auth_session(session_id: &str) -> Result<Option<AuthSession>, String> {
    kv_get(&sessions_store(), &format!("session:{session_id}"))
}

pub fn delete_auth_session(session_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("session:{session_id}"))
}

// ── Auth code operations ────────────────────────────────────

pub fn save_auth_code(code: &str, auth_code: &AuthCode) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("code:{code}"), auth_code)
}

#[allow(dead_code)]
pub fn get_auth_code(code: &str) -> Result<Option<AuthCode>, String> {
    kv_get(&sessions_store(), &format!("code:{code}"))
}

/// Get auth code with revision for CAS consumption.
pub fn get_auth_code_cas(code: &str) -> Result<Option<(AuthCode, u64)>, String> {
    kv_get_revision(&sessions_store(), &format!("code:{code}"))
}

/// Atomically consume an auth code (CAS swap to consumed marker).
/// Returns Err if the code was already consumed by another request.
pub fn consume_auth_code(code: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap(&sessions_store(), &format!("code:{code}"), &consumed, revision)?;
    Ok(())
}

#[allow(dead_code)]
pub fn delete_auth_code(code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("code:{code}"))
}

// ── Refresh token operations ────────────────────────────────

#[allow(dead_code)]
pub fn save_refresh_token(token_hash: &str, entry: &RefreshEntry) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("refresh:{token_hash}"), entry)?;
    kv_set_raw(
        &sessions_store(),
        &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        &[1],
    )
}

pub fn get_refresh_token(token_hash: &str) -> Result<Option<RefreshEntry>, String> {
    kv_get(&sessions_store(), &format!("refresh:{token_hash}"))
}

/// Get refresh token with revision for CAS consumption.
/// Returns `None` if the key is missing or the value cannot be deserialized
/// (e.g. it has been CAS-swapped to a consumed marker).
pub fn get_refresh_token_cas(
    token_hash: &str,
) -> Result<Option<(RefreshEntry, u64)>, String> {
    match kv_get_revision(&sessions_store(), &format!("refresh:{token_hash}")) {
        Ok(v) => Ok(v),
        Err(e) if e.starts_with("deserialize:") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically consume a refresh token (CAS swap to consumed marker).
pub fn consume_refresh_token(token_hash: &str, revision: u64) -> Result<(), String> {
    let consumed = serde_json::json!({"consumed": true});
    kv_cas_swap(
        &sessions_store(),
        &format!("refresh:{token_hash}"),
        &consumed,
        revision,
    )?;
    Ok(())
}

/// Mark a consumed refresh token hash so replay can be detected.
pub fn mark_refresh_consumed(token_hash: &str, user_id: &str) -> Result<(), String> {
    kv_set_raw(
        &sessions_store(),
        &format!("consumed:{token_hash}"),
        user_id.as_bytes(),
    )
}

/// Check if a refresh token hash was previously consumed (replay detection).
pub fn get_consumed_refresh(token_hash: &str) -> Result<Option<String>, String> {
    let store_name = sessions_store();
    let safe_key = sanitize_key(&format!("consumed:{token_hash}"));
    let store = kv::open(&store_name).map_err(|e| format!("open sessions: {e:?}"))?;
    match store.get(&safe_key).map_err(|e| format!("get consumed: {e:?}"))? {
        Some(entry) => Ok(Some(String::from_utf8_lossy(&entry.value).to_string())),
        None => Ok(None),
    }
}

pub fn delete_refresh_token(token_hash: &str) -> Result<(), String> {
    // Tolerate deserialization failures (e.g. consumed marker) when cleaning up the index.
    if let Ok(Some(entry)) = get_refresh_token(token_hash) {
        let _ = kv_delete(
            &sessions_store(),
            &format!("refresh_idx:{}:{token_hash}", entry.user_id),
        );
    }
    kv_delete(&sessions_store(), &format!("refresh:{token_hash}"))
}

/// Task 2.12: Revoke all sessions for a user (used for security breach or password change)
pub fn revoke_user_sessions(user_id: &str) -> Result<(), String> {
    let store_name = sessions_store();
    let key = format!("revoked:user:{user_id}");
    kv_set_raw(&store_name, &key, &unix_now().to_be_bytes())
}

/// Check if a user's sessions have been revoked.
/// Returns true if the token (issued at `iat`) was issued before the revocation time.
pub fn is_user_revoked(user_id: &str, iat: u64) -> Result<bool, String> {
    let store_name = sessions_store();
    let key = sanitize_key(&format!("revoked:user:{user_id}"));
    let store = kv::open(&store_name).map_err(|e| format!("open sessions: {e:?}"))?;
    match store.get(&key).map_err(|e| format!("get revoked: {e:?}"))? {
        Some(entry) if entry.value.len() == 8 => {
            let revoked_at = u64::from_be_bytes(entry.value.try_into().unwrap());
            Ok(iat < revoked_at)
        }
        Some(_) => Ok(true), // presence without timestamp → revoke all
        None => Ok(false),
    }
}

/// Delete all refresh tokens for a given user (used during logout).
/// Task 2.20: Use secondary index for refresh tokens to avoid O(n) scan.
pub fn delete_user_refresh_tokens(user_id: &str) -> Result<u32, String> {
    let store_name = sessions_store();
    let prefix = format!("refresh_idx--{user_id}--");
    let keys = kv_list_keys(&store_name)?;
    let mut count = 0u32;
    for key in keys {
        if key.starts_with(&prefix) {
            let token_hash = key.strip_prefix(&prefix).unwrap_or("");
            if !token_hash.is_empty() {
                kv_delete(&store_name, &format!("refresh:{token_hash}"))?;
                kv_delete(&store_name, &key)?;
                count += 1;
            }
        }
    }
    // Task 2.12: Also trigger session revocation (for access tokens)
    crate::store::revoke_user_sessions(user_id)?;
    Ok(count)
}

// ── OIDC client operations ──────────────────────────────────

pub fn get_client(client_id: &str) -> Result<Option<OidcClient>, String> {
    kv_get(&clients_store(), &format!("client:{client_id}"))
}

pub fn save_client(client: &OidcClient) -> Result<(), String> {
    kv_set(&clients_store(), &format!("client:{}", client.client_id), client)
}

pub fn list_clients() -> Result<Vec<OidcClient>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name)?;
    let mut clients = Vec::new();
    for key in keys {
        if key.starts_with("client--")
            && let Some(c) = kv_get::<OidcClient>(&store_name, &key)?
        {
            clients.push(c);
        }
    }
    Ok(clients)
}

// ── Tenant operations ───────────────────────────────────────

pub fn create_tenant(tenant: &Tenant) -> Result<(), String> {
    let key = format!("tenant:{}", tenant.id);
    let store_name = tenants_store();
    if kv_get::<Tenant>(&store_name, &key)?.is_some() {
        return Err("tenant already exists".into());
    }
    kv_set(&store_name, &key, tenant)
}

pub fn get_tenant(id: &str) -> Result<Option<Tenant>, String> {
    kv_get(&tenants_store(), &format!("tenant:{id}"))
}

pub fn delete_tenant(id: &str) -> Result<(), String> {
    kv_delete(&tenants_store(), &format!("tenant:{id}"))
}

pub fn list_tenants() -> Result<Vec<Tenant>, String> {
    let store_name = tenants_store();
    let keys = kv_list_keys(&store_name)?;
    let mut tenants = Vec::new();
    for key in keys {
        if key.starts_with("tenant--")
            && let Some(t) = kv_get::<Tenant>(&store_name, &key)?
        {
            tenants.push(t);
        }
    }
    Ok(tenants)
}

// ── Membership operations ───────────────────────────────────

pub fn add_membership(m: &Membership) -> Result<(), String> {
    let store_name = memberships_store();
    // Forward index: tenant → user
    let fwd = format!("tenant:{}:user:{}", m.tenant_id, m.user_id);
    kv_set(&store_name, &fwd, m)?;
    // Reverse index: user → tenant (for lookup)
    let rev = format!("user:{}:tenant:{}", m.user_id, m.tenant_id);
    kv_set_raw(&store_name, &rev, m.role.as_bytes())
}

pub fn get_membership(tenant_id: &str, user_id: &str) -> Result<Option<Membership>, String> {
    kv_get(
        &memberships_store(),
        &format!("tenant:{tenant_id}:user:{user_id}"),
    )
}

pub fn remove_membership(tenant_id: &str, user_id: &str) -> Result<(), String> {
    let store_name = memberships_store();
    kv_delete(
        &store_name,
        &format!("tenant:{tenant_id}:user:{user_id}"),
    )?;
    kv_delete(
        &store_name,
        &format!("user:{user_id}:tenant:{tenant_id}"),
    )
}

pub fn list_tenant_members(tenant_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("tenant--{tenant_id}--user--");
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name)?;
    let mut members = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(m) = kv_get::<Membership>(&store_name, &key)?
        {
            members.push(m);
        }
    }
    Ok(members)
}

pub fn list_user_tenants(user_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("user--{user_id}--tenant--");
    let keys = kv_list_keys(&memberships_store())?;
    let mut memberships = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            // Extract tenant_id from key
            let tenant_id = key.strip_prefix(&prefix).unwrap_or("");
            if let Some(m) = get_membership(tenant_id, user_id)? {
                memberships.push(m);
            }
        }
    }
    Ok(memberships)
}

// ── Invitation operations ───────────────────────────────────

pub fn save_invitation(inv: &Invitation) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("invite:{}", inv.token), inv)
}

pub fn get_invitation(token: &str) -> Result<Option<Invitation>, String> {
    kv_get(&sessions_store(), &format!("invite:{token}"))
}

pub fn delete_invitation(token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("invite:{token}"))
}

// ── Account lockout operations ──────────────────────────────

pub fn is_account_locked(user_id: &str) -> Result<bool, String> {
    match kv_get::<LoginAttempts>(&sessions_store(), &format!("lockout:{user_id}"))? {
        Some(a) if a.locked_until > unix_now() => Ok(true),
        _ => Ok(false),
    }
}

/// Record a failed login. Returns true if the account is now locked.
pub fn record_failed_login(user_id: &str) -> Result<bool, String> {
    let store_name = sessions_store();
    let key = format!("lockout:{user_id}");
    let mut attempts = kv_get::<LoginAttempts>(&store_name, &key)?.unwrap_or(LoginAttempts {
        failures: 0,
        locked_until: 0,
    });

    // If previously locked and lock expired, reset counter
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
    kv_set(&store_name, &key, &attempts)?;
    Ok(locked)
}

pub fn clear_login_attempts(user_id: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("lockout:{user_id}"))
}

// ── Audit log operations ────────────────────────────────────

pub fn log_audit(
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
    kv_set(&audit_store(), &key, &event)
}

pub fn list_audit_events(
    actor_id: Option<&str>,
    target_id: Option<&str>,
    event_type: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    limit: usize,
) -> Result<Vec<AuditEvent>, String> {
    let store_name = audit_store();
    let keys = kv_list_keys(&store_name)?;
    let mut events = Vec::new();

    for key in keys {
        if key.starts_with("audit--")
            && let Some(event) = kv_get::<AuditEvent>(&store_name, &key)?
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
pub fn ensure_default_client() -> Result<(), String> {
    let default_id = "default";
    if get_client(default_id)?.is_some() {
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
    };
    kv_set(&clients_store(), &format!("client:{default_id}"), &client)
}

/// Register the Lattice-ID Admin UI OIDC client.
/// Called per-request in dev mode to ensure the admin client always exists.
pub fn ensure_admin_client(issuer: &str, dev_mode: bool) -> Result<(), String> {
    let admin_id = "lid-admin";
    if get_client(admin_id)?.is_some() {
        return Ok(());
    }
    // Derive redirect URIs from issuer — production uses the same origin,
    // local dev uses known ports.
    let mut redirect_uris = vec![format!("{issuer}/"), format!("{issuer}/callback")];
    
    if dev_mode {
        // Also allow common local dev ports
        for port in &["8090", "8091"] {
            redirect_uris.push(format!("http://localhost:{port}/"));
            redirect_uris.push(format!("http://localhost:{port}/callback"));
        }
    }
    let client = OidcClient {
        client_id: admin_id.to_string(),
        client_secret: None,
        redirect_uris,
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        name: "Lattice-ID Admin".to_string(),
        theme: None,
    };
    kv_set(&clients_store(), &format!("client:{admin_id}"), &client)
}

// ── Signing key persistence ─────────────────────────────────

pub fn load_signing_keys() -> Result<Option<serde_json::Value>, String> {
    kv_get(&keys_store(), SIGNING_KEYS_KEY)
}

// ── Identity provider operations ────────────────────────────

pub fn save_identity_provider(idp: &IdentityProvider) -> Result<(), String> {
    kv_set(&clients_store(), &format!("idp:{}", idp.id), idp)
}

pub fn get_identity_provider(id: &str) -> Result<Option<IdentityProvider>, String> {
    kv_get(&clients_store(), &format!("idp:{id}"))
}

pub fn get_identity_provider_by_type(
    provider_type: &str,
) -> Result<Option<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name)?;
    for key in keys {
        if key.starts_with("idp--")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key)?
            && idp.provider_type == provider_type
            && idp.enabled
        {
            return Ok(Some(idp));
        }
    }
    Ok(None)
}

pub fn list_identity_providers() -> Result<Vec<IdentityProvider>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name)?;
    let mut providers = Vec::new();
    for key in keys {
        if key.starts_with("idp--")
            && let Some(idp) = kv_get::<IdentityProvider>(&store_name, &key)?
        {
            providers.push(idp);
        }
    }
    Ok(providers)
}

pub fn delete_identity_provider(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("idp:{id}"))
}

// ── Social identity operations ──────────────────────────────

pub fn save_social_identity(si: &SocialIdentity) -> Result<(), String> {
    // Index by provider:sub for login lookup
    let key = format!("social:{}:{}", si.provider, si.provider_sub);
    kv_set(&user_idx_store(), &key, si)
}

pub fn get_social_identity(
    provider: &str,
    provider_sub: &str,
) -> Result<Option<SocialIdentity>, String> {
    kv_get(&user_idx_store(), &format!("social:{provider}:{provider_sub}"))
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

pub fn save_mfa_pending(mfa_token: &str, pending: &MfaPending) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("mfa:{mfa_token}"), pending)
}

pub fn get_mfa_pending(mfa_token: &str) -> Result<Option<MfaPending>, String> {
    kv_get(&sessions_store(), &format!("mfa:{mfa_token}"))
}

pub fn delete_mfa_pending(mfa_token: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("mfa:{mfa_token}"))
}

// ── Known IPs (suspicious login detection) ──────────────────

const MAX_KNOWN_IPS: usize = 20;

#[derive(Serialize, Deserialize)]
struct KnownIps {
    ips: Vec<String>,
}

/// Check whether `ip` is already known for this user. If not, record it
/// and return `true` (= new / suspicious). Returns `false` for known IPs
/// or when the IP is empty/unknown.
pub fn check_and_record_ip(user_id: &str, ip: &str) -> bool {
    if ip.is_empty() || ip == "unknown" {
        return false;
    }
    let key = format!("known_ips:{user_id}");
    let store = sessions_store();
    let mut entry: KnownIps = kv_get(&store, &key)
        .ok()
        .flatten()
        .unwrap_or(KnownIps { ips: Vec::new() });

    if entry.ips.iter().any(|existing| existing == ip) {
        return false; // already known
    }

    // New IP — append and cap at MAX_KNOWN_IPS (drop oldest)
    entry.ips.push(ip.to_string());
    if entry.ips.len() > MAX_KNOWN_IPS {
        entry.ips.remove(0);
    }
    let _ = kv_set(&store, &key, &entry);
    true
}

// ── Hook operations ─────────────────────────────────────────

pub fn save_hook(hook: &Hook) -> Result<(), String> {
    kv_set(&clients_store(), &format!("hook:{}", hook.id), hook)
}

pub fn get_hook(id: &str) -> Result<Option<Hook>, String> {
    kv_get(&clients_store(), &format!("hook:{id}"))
}

pub fn list_hooks() -> Result<Vec<Hook>, String> {
    let store_name = clients_store();
    let keys = kv_list_keys(&store_name)?;
    let mut hooks = Vec::new();
    for key in keys {
        if key.starts_with("hook--")
            && let Some(hook) = kv_get::<Hook>(&store_name, &key)?
        {
            hooks.push(hook);
        }
    }
    Ok(hooks)
}

pub fn delete_hook(id: &str) -> Result<(), String> {
    kv_delete(&clients_store(), &format!("hook:{id}"))
}

/// Save an immutable version snapshot for audit purposes.
pub fn save_hook_version(ver: &HookVersion) -> Result<(), String> {
    let key = format!("hookver:{}:{:06}", ver.hook_id, ver.version);
    kv_set(&audit_store(), &key, ver)
}

/// List all version snapshots for a hook, ordered by version.
pub fn list_hook_versions(hook_id: &str) -> Result<Vec<HookVersion>, String> {
    let store_name = audit_store();
    let prefix = format!("hookver--{}--", sanitize_key(hook_id));
    let keys = kv_list_keys(&store_name)?;
    let mut versions = Vec::new();
    for key in keys {
        if key.starts_with(&prefix)
            && let Some(ver) = kv_get::<HookVersion>(&store_name, &key)?
        {
            versions.push(ver);
        }
    }
    versions.sort_by_key(|v| v.version);
    Ok(versions)
}

// ── Runtime settings ────────────────────────────────────────

/// Runtime-mutable settings stored in KV.  These can be modified by
/// superadmins via the management API.  Deployment config provides
/// defaults; KV settings override them.
#[derive(Serialize, Deserialize, Default)]
pub struct RuntimeSettings {
    /// Whether self-service registration is open.
    /// Default is `false` — closed until a superadmin enables it.
    #[serde(default)]
    pub allow_registration: bool,
}

const SETTINGS_KEY: &str = "settings:global";

pub fn get_runtime_settings() -> RuntimeSettings {
    kv_get::<RuntimeSettings>(&clients_store(), SETTINGS_KEY)
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub fn save_runtime_settings(settings: &RuntimeSettings) -> Result<(), String> {
    kv_set(&clients_store(), SETTINGS_KEY, settings)
}
