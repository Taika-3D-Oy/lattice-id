#![allow(dead_code)]

use crate::bindings::taika3d::lid::keyvalue_nats_cas as kv;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
pub struct OidcClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Membership {
    pub tenant_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: u64,
}

/// Minimal struct for GC — only needs created_at to check expiry.
#[derive(Deserialize)]
struct AuthSession {
    #[allow(dead_code)]
    client_id: String,
    created_at: u64,
}

/// Minimal struct for GC — only needs expires_at.
#[derive(Deserialize)]
struct Invitation {
    expires_at: u64,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn config_value(key: &str) -> Option<String> {
    crate::bindings::wasi::config::store::get(key)
        .ok()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn store_prefix() -> &'static str {
    static PREFIX: OnceLock<String> = OnceLock::new();
    PREFIX.get_or_init(|| {
        config_value("kv_prefix").unwrap_or_else(|| "lid".to_string())
    })
}

pub fn core_service_auth_key() -> Option<String> {
    config_value("core_service_auth_key")
}

pub fn fill_random(buf: &mut [u8]) {
    use rand_core::{RngCore, OsRng};
    OsRng.fill_bytes(buf);
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
fn memberships_store() -> String { store_name("memberships") }
fn tenants_store() -> String {
    config_value("tenant_bucket").unwrap_or_else(|| store_name("tenants"))
}
fn audit_store() -> String { store_name("audit") }

/// Sanitize a key for NATS JetStream KV compatibility.
/// NATS KV keys only allow: A-Z, a-z, 0-9, '-', '_', '/', '=', '.' (middle only).
/// File-backed KV (wash dev) interprets '/' as directory separator, so we avoid it.
/// We replace ':' with '--' and '@' with '_at_'.
pub fn sanitize_key(key: &str) -> String {
    key.replace(':', "--").replace('@', "_at_")
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

pub fn create_user(user: &User) -> Result<(), String> {
    if get_user_by_email(&user.email)?.is_some() {
        return Err("email already registered".into());
    }
    kv_set(&users_store(), &format!("user:{}", user.id), user)?;
    kv_set_raw(
        &user_idx_store(),
        &format!("email:{}", user.email.to_lowercase()),
        user.id.as_bytes(),
    )
}

pub fn get_user(id: &str) -> Result<Option<User>, String> {
    kv_get(&users_store(), &format!("user:{id}"))
}

/// Check if a pre-sanitized email key exists in the user-idx store.
/// Used by the `lookup_user_exists` op to answer shard routing queries
/// without returning any user data.
pub fn user_idx_exists(sanitized_key: &str) -> Result<bool, String> {
    let store_name = user_idx_store();
    let store = kv::open(&store_name).map_err(|e| format!("open idx: {e:?}"))?;
    match store.get(sanitized_key).map_err(|e| format!("get idx: {e:?}"))? {
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

pub fn get_user_by_email(email: &str) -> Result<Option<User>, String> {
    let key = sanitize_key(&format!("email:{}", email.to_lowercase()));
    let store_name = user_idx_store();
    let store = kv::open(&store_name).map_err(|e| format!("open idx: {e:?}"))?;
    match store.get(&key).map_err(|e| format!("get idx: {e:?}"))? {
        Some(entry) => {
            let user_id = String::from_utf8_lossy(&entry.value);
            get_user(&user_id)
        }
        None => Ok(None),
    }
}

pub fn list_users() -> Result<Vec<User>, String> {
    let store_name = users_store();
    let keys = kv_list_keys(&store_name)?;
    let mut users = Vec::new();
    for key in keys {
        if key.starts_with("user--")
            && let Some(user) = kv_get::<User>(&store_name, &key)?
        {
            users.push(user);
        }
    }
    Ok(users)
}

pub fn get_auth_code(code: &str) -> Result<Option<AuthCode>, String> {
    kv_get(&sessions_store(), &format!("code:{code}"))
}

pub fn delete_auth_code(code: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("code:{code}"))
}

pub fn save_refresh_token(token_hash: &str, entry: &RefreshEntry) -> Result<(), String> {
    kv_set(&sessions_store(), &format!("refresh:{token_hash}"), entry)
}

pub fn get_refresh_token(token_hash: &str) -> Result<Option<RefreshEntry>, String> {
    kv_get(&sessions_store(), &format!("refresh:{token_hash}"))
}

pub fn delete_refresh_token(token_hash: &str) -> Result<(), String> {
    kv_delete(&sessions_store(), &format!("refresh:{token_hash}"))
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
/// Returns the user_id if it was consumed.
pub fn get_consumed_refresh(token_hash: &str) -> Result<Option<String>, String> {
    let store = kv::open(&sessions_store()).map_err(|e| format!("open sessions: {e:?}"))?;
    let safe_key = sanitize_key(&format!("consumed:{token_hash}"));
    match store.get(&safe_key).map_err(|e| format!("get consumed: {e:?}"))? {
        Some(entry) => Ok(Some(String::from_utf8_lossy(&entry.value).to_string())),
        None => Ok(None),
    }
}

pub fn get_client(client_id: &str) -> Result<Option<OidcClient>, String> {
    kv_get(&clients_store(), &format!("client:{client_id}"))
}

pub fn save_client(client: &OidcClient) -> Result<(), String> {
    kv_set(&clients_store(), &format!("client:{}", client.client_id), client)
}

pub fn revoke_user_sessions(user_id: &str) -> Result<(), String> {
    let now = unix_now();
    kv_set(
        &sessions_store(),
        &format!("revoke_all:{user_id}"),
        &now,
    )
}

pub fn is_user_revoked(user_id: &str, iat: u64) -> Result<bool, String> {
    if let Some(revoke_at) = kv_get::<u64>(&sessions_store(), &format!("revoke_all:{user_id}"))? {
        return Ok(iat < revoke_at);
    }
    Ok(false)
}

pub fn get_membership(tenant_id: &str, user_id: &str) -> Result<Option<Membership>, String> {
    kv_get(
        &memberships_store(),
        &format!("tenant:{tenant_id}:user:{user_id}"),
    )
}

pub fn list_user_tenants(user_id: &str) -> Result<Vec<Membership>, String> {
    let prefix = format!("user--{user_id}--tenant--");
    let store_name = memberships_store();
    let keys = kv_list_keys(&store_name)?;
    let mut memberships = Vec::new();
    for key in keys {
        if key.starts_with(&prefix) {
            let tenant_id = key.strip_prefix(&prefix).unwrap_or("");
            if let Some(membership) = get_membership(tenant_id, user_id)? {
                memberships.push(membership);
            }
        }
    }
    Ok(memberships)
}

/// Garbage-collect expired entries from KV stores.
/// Called periodically by the background GC timer.
pub fn gc_expired_entries() {
    let now = unix_now();
    let mut codes = 0u64;
    let mut sessions = 0u64;
    let mut refresh_tokens = 0u64;
    let mut consumed = 0u64;
    let mut invitations = 0u64;

    let s_store = sessions_store();
    if let Ok(keys) = kv_list_keys(&s_store) {
        for key in keys {
            if key.starts_with("code--") {
                if let Ok(Some(code)) = kv_get::<AuthCode>(&s_store, &key) {
                    if code.expires_at < now {
                        let _ = kv_delete(&s_store, &key);
                        codes += 1;
                    }
                }
            } else if key.starts_with("session--") {
                if let Ok(Some(sess)) = kv_get::<AuthSession>(&s_store, &key) {
                    // Auth sessions expire after 1 hour
                    if sess.created_at + 3600 < now {
                        let _ = kv_delete(&s_store, &key);
                        sessions += 1;
                    }
                }
            } else if key.starts_with("refresh--") {
                if let Ok(Some(entry)) = kv_get::<RefreshEntry>(&s_store, &key) {
                    if entry.expires_at < now {
                        let hash = key.strip_prefix("refresh--").unwrap_or("");
                        let _ = kv_delete(&s_store, &format!("refresh_idx:{}:{}", entry.user_id, hash));
                        let _ = kv_delete(&s_store, &key);
                        refresh_tokens += 1;
                    }
                }
            } else if key.starts_with("consumed--") {
                // Consumed-hash entries are safe to purge after 30 days
                // (well past any refresh token family lifetime).
                // They are raw strings (user_id), not JSON, so we check
                // by age of the key prefix. Since we can't know when it was
                // written without extra metadata, we check if the
                // corresponding refresh entry is gone (meaning the family expired).
                // Simple approach: just keep them for 30 days based on a TTL marker.
                // For now, delete consumed entries whose refresh family is gone.
                let hash = key.strip_prefix("consumed--").unwrap_or("");
                if !hash.is_empty() {
                    let refresh_key = format!("refresh--{hash}");
                    // If the refresh token is also gone, the consumed marker is stale
                    if let Ok(None) = kv_get::<RefreshEntry>(&s_store, &refresh_key) {
                        let _ = kv_delete(&s_store, &key);
                        consumed += 1;
                    }
                }
            }
        }
    }

    // Clean up expired invitations from tenants store
    let t_store = tenants_store();
    if let Ok(keys) = kv_list_keys(&t_store) {
        for key in keys {
            if key.starts_with("invite--") {
                if let Ok(Some(inv)) = kv_get::<Invitation>(&t_store, &key) {
                    if inv.expires_at < now {
                        let _ = kv_delete(&t_store, &key);
                        invitations += 1;
                    }
                }
            }
        }
    }

    let total = codes + sessions + refresh_tokens + consumed + invitations;
    if total > 0 {
        crate::logger::info(
            "gc.purged",
            None,
            serde_json::json!({
                "total": total,
                "codes": codes,
                "sessions": sessions,
                "refresh_tokens": refresh_tokens,
                "consumed": consumed,
                "invitations": invitations,
            }),
        );
    }
}

pub fn log_audit(
    event_type: &str,
    actor_id: &str,
    target_id: &str,
    details: &str,
) -> Result<(), String> {
    let now = unix_now();
    let key = format!("audit:{now}:{}", random_hex(4));
    let event = serde_json::json!({
        "event_type": event_type,
        "actor_id": actor_id,
        "target_id": target_id,
        "details": details,
        "timestamp": now,
    });
    kv_set(&audit_store(), &key, &event)
}

// ── Signing key persistence ─────────────────────────────────

const SIGNING_KEYS_KEY: &str = "signing_keys";

pub fn persist_signing_keys(data: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(data).map_err(|e| format!("serialize keys: {e}"))?;
    kv_set_raw(&keys_store(), SIGNING_KEYS_KEY, &bytes)
}

pub fn load_signing_keys() -> Result<Option<serde_json::Value>, String> {
    kv_get(&keys_store(), SIGNING_KEYS_KEY)
}

/// Get signing keys with revision for CAS rotation.
pub fn load_signing_keys_revision() -> Result<Option<(serde_json::Value, u64)>, String> {
    let store_name = keys_store();
    let store = kv::open(&store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let safe_key = sanitize_key(SIGNING_KEYS_KEY);
    match store.get(&safe_key).map_err(|e| format!("get signing_keys: {e:?}"))? {
        Some(entry) => {
            let val = serde_json::from_slice(&entry.value).map_err(|e| format!("deserialize: {e}"))?;
            Ok(Some((val, entry.revision)))
        }
        None => Ok(None),
    }
}

/// Atomically swap signing keys if revision matches.
pub fn cas_persist_signing_keys(data: &serde_json::Value, revision: u64) -> Result<u64, String> {
    let store_name = keys_store();
    let store = kv::open(&store_name).map_err(|e| format!("open {store_name}: {e:?}"))?;
    let bytes = serde_json::to_vec(data).map_err(|e| format!("serialize keys: {e}"))?;
    let safe_key = sanitize_key(SIGNING_KEYS_KEY);
    store.swap(&safe_key, &bytes, revision)
        .map_err(|e| format!("{e:?}"))
}

// ── CAS-based distributed task claiming ─────────────────────

/// Attempt to claim a periodic task using CAS. Returns true if this instance
/// wins the claim (and should run the task). Only one instance across all
/// workload replicas will succeed per interval.
///
/// The task's last-run timestamp is stored in `lid-sessions` under
/// `maintenance:{task_name}`. On each attempt:
///   1. Read (timestamp, revision) — if now - timestamp < interval_secs, skip.
///   2. CAS swap(key, now, revision) — if OK, we're the winner.
///   3. If swap fails (another instance won), return false.
pub fn try_claim_task(task_name: &str, interval_secs: u64) -> bool {
    let store_name = sessions_store();
    let key = format!("maintenance:{task_name}");
    let safe_key = sanitize_key(&key);
    let now = unix_now();

    let store = match kv::open(&store_name) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let now_bytes = now.to_be_bytes().to_vec();

    match store.get(&safe_key) {
        Ok(Some(entry)) => {
            let last_run = if entry.value.len() == 8 {
                u64::from_be_bytes(entry.value[..8].try_into().unwrap_or([0; 8]))
            } else {
                0
            };
            if now.saturating_sub(last_run) < interval_secs {
                return false; // too soon — someone ran recently
            }
            // Try to claim
            store.swap(&safe_key, &now_bytes, entry.revision).is_ok()
        }
        Ok(None) => {
            // First ever run — try to create
            store.set(&safe_key, &now_bytes).is_ok()
        }
        Err(_) => false,
    }
}

// ── Cross-region config sync ────────────────────────────────

/// Region ID from deployment config.
pub fn region_id() -> Option<String> {
    config_value("region_id")
}

/// Shared secret for authenticating cross-region `/internal/*` HTTP requests.
pub fn internal_auth_secret() -> Option<String> {
    config_value("internal_auth_secret")
}

/// Internal URLs for all regions (JSON object from config).
fn region_internal_urls() -> Vec<(String, String)> {
    let json_str = match config_value("region_internal_urls") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let map: std::collections::HashMap<String, String> =
        serde_json::from_str(&json_str).unwrap_or_default();
    map.into_iter().collect()
}

/// Fetch client and tenant config from all remote regions and upsert into local KV.
/// Called by the background loop when CAS claim succeeds.
pub async fn sync_remote_config() {
    let self_region = region_id().unwrap_or_default();
    let urls = region_internal_urls();

    for (region_name, base_url) in &urls {
        if *region_name == self_region {
            continue;
        }
        let url = format!("{}/internal/config", base_url.trim_end_matches('/'));
        match http_get_json(&url).await {
            Ok(data) => {
                let clients = data.get("clients").and_then(|v| v.as_array());
                let tenants = data.get("tenants").and_then(|v| v.as_array());
                let mut synced = 0u64;

                if let Some(clients) = clients {
                    let store = clients_store();
                    for client in clients {
                        if let Some(id) = client.get("client_id").and_then(|v| v.as_str()) {
                            let key = format!("client:{id}");
                            let _ = kv_set(&store, &key, client);
                            synced += 1;
                        }
                    }
                }
                if let Some(tenants) = tenants {
                    let store = tenants_store();
                    for tenant in tenants {
                        if let Some(id) = tenant.get("id").and_then(|v| v.as_str()) {
                            let key = format!("tenant:{id}");
                            let _ = kv_set(&store, &key, tenant);
                            synced += 1;
                        }
                    }
                }

                if synced > 0 {
                    crate::logger::info(
                        "config_sync.synced",
                        None,
                        serde_json::json!({ "region": region_name, "items": synced }),
                    );
                }
            }
            Err(e) => {
                crate::logger::warn(
                    "config_sync.failed",
                    None,
                    serde_json::json!({ "region": region_name, "error": e }),
                );
            }
        }
    }
}

/// HTTP GET returning parsed JSON. Uses wstd high-level HTTP client.
async fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    use wstd::http::{Body, Client};

    let mut builder = wstd::http::Request::builder()
        .method(wstd::http::Method::GET)
        .uri(url)
        .header("accept", "application/json");

    // Attach shared secret if configured
    if let Some(secret) = internal_auth_secret() {
        builder = builder.header("x-internal-auth", secret);
    }

    let request = builder
        .body(Body::empty())
        .map_err(|e| format!("build request: {e}"))?;

    let response = Client::new()
        .send(request)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = response.status();
    let mut body = response.into_body();
    let bytes = body.contents().await.map_err(|e| format!("read body: {e}"))?;

    if !status.is_success() {
        return Err(format!("http {}", status.as_u16()));
    }

    serde_json::from_slice(&bytes).map_err(|e| format!("parse JSON: {e}"))
}
