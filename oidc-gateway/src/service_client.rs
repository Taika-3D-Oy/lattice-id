use serde_json::{Value, json};
use wstd::io::{AsyncRead, AsyncWrite};
use wstd::net::TcpStream;

use crate::{jwt, keys, store};

trait ReadExt: AsyncRead + Unpin {
    async fn read_exact_lid(&mut self, mut buf: &mut [u8]) -> Result<(), String> {
        while !buf.is_empty() {
            let n = AsyncRead::read(self, buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("failed to fill whole buffer".to_string());
            }
            let (_, rest) = std::mem::take(&mut buf).split_at_mut(n);
            buf = rest;
        }
        Ok(())
    }
}
impl<T: AsyncRead + Unpin> ReadExt for T {}

trait WriteExt: AsyncWrite + Unpin {
    async fn write_all_lid(&mut self, mut buf: &[u8]) -> Result<(), String> {
        while !buf.is_empty() {
            let n = AsyncWrite::write(self, buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("failed to write whole buffer".to_string());
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}
impl<T: AsyncWrite + Unpin> WriteExt for T {}

const SERVICE_ADDR: &str = "127.0.0.1:7899";

/// Hash a password locally via imported hasher (stateless scaling).
pub fn hash_password(plain: &str) -> Result<String, String> {
    crate::bindings::lattice_id::crypto::password::hash(plain)
}

/// Verify a password locally via imported hasher (stateless scaling).
pub fn verify_password(plain: &str, hash: &str) -> Result<bool, String> {
    crate::bindings::lattice_id::crypto::password::verify(plain, hash)
}

/// Send a JSON request to core-service via TCP and return the parsed response.
/// Task 2.13: Implement TCP framing (length-prefixed).
/// Task 2.17: Authenticate TCP channel with HMAC-based handshake.
pub async fn call(request: &Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect(SERVICE_ADDR).await.map_err(|e| {
        crate::logger::error_message("core_service.connect_failed", e);
        "internal service unavailable".to_string()
    })?;

    // Phase 2.17: Authenticate connection if an auth key is configured.
    if let Some(auth_key) = crate::store::core_service_auth_key() {
        use sha2::{Digest, Sha256};
        // 1. Read 16-byte nonce from server
        let mut nonce = [0u8; 16];
        stream.read_exact_lid(&mut nonce)
            .await
            .map_err(|e| format!("read auth nonce: {e}"))?;

        // 2. Compute HMAC-like challenge: SHA256(nonce + auth_key)
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(auth_key.as_bytes());
        let response = hasher.finalize();

        // 3. Send 32-byte response back to server
        stream.write_all_lid(&response)
            .await
            .map_err(|e| format!("write auth response: {e}"))?;
    }

    let mut request_obj = request
        .as_object()
        .cloned()
        .ok_or_else(|| "request must be a JSON object".to_string())?;
    if let Some(trace_id) = crate::logger::current_trace_id() {
        request_obj.insert("trace_id".to_string(), Value::String(trace_id));
    }

    let req_bytes = serde_json::to_vec(&Value::Object(request_obj))
        .map_err(|e| format!("serialize: {e}"))?;
    let req_len = (req_bytes.len() as u32).to_be_bytes();

    stream.write_all_lid(&req_len)
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream.write_all_lid(&req_bytes)
        .await
        .map_err(|e| format!("write: {e}"))?;

    // Read 4-byte response length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact_lid(&mut len_buf)
        .await
        .map_err(|e| format!("read length: {e}"))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 1024 * 1024 {
        return Err("Response too large from core-service".into());
    }

    let mut buf = vec![0u8; resp_len];
    stream.read_exact_lid(&mut buf)
        .await
        .map_err(|e| format!("read body: {e}"))?;

    let resp: Value = serde_json::from_slice(&buf).map_err(|e| format!("parse response: {e}"))?;

    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(resp)
    } else {
        let err = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        Err(err.to_string())
    }
}

/// Verify a JWT and enforce issuer, audience, and token_type requirements.
/// Now runs entirely locally using signing keys loaded from KV.
pub async fn verify_token_scoped(
    token: &str,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
    required_token_type: Option<&str>,
) -> Result<Value, String> {
    let key_store = keys::KeyStore::load()?;
    let verifiers = key_store.all_verifiers();
    let claims = jwt::verify(token, &verifiers)?;

    // Validate iat and nbf
    let now = store::unix_now();
    if let Some(iat) = claims.get("iat").and_then(|v| v.as_u64()) {
        if iat > now + 30 {
            return Err("token iat is in the future".into());
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64()) {
        if nbf > now + 30 {
            return Err("token not yet active (nbf)".into());
        }
    }

    // Revocation check
    if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
        let iat = claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Ok(true) = store::is_user_revoked(sub, iat) {
            return Err("token revoked".into());
        }
    }

    // Issuer check
    if let Some(expected) = expected_issuer {
        let issuer = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if issuer != expected {
            return Err("invalid issuer".into());
        }
    }

    // Audience check
    if let Some(expected) = expected_audience {
        let aud_ok = match claims.get("aud") {
            Some(Value::String(value)) => value == expected,
            Some(Value::Array(values)) => values
                .iter()
                .any(|value| value.as_str() == Some(expected)),
            _ => false,
        };
        if !aud_ok {
            return Err("invalid audience".into());
        }
    }

    // Token type check
    if let Some(expected) = required_token_type {
        let token_type = claims
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if token_type != expected {
            return Err("invalid token type".into());
        }
    }

    Ok(claims)
}

/// Get the JWKS (public keys) — now loaded directly from KV.
pub async fn get_jwks() -> Result<Value, String> {
    let key_store = keys::KeyStore::load()?;
    Ok(key_store.jwks())
}

pub async fn health_status() -> Result<Value, String> {
    let resp = call(&json!({"op": "health_status"})).await?;
    resp.get("data")
        .cloned()
        .ok_or_else(|| "missing health status data".into())
}

/// Import previously saved signing keys into core-service.
pub async fn import_keys(data: &Value) -> Result<(), String> {
    call(&json!({"op": "import_keys", "data": data})).await?;
    Ok(())
}

/// Check rate limit via the imported abuse protection component.
/// Returns (allowed, remaining).
pub async fn check_rate(key: &str, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
    crate::bindings::taika3d::lid::abuse::check_rate(key, limit, window_secs)
}

pub async fn increment_metric(name: &str, labels: &[(&str, &str)]) -> Result<(), String> {
    let label_map: serde_json::Map<String, serde_json::Value> = labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), json!(*v)))
        .collect();
    let _ = call(&json!({
        "op": "metric_increment",
        "name": name,
        "labels": label_map,
    }))
    .await;
    Ok(())
}

pub async fn render_metrics() -> Result<String, String> {
    let resp = call(&json!({ "op": "metrics_render" })).await?;
    resp.get("data")
        .and_then(|d| d.get("text"))
        .and_then(|v| v.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| "missing metrics text".to_string())
}

/// Cross-region lookup: first check local region via authority component,
/// then query remote regions via HTTP if not found.
/// Returns `Some(region_id)` if found, `None` otherwise.
pub async fn lookup_region(email_hash: &str) -> Result<Option<String>, String> {
    let cache_key = format!("region:{}", email_hash);

    // 1. Check in-memory cache
    if let Ok(Some(region)) = crate::store::kv_cache_get::<Option<String>>(&cache_key) {
        return Ok(region);
    }

    // 2. Check local NATS KV via authority component
    let local = crate::bindings::taika3d::lid::authority::lookup(email_hash)?;
    if local.found {
        let region = local.region;
        let _ = crate::store::kv_cache_set(&cache_key, &region, 3600);
        return Ok(region);
    }

    // 3. Not found locally — query each remote region via HTTP.
    // region_internal_urls uses proper hostnames (e.g., eu.lid.internal:8000)
    // that match the remote gateway's virtual-host config, so the Host header
    // derived from the URL is correct automatically.
    let self_region = crate::store::region_id().unwrap_or_default();
    let internal_urls = crate::store::region_internal_urls();

    for (region_name, base_url) in &internal_urls {
        if *region_name == self_region {
            continue;
        }
        let url = format!(
            "{}/internal/lookup?hash={}",
            base_url.trim_end_matches('/'),
            email_hash
        );
        match internal_http_get(&url).await {
            Ok(body) => {
                if let Ok(reply) = serde_json::from_slice::<LookupReply>(&body) {
                    if reply.found {
                        let region = Some(reply.region);
                        let _ = crate::store::kv_cache_set(&cache_key, &region, 3600);
                        return Ok(region);
                    }
                }
            }
            Err(e) => {
                crate::logger::warn(
                    "cross_region.lookup_failed",
                    serde_json::json!({ "region": region_name, "error": e }),
                );
            }
        }
    }

    // Not found anywhere — cache the negative result (shorter TTL)
    let _ = crate::store::kv_cache_set::<Option<String>>(&cache_key, &None, 300);
    Ok(None)
}

#[derive(serde::Deserialize)]
struct LookupReply {
    found: bool,
    region: String,
}

/// HTTP GET for cross-region internal calls. Uses wstd high-level API.
async fn internal_http_get(url: &str) -> Result<Vec<u8>, String> {
    use wstd::http::{Body, Client};

    let mut builder = wstd::http::Request::builder()
        .method(wstd::http::Method::GET)
        .uri(url)
        .header("accept", "application/json");

    // Attach shared secret if configured
    if let Some(secret) = crate::store::internal_auth_secret() {
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
    let mut resp_body = response.into_body();
    let bytes = resp_body
        .contents()
        .await
        .map_err(|e| format!("read body: {e}"))?;

    if !status.is_success() {
        return Err(format!("http {}", status.as_u16()));
    }

    Ok(bytes.to_vec())
}
