#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "abuse-protection",
        path: "wit",
        async: [
            "import:wasmcloud:messaging/consumer@0.2.0#request",
            "export:taika3d:lid/abuse#check-rate",
            "export:taika3d:lid/abuse#record-metric",
        ],
        generate_all,
    });
}

use base64::Engine;
use bindings::exports::taika3d::lid::abuse::Guest;
use bindings::wasi::config::store as config_store;
use bindings::wasmcloud::messaging::consumer;

struct AbuseProtection;

const TIMEOUT_MS: u32 = 5000;

fn rate_limits_table() -> String {
    "abuse-rate-limits".to_string()
}

/// Build a lattice-db NATS subject from the configured instance prefix.
/// Reads `ldb_instance` config (defaults to `"lid"`).
fn ldb_subject(op: &str) -> String {
    let instance = config_store::get("ldb_instance")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "lid".to_string());
    format!("{instance}.{op}")
}

/// Send a JSON request to lattice-db via wasmcloud:messaging and parse the response.
async fn ldb_request(
    subject: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::to_vec(payload).map_err(|e| format!("serialize: {e}"))?;
    let resp = consumer::request(subject.to_string(), body, TIMEOUT_MS).await?;
    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("parse response: {e}"))?;
    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }
    Ok(val)
}

impl Guest for AbuseProtection {
    async fn check_rate(key: String, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();

        // Bucket key: rate:{key}:{window_start}
        // Each window is a counter stored in lattice-db with TTL.
        let window_start = now - (now % window_secs);
        let db_key = format!("rate:{}:{}", key, window_start);
        let table = rate_limits_table();

        // Retry loop to ensure the increment is actually recorded
        const MAX_RETRIES: usize = 5;
        for _attempt in 0..MAX_RETRIES {
            // Read current counter with revision
            let payload = serde_json::json!({ "table": table, "key": db_key });
            let (count, revision) = match ldb_request(&ldb_subject("get"), &payload).await {
                Ok(resp) => {
                    let value_b64 = resp.get("value").and_then(|v| v.as_str()).unwrap_or("MA==");
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(value_b64)
                        .unwrap_or_default();
                    let count_str = String::from_utf8_lossy(&bytes);
                    let count: u64 = count_str.trim().parse().unwrap_or(0);
                    let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
                    (count, revision)
                }
                Err(e) if e.contains("not found") => (0u64, 0u64),
                Err(e) => return Err(format!("rate limit get: {e}")),
            };

            if count >= limit {
                return Ok((false, 0));
            }

            // Increment counter via CAS (or create if first hit)
            let new_count = (count + 1).to_string();
            let new_value = base64::engine::general_purpose::STANDARD.encode(new_count.as_bytes());

            if revision == 0 {
                // First hit in this window — atomic create with TTL
                let payload = serde_json::json!({
                    "table": table,
                    "key": db_key,
                    "value": new_value,
                    "ttl_seconds": window_secs + 10,
                });
                match ldb_request(&ldb_subject("create"), &payload).await {
                    Ok(_) => return Ok((true, limit - count - 1)),
                    Err(e) if e.contains("already exists") => {
                        continue; // retry — re-read the real count and CAS
                    }
                    Err(e) => return Err(format!("rate limit create: {e}")),
                }
            } else {
                // Existing counter — CAS update
                let payload = serde_json::json!({
                    "table": table,
                    "key": db_key,
                    "value": new_value,
                    "revision": revision,
                });
                match ldb_request(&ldb_subject("cas"), &payload).await {
                    Ok(_) => return Ok((true, limit - count - 1)),
                    Err(e) if e.contains("revision mismatch") => {
                        continue; // retry with fresh revision
                    }
                    Err(e) => return Err(format!("rate limit cas: {e}")),
                }
            }
        }

        // If all retries exhausted, allow the request but don't increment
        // (fail-open to avoid blocking legitimate traffic)
        Ok((true, 0))
    }

    async fn record_metric(_name: String, _labels: Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
}

bindings::export!(AbuseProtection with_types_in bindings);
