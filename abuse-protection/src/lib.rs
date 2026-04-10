#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "abuse-protection",
        path: "wit",
    });
}

use bindings::exports::taika3d::lid::abuse::Guest;
use bindings::taika3d::lid::keyvalue_nats_cas as kv;
use serde::{Deserialize, Serialize};

struct AbuseProtection;

/// Sanitize a key for NATS JetStream KV compatibility.
/// NATS KV keys only allow: A-Z, a-z, 0-9, '-', '_', '/', '=', '.' (middle only).
fn sanitize_key(key: &str) -> String {
    key.replace(':', "--").replace('@', "_at_")
}

#[derive(Serialize, Deserialize, Default)]
struct WindowState {
    timestamps: Vec<u64>,
}

impl Guest for AbuseProtection {
    fn check_rate(key: String, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
        let key = sanitize_key(&key);
        let bucket = kv::open("lid-abuse-rate-limits")
            .map_err(|e| format!("failed to open bucket: {e:?}"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        
        let cutoff = now.saturating_sub(window_secs);

        // Optimistic concurrency control retry loop
        for _ in 0..10 {
            let entry = bucket.get(&key)
                .map_err(|e| format!("get failed: {e:?}"))?;
            
            let (mut state, revision) = if let Some(e) = &entry {
                let s = serde_json::from_slice::<WindowState>(&e.value)
                    .map_err(|e| format!("parse failed: {e}"))?;
                (s, Some(e.revision))
            } else {
                (WindowState::default(), None)
            };

            // Remove expired entries
            state.timestamps.retain(|&t| t > cutoff);

            let count = state.timestamps.len() as u64;
            if count >= limit {
                return Ok((false, 0));
            }

            // In-memory sliding window: push CURRENT timestamp
            state.timestamps.push(now);
            
            let new_data = serde_json::to_vec(&state)
                .map_err(|e| format!("serialize failed: {e}"))?;

            // Atomic CAS using revision
            let result = match revision {
                Some(rev) => bucket.swap(&key, &new_data, rev),
                None => bucket.create(&key, &new_data),
            };

            match result {
                Ok(_new_rev) => {
                    return Ok((true, limit - count - 1));
                }
                Err(kv::Error::RevisionMismatch) | Err(kv::Error::KeyExists) => {
                    // Contention, retry
                    continue;
                }
                Err(e) => return Err(format!("swap failed: {e:?}")),
            }
        }

        Err("too much contention on rate limit key".to_string())
    }

    fn record_metric(_name: String, _labels: Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
}

bindings::export!(AbuseProtection with_types_in bindings);
