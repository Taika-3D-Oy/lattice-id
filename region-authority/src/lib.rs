#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "region-authority",
        path: "wit",
        generate_all,
    });
}

use bindings::exports::taika3d::lid::authority::{Guest, LookupResult};
use bindings::taika3d::lid::keyvalue_nats_cas as kv;
use bindings::taika3d::lid::keyvalue_in_memory as cache_kv;

struct RegionAuthority;

fn sanitize_key(key: &str) -> String {
    key.replace(':', "--").replace('@', "_at_")
}

impl Guest for RegionAuthority {
    /// Check region-wide NATS KV with per-instance in-memory cache.
    /// Cross-region HTTP is handled by oidc-gateway.
    fn lookup(email_hash: String) -> Result<LookupResult, String> {
        let key = sanitize_key(&format!("email:{}", email_hash));

        // 1. Fast path: check per-instance in-memory cache
        if let Ok(cache) = cache_kv::open("lid-authority-cache") {
            if let Ok(Some(_)) = cache.get(&key) {
                return Ok(LookupResult {
                    found: true,
                    region: Some("local".to_string()),
                });
            }
        }

        // 2. Check region-wide NATS JetStream KV (shared across all instances)
        let idx_bucket = kv::open("lid-user-idx")
            .map_err(|e| format!("failed to open region index: {e:?}"))?;

        if idx_bucket.exists(&key).map_err(|e| format!("{e:?}"))? {
            // Populate cache for next time (value doesn't matter, just presence)
            if let Ok(cache) = cache_kv::open("lid-authority-cache") {
                let _ = cache.set(&key, b"1");
            }
            return Ok(LookupResult {
                found: true,
                region: Some("local".to_string()),
            });
        }

        Ok(LookupResult { found: false, region: None })
    }
}

bindings::export!(RegionAuthority with_types_in bindings);
