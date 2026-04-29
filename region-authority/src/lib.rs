#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "region-authority",
        path: "wit",
        async: [
            "import:wasmcloud:messaging/consumer@0.2.0#request",
            "export:taika3d:lid/authority#lookup",
        ],
        generate_all,
    });
}

use bindings::exports::taika3d::lid::authority::{Guest, LookupResult};
use bindings::wasi::config::store as config_store;
use bindings::wasmcloud::messaging::consumer;

use std::cell::RefCell;
use std::collections::HashMap;

struct RegionAuthority;

thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

fn user_idx_table() -> String {
    "user-idx".to_string()
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

/// Check lattice-db for the email index entry.
async fn email_exists_in_db(email_hash: &str) -> bool {
    let key = format!("email:{email_hash}");
    let table = user_idx_table();
    let mut payload = serde_json::json!({
        "table": table,
        "key": key,
    });
    // Inject consistency context if available.
    let min_rev = SESSION_REVISIONS.with(|sr| sr.borrow().get(&table).copied());
    if let Some(rev) = min_rev {
        payload.as_object_mut().unwrap().insert(
            "consistency".to_string(),
            serde_json::json!({ "min_revision": rev }),
        );
    }
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    match consumer::request(ldb_subject("exists"), body, 2000).await {
        Ok(msg) => {
            if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&msg.body) {
                resp.get("exists")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

impl Guest for RegionAuthority {
    async fn lookup(email_hash: String) -> Result<LookupResult, String> {
        if email_exists_in_db(&email_hash).await {
            Ok(LookupResult {
                found: true,
                region: Some("local".to_string()),
            })
        } else {
            Ok(LookupResult {
                found: false,
                region: None,
            })
        }
    }
}

bindings::export!(RegionAuthority with_types_in bindings);
