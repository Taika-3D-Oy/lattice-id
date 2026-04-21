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

struct RegionAuthority;

fn user_idx_table() -> String {
    let prefix = config_store::get("kv_prefix")
        .ok()
        .flatten()
        .unwrap_or_else(|| "lid".to_string());
    format!("{prefix}-user-idx")
}

fn ldb_tenant() -> Option<String> {
    config_store::get("ldb_tenant")
        .ok()
        .flatten()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Check lattice-db for the email index entry.
async fn email_exists_in_db(email_hash: &str) -> bool {
    let key = format!("email:{email_hash}");
    let mut payload = serde_json::json!({
        "table": user_idx_table(),
        "key": key,
    });
    if let Some(tenant) = ldb_tenant() {
        payload
            .as_object_mut()
            .unwrap()
            .insert("_partition".to_string(), serde_json::Value::String(tenant));
    }
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    match consumer::request("ldb.exists".to_string(), body, 2000).await {
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
