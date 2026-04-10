use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

// ── Data types (mirror oidc-gateway management API responses) ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub name: String,
    #[serde(default)]
    pub theme: Option<ClientTheme>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientTheme {
    pub app_name: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub primary_color: Option<String>,
    #[serde(default)]
    pub background_color: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub status: String,
    pub created_at: u64,
    #[serde(default)]
    pub totp_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: String,
    pub provider_type: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_type: String,
    pub actor: String,
    pub detail: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct CreateClientRequest {
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<ClientTheme>,
}

#[derive(Serialize)]
pub struct CreateIdpRequest {
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub enabled: bool,
}

// ── API error type ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApiError(pub String);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type Result<T> = std::result::Result<T, ApiError>;

fn err(msg: impl Into<String>) -> ApiError {
    ApiError(msg.into())
}

// ── Bootstrap ───────────────────────────────────────────────

pub async fn check_bootstrap() -> Result<bool> {
    let resp = Request::get("/api/bootstrap/status")
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if resp.status() >= 500 {
        return Err(err(format!("backend not ready (HTTP {})", resp.status())));
    }
    if !resp.ok() {
        return Ok(false);
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| err(e.to_string()))?;
    Ok(body.get("needs_bootstrap").and_then(|v| v.as_bool()).unwrap_or(false))
}

pub async fn submit_bootstrap(email: &str, name: &str, password: &str) -> Result<()> {
    let body = serde_json::json!({ "email": email, "password": password, "name": name });
    let resp = Request::post("/register")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "registration failed".into());
        return Err(err(msg));
    }
    Ok(())
}

// ── Clients ─────────────────────────────────────────────────

pub async fn fetch_clients(token: &str) -> Result<Vec<OidcClient>> {
    let resp = Request::get("/api/clients")
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn create_client(token: &str, req: &CreateClientRequest) -> Result<OidcClient> {
    let resp = Request::post("/api/clients")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "create failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

// ── Users ───────────────────────────────────────────────────

pub async fn fetch_users(token: &str) -> Result<Vec<User>> {
    let tenants: Vec<Tenant> = {
        let resp = Request::get("/api/tenants")
            .header("Authorization", &format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        if !resp.ok() {
            return Err(err(format!("HTTP {}", resp.status())));
        }
        resp.json().await.map_err(|e| err(e.to_string()))?
    };

    let mut all_users = Vec::new();
    for tenant in &tenants {
        let resp = Request::get(&format!("/api/tenants/{}/users", tenant.id))
            .header("Authorization", &format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| err(e.to_string()))?;
        if resp.ok() {
            if let Ok(mut users) = resp.json::<Vec<User>>().await {
                all_users.append(&mut users);
            }
        }
    }
    Ok(all_users)
}

// ── Identity Providers ──────────────────────────────────────

pub async fn fetch_identity_providers(token: &str) -> Result<Vec<IdentityProvider>> {
    let resp = Request::get("/api/identity-providers")
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn create_identity_provider(token: &str, req: &CreateIdpRequest) -> Result<IdentityProvider> {
    let resp = Request::post("/api/identity-providers")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "create failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn delete_identity_provider(token: &str, id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/identity-providers/{id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    Ok(())
}

// ── MFA management ──────────────────────────────────────────

pub async fn disable_user_mfa(token: &str, user_id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/users/{user_id}/mfa"))
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    Ok(())
}

// ── Audit Log ───────────────────────────────────────────────

pub async fn fetch_audit_log(token: &str) -> Result<Vec<AuditEntry>> {
    let resp = Request::get("/api/audit")
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

// ── Helpers ─────────────────────────────────────────────────

pub fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return "\u{2014}".into();
    }
    let total_secs = ts;
    let days = total_secs / 86400;
    let years = 1970 + days / 365;
    let remaining = days % 365;
    let months = remaining / 30 + 1;
    let day = remaining % 30 + 1;
    let time_secs = total_secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    format!("{years}-{months:02}-{day:02} {hours:02}:{minutes:02}")
}
