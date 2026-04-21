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

// ── Passkey management ──────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub name: String,
    pub created_at: u64,
    pub sign_count: u32,
}

pub async fn fetch_passkeys(token: &str, user_id: &str) -> Result<Vec<PasskeyInfo>> {
    let resp = Request::get(&format!("/api/users/{user_id}/passkeys"))
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn delete_passkey(token: &str, user_id: &str, cred_id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/users/{user_id}/passkeys/{cred_id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        return Err(err(format!("HTTP {}", resp.status())));
    }
    Ok(())
}

/// Start passkey registration — returns { token, publicKey }.
pub async fn passkey_register_options(token: &str, user_id: &str) -> Result<serde_json::Value> {
    let resp = Request::post(&format!("/api/users/{user_id}/passkeys/register-options"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| err(e.to_string()))?
        .send()
        .await
        .map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "request failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

/// Complete passkey registration with the WebAuthn attestation.
pub async fn passkey_register_complete(
    token: &str,
    user_id: &str,
    reg_token: &str,
    client_data_json: &str,
    attestation_object: &str,
    name: &str,
) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "token": reg_token,
        "clientDataJSON": client_data_json,
        "attestationObject": attestation_object,
        "name": name,
    });
    let resp = Request::post(&format!("/api/users/{user_id}/passkeys/register-complete"))
        .header("Authorization", &format!("Bearer {token}"))
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
    resp.json().await.map_err(|e| err(e.to_string()))
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

// ── Tenants (new) ───────────────────────────────────────────

pub async fn fetch_tenants(token: &str) -> Result<Vec<Tenant>> {
    let resp = Request::get("/api/tenants")
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

#[derive(Serialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub display_name: String,
}

pub async fn create_tenant(token: &str, req: &CreateTenantRequest) -> Result<Tenant> {
    let resp = Request::post("/api/tenants")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "create failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn delete_tenant(token: &str, id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/tenants/{id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TenantMember {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub joined_at: u64,
}

pub async fn fetch_tenant_members(token: &str, tenant_id: &str) -> Result<Vec<TenantMember>> {
    let resp = Request::get(&format!("/api/tenants/{tenant_id}/users"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn remove_tenant_member(token: &str, tenant_id: &str, user_id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/tenants/{tenant_id}/users/{user_id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    Ok(())
}

#[derive(Serialize)]
pub struct InviteRequest { pub email: String, pub role: String }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteResponse {
    pub email: String,
    pub role: String,
    pub invite_token: String,
    pub expires_at: u64,
}

pub async fn invite_to_tenant(token: &str, tenant_id: &str, req: &InviteRequest) -> Result<InviteResponse> {
    let resp = Request::post(&format!("/api/tenants/{tenant_id}/users/invite"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "invite failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

// ── Hooks (new) ──────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hook {
    pub id: String,
    pub name: String,
    pub trigger: String,
    pub script: String,
    pub enabled: bool,
    pub priority: i32,
    pub version: u32,
    pub script_hash: String,
    pub created_at: u64,
    #[serde(default)] pub updated_by: String,
    #[serde(default)] pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HookTestResult {
    pub success: bool,
    #[serde(default)] pub deny_reason: Option<String>,
    #[serde(default)] pub set_superadmin: Option<bool>,
    #[serde(default)] pub add_to_tenants: Option<Vec<String>>,
    #[serde(default)] pub extra_claims: Option<serde_json::Value>,
    #[serde(default)] pub log_messages: Option<Vec<String>>,
    #[serde(default)] pub error: Option<String>,
}

#[derive(Serialize)]
pub struct CreateHookRequest { pub name: String, pub trigger: String, pub script: String, pub enabled: bool, pub priority: i32 }

#[derive(Serialize)]
pub struct UpdateHookRequest { pub name: String, pub trigger: String, pub script: String, pub enabled: bool, pub priority: i32 }

pub async fn fetch_hooks(token: &str) -> Result<Vec<Hook>> {
    let resp = Request::get("/api/hooks")
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn create_hook(token: &str, req: &CreateHookRequest) -> Result<Hook> {
    let resp = Request::post("/api/hooks")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "create failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn update_hook(token: &str, id: &str, req: &UpdateHookRequest) -> Result<Hook> {
    let resp = Request::put(&format!("/api/hooks/{id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "update failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn delete_hook(token: &str, id: &str) -> Result<()> {
    let resp = Request::delete(&format!("/api/hooks/{id}"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    Ok(())
}

pub async fn test_hook(token: &str, id: &str) -> Result<HookTestResult> {
    let resp = Request::post(&format!("/api/hooks/{id}/test"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "test failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn fetch_hook_versions(token: &str, id: &str) -> Result<Vec<HookVersion>> {
    let resp = Request::get(&format!("/api/hooks/{id}/versions"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

// ── Settings (new) ───────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSettings { pub allow_registration: bool }

#[derive(Serialize)]
pub struct UpdateSettingsRequest { pub allow_registration: bool }

pub async fn fetch_settings(token: &str) -> Result<AppSettings> {
    let resp = Request::get("/api/settings")
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn update_settings(token: &str, req: &UpdateSettingsRequest) -> Result<AppSettings> {
    let resp = Request::put("/api/settings")
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(req).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "update failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

// ── MFA setup (new) ──────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaSetup { pub secret: String, pub otpauth_uri: String }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MfaConfirm { pub enabled: bool, pub recovery_codes: Vec<String> }

pub async fn get_mfa_setup(token: &str, user_id: &str) -> Result<MfaSetup> {
    let resp = Request::get(&format!("/api/users/{user_id}/mfa/setup"))
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn confirm_mfa(token: &str, user_id: &str, code: &str) -> Result<MfaConfirm> {
    let body = serde_json::json!({ "code": code });
    let resp = Request::post(&format!("/api/users/{user_id}/mfa/confirm"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "confirm failed".into());
        return Err(err(msg));
    }
    resp.json().await.map_err(|e| err(e.to_string()))
}

pub async fn send_password_reset(token: &str, user_id: &str) -> Result<()> {
    let resp = Request::post(&format!("/api/users/{user_id}/password-reset"))
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| err(e.to_string()))?.send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
    Ok(())
}

// ── Audit with filters (new) ─────────────────────────────────

#[derive(Default)]
pub struct AuditFilters {
    pub actor_id:   Option<String>,
    pub target_id:  Option<String>,
    pub event_type: Option<String>,
    pub since:      Option<u64>,
    pub until:      Option<u64>,
    pub limit:      Option<u32>,
}

pub async fn fetch_audit_log_filtered(token: &str, filters: &AuditFilters) -> Result<Vec<AuditEntry>> {
    let mut url = "/api/audit?_=1".to_string();
    if let Some(ref v) = filters.actor_id   { url.push_str(&format!("&actor_id={v}"));   }
    if let Some(ref v) = filters.target_id  { url.push_str(&format!("&target_id={v}"));  }
    if let Some(ref v) = filters.event_type { url.push_str(&format!("&event_type={v}")); }
    if let Some(v) = filters.since  { url.push_str(&format!("&since={v}"));  }
    if let Some(v) = filters.until  { url.push_str(&format!("&until={v}"));  }
    if let Some(v) = filters.limit  { url.push_str(&format!("&limit={v}"));  }
    let resp = Request::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send().await.map_err(|e| err(e.to_string()))?;
    if !resp.ok() { return Err(err(format!("HTTP {}", resp.status()))); }
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

pub fn relative_time(ts: u64) -> String {
    if ts == 0 { return "\u{2014}".into(); }
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let diff = now.saturating_sub(ts);
    if diff < 60           { "just now".into() }
    else if diff < 3_600   { format!("{}m ago", diff / 60) }
    else if diff < 86_400  { format!("{}h ago", diff / 3_600) }
    else if diff < 2_592_000 { format!("{}d ago", diff / 86_400) }
    else { format_timestamp(ts) }
}
