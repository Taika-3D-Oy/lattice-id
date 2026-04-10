use serde_json::Value;
use wstd::http::{Body, Response, StatusCode};

use crate::store::{self, IdentityProvider, Invitation, Membership, Tenant};

// ── Auth helpers ────────────────────────────────────────────

/// Extract and verify Bearer token, returning JWT claims.
pub(crate) async fn require_auth(auth_header: Option<&str>) -> Result<Value, String> {
    let header = auth_header.ok_or("missing Authorization header")?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or("invalid Authorization header")?;
    crate::service_client::verify_token_scoped(
        token,
        Some(&crate::get_issuer()),
        Some("lid-admin"),
        Some("access"),
    )
    .await
}

/// Check that claims have the "superadmin" role (no tenant scope).
pub(crate) fn require_superadmin(claims: &Value) -> Result<(), String> {
    let role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if role == "superadmin" {
        Ok(())
    } else {
        Err("forbidden: superadmin role required".into())
    }
}

/// Check that the caller has at least the given role for a specific tenant.
fn require_tenant_role(claims: &Value, tenant_id: &str, min_role: &str) -> Result<(), String> {
    if claim_has_tenant_role(claims, tenant_id, min_role) {
        return Ok(());
    }
    Err(format!("forbidden: requires {min_role} role or higher"))
}

pub(crate) fn claim_has_tenant_role(claims: &Value, tenant_id: &str, min_role: &str) -> bool {
    let caller_role = get_caller_tenant_role(claims, tenant_id);
    role_level(caller_role) >= role_level(min_role)
}

pub(crate) fn role_level(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "manager" => 2,
        "member" => 1,
        _ => 0,
    }
}

pub(crate) fn get_caller_tenant_role<'a>(claims: &'a Value, tenant_id: &str) -> &'a str {
    let global_role = claims.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if global_role == "superadmin" {
        return "owner"; // effectively
    }

    if claims
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .is_some_and(|claim_tenant| claim_tenant == tenant_id)
    {
        return global_role;
    }

    claims
        .get("tenants")
        .and_then(|v| v.as_array())
        .and_then(|tenants| {
            tenants.iter().find(|tenant| {
                tenant.get("tenant_id").and_then(|v| v.as_str()) == Some(tenant_id)
            })
        })
        .and_then(|t| t.get("role").and_then(|v| v.as_str()))
        .unwrap_or("")
}

// ── Tenant endpoints ────────────────────────────────────────

/// GET /api/tenants
pub async fn list_tenants(auth: Option<&str>) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let tenants = store::list_tenants()?;
    let list: Vec<Value> = tenants
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "display_name": t.display_name,
                "status": t.status,
                "created_at": t.created_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// GET /api/audit?actor_id=...&target_id=...&event_type=...&since=...&until=...&limit=...
pub async fn list_audit_events(auth: Option<&str>, query: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let params = crate::util::parse_query(query);
    let get = |key: &str| -> Option<&str> {
        params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let actor_id = get("actor_id").filter(|value| !value.is_empty());
    let target_id = get("target_id").filter(|value| !value.is_empty());
    let event_type = get("event_type").filter(|value| !value.is_empty());
    let since = match get("since") {
        Some(value) => Some(value.parse::<u64>().map_err(|_| "invalid since")?),
        None => None,
    };
    let until = match get("until") {
        Some(value) => Some(value.parse::<u64>().map_err(|_| "invalid until")?),
        None => None,
    };
    if let (Some(lower), Some(upper)) = (since, until)
        && lower > upper
    {
        return Err("invalid time range: since must be <= until".into());
    }

    let requested_limit = match get("limit") {
        Some(value) => value.parse::<usize>().map_err(|_| "invalid limit")?,
        None => 100,
    };
    if requested_limit == 0 {
        return Err("limit must be at least 1".into());
    }
    let limit = requested_limit.min(500);

    let events = store::list_audit_events(actor_id, target_id, event_type, since, until, limit)?;
    let body = serde_json::json!({
        "events": events,
        "filters": {
            "actor_id": actor_id,
            "target_id": target_id,
            "event_type": event_type,
            "since": since,
            "until": until,
            "limit": limit,
        }
    });
    json_ok(&body)
}

/// POST /api/tenants
pub async fn create_tenant(auth: Option<&str>, body: &[u8]) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        display_name: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() {
        return Err("name is required".into());
    }
    if req.name.len() > 128 {
        return Err("name too long (max 128 characters)".into());
    }
    if req.display_name.len() > 256 {
        return Err("display_name too long (max 256 characters)".into());
    }

    let tenant = Tenant {
        id: store::random_hex(16),
        name: req.name,
        display_name: req.display_name,
        status: "active".to_string(),
        created_at: store::unix_now(),
    };
    store::create_tenant(&tenant)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("tenant_created", sub, &tenant.id, &tenant.name);

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": tenant.id,
            "name": tenant.name,
            "display_name": tenant.display_name,
            "status": tenant.status,
        }),
    )
}

/// GET /api/tenants/:id
pub async fn get_tenant(auth: Option<&str>, tenant_id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let tenant = store::get_tenant(tenant_id)?.ok_or("tenant not found")?;
    json_ok(&serde_json::json!({
        "id": tenant.id,
        "name": tenant.name,
        "display_name": tenant.display_name,
        "status": tenant.status,
        "created_at": tenant.created_at,
    }))
}

/// DELETE /api/tenants/:id
pub async fn delete_tenant(auth: Option<&str>, tenant_id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    store::get_tenant(tenant_id)?.ok_or("tenant not found")?;
    store::delete_tenant(tenant_id)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("tenant_deleted", sub, tenant_id, "");

    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Tenant user/membership endpoints ────────────────────────

/// GET /api/tenants/:id/users
pub async fn list_tenant_users(
    auth: Option<&str>,
    tenant_id: &str,
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    let members = store::list_tenant_members(tenant_id)?;
    let mut users = Vec::new();
    for m in &members {
        if let Some(user) = store::get_user(&m.user_id)? {
            users.push(serde_json::json!({
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": m.role,
                "joined_at": m.joined_at,
            }));
        }
    }

    json_ok(&serde_json::json!(users))
}

/// POST /api/tenants/:id/users — add existing user to tenant
pub async fn add_tenant_user(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    #[derive(serde::Deserialize)]
    struct Req {
        user_id: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["owner", "admin", "manager", "member"].contains(&req.role.as_str()) {
        return Err("invalid role (must be owner, admin, manager, or member)".into());
    }

    // Hierarchy check: cannot assign a role higher than your own
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    if role_level(&req.role) > role_level(caller_role) {
        return Err(format!(
            "forbidden: cannot assign role {} which is higher than your role {}",
            req.role, caller_role
        ));
    }

    store::get_tenant(tenant_id)?.ok_or("tenant not found")?;
    store::get_user(&req.user_id)?.ok_or("user not found")?;

    if store::get_membership(tenant_id, &req.user_id)?.is_some() {
        return Err("user is already a member of this tenant".into());
    }

    let membership = Membership {
        tenant_id: tenant_id.to_string(),
        user_id: req.user_id.clone(),
        role: req.role.clone(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "user_added_to_tenant",
        sub,
        &req.user_id,
        &format!("tenant:{tenant_id} role:{}", req.role),
    );

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "tenant_id": tenant_id,
            "user_id": req.user_id,
            "role": req.role,
        }),
    )
}

/// DELETE /api/tenants/:tid/users/:uid
pub async fn remove_tenant_user(
    auth: Option<&str>,
    tenant_id: &str,
    user_id: &str,
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    let membership = store::get_membership(tenant_id, user_id)?.ok_or("membership not found")?;

    // Hierarchy check: cannot remove someone with a role higher or equal to yours,
    // unless you are superadmin.
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    let target_role = membership.role.as_str();

    // Special case: can always remove yourself.
    let caller_sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if caller_sub != user_id
        && claims.get("role").and_then(|v| v.as_str()) != Some("superadmin")
        && role_level(target_role) >= role_level(caller_role)
    {
        return Err(format!(
            "forbidden: cannot remove user with role {} (you are {})",
            target_role, caller_role
        ));
    }

    store::remove_membership(tenant_id, user_id)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "user_removed_from_tenant",
        sub,
        user_id,
        &format!("tenant:{tenant_id}"),
    );

    json_ok(&serde_json::json!({"removed": true}))
}

/// POST /api/tenants/:id/users/invite
pub async fn invite_user(
    auth: Option<&str>,
    tenant_id: &str,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_tenant_role(&claims, tenant_id, "manager")?;

    #[derive(serde::Deserialize)]
    struct Req {
        email: String,
        role: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["admin", "manager", "member"].contains(&req.role.as_str()) {
        return Err("invalid role for invitation".into());
    }

    // Hierarchy check: cannot invite someone to a role higher than your own
    let caller_role = get_caller_tenant_role(&claims, tenant_id);
    if role_level(&req.role) > role_level(caller_role) {
        return Err(format!(
            "forbidden: cannot invite to role {} which is higher than your role {}",
            req.role, caller_role
        ));
    }

    store::get_tenant(tenant_id)?.ok_or("tenant not found")?;

    let inviter_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let invitation = Invitation {
        tenant_id: tenant_id.to_string(),
        email: req.email.clone(),
        role: req.role.clone(),
        token: store::random_hex(32),
        invited_by: inviter_id.to_string(),
        expires_at: store::unix_now() + 86400 * 7, // 7 days
    };
    store::save_invitation(&invitation)?;

    // Publish invitation email event
    let tenant_display = crate::store::get_tenant(tenant_id)
        .ok()
        .flatten()
        .map(|t| t.display_name)
        .unwrap_or_else(|| tenant_id.to_string());
    crate::email::send_invitation_email(
        &crate::get_issuer(),
        &req.email,
        &invitation.token,
        &tenant_display,
        &req.role,
    );

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "email": req.email,
            "role": req.role,
            "invite_token": invitation.token,
            "expires_at": invitation.expires_at,
        }),
    )
}

/// POST /api/invitations/accept — accept an invitation token
pub async fn accept_invitation(body: &[u8]) -> Result<Response<Body>, String> {
    #[derive(serde::Deserialize)]
    struct Req {
        token: String,
        user_id: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let inv = store::get_invitation(&req.token)?.ok_or("invalid or expired invitation")?;

    if store::unix_now() > inv.expires_at {
        store::delete_invitation(&req.token)?;
        return Err("invitation expired".into());
    }

    // Verify user exists and email matches
    let user = store::get_user(&req.user_id)?.ok_or("user not found")?;
    if user.email.to_lowercase() != inv.email.to_lowercase() {
        return Err("email does not match invitation".into());
    }

    // Create membership
    let membership = Membership {
        tenant_id: inv.tenant_id.clone(),
        user_id: req.user_id.clone(),
        role: inv.role.clone(),
        joined_at: store::unix_now(),
    };
    store::add_membership(&membership)?;
    store::delete_invitation(&req.token)?;

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "tenant_id": inv.tenant_id,
            "user_id": req.user_id,
            "role": inv.role,
        }),
    )
}

// ── Client endpoints ────────────────────────────────────────

/// GET /api/clients
pub async fn list_clients(auth: Option<&str>) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let clients = store::list_clients()?;
    let list: Vec<Value> = clients
        .iter()
        .map(|c| {
            serde_json::json!({
                "client_id": c.client_id,
                "name": c.name,
                "redirect_uris": c.redirect_uris,
                "grant_types": c.grant_types,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/clients
pub async fn create_client(auth: Option<&str>, body: &[u8]) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        redirect_uris: Vec<String>,
        grant_types: Option<Vec<String>>,
        #[serde(default)]
        confidential: bool,
        #[serde(default)]
        theme: Option<store::ClientTheme>,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() {
        return Err("name is required".into());
    }
    if req.redirect_uris.is_empty() {
        return Err("at least one redirect_uri is required".into());
    }
    // Validate redirect URI schemes
    for uri in &req.redirect_uris {
        if !uri.starts_with("http://") && !uri.starts_with("https://") {
            return Err("redirect_uris must use http or https scheme".into());
        }
    }

    let client_secret = if req.confidential {
        Some(store::random_hex(32))
    } else {
        None
    };

    let client = store::OidcClient {
        client_id: store::random_hex(16),
        client_secret: client_secret.clone(),
        name: req.name,
        redirect_uris: req.redirect_uris,
        grant_types: req.grant_types.unwrap_or_else(|| {
            vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ]
        }),
        theme: req.theme,
    };
    store::save_client(&client)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("client_created", sub, &client.client_id, &client.name);

    let mut resp = serde_json::json!({
        "client_id": client.client_id,
        "name": client.name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
    });
    // Only show secret once at creation time
    if let Some(secret) = client_secret {
        resp["client_secret"] = serde_json::json!(secret);
    }

    json_response(StatusCode::CREATED, &resp)
}

// ── Password reset initiation ───────────────────────────────

/// POST /api/users/:id/password-reset
pub async fn initiate_password_reset(
    auth: Option<&str>,
    user_id: &str,
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    // Rate limit password reset initiation: 3 per hour per user_id
    match crate::service_client::check_rate(&format!("reset_init:{}", user_id), 3, 3600).await {
        Ok((false, _)) => return Err("too many reset requests. please try again later.".into()),
        Err(e) => crate::logger::error_message("rate_limit.password_reset_init_check_failed", e),
        _ => {}
    }

    let user = store::get_user(user_id)?.ok_or("user not found")?;

    let reset_token = store::random_hex(32);
    // Store as a short-lived invitation-like entry
    let inv = Invitation {
        tenant_id: String::new(),
        email: user.email.clone(),
        role: "password_reset".to_string(),
        token: reset_token.clone(),
        invited_by: claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("system")
            .to_string(),
        expires_at: store::unix_now() + 3600, // 1 hour
    };
    store::save_invitation(&inv)?;

    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();
    let _ = store::log_audit("password_reset_initiated", &sub, user_id, &user.email);

    // Publish password reset email event
    crate::email::send_password_reset_email(
        &crate::get_issuer(),
        &user.email,
        &user.name,
        &reset_token,
    );

    json_ok(&serde_json::json!({
        "user_id": user_id,
        "email": user.email,
        "reset_token": reset_token,
        "expires_in": 3600,
    }))
}

// ── Settings management ─────────────────────────────────────

/// GET /api/settings — read current runtime settings (superadmin only)
pub async fn get_settings(auth: Option<&str>) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let settings = store::get_runtime_settings();
    json_ok(&serde_json::json!({
        "allow_registration": settings.allow_registration,
    }))
}

/// PUT /api/settings — update runtime settings (superadmin only)
pub async fn update_settings(
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        #[serde(default)]
        allow_registration: Option<bool>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut settings = store::get_runtime_settings();

    if let Some(v) = req.allow_registration {
        settings.allow_registration = v;
    }

    store::save_runtime_settings(&settings)?;

    let actor = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let _ = store::log_audit(
        "settings_updated",
        actor,
        "settings:global",
        &serde_json::to_string(&serde_json::json!({
            "allow_registration": settings.allow_registration,
        }))
        .unwrap_or_default(),
    );

    json_ok(&serde_json::json!({
        "allow_registration": settings.allow_registration,
    }))
}

// ── Response helpers ────────────────────────────────────────

fn json_ok(value: &Value) -> Result<Response<Body>, String> {
    json_response(StatusCode::OK, value)
}

fn json_response(status: StatusCode, value: &Value) -> Result<Response<Body>, String> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(value).unwrap_or_default().into())
        .unwrap())
}

// ── MFA management ──────────────────────────────────────────

/// POST /api/users/:id/mfa/setup — generate TOTP secret and return QR URI.
pub async fn mfa_setup(auth: Option<&str>, user_id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let mut user = store::get_user(user_id)?.ok_or("user not found")?;
    if user.totp_enabled {
        return Err("MFA is already enabled".into());
    }

    let secret = crate::totp::generate_secret();
    let issuer = crate::get_issuer();
    let otpauth_uri = crate::totp::otpauth_uri(&secret, &user.email, &issuer);

    // Store secret but don't enable yet (requires confirm step)
    user.totp_secret = Some(secret.clone());
    store::update_user(&user)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_setup_started", sub, user_id, "");

    json_ok(&serde_json::json!({
        "secret": secret,
        "otpauth_uri": otpauth_uri,
    }))
}

/// POST /api/users/:id/mfa/confirm — verify TOTP code and enable MFA.
pub async fn mfa_confirm(
    auth: Option<&str>,
    user_id: &str,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    #[derive(serde::Deserialize)]
    struct Req {
        code: String,
    }
    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    let mut user = store::get_user(user_id)?.ok_or("user not found")?;
    let secret = user
        .totp_secret
        .as_deref()
        .ok_or("MFA setup not started — call /mfa/setup first")?;

    if !crate::totp::verify_totp(secret, req.code.trim()) {
        return Err("invalid TOTP code".into());
    }

    // Enable MFA and generate recovery codes
    let recovery_codes = crate::totp::generate_recovery_codes();
    user.totp_enabled = true;
    user.recovery_codes = recovery_codes.clone();
    store::update_user(&user)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_enabled", sub, user_id, "");

    json_ok(&serde_json::json!({
        "enabled": true,
        "recovery_codes": recovery_codes,
    }))
}

/// DELETE /api/users/:id/mfa — disable MFA for a user.
pub async fn mfa_disable(auth: Option<&str>, user_id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_self_or_superadmin(&claims, user_id)?;

    let mut user = store::get_user(user_id)?.ok_or("user not found")?;
    user.totp_secret = None;
    user.totp_enabled = false;
    user.recovery_codes.clear();
    store::update_user(&user)?;

    // Task 2.12: Revoke all sessions/tokens on MFA disable
    let _ = store::delete_user_refresh_tokens(user_id);

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("mfa_disabled", sub, user_id, "tokens revoked");

    json_ok(&serde_json::json!({"disabled": true}))
}

/// Check that the caller is the user themselves, or has superadmin role.
/// For security-critical global account operations, we don't allow tenant admins
/// to act on users unless they are superadmin.
fn require_self_or_superadmin(claims: &Value, user_id: &str) -> Result<(), String> {
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub == user_id {
        return Ok(());
    }
    if claims.get("role").and_then(|v| v.as_str()) == Some("superadmin") {
        return Ok(());
    }
    Err("forbidden: can only manage your own credentials, or requires superadmin role".into())
}

/// Check that the caller is the user themselves, or has admin/superadmin role.
#[allow(dead_code)]
fn require_self_or_admin(claims: &Value, user_id: &str) -> Result<(), String> {
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    if sub == user_id {
        return Ok(());
    }
    if has_admin_scope_over_user(claims, user_id)? {
        return Ok(());
    }
    Err("forbidden: can only manage your own MFA, or requires admin role".into())
}

#[allow(dead_code)]
fn has_admin_scope_over_user(claims: &Value, user_id: &str) -> Result<bool, String> {
    if claims.get("role").and_then(|v| v.as_str()) == Some("superadmin") {
        return Ok(true);
    }

    let memberships = store::list_user_tenants(user_id)?;
    Ok(memberships
        .iter()
        .any(|membership| claim_has_tenant_role(claims, &membership.tenant_id, "admin")))
}

// ── Identity provider management ────────────────────────────

/// GET /api/identity-providers
pub async fn list_identity_providers(auth: Option<&str>) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let providers = store::list_identity_providers()?;
    let list: Vec<Value> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "provider_type": p.provider_type,
                "client_id": p.client_id,
                "enabled": p.enabled,
                // Do not expose client_secret in list
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/identity-providers
pub async fn create_identity_provider(
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        provider_type: String,
        client_id: String,
        client_secret: String,
        #[serde(default = "default_true")]
        enabled: bool,
    }
    fn default_true() -> bool {
        true
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if !["google", "github"].contains(&req.provider_type.as_str()) {
        return Err("unsupported provider_type (supported: google, github)".into());
    }
    if req.client_id.is_empty() || req.client_secret.is_empty() {
        return Err("client_id and client_secret are required".into());
    }

    let idp = IdentityProvider {
        id: store::random_hex(16),
        provider_type: req.provider_type,
        client_id: req.client_id,
        client_secret: req.client_secret,
        enabled: req.enabled,
    };
    store::save_identity_provider(&idp)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "identity_provider_created",
        sub,
        &idp.id,
        &idp.provider_type,
    );

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": idp.id,
            "provider_type": idp.provider_type,
            "client_id": idp.client_id,
            "enabled": idp.enabled,
        }),
    )
}

/// DELETE /api/identity-providers/:id
pub async fn delete_identity_provider(
    auth: Option<&str>,
    id: &str,
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    store::get_identity_provider(id)?.ok_or("identity provider not found")?;
    store::delete_identity_provider(id)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit("identity_provider_deleted", sub, id, "");

    json_ok(&serde_json::json!({"deleted": true}))
}

// ── Hook management (Rhai scripting) ────────────────────────

const VALID_TRIGGERS: &[&str] = &["post-login", "post-registration"];

/// GET /api/hooks — list all hooks (superadmin).
pub async fn list_hooks(auth: Option<&str>) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hooks = store::list_hooks()?;
    let list: Vec<Value> = hooks
        .iter()
        .map(|h| {
            serde_json::json!({
                "id": h.id,
                "name": h.name,
                "trigger": h.trigger,
                "script": h.script,
                "enabled": h.enabled,
                "priority": h.priority,
                "version": h.version,
                "script_hash": h.script_hash,
                "created_at": h.created_at,
                "updated_by": h.updated_by,
                "updated_at": h.updated_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}

/// POST /api/hooks — create a new hook (superadmin).
pub async fn create_hook(auth: Option<&str>, body: &[u8]) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: String,
        trigger: String,
        script: String,
        #[serde(default = "hooks_default_true")]
        enabled: bool,
        #[serde(default)]
        priority: i32,
    }
    fn hooks_default_true() -> bool {
        true
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if req.name.is_empty() || req.name.len() > 128 {
        return Err("name must be 1-128 characters".into());
    }
    if !VALID_TRIGGERS.contains(&req.trigger.as_str()) {
        return Err(format!(
            "invalid trigger (valid: {})",
            VALID_TRIGGERS.join(", ")
        ));
    }
    if req.script.is_empty() || req.script.len() > 65536 {
        return Err("script must be 1-65536 characters".into());
    }

    // Validate script compiles
    if let Err(e) = crate::hooks::test_hook(&req.script, &req.trigger) {
        return Err(format!("script validation failed: {e}"));
    }

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let script_hash = store::sha256_hex(&req.script);
    let now = store::unix_now();

    let hook = store::Hook {
        id: store::random_hex(16),
        name: req.name,
        trigger: req.trigger,
        script: req.script,
        enabled: req.enabled,
        priority: req.priority,
        created_at: now,
        version: 1,
        script_hash: script_hash.clone(),
        updated_by: sub.to_string(),
        updated_at: now,
    };
    store::save_hook(&hook)?;

    // Save immutable version snapshot
    let ver = store::HookVersion {
        hook_id: hook.id.clone(),
        version: 1,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: sub.to_string(),
        changed_at: now,
    };
    let _ = store::save_hook_version(&ver);

    let _ = store::log_audit(
        "hook_created",
        sub,
        &hook.id,
        &format!("name={} hash={} v={}", hook.name, script_hash, 1),
    );

    json_response(
        StatusCode::CREATED,
        &serde_json::json!({
            "id": hook.id,
            "name": hook.name,
            "trigger": hook.trigger,
            "enabled": hook.enabled,
            "priority": hook.priority,
            "version": hook.version,
            "script_hash": hook.script_hash,
        }),
    )
}

/// PUT /api/hooks/:id — update an existing hook (superadmin).
pub async fn update_hook(
    auth: Option<&str>,
    id: &str,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let mut hook = store::get_hook(id)?.ok_or("hook not found")?;

    #[derive(serde::Deserialize)]
    struct Req {
        name: Option<String>,
        trigger: Option<String>,
        script: Option<String>,
        enabled: Option<bool>,
        priority: Option<i32>,
    }

    let req: Req = serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;

    if let Some(name) = req.name {
        if name.is_empty() || name.len() > 128 {
            return Err("name must be 1-128 characters".into());
        }
        hook.name = name;
    }
    if let Some(trigger) = req.trigger {
        if !VALID_TRIGGERS.contains(&trigger.as_str()) {
            return Err(format!(
                "invalid trigger (valid: {})",
                VALID_TRIGGERS.join(", ")
            ));
        }
        hook.trigger = trigger;
    }
    if let Some(script) = req.script {
        if script.is_empty() || script.len() > 65536 {
            return Err("script must be 1-65536 characters".into());
        }
        if let Err(e) = crate::hooks::test_hook(&script, &hook.trigger) {
            return Err(format!("script validation failed: {e}"));
        }
        hook.script = script;
    }
    if let Some(enabled) = req.enabled {
        hook.enabled = enabled;
    }
    if let Some(priority) = req.priority {
        hook.priority = priority;
    }

    // Bump version, recompute hash, record who changed it
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    hook.version += 1;
    hook.script_hash = store::sha256_hex(&hook.script);
    hook.updated_by = sub.to_string();
    hook.updated_at = store::unix_now();

    store::save_hook(&hook)?;

    // Save immutable version snapshot
    let ver = store::HookVersion {
        hook_id: hook.id.clone(),
        version: hook.version,
        name: hook.name.clone(),
        trigger: hook.trigger.clone(),
        script: hook.script.clone(),
        script_hash: hook.script_hash.clone(),
        enabled: hook.enabled,
        priority: hook.priority,
        changed_by: sub.to_string(),
        changed_at: hook.updated_at,
    };
    let _ = store::save_hook_version(&ver);

    let _ = store::log_audit(
        "hook_updated",
        sub,
        id,
        &format!("name={} hash={} v={}", hook.name, hook.script_hash, hook.version),
    );

    json_ok(&serde_json::json!({
        "id": hook.id,
        "name": hook.name,
        "trigger": hook.trigger,
        "enabled": hook.enabled,
        "priority": hook.priority,
        "version": hook.version,
        "script_hash": hook.script_hash,
    }))
}

/// DELETE /api/hooks/:id — delete a hook (superadmin).
pub async fn delete_hook(auth: Option<&str>, id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hook = store::get_hook(id)?.ok_or("hook not found")?;
    store::delete_hook(id)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let _ = store::log_audit(
        "hook_deleted",
        sub,
        id,
        &format!("name={} hash={} v={}", hook.name, hook.script_hash, hook.version),
    );

    json_ok(&serde_json::json!({"deleted": true, "last_version": hook.version, "script_hash": hook.script_hash}))
}

/// POST /api/hooks/:id/test — dry-run a hook with sample data (superadmin).
pub async fn test_hook(auth: Option<&str>, id: &str) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let hook = store::get_hook(id)?.ok_or("hook not found")?;

    match crate::hooks::test_hook(&hook.script, &hook.trigger) {
        Ok(outcome) => json_ok(&serde_json::json!({
            "success": true,
            "deny_reason": outcome.deny_reason,
            "set_superadmin": outcome.set_superadmin,
            "add_to_tenants": outcome.add_to_tenants.iter()
                .map(|(t, r)| serde_json::json!({"tenant_id": t, "role": r}))
                .collect::<Vec<_>>(),
            "extra_claims": outcome.extra_claims.iter()
                .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
                .collect::<Vec<_>>(),
            "log_messages": outcome.log_messages,
        })),
        Err(e) => json_ok(&serde_json::json!({
            "success": false,
            "error": e,
        })),
    }
}

/// GET /api/hooks/:id/versions — list all version snapshots for a hook (superadmin).
/// Returns the full script + metadata for every version ever saved,
/// enabling auditors to diff any two versions and trace exactly what changed.
pub async fn list_hook_versions(
    auth: Option<&str>,
    id: &str,
) -> Result<Response<Body>, String> {
    let claims = require_auth(auth).await?;
    require_superadmin(&claims)?;

    let versions = store::list_hook_versions(id)?;
    let list: Vec<Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "hook_id": v.hook_id,
                "version": v.version,
                "name": v.name,
                "trigger": v.trigger,
                "script": v.script,
                "script_hash": v.script_hash,
                "enabled": v.enabled,
                "priority": v.priority,
                "changed_by": v.changed_by,
                "changed_at": v.changed_at,
            })
        })
        .collect();

    json_ok(&serde_json::json!(list))
}
