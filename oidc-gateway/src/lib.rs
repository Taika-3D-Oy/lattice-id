pub mod bindings {
    wit_bindgen::generate!({
        world: "gateway",
        path: "wit",
        generate_all,
    });
}

mod authorize;
mod discovery;
mod email;
mod google;
mod hooks;
mod jwt;
mod keys;
mod login;
mod logger;
mod management;
#[cfg(test)]
mod management_tests;
mod service_client;
mod store;
mod token;
pub mod totp;
mod userinfo;
pub mod util;

use wstd::http::{Body, Method, Request, Response, StatusCode};

fn get_issuer() -> String {
    bindings::wasi::config::store::get("issuer_url")
        .ok()
        .flatten()
        .unwrap_or_else(|| "http://localhost:8000".to_string())
}

pub fn is_dev_mode() -> bool {
    bindings::wasi::config::store::get("dev_mode")
        .ok()
        .flatten()
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false) // default to secure production mode
}

/// Whether email verification is required before users can log in.
/// Default: true (production-safe).  Set `require_email_verification=false`
/// in deployment config to disable for local development.
pub fn require_email_verification() -> bool {
    bindings::wasi::config::store::get("require_email_verification")
        .ok()
        .flatten()
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true) // default: enforce
}

/// Whether self-service registration is currently allowed.
///
/// Registration is permitted when ANY of:
///   1. Deployment config `allow_registration` is `"true"`
///   2. The runtime KV setting `allow_registration` is `true`
///      (toggled by superadmin via `PUT /api/settings`)
///   3. No superadmin exists yet (bootstrap window)
pub fn is_registration_allowed() -> bool {
    // Config override
    if let Some(v) = bindings::wasi::config::store::get("allow_registration")
        .ok()
        .flatten()
    {
        if v == "true" || v == "1" {
            return true;
        }
    }
    // Runtime KV setting
    if store::get_runtime_settings().allow_registration {
        return true;
    }
    // Bootstrap window: open while no superadmin exists
    !hooks::has_superadmin()
}

/// Read the optional bootstrap hook script from deployment config.
/// This is a Rhai script that runs for every new registration when no
/// superadmin exists yet, allowing zero-credential initial setup.
pub fn get_bootstrap_hook() -> Option<String> {
    bindings::wasi::config::store::get("bootstrap_hook")
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
}

#[wstd::http_server]
async fn main(req: Request<Body>) -> Result<Response<Body>, wstd::http::Error> {
    let req_origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let remote_ip = logger::request_remote_ip(req.headers());
    let full_path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let trace_id = logger::begin_request(req.headers(), req.method(), &full_path, &remote_ip);

    // NOTE: Component instances are fresh per request (new Store + Instance),
    // so static guards cannot skip this. The call is cheap and idempotent.
    if is_dev_mode() {
        let _ = store::ensure_default_client();
        let _ = store::ensure_admin_client(&get_issuer(), true);
    }

    // Restore signing keys from KV into core-service if available.
    // NOTE: core-service loads its own keys on startup, so this is a
    // belt-and-suspenders fallback in case core-service restarted
    // without persisted keys.  Runs every request (KV read is cheap).
    if let Err(e) = restore_signing_keys().await {
        logger::error_message("signing_keys.restore_failed", e);
    }

    let resp = match handle(req, &remote_ip).await {
        Ok(resp) => resp,
        Err(e) => {
            logger::warn("http.request.rejected", serde_json::json!({ "error": e }));
            error_json(StatusCode::BAD_REQUEST, &e)
        }
    };
    logger::finish_request(resp.status().as_u16());

    // Add CORS and security headers to every response
    let resp = with_cors_and_security(resp, req_origin.as_deref(), &trace_id);
    logger::clear_request();
    Ok(resp)
}

async fn restore_signing_keys() -> Result<(), String> {
    if let Some(data) = store::load_signing_keys()? {
        service_client::import_keys(&data).await?;
    }
    Ok(())
}


async fn handle_email_verification(query: &str) -> Result<Response<Body>, String> {
    let params = util::parse_query(query);
    let token = params.iter().find(|(k, _)| k == "token").map(|(_, v)| v).ok_or("missing token")?;

    // Rate limit: 5 attempts per token per hour
    match crate::service_client::check_rate(&format!("verify_email:{}", token), 5, 3600).await {
        Ok((false, _)) => return Err("too many verification attempts. please try again later.".into()),
        _ => {}
    }

    // Look up verification token (stored as invitation with role "verify_email")
    let inv = match store::get_invitation(token) {
        Ok(Some(i)) if i.role == "verify_email" && store::unix_now() <= i.expires_at => i,
        _ => {
            logger::warn(
                "email_verification.invalid_token",
                serde_json::json!({ "token": token }),
            );
            return Err("Verification link is invalid or has expired.".into());
        }
    };

    // Find and activate user
    let mut user = store::get_user_by_email(&inv.email)?.ok_or("user not found")?;
    if user.status == "pending" {
        user.status = "active".to_string();
        store::update_user(&user)?;
        let _ = store::log_audit("email_verified", &user.id, &user.id, &user.email);
    }

    // Clean up token
    store::delete_invitation(token)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(r#"<!DOCTYPE html><html><body><h1>Email Verified!</h1><p>Your email has been verified. You can now log in.</p></body></html>"#.into())
        .unwrap())
}

async fn handle(req: Request<Body>, remote_ip: &str) -> Result<Response<Body>, String> {
    let (parts, body) = req.into_parts();
    // Task 2.6: IP-based rate limiting (global IP check)
    if remote_ip != "unknown" {
        match service_client::check_rate(&format!("ip:{}", remote_ip), 1000, 3600).await {
            Ok((false, _)) => return Ok(error_json(StatusCode::TOO_MANY_REQUESTS, "IP rate limit exceeded")),
            _ => {}
        }
    }

    let full_path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let route_path = full_path.split('?').next().unwrap_or(full_path);

    if route_path == "/" {
        return Ok(index_page());
    }

    if route_path.starts_with("/admin") {
        return Ok(admin_ui_unavailable());
    }

    let query = full_path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let issuer = get_issuer();
    let auth = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match (&parts.method, route_path) {
        // ── Health / Readiness ─────────────────────────────
        (&Method::GET, "/healthz") => Ok(healthz()),
        (&Method::GET, "/readyz") => readyz(auth).await,
        (&Method::GET, "/metrics") => handle_metrics(auth).await,
        (&Method::GET, "/verify/email") => handle_email_verification(query).await,

        // ── Discovery ───────────────────────────────────────
        (&Method::GET, "/.well-known/openid-configuration") => {
            Ok(discovery::openid_configuration(&issuer))
        }
        (&Method::GET, "/.well-known/jwks.json") => Ok(discovery::jwks().await),

        // ── OIDC flow ───────────────────────────────────────
        (&Method::GET, "/authorize") => authorize::handle(query, &issuer).await,

        (&Method::POST, "/login") => {
            let body_bytes = read_body(body).await?;
            login::handle_login(&body_bytes, remote_ip).await
        }

        (&Method::POST, "/login/mfa") => {
            let body_bytes = read_body(body).await?;
            login::handle_mfa(&body_bytes, remote_ip).await
        }

        (&Method::POST, "/token") => {
            let body_bytes = read_body(body).await?;
            token::handle(&body_bytes, &issuer, auth).await
        }

        (&Method::POST, "/token/introspect") => {
            let body_bytes = read_body(body).await?;
            token::handle_introspect(&body_bytes, &issuer, auth).await
        }

        (&Method::GET, "/userinfo") => userinfo::handle(auth, &issuer).await,

        // ── Logout ──────────────────────────────────────────
        (&Method::GET, "/logout") => handle_logout(query, auth).await,

        // ── Token revocation ────────────────────────────────
        (&Method::POST, "/token/revoke") => {
            let body_bytes = read_body(body).await?;
            token::handle_revoke(&body_bytes).await
        }

        // ── User registration ───────────────────────────────
        (&Method::POST, "/register") => {
            let body_bytes = read_body(body).await?;
            handle_register(&body_bytes).await
        }

        // ── Password reset complete ──────────────────────────
        (&Method::POST, "/password-reset/complete") => {
            let body_bytes = read_body(body).await?;
            handle_password_reset_complete(&body_bytes).await
        }

        // ── Social login ────────────────────────────────────
        (&Method::GET, "/auth/google") => google::start(query, &issuer),
        (&Method::GET, "/auth/google/callback") => google::callback(query, &issuer, remote_ip).await,

        // ── Cross-region internal lookup ─────────────────────
        (&Method::GET, "/internal/lookup") => {
            verify_internal_auth(&parts.headers)?;
            handle_internal_lookup(query).await
        }
        (&Method::GET, "/internal/config") => {
            verify_internal_auth(&parts.headers)?;
            handle_internal_config().await
        }

        // ── Bootstrap status (public, no auth) ─────────────
        (&Method::GET, "/api/bootstrap/status") => {
            let needs = !hooks::has_superadmin();
            let body = serde_json::json!({ "needs_bootstrap": needs });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&body).unwrap_or_default().into())
                .unwrap())
        }

        // ── Management API ───────────────────────────────────
        (&Method::GET, "/api/tenants") => management::list_tenants(auth).await,
        (&Method::GET, "/api/audit") => management::list_audit_events(auth, query).await,
        (&Method::POST, "/api/tenants") => {
            let body_bytes = read_body(body).await?;
            management::create_tenant(auth, &body_bytes).await
        }
        (&Method::GET, "/api/clients") => management::list_clients(auth).await,
        (&Method::POST, "/api/clients") => {
            let body_bytes = read_body(body).await?;
            management::create_client(auth, &body_bytes).await
        }
        (&Method::POST, "/api/invitations/accept") => {
            let body_bytes = read_body(body).await?;
            management::accept_invitation(&body_bytes).await
        }
        (&Method::GET, "/api/settings") => management::get_settings(auth).await,
        (&Method::PUT, "/api/settings") => {
            let body_bytes = read_body(body).await?;
            management::update_settings(auth, &body_bytes).await
        }
        // ── CORS preflight ──────────────────────────────────
        (&Method::OPTIONS, _) => Ok(cors_preflight_base()),

        // ── Dynamic API routes ──────────────────────────────
        _ if route_path.starts_with("/api/") => {
            let body_bytes = read_body(body).await?;
            route_api(&parts.method, route_path, auth, &body_bytes).await
        }

        // ── Fallback ────────────────────────────────────────
        _ => Ok(error_json(StatusCode::NOT_FOUND, "not found")),
    }
}

/// Verify the shared secret on `/internal/*` requests.
/// In development mode a missing secret is tolerated so `wash dev` keeps
/// working without extra configuration. Outside dev mode, `/internal/*`
/// requests require `internal_auth_secret` to be configured and matched.
fn verify_internal_auth(headers: &wstd::http::HeaderMap) -> Result<(), String> {
    let Some(expected) = store::internal_auth_secret().filter(|s| !s.trim().is_empty()) else {
        if is_dev_mode() {
            return Ok(());
        }
        return Err("internal_auth_secret is not configured".into());
    };
    let provided = headers
        .get("x-internal-auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    use subtle::ConstantTimeEq;
    let ok: bool = provided.as_bytes().ct_eq(expected.as_bytes()).into();
    if ok {
        Ok(())
    } else {
        Err("unauthorized internal request".into())
    }
}

/// Cross-region internal lookup: check if an email hash exists in this region's KV.
/// Called by remote region-authority instances via HTTP.
async fn handle_internal_lookup(query: &str) -> Result<Response<Body>, String> {
    let params = util::parse_query(query);
    let hash = match util::form_value(&params, "hash") {
        Some(h) => h,
        None => return Ok(error_json(StatusCode::BAD_REQUEST, "missing hash parameter")),
    };

    let region_id = store::region_id().unwrap_or_else(|| "unknown".to_string());
    let found = store::email_hash_exists(&hash).unwrap_or(false);

    let body = serde_json::json!({ "found": found, "region": region_id });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .map_err(|e| e.to_string())?)
}

/// Export all OIDC clients and tenants for cross-region config sync.
/// Called by remote core-service instances via HTTP.
/// Note: client_secret is stripped to prevent credential leakage.
async fn handle_internal_config() -> Result<Response<Body>, String> {
    let clients: Vec<serde_json::Value> = store::list_clients()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let mut v = serde_json::to_value(&c).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                obj.remove("client_secret");
            }
            v
        })
        .collect();
    let tenants = store::list_tenants().unwrap_or_default();

    let body = serde_json::json!({
        "clients": clients,
        "tenants": tenants,
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .map_err(|e| e.to_string())?)
}

/// Route dynamic /api/ paths with path parameters.
async fn route_api(
    method: &Method,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<Body>, String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        // GET /api/tenants/:id
        (&Method::GET, ["api", "tenants", id]) => management::get_tenant(auth, id).await,
        // DELETE /api/tenants/:id
        (&Method::DELETE, ["api", "tenants", id]) => management::delete_tenant(auth, id).await,
        // GET /api/tenants/:id/users
        (&Method::GET, ["api", "tenants", id, "users"]) => {
            management::list_tenant_users(auth, id).await
        }
        // POST /api/tenants/:id/users
        (&Method::POST, ["api", "tenants", id, "users"]) => {
            management::add_tenant_user(auth, id, body).await
        }
        // POST /api/tenants/:id/users/invite
        (&Method::POST, ["api", "tenants", id, "users", "invite"]) => {
            management::invite_user(auth, id, body).await
        }
        // DELETE /api/tenants/:tid/users/:uid
        (&Method::DELETE, ["api", "tenants", tid, "users", uid]) => {
            management::remove_tenant_user(auth, tid, uid).await
        }
        // POST /api/users/:id/password-reset
        (&Method::POST, ["api", "users", id, "password-reset"]) => {
            management::initiate_password_reset(auth, id).await
        }
        // POST /api/users/:id/mfa/setup
        (&Method::POST, ["api", "users", id, "mfa", "setup"]) => {
            management::mfa_setup(auth, id).await
        }
        // POST /api/users/:id/mfa/confirm
        (&Method::POST, ["api", "users", id, "mfa", "confirm"]) => {
            management::mfa_confirm(auth, id, body).await
        }
        // DELETE /api/users/:id/mfa
        (&Method::DELETE, ["api", "users", id, "mfa"]) => management::mfa_disable(auth, id).await,
        // ── Identity provider management ────────────────────
        // GET /api/identity-providers
        (&Method::GET, ["api", "identity-providers"]) => {
            management::list_identity_providers(auth).await
        }
        // POST /api/identity-providers
        (&Method::POST, ["api", "identity-providers"]) => {
            management::create_identity_provider(auth, body).await
        }
        // DELETE /api/identity-providers/:id
        (&Method::DELETE, ["api", "identity-providers", id]) => {
            management::delete_identity_provider(auth, id).await
        }
        // ── Hook management ─────────────────────────────────
        // GET /api/hooks
        (&Method::GET, ["api", "hooks"]) => management::list_hooks(auth).await,
        // POST /api/hooks
        (&Method::POST, ["api", "hooks"]) => management::create_hook(auth, body).await,
        // PUT /api/hooks/:id
        (&Method::PUT, ["api", "hooks", id]) => management::update_hook(auth, id, body).await,
        // DELETE /api/hooks/:id
        (&Method::DELETE, ["api", "hooks", id]) => management::delete_hook(auth, id).await,
        // POST /api/hooks/:id/test
        (&Method::POST, ["api", "hooks", id, "test"]) => {
            management::test_hook(auth, id).await
        }
        // GET /api/hooks/:id/versions
        (&Method::GET, ["api", "hooks", id, "versions"]) => {
            management::list_hook_versions(auth, id).await
        }
        _ => Ok(error_json(StatusCode::NOT_FOUND, "not found")),
    }
}

async fn handle_register(body_bytes: &[u8]) -> Result<Response<Body>, String> {
    #[derive(serde::Deserialize)]
    struct RegisterReq {
        email: String,
        password: String,
        name: String,
    }

    let req: RegisterReq =
        serde_json::from_slice(body_bytes).map_err(|e| format!("invalid JSON: {e}"))?;

    // Gate: registration must be explicitly allowed (or bootstrap window open)
    if !is_registration_allowed() {
        return Ok(error_json(
            StatusCode::FORBIDDEN,
            "registration is currently closed",
        ));
    }

    // Rate limit registration: 3 attempts per hour per IP (well, just use a generic key for now if we don't have IP)
    // Actually Task 1.4 says "per-IP or per-email". Let's use email for now as we don't have easy IP access yet.
    match crate::service_client::check_rate(&format!("register:{}", req.email.to_lowercase()), 3, 3600).await {
        Ok((false, _)) => return Err("too many registration attempts. please try again later.".into()),
        Err(e) => logger::error_message("rate_limit.register_check_failed", e),
        _ => {}
    }

    if req.email.is_empty() || !req.email.contains('@') {
        return Err("invalid email".into());
    }
    if req.email.len() > 256 {
        return Err("email too long".into());
    }
    if req.password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    if req.password.len() > 1024 {
        return Err("password too long".into());
    }
    if req.name.is_empty() || req.name.len() > 256 {
        return Err("name must be 1-256 characters".into());
    }

    // Hash password via core-service
    let password_hash = service_client::hash_password(&req.password)?;

    let initial_status = if require_email_verification() {
        "pending"
    } else {
        "active"
    };

    let user = store::User {
        id: store::random_hex(16),
        email: req.email,
        name: req.name,
        password_hash,
        status: initial_status.to_string(),
        created_at: store::unix_now(),
        superadmin: false,
        totp_secret: None,
        totp_enabled: false,
        recovery_codes: Vec::new(),
    };

    match store::create_user(&user) {
        Ok(_) => {
            let _ = store::log_audit("user_registered", &user.id, &user.id, &user.email);

            // Bootstrap hook: config-supplied Rhai script for zero-credential setup
            let mut user_mut = user.clone();
            let boot = hooks::execute_bootstrap_hook(&user_mut);
            if let Some(reason) = &boot.deny_reason {
                let _ = store::log_audit(
                    "registration_denied_by_bootstrap_hook",
                    &user_mut.id,
                    &user_mut.id,
                    reason,
                );
                return Err(format!("registration denied: {reason}"));
            }
            if let Err(e) = hooks::apply_outcome(&mut user_mut, &boot) {
                logger::error_message("bootstrap_hook.apply_failed", e);
            }

            // Execute post-registration hooks (Rhai scripting)
            let outcome = hooks::execute_hooks("post-registration", &user_mut);
            if let Some(reason) = &outcome.deny_reason {
                let _ = store::log_audit(
                    "registration_denied_by_hook",
                    &user_mut.id,
                    &user_mut.id,
                    reason,
                );
                return Err(format!("registration denied: {reason}"));
            }
            if let Err(e) = hooks::apply_outcome(&mut user_mut, &outcome) {
                logger::error_message("hooks.apply_failed", e);
            }
        }
        Err(e) if e == "email already registered" => {
            // Task 1.9: Prevent email enumeration. Log internal error but return success.
            logger::warn(
                "user_registration.duplicate_email",
                serde_json::json!({ "email": user.email }),
            );
        }
        Err(e) => return Err(e),
    }

    // Email verification flow: generate and send token when verification is required
    if require_email_verification() {
        let verify_token = store::random_hex(32);
        let verify_inv = store::Invitation {
            tenant_id: "system".to_string(),
            email: user.email.clone(),
            role: "verify_email".to_string(),
            token: verify_token.clone(),
            invited_by: "system".to_string(),
            expires_at: store::unix_now() + 86400, // 24 hours
        };
        store::save_invitation(&verify_inv)?;
        let _ = store::log_audit("email_verification_link_generated", &user.id, &user.id, &verify_token);
        if is_dev_mode() {
            logger::info(
                &format!("LID_VERIFY: {} {}", user.email, verify_token),
                serde_json::json!({}),
            );
        }
        email::send_verification_email(&get_issuer(), &user.email, &user.name, &verify_token);
    }

    let resp = serde_json::json!({
        "status": "success",
        "message": "User registered successfully",
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&resp).unwrap_or_default().into())
        .unwrap())
}

async fn handle_password_reset_complete(body_bytes: &[u8]) -> Result<Response<Body>, String> {
    #[derive(serde::Deserialize)]
    struct ResetReq {
        token: String,
        new_password: String,
    }

    let req: ResetReq =
        serde_json::from_slice(body_bytes).map_err(|e| format!("invalid JSON: {e}"))?;

    // Rate limit reset: 5 attempts per 15 mins per token
    match crate::service_client::check_rate(&format!("reset_complete:{}", req.token), 5, 900).await {
        Ok((false, _)) => return Err("too many reset attempts. please try again later.".into()),
        Err(e) => logger::error_message("rate_limit.password_reset_check_failed", e),
        _ => {}
    }

    if req.new_password.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    if req.new_password.len() > 1024 {
        return Err("password too long".into());
    }

    // Task 1.9: Fix email enumeration. 
    // Return a generic success even if token is invalid or expired, 
    // unless we want to be specific for the UI. 
    // Actually, for "complete" we usually need to know if it worked.
    // The roadmap says "registration and password reset should return identical responses whether the email exists or not".
    // This mostly applies to the *initiation* phase and *registration*.

    // Look up reset token (stored as invitation with role "password_reset")
    let inv = match store::get_invitation(&req.token) {
        Ok(Some(i)) if i.role == "password_reset" && store::unix_now() <= i.expires_at => i,
        _ => {
            // Return generic success to avoid enumeration, 
            // but log the failure.
            logger::warn(
                "password_reset.invalid_token",
                serde_json::json!({ "token": req.token }),
            );
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(r#"{"ok":true,"message":"If the token was valid, your password has been reset."}"#.into())
                .unwrap());
        }
    };

    // Find user by email
    let mut user = store::get_user_by_email(&inv.email)?.ok_or("user not found")?;

    // Hash new password and update user
    user.password_hash = service_client::hash_password(&req.new_password)?;
    store::update_user(&user)?;

    // Clean up token
    store::delete_invitation(&req.token)?;

    // Revoke all refresh tokens for this user
    if let Err(e) = store::delete_user_refresh_tokens(&user.id) {
        logger::error_message("password_reset.revoke_tokens_failed", e);
    }

    let _ = store::log_audit(
        "password_reset_completed",
        &user.id,
        &user.id,
        "password reset via token",
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(r#"{"ok":true}"#.into())
        .unwrap())
}

/// Handle GET /logout — RP-initiated logout (OIDC RP-Initiated Logout 1.0).
async fn handle_logout(query: &str, auth: Option<&str>) -> Result<Response<Body>, String> {
    let params = util::parse_query(query);

    let id_token_hint = params
        .iter()
        .find(|(k, _)| k == "id_token_hint")
        .map(|(_, v)| v.as_str());
    let post_logout_uri = params
        .iter()
        .find(|(k, _)| k == "post_logout_redirect_uri")
        .map(|(_, v)| v.as_str());
    let logout_state = params
        .iter()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.as_str());

    // Try to identify the user from id_token_hint or Authorization header
    let token = id_token_hint.or_else(|| {
        auth.and_then(|a| {
            a.strip_prefix("Bearer ")
                .or_else(|| a.strip_prefix("bearer "))
        })
    });

    if let Some(token) = token
        && let Ok(claims) = service_client::verify_token_scoped(token, Some(&get_issuer()), None, None).await
        && let Some(sub) = claims.get("sub").and_then(|v| v.as_str())
    {
        // Revoke all refresh tokens for this user
        let _ = store::delete_user_refresh_tokens(sub);
        let _ = store::log_audit("logout", sub, sub, "");
    }

    // Redirect to post_logout_redirect_uri if provided, otherwise show confirmation
    // Validate the URI against registered client redirect URIs to prevent open redirects
    match post_logout_uri {
        Some(uri) if !uri.is_empty() && is_allowed_redirect(uri) => {
            // Append state parameter if present (RP-Initiated Logout 1.0 §3)
            let location = match logout_state {
                Some(s) if !s.is_empty() => {
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    format!("{uri}{sep}state={}", util::percent_encode(s))
                }
                _ => uri.to_string(),
            };
            Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", &location)
                .header("cache-control", "no-store")
                .body(Body::empty())
                .unwrap())
        }
        _ => {
            let html = r#"<!DOCTYPE html>
<html><head><title>Logged Out</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f8fafc}
.card{background:#fff;padding:40px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}
</style></head><body><div class="card"><h1>Signed Out</h1><p>You have been signed out successfully.</p></div></body></html>"#;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-store")
                .body(html.into())
                .unwrap())
        }
    }
}

const MAX_BODY_SIZE: usize = 1_048_576; // 1 MiB

async fn read_body(mut body: Body) -> Result<Vec<u8>, String> {
    let bytes = body
        .contents()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("read body: {e}"))?;
    if bytes.len() > MAX_BODY_SIZE {
        return Err("request body too large".into());
    }
    Ok(bytes)
}

fn healthz() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(r#"{"ok":true,"status":"healthy"}"#.into())
        .unwrap()
}

async fn handle_metrics(auth: Option<&str>) -> Result<Response<Body>, String> {
    if !is_dev_mode() {
        let claims = management::require_auth(auth).await?;
        management::require_superadmin(&claims)?;
    }

    let metrics = service_client::render_metrics().await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .header("cache-control", "no-store")
        .body(metrics.into())
        .unwrap())
}

fn index_page() -> Response<Body> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lattice-ID</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;color:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:720px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:32px;box-shadow:0 10px 30px rgba(15,23,42,.08)}
h1{margin:0 0 12px;font-size:32px}
p{line-height:1.6;color:#334155}
ul{padding-left:20px;color:#334155}
a{color:#0f766e}
code{background:#f1f5f9;padding:2px 6px;border-radius:6px}
</style>
</head>
<body>
<main class="card">
<h1>Lattice-ID</h1>
<p>This workload serves the OIDC provider and management API. The separate admin UI host is currently experimental and is not bundled into the default gateway build.</p>
<ul>
<li>Discovery: <a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></li>
<li>JWKS: <a href="/.well-known/jwks.json">/.well-known/jwks.json</a></li>
<li>Health: <a href="/healthz">/healthz</a></li>
<li>Readiness: <a href="/readyz">/readyz</a></li>
</ul>
<p>Interactive sign-in starts at <code>/authorize</code> with a registered client.</p>
</main>
</body>
</html>"#;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(html.into())
        .unwrap()
}

fn admin_ui_unavailable() -> Response<Body> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin UI Unavailable</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;color:#0f172a;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{max-width:640px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:32px;box-shadow:0 10px 30px rgba(15,23,42,.08)}
h1{margin:0 0 12px;font-size:28px}
p{line-height:1.6;color:#334155}
a{color:#0f766e}
</style>
</head>
<body>
<main class="card">
<h1>Admin UI Not Bundled</h1>
<p>The standalone admin UI host is currently experimental and is not loaded by the default <code>wash dev</code> workspace path.</p>
<p>Use the management API directly or deploy the separate admin UI host explicitly for builds that need it.</p>
<p><a href="/">Back to the provider landing page</a></p>
</main>
</body>
</html>"#;

    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header("content-type", "text/html; charset=utf-8")
        .body(html.into())
        .unwrap()
}

async fn readyz(auth: Option<&str>) -> Result<Response<Body>, String> {
    let core_status = service_client::health_status().await.ok();
    let core_service = core_status.is_some();
    let keys_loaded = core_status
        .as_ref()
        .and_then(|status| status.get("keys_loaded"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let kv_started = std::time::Instant::now();
    let users_probe = store::list_users().is_ok();
    let clients_probe = store::list_clients().is_ok();
    let kv_latency_ms = kv_started.elapsed().as_millis() as u64;
    let keyvalue = users_probe && clients_probe;

    let status = if core_service && keyvalue {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let detailed_access = match auth {
        Some(_) => {
            let claims = management::require_auth(auth).await?;
            management::require_superadmin(&claims)?;
            true
        }
        None => false,
    };

    let body = if detailed_access {
        serde_json::json!({
            "ok": status == StatusCode::OK,
            "status": if status == StatusCode::OK { "ready" } else { "not_ready" },
            "checks": {
                "core_service": core_service,
                "keyvalue": keyvalue,
                "keys_loaded": keys_loaded,
            },
            "details": {
                "core_service": core_status.unwrap_or_else(|| serde_json::json!({
                    "keys_loaded": false,
                    "current_kid": null,
                    "current_key_created_at": null,
                    "current_key_age_secs": null,
                    "last_rotation_at": null,
                    "retired_key_count": null,
                    "rate_limiter_size": null,
                })),
                "keyvalue": {
                    "users_probe": users_probe,
                    "clients_probe": clients_probe,
                    "latency_ms": kv_latency_ms,
                }
            }
        })
    } else {
        serde_json::json!({
            "ok": status == StatusCode::OK,
            "status": if status == StatusCode::OK { "ready" } else { "not_ready" },
        })
    };

    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap_or_default().into())
        .unwrap())
}

pub fn error_json(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": msg });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap_or_default().into())
        .unwrap()
}

/// Check if a URI exactly matches any registered client redirect_uri.
fn is_allowed_redirect(uri: &str) -> bool {
    match store::list_clients() {
        Ok(clients) => clients
            .iter()
            .any(|c| c.redirect_uris.iter().any(|ru| ru == uri)),
        Err(_) => false,
    }
}

/// Derive the allowed CORS origin from registered client redirect URIs.
/// Returns the Origin header value if it matches a registered client's redirect URI origin.
fn allowed_origin(req_origin: Option<&str>) -> Option<String> {
    let origin = req_origin?;
    if origin.is_empty() {
        return None;
    }
    let clients = store::list_clients().ok()?;
    for client in &clients {
        for uri in &client.redirect_uris {
            // Extract origin from redirect_uri (scheme + host[:port])
            if let Some(pos) = uri.find("://") {
                let after_scheme = &uri[pos + 3..];
                let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
                let client_origin = &uri[..pos + 3 + host_end];
                if origin == client_origin {
                    return Some(origin.to_string());
                }
            }
        }
    }
    None
}

/// Add CORS and security headers to a response.
fn with_cors_and_security(
    resp: Response<Body>,
    req_origin: Option<&str>,
    request_id: &str,
) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    let origin_value = allowed_origin(req_origin).unwrap_or_else(|| "null".to_string());
    parts
        .headers
        .insert("access-control-allow-origin", origin_value.parse().unwrap());
    parts.headers.insert(
        "access-control-allow-methods",
        "GET, POST, DELETE, OPTIONS".parse().unwrap(),
    );
    parts.headers.insert(
        "access-control-allow-headers",
        "authorization, content-type, traceparent, x-request-id"
            .parse()
            .unwrap(),
    );
    parts.headers.insert(
        "access-control-expose-headers",
        "x-request-id".parse().unwrap(),
    );
    parts
        .headers
        .insert("access-control-allow-credentials", "true".parse().unwrap());
    parts
        .headers
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    parts
        .headers
        .insert("x-frame-options", "DENY".parse().unwrap());

    // Task 1.10: Content-Security-Policy
    // Default policy: only allow self for scripts, styles, images. 
    // Allow Google fonts and Google identity if needed, but for now keep it tight.
    parts.headers.insert(
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self';"
            .parse()
            .unwrap(),
    );

    // Task 1.11: Strict-Transport-Security (off in dev mode)
    if !is_dev_mode() {
        parts.headers.insert(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains; preload"
                .parse()
                .unwrap(),
        );
    }

    // Task 1.12: Referrer-Policy and Permissions-Policy
    parts
        .headers
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    parts.headers.insert(
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
            .parse()
            .unwrap(),
    );
    if let Ok(value) = request_id.parse() {
        parts.headers.insert("x-request-id", value);
    }

    Response::from_parts(parts, body)
}

fn cors_preflight_base() -> Response<Body> {
    // CORS origin/methods/headers are added by with_cors_and_security in main()
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-max-age", "86400")
        .body(Body::empty())
        .unwrap()
}
