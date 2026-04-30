pub mod bindings {
    wit_bindgen::generate!({
        world: "gateway",
        path: "wit",
        async: [
            "import:wasi:config/store@0.2.0-rc.1#get",
            "import:wasi:config/store@0.2.0-rc.1#get-all",
            "import:wasi:sockets/types@0.3.0-rc-2026-03-15#[method]tcp-socket.connect",
            "import:wasmcloud:messaging/consumer@0.2.0#request",
            "import:wasmcloud:messaging/consumer@0.2.0#publish",
        ],
        generate_all,
    });
}

mod account;
mod authorize;
mod backchannel;
mod device;
mod discovery;
mod email;
mod google;
mod hooks;
pub mod http_client;
mod jwt;
mod keys;
mod logger;
mod login;
mod management;
#[cfg(test)]
mod management_tests;
mod passkeys;
mod service_client;
mod social;
mod store;
mod token;
pub mod totp;
mod userinfo;
pub mod util;

use http::{Method, Response, StatusCode};
use wasip3::http::types::ErrorCode;
use wasip3::http_compat::IncomingRequestBody;

fn get_issuer() -> String {
    store::config_value("issuer_url").unwrap_or_else(|| "http://localhost:8000".to_string())
}

pub fn is_dev_mode() -> bool {
    store::config_value("dev_mode")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false) // default to secure production mode
}

/// Whether email verification is required before users can log in.
/// Default: true (production-safe).  Set `require_email_verification=false`
/// in deployment config to disable for local development.
pub fn require_email_verification() -> bool {
    store::config_value("require_email_verification")
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
pub async fn is_registration_allowed() -> bool {
    // Config override
    if let Some(v) = store::config_value("allow_registration")
        && (v == "true" || v == "1")
    {
        return true;
    }
    // Runtime KV setting
    if store::get_runtime_settings().await.allow_registration {
        return true;
    }
    // Bootstrap window: open while no superadmin exists
    !hooks::has_superadmin().await
}

/// Read the optional bootstrap hook script from deployment config.
/// This is a Rhai script that runs for every new registration when no
/// superadmin exists yet, allowing zero-credential initial setup.
pub fn get_bootstrap_hook() -> Option<String> {
    store::config_value("bootstrap_hook").filter(|s| !s.trim().is_empty())
}

// -- HTTP service export --
wasip3::http::service::export!(HttpHandler);
struct HttpHandler;
impl wasip3::exports::http::handler::Guest for HttpHandler {
    async fn handle(
        request: wasip3::http::types::Request,
    ) -> Result<wasip3::http::types::Response, ErrorCode> {
        let req = wasip3::http_compat::http_from_wasi_request(request)?;
        let resp = handle_request(req)
            .await
            .unwrap_or_else(|e| error_json(StatusCode::INTERNAL_SERVER_ERROR, &e));
        wasip3::http_compat::http_into_wasi_response(resp)
    }
}

async fn handle_request(
    req: http::Request<IncomingRequestBody>,
) -> Result<Response<String>, String> {
    // Load config values (cached for this request)
    store::init_config().await;

    // ── Session consistency: seed from inbound header or cookie ──
    // Header `x-lid-consistency` takes priority (API clients).
    // Cookie `__lid_cr` is the browser fallback (auto round-tripped).
    let inbound_revisions = req
        .headers()
        .get("x-lid-consistency")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers()
                .get_all("cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(';'))
                .map(|c| c.trim())
                .find(|c| c.starts_with("__lid_cr="))
                .and_then(|c| c.strip_prefix("__lid_cr="))
        })
        .and_then(|raw| serde_json::from_str::<std::collections::HashMap<String, u64>>(raw).ok());
    if let Some(revisions) = inbound_revisions {
        store::seed_session_revisions(revisions);
    }

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
    let req_path = full_path.split('?').next().unwrap_or("/").to_string();
    let trace_id = logger::begin_request(req.headers(), req.method(), &full_path, &remote_ip);

    // NOTE: Component instances are fresh per request (new Store + Instance),
    // so static guards cannot skip this. The call is cheap and idempotent.
    if is_dev_mode() {
        let _ = store::ensure_default_client().await;
        let _ = store::ensure_admin_client(&get_issuer(), true).await;
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
    let resp = with_cors_and_security(resp, req_origin.as_deref(), &trace_id, &req_path).await;

    // ── Session consistency: emit updated revisions ──
    let resp = {
        let revisions = store::get_session_revisions();
        if !revisions.is_empty() {
            let (mut parts, body) = resp.into_parts();
            if let Ok(json) = serde_json::to_string(&revisions) {
                // Header for API clients
                if let Ok(val) = json.parse() {
                    parts.headers.insert("x-lid-consistency", val);
                }
                // HttpOnly cookie for browsers (SameSite=Lax, path=/, 24h max-age)
                let cookie = format!(
                    "__lid_cr={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
                    json,
                );
                if let Ok(val) = cookie.parse() {
                    parts.headers.append("set-cookie", val);
                }
            }
            Response::from_parts(parts, body)
        } else {
            resp
        }
    };

    logger::clear_request();
    Ok(resp)
}

async fn handle_email_verification(query: &str) -> Result<Response<String>, String> {
    let params = util::parse_query(query);
    let token = params
        .iter()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v)
        .ok_or("missing token")?;

    // Rate limit: 5 attempts per token per hour
    if let Ok((false, _)) =
        crate::service_client::check_rate(&format!("verify_email:{}", token), 5, 3600).await
    {
        return Err("too many verification attempts. please try again later.".into());
    }

    // Look up verification token (stored as invitation with role "verify_email")
    let inv = match store::get_invitation(token).await {
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
    let user = store::get_user_by_email(&inv.email)
        .await?
        .ok_or("user not found")?;
    if user.status == "pending" {
        store::update_user_rmw(&user.id, |u| {
            if u.status == "pending" {
                u.status = "active".to_string();
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .await?;
        let _ = store::log_audit("email_verified", &user.id, &user.id, &user.email).await;
    }

    // Clean up token
    store::delete_invitation(token).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(r#"<!DOCTYPE html><html><body><h1>Email Verified!</h1><p>Your email has been verified. You can now log in.</p></body></html>"#.to_string())
        .unwrap())
}

async fn handle(
    req: http::Request<IncomingRequestBody>,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    let (parts, body) = req.into_parts();
    // Task 2.6: IP-based rate limiting (global IP check)
    if remote_ip != "unknown"
        && let Ok((false, _)) =
            service_client::check_rate(&format!("ip:{}", remote_ip), 1000, 3600).await
    {
        return Ok(error_json(
            StatusCode::TOO_MANY_REQUESTS,
            "IP rate limit exceeded",
        ));
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
        return Ok(serve_admin_asset(route_path));
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
        (&Method::GET, "/version") => Ok(version_response()),

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

        // ── Consent screen (third-party clients / prompt=consent) ────
        (&Method::POST, "/consent") => {
            let body_bytes = read_body(body).await?;
            login::handle_consent(&body_bytes).await
        }

        (&Method::POST, "/token") => {
            let body_bytes = read_body(body).await?;
            token::handle(&body_bytes, &issuer, auth).await
        }

        (&Method::POST, "/token/introspect") => {
            let body_bytes = read_body(body).await?;
            token::handle_introspect(&body_bytes, &issuer, auth).await
        }

        (&Method::GET, "/userinfo") | (&Method::POST, "/userinfo") => {
            userinfo::handle(auth, &issuer).await
        }

        // ── Logout ──────────────────────────────────────────
        (&Method::GET, "/logout") => handle_logout(query, auth).await,

        // ── Token revocation ────────────────────────────────
        (&Method::POST, "/token/revoke") => {
            let body_bytes = read_body(body).await?;
            token::handle_revoke(&body_bytes, auth).await
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
        (&Method::GET, "/auth/google") => google::start(query, &issuer).await,
        (&Method::GET, "/auth/google/callback") => {
            google::callback(query, &issuer, remote_ip).await
        }

        // ── Generic OIDC federation (/auth/social/{provider_id}) ────
        (&Method::GET, p) if p.starts_with("/auth/social/") && !p[13..].contains('/') => {
            social::start(&p[13..], query, &issuer).await
        }
        (&Method::GET, p) if p.starts_with("/auth/social/") && p.ends_with("/callback") => {
            social::callback(&p[13..p.len() - 9], query, &issuer, remote_ip).await
        }

        // ── Device Authorization Grant (RFC 8628) ───────────
        (&Method::POST, "/device_authorization") => {
            let body_bytes = read_body(body).await?;
            device::start(&body_bytes, &issuer).await
        }
        (&Method::GET, "/device") => Ok(device::page(query).await),
        (&Method::POST, "/device") => {
            let body_bytes = read_body(body).await?;
            device::submit(&body_bytes, &issuer).await
        }
        (&Method::GET, "/device/complete") => Ok(device::complete(query).await),

        // ── Passkey authentication (public) ─────────────────
        (&Method::POST, "/passkeys/auth-options") => management::passkey_auth_options().await,
        (&Method::POST, "/passkeys/auth-complete") => {
            let body_bytes = read_body(body).await?;
            management::passkey_auth_complete(&body_bytes, remote_ip).await
        }

        // ── Account self-service (cookie-based auth) ────────
        (&Method::GET, "/account") => account::dashboard(&parts.headers).await,
        (&Method::GET, "/account/passkeys") => {
            account::passkeys_page(&parts.headers, None, None).await
        }
        (&Method::POST, "/account/passkeys/register") => {
            let body_bytes = read_body(body).await?;
            account::passkeys_register(&parts.headers, &body_bytes).await
        }
        (&Method::POST, "/account/passkeys/delete") => {
            let body_bytes = read_body(body).await?;
            account::passkeys_delete(&parts.headers, &body_bytes).await
        }
        (&Method::GET, "/account/mfa") => account::mfa_page(&parts.headers, None, None).await,
        (&Method::POST, "/account/mfa/setup") => account::mfa_setup(&parts.headers).await,
        (&Method::POST, "/account/mfa/confirm") => {
            let body_bytes = read_body(body).await?;
            account::mfa_confirm(&parts.headers, &body_bytes).await
        }
        (&Method::POST, "/account/mfa/disable") => {
            let body_bytes = read_body(body).await?;
            account::mfa_disable(&parts.headers, &body_bytes).await
        }
        (&Method::GET, "/account/logout") => Ok(account::logout(&parts.headers).await),

        // ── Cross-region internal lookup ─────────────────────
        (&Method::GET, "/internal/lookup") => {
            verify_internal_auth(&parts.headers)?;
            handle_internal_lookup(query).await
        }
        (&Method::GET, "/internal/config") => {
            verify_internal_auth(&parts.headers)?;
            handle_internal_config().await
        }
        (&Method::POST, "/internal/replicate") => {
            verify_internal_auth(&parts.headers)?;
            let body_bytes = read_body(body).await?;
            handle_internal_replicate(&body_bytes).await
        }

        // ── Bootstrap status (public, no auth) ─────────────
        (&Method::GET, "/api/bootstrap/status") => {
            let needs = !hooks::has_superadmin().await;
            let body = serde_json::json!({ "needs_bootstrap": needs });
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&body).unwrap_or_default())
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
fn verify_internal_auth(headers: &http::HeaderMap) -> Result<(), String> {
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
async fn handle_internal_lookup(query: &str) -> Result<Response<String>, String> {
    let params = util::parse_query(query);
    let hash = match util::form_value(&params, "hash") {
        Some(h) => h,
        None => {
            return Ok(error_json(
                StatusCode::BAD_REQUEST,
                "missing hash parameter",
            ));
        }
    };

    let region_id = store::region_id().unwrap_or_else(|| "unknown".to_string());
    let found = store::email_hash_exists(hash).await.unwrap_or(false);

    let body = serde_json::json!({ "found": found, "region": region_id });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(body.to_string())
        .map_err(|e| e.to_string())
}

/// Export all OIDC clients and tenants for cross-region config sync.
/// Called by remote gateway instances via HTTP.
/// Note: client_secret is stripped to prevent credential leakage.
async fn handle_internal_config() -> Result<Response<String>, String> {
    let clients: Vec<serde_json::Value> = store::list_clients()
        .await
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
    let tenants = store::list_tenants().await.unwrap_or_default();

    let body = serde_json::json!({
        "clients": clients,
        "tenants": tenants,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(body.to_string())
        .map_err(|e| e.to_string())
}

/// Accept a replicated tenant or client mutation from a remote region.
/// Payload: { "op": "put"|"delete", "kind": "tenant"|"client", "id": "...", "data": {...} }
async fn handle_internal_replicate(body: &[u8]) -> Result<Response<String>, String> {
    #[derive(serde::Deserialize)]
    struct ReplicateReq {
        op: String,
        kind: String,
        id: String,
        data: Option<serde_json::Value>,
    }
    let req: ReplicateReq =
        serde_json::from_slice(body).map_err(|e| format!("invalid replicate payload: {e}"))?;

    match (req.op.as_str(), req.kind.as_str()) {
        ("put", "tenant") => {
            let data = req.data.ok_or("missing data for tenant put")?;
            let tenant: store::Tenant =
                serde_json::from_value(data).map_err(|e| format!("invalid tenant: {e}"))?;
            // Use kv_set directly to upsert (skip the exists check in create_tenant)
            store::kv_set(
                &store::tenants_store_name(),
                &format!("tenant:{}", tenant.id),
                &tenant,
            )
            .await?;
        }
        ("delete", "tenant") => {
            store::delete_tenant(&req.id).await?;
        }
        ("put", "client") => {
            let data = req.data.ok_or("missing data for client put")?;
            let client: store::OidcClient =
                serde_json::from_value(data).map_err(|e| format!("invalid client: {e}"))?;
            store::save_client(&client).await?;
        }
        ("delete", "client") => {
            store::kv_delete(&store::clients_store_name(), &format!("client:{}", req.id)).await?;
        }
        _ => return Err(format!("unknown replicate op={} kind={}", req.op, req.kind)),
    }

    let body = serde_json::json!({"ok": true});
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(body.to_string())
        .map_err(|e| e.to_string())
}

/// Route dynamic /api/ paths with path parameters.
async fn route_api(
    method: &Method,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> Result<Response<String>, String> {
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
        // GET /api/users/:id/export — GDPR data export
        (&Method::GET, ["api", "users", id, "export"]) => {
            management::export_user_data(auth, id).await
        }
        // DELETE /api/users/:id — GDPR erasure
        (&Method::DELETE, ["api", "users", id]) => management::delete_user(auth, id).await,
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
        // ── Passkey management ──────────────────────────────
        // GET /api/users/:id/passkeys
        (&Method::GET, ["api", "users", id, "passkeys"]) => {
            management::list_passkeys(auth, id).await
        }
        // POST /api/users/:id/passkeys/register-options
        (&Method::POST, ["api", "users", id, "passkeys", "register-options"]) => {
            management::passkey_register_options(auth, id).await
        }
        // POST /api/users/:id/passkeys/register-complete
        (&Method::POST, ["api", "users", id, "passkeys", "register-complete"]) => {
            management::passkey_register_complete(auth, id, body).await
        }
        // DELETE /api/users/:id/passkeys/:cred_id
        (&Method::DELETE, ["api", "users", id, "passkeys", cred_id]) => {
            management::delete_passkey(auth, id, cred_id).await
        }
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
        (&Method::POST, ["api", "hooks", id, "test"]) => management::test_hook(auth, id).await,
        // GET /api/hooks/:id/versions
        (&Method::GET, ["api", "hooks", id, "versions"]) => {
            management::list_hook_versions(auth, id).await
        }
        _ => Ok(error_json(StatusCode::NOT_FOUND, "not found")),
    }
}

async fn handle_register(body_bytes: &[u8]) -> Result<Response<String>, String> {
    #[derive(serde::Deserialize)]
    struct RegisterReq {
        email: String,
        password: String,
        name: String,
    }

    let req: RegisterReq =
        serde_json::from_slice(body_bytes).map_err(|e| format!("invalid JSON: {e}"))?;

    // Gate: registration must be explicitly allowed (or bootstrap window open)
    if !is_registration_allowed().await {
        return Ok(error_json(
            StatusCode::FORBIDDEN,
            "registration is currently closed",
        ));
    }

    // Rate limit registration: 3 attempts per hour per IP (well, just use a generic key for now if we don't have IP)
    // Actually Task 1.4 says "per-IP or per-email". Let's use email for now as we don't have easy IP access yet.
    match crate::service_client::check_rate(
        &format!("register:{}", req.email.to_lowercase()),
        3,
        3600,
    )
    .await
    {
        Ok((false, _)) => {
            return Err("too many registration attempts. please try again later.".into());
        }
        Err(e) => logger::error_message("rate_limit.register_check_failed", e),
        _ => {}
    }

    if req.email.is_empty() || !req.email.contains('@') {
        return Err("invalid email".into());
    }
    // Reject emails that are clearly malformed or contain dangerous characters
    let (local, domain) = req.email.rsplit_once('@').unwrap();
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("invalid email format".into());
    }
    if req.email.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("email contains invalid characters".into());
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

    // Hash password via password-hasher
    let password_hash = service_client::hash_password(&req.password).await?;

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
        passkey_credentials: Vec::new(),
    };

    match store::create_user(&user).await {
        Ok(_) => {
            let _ = store::log_audit("user_registered", &user.id, &user.id, &user.email).await;

            // Bootstrap hook: config-supplied Rhai script for zero-credential setup
            let mut user_mut = user.clone();
            let boot = hooks::execute_bootstrap_hook(&user_mut).await;
            if let Some(reason) = &boot.deny_reason {
                let _ = store::log_audit(
                    "registration_denied_by_bootstrap_hook",
                    &user_mut.id,
                    &user_mut.id,
                    reason,
                )
                .await;
                return Err(format!("registration denied: {reason}"));
            }
            if let Err(e) = hooks::apply_outcome(&mut user_mut, &boot).await {
                logger::error_message("bootstrap_hook.apply_failed", e);
            }

            // When bootstrap promotes the first superadmin, ensure the
            // lid-admin OAuth client exists so the admin UI can log in.
            // In dev mode this is handled per-request, but production
            // deployments only reach here once during initial bootstrap.
            if boot.set_superadmin == Some(true) {
                let issuer = get_issuer();
                if let Err(e) = store::ensure_admin_client(&issuer, false).await {
                    logger::error_message("bootstrap.ensure_admin_client_failed", e);
                }
            }

            // Execute post-registration hooks (Rhai scripting)
            let outcome = hooks::execute_hooks("post-registration", &user_mut).await;
            if let Some(reason) = &outcome.deny_reason {
                let _ = store::log_audit(
                    "registration_denied_by_hook",
                    &user_mut.id,
                    &user_mut.id,
                    reason,
                )
                .await;
                return Err(format!("registration denied: {reason}"));
            }
            if let Err(e) = hooks::apply_outcome(&mut user_mut, &outcome).await {
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
        store::save_invitation(&verify_inv).await?;
        let _ = store::log_audit(
            "email_verification_link_generated",
            &user.id,
            &user.id,
            &store::sanitize_email_for_lookup(&verify_token),
        )
        .await;
        if is_dev_mode() {
            logger::info(
                &format!("LID_VERIFY: {} {}", user.email, verify_token),
                serde_json::json!({}),
            );
        }
        email::send_verification_email(&get_issuer(), &user.email, &user.name, &verify_token).await;
    }

    let resp = serde_json::json!({
        "status": "success",
        "message": "User registered successfully",
    });

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&resp).unwrap_or_default())
        .unwrap())
}

async fn handle_password_reset_complete(body_bytes: &[u8]) -> Result<Response<String>, String> {
    #[derive(serde::Deserialize)]
    struct ResetReq {
        token: String,
        new_password: String,
    }

    let req: ResetReq =
        serde_json::from_slice(body_bytes).map_err(|e| format!("invalid JSON: {e}"))?;

    // Rate limit reset: 5 attempts per 15 mins per token
    match crate::service_client::check_rate(&format!("reset_complete:{}", req.token), 5, 900).await
    {
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
    let inv = match store::get_invitation(&req.token).await {
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
                .body(r#"{"ok":true,"message":"If the token was valid, your password has been reset."}"#.to_string())
                .unwrap());
        }
    };

    // Find user by email
    let user = store::get_user_by_email(&inv.email)
        .await?
        .ok_or("user not found")?;

    // Hash new password and update user atomically
    let new_hash = service_client::hash_password(&req.new_password).await?;
    store::update_user_rmw(&user.id, |u| {
        u.password_hash = new_hash.clone();
        Ok(true)
    })
    .await?;

    // Clean up token
    store::delete_invitation(&req.token).await?;

    // Revoke all refresh tokens for this user
    if let Err(e) = store::delete_user_refresh_tokens(&user.id).await {
        logger::error_message("password_reset.revoke_tokens_failed", e);
    }

    let _ = store::log_audit(
        "password_reset_completed",
        &user.id,
        &user.id,
        "password reset via token",
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(r#"{"ok":true}"#.to_string())
        .unwrap())
}

/// Handle GET /logout — RP-initiated logout (OIDC RP-Initiated Logout 1.0).
async fn handle_logout(query: &str, auth: Option<&str>) -> Result<Response<String>, String> {
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

    // Identify the client (aud) from the token, if any. We bind
    // post_logout_redirect_uri validation to this client to prevent open
    // redirects via another client's registered URI.
    let mut hinted_client_id: Option<String> = None;
    if let Some(token) = token
        && let Ok(claims) =
            service_client::verify_token_scoped(token, Some(&get_issuer()), None, None).await
        && let Some(sub) = claims.get("sub").and_then(|v| v.as_str())
    {
        hinted_client_id = claims
            .get("aud")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // Backchannel logout: notify clients before revoking tokens
        backchannel::notify_all_clients(sub, &get_issuer()).await;
        // Revoke all refresh tokens for this user
        let _ = store::delete_user_refresh_tokens(sub).await;
        let _ = store::log_audit("logout", sub, sub, "").await;
    }

    // Redirect to post_logout_redirect_uri if provided, otherwise show confirmation.
    // RP-Initiated Logout 1.0: the URI must be registered with the *specific*
    // client identified by id_token_hint. If id_token_hint is missing or invalid,
    // reject the redirect to prevent open-redirect abuse.
    let uri_allowed = async |uri: &str| -> bool {
        let Some(cid) = hinted_client_id.as_deref() else {
            return false;
        };
        match store::get_client(cid).await {
            Ok(Some(c)) => c.redirect_uris.iter().any(|ru| ru == uri),
            _ => false,
        }
    };

    match post_logout_uri {
        Some(uri) if !uri.is_empty() && uri_allowed(uri).await => {
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
                .body(String::new())
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
                .body(html.to_string())
                .unwrap())
        }
    }
}

const MAX_BODY_SIZE: usize = 1_048_576; // 1 MiB

async fn read_body(body: IncomingRequestBody) -> Result<Vec<u8>, String> {
    let bytes = http_client::collect_body(body).await?;
    if bytes.len() > MAX_BODY_SIZE {
        return Err("request body too large".into());
    }
    Ok(bytes)
}

fn healthz() -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(r#"{"ok":true,"status":"healthy"}"#.to_string())
        .unwrap()
}

/// Build info: returned by GET /version. Useful for customers integrating
/// against a development build to correlate behaviour to a specific commit.
fn version_response() -> Response<String> {
    let body = serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("LATTICE_ID_GIT_SHA").unwrap_or("unknown"),
        "build_date": option_env!("LATTICE_ID_BUILD_DATE").unwrap_or("unknown"),
        "rustc": option_env!("LATTICE_ID_RUSTC").unwrap_or("unknown"),
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap()
}

async fn handle_metrics(auth: Option<&str>) -> Result<Response<String>, String> {
    if !is_dev_mode() {
        let claims = management::require_auth(auth).await?;
        management::require_superadmin(&claims)?;
    }

    // Metrics are collected via NATS publish (fire-and-forget).
    // A dedicated metrics subscriber can aggregate them in the future.
    let metrics = String::from(
        "# lattice-id metrics endpoint\n# Metrics are published via NATS (lid.metrics)\n",
    );
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .header("cache-control", "no-store")
        .body(metrics)
        .unwrap())
}

fn index_page() -> Response<String> {
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
        .body(html.to_string())
        .unwrap()
}

/// Serve admin UI assets from the `lattice-id:admin/assets` component.
/// SPA fallback: any path that doesn't match a file gets index.html.
fn serve_admin_asset(route_path: &str) -> Response<String> {
    use bindings::lattice_id::admin::assets;

    // Strip /admin prefix to get the asset path within the SPA.
    let asset_path = route_path.strip_prefix("/admin").unwrap_or("");
    let asset_path = asset_path.strip_prefix('/').unwrap_or(asset_path);

    // Try the exact path first, then fall back to index.html (SPA routing).
    let asset = if asset_path.is_empty() {
        assets::get_asset("index.html")
    } else {
        assets::get_asset(asset_path).or_else(|| assets::get_asset("index.html"))
    };

    match asset {
        Some(a) => {
            // The HTTP layer uses Response<String> but WASI serializes it as
            // raw bytes. For binary assets (wasm, images) we use unchecked
            // conversion to preserve the exact bytes through the pipeline.
            let body = if a.content_type.starts_with("text/")
                || a.content_type.contains("javascript")
                || a.content_type.contains("json")
            {
                String::from_utf8(a.data).unwrap_or_default()
            } else {
                // SAFETY: these bytes are never used as a Rust &str — they
                // pass straight into the WASI HTTP response body encoder.
                unsafe { String::from_utf8_unchecked(a.data) }
            };
            // Cache static assets (hashed filenames) aggressively.
            // Snippet files (snippets/**) are NOT hashed by name and must not
            // be cached indefinitely — they can renumber across builds.
            let is_hashed = asset_path.contains('-')
                && !asset_path.starts_with("snippets/")
                && (asset_path.ends_with(".js")
                    || asset_path.ends_with(".wasm")
                    || asset_path.ends_with(".css"));
            let cache = if is_hashed {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", &a.content_type)
                .header("cache-control", cache)
                .body(body)
                .unwrap()
        }
        None => {
            // No admin-ui-host component linked — show a helpful message.
            let html = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Admin UI</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8fafc;color:#0f172a}.card{max-width:480px;background:#fff;border-radius:12px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,.08)}h1{margin:0 0 12px}p{line-height:1.6;color:#475569}a{color:#2563eb}</style>
</head><body><div class="card"><h1>Admin UI Not Available</h1>
<p>The admin-ui-host component is not loaded. Add it to your workload deployment or run <code>trunk serve</code> in the admin-ui directory for development.</p>
<p><a href="/">Back</a></p></div></body></html>"#;
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .header("content-type", "text/html; charset=utf-8")
                .body(html.to_string())
                .unwrap()
        }
    }
}

async fn readyz(auth: Option<&str>) -> Result<Response<String>, String> {
    let kv_started = std::time::Instant::now();
    let users_probe = store::list_users().await.is_ok();
    let clients_probe = store::list_clients().await.is_ok();
    let kv_latency_ms = kv_started.elapsed().as_millis() as u64;
    let keyvalue = users_probe && clients_probe;

    let keys_ok = keys::KeyStore::load().await.is_ok();

    let status = if keyvalue && keys_ok {
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
                "keyvalue": keyvalue,
                "keys_loaded": keys_ok,
            },
            "details": {
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
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap())
}

pub fn error_json(status: StatusCode, msg: &str) -> Response<String> {
    // Map HTTP status to a coarse OAuth2-style error code so RFC 6749 clients
    // can parse the response. Endpoints with specific OAuth2 semantics (token,
    // introspect, revoke) use their own `*_error` helpers with proper codes.
    let error_code = match status.as_u16() {
        400 => "invalid_request",
        401 => "invalid_token",
        403 => "insufficient_scope",
        404 => "not_found",
        429 => "too_many_requests",
        s if s >= 500 => "server_error",
        _ => "error",
    };
    let body = serde_json::json!({
        "error": error_code,
        "error_description": msg,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body).unwrap_or_default())
        .unwrap()
}

/// Derive the allowed CORS origin from registered client redirect URIs.
async fn allowed_origin(req_origin: Option<&str>) -> Option<String> {
    let origin = req_origin?;
    if origin.is_empty() {
        return None;
    }
    let clients = store::list_clients().await.ok()?;
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
///
/// Public-info endpoints (discovery, JWKS, version) get a permissive `*`
/// origin and skip credentials so they can be fetched from any browser context.
/// All other endpoints echo the origin only if it matches a registered
/// client redirect URI, and include `allow-credentials: true`.
async fn with_cors_and_security(
    resp: Response<String>,
    req_origin: Option<&str>,
    request_id: &str,
    path: &str,
) -> Response<String> {
    let (mut parts, body) = resp.into_parts();
    let public_path = matches!(
        path,
        "/.well-known/openid-configuration" | "/.well-known/jwks.json" | "/version" | "/health"
    );

    if public_path {
        parts
            .headers
            .insert("access-control-allow-origin", "*".parse().unwrap());
    } else {
        let origin_value = allowed_origin(req_origin)
            .await
            .unwrap_or_else(|| "null".to_string());
        parts
            .headers
            .insert("access-control-allow-origin", origin_value.parse().unwrap());
        parts
            .headers
            .insert("access-control-allow-credentials", "true".parse().unwrap());
    }
    parts.headers.insert(
        "access-control-allow-methods",
        "GET, POST, DELETE, OPTIONS".parse().unwrap(),
    );
    parts.headers.insert(
        "access-control-allow-headers",
        "authorization, content-type, traceparent, x-request-id, x-lid-consistency"
            .parse()
            .unwrap(),
    );
    parts.headers.insert(
        "access-control-expose-headers",
        "x-request-id, x-lid-consistency".parse().unwrap(),
    );
    parts
        .headers
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    parts
        .headers
        .insert("x-frame-options", "DENY".parse().unwrap());

    // Task 1.10: Content-Security-Policy
    // Allow 'unsafe-inline' for script-src: login page passkey JS and account
    // page WebAuthn JS are inline scripts authored by gateway (not user-supplied).
    parts.headers.insert(
        "content-security-policy",
        "default-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self';"
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

fn cors_preflight_base() -> Response<String> {
    // CORS origin/methods/headers are added by with_cors_and_security in main()
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-max-age", "86400")
        .body(String::new())
        .unwrap()
}
