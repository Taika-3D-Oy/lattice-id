use crate::store::{self, ClientTheme};
use crate::util;
use wstd::http::{Body, Response, StatusCode};

const ACR_TOTP_MFA: &str = "urn:lattice-id:mfa:totp";

fn primary_amr_for_flow(flow: &str) -> Vec<String> {
    match flow {
        "password" => vec!["pwd".to_string()],
        _ => Vec::new(),
    }
}

fn merge_amr(primary: &[String], additions: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for item in primary {
        if !values.iter().any(|existing| existing == item) {
            values.push(item.clone());
        }
    }
    for item in additions {
        if !values.iter().any(|existing| existing == item) {
            values.push((*item).to_string());
        }
    }
    values
}

fn select_acr(session: &store::AuthSession, amr: &[String]) -> Option<String> {
    let has_mfa = amr.iter().any(|value| value == "mfa") && amr.iter().any(|value| value == "otp");
    if has_mfa {
        return Some(ACR_TOTP_MFA.to_string());
    }

    if session.acr_values.iter().any(|value| value == ACR_TOTP_MFA) {
        return None;
    }

    None
}

/// Default theme used when no client theme is configured.
fn default_theme() -> ClientTheme {
    ClientTheme {
        app_name: "Lattice-ID".to_string(),
        logo_url: None,
        primary_color: None,
        background_color: None,
    }
}

/// Resolve the theme for the current auth session's client.
fn resolve_theme(session_id: &str) -> ClientTheme {
    let session = match store::get_auth_session(session_id) {
        Ok(Some(s)) => s,
        _ => return default_theme(),
    };
    match store::get_client(&session.client_id) {
        Ok(Some(c)) => c.theme.unwrap_or_else(default_theme),
        _ => default_theme(),
    }
}

fn hinted_email(session_id: &str) -> Option<String> {
    store::get_auth_session(session_id)
        .ok()
        .flatten()
        .and_then(|session| session.hinted_email)
}

/// Render the login page HTML with theming, optional Google button, and optional MFA.
pub fn login_page(session_id: &str, error: Option<&str>) -> Response<Body> {
    let theme = resolve_theme(session_id);
    let hinted_email = hinted_email(session_id).unwrap_or_default();
    let primary = util::sanitize_color(theme.primary_color.as_deref(), "#2563eb");
    let primary_hover = darken_hex(&primary);
    let bg = util::sanitize_color(theme.background_color.as_deref(), "#f8fafc");
    let app_name = util::html_escape(&theme.app_name);

    let logo_html = match &theme.logo_url {
        Some(url) if util::is_safe_url(url) => format!(
            r#"<img src="{}" alt="{}" style="max-height:48px;margin-bottom:16px">"#,
            util::html_escape(url),
            app_name,
        ),
        _ => String::new(),
    };

    let error_html = match error {
        Some(msg) => format!(
            r#"<div style="color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;padding:10px 14px;border-radius:6px;margin-bottom:16px;font-size:14px">{}</div>"#,
            util::html_escape(msg)
        ),
        None => String::new(),
    };

    // Check if Google identity provider is enabled
    let google_enabled = store::get_identity_provider_by_type("google")
        .ok()
        .flatten()
        .is_some();

    let google_html = if google_enabled {
        format!(
            r##"<div class="divider"><span>or</span></div>
<a href="/auth/google?session_id={session_id}" class="google-btn">
<svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
Continue with Google
</a>"##,
            session_id = session_id
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — {app_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:{bg};min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:40px;width:100%;max-width:400px}}
h1{{font-size:24px;font-weight:600;color:#0f172a;margin-bottom:8px}}
.sub{{color:#64748b;font-size:14px;margin-bottom:24px}}
label{{display:block;font-size:14px;font-weight:500;color:#334155;margin-bottom:6px}}
input[type=email],input[type=password]{{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px;margin-bottom:16px;outline:none;transition:border .15s}}
input:focus{{border-color:{primary};box-shadow:0 0 0 3px {primary}1a}}
button{{width:100%;padding:12px;background:{primary};color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;transition:background .15s}}
button:hover{{background:{primary_hover}}}
.divider{{display:flex;align-items:center;margin:20px 0;color:#94a3b8;font-size:13px}}
.divider::before,.divider::after{{content:'';flex:1;border-bottom:1px solid #e2e8f0}}
.divider span{{padding:0 12px}}
.google-btn{{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px;font-weight:500;color:#334155;text-decoration:none;transition:background .15s;cursor:pointer}}
.google-btn:hover{{background:#f1f5f9}}
.footer{{text-align:center;margin-top:20px;font-size:12px;color:#94a3b8}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Sign In</h1>
<p class="sub">{app_name}</p>
{error_html}
<form method="POST" action="/login">
<input type="hidden" name="session_id" value="{session_id}">
<label for="email">Email</label>
<input type="email" id="email" name="email" value="{hinted_email}" required autocomplete="email" autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
<button type="submit">Sign In</button>
</form>
{google_html}
<p class="footer">Powered by Lattice-ID</p>
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.into())
        .unwrap()
}

/// Render MFA challenge page (TOTP code input).
pub fn mfa_page(mfa_token: &str, session_id: &str, error: Option<&str>) -> Response<Body> {
    let theme = resolve_theme(session_id);
    let primary = util::sanitize_color(theme.primary_color.as_deref(), "#2563eb");
    let primary_hover = darken_hex(&primary);
    let bg = util::sanitize_color(theme.background_color.as_deref(), "#f8fafc");
    let app_name = util::html_escape(&theme.app_name);

    let error_html = match error {
        Some(msg) => format!(
            r#"<div style="color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;padding:10px 14px;border-radius:6px;margin-bottom:16px;font-size:14px">{}</div>"#,
            util::html_escape(msg)
        ),
        None => String::new(),
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-Factor Authentication — {app_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:{bg};min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:40px;width:100%;max-width:400px}}
h1{{font-size:24px;font-weight:600;color:#0f172a;margin-bottom:8px}}
.sub{{color:#64748b;font-size:14px;margin-bottom:24px}}
label{{display:block;font-size:14px;font-weight:500;color:#334155;margin-bottom:6px}}
input[type=text]{{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:20px;margin-bottom:16px;outline:none;text-align:center;letter-spacing:8px;font-family:monospace}}
input:focus{{border-color:{primary};box-shadow:0 0 0 3px {primary}1a}}
button{{width:100%;padding:12px;background:{primary};color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;transition:background .15s}}
button:hover{{background:{primary_hover}}}
.hint{{color:#64748b;font-size:13px;margin-top:12px;text-align:center}}
.footer{{text-align:center;margin-top:20px;font-size:12px;color:#94a3b8}}
</style>
</head>
<body>
<div class="card">
<h1>Two-Factor Authentication</h1>
<p class="sub">Enter the code from your authenticator app</p>
{error_html}
<form method="POST" action="/login/mfa">
<input type="hidden" name="mfa_token" value="{mfa_token}">
<input type="hidden" name="session_id" value="{session_id}">
<label for="code">Authentication Code</label>
<input type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{{6,8}}" maxlength="8" autofocus>
<button type="submit">Verify</button>
</form>
<p class="hint">You can also use a recovery code</p>
<p class="footer">Powered by Lattice-ID</p>
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.into())
        .unwrap()
}

/// Handle POST /login — validate credentials, check MFA, issue auth code, redirect.
pub async fn handle_login(body_bytes: &[u8], remote_ip: &str) -> Result<Response<Body>, String> {
    let form = util::parse_form(body_bytes);
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let email = util::form_value(&form, "email").ok_or("missing email")?;
    let password = util::form_value(&form, "password").ok_or("missing password")?;

    // Task 2.8: Suspicious login detection (Log IP)
    let _ = crate::store::log_audit("login_attempt", "", "", &format!("email:{} ip:{}", email, remote_ip));

    // Rate limit: 10 login attempts per email per 60 seconds
    match crate::service_client::check_rate(&format!("login:{}", email.to_lowercase()), 10, 60).await
    {
        Ok((false, _)) => {
            let _ = crate::service_client::increment_metric(
                "lattice_id_rate_limit_hits_total",
                &[("scope", "login")],
            )
            .await;
            return Ok(login_page(
                session_id,
                Some("Too many login attempts. Please wait and try again."),
            ));
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.login_check_failed", e);
        }
        _ => {}
    }

    // Load auth session
    let session = crate::store::get_auth_session(session_id)?.ok_or("invalid or expired session")?;

    // Check auth session expiry (e.g., 10 minutes)
    if crate::store::unix_now() > session.created_at + 600 {
        return Ok(login_page(session_id, Some("Login session expired. Please start over.")));
    }

    // Look up user by email.
    // Return the same generic error for non-existent AND pending users
    // to prevent email enumeration (CWE-200).
    let user = match crate::store::get_user_by_email(email)? {
        Some(u) if u.status == "active" => u,
        _ => {
            // Cross-region redirect: if user not found locally, check remote regions
            if store::region_id().is_some() {
                let email_hash = store::sanitize_email_for_lookup(&email.to_lowercase());
                if let Ok(Some(region)) = crate::service_client::lookup_region(&email_hash).await {
                    if let Some(base_url) = store::region_domain(&region) {
                        // Redirect to the remote region's /authorize preserving OIDC params
                        let enc = crate::util::percent_encode;
                        let mut url = format!(
                            "{}/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method={}&state={}&scope={}&nonce={}&login_hint={}",
                            base_url,
                            enc(&session.client_id),
                            enc(&session.redirect_uri),
                            enc(&session.code_challenge),
                            enc(&session.code_challenge_method),
                            enc(&session.state),
                            enc(&session.scope),
                            enc(&session.nonce),
                            enc(email),
                        );
                        if let Some(max_age) = session.max_age {
                            url.push_str(&format!("&max_age={max_age}"));
                        }
                        // Clean up the local session
                        let _ = store::delete_auth_session(session_id);
                        return Ok(Response::builder()
                            .status(wstd::http::StatusCode::FOUND)
                            .header("location", &url)
                            .body(Body::empty())
                            .unwrap());
                    }
                }
            }

            // Perform a dummy password hash to prevent timing-based enumeration.
            let _ = crate::service_client::verify_password(password, "$argon2id$v=19$m=32768,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            return Ok(login_page(session_id, Some("Invalid email or password")));
        }
    };

    // Check account lockout
    if crate::store::is_account_locked(&user.id)? {
        let _ = crate::store::log_audit("login_locked", &user.id, &user.id, "account locked");
        let _ = crate::service_client::increment_metric(
            "lattice_id_login_attempts_total",
            &[("flow", "password"), ("result", "failure")],
        )
        .await;
        return Ok(login_page(
            session_id,
            Some(
                "Account temporarily locked due to too many failed attempts. Please try again later.",
            ),
        ));
    }

    // Verify password via core-service
    match crate::service_client::verify_password(password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            let locked = crate::store::record_failed_login(&user.id).unwrap_or(false);
            let _ = crate::store::log_audit("login_failure", &user.id, &user.id, email);
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            if locked {
                let _ = crate::store::log_audit(
                    "account_locked",
                    &user.id,
                    &user.id,
                    "locked after repeated failures",
                );
                return Ok(login_page(
                    session_id,
                    Some("Account temporarily locked due to too many failed attempts."),
                ));
            }
            return Ok(login_page(session_id, Some("Invalid email or password")));
        }
        Err(e) => {
            crate::logger::error_message("authentication.password_verify_failed", e);
            return Ok(login_page(session_id, Some("Authentication service error")));
        }
    }

    // Password verified — check if MFA is required
    if user.totp_enabled {
        let mfa_token = store::random_hex(32);
        let pending = store::MfaPending {
            user_id: user.id.clone(),
            session_id: session_id.to_string(),
            primary_amr: primary_amr_for_flow("password"),
            expires_at: store::unix_now() + 300, // 5 minutes
            remote_ip: remote_ip.to_string(),
        };
        store::save_mfa_pending(&mfa_token, &pending)?;
        return Ok(mfa_page(&mfa_token, session_id, None));
    }

    // No MFA — complete login
    complete_login(&user, session_id, "password", remote_ip).await
}

/// Handle POST /login/mfa — verify TOTP code and complete login.
pub async fn handle_mfa(body_bytes: &[u8], _remote_ip: &str) -> Result<Response<Body>, String> {
    let form = util::parse_form(body_bytes);
    let mfa_token = util::form_value(&form, "mfa_token").ok_or("missing mfa_token")?;
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let code = util::form_value(&form, "code").ok_or("missing code")?;

    // Rate limit MFA: 5 attempts per token per 15 minutes
    match crate::service_client::check_rate(&format!("mfa:{}", mfa_token), 5, 900).await {
        Ok((false, _)) => {
            let _ = store::delete_mfa_pending(mfa_token);
            return Ok(login_page(session_id, Some("Too many MFA attempts. Session invalidated.")));
        }
        Err(e) => crate::logger::error_message("rate_limit.mfa_check_failed", e),
        _ => {}
    }

    let pending = store::get_mfa_pending(mfa_token)?.ok_or("invalid or expired MFA session")?;
    if store::unix_now() > pending.expires_at {
        store::delete_mfa_pending(mfa_token)?;
        return Ok(login_page(
            session_id,
            Some("MFA session expired, please log in again"),
        ));
    }

    let user = store::get_user(&pending.user_id)?.ok_or("user not found")?;

    let totp_secret = user
        .totp_secret
        .as_deref()
        .ok_or("MFA not configured for this user")?;

    // Try TOTP code first
    if crate::totp::verify_totp(totp_secret, code.trim()) {
        store::delete_mfa_pending(mfa_token)?;
        let _ = store::log_audit("mfa_success", &user.id, &user.id, "totp");
        let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
        return complete_login_with_amr(&user, session_id, "totp", amr, &pending.remote_ip).await;
    }

    // Try recovery codes
    let code_trimmed = code.trim().to_lowercase();
    let mut updated_user = user.clone();
    if let Some(pos) = updated_user
        .recovery_codes
        .iter()
        .position(|c| crate::totp::constant_time_eq(c.as_bytes(), code_trimmed.as_bytes()))
    {
        updated_user.recovery_codes.remove(pos);
        store::update_user(&updated_user)?;
        store::delete_mfa_pending(mfa_token)?;
        let _ = store::log_audit(
            "mfa_success",
            &updated_user.id,
            &updated_user.id,
            "recovery_code",
        );
        let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
        return complete_login_with_amr(&updated_user, session_id, "recovery_code", amr, &pending.remote_ip).await;
    }

    let _ = store::log_audit("mfa_failure", &updated_user.id, &updated_user.id, "");
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", "mfa"), ("result", "failure")],
    )
    .await;
    Ok(mfa_page(
        mfa_token,
        session_id,
        Some("Invalid code. Please try again."),
    ))
}

/// Complete login after password (and optional MFA) verification.
pub async fn complete_login(
    user: &store::User,
    session_id: &str,
    flow: &str,
    remote_ip: &str,
) -> Result<Response<Body>, String> {
    complete_login_with_amr(user, session_id, flow, primary_amr_for_flow(flow), remote_ip).await
}

async fn complete_login_with_amr(
    user: &store::User,
    session_id: &str,
    flow: &str,
    amr: Vec<String>,
    remote_ip: &str,
) -> Result<Response<Body>, String> {
    // Execute post-login hooks (Rhai scripting)
    let outcome = crate::hooks::execute_hooks("post-login", user);

    // If a hook denied the login, abort
    if let Some(reason) = &outcome.deny_reason {
        let _ = crate::store::log_audit(
            "login_denied_by_hook",
            &user.id,
            &user.id,
            reason,
        );
        return Ok(login_page(session_id, Some(reason)));
    }

    // Apply hook side-effects (superadmin promotion, tenant membership, etc.)
    let mut user = user.clone();
    if let Err(e) = crate::hooks::apply_outcome(&mut user, &outcome) {
        crate::logger::error_message("hooks.apply_failed", e);
    }

    // Suspicious login detection: flag logins from previously-unseen IPs
    if store::check_and_record_ip(&user.id, remote_ip) {
        let _ = store::log_audit(
            "suspicious_login",
            &user.id,
            &user.id,
            &format!("new_ip:{}", remote_ip),
        );
    }

    let _ = crate::store::clear_login_attempts(&user.id);
    let _ = crate::store::log_audit("login_success", &user.id, &user.id, "");
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", flow), ("result", "success")],
    )
    .await;

    let session =
        crate::store::get_auth_session(session_id)?.ok_or("invalid or expired session")?;
    let acr = select_acr(&session, &amr);

    // Generate auth code
    let code = crate::store::random_hex(32);
    let auth_time = crate::store::unix_now();
    let auth_code = crate::store::AuthCode {
        user_id: user.id.clone(),
        client_id: session.client_id.clone(),
        redirect_uri: session.redirect_uri.clone(),
        code_challenge: session.code_challenge.clone(),
        code_challenge_method: session.code_challenge_method.clone(),
        nonce: session.nonce.clone(),
        scope: session.scope.clone(),
        auth_time,
        amr,
        acr,
        requested_id_token_claims: session.requested_id_token_claims.clone(),
        requested_userinfo_claims: session.requested_userinfo_claims.clone(),
        extra_claims: outcome.extra_claims.clone(),
        expires_at: crate::store::unix_now() + 300,
    };
    crate::store::save_auth_code(&code, &auth_code)?;
    let _ = crate::store::delete_auth_session(session_id);

    let mut redirect_url = format!("{}?code={code}", session.redirect_uri);
    if !session.state.is_empty() {
        redirect_url.push_str(&format!("&state={}", session.state));
    }

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &redirect_url)
        .header("cache-control", "no-store")
        .body(Body::empty())
        .unwrap())
}

/// Darken a hex color by ~15% for hover states.
fn darken_hex(hex: &str) -> String {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return "#1d4ed8".to_string(); // fallback
    }
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(37);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(99);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(235);
    let darken = |c: u8| (c as f32 * 0.85) as u8;
    format!("#{:02x}{:02x}{:02x}", darken(r), darken(g), darken(b))
}
