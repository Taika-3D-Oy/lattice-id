use crate::store::{self, ClientTheme};
use crate::util;
use http::{Response, StatusCode};

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
async fn resolve_theme(session_id: &str) -> ClientTheme {
    let session = match store::get_auth_session(session_id).await {
        Ok(Some(s)) => s,
        _ => return default_theme(),
    };
    match store::get_client(&session.client_id).await {
        Ok(Some(c)) => c.theme.unwrap_or_else(default_theme),
        _ => default_theme(),
    }
}

async fn hinted_email(session_id: &str) -> Option<String> {
    store::get_auth_session(session_id)
        .await
        .ok()
        .flatten()
        .and_then(|session| session.hinted_email)
}

/// Render the login page HTML with theming, optional Google button, and optional MFA.
pub async fn login_page(session_id: &str, error: Option<&str>) -> Response<String> {
    let theme = resolve_theme(session_id).await;
    let hinted_email = hinted_email(session_id).await.unwrap_or_default();
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
        .await
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
button,.passkey-btn{{width:100%;padding:12px;background:{primary};color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;transition:background .15s}}
button:hover,.passkey-btn:hover{{background:{primary_hover}}}
.passkey-btn{{display:flex;align-items:center;justify-content:center;gap:8px;background:transparent;color:#334155;border:1px solid #cbd5e1}}
.passkey-btn:hover{{background:#f1f5f9}}
.divider{{display:flex;align-items:center;margin:20px 0;color:#94a3b8;font-size:13px}}
.divider::before,.divider::after{{content:'';flex:1;border-bottom:1px solid #e2e8f0}}
.divider span{{padding:0 12px}}
.google-btn{{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px;font-weight:500;color:#334155;text-decoration:none;transition:background .15s;cursor:pointer}}
.google-btn:hover{{background:#f1f5f9}}
.footer{{text-align:center;margin-top:20px;font-size:12px;color:#94a3b8}}
.passkey-error{{color:#b91c1c;font-size:13px;margin-top:8px;display:none}}
</style>
</head>
<body>
<div class="card">
{logo_html}
<h1>Sign In</h1>
<p class="sub">{app_name}</p>
{error_html}
<form method="POST" action="/login" id="login-form">
<input type="hidden" name="session_id" value="{session_id}">
<label for="email">Email</label>
<input type="email" id="email" name="email" value="{hinted_email}" required autocomplete="email" autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
<button type="submit" id="login-btn">Sign In</button>
</form>
{google_html}
<div id="passkey-section" style="display:none">
<div class="divider"><span>or</span></div>
<button type="button" class="passkey-btn" id="passkey-btn" onclick="startPasskeyAuth()">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
Sign in with passkey
</button>
<div class="passkey-error" id="passkey-error"></div>
</div>
<p class="footer"><a href="/account" style="color:#94a3b8;text-decoration:none">Manage your account</a> · Powered by Lattice-ID</p>
</div>
<script>
(function(){{
  if(!window.PublicKeyCredential)return;
  document.getElementById('passkey-section').style.display='block';

  function b64url(buf){{
    var s='',b=new Uint8Array(buf);
    for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }}
  function b64urlDecode(s){{
    s=s.replace(/-/g,'+').replace(/_/g,'/');
    while(s.length%4)s+='=';
    var b=atob(s),a=new Uint8Array(b.length);
    for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);
    return a.buffer;
  }}

  window.startPasskeyAuth=async function(){{
    var errEl=document.getElementById('passkey-error');
    var btn=document.getElementById('passkey-btn');
    errEl.style.display='none';
    btn.disabled=true;
    btn.textContent='Waiting for passkey\u2026';
    try{{
      var r=await fetch('/passkeys/auth-options',{{method:'POST',headers:{{'content-type':'application/json'}},body:'{{}}'}});
      if(!r.ok)throw new Error(await r.text());
      var d=await r.json();
      var opts=d.publicKey;
      opts.challenge=b64urlDecode(opts.challenge);
      if(opts.allowCredentials){{
        opts.allowCredentials=opts.allowCredentials.map(function(c){{
          c.id=b64urlDecode(c.id);return c;
        }});
      }}
      var cred=await navigator.credentials.get({{publicKey:opts}});
      var body=JSON.stringify({{
        token:d.token,
        session_id:'{session_id}',
        credential_id:b64url(cred.rawId),
        clientDataJSON:b64url(cred.response.clientDataJSON),
        authenticatorData:b64url(cred.response.authenticatorData),
        signature:b64url(cred.response.signature)
      }});
      var r2=await fetch('/passkeys/auth-complete',{{method:'POST',headers:{{'content-type':'application/json'}},body:body}});
      if(!r2.ok)throw new Error(await r2.text());
      var d2=await r2.json();
      if(d2.redirect){{window.location.href=d2.redirect;return;}}
      window.location.reload();
    }}catch(e){{
      if(e.name==='NotAllowedError'){{
        errEl.textContent='Passkey authentication was cancelled.';
      }}else{{
        errEl.textContent='Passkey error: '+(e.message||e);
      }}
      errEl.style.display='block';
      btn.disabled=false;
      btn.innerHTML='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg> Sign in with passkey';
    }}
  }};
}})();
// Prevent double-submit on login form
var f=document.getElementById('login-form');
if(f)f.addEventListener('submit',function(){{
  var b=document.getElementById('login-btn');
  if(b){{b.disabled=true;b.textContent='Signing in\u2026';}}
}});
</script>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

/// Render MFA challenge page (TOTP code input).
pub async fn mfa_page(mfa_token: &str, session_id: &str, error: Option<&str>) -> Response<String> {
    let theme = resolve_theme(session_id).await;
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
<form method="POST" action="/login/mfa" id="mfa-form">
<input type="hidden" name="mfa_token" value="{mfa_token}">
<input type="hidden" name="session_id" value="{session_id}">
<label for="code">Authentication Code</label>
<input type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{{6,8}}" maxlength="8" autofocus>
<button type="submit" id="mfa-btn">Verify</button>
</form>
<p class="hint">You can also use a recovery code</p>
<p class="footer">Powered by Lattice-ID</p>
</div>
<script>
var f=document.getElementById('mfa-form');
if(f)f.addEventListener('submit',function(){{
  var b=document.getElementById('mfa-btn');
  if(b){{b.disabled=true;b.textContent='Verifying\u2026';}}
}});
</script>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

/// Handle POST /login — validate credentials, check MFA, issue auth code, redirect.
pub async fn handle_login(body_bytes: &[u8], remote_ip: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let email = util::form_value(&form, "email").ok_or("missing email")?;
    let password = util::form_value(&form, "password").ok_or("missing password")?;

    // Task 2.8: Suspicious login detection (Log IP)
    let _ = crate::store::log_audit(
        "login_attempt",
        "",
        "",
        &format!("email:{} ip:{}", email, remote_ip),
    )
    .await;

    // Rate limit: 10 login attempts per email per 60 seconds
    match crate::service_client::check_rate(&format!("login:{}", email.to_lowercase()), 10, 60)
        .await
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
            )
            .await);
        }
        Err(e) => {
            crate::logger::error_message("rate_limit.login_check_failed", e);
        }
        _ => {}
    }

    // Load auth session
    let session = crate::store::get_auth_session(session_id)
        .await?
        .ok_or("invalid or expired session")?;

    // Check auth session expiry (e.g., 10 minutes)
    if crate::store::unix_now() > session.created_at + 600 {
        return Ok(login_page(
            session_id,
            Some("Login session expired. Please start over."),
        )
        .await);
    }

    // Look up user by email.
    // Return the same generic error for non-existent AND pending users
    // to prevent email enumeration (CWE-200).
    let user = match crate::store::get_user_by_email(email).await? {
        Some(u) if u.status == "active" => u,
        _ => {
            // Cross-region redirect: if user not found locally, check remote regions
            if store::region_id().is_some() {
                let email_hash = store::hmac_email(&email.to_lowercase());
                if let Ok(Some(region)) = crate::service_client::lookup_region(&email_hash).await
                    && let Some(base_url) = store::region_domain(&region)
                {
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
                    let _ = store::delete_auth_session(session_id).await;
                    return Ok(Response::builder()
                        .status(http::StatusCode::FOUND)
                        .header("location", &url)
                        .body(String::new())
                        .unwrap());
                }
            }

            // Perform a dummy password hash to prevent timing-based enumeration.
            let _ = crate::service_client::verify_password(
                password,
                "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ).await;
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
        }
    };

    // Check account lockout
    if crate::store::is_account_locked(&user.id).await? {
        let _ = crate::store::log_audit("login_locked", &user.id, &user.id, "account locked").await;
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
        ).await);
    }

    // Verify password via password-hasher
    match crate::service_client::verify_password(password, &user.password_hash).await {
        Ok(true) => {}
        Ok(false) => {
            let locked = crate::store::record_failed_login(&user.id)
                .await
                .unwrap_or(false);
            let _ = crate::store::log_audit("login_failure", &user.id, &user.id, email).await;
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
                )
                .await;
                return Ok(login_page(
                    session_id,
                    Some("Account temporarily locked due to too many failed attempts."),
                )
                .await);
            }
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
        }
        Err(_e) => {
            // Return the same generic message for all failures (including
            // social-only accounts whose password_hash isn't valid Argon2).
            // This prevents distinguishing social accounts from password accounts.
            let _ = crate::service_client::increment_metric(
                "lattice_id_login_attempts_total",
                &[("flow", "password"), ("result", "failure")],
            )
            .await;
            return Ok(login_page(session_id, Some("Invalid email or password")).await);
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
        store::save_mfa_pending(&mfa_token, &pending).await?;
        return Ok(mfa_page(&mfa_token, session_id, None).await);
    }

    // No MFA — complete login
    complete_login(&user, session_id, "password", remote_ip).await
}

/// Handle POST /login/mfa — verify TOTP code and complete login.
pub async fn handle_mfa(body_bytes: &[u8], _remote_ip: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let mfa_token = util::form_value(&form, "mfa_token").ok_or("missing mfa_token")?;
    let session_id = util::form_value(&form, "session_id").ok_or("missing session_id")?;
    let code = util::form_value(&form, "code").ok_or("missing code")?;

    // Rate limit MFA: 5 attempts per token per 15 minutes
    match crate::service_client::check_rate(&format!("mfa:{}", mfa_token), 5, 900).await {
        Ok((false, _)) => {
            let _ = store::delete_mfa_pending(mfa_token).await;
            return Ok(login_page(
                session_id,
                Some("Too many MFA attempts. Session invalidated."),
            )
            .await);
        }
        Err(e) => crate::logger::error_message("rate_limit.mfa_check_failed", e),
        _ => {}
    }

    let pending = store::get_mfa_pending(mfa_token)
        .await?
        .ok_or("invalid or expired MFA session")?;
    if store::unix_now() > pending.expires_at {
        store::delete_mfa_pending(mfa_token).await?;
        return Ok(login_page(session_id, Some("MFA session expired, please log in again")).await);
    }

    let user = store::get_user(&pending.user_id)
        .await?
        .ok_or("user not found")?;

    let totp_secret = user
        .totp_secret
        .as_deref()
        .ok_or("MFA not configured for this user")?;

    // Try TOTP code first
    if crate::totp::verify_totp(totp_secret, code.trim()) {
        store::delete_mfa_pending(mfa_token).await?;
        let _ = store::log_audit("mfa_success", &user.id, &user.id, "totp").await;
        let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
        return complete_login_with_amr(&user, session_id, "totp", amr, &pending.remote_ip).await;
    }

    // Try recovery codes — use CAS to prevent double-use across replicas
    let code_trimmed = code.trim().to_lowercase();
    let user_id = user.id.clone();
    let code_for_closure = code_trimmed.clone();
    let rmw_result =
        store::update_user_rmw(&user_id, |u| {
            if let Some(pos) = u.recovery_codes.iter().position(|c| {
                crate::totp::constant_time_eq(c.as_bytes(), code_for_closure.as_bytes())
            }) {
                u.recovery_codes.remove(pos);
                Ok(true) // commit
            } else {
                Ok(false) // code not found, no change
            }
        })
        .await;

    match rmw_result {
        Ok(()) => {
            // Check if the code was actually found (re-read to confirm)
            let updated_user = store::get_user(&user_id).await?.ok_or("user not found")?;
            // If the code is no longer present, it was consumed by us (or another replica — either way it's gone)
            if !updated_user
                .recovery_codes
                .iter()
                .any(|c| crate::totp::constant_time_eq(c.as_bytes(), code_trimmed.as_bytes()))
                && user
                    .recovery_codes
                    .iter()
                    .any(|c| crate::totp::constant_time_eq(c.as_bytes(), code_trimmed.as_bytes()))
            {
                store::delete_mfa_pending(mfa_token).await?;
                let _ = store::log_audit(
                    "mfa_success",
                    &updated_user.id,
                    &updated_user.id,
                    "recovery_code",
                )
                .await;
                let amr = merge_amr(&pending.primary_amr, &["otp", "mfa"]);
                return complete_login_with_amr(
                    &updated_user,
                    session_id,
                    "recovery_code",
                    amr,
                    &pending.remote_ip,
                )
                .await;
            }
        }
        Err(e) => {
            crate::logger::error_message("mfa.recovery_code_update_failed", e);
        }
    }

    let _ = store::log_audit("mfa_failure", &user.id, &user.id, "").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", "mfa"), ("result", "failure")],
    )
    .await;
    Ok(mfa_page(
        mfa_token,
        session_id,
        Some("Invalid code. Please try again."),
    )
    .await)
}

/// Complete login after password (and optional MFA) verification.
pub async fn complete_login(
    user: &store::User,
    session_id: &str,
    flow: &str,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    complete_login_with_amr(
        user,
        session_id,
        flow,
        primary_amr_for_flow(flow),
        remote_ip,
    )
    .await
}

pub async fn complete_login_with_amr(
    user: &store::User,
    session_id: &str,
    flow: &str,
    amr: Vec<String>,
    remote_ip: &str,
) -> Result<Response<String>, String> {
    // Execute post-login hooks (Rhai scripting)
    let outcome = crate::hooks::execute_hooks("post-login", user).await;

    // If a hook denied the login, abort
    if let Some(reason) = &outcome.deny_reason {
        let _ = crate::store::log_audit("login_denied_by_hook", &user.id, &user.id, reason).await;
        return Ok(login_page(session_id, Some(reason)).await);
    }

    // Apply hook side-effects (superadmin promotion, tenant membership, etc.)
    let mut user = user.clone();
    if let Err(e) = crate::hooks::apply_outcome(&mut user, &outcome).await {
        crate::logger::error_message("hooks.apply_failed", e);
    }

    // Suspicious login detection: flag logins from previously-unseen IPs
    if store::check_and_record_ip(&user.id, remote_ip).await {
        let _ = store::log_audit(
            "suspicious_login",
            &user.id,
            &user.id,
            &format!("new_ip:{}", remote_ip),
        )
        .await;
    }

    let _ = crate::store::clear_login_attempts(&user.id).await;
    let _ = crate::store::log_audit("login_success", &user.id, &user.id, "").await;
    let _ = crate::service_client::increment_metric(
        "lattice_id_login_attempts_total",
        &[("flow", flow), ("result", "success")],
    )
    .await;

    let session = crate::store::consume_auth_session(session_id)
        .await?
        .ok_or("Login already in progress. Please wait for the redirect.")?;
    let acr = select_acr(&session, &amr);

    // ── Device authorization grant (RFC 8628) ──
    // device::submit() creates an auth session with code_challenge_method = "device"
    // and state = device_code. Detect this and finalize the device code instead of
    // issuing an authorization code.
    if session.code_challenge_method == "device" {
        let device_code = &session.state;
        if let Err(e) =
            crate::store::update_device_code_status(device_code, "approved", Some(&user.id)).await
        {
            crate::logger::error_message("device.approve_failed", e);
            return Ok(login_page(
                session_id,
                Some("Failed to activate device. Please try again."),
            )
            .await);
        }
        let _ = crate::store::log_audit("device_approved", &user.id, &user.id, &session.client_id)
            .await;

        let mut builder = Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "/device/complete")
            .header("cache-control", "no-store");
        if let Ok(cookie) = crate::account::create_session_cookie(&user.id).await {
            builder = builder.header("set-cookie", cookie);
        }
        return Ok(builder.body(String::new()).unwrap());
    }

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
        amr: amr.clone(),
        acr: acr.clone(),
        requested_id_token_claims: session.requested_id_token_claims.clone(),
        requested_userinfo_claims: session.requested_userinfo_claims.clone(),
        extra_claims: outcome.extra_claims.clone(),
        expires_at: crate::store::unix_now() + 300,
        state: session.state.clone(),
    };

    // ── Consent screen ──────────────────────────────────────
    // If the session requires consent, show the consent page before issuing
    // the auth code. The consent page POSTs back with the code ready to use.
    if session.needs_consent {
        // Store the pending auth code *before* consent so we can issue it
        // after approval without re-doing the whole login.
        crate::store::save_auth_code(&code, &auth_code).await?;

        let client = crate::store::get_client(&auth_code.client_id)
            .await?
            .unwrap_or_default();
        return Ok(consent_page(&code, &auth_code, &client, &user).await);
    }

    crate::store::save_auth_code(&code, &auth_code).await?;

    let mut redirect_url = format!("{}?code={code}", session.redirect_uri);
    if !session.state.is_empty() {
        redirect_url.push_str(&format!("&state={}", session.state));
    }

    // Set account session cookie so the user can visit /account later
    let mut builder = Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &redirect_url)
        .header("cache-control", "no-store");
    if let Ok(cookie) = crate::account::create_session_cookie(&user.id).await {
        builder = builder.header("set-cookie", cookie);
    }

    Ok(builder.body(String::new()).unwrap())
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

/// Render the consent page shown to users for third-party / prompt=consent flows.
/// The page shows what scopes are requested and lets the user approve or deny.
pub async fn consent_page(
    code: &str,
    auth_code: &crate::store::AuthCode,
    client: &crate::store::OidcClient,
    user: &crate::store::User,
) -> Response<String> {
    let app_name = crate::util::html_escape(&client.name);
    let user_email = crate::util::html_escape(&user.email);
    let scope_list: Vec<&str> = auth_code
        .scope
        .split_whitespace()
        .filter(|s| *s != "openid")
        .collect();

    let scope_descriptions: Vec<String> = auth_code.scope.split_whitespace().map(|s| {
        let desc = match s {
            "openid"   => "Verify your identity",
            "email"    => "Read your email address",
            "profile"  => "Read your name and profile info",
            "offline_access" => "Stay signed in (refresh tokens)",
            other      => other,
        };
        format!(r#"<li style="padding:6px 0;border-bottom:1px solid #f1f5f9;color:#334155">{}</li>"#,
            crate::util::html_escape(desc))
    }).collect();
    let scopes_html = scope_descriptions.join("\n");

    let _ = scope_list; // suppress warning

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorise {app_name}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:40px;width:100%;max-width:440px}}
h1{{font-size:22px;font-weight:600;color:#0f172a;margin-bottom:6px}}
.sub{{color:#64748b;font-size:14px;margin-bottom:24px}}
.client-name{{font-weight:600;color:#0f172a}}
ul{{list-style:none;margin-bottom:24px;padding:0;border-top:1px solid #f1f5f9}}
.actions{{display:flex;gap:12px}}
button{{flex:1;padding:12px;border:none;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer}}
.btn-approve{{background:#2563eb;color:#fff}}
.btn-approve:hover{{background:#1d4ed8}}
.btn-deny{{background:#fff;color:#334155;border:1px solid #cbd5e1}}
.btn-deny:hover{{background:#f1f5f9}}
.footer{{text-align:center;margin-top:20px;font-size:12px;color:#94a3b8}}
</style>
</head>
<body>
<div class="card">
<h1>Authorise <span class="client-name">{app_name}</span></h1>
<p class="sub">Signed in as {user_email}</p>

<p style="font-size:14px;color:#334155;margin-bottom:12px"><strong>{app_name}</strong> is requesting access to:</p>
<ul>
{scopes_html}
</ul>

<form method="POST" action="/consent">
<input type="hidden" name="code" value="{code}">
<input type="hidden" name="decision" value="approve">
<div class="actions">
<button type="submit" class="btn-approve" name="decision" value="approve">Allow access</button>
<button type="submit" class="btn-deny" name="decision" value="deny">Deny</button>
</div>
</form>

<p class="footer">Powered by Lattice-ID</p>
</div>
</body>
</html>"#,
        code = crate::util::html_escape(code),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// Handle POST /consent — user approves or denies.
pub async fn handle_consent(body_bytes: &[u8]) -> Result<Response<String>, String> {
    let form = crate::util::parse_form(body_bytes);
    let code = crate::util::form_value(&form, "code").ok_or("missing code")?;
    let decision = crate::util::form_value(&form, "decision").unwrap_or("deny");

    let auth_code = crate::store::get_auth_code(code)
        .await?
        .ok_or("invalid or expired authorisation code")?;

    if crate::store::unix_now() > auth_code.expires_at {
        let _ = crate::store::delete_auth_code(code).await;
        return Err("authorisation code expired".into());
    }

    if decision != "approve" {
        let _ = crate::store::delete_auth_code(code).await;
        // Redirect back to the client with access_denied
        let sep = if auth_code.redirect_uri.contains('?') {
            '&'
        } else {
            '?'
        };
        let mut loc = format!(
            "{}{}error=access_denied&error_description=user+denied+consent",
            auth_code.redirect_uri, sep
        );
        if !auth_code.state.is_empty() {
            loc.push_str(&format!(
                "&state={}",
                crate::util::percent_encode(&auth_code.state)
            ));
        }
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header("location", &loc)
            .header("cache-control", "no-store")
            .body(String::new())
            .unwrap());
    }

    // Approved — redirect with the auth code
    let sep = if auth_code.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut redirect = format!(
        "{}{}code={}",
        auth_code.redirect_uri,
        sep,
        crate::util::percent_encode(code)
    );
    if !auth_code.state.is_empty() {
        redirect.push_str(&format!(
            "&state={}",
            crate::util::percent_encode(&auth_code.state)
        ));
    }

    let _ = crate::store::log_audit(
        "consent_approved",
        &auth_code.user_id,
        &auth_code.client_id,
        &auth_code.scope,
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &redirect)
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}
