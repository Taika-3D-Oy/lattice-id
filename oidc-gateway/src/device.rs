//! RFC 8628 — OAuth 2.0 Device Authorization Grant.
//!
//! # Flow
//!
//! 1. Device: POST /device_authorization → (device_code, user_code, verification_uri)
//! 2. User: GET /device → simple HTML form; enters user_code
//! 3. User: authenticates normally via the existing login page
//!    (the auth session carries a device_code reference)
//! 4. Device: polls POST /token with grant_type=urn:…:device_code until approved
//!
//! Device codes expire after 5 minutes.
//! Polling interval is enforced at 5 seconds via rate limiting in token.rs.

use crate::{store, util};
use http::{Response, StatusCode};

/// POST /device_authorization — RFC 8628 §3.1.
pub async fn start(body_bytes: &[u8], issuer: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());

    let client_id = get("client_id").ok_or("missing client_id")?;
    let scope = get("scope").unwrap_or("openid email").to_string();

    // Verify client exists
    let client = store::get_client(client_id)
        .await?
        .ok_or_else(|| format!("unknown client_id: {client_id}"))?;

    if !client
        .grant_types
        .contains(&"urn:ietf:params:oauth:grant-type:device_code".to_string())
    {
        return Err(format!(
            "client '{}' is not authorized to use the device authorization grant",
            client_id
        ));
    }

    let device_code = store::random_hex(32);
    // Display form has a hyphen for human readability ("XXXX-XXXX") but the
    // canonical lookup key is the hyphen-stripped uppercase form so users can
    // type it either way (with/without separator).
    let user_code_display = generate_user_code();
    let user_code = user_code_display.replace('-', "");
    let expires_in: u64 = 300; // 5 minutes
    let interval: u64 = 5;

    let dc = store::DeviceCode {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: client_id.to_string(),
        scope: scope.clone(),
        expires_at: store::unix_now() + expires_in,
        status: "pending".to_string(),
        user_id: None,
    };
    store::save_device_code(&dc).await?;

    let verification_uri = format!("{issuer}/device");
    let verification_uri_complete = format!(
        "{issuer}/device?user_code={}",
        util::percent_encode(&user_code_display)
    );

    let response = serde_json::json!({
        "device_code": device_code,
        "user_code": user_code_display,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": expires_in,
        "interval": interval,
    });

    let _ = crate::service_client::increment_metric(
        "lattice_id_device_auth_total",
        &[("client_id", client_id)],
    )
    .await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&response).unwrap_or_default())
        .unwrap())
}

/// GET /device[?user_code=...] — HTML page where the user enters their user code.
pub async fn page(query: &str) -> Response<String> {
    let params = util::parse_query(query);
    let prefilled_code = params
        .iter()
        .find(|(k, _)| k == "user_code")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device Activation</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background:#111827; color:#f9fafb; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }}
  .card {{ background:#1f2937; border-radius:12px; padding:40px; max-width:400px; width:100%; box-shadow:0 4px 32px rgba(0,0,0,.5); }}
  h1 {{ font-size:1.5rem; margin-bottom:8px; }}
  p {{ color:#9ca3af; margin-bottom:24px; font-size:.95rem; }}
  input {{ width:100%; box-sizing:border-box; padding:12px; border:1px solid #374151; border-radius:8px; background:#111827; color:#f9fafb; font-size:1.4rem; letter-spacing:.3em; text-align:center; text-transform:uppercase; }}
  button {{ width:100%; margin-top:16px; padding:12px; border:none; border-radius:8px; background:#3b82f6; color:#fff; font-size:1rem; cursor:pointer; }}
  button:hover {{ background:#2563eb; }}
  .error {{ color:#f87171; margin-top:12px; font-size:.9rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>Device Activation</h1>
  <p>Enter the code displayed on your device to sign in.</p>
  <form method="POST" action="/device">
    <input type="text" name="user_code" value="{prefilled_code}" placeholder="XXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="9" required>
    <button type="submit">Continue</button>
  </form>
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// POST /device — user submits user_code.
/// Validates the code and redirects to the normal OIDC login flow,
/// carrying the device_code in the auth session.
pub async fn submit(body_bytes: &[u8], issuer: &str) -> Result<Response<String>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let user_code = get("user_code")
        .ok_or("missing user_code")?
        .trim()
        .to_uppercase()
        .replace(['-', ' '], "");

    let dc = store::get_device_code_by_user_code(&user_code)
        .await?
        .ok_or_else(|| "invalid or expired user code".to_string())?;

    if store::unix_now() > dc.expires_at {
        return Ok(page_with_error(
            "Code has expired. Please restart on your device.",
        ));
    }
    if dc.status != "pending" {
        return Ok(page_with_error("This code has already been used."));
    }

    // Create a normal OIDC auth session that also carries the device_code.
    // After login completes, the device code status is updated to "approved".
    let session_id = store::random_hex(32);
    let session = store::AuthSession {
        client_id: dc.client_id.clone(),
        redirect_uri: format!("{issuer}/device/complete"),
        code_challenge: String::new(),
        code_challenge_method: "device".to_string(), // sentinel: device flow
        state: dc.device_code.clone(),               // carry device_code in state
        scope: dc.scope.clone(),
        nonce: String::new(),
        max_age: None,
        acr_values: Vec::new(),
        requested_id_token_claims: Vec::new(),
        requested_userinfo_claims: Vec::new(),
        hinted_user_id: None,
        hinted_email: None,
        created_at: store::unix_now(),
        needs_consent: false,
    };
    store::save_auth_session(&session_id, &session).await?;

    // Redirect to the login page
    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", format!("/login?session_id={session_id}"))
        .header("cache-control", "no-store")
        .body(String::new())
        .unwrap())
}

/// GET /device/complete — shown after the user has authenticated for a device flow.
/// Approval and user_id capture happen in `login::complete_login_with_amr` when it
/// detects the device sentinel; this page is purely visual confirmation.
pub async fn complete(_query: &str) -> Response<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Device Activated</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background:#111827; color:#f9fafb; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }
  .card { background:#1f2937; border-radius:12px; padding:40px; max-width:400px; width:100%; text-align:center; }
  .check { font-size:4rem; margin-bottom:16px; }
  h1 { font-size:1.5rem; }
  p { color:#9ca3af; }
</style>
</head>
<body>
<div class="card">
  <div class="check">✓</div>
  <h1>Device Activated!</h1>
  <p>You can close this window. Your device is now signed in.</p>
</div>
</body>
</html>"#;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html.to_string())
        .unwrap()
}

fn page_with_error(error: &str) -> Response<String> {
    let escaped = html_escape(error);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Device Activation</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background:#111827; color:#f9fafb; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }}
  .card {{ background:#1f2937; border-radius:12px; padding:40px; max-width:400px; width:100%; }}
  h1 {{ font-size:1.5rem; margin-bottom:8px; }}
  p {{ color:#9ca3af; margin-bottom:24px; }}
  input {{ width:100%; box-sizing:border-box; padding:12px; border:1px solid #374151; border-radius:8px; background:#111827; color:#f9fafb; font-size:1.4rem; letter-spacing:.3em; text-align:center; text-transform:uppercase; }}
  button {{ width:100%; margin-top:16px; padding:12px; border:none; border-radius:8px; background:#3b82f6; color:#fff; font-size:1rem; cursor:pointer; }}
  .error {{ color:#f87171; margin-top:12px; font-size:.9rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>Device Activation</h1>
  <p>Enter the code displayed on your device to sign in.</p>
  <form method="POST" action="/device">
    <input type="text" name="user_code" placeholder="XXXX-XXXX" autocomplete="off" spellcheck="false" maxlength="9" required>
    <button type="submit">Continue</button>
  </form>
  <div class="error">{escaped}</div>
</div>
</body>
</html>"#
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(html)
        .unwrap()
}

/// Generate an 8-character user-facing code in XXXX-XXXX format.
/// Uses only unambiguous characters (no 0/O, 1/I/L).
fn generate_user_code() -> String {
    const CHARS: &[u8] = b"ACDEFGHJKMNPQRTVWXY2345679";
    let mut code = [0u8; 8];
    getrandom::getrandom(&mut code).expect("random");
    let chars: Vec<char> = code
        .iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect();
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
