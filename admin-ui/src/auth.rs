/// Lattice-ID OIDC PKCE flow for browser Wasm (Leptos version).

use leptos::prelude::*;
use gloo_storage::{LocalStorage, Storage};

const ISSUER_URL_KEY: &str = "lid_admin_issuer_url";
const CLIENT_ID_KEY: &str = "lid_admin_client_id";
const REDIRECT_URI_KEY: &str = "lid_admin_redirect_uri";
const OIDC_STATE_KEY: &str = "oidc_state";
const OIDC_VERIFIER_KEY: &str = "oidc_verifier";

// ── AuthContext ──────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct AuthContext {
    pub token: ReadSignal<String>,
    pub set_token: WriteSignal<String>,
    pub issuer_url: ReadSignal<String>,
    pub set_issuer_url: WriteSignal<String>,
    /// Becomes true once the OIDC callback has been fully processed (or there was none).
    pub auth_ready: ReadSignal<bool>,
    pub set_auth_ready: WriteSignal<bool>,
}

// ── Defaults ────────────────────────────────────────────────

pub fn default_issuer_url() -> String {
    // Try localStorage first
    if let Ok(v) = LocalStorage::get::<String>(ISSUER_URL_KEY) {
        if !v.is_empty() {
            return v;
        }
    }
    // Fall back to current origin or localhost
    let window = web_sys::window().unwrap();
    // Use current origin — the admin UI is served by the same gateway
    window.location().origin().unwrap_or_default()
}

pub fn default_client_id() -> String {
    LocalStorage::get::<String>(CLIENT_ID_KEY).unwrap_or_else(|_| "lid-admin".into())
}

pub fn default_redirect_uri() -> String {
    if let Ok(v) = LocalStorage::get::<String>(REDIRECT_URI_KEY) {
        if !v.is_empty() {
            // Discard any cached value that accidentally contains a port number,
            // so old broken values self-heal on next load.
            let has_port = v.split("//").nth(1).map(|rest| {
                rest.split('/').next().unwrap_or("").contains(':')
            }).unwrap_or(false);
            if !has_port {
                return v;
            }
        }
    }
    let window = web_sys::window().unwrap();
    let location = window.location();
    // Build the URI from protocol + hostname (no port) + pathname so it always
    // points at the gateway regardless of which dev port Trunk is running on.
    let protocol = location.protocol().unwrap_or_else(|_| "https:".into());
    let hostname = location.hostname().unwrap_or_default();
    let pathname = location.pathname().unwrap_or_else(|_| "/".into());
    format!("{protocol}//{hostname}{pathname}")
}

// ── Check for OIDC callback ────────────────────────────────

pub fn check_callback(ctx: AuthContext) {
    let window = web_sys::window().unwrap();
    let search = window.location().search().unwrap_or_default();
    if !search.contains("code=") {
        ctx.set_auth_ready.set(true);
        return;
    }

    let params = parse_query(&search);
    let code = match params.iter().find(|(k, _)| k == "code") {
        Some((_, v)) => v.clone(),
        None => return,
    };
    let returned_state = params.iter().find(|(k, _)| k == "state").map(|(_, v)| v.as_str());

    let stored_state = LocalStorage::get::<String>(OIDC_STATE_KEY).ok();
    if stored_state.as_deref() != returned_state {
        log::warn!("OIDC state mismatch");
        clear_url_params();
        return;
    }

    let code_verifier = match LocalStorage::get::<String>(OIDC_VERIFIER_KEY) {
        Ok(v) => v,
        Err(_) => {
            log::warn!("missing code_verifier");
            clear_url_params();
            return;
        }
    };

    LocalStorage::delete(OIDC_STATE_KEY);
    LocalStorage::delete(OIDC_VERIFIER_KEY);
    clear_url_params();

    let client_id = default_client_id();
    let redirect_uri = default_redirect_uri();

    wasm_bindgen_futures::spawn_local(async move {
        match exchange_code(&client_id, &redirect_uri, &code, &code_verifier).await {
            Ok(token) => ctx.set_token.set(token),
            Err(e) => log::error!("token exchange failed: {e}"),
        }
        ctx.set_auth_ready.set(true);
    });
}

// ── Login redirect ──────────────────────────────────────────

pub fn login_redirect(issuer_url: &str, client_id: &str, redirect_uri: &str) {
    let state_value = random_string(32);
    let code_verifier = random_string(64);
    let code_challenge = sha256_base64url(code_verifier.as_bytes());

    let _ = LocalStorage::set(OIDC_STATE_KEY, &state_value);
    let _ = LocalStorage::set(OIDC_VERIFIER_KEY, &code_verifier);
    let _ = LocalStorage::set(ISSUER_URL_KEY, issuer_url);
    let _ = LocalStorage::set(CLIENT_ID_KEY, client_id);
    let _ = LocalStorage::set(REDIRECT_URI_KEY, redirect_uri);

    let url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}&code_challenge={}&code_challenge_method=S256",
        issuer_url,
        client_id,
        url_encode(redirect_uri),
        state_value,
        code_challenge,
    );

    let window = web_sys::window().unwrap();
    let _ = window.location().set_href(&url);
}

// ── Token exchange ──────────────────────────────────────────

async fn exchange_code(
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<String, String> {
    let body = format!(
        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
        code,
        client_id,
        url_encode(redirect_uri),
        verifier,
    );

    let resp = gloo_net::http::Request::post("/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.ok() {
        let msg = resp.text().await.unwrap_or_else(|_| "exchange failed".into());
        return Err(msg);
    }

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let tr: TokenResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(tr.access_token)
}

// ── Helpers ─────────────────────────────────────────────────

fn clear_url_params() {
    let window = web_sys::window().unwrap();
    let _ = window.history().unwrap().replace_state_with_url(
        &wasm_bindgen::JsValue::NULL,
        "",
        Some(&window.location().pathname().unwrap_or_default()),
    );
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .trim_start_matches('?')
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect()
}

fn random_string(len: usize) -> String {
    let crypto = web_sys::window().unwrap().crypto().unwrap();
    let mut buf = vec![0u8; len];
    crypto.get_random_values_with_u8_array(&mut buf).unwrap();
    buf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        [..len]
        .to_string()
}

fn sha256_base64url(input: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let hash = Sha256::digest(input);
    URL_SAFE_NO_PAD.encode(hash)
}

fn url_encode(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}
