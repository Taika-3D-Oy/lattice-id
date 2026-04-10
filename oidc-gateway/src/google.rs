use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint_dig::BigUint;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use wstd::http::{Body, Response, StatusCode};

use crate::store;
use crate::util;

const DEFAULT_GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

fn google_auth_url() -> &'static str {
    option_env!("LATTICE_ID_GOOGLE_AUTH_URL").unwrap_or(DEFAULT_GOOGLE_AUTH_URL)
}

fn google_token_url() -> &'static str {
    option_env!("LATTICE_ID_GOOGLE_TOKEN_URL").unwrap_or(DEFAULT_GOOGLE_TOKEN_URL)
}

fn google_jwks_url() -> &'static str {
    option_env!("LATTICE_ID_GOOGLE_JWKS_URL").unwrap_or(DEFAULT_GOOGLE_JWKS_URL)
}

/// Handle GET /auth/google?session_id=... — redirect to Google's OAuth2 consent screen.
pub fn start(query: &str, issuer: &str) -> Result<Response<Body>, String> {
    let params = util::parse_query(query);
    let session_id = params
        .iter()
        .find(|(k, _)| k == "session_id")
        .map(|(_, v)| v.as_str())
        .ok_or("missing session_id")?;

    // Validate the auth session still exists
    let session = store::get_auth_session(session_id)?.ok_or("invalid or expired session")?;

    // Check auth session expiry
    if store::unix_now() > session.created_at + 600 {
        return Err("auth session expired".into());
    }

    let idp =
        store::get_identity_provider_by_type("google")?.ok_or("Google login is not configured")?;

    // Build state = session_id (we'll verify on callback)
    let state = session_id;

    let callback_url = format!("{issuer}/auth/google/callback");
    let mut google_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={state}&access_type=online&prompt=select_account",
        google_auth_url(),
        util::percent_encode(&idp.client_id),
        util::percent_encode(&callback_url),
    );

    // Propagate nonce if present in the session
    if !session.nonce.is_empty() {
        google_url.push_str("&nonce=");
        google_url.push_str(&util::percent_encode(&session.nonce));
    }

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header("location", &google_url)
        .header("cache-control", "no-store")
        .body(Body::empty())
        .unwrap())
}

/// Handle GET /auth/google/callback?code=...&state=... — exchange code for id_token.
pub async fn callback(query: &str, issuer: &str, remote_ip: &str) -> Result<Response<Body>, String> {
    let params = util::parse_query(query);
    let get = |key: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    let code = get("code").ok_or("missing code from Google")?;
    let state = get("state").ok_or("missing state")?;
    let session_id = state; // state = session_id

    // Validate auth session
    let session = store::get_auth_session(session_id)?.ok_or("invalid or expired session")?;

    // Check auth session expiry
    if store::unix_now() > session.created_at + 600 {
        return Ok(crate::login::login_page(
            session_id,
            Some("Auth session expired. Please start over."),
        ));
    }

    // Check for error from Google
    if let Some(error) = get("error") {
        return Ok(crate::login::login_page(
            session_id,
            Some(&format!("Google login failed: {error}")),
        ));
    }

    let idp =
        store::get_identity_provider_by_type("google")?.ok_or("Google login is not configured")?;

    let callback_url = format!("{issuer}/auth/google/callback");

    // Exchange authorization code for tokens
    let token_body = format!(
        "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
        util::percent_encode(code),
        util::percent_encode(&idp.client_id),
        util::percent_encode(&idp.client_secret),
        util::percent_encode(&callback_url),
    );

    let token_response = http_post(google_token_url(), &token_body).await?;

    let id_token_str = token_response
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or("missing id_token from Google")?;

    let google_claims = verify_google_id_token(id_token_str, &idp.client_id, &session.nonce).await?;

    let google_sub = google_claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or("missing sub in Google id_token")?;
    let google_email = google_claims
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or("missing email in Google id_token")?;
    let google_name = google_claims
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(google_email);
    let email_verified = google_claims
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !email_verified {
        return Ok(crate::login::login_page(
            session_id,
            Some("Google account email is not verified"),
        ));
    }

    // Look up existing social identity link
    let user = if let Some(si) = store::get_social_identity("google", google_sub)? {
        // Known Google identity → get linked user
        store::get_user(&si.user_id)?.ok_or("linked user not found")?
    } else if let Some(existing_user) = store::get_user_by_email(google_email)? {
        // Email matches an existing user → auto-link
        let si = store::SocialIdentity {
            provider: "google".to_string(),
            provider_sub: google_sub.to_string(),
            user_id: existing_user.id.clone(),
            email: google_email.to_string(),
            linked_at: store::unix_now(),
        };
        store::save_social_identity(&si)?;
        let _ = store::log_audit(
            "social_identity_linked",
            &existing_user.id,
            &existing_user.id,
            "google (auto-linked by email)",
        );
        existing_user
    } else {
        // New user — gate registration
        if !crate::is_registration_allowed() {
            return Ok(crate::login::login_page(
                session_id,
                Some("Registration is currently closed"),
            ));
        }

        // Auto-create from Google profile.
        // Google already verified the email, so user starts as "active"
        // regardless of the require_email_verification setting.
        let password_hash = format!("social:google:{google_sub}"); // not a real hash — user can't password-login
        let mut user = store::User {
            id: store::random_hex(16),
            email: google_email.to_string(),
            name: google_name.to_string(),
            password_hash,
            status: "active".to_string(),
            created_at: store::unix_now(),
            superadmin: false,
            totp_secret: None,
            totp_enabled: false,
            recovery_codes: Vec::new(),
        };
        store::create_user(&user)?;

        // Link the social identity
        let si = store::SocialIdentity {
            provider: "google".to_string(),
            provider_sub: google_sub.to_string(),
            user_id: user.id.clone(),
            email: google_email.to_string(),
            linked_at: store::unix_now(),
        };
        store::save_social_identity(&si)?;

        let _ = store::log_audit("user_registered_social", &user.id, &user.id, "google");

        // Bootstrap hook: config-supplied Rhai script for zero-credential setup
        let boot = crate::hooks::execute_bootstrap_hook(&user);
        if let Some(reason) = &boot.deny_reason {
            let _ = store::log_audit(
                "registration_denied_by_bootstrap_hook",
                &user.id,
                &user.id,
                &reason,
            );
            return Ok(crate::login::login_page(session_id, Some(&reason)));
        }
        if let Err(e) = crate::hooks::apply_outcome(&mut user, &boot) {
            crate::logger::error_message("bootstrap_hook.apply_failed", e);
        }

        // Execute post-registration hooks for social signups
        let outcome = crate::hooks::execute_hooks("post-registration", &user);
        if let Some(reason) = &outcome.deny_reason {
            let _ = store::log_audit(
                "registration_denied_by_hook",
                &user.id,
                &user.id,
                &reason,
            );
            return Ok(crate::login::login_page(session_id, Some(&reason)));
        }
        if let Err(e) = crate::hooks::apply_outcome(&mut user, &outcome) {
            crate::logger::error_message("hooks.apply_failed", e);
        }

        user
    };

    if user.status != "active" {
        return Ok(crate::login::login_page(
            session_id,
            Some("Account is not active"),
        ));
    }

    // MFA check: if TOTP is enabled, require MFA even for social login
    if user.totp_enabled {
        let mfa_token = store::random_hex(32);
        let pending = store::MfaPending {
            user_id: user.id.clone(),
            session_id: session_id.to_string(),
            primary_amr: Vec::new(),
            expires_at: store::unix_now() + 300,
            remote_ip: remote_ip.to_string(),
        };
        store::save_mfa_pending(&mfa_token, &pending)?;
        return Ok(crate::login::mfa_page(&mfa_token, session_id, None));
    }

    // Complete login (issue auth code, redirect to client)
    let _ = store::log_audit("login_success", &user.id, &user.id, "google");
    crate::login::complete_login(&user, session_id, "google", remote_ip).await
}

/// Make an HTTP POST request with form-urlencoded body.
async fn http_post(url: &str, body: &str) -> Result<serde_json::Value, String> {
    let request = wstd::http::Request::builder()
        .method(wstd::http::Method::POST)
        .uri(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(Body::from(body.to_string()))
        .map_err(|e| format!("build request: {e}"))?;

    let response = wstd::http::Client::new()
        .send(request)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = response.status();
    let mut resp_body = response.into_body();
    let bytes = resp_body
        .contents()
        .await
        .map_err(|e| format!("read body: {e}"))?;

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(bytes);
        crate::logger::warn(
            "google.token_exchange_failed",
            serde_json::json!({
                "status": status.as_u16(),
                "response": body_str.to_string(),
            }),
        );
        return Err("token exchange with Google failed".into());
    }

    serde_json::from_slice(bytes).map_err(|e| format!("parse response: {e}"))
}

async fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let request = wstd::http::Request::builder()
        .method(wstd::http::Method::GET)
        .uri(url)
        .header("accept", "application/json")
        .body(Body::empty())
        .map_err(|e| format!("build request: {e}"))?;

    let response = wstd::http::Client::new()
        .send(request)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = response.status();
    let mut resp_body = response.into_body();
    let bytes = resp_body
        .contents()
        .await
        .map_err(|e| format!("read body: {e}"))?;

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(bytes);
        crate::logger::warn(
            "google.jwks_fetch_failed",
            serde_json::json!({
                "status": status.as_u16(),
                "response": body_str.to_string(),
            }),
        );
        return Err("failed to fetch Google signing keys".into());
    }

    serde_json::from_slice(bytes).map_err(|e| format!("parse response: {e}"))
}

async fn verify_google_id_token(
    token: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }

    let header = decode_jwt_segment(parts[0], "header")?;
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or("missing kid in Google id_token header")?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(format!("unsupported Google token algorithm: {alg}"));
    }

    let jwks = http_get_json(google_jwks_url()).await?;
    verify_google_signature(token, kid, &jwks)?;

    let claims = decode_jwt_segment(parts[1], "payload")?;
    validate_google_claims(&claims, expected_audience, expected_nonce)?;
    Ok(claims)
}

fn verify_google_signature(token: &str, kid: &str, jwks: &serde_json::Value) -> Result<(), String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("signature decode: {e}"))?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|e| format!("bad signature: {e}"))?;

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or("invalid Google JWKS response")?;

    let jwk = keys
        .iter()
        .find(|key| {
            key.get("kid").and_then(|v| v.as_str()) == Some(kid)
                && key.get("kty").and_then(|v| v.as_str()) == Some("RSA")
        })
        .ok_or("no matching Google signing key found")?;

    let modulus = decode_biguint(
        jwk.get("n")
            .and_then(|v| v.as_str())
            .ok_or("missing modulus in Google JWK")?,
    )?;
    let exponent = decode_biguint(
        jwk.get("e")
            .and_then(|v| v.as_str())
            .ok_or("missing exponent in Google JWK")?,
    )?;

    let public_key = RsaPublicKey::new(modulus, exponent)
        .map_err(|e| format!("invalid Google public key: {e}"))?;
    let verifier = VerifyingKey::<Sha256>::new(public_key);
    verifier
        .verify(message.as_bytes(), &sig)
        .map_err(|e| format!("Google signature verification failed: {e}"))
}

fn validate_google_claims(
    claims: &serde_json::Value,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<(), String> {
    let issuer = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    if issuer != "accounts.google.com" && issuer != "https://accounts.google.com" {
        return Err("invalid Google token issuer".into());
    }

    let audience_ok = match claims.get("aud") {
        Some(serde_json::Value::String(aud)) => aud == expected_audience,
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some(expected_audience)),
        _ => false,
    };
    if !audience_ok {
        return Err("invalid Google token audience".into());
    }

    let now = unix_now();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or("missing exp in Google id_token")?;
    if now > exp {
        return Err("Google id_token expired".into());
    }

    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64())
        && now < nbf
    {
        return Err("Google id_token is not yet valid".into());
    }

    if !expected_nonce.is_empty() {
        let nonce = claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or("missing nonce in Google id_token")?;
        if nonce != expected_nonce {
            return Err("invalid Google token nonce".into());
        }
    }

    Ok(())
}

fn decode_jwt_segment(token_part: &str, label: &str) -> Result<serde_json::Value, String> {
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token_part)
        .map_err(|e| format!("decode {label}: {e}"))?;
    serde_json::from_slice(&payload_bytes).map_err(|e| format!("parse {label}: {e}"))
}

fn decode_biguint(value: &str) -> Result<BigUint, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("base64 decode JWK integer: {e}"))?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::validate_google_claims;

    #[test]
    fn accepts_valid_google_claims() {
        let now = super::unix_now();
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "google-client-id",
            "exp": now + 300,
            "nonce": "expected-nonce",
        });

        assert!(validate_google_claims(&claims, "google-client-id", "expected-nonce").is_ok());
    }

    #[test]
    fn rejects_wrong_google_audience() {
        let now = super::unix_now();
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "someone-else",
            "exp": now + 300,
            "nonce": "expected-nonce",
        });

        assert_eq!(
            validate_google_claims(&claims, "google-client-id", "expected-nonce")
                .unwrap_err(),
            "invalid Google token audience"
        );
    }

    #[test]
    fn rejects_wrong_google_issuer() {
        let now = super::unix_now();
        let claims = serde_json::json!({
            "iss": "https://evil.example.com",
            "aud": "google-client-id",
            "exp": now + 300,
            "nonce": "expected-nonce",
        });

        assert_eq!(
            validate_google_claims(&claims, "google-client-id", "expected-nonce")
                .unwrap_err(),
            "invalid Google token issuer"
        );
    }

    #[test]
    fn rejects_expired_google_token() {
        let now = super::unix_now();
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "google-client-id",
            "exp": now.saturating_sub(1),
            "nonce": "expected-nonce",
        });

        assert_eq!(
            validate_google_claims(&claims, "google-client-id", "expected-nonce")
                .unwrap_err(),
            "Google id_token expired"
        );
    }

    #[test]
    fn rejects_google_nonce_mismatch() {
        let now = super::unix_now();
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": "google-client-id",
            "exp": now + 300,
            "nonce": "wrong-nonce",
        });

        assert_eq!(
            validate_google_claims(&claims, "google-client-id", "expected-nonce")
                .unwrap_err(),
            "invalid Google token nonce"
        );
    }
}
