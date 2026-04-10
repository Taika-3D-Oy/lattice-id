use wstd::http::{Body, Response, StatusCode};

use crate::{jwt, store, util};

/// RFC 6749 §5.2 compliant error response for the token endpoint.
fn token_error(status: StatusCode, error: &str, description: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&body).unwrap_or_default().into())
        .unwrap()
}

/// Map an internal error string to a RFC 6749 §5.2 error response.
fn map_token_error(e: &str) -> Response<Body> {
    if e.contains("client_id") || e.contains("client_secret") || e.contains("client authentication") {
        token_error(StatusCode::UNAUTHORIZED, "invalid_client", e)
    } else if e.contains("grant_type") || e.contains("not authorized to use") {
        token_error(StatusCode::BAD_REQUEST, "unauthorized_client", e)
    } else if e.contains("code") || e.contains("expired") || e.contains("PKCE") || e.contains("redirect_uri") || e.contains("refresh token") || e.contains("user not found") || e.contains("mismatch") || e.contains("consumed") || e.contains("revoked") || e.contains("replay") {
        token_error(StatusCode::BAD_REQUEST, "invalid_grant", e)
    } else if e.contains("rate") || e.contains("too many") {
        token_error(StatusCode::TOO_MANY_REQUESTS, "invalid_request", e)
    } else {
        token_error(StatusCode::BAD_REQUEST, "invalid_request", e)
    }
}

/// Parse client credentials from HTTP Basic Authorization header (RFC 6749 §2.3.1).
fn parse_basic_auth(auth_header: Option<&str>) -> Option<(String, String)> {
    let header = auth_header?;
    let encoded = header.strip_prefix("Basic ").or_else(|| header.strip_prefix("basic "))?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = text.split_once(':')?;
    Some((
        util::url_decode(client_id),
        util::url_decode(client_secret),
    ))
}

/// Handle POST /token — authorization_code and refresh_token grants.
pub async fn handle(body_bytes: &[u8], issuer: &str, auth_header: Option<&str>) -> Result<Response<Body>, String> {
    let mut form = util::parse_form(body_bytes);

    // Support client_secret_basic: override form credentials with Basic auth if present
    if let Some((basic_id, basic_secret)) = parse_basic_auth(auth_header) {
        // Per RFC 6749 §2.3: client MUST NOT use more than one authentication method
        let form_has_secret = form.iter().any(|(k, _)| k == "client_secret");
        if !form_has_secret {
            // Remove any form client_id and replace with Basic credentials
            form.retain(|(k, _)| k != "client_id");
            form.push(("client_id".to_string(), basic_id));
            form.push(("client_secret".to_string(), basic_secret));
        }
    }

    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let grant_type = get("grant_type").ok_or("missing grant_type")?;

    // Rate limit token endpoint per client_id: 100 requests per 60s
    let rate_key = match get("client_id") {
        Some(cid) => format!("token:{}", cid),
        None => match get("refresh_token") {
            Some(rt) => format!("token_rt:{}", &rt[..rt.len().min(16)]),
            None => format!("token_grant:{}", grant_type),
        },
    };
    match crate::service_client::check_rate(&rate_key, 100, 60).await {
        Ok((false, _)) => return Err("too many token requests. please try again later.".into()),
        Err(e) => crate::logger::error_message("rate_limit.token_check_failed", e),
        _ => {}
    }

    let result = match grant_type {
        "authorization_code" => handle_code_exchange(&form, issuer).await,
        "refresh_token" => handle_refresh(&form, issuer).await,
        _ => return Ok(token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", &format!("unsupported grant_type: {grant_type}"))),
    };

    match result {
        Ok(resp) => Ok(resp),
        Err(e) => Ok(map_token_error(&e)),
    }
}

async fn handle_code_exchange(
    form: &[(String, String)],
    issuer: &str,
) -> Result<Response<Body>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let code = get("code").ok_or("missing code")?;
    let code_verifier = get("code_verifier").ok_or("missing code_verifier")?;
    let redirect_uri = get("redirect_uri").ok_or("missing redirect_uri")?;
    let client_id = get("client_id").ok_or("missing client_id")?;
    let client_secret = get("client_secret");

    // Load signing keys from KV (persisted by core-service)
    // Verify client
    let client = verify_client(client_id, client_secret)?;
    if !client.grant_types.contains(&"authorization_code".to_string()) {
        return Err(format!(
            "client '{}' is not authorized to use grant_type 'authorization_code'",
            client_id
        ));
    }

    // CAS: get auth code with revision for atomic consumption
    let (auth_code, revision) = store::get_auth_code_cas(code)?
        .ok_or("invalid or expired code")?;

    if auth_code.client_id != client_id {
        return Err("client_id mismatch".into());
    }
    if auth_code.redirect_uri != redirect_uri {
        return Err("redirect_uri mismatch".into());
    }
    if store::unix_now() > auth_code.expires_at {
        return Err("authorization code expired".into());
    }
    if !verify_pkce(
        code_verifier,
        &auth_code.code_challenge,
        &auth_code.code_challenge_method,
    ) {
        return Err("PKCE verification failed".into());
    }

    // CAS: atomically consume the auth code (prevents double-spend)
    store::consume_auth_code(code, revision)
        .map_err(|_| "authorization code already consumed".to_string())?;

    let user = store::get_user(&auth_code.user_id)?
        .ok_or("user not found")?;

    let nonce = if auth_code.nonce.is_empty() {
        None
    } else {
        Some(auth_code.nonce.as_str())
    };
    let auth_time = if auth_code.auth_time == 0 {
        store::unix_now()
    } else {
        auth_code.auth_time
    };
    let (access_claims, id_claims) = build_claims(
        issuer,
        &user,
        client_id,
        nonce,
        auth_time,
        &auth_code.amr,
        auth_code.acr.as_deref(),
        &auth_code.scope,
        &auth_code.requested_id_token_claims,
        &auth_code.requested_userinfo_claims,
        &auth_code.extra_claims,
    );

    // Sign tokens via key-manager component
    let access_token = jwt::sign(&access_claims)?;
    let id_token = jwt::sign(&id_claims)?;

    // Create refresh token
    let refresh_raw = store::random_hex(32);
    let refresh_hash = hex_sha256(&refresh_raw);
    let refresh_entry = store::RefreshEntry {
        user_id: user.id,
        client_id: client_id.to_string(),
        expires_at: store::unix_now() + 86400 * 30,
        scope: auth_code.scope.clone(),
        version: store::unix_now(),
        auth_time,
        amr: auth_code.amr.clone(),
        acr: auth_code.acr.clone(),
        requested_id_token_claims: auth_code.requested_id_token_claims.clone(),
        requested_userinfo_claims: auth_code.requested_userinfo_claims.clone(),
    };
    store::save_refresh_token(&refresh_hash, &refresh_entry)?;

    // Clean up consumed auth code
    let _ = store::delete_auth_code(code);

    // Record metrics
    for token_type in ["access", "id_token", "refresh_token"] {
        let _ = crate::service_client::increment_metric(
            "lattice_id_token_issued_total",
            &[("grant_type", "authorization_code"), ("token_type", token_type)],
        )
        .await;
    }

    // Only issue refresh token when offline_access scope is present or client is confidential
    let has_offline_access = auth_code.scope.split(' ').any(|s| s == "offline_access")
        || client.client_secret.is_some();

    let mut response = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": auth_code.scope,
    });
    if has_offline_access {
        response["refresh_token"] = serde_json::json!(refresh_raw);
    } else {
        // Clean up the refresh token we just stored — it won't be used
        let _ = store::delete_refresh_token(&refresh_hash);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&response).unwrap_or_default().into())
        .unwrap())
}

async fn handle_refresh(form: &[(String, String)], issuer: &str) -> Result<Response<Body>, String> {
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let refresh_token = get("refresh_token").ok_or("missing refresh_token")?;
    let client_id = get("client_id").ok_or("missing client_id")?;
    let client_secret = get("client_secret");

    let client = verify_client(client_id, client_secret)?;
    if !client.grant_types.contains(&"refresh_token".to_string()) {
        return Err(format!(
            "client '{}' is not authorized to use grant_type 'refresh_token'",
            client_id
        ));
    }

    let refresh_hash = hex_sha256(refresh_token);

    // CAS: get refresh token with revision for atomic consumption
    let (entry, revision) = match store::get_refresh_token_cas(&refresh_hash)? {
        Some(pair) => pair,
        None => {
            // Replay detection: check if token was previously consumed
            if let Ok(Some(user_id)) = store::get_consumed_refresh(&refresh_hash) {
                let _ = store::revoke_user_sessions(&user_id);
                let _ = store::delete_user_refresh_tokens(&user_id);
                let _ = crate::service_client::increment_metric(
                    "lattice_id_refresh_usage_total",
                    &[("result", "replay_detected")],
                )
                .await;
                return Err(
                    "refresh token replay detected — all sessions revoked".into(),
                );
            }
            let _ = crate::service_client::increment_metric(
                "lattice_id_refresh_usage_total",
                &[("result", "invalid")],
            )
            .await;
            return Err("invalid refresh token".into());
        }
    };

    if entry.client_id != client_id {
        return Err("client_id mismatch".into());
    }
    if store::unix_now() > entry.expires_at {
        let _ = store::delete_refresh_token(&refresh_hash);
        let _ = crate::service_client::increment_metric(
            "lattice_id_refresh_usage_total",
            &[("result", "expired")],
        )
        .await;
        return Err("refresh token expired".into());
    }

    // CAS: atomically consume the old refresh token
    store::consume_refresh_token(&refresh_hash, revision)
        .map_err(|_| "refresh token already consumed".to_string())?;

    let user = store::get_user(&entry.user_id)?
        .ok_or("user not found")?;

    let auth_time = if entry.auth_time == 0 {
        store::unix_now()
    } else {
        entry.auth_time
    };
    let (access_claims, id_claims) = build_claims(
        issuer,
        &user,
        client_id,
        None,
        auth_time,
        &entry.amr,
        entry.acr.as_deref(),
        &entry.scope,
        &entry.requested_id_token_claims,
        &entry.requested_userinfo_claims,
        &[],
    );

    let access_token = jwt::sign(&access_claims)?;
    let id_token = jwt::sign(&id_claims)?;

    // Issue new refresh token
    let new_refresh_raw = store::random_hex(32);
    let new_refresh_hash = hex_sha256(&new_refresh_raw);
    let new_entry = store::RefreshEntry {
        user_id: entry.user_id.clone(),
        client_id: client_id.to_string(),
        expires_at: store::unix_now() + 86400 * 30,
        scope: entry.scope.clone(),
        version: entry.version,
        auth_time,
        amr: entry.amr.clone(),
        acr: entry.acr.clone(),
        requested_id_token_claims: entry.requested_id_token_claims.clone(),
        requested_userinfo_claims: entry.requested_userinfo_claims.clone(),
    };
    store::save_refresh_token(&new_refresh_hash, &new_entry)?;

    // Mark old token as consumed for replay detection, then delete
    store::mark_refresh_consumed(&refresh_hash, &entry.user_id)?;
    let _ = store::delete_refresh_token(&refresh_hash);

    let _ = crate::service_client::increment_metric(
        "lattice_id_refresh_usage_total",
        &[("result", "success")],
    )
    .await;
    for token_type in ["access", "id_token", "refresh_token"] {
        let _ = crate::service_client::increment_metric(
            "lattice_id_token_issued_total",
            &[("grant_type", "refresh_token"), ("token_type", token_type)],
        )
        .await;
    }

    let response = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "refresh_token": new_refresh_raw,
        "scope": entry.scope,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&response).unwrap_or_default().into())
        .unwrap())
}

/// Handle POST /token/revoke — RFC 7009 token revocation.
pub async fn handle_revoke(body_bytes: &[u8]) -> Result<Response<Body>, String> {
    let form = util::parse_form(body_bytes);
    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let token = get("token").ok_or("missing token")?;
    let token_type_hint = get("token_type_hint");

    // Try to revoke as refresh token first (most common case)
    let revoked_refresh = if token_type_hint != Some("access_token") {
        let hash = hex_sha256(token);
        if store::get_refresh_token(&hash)?.is_some() {
            store::delete_refresh_token(&hash)?;
            true
        } else {
            false
        }
    } else {
        false
    };

    // Per RFC 7009, always return 200 OK regardless of whether the token was found
    // (to prevent token existence probing)
    if revoked_refresh {
        let _ = store::log_audit("token_revoked", "", "", "refresh_token");
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .body(Body::empty())
        .unwrap())
}

/// Handle POST /token/introspect — RFC 7662 token introspection.
pub async fn handle_introspect(body_bytes: &[u8], issuer: &str, auth_header: Option<&str>) -> Result<Response<Body>, String> {
    let mut form = util::parse_form(body_bytes);

    // Support client_secret_basic for introspection
    if let Some((basic_id, basic_secret)) = parse_basic_auth(auth_header) {
        let form_has_secret = form.iter().any(|(k, _)| k == "client_secret");
        if !form_has_secret {
            form.retain(|(k, _)| k != "client_id");
            form.push(("client_id".to_string(), basic_id));
            form.push(("client_secret".to_string(), basic_secret));
        }
    }

    let get = |key: &str| -> Option<&str> {
        form.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    };

    let token = get("token").ok_or("missing token")?;
    let client_id = get("client_id").ok_or("missing client_id")?;
    let client_secret = get("client_secret").ok_or("missing client_secret")?;

    let client = match authenticate_confidential_client(client_id, client_secret) {
        Ok(client) => client,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .header("cache-control", "no-store")
                .header("www-authenticate", "Bearer realm=\"token-introspection\"")
                .body(r#"{"error":"invalid_client"}"#.into())
                .unwrap());
        }
    };

    match crate::service_client::check_rate(&format!("introspect:{}", client.client_id), 100, 60).await {
        Ok((false, _)) => {
            return Ok(json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({ "error": "rate_limit_exceeded" }),
            ));
        }
        Err(e) => crate::logger::error_message("rate_limit.introspection_check_failed", e),
        _ => {}
    }

    let response = match crate::service_client::verify_token_scoped(token, Some(issuer), None, None).await {
        Ok(claims) => build_introspection_response(&claims),
        Err(_) => serde_json::json!({ "active": false }),
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&response).unwrap_or_default().into())
        .unwrap())
}

fn authenticate_confidential_client(
    client_id: &str,
    client_secret: &str,
) -> Result<store::OidcClient, String> {
    use subtle::ConstantTimeEq;

    let client = store::get_client(client_id)?.ok_or("invalid client authentication")?;
    let expected_secret = client
        .client_secret
        .as_deref()
        .ok_or("invalid client authentication")?;

    let matches: bool = expected_secret
        .as_bytes()
        .ct_eq(client_secret.as_bytes())
        .into();
    if !matches {
        return Err("invalid client authentication".into());
    }

    Ok(client)
}

fn build_introspection_response(claims: &serde_json::Value) -> serde_json::Value {
    let mut response = serde_json::json!({
        "active": true,
    });

    for key in ["iss", "sub", "exp", "iat", "nbf", "scope", "client_id", "username", "token_type", "email", "name", "tenant_id", "role", "auth_time"] {
        if let Some(value) = claims.get(key) {
            response[key] = value.clone();
        }
    }

    if let Some(aud) = claims.get("aud") {
        response["aud"] = aud.clone();
        if response.get("client_id").is_none() {
            match aud {
                serde_json::Value::String(value) => response["client_id"] = serde_json::json!(value),
                serde_json::Value::Array(values) if values.len() == 1 => {
                    if let Some(value) = values[0].as_str() {
                        response["client_id"] = serde_json::json!(value);
                    }
                }
                _ => {}
            }
        }
    }

    response
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(value).unwrap_or_default().into())
        .unwrap()
}

fn hex_sha256(input: &str) -> String {
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Helpers migrated from core-service ──────────────────────

fn verify_client(client_id: &str, client_secret: Option<&str>) -> Result<store::OidcClient, String> {
    use subtle::ConstantTimeEq;

    let client = store::get_client(client_id)?
        .ok_or_else(|| format!("unknown client_id: {client_id}"))?;

    if let Some(expected_secret) = &client.client_secret {
        match client_secret {
            Some(provided)
                if provided.as_bytes().ct_eq(expected_secret.as_bytes()).into() =>
            {
                Ok(client)
            }
            Some(_) => Err("invalid client_secret".into()),
            None => Err("client_secret required for confidential clients".into()),
        }
    } else {
        Ok(client)
    }
}

fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    if method == "plain" {
        return code_verifier.as_bytes().ct_eq(code_challenge.as_bytes()).into();
    }
    if method != "S256" {
        return false;
    }

    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hash);

    computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
}

fn build_claims(
    issuer: &str,
    user: &store::User,
    client_id: &str,
    nonce: Option<&str>,
    auth_time: u64,
    amr: &[String],
    acr: Option<&str>,
    scope: &str,
    requested_id_token_claims: &[String],
    requested_userinfo_claims: &[String],
    extra_claims: &[(String, String)],
) -> (serde_json::Value, serde_json::Value) {
    let now = store::unix_now();
    let memberships = store::list_user_tenants(&user.id).unwrap_or_default();

    let email_verified = user.status == "active";
    let mut access_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + 3600,
        "nbf": now - 30,
        "iat": now,
        "email": user.email,
        "email_verified": email_verified,
        "name": user.name,
        "scope": scope,
        "auth_time": auth_time,
        "token_type": "access",
    });
    let mut id_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + 3600,
        "nbf": now - 30,
        "iat": now,
        "auth_time": auth_time,
        "email": user.email,
        "email_verified": email_verified,
        "name": user.name,
    });

    if let Some(value) = nonce
        && !value.is_empty()
    {
        id_claims["nonce"] = serde_json::json!(value);
    }

    if !amr.is_empty() {
        access_claims["amr"] = serde_json::json!(amr);
        id_claims["amr"] = serde_json::json!(amr);
    }

    if let Some(value) = acr
        && !value.is_empty()
    {
        access_claims["acr"] = serde_json::json!(value);
        id_claims["acr"] = serde_json::json!(value);
    }

    if !requested_userinfo_claims.is_empty() {
        access_claims["lid_userinfo_claims"] = serde_json::json!(requested_userinfo_claims);
    }

    if user.superadmin {
        access_claims["role"] = serde_json::json!("superadmin");
        id_claims["role"] = serde_json::json!("superadmin");
    } else if memberships.len() == 1 {
        let membership = &memberships[0];
        access_claims["tenant_id"] = serde_json::json!(membership.tenant_id);
        access_claims["role"] = serde_json::json!(membership.role);
        id_claims["tenant_id"] = serde_json::json!(membership.tenant_id);
        id_claims["role"] = serde_json::json!(membership.role);
    } else if memberships.len() > 1 {
        let tenants: Vec<serde_json::Value> = memberships
            .iter()
            .map(|membership| {
                serde_json::json!({
                    "tenant_id": membership.tenant_id,
                    "role": membership.role,
                })
            })
            .collect();
        access_claims["tenants"] = serde_json::json!(tenants);
        id_claims["tenants"] = serde_json::json!(tenants);
    }

    // Add requested id_token claims from user profile
    for claim_name in requested_id_token_claims {
        add_derived_profile_claim(&mut id_claims, user, claim_name);
    }

    // Merge custom claims injected by Rhai hooks
    for (key, value) in extra_claims {
        access_claims[key] = serde_json::json!(value);
        id_claims[key] = serde_json::json!(value);
    }

    (access_claims, id_claims)
}

fn add_derived_profile_claim(claims: &mut serde_json::Value, user: &store::User, claim_name: &str) {
    match claim_name {
        "name" => claims["name"] = serde_json::json!(user.name),
        "given_name" => {
            if let Some(value) = user.name.split_whitespace().next()
                && !value.is_empty()
            {
                claims["given_name"] = serde_json::json!(value);
            }
        }
        "family_name" => {
            let mut parts = user.name.split_whitespace();
            let _ = parts.next();
            let remainder = parts.collect::<Vec<_>>().join(" ");
            if !remainder.is_empty() {
                claims["family_name"] = serde_json::json!(remainder);
            }
        }
        "preferred_username" => {
            let preferred = user.email.split('@').next().unwrap_or("");
            if !preferred.is_empty() {
                claims["preferred_username"] = serde_json::json!(preferred);
            }
        }
        "email" => claims["email"] = serde_json::json!(user.email),
        "email_verified" => claims["email_verified"] = serde_json::json!(user.status == "active"),
        _ => {}
    }
}
