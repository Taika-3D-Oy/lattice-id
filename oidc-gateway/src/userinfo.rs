use wstd::http::{Body, Response, StatusCode};

fn has_scope(scope: &str, value: &str) -> bool {
    scope.split(' ').any(|candidate| candidate == value)
}

fn push_unique(values: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !values.iter().any(|existing| existing == candidate) {
        values.push(candidate.to_string());
    }
}

fn requested_userinfo_claims(claims: &serde_json::Value) -> Vec<String> {
    let mut requested = vec!["sub".to_string()];
    let scope = claims.get("scope").and_then(|value| value.as_str()).unwrap_or("");
    if has_scope(scope, "profile") {
        for claim_name in ["name", "given_name", "family_name", "preferred_username"] {
            push_unique(&mut requested, claim_name);
        }
    }
    if has_scope(scope, "email") {
        push_unique(&mut requested, "email");
        push_unique(&mut requested, "email_verified");
    }
    if let Some(extra) = claims.get("lid_userinfo_claims").and_then(|value| value.as_array()) {
        for claim_name in extra {
            if let Some(claim_name) = claim_name.as_str() {
                push_unique(&mut requested, claim_name);
            }
        }
    }
    requested
}

fn populate_userinfo_claim(
    userinfo: &mut serde_json::Map<String, serde_json::Value>,
    requested: &str,
    user: &crate::store::User,
    claims: &serde_json::Value,
) {
    match requested {
        "sub" => {
            if let Some(value) = claims.get("sub") {
                userinfo.insert("sub".to_string(), value.clone());
            }
        }
        "name" => {
            userinfo.insert("name".to_string(), serde_json::json!(user.name));
        }
        "given_name" => {
            if let Some(value) = user.name.split_whitespace().next()
                && !value.is_empty()
            {
                userinfo.insert("given_name".to_string(), serde_json::json!(value));
            }
        }
        "family_name" => {
            let mut parts = user.name.split_whitespace();
            let _ = parts.next();
            let remainder = parts.collect::<Vec<_>>().join(" ");
            if !remainder.is_empty() {
                userinfo.insert("family_name".to_string(), serde_json::json!(remainder));
            }
        }
        "preferred_username" => {
            let preferred = user.email.split('@').next().unwrap_or("");
            if !preferred.is_empty() {
                userinfo.insert("preferred_username".to_string(), serde_json::json!(preferred));
            }
        }
        "email" => {
            userinfo.insert("email".to_string(), serde_json::json!(user.email));
        }
        "email_verified" => {
            userinfo.insert("email_verified".to_string(), serde_json::json!(user.status == "active"));
        }
        "auth_time" | "amr" | "acr" | "tenant_id" | "role" | "tenants" => {
            if let Some(value) = claims.get(requested) {
                userinfo.insert(requested.to_string(), value.clone());
            }
        }
        _ => {}
    }
}

/// Handle GET /userinfo — validate Bearer token, return user claims.
/// Per OIDC Core §5.3.3: The access token MUST be validated (issuer, audience, type).
pub async fn handle(auth_header: Option<&str>, issuer: &str) -> Result<Response<Body>, String> {
    let token = extract_bearer(auth_header)?;

    // Verify JWT via core-service.
    // Pass audience=None: the core-service already validates that the token was issued
    // by this authority. The access token's aud claim is the client_id, not a fixed
    // "userinfo" value — OIDC Core §5.3.3 requires the OP to validate the token,
    // which we do by checking issuer + token_type=access.
    let claims = crate::service_client::verify_token_scoped(
        &token,
        Some(issuer),
        None,
        Some("access"),
    )
    .await?;

    let user_id = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .ok_or("missing subject claim")?;
    let user = crate::store::get_user(user_id)?.ok_or("user not found")?;
    let requested_claims = requested_userinfo_claims(&claims);

    let mut userinfo = serde_json::Map::new();
    for requested in requested_claims {
        populate_userinfo_claim(&mut userinfo, &requested, &user, &claims);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(serde_json::to_string(&serde_json::Value::Object(userinfo)).unwrap_or_default().into())
        .unwrap())
}

fn extract_bearer(header: Option<&str>) -> Result<String, String> {
    let header = header.ok_or("missing Authorization header")?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or("invalid Authorization header (expected Bearer)")?;
    Ok(token.to_string())
}
