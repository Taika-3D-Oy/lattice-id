use wstd::http::{Body, Response, StatusCode};

/// GET /.well-known/openid-configuration
pub fn openid_configuration(issuer: &str) -> Response<Body> {
    let doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "introspection_endpoint": format!("{issuer}/token/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "registration_endpoint": format!("{issuer}/register"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "revocation_endpoint": format!("{issuer}/token/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_parameter_supported": true,
        "claim_types_supported": ["normal"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "acr", "amr", "email", "email_verified", "name", "given_name", "family_name", "preferred_username", "nonce", "tenant_id", "role"],
        "acr_values_supported": ["urn:lattice-id:mfa:totp"],
        "social_login_endpoint": format!("{issuer}/auth/google"),
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "public, max-age=3600")
        .body(serde_json::to_string(&doc).unwrap_or_default().into())
        .unwrap()
}

/// GET /.well-known/jwks.json — fetches JWKS from core-service.
pub async fn jwks() -> Response<Body> {
    match crate::service_client::get_jwks().await {
        Ok(jwks) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "public, max-age=300")
            .body(serde_json::to_string(&jwks).unwrap_or_default().into())
            .unwrap(),
        Err(e) => {
            crate::logger::error_message("jwks.fetch_failed", e);
            crate::error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signing key service unavailable",
            )
        }
    }
}
