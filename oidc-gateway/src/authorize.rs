use crate::store::{self, AuthSession};
use crate::util;
use http::{Response, StatusCode};

#[derive(Default)]
struct ClaimsRequest {
    id_token_claims: Vec<String>,
    userinfo_claims: Vec<String>,
    acr_values: Vec<String>,
}

struct ValidatedHint {
    user_id: String,
    email: String,
}

fn parse_acr_values(raw: Option<&str>) -> Vec<String> {
    let mut values = Vec::new();
    for item in raw.unwrap_or("").split(' ') {
        let item = item.trim();
        if item.is_empty() || values.iter().any(|existing| existing == item) {
            continue;
        }
        values.push(item.to_string());
    }
    values
}

fn push_unique(values: &mut Vec<String>, candidate: &str) {
    if !candidate.is_empty() && !values.iter().any(|existing| existing == candidate) {
        values.push(candidate.to_string());
    }
}

fn parse_claims_param(raw: Option<&str>) -> Result<ClaimsRequest, String> {
    let Some(raw) = raw.filter(|value| !value.is_empty()) else {
        return Ok(ClaimsRequest::default());
    };

    let claims_json: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "invalid claims parameter (must be JSON object)")?;
    let claims_obj = claims_json
        .as_object()
        .ok_or("invalid claims parameter (must be JSON object)")?;

    let mut parsed = ClaimsRequest::default();
    for (target, output) in [
        ("id_token", &mut parsed.id_token_claims),
        ("userinfo", &mut parsed.userinfo_claims),
    ] {
        let Some(requested) = claims_obj.get(target) else {
            continue;
        };
        let requested = requested
            .as_object()
            .ok_or("invalid claims parameter target (must be object)")?;
        for (claim_name, descriptor) in requested {
            if !(descriptor.is_null() || descriptor.is_object()) {
                return Err("invalid claims parameter claim descriptor".into());
            }
            push_unique(output, claim_name);

            if target == "id_token"
                && claim_name == "acr"
                && let Some(descriptor) = descriptor.as_object()
            {
                if let Some(value) = descriptor.get("value").and_then(|value| value.as_str()) {
                    push_unique(&mut parsed.acr_values, value);
                }
                if let Some(values) = descriptor.get("values").and_then(|value| value.as_array()) {
                    for value in values {
                        let value = value
                            .as_str()
                            .ok_or("invalid claims parameter acr values")?;
                        push_unique(&mut parsed.acr_values, value);
                    }
                }
            }
        }
    }

    Ok(parsed)
}

fn authorize_error_redirect(
    redirect_uri: &str,
    state: &str,
    error: &str,
    description: &str,
) -> Response<String> {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!(
        "{redirect_uri}{separator}error={}&error_description={}",
        util::percent_encode(error),
        util::percent_encode(description),
    );
    if !state.is_empty() {
        location.push_str("&state=");
        location.push_str(&util::percent_encode(state));
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .body(String::new())
        .unwrap()
}

async fn validate_id_token_hint(
    raw_hint: Option<&str>,
    issuer: &str,
    client_id: &str,
) -> Result<Option<ValidatedHint>, String> {
    let Some(raw_hint) = raw_hint.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let claims =
        crate::service_client::verify_token_scoped(raw_hint, Some(issuer), Some(client_id), None)
            .await
            .map_err(|_| "invalid id_token_hint")?;

    if claims
        .get("token_type")
        .and_then(|value| value.as_str())
        .is_some()
    {
        return Err("invalid id_token_hint".into());
    }

    let user_id = claims
        .get("sub")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or("invalid id_token_hint")?;
    let user = store::get_user(user_id)
        .await?
        .filter(|user| user.status == "active")
        .ok_or("invalid id_token_hint")?;

    Ok(Some(ValidatedHint {
        user_id: user.id,
        email: user.email,
    }))
}

/// Handle GET /authorize — validate PKCE params, store session, serve login page.
pub async fn handle(query: &str, issuer: &str) -> Result<Response<String>, String> {
    let params = util::parse_query(query);
    let get = |key: &str| -> Option<&str> {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };

    // Required OIDC params
    let response_type = get("response_type").ok_or("missing response_type")?;
    if response_type != "code" {
        return Err(format!("unsupported response_type: {response_type}"));
    }

    let client_id = get("client_id").ok_or("missing client_id")?;
    let redirect_uri = get("redirect_uri").ok_or("missing redirect_uri")?;
    let code_challenge = get("code_challenge").ok_or("missing code_challenge (PKCE required)")?;
    let code_challenge_method = get("code_challenge_method").unwrap_or("S256");
    if code_challenge_method != "S256" {
        return Err("only S256 code_challenge_method is supported".into());
    }

    let prompt = get("prompt").unwrap_or("");
    let state = get("state").unwrap_or("");
    let id_token_hint = get("id_token_hint");
    let login_hint = get("login_hint");
    let max_age = match get("max_age") {
        Some(value) => Some(
            value
                .parse::<u64>()
                .map_err(|_| "invalid max_age (must be a non-negative integer)")?,
        ),
        None => None,
    };
    // Task 2.16: Support OIDC prompt parameter (OIDC Core §3.1.2.1).
    if prompt == "none" {
        // prompt=none requires returning an error if the user is not already authenticated.
        // Lattice-ID uses per-request auth sessions (no persistent browser sessions),
        // so the user is never "already authenticated" — always return login_required.
        let err_redirect = format!(
            "{}{}error=login_required&error_description=prompt%3Dnone%20requires%20existing%20session&state={}",
            redirect_uri,
            if redirect_uri.contains('?') { "&" } else { "?" },
            state
        );
        return Ok(Response::builder()
            .status(http::StatusCode::FOUND)
            .header("location", &err_redirect)
            .body(String::new())
            .unwrap());
    }
    // prompt=login: Force re-authentication (default behavior of this endpoint).
    // prompt=consent: Always implied (no stored consent).

    let scope = get("scope").unwrap_or("openid");
    let nonce = get("nonce").unwrap_or("");
    let mut acr_values = parse_acr_values(get("acr_values"));
    let claims_request = parse_claims_param(get("claims"))?;
    if !acr_values.is_empty() && !claims_request.acr_values.is_empty() {
        return Err("claims parameter acr request cannot be combined with acr_values".into());
    }
    if acr_values.is_empty() {
        acr_values = claims_request.acr_values.clone();
    }

    // Validate client
    let client = store::get_client(client_id)
        .await?
        .ok_or_else(|| format!("unknown client_id: {client_id}"))?;

    // Validate redirect_uri
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Err("redirect_uri not registered for this client".into());
    }

    let validated_hint = match validate_id_token_hint(id_token_hint, issuer, client_id).await {
        Ok(value) => value,
        Err(_) => {
            return Ok(authorize_error_redirect(
                redirect_uri,
                state,
                "invalid_request",
                "invalid id_token_hint",
            ));
        }
    };

    // Store auth session
    let session_id = store::random_hex(16);
    // Require consent when:
    //  - explicitly requested with prompt=consent, OR
    //  - the client is not first-party (and not the built-in admin/default clients)
    let builtin_clients = ["lid-admin", "lid-default"];
    let is_first_party =
        client.first_party || builtin_clients.contains(&client_id) || crate::is_dev_mode(); // dev mode skips consent for convenience
    let needs_consent = prompt == "consent" || !is_first_party;
    let session = AuthSession {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        code_challenge: code_challenge.to_string(),
        code_challenge_method: code_challenge_method.to_string(),
        state: state.to_string(),
        scope: scope.to_string(),
        nonce: nonce.to_string(),
        max_age,
        acr_values,
        requested_id_token_claims: claims_request.id_token_claims,
        requested_userinfo_claims: claims_request.userinfo_claims,
        hinted_user_id: validated_hint.as_ref().map(|hint| hint.user_id.clone()),
        hinted_email: validated_hint
            .as_ref()
            .map(|hint| hint.email.clone())
            .or_else(|| login_hint.filter(|h| !h.is_empty()).map(|h| h.to_string())),
        created_at: store::unix_now(),
        needs_consent,
    };
    store::save_auth_session(&session_id, &session).await?;

    // Serve login page
    Ok(crate::login::login_page(&session_id, None).await)
}
