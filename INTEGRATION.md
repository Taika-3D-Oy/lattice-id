# Integrating Lattice-ID with Your wasmCloud App

This guide shows how to add Lattice-ID authentication to an existing wasmCloud application.

## Overview

Your app validates Lattice-ID JWTs the same way it would validate any OIDC provider's tokens:

1. Fetch JWKS from `{lattice-id}/.well-known/jwks.json`
2. Verify RS256 JWT signature using the matching key
3. Check expiry, audience, and extract claims (`sub`, `email`, `role`, `tenant_id`)

## Step 1: Register an OIDC Client

Using the management API:

```bash
curl -s -X POST http://lattice-id:8000/api/clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name": "My Application",
    "redirect_uris": [
      "https://myapp.example.com/callback",
      "http://localhost:3000/callback"
    ],
    "theme": {
      "app_name": "My Application",
      "logo_url": "https://myapp.example.com/logo.png",
      "primary_color": "#4a90d9",
      "background_color": "#1a1a2e"
    }
  }'
```

Save the returned `client_id`. You'll need it for the frontend OIDC flow.

The optional `theme` object customizes the Lattice-ID login page for your app:

## Step 2: JWT Validation in Your API (Rust)

Add these dependencies to your component's `Cargo.toml`:

```toml
base64 = { version = "0.22", default-features = false, features = ["alloc"] }
rsa = { version = "0.9", default-features = false, features = ["sha2"] }
sha2 = { version = "0.10", default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### Fetch and Cache JWKS

```rust
use std::sync::Mutex;

static JWKS_CACHE: Mutex<Option<JwksResponse>> = Mutex::new(None);

#[derive(serde::Deserialize, Clone)]
struct JwksResponse { keys: Vec<Jwk> }

#[derive(serde::Deserialize, Clone)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: String,
    e: String,
}

async fn get_jwks(jwks_url: &str) -> Result<JwksResponse, String> {
    if let Some(cached) = JWKS_CACHE.lock().unwrap().clone() {
        return Ok(cached);
    }

    let request = wstd::http::Request::builder()
        .method(wstd::http::Method::GET)
        .uri(jwks_url)
        .body(wstd::http::Body::empty())
        .map_err(|e| format!("build request: {e}"))?;

    let response = wstd::http::Client::new()
        .send(request).await
        .map_err(|e| format!("JWKS fetch failed: {e}"))?;

    let mut body = response.into_body();
    let bytes = body.contents().await
        .map_err(|e| format!("read body: {e}"))?;

    let jwks: JwksResponse = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse JWKS: {e}"))?;

    *JWKS_CACHE.lock().unwrap() = Some(jwks.clone());
    Ok(jwks)
}
```

### Verify JWT

```rust
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPublicKey, pkcs1v15::VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;

#[derive(serde::Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub exp: u64,
    pub aud: serde_json::Value,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl Claims {
    pub fn is_admin(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "owner" | "superadmin")
    }

    pub fn is_manager_or_above(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "owner" | "superadmin" | "manager")
    }
}

pub async fn validate_token(
    headers: &wstd::http::HeaderMap,
    jwks_url: &str,
    expected_audience: &str,
) -> Result<Claims, String> {
    // Extract Bearer token
    let auth = headers.get("authorization")
        .ok_or("missing Authorization header")?
        .to_str().map_err(|_| "invalid header")?;
    let token = auth.strip_prefix("Bearer ")
        .ok_or("expected Bearer token")?;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT".into());
    }

    // Decode header for kid + alg
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(parts[0]).map_err(|e| format!("decode: {e}"))?
    ).map_err(|e| format!("parse: {e}"))?;

    if header.get("alg").and_then(|v| v.as_str()) != Some("RS256") {
        return Err("unsupported algorithm".into());
    }
    let kid = header.get("kid").and_then(|v| v.as_str())
        .ok_or("missing kid")?;

    // Fetch JWKS and find matching key
    let jwks = get_jwks(jwks_url).await?;
    let jwk = jwks.keys.iter()
        .find(|k| k.kid.as_deref() == Some(kid) && k.kty == "RSA")
        .ok_or("no matching key")?;

    // Build RSA public key
    let n = rsa::BigUint::from_bytes_be(
        &URL_SAFE_NO_PAD.decode(&jwk.n).map_err(|e| format!("decode n: {e}"))?
    );
    let e = rsa::BigUint::from_bytes_be(
        &URL_SAFE_NO_PAD.decode(&jwk.e).map_err(|e| format!("decode e: {e}"))?
    );
    let rsa_key = RsaPublicKey::new(n, e).map_err(|e| format!("bad key: {e}"))?;

    // Verify signature
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])
        .map_err(|e| format!("decode sig: {e}"))?;
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("bad sig: {e}"))?;
    VerifyingKey::<Sha256>::new(rsa_key)
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "invalid signature")?;

    // Decode and validate claims
    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| format!("decode: {e}"))?
    ).map_err(|e| format!("parse claims: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    if claims.exp < now {
        return Err("token expired".into());
    }

    // Verify audience
    let aud_ok = match &claims.aud {
        serde_json::Value::String(s) => s == expected_audience,
        serde_json::Value::Array(arr) => arr.iter()
            .any(|v| v.as_str() == Some(expected_audience)),
        _ => false,
    };
    if !aud_ok {
        return Err("invalid audience".into());
    }

    Ok(claims)
}
```

## Step 3: Frontend OIDC Integration

### Browser PKCE Flow

```javascript
// 1. Generate PKCE verifier + challenge
const verifier = crypto.randomUUID() + crypto.randomUUID();
const challenge = btoa(String.fromCharCode(
  ...new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(verifier)))
)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');

// 2. Store verifier + state
const state = crypto.randomUUID();
sessionStorage.setItem('pkce_verifier', verifier);
sessionStorage.setItem('pkce_state', state);

// 3. Redirect to Lattice-ID
window.location.href = `${LATTICE_ID_URL}/authorize?` + new URLSearchParams({
  response_type: 'code',
  client_id: CLIENT_ID,
  redirect_uri: window.location.origin + '/callback',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  state: state,
  scope: 'openid profile email',
});
```

### Callback Handler

```javascript
// On /callback page:
const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const returnedState = params.get('state');

if (returnedState !== sessionStorage.getItem('pkce_state')) {
  throw new Error('State mismatch');
}

const verifier = sessionStorage.getItem('pkce_verifier');
sessionStorage.removeItem('pkce_verifier');
sessionStorage.removeItem('pkce_state');

const response = await fetch(`${LATTICE_ID_URL}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    client_id: CLIENT_ID,
    redirect_uri: window.location.origin + '/callback',
    code_verifier: verifier,
  }),
});

const tokens = await response.json();
// tokens.access_token — use for API calls
// tokens.id_token — user identity
// tokens.refresh_token — for token refresh
```

### Rust/egui (Wasm) Frontend

For Rust browser apps using egui, the PKCE flow is the same but using `ehttp` for the token exchange and `web-sys` for localStorage/crypto. See the `admin-ui` directory in this repo for a working Leptos example.

## Step 4: Deployment

### Option A: Same workload

Add the Lattice-ID components alongside your application in the same `WorkloadDeployment`. See [deploy/workloaddeployment-local.yaml](deploy/workloaddeployment-local.yaml) for an example manifest.

### Option B: Separate workloads

Deploy Lattice-ID as a standalone workload and have your application fetch JWKS over HTTP. Your app only needs the JWKS URL to verify tokens — no direct dependency on Lattice-ID components.

## Claim Mapping Reference

| Lattice-ID Claim | Description | Example |
|-------------------|-------------|---------|
| `sub` | User ID (hex) | `"8f1554b5d1f8e3f0..."` |
| `email` | User email | `"user@example.com"` |
| `name` | Display name | `"Alice Test"` |
| `role` | Tenant role | `"admin"` / `"manager"` / `"member"` |
| `tenant_id` | Tenant ID (hex) | `"787fc687..."` |
| `tenants` | Multi-tenant array | `[{"tenant_id":"...","role":"..."}]` |
| `token_type` | Token purpose | `"access"` |

## Migration from Auth0

If you're migrating from Auth0:

1. **Claims mapping**: Auth0 uses namespaced claims (`https://yourapp.com/role`). Lattice-ID uses flat claims (`role`, `tenant_id`). Update your `Claims` struct accordingly.

2. **JWKS URL**: Change from `https://{auth0_domain}/.well-known/jwks.json` to `http://{lattice-id}/.well-known/jwks.json`.

3. **Audience**: Create an OIDC client in Lattice-ID with the same `client_id` or update your audience config.

4. **User management**: Replace Auth0 Management API calls with Lattice-ID's `/api/tenants/*/users` endpoints.

5. **Frontend**: Change the authorization URL from Auth0 to Lattice-ID. The PKCE flow is identical.

## Setting Up Google Login

### 1. Create Google OAuth2 credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create an OAuth 2.0 Client ID (Web application)
3. Add `https://{your-lattice-id-domain}/auth/google/callback` as an authorized redirect URI
4. Note the **Client ID** and **Client Secret**

### 2. Register the identity provider

```bash
curl -s -X POST http://lattice-id:8000/api/identity-providers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "provider_type": "google",
    "client_id": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
    "client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
    "enabled": true
  }'
```

### 3. How it works

When Google login is configured, the Lattice-ID login page shows a "Sign in with Google" button. The flow:

1. User clicks "Sign in with Google" on the login page
2. Lattice-ID redirects to Google's consent screen
3. Google redirects back to `/auth/google/callback` with an authorization code
4. Lattice-ID exchanges the code for an id_token server-side
5. Lattice-ID finds or creates the user and issues an OIDC authorization code
6. The user is redirected back to your app's `redirect_uri`

Account linking: If a user with the same email already exists, the Google identity is automatically linked. Otherwise a new account is created.

## Setting Up MFA / TOTP

### 1. Enroll a user

```bash
# Generate TOTP secret
curl -s -X POST "http://lattice-id:8000/api/users/$USER_ID/mfa/setup" \
  -H "Authorization: Bearer $TOKEN"
# Returns: { "secret": "...", "otpauth_uri": "otpauth://totp/..." }

# User scans QR code, then confirm with a code from their authenticator
curl -s -X POST "http://lattice-id:8000/api/users/$USER_ID/mfa/confirm" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"code": "123456"}'
# Returns: { "recovery_codes": ["abc12345", ...] }
```

### 2. Login flow with MFA

When MFA is enabled, after entering a correct password the user sees a TOTP code input page. The flow is transparent to the relying party — the OIDC authorization code is only issued after both factors are verified.

### 3. Disable MFA

```bash
curl -s -X DELETE "http://lattice-id:8000/api/users/$USER_ID/mfa" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Recovery codes

During MFA enrollment, 10 one-time recovery codes are returned. Each code can be used once in place of a TOTP code. Store them securely.
