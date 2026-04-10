use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::keys::SigningKeyPair;

/// Sign a set of claims as an RS256 JWT.
/// The caller provides all claims (iss, sub, aud, exp, iat, etc.)
/// — the service adds only the header (alg, typ, kid).
pub fn sign(claims: &serde_json::Value, kp: &SigningKeyPair) -> Result<String, String> {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kp.kid,
    });

    let h = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| format!("header encode: {e}"))?);
    let p = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| format!("claims encode: {e}"))?);
    let message = format!("{h}.{p}");

    let sig = kp
        .signing_key
        .try_sign(message.as_bytes())
        .map_err(|e| format!("signing failed: {e}"))?;
    let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(format!("{message}.{s}"))
}

/// Verify an RS256 JWT and return the decoded claims.
/// Tries all provided verifying keys (current + rotated), matching by kid.
pub fn verify(
    token: &str,
    verifiers: &[(&str, &VerifyingKey<Sha256>)],
) -> Result<serde_json::Value, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".into());
    }
    let (h_b64, p_b64, s_b64) = (parts[0], parts[1], parts[2]);

    // Decode header and check algorithm
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h_b64)
            .map_err(|e| format!("header decode: {e}"))?,
    )
    .map_err(|e| format!("header parse: {e}"))?;

    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(format!("unsupported algorithm: {alg}"));
    }

    // Verify signature over "<header>.<payload>"
    let message = format!("{h_b64}.{p_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(s_b64)
        .map_err(|e| format!("signature decode: {e}"))?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|e| format!("bad signature: {e}"))?;

    // Find matching verifier by kid header, or try all if no kid
    let token_kid = header.get("kid").and_then(|v| v.as_str());
    let candidates: Vec<&&VerifyingKey<Sha256>> = if let Some(kid) = token_kid {
        verifiers
            .iter()
            .filter(|(k, _)| *k == kid)
            .map(|(_, v)| v)
            .collect()
    } else {
        verifiers.iter().map(|(_, v)| v).collect()
    };

    if candidates.is_empty() {
        return Err("no matching signing key found".into());
    }

    let mut last_err = String::new();
    for vk in &candidates {
        match vk.verify(message.as_bytes(), &sig) {
            Ok(()) => {
                let claims: serde_json::Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(p_b64)
                        .map_err(|e| format!("payload decode: {e}"))?,
                )
                .map_err(|e| format!("payload parse: {e}"))?;

                if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now > exp {
                        return Err("token expired".into());
                    }
                }
                return Ok(claims);
            }
            Err(e) => {
                last_err = format!("verification failed: {e}");
            }
        }
    }

    Err(last_err)
}
