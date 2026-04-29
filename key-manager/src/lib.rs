#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "key-manager",
        path: "wit",
        async: [
            "import:wasmcloud:messaging/consumer@0.2.0#request",
            "export:taika3d:lid/keys#get-public-key",
            "export:taika3d:lid/keys#get-public-keys",
            "export:taika3d:lid/keys#get-kid",
            "export:taika3d:lid/keys#sign-jwt",
        ],
        generate_all,
    });
}

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bindings::exports::taika3d::lid::keys::Guest;
use bindings::wasi::config::store as config_store;
use bindings::wasmcloud::messaging::consumer;
use p256::ecdsa::SigningKey as EcSigningKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

struct KeyManager;

struct LoadedKeys {
    kid: String,
    rsa_jwk: String,
    #[allow(dead_code)]
    ec_kid: String,
    ec_jwk: String,
    signing_key: SigningKey<Sha256>,
    ec_signing_key: EcSigningKey,
}

const KEY_NAME: &str = "signing-key-v1";
const EC_KEY_NAME: &str = "signing-key-ec-v1";
const TIMEOUT_MS: u32 = 5000;

fn keys_table() -> String {
    "keys".to_string()
}

/// Build a lattice-db NATS subject from the configured instance prefix.
/// Reads `ldb_instance` config (defaults to `"lid"`).
fn ldb_subject(op: &str) -> String {
    let instance = config_store::get("ldb_instance")
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "lid".to_string());
    format!("{instance}.{op}")
}

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

/// Send a JSON request to lattice-db via wasmcloud:messaging and parse the response.
/// Injects `consistency.min_revision` and extracts `session.revisions` (lattice-db ≥ 1.6.0).
async fn ldb_request(
    subject: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let payload = if let Some(table) = payload.get("table").and_then(|t| t.as_str()) {
        let min_rev = SESSION_REVISIONS.with(|sr| sr.borrow().get(table).copied());
        if let Some(rev) = min_rev {
            let mut p = payload.clone();
            p.as_object_mut().unwrap().insert(
                "consistency".to_string(),
                serde_json::json!({ "min_revision": rev }),
            );
            p
        } else {
            payload.clone()
        }
    } else {
        payload.clone()
    };

    let body = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;
    let resp = consumer::request(subject.to_string(), body, TIMEOUT_MS).await?;
    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("parse response: {e}"))?;
    if let Some(err) = val.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }

    if let Some(session) = val.get("session").and_then(|s| s.as_object())
        && let Some(revisions) = session.get("revisions").and_then(|r| r.as_object())
    {
        SESSION_REVISIONS.with(|sr| {
            let mut map = sr.borrow_mut();
            for (table, rev_val) in revisions {
                if let Some(rev) = rev_val.as_u64() {
                    let entry = map.entry(table.clone()).or_insert(0);
                    if rev > *entry {
                        *entry = rev;
                    }
                }
            }
        });
    }
    if let (Some(table), Some(revision)) = (
        payload.get("table").and_then(|t| t.as_str()),
        val.get("revision").and_then(|v| v.as_u64()),
    ) {
        SESSION_REVISIONS.with(|sr| {
            let mut map = sr.borrow_mut();
            let entry = map.entry(table.to_string()).or_insert(0);
            if revision > *entry {
                *entry = revision;
            }
        });
    }

    Ok(val)
}

/// Try to load the signing key from lattice-db.
async fn load_from_db() -> Result<Option<StoredKey>, String> {
    let payload = serde_json::json!({ "table": keys_table(), "key": KEY_NAME });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let stored: StoredKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize key: {e}"))?;
            Ok(Some(stored))
        }
        Err(e) if e.contains("not found") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Generate a new RSA key and store it in lattice-db atomically (create = fail if exists).
async fn generate_and_store() -> Result<StoredKey, String> {
    let mut rng = rand_core::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA gen failed: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);

    let kid = generate_kid(&public_key);

    let stored = StoredKey {
        kid: kid.clone(),
        n: URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
        d: URL_SAFE_NO_PAD.encode(private_key.d().to_bytes_be()),
        primes: private_key
            .primes()
            .iter()
            .map(|p| URL_SAFE_NO_PAD.encode(p.to_bytes_be()))
            .collect(),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize: {e}"))?;
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(&stored_bytes);
    let payload = serde_json::json!({ "table": keys_table(), "key": KEY_NAME, "value": value_b64 });

    match ldb_request(&ldb_subject("create"), &payload).await {
        Ok(_) => {
            eprintln!("KEY-MANAGER: generated and stored new signing key kid={kid}");
            Ok(stored)
        }
        Err(e) if e.contains("already exists") => {
            // Another instance won the race — load the winner's key
            eprintln!("KEY-MANAGER: key race lost, loading existing key");
            load_from_db()
                .await?
                .ok_or_else(|| "key disappeared after race".to_string())
        }
        Err(e) => Err(format!("store key: {e}")),
    }
}

async fn load_keys() -> Result<LoadedKeys, String> {
    let stored = match load_from_db().await? {
        Some(s) => s,
        None => generate_and_store().await?,
    };
    let ec_stored = match load_ec_from_db().await? {
        Some(s) => s,
        None => generate_and_store_ec().await?,
    };
    let loaded = stored.to_loaded()?;
    let ec_loaded = ec_stored.to_loaded_ec()?;
    Ok(LoadedKeys {
        kid: loaded.kid,
        rsa_jwk: loaded.jwk,
        ec_kid: ec_loaded.kid,
        ec_jwk: ec_loaded.jwk,
        signing_key: loaded.signing_key,
        ec_signing_key: ec_loaded.signing_key,
    })
}

struct RsaLoaded {
    kid: String,
    jwk: String,
    signing_key: SigningKey<Sha256>,
}
struct EcLoaded {
    kid: String,
    jwk: String,
    signing_key: EcSigningKey,
}

impl Guest for KeyManager {
    async fn get_public_key() -> Result<String, String> {
        let keys = load_keys().await?;
        Ok(keys.rsa_jwk)
    }

    async fn get_public_keys() -> Result<String, String> {
        let keys = load_keys().await?;
        let arr = serde_json::json!([
            serde_json::from_str::<serde_json::Value>(&keys.rsa_jwk)
                .map_err(|e| format!("parse rsa jwk: {e}"))?,
            serde_json::from_str::<serde_json::Value>(&keys.ec_jwk)
                .map_err(|e| format!("parse ec jwk: {e}"))?
        ]);
        Ok(arr.to_string())
    }

    async fn get_kid() -> Result<String, String> {
        let keys = load_keys().await?;
        Ok(keys.kid)
    }

    async fn sign_jwt(header: String, payload: String) -> Result<String, String> {
        let keys = load_keys().await?;
        // Decode the header to determine the algorithm
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&header)
            .map_err(|e| format!("decode header: {e}"))?;
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|e| format!("parse header: {e}"))?;
        let alg = header_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("RS256");

        let message = format!("{}.{}", header, payload);
        match alg {
            "RS256" => {
                let sig = keys.signing_key.sign(message.as_bytes());
                Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
            }
            "ES256" => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = keys.ec_signing_key.sign(message.as_bytes());
                // RFC 7518 §3.4: ES256 signature is R || S (each 32 bytes) in big-endian
                let sig_bytes = sig.to_bytes();
                Ok(URL_SAFE_NO_PAD.encode(sig_bytes))
            }
            _ => Err(format!("unsupported algorithm: {alg}")),
        }
    }
}

// ── Persistence types ──────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKey {
    kid: String,
    n: String,
    e: String,
    d: String,
    primes: Vec<String>,
}

impl StoredKey {
    fn to_loaded(&self) -> Result<RsaLoaded, String> {
        use num_bigint_dig::BigUint;
        let n = decode_biguint(&self.n, "n")?;
        let e = decode_biguint(&self.e, "e")?;
        let d = decode_biguint(&self.d, "d")?;
        let primes: Vec<BigUint> = self
            .primes
            .iter()
            .enumerate()
            .map(|(i, p)| decode_biguint(p, &format!("prime[{i}]")))
            .collect::<Result<Vec<_>, _>>()?;

        let private_key = RsaPrivateKey::from_components(n.clone(), e.clone(), d, primes)
            .map_err(|e| format!("reconstruct key: {e}"))?;
        let public_key = RsaPublicKey::from(&private_key);

        let jwk = build_jwk_string(&public_key, &self.kid);

        Ok(RsaLoaded {
            kid: self.kid.clone(),
            jwk,
            signing_key: SigningKey::<Sha256>::new(private_key),
        })
    }
}

fn decode_biguint(b64: &str, label: &str) -> Result<num_bigint_dig::BigUint, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("decode {label}: {e}"))?;
    Ok(num_bigint_dig::BigUint::from_bytes_be(&bytes))
}

fn generate_kid(pub_key: &RsaPublicKey) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(pub_key.n().to_bytes_be());
    hasher.update(pub_key.e().to_bytes_be());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&hash[..12])
}

fn build_jwk_string(pub_key: &RsaPublicKey, kid: &str) -> String {
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    })
    .to_string()
}

// ── EC (P-256 / ES256) key storage ───────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEcKey {
    kid: String,
    /// Raw 32-byte P-256 scalar, base64url-encoded.
    d: String,
}

impl StoredEcKey {
    fn to_loaded_ec(&self) -> Result<EcLoaded, String> {
        let scalar_bytes = URL_SAFE_NO_PAD
            .decode(&self.d)
            .map_err(|e| format!("decode EC key: {e}"))?;
        let sk = EcSigningKey::from_bytes(scalar_bytes.as_slice().into())
            .map_err(|e| format!("parse EC key: {e}"))?;
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false); // uncompressed
        let coords = point.coordinates();
        let (x_bytes, y_bytes) = match coords {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (x, y),
            _ => return Err("expected uncompressed EC point".into()),
        };
        let jwk = serde_json::json!({
            "kty": "EC",
            "use": "sig",
            "alg": "ES256",
            "kid": self.kid,
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x_bytes),
            "y": URL_SAFE_NO_PAD.encode(y_bytes),
        })
        .to_string();
        Ok(EcLoaded {
            kid: self.kid.clone(),
            jwk,
            signing_key: sk,
        })
    }
}

async fn load_ec_from_db() -> Result<Option<StoredEcKey>, String> {
    let payload = serde_json::json!({ "table": keys_table(), "key": EC_KEY_NAME });
    match ldb_request(&ldb_subject("get"), &payload).await {
        Ok(resp) => {
            let value_b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value_b64)
                .map_err(|e| format!("base64 decode: {e}"))?;
            let stored: StoredEcKey =
                serde_json::from_slice(&bytes).map_err(|e| format!("deserialize EC key: {e}"))?;
            Ok(Some(stored))
        }
        Err(e) if e.contains("not found") => Ok(None),
        Err(e) => Err(e),
    }
}

async fn generate_and_store_ec() -> Result<StoredEcKey, String> {
    let sk = EcSigningKey::random(&mut rand_core::OsRng);
    let scalar_bytes: Vec<u8> = sk.to_bytes().to_vec();

    // Compute kid from the public key
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let kid = {
        use sha2::Digest;
        let hash = Sha256::digest(point.as_bytes());
        URL_SAFE_NO_PAD.encode(&hash[..12])
    };

    let stored = StoredEcKey {
        kid: kid.clone(),
        d: URL_SAFE_NO_PAD.encode(&scalar_bytes),
    };

    let stored_bytes = serde_json::to_vec(&stored).map_err(|e| format!("serialize EC key: {e}"))?;
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(&stored_bytes);
    let payload =
        serde_json::json!({ "table": keys_table(), "key": EC_KEY_NAME, "value": value_b64 });

    match ldb_request(&ldb_subject("create"), &payload).await {
        Ok(_) => {
            eprintln!("KEY-MANAGER: generated and stored new EC signing key kid={kid}");
            Ok(stored)
        }
        Err(e) if e.contains("already exists") => {
            eprintln!("KEY-MANAGER: EC key race lost, loading existing key");
            load_ec_from_db()
                .await?
                .ok_or_else(|| "EC key disappeared after race".to_string())
        }
        Err(e) => Err(format!("store EC key: {e}")),
    }
}

bindings::export!(KeyManager with_types_in bindings);
