#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "key-manager",
        path: "wit",
    });
}

use bindings::exports::taika3d::lid::keys::Guest;
use bindings::taika3d::lid::keyvalue_nats_cas as kv;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::signature::{Signer, SignatureEncoding};

const ROTATION_INTERVAL: u64 = 86400; // 24 hours
const KEY_KV_PATH: &str = "config/signing-keys";

struct KeyManager;

#[derive(Serialize, Deserialize, Clone)]
struct ExportedKeyStore {
    current: ExportedSigningKey,
    previous: Vec<ExportedRetiredKey>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ExportedSigningKey {
    kid: String,
    created_at: u64,
    n: String,
    e: String,
    d: String,
    primes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ExportedRetiredKey {
    kid: String,
    retired_at: u64,
    jwk: serde_json::Value,
}

struct KeyStore {
    current: SigningKeyPair,
    previous: Vec<RetiredKey>,
}

struct SigningKeyPair {
    kid: String,
    private_key: RsaPrivateKey,
    signing_key: SigningKey<Sha256>,
    jwk: String,
    created_at: u64,
}

struct RetiredKey {
    kid: String,
    jwk: serde_json::Value,
    retired_at: u64,
}

impl Guest for KeyManager {
    fn get_public_key() -> Result<String, String> {
        let ks = ensure_keys()?;
        Ok(ks.current.jwk.clone())
    }

    fn get_kid() -> Result<String, String> {
        let ks = ensure_keys()?;
        Ok(ks.current.kid.clone())
    }

    fn sign_jwt(header: String, payload: String) -> Result<String, String> {
        let ks = ensure_keys()?;
        
        let message = format!("{}.{}", header, payload);
        let signature = ks.current.signing_key.sign(message.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

fn ensure_keys() -> Result<KeyStore, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let bucket = kv::open("lid-keys")
        .map_err(|e| format!("failed to open bucket: {e:?}"))?;

    // 1. Try to load from KV first
    let (exported, revision) = match bucket.get(KEY_KV_PATH).map_err(|e| format!("{e:?}"))? {
        Some(entry) => {
            let exported: ExportedKeyStore = serde_json::from_slice(&entry.value)
                .map_err(|e| format!("parse failed: {e}"))?;
            (exported, Some(entry.revision))
        }
        None => {
            // Generate fresh if not in KV
            let ks = generate_new_keystore(now)?;
            let exported = export_keystore(&ks)?;
            let data = serde_json::to_vec(&exported).map_err(|e| e.to_string())?;
            // Initial persist
            bucket.create(KEY_KV_PATH, &data).map_err(|e| format!("{e:?}"))?;
            return Ok(ks);
        }
    };

    // 2. Check for rotation if it's time
    if now - exported.current.created_at >= ROTATION_INTERVAL {
        if let Some(rev) = revision {
            let mut ks = import_keystore(exported.clone())?;
            rotate_keystore(&mut ks, now)?;
            let new_exported = export_keystore(&ks)?;
            let new_data = serde_json::to_vec(&new_exported).map_err(|e| e.to_string())?;
            
            match bucket.swap(KEY_KV_PATH, &new_data, rev) {
                Ok(_new_rev) => {
                    return Ok(ks);
                }
                Err(kv::Error::RevisionMismatch) => {
                    // Lost race, fall through to return current
                }
                Err(e) => return Err(format!("swap failed: {e:?}")),
            }
        }
    }

    // 3. Return imported keystore
    import_keystore(exported)
}

fn generate_new_keystore(now: u64) -> Result<KeyStore, String> {
    let mut rng = rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("RSA gen failed: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);
    
    let kid = generate_kid(&public_key);
    let jwk = build_jwk_string(&public_key, &kid);
    
    Ok(KeyStore {
        current: SigningKeyPair {
            kid,
            jwk,
            signing_key: SigningKey::<Sha256>::new(private_key.clone()),
            private_key,
            created_at: now,
        },
        previous: Vec::new(),
    })
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
    }).to_string()
}

fn rotate_keystore(ks: &mut KeyStore, now: u64) -> Result<(), String> {
    let mut rng = rand_core::OsRng;
    let new_private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("RSA gen failed: {}", e))?;
    let new_public = RsaPublicKey::from(&new_private);
    let new_kid = generate_kid(&new_public);
    let new_jwk = build_jwk_string(&new_public, &new_kid);

    let old = std::mem::replace(&mut ks.current, SigningKeyPair {
        kid: new_kid,
        jwk: new_jwk,
        signing_key: SigningKey::<Sha256>::new(new_private.clone()),
        private_key: new_private,
        created_at: now,
    });

    ks.previous.push(RetiredKey {
        kid: old.kid,
        jwk: serde_json::from_str(&old.jwk).unwrap(),
        retired_at: now,
    });

    Ok(())
}

fn export_keystore(ks: &KeyStore) -> Result<ExportedKeyStore, String> {
    let n = URL_SAFE_NO_PAD.encode(ks.current.private_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(ks.current.private_key.e().to_bytes_be());
    let d = URL_SAFE_NO_PAD.encode(ks.current.private_key.d().to_bytes_be());
    let primes = ks.current.private_key.primes().iter()
        .map(|p| URL_SAFE_NO_PAD.encode(p.to_bytes_be()))
        .collect();

    Ok(ExportedKeyStore {
        current: ExportedSigningKey {
            kid: ks.current.kid.clone(),
            created_at: ks.current.created_at,
            n, e, d, primes,
        },
        previous: ks.previous.iter().map(|rk| ExportedRetiredKey {
            kid: rk.kid.clone(),
            retired_at: rk.retired_at,
            jwk: rk.jwk.clone(),
        }).collect(),
    })
}

fn import_keystore(exported: ExportedKeyStore) -> Result<KeyStore, String> {
    use num_bigint_dig::BigUint;

    let n = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&exported.current.n).map_err(|e| e.to_string())?);
    let e = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&exported.current.e).map_err(|e| e.to_string())?);
    let d = BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&exported.current.d).map_err(|e| e.to_string())?);
    let mut primes = Vec::new();
    for p_str in exported.current.primes {
        primes.push(BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&p_str).map_err(|e| e.to_string())?));
    }

    let private_key = RsaPrivateKey::from_components(n, e, d, primes)
        .map_err(|e| format!("RSA import failed: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);
    let jwk = build_jwk_string(&public_key, &exported.current.kid);

    Ok(KeyStore {
        current: SigningKeyPair {
            kid: exported.current.kid,
            jwk,
            signing_key: SigningKey::<Sha256>::new(private_key.clone()),
            private_key,
            created_at: exported.current.created_at,
        },
        previous: exported.previous.iter().map(|rk| RetiredKey {
            kid: rk.kid.clone(),
            jwk: rk.jwk.clone(),
            retired_at: rk.retired_at,
        }).collect(),
    })
}

bindings::export!(KeyManager with_types_in bindings);
