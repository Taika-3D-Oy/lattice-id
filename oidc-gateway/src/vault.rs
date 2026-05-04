use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hkdf::Hkdf;
use sha2::Sha256;

use std::cell::RefCell;

// ── Constants ────────────────────────────────────────────────────────────────

const VERSION_LEN: usize = 1;
const NONCE_LEN: usize = 12;
const MIN_ENVELOPE_LEN: usize = VERSION_LEN + NONCE_LEN + 17;
const MASTER_KEY_PREFIX: &str = "master";

// ── Thread-local state ───────────────────────────────────────────────────────

thread_local! {
    static MASTER_KEYS: RefCell<Vec<(u32, [u8; 32])>> = const { RefCell::new(Vec::new()) };
    static CURRENT_VERSION: RefCell<u32> = const { RefCell::new(0) };
    static INITIALIZED: RefCell<bool> = const { RefCell::new(false) };
}

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum VaultError {
    KmsUnavailable(String),
    InvalidCiphertext(String),
    VersionNotFound(u32),
    AadMismatch,
    Internal(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::KmsUnavailable(s) => write!(f, "kms unavailable: {s}"),
            VaultError::InvalidCiphertext(s) => write!(f, "invalid ciphertext: {s}"),
            VaultError::VersionNotFound(v) => write!(f, "key version not found: {v}"),
            VaultError::AadMismatch => write!(f, "AAD mismatch (wrong context or tampered data)"),
            VaultError::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

fn vault_table() -> String {
    "vault".to_string()
}

// ── Master key management ─────────────────────────────────────────────────────

fn dev_master_from_seed(seed: &str, version: u32) -> [u8; 32] {
    let salt = format!("lattice-id-dev-vault-v{version}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"master-key", &mut key).expect("hkdf expand");
    key
}

async fn load_master_key(version: u32) -> Result<[u8; 32], VaultError> {
    let kms_endpoint = crate::bindings::wasi::config::store::get("kms_endpoint".to_string())
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    if kms_endpoint.is_empty() {
        // Dev-mode seed path: only permitted when dev_mode=true.
        // Crashes if neither kms_endpoint nor kms_dev_seed is configured so
        // a production misconfiguration is caught at startup rather than
        // silently using an insecure public default.
        let is_dev = crate::store::config_value("dev_mode")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let seed = crate::bindings::wasi::config::store::get("kms_dev_seed".to_string())
            .await
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty());
        match seed {
            Some(s) if is_dev => return Ok(dev_master_from_seed(&s, version)),
            Some(_) => {
                // kms_dev_seed present but dev_mode is off — refuse to start.
                return Err(VaultError::KmsUnavailable(
                    "kms_dev_seed is set but dev_mode is false. \
                     Set kms_endpoint for production or enable dev_mode for local development."
                        .into(),
                ));
            }
            None => {
                return Err(VaultError::KmsUnavailable(
                    "No KMS configured: set kms_endpoint (production) \
                     or kms_dev_seed + dev_mode=true (development)."
                        .into(),
                ));
            }
        }
    }

    let table = vault_table();
    let key_name = format!("{MASTER_KEY_PREFIX}:{version}");
    let wrapped = crate::store::kv_get_raw(&table, &key_name)
        .await
        .map_err(VaultError::KmsUnavailable)?
        .ok_or(VaultError::VersionNotFound(version))?;

    let kms_token = crate::bindings::wasi::config::store::get("kms_token".to_string())
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let transit_key_name = crate::bindings::wasi::config::store::get("kms_key_name".to_string())
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "lattice-id-master".to_string());
    let decrypt_url = format!("{kms_endpoint}/v1/transit/decrypt/{transit_key_name}");

    let ciphertext_b64 = B64.encode(&wrapped);
    let req_payload = serde_json::json!({
        "_http": true,
        "method": "POST",
        "url": decrypt_url,
        "headers": {
            "X-Vault-Token": kms_token,
            "Content-Type": "application/json"
        },
        "body": serde_json::json!({ "ciphertext": format!("vault:v1:{ciphertext_b64}") }).to_string()
    });

    let resp = crate::store::ldb_request("kms.request", &req_payload)
        .await
        .map_err(VaultError::KmsUnavailable)?;

    let plaintext_b64 = resp
        .pointer("/data/plaintext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultError::KmsUnavailable("missing plaintext in KMS response".into()))?;

    let key_bytes = B64
        .decode(plaintext_b64)
        .map_err(|e| VaultError::KmsUnavailable(format!("base64 decode key: {e}")))?;

    key_bytes
        .try_into()
        .map_err(|_| VaultError::KmsUnavailable("KMS returned wrong key length".into()))
}

async fn ensure_initialized() -> Result<(), VaultError> {
    if INITIALIZED.with(|i| *i.borrow()) {
        return Ok(());
    }

    let table = vault_table();
    let version: u32 = match crate::store::kv_get_raw(&table, "current_version").await {
        Ok(Some(bytes)) => {
            let s = String::from_utf8(bytes).map_err(|e| VaultError::Internal(e.to_string()))?;
            s.trim().parse().unwrap_or(0)
        }
        Ok(None) => {
            crate::store::kv_set_raw(&table, "current_version", b"0")
                .await
                .map_err(VaultError::Internal)?;
            0
        }
        Err(e) => return Err(VaultError::KmsUnavailable(e)),
    };

    let master = load_master_key(version).await?;
    MASTER_KEYS.with(|mk| mk.borrow_mut().push((version, master)));
    CURRENT_VERSION.with(|v| *v.borrow_mut() = version);
    INITIALIZED.with(|i| *i.borrow_mut() = true);
    Ok(())
}

async fn get_master_key(version: u32) -> Result<[u8; 32], VaultError> {
    let cached = MASTER_KEYS.with(|mk| {
        mk.borrow()
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, k)| *k)
    });
    if let Some(key) = cached {
        return Ok(key);
    }
    let master = load_master_key(version).await?;
    MASTER_KEYS.with(|mk| mk.borrow_mut().push((version, master)));
    Ok(master)
}

// ── DEK derivation ───────────────────────────────────────────────────────────

fn derive_dek(master: &[u8; 32], context: &str, version: u32) -> [u8; 32] {
    let salt = format!("lattice-id-vault-dek-v{version}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master);
    let mut dek = [0u8; 32];
    hk.expand(context.as_bytes(), &mut dek)
        .expect("hkdf expand");
    dek
}

// ── Envelope encode / decode ─────────────────────────────────────────────────

fn encode_envelope(version: u32, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ciphertext.len());
    out.push(version as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

fn decode_envelope(envelope: &[u8]) -> Result<(u32, [u8; 12], &[u8]), VaultError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(VaultError::InvalidCiphertext(format!(
            "envelope too short: {} bytes",
            envelope.len()
        )));
    }
    let version = envelope[0] as u32;
    let nonce_bytes: [u8; 12] = envelope[1..13].try_into().unwrap();
    let ct = &envelope[13..];
    Ok((version, nonce_bytes, ct))
}

// ── Public API ───────────────────────────────────────────────────────────────

pub async fn encrypt(context: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    ensure_initialized().await?;

    let version = CURRENT_VERSION.with(|v| *v.borrow());
    let master = get_master_key(version).await?;
    let dek = derive_dek(&master, context, version);

    let mut nonce_arr = [0u8; 12];
    getrandom::getrandom(&mut nonce_arr)
        .map_err(|e| VaultError::Internal(format!("random nonce: {e}")))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let payload = Payload {
        msg: plaintext,
        aad: context.as_bytes(),
    };
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_arr), payload)
        .map_err(|e| VaultError::Internal(format!("AES-GCM encrypt: {e}")))?;
    Ok(encode_envelope(version, &nonce_arr, &ct))
}

pub async fn decrypt(context: &str, ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
    ensure_initialized().await?;

    let (version, nonce_bytes, ct) = decode_envelope(ciphertext)?;
    let master = get_master_key(version).await?;
    let dek = derive_dek(&master, context, version);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let payload = Payload {
        msg: ct,
        aad: context.as_bytes(),
    };
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| VaultError::AadMismatch)
}

pub fn current_version() -> u32 {
    CURRENT_VERSION.with(|v| *v.borrow())
}

#[allow(dead_code)]
pub async fn rotate_master() -> Result<u32, VaultError> {
    ensure_initialized().await?;

    let old_version = CURRENT_VERSION.with(|v| *v.borrow());
    let new_version = old_version + 1;
    let table = vault_table();

    let kms_endpoint = crate::bindings::wasi::config::store::get("kms_endpoint".to_string())
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    if !kms_endpoint.is_empty() {
        let mut new_key = [0u8; 32];
        getrandom::getrandom(&mut new_key)
            .map_err(|e| VaultError::Internal(format!("random: {e}")))?;

        let kms_token = crate::bindings::wasi::config::store::get("kms_token".to_string())
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let transit_key_name =
            crate::bindings::wasi::config::store::get("kms_key_name".to_string())
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "lattice-id-master".to_string());
        let encrypt_url = format!("{kms_endpoint}/v1/transit/encrypt/{transit_key_name}");

        let new_key_b64 = B64.encode(new_key);
        let req_payload = serde_json::json!({
            "_http": true,
            "method": "POST",
            "url": encrypt_url,
            "headers": {
                "X-Vault-Token": kms_token,
                "Content-Type": "application/json"
            },
            "body": serde_json::json!({ "plaintext": new_key_b64 }).to_string()
        });

        let resp = crate::store::ldb_request("kms.request", &req_payload)
            .await
            .map_err(VaultError::KmsUnavailable)?;

        let wrapped_b64 = resp
            .pointer("/data/ciphertext")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::KmsUnavailable("missing ciphertext in KMS wrap response".into())
            })?;

        let raw_b64 = wrapped_b64.trim_start_matches("vault:v1:");
        let wrapped_bytes = B64
            .decode(raw_b64)
            .map_err(|e| VaultError::KmsUnavailable(format!("base64 decode wrapped: {e}")))?;

        let key_name = format!("{MASTER_KEY_PREFIX}:{new_version}");
        crate::store::kv_set_raw(&table, &key_name, &wrapped_bytes)
            .await
            .map_err(VaultError::Internal)?;

        MASTER_KEYS.with(|mk| mk.borrow_mut().push((new_version, new_key)));
    }

    crate::store::kv_set_raw(
        &table,
        "current_version",
        new_version.to_string().as_bytes(),
    )
    .await
    .map_err(VaultError::Internal)?;

    CURRENT_VERSION.with(|v| *v.borrow_mut() = new_version);
    Ok(new_version)
}
