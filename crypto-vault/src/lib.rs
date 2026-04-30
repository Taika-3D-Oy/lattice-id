/// crypto-vault — Envelope encryption component for Lattice-ID.
///
/// # Design
///
/// Key hierarchy:
///
///   KMS root key (Vault Transit or dev seed)
///     └─ Master Key[version]  (32 bytes, fetched from KMS on startup)
///          └─ DEK = HKDF-SHA256(master, salt=context, info=version)
///               └─ AES-256-GCM(DEK, nonce, plaintext, aad=context)
///
/// Envelope format stored in KV:
///   [version: u8][nonce: 12 bytes][ciphertext + 16-byte GCM tag]
///
/// "context" is used as AEAD Associated Data (AAD) and as the HKDF info
/// string.  It must be the same at encrypt and decrypt time.
/// Convention: "{bucket}:{key-prefix}"  e.g.  "lid-users:user"
///
/// # Key storage
///
/// The wrapped (KMS-encrypted) master key for each version is stored in the
/// `{kv_prefix}-vault` KV bucket under key `master:{version}`.
///
/// In development mode (`kms_endpoint` empty) the master key is derived
/// directly from `kms_dev_seed` config — **never use in production**.
///
/// # Rotation
///
/// Calling `rotate_master()` generates a new 32-byte master key, wraps it
/// via KMS, stores it, and bumps the active version.  Existing records remain
/// decryptable because we keep all historical master keys accessible.
///
/// # getrandom WASM custom handler
///
/// WASM has no OS random source.  We provide a custom handler that calls the
/// WASI `wasi:random/random` API via the `getrandom` crate's `custom` feature.
mod bindings {
    wit_bindgen::generate!({
        world: "crypto-vault",
        path: "wit",
        async: [
            "import:wasi:sockets/types@0.3.0-rc-2026-03-15#[method]tcp-socket.connect",
            "export:taika3d:lid/vault#encrypt",
            "export:taika3d:lid/vault#decrypt",
            "export:taika3d:lid/vault#rotate-master",
        ],
        generate_all,
    });
}

use bindings::exports::taika3d::lid::vault::{Guest, VaultError};
use bindings::wasi::config::store as config_store;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hkdf::Hkdf;
use sha2::Sha256;

use std::cell::RefCell;

// ── Constants ────────────────────────────────────────────────

/// Size of the version prefix byte in the envelope.
const VERSION_LEN: usize = 1;
/// Size of the AES-GCM nonce.
const NONCE_LEN: usize = 12;
/// Minimum valid envelope length: version + nonce + at minimum 1 byte + 16-byte GCM tag.
const MIN_ENVELOPE_LEN: usize = VERSION_LEN + NONCE_LEN + 17;
/// Key name prefix used in the vault KV bucket.
const MASTER_KEY_PREFIX: &str = "master";

// ── Thread-local state ───────────────────────────────────────

// In-memory cache of unwrapped master keys indexed by version.
// WASM component instances are fresh per request so this cache lives only
// for the duration of a single request, acting as a warm-start optimisation
// when multiple encryptions happen in the same invocation.
thread_local! {
    static MASTER_KEYS: RefCell<Vec<(u32, [u8; 32])>> = const { RefCell::new(Vec::new()) };
    static CURRENT_VERSION: RefCell<u32> = const { RefCell::new(0) };
    static INITIALIZED: RefCell<bool> = const { RefCell::new(false) };
}

// ── KV helpers (same NATS messaging pattern as key-manager) ──

fn vault_table() -> String {
    "vault".to_string()
}

use std::collections::HashMap;

thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

/// Send a JSON request to lattice-db via localhost TCP.
async fn ldb_request(op: &str, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    use crate::bindings::wasi::sockets::types::{
        IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, TcpSocket,
    };
    use wit_bindgen::StreamResult;

    const LDB_TCP_PORT: u16 = 4080;

    let mut payload = payload.clone();
    payload
        .as_object_mut()
        .unwrap()
        .insert("_op".to_string(), serde_json::Value::String(op.to_string()));

    if let Some(table) = payload.get("table").and_then(|t| t.as_str()) {
        let min_rev = SESSION_REVISIONS.with(|sr| sr.borrow().get(table).copied());
        if let Some(rev) = min_rev {
            payload.as_object_mut().unwrap().insert(
                "consistency".to_string(),
                serde_json::json!({ "min_revision": rev }),
            );
        }
    }

    let body = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;

    let socket =
        TcpSocket::create(IpAddressFamily::Ipv4).map_err(|e| format!("tcp create: {e:?}"))?;
    let addr = IpSocketAddress::Ipv4(Ipv4SocketAddress {
        port: LDB_TCP_PORT,
        address: (127, 0, 0, 1),
    });
    socket
        .connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e:?}"))?;

    let (mut rx, _rx_done) = socket.receive();
    let (mut tx, tx_rx) = crate::bindings::wit_stream::new::<u8>();
    let _send_fut = socket.send(tx_rx);

    let len_bytes = (body.len() as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len_bytes);
    frame.extend_from_slice(&body);
    let remaining = tx.write_all(frame).await;
    if !remaining.is_empty() {
        return Err("tcp send failed".into());
    }
    drop(tx);

    let mut buf = Vec::new();
    while buf.len() < 4 {
        let read_buf = Vec::with_capacity(4096);
        let (status, data) = rx.read(read_buf).await;
        match status {
            StreamResult::Complete(n) => buf.extend_from_slice(&data[..n]),
            _ => return Err("tcp read failed (length)".into()),
        }
    }
    let resp_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    buf.drain(..4);

    while buf.len() < resp_len {
        let read_buf = Vec::with_capacity(4096);
        let (status, data) = rx.read(read_buf).await;
        match status {
            StreamResult::Complete(n) => buf.extend_from_slice(&data[..n]),
            _ => return Err("tcp read failed (body)".into()),
        }
    }

    let val: serde_json::Value =
        serde_json::from_slice(&buf[..resp_len]).map_err(|e| format!("parse response: {e}"))?;

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

/// Read raw bytes from a KV bucket (returns None when the key doesn't exist).
async fn kv_get_raw(table: &str, key: &str) -> Result<Option<Vec<u8>>, String> {
    let payload = serde_json::json!({ "table": table, "key": key });
    match ldb_request("get", &payload).await {
        Ok(resp) => {
            let b64 = resp
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or("missing value")?;
            let bytes = B64.decode(b64).map_err(|e| format!("base64: {e}"))?;
            Ok(Some(bytes))
        }
        Err(e) if e.contains("not found") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write raw bytes to a KV bucket (no TTL).
async fn kv_set_raw(table: &str, key: &str, value: &[u8]) -> Result<(), String> {
    let encoded = B64.encode(value);
    let payload = serde_json::json!({ "table": table, "key": key, "value": encoded });
    ldb_request("put", &payload).await?;
    Ok(())
}

// ── KMS / master key management ──────────────────────────────

/// Dev-mode master key derivation: HKDF from a plaintext seed string.
/// ONLY used when `kms_endpoint` is not configured.
fn dev_master_from_seed(seed: &str, version: u32) -> [u8; 32] {
    let salt = format!("lattice-id-dev-vault-v{version}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), seed.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"master-key", &mut key).expect("hkdf expand");
    key
}

/// Load the master key for `version`.
/// - Dev mode (no kms_endpoint): derive from seed.
/// - Production: fetch wrapped key from KV, unwrap via Vault Transit HTTP API.
async fn load_master_key(version: u32) -> Result<[u8; 32], VaultError> {
    let kms_endpoint = config_store::get("kms_endpoint")
        .ok()
        .flatten()
        .unwrap_or_default();

    if kms_endpoint.is_empty() {
        // ── Dev mode ─────────────────────────────────────────
        let seed = config_store::get("kms_dev_seed")
            .ok()
            .flatten()
            .unwrap_or_else(|| "lattice-id-insecure-dev-seed-change-in-prod".to_string());
        return Ok(dev_master_from_seed(&seed, version));
    }

    // ── Production: Vault Transit ─────────────────────────────
    // The wrapped master key is stored in the vault KV bucket.
    let table = vault_table();
    let key_name = format!("{MASTER_KEY_PREFIX}:{version}");

    let wrapped = kv_get_raw(&table, &key_name)
        .await
        .map_err(VaultError::KmsUnavailable)?
        .ok_or(VaultError::VersionNotFound(version))?;

    // POST {kms_endpoint}/v1/transit/decrypt/lattice-id-master
    // Body: {"ciphertext": "vault:v1:<base64>"}
    // Response: {"data": {"plaintext": "<base64 of 32 bytes>"}}
    let kms_token = config_store::get("kms_token")
        .ok()
        .flatten()
        .unwrap_or_default();
    let transit_key_name = config_store::get("kms_key_name")
        .ok()
        .flatten()
        .unwrap_or_else(|| "lattice-id-master".to_string());
    let decrypt_url = format!("{kms_endpoint}/v1/transit/decrypt/{transit_key_name}");

    // We send the Vault Transit request through wasmcloud:messaging by
    // publishing to a NATS subject that an http-client bridge handles.
    // In the default deployment this is the wasi:http/outgoing-handler,
    // but to keep WIT surface minimal we use a simple JSON envelope over
    // wasmcloud:messaging.  A future version can import wasi:http directly.
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

    let resp = ldb_request("kms.request", &req_payload)
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

/// Ensure the in-memory cache is populated, loading from KMS if needed.
async fn ensure_initialized() -> Result<(), VaultError> {
    let already_init = INITIALIZED.with(|i| *i.borrow());
    if already_init {
        return Ok(());
    }

    // Load current version number from KV.
    let table = vault_table();
    let version: u32 = match kv_get_raw(&table, "current_version").await {
        Ok(Some(bytes)) => {
            let s = String::from_utf8(bytes).map_err(|e| VaultError::Internal(e.to_string()))?;
            s.trim().parse().unwrap_or(0)
        }
        Ok(None) => {
            // First boot — initialize version 0 and store it.
            kv_set_raw(&table, "current_version", b"0")
                .await
                .map_err(VaultError::Internal)?;
            0
        }
        Err(e) => return Err(VaultError::KmsUnavailable(e)),
    };

    // Load the master key for the current version.
    let master = load_master_key(version).await?;

    MASTER_KEYS.with(|mk| mk.borrow_mut().push((version, master)));
    CURRENT_VERSION.with(|v| *v.borrow_mut() = version);
    INITIALIZED.with(|i| *i.borrow_mut() = true);

    Ok(())
}

/// Retrieve a cached master key, loading it from KMS if not yet in memory.
async fn get_master_key(version: u32) -> Result<[u8; 32], VaultError> {
    // Check cache first.
    let cached = MASTER_KEYS.with(|mk| {
        mk.borrow()
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, k)| *k)
    });
    if let Some(key) = cached {
        return Ok(key);
    }
    // Not in cache — load from KMS.
    let master = load_master_key(version).await?;
    MASTER_KEYS.with(|mk| mk.borrow_mut().push((version, master)));
    Ok(master)
}

// ── DEK derivation ────────────────────────────────────────────

/// Derive a 32-byte Data Encryption Key from `master` using HKDF-SHA256.
/// `context` is the HKDF info string (= AAD for GCM); `version` is mixed
/// into the salt so rotating the master also rotates all DEKs.
fn derive_dek(master: &[u8; 32], context: &str, version: u32) -> [u8; 32] {
    let salt = format!("lattice-id-vault-dek-v{version}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), master);
    let mut dek = [0u8; 32];
    hk.expand(context.as_bytes(), &mut dek)
        .expect("hkdf expand");
    dek
}

// ── Envelope encode / decode ─────────────────────────────────

/// Build the binary envelope: [version: u8][nonce: 12][ct + tag: rest].
fn encode_envelope(version: u32, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ciphertext.len());
    out.push(version as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Parse the binary envelope. Returns `(version, nonce, ciphertext_with_tag)`.
fn decode_envelope(envelope: &[u8]) -> Result<(u32, [u8; 12], &[u8]), VaultError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(VaultError::InvalidCiphertext(format!(
            "envelope too short: {} bytes (minimum {MIN_ENVELOPE_LEN})",
            envelope.len()
        )));
    }
    let version = envelope[0] as u32;
    let nonce_bytes: [u8; 12] = envelope[1..13].try_into().unwrap();
    let ct = &envelope[13..];
    Ok((version, nonce_bytes, ct))
}

// ── Component implementation ─────────────────────────────────

struct CryptoVault;

impl Guest for CryptoVault {
    async fn encrypt(context: String, plaintext: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        ensure_initialized().await?;

        let version = CURRENT_VERSION.with(|v| *v.borrow());
        let master = get_master_key(version).await?;
        let dek = derive_dek(&master, &context, version);

        let mut nonce_arr = [0u8; 12];
        getrandom::getrandom(&mut nonce_arr)
            .map_err(|e| VaultError::Internal(format!("random nonce: {e}")))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        let payload = Payload {
            msg: &plaintext,
            aad: context.as_bytes(),
        };
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_arr), payload)
            .map_err(|e| VaultError::Internal(format!("AES-GCM encrypt: {e}")))?;
        Ok(encode_envelope(version, &nonce_arr, &ct))
    }

    async fn decrypt(context: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, VaultError> {
        ensure_initialized().await?;

        let (version, nonce_bytes, ct) = decode_envelope(&ciphertext)?;
        let master = get_master_key(version).await?;
        let dek = derive_dek(&master, &context, version);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
        let payload = Payload {
            msg: ct,
            aad: context.as_bytes(),
        };
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| VaultError::AadMismatch) // GCM tag failure = wrong AAD or tampered
    }

    fn current_version() -> u32 {
        CURRENT_VERSION.with(|v| *v.borrow())
    }

    async fn rotate_master() -> Result<u32, VaultError> {
        ensure_initialized().await?;

        let old_version = CURRENT_VERSION.with(|v| *v.borrow());
        let new_version = old_version + 1;
        let table = vault_table();

        let kms_endpoint = config_store::get("kms_endpoint")
            .ok()
            .flatten()
            .unwrap_or_default();

        if kms_endpoint.is_empty() {
            // Dev mode: no actual KMS — just bump the version counter.
            // The dev_master_from_seed() function will derive a new key
            // automatically for the new version.
        } else {
            // Production: generate a new 32-byte key and wrap it via KMS.
            let mut new_key = [0u8; 32];
            getrandom::getrandom(&mut new_key)
                .map_err(|e| VaultError::Internal(format!("random: {e}")))?;

            let kms_token = config_store::get("kms_token")
                .ok()
                .flatten()
                .unwrap_or_default();
            let transit_key_name = config_store::get("kms_key_name")
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

            let resp = ldb_request("kms.request", &req_payload)
                .await
                .map_err(VaultError::KmsUnavailable)?;

            let wrapped_b64 = resp
                .pointer("/data/ciphertext")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    VaultError::KmsUnavailable("missing ciphertext in KMS wrap response".into())
                })?;

            // Strip "vault:v1:" prefix that Vault Transit adds.
            let raw_b64 = wrapped_b64.trim_start_matches("vault:v1:");
            let wrapped_bytes = B64
                .decode(raw_b64)
                .map_err(|e| VaultError::KmsUnavailable(format!("base64 decode wrapped: {e}")))?;

            let key_name = format!("{MASTER_KEY_PREFIX}:{new_version}");
            kv_set_raw(&table, &key_name, &wrapped_bytes)
                .await
                .map_err(VaultError::Internal)?;

            // Cache the new unwrapped key immediately.
            MASTER_KEYS.with(|mk| mk.borrow_mut().push((new_version, new_key)));
        }

        // Persist the new current version.
        kv_set_raw(
            &table,
            "current_version",
            new_version.to_string().as_bytes(),
        )
        .await
        .map_err(VaultError::Internal)?;

        CURRENT_VERSION.with(|v| *v.borrow_mut() = new_version);

        Ok(new_version)
    }
}

bindings::export!(CryptoVault with_types_in bindings);
