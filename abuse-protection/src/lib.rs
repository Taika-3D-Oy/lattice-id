#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "abuse-protection",
        path: "wit",
        async: [
            "import:wasi:sockets/types@0.3.0-rc-2026-03-15#[method]tcp-socket.connect",
            "export:taika3d:lid/abuse#check-rate",
            "export:taika3d:lid/abuse#record-metric",
        ],
        generate_all,
    });
}

use base64::Engine;
use bindings::exports::taika3d::lid::abuse::Guest;

struct AbuseProtection;

fn rate_limits_table() -> String {
    "abuse-rate-limits".to_string()
}

use std::cell::RefCell;
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

impl Guest for AbuseProtection {
    async fn check_rate(key: String, limit: u64, window_secs: u64) -> Result<(bool, u64), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();

        // Bucket key: rate:{key}:{window_start}
        // Each window is a counter stored in lattice-db with TTL.
        let window_start = now - (now % window_secs);
        let db_key = format!("rate:{}:{}", key, window_start);
        let table = rate_limits_table();

        // Retry loop to ensure the increment is actually recorded
        const MAX_RETRIES: usize = 5;
        for _attempt in 0..MAX_RETRIES {
            // Read current counter with revision
            let payload = serde_json::json!({ "table": table, "key": db_key });
            let (count, revision) = match ldb_request("get", &payload).await {
                Ok(resp) => {
                    let value_b64 = resp.get("value").and_then(|v| v.as_str()).unwrap_or("MA==");
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(value_b64)
                        .unwrap_or_default();
                    let count_str = String::from_utf8_lossy(&bytes);
                    let count: u64 = count_str.trim().parse().unwrap_or(0);
                    let revision = resp.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
                    (count, revision)
                }
                Err(e) if e.contains("not found") => (0u64, 0u64),
                Err(e) => return Err(format!("rate limit get: {e}")),
            };

            if count >= limit {
                return Ok((false, 0));
            }

            // Increment counter via CAS (or create if first hit)
            let new_count = (count + 1).to_string();
            let new_value = base64::engine::general_purpose::STANDARD.encode(new_count.as_bytes());

            if revision == 0 {
                // First hit in this window — atomic create with TTL
                let payload = serde_json::json!({
                    "table": table,
                    "key": db_key,
                    "value": new_value,
                    "ttl_seconds": window_secs + 10,
                });
                match ldb_request("create", &payload).await {
                    Ok(_) => return Ok((true, limit - count - 1)),
                    Err(e) if e.contains("already exists") => {
                        continue; // retry — re-read the real count and CAS
                    }
                    Err(e) => return Err(format!("rate limit create: {e}")),
                }
            } else {
                // Existing counter — CAS update
                let payload = serde_json::json!({
                    "table": table,
                    "key": db_key,
                    "value": new_value,
                    "revision": revision,
                });
                match ldb_request("cas", &payload).await {
                    Ok(_) => return Ok((true, limit - count - 1)),
                    Err(e) if e.contains("revision mismatch") => {
                        continue; // retry with fresh revision
                    }
                    Err(e) => return Err(format!("rate limit cas: {e}")),
                }
            }
        }

        // If all retries exhausted, allow the request but don't increment
        // (fail-open to avoid blocking legitimate traffic)
        Ok((true, 0))
    }

    async fn record_metric(_name: String, _labels: Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
}

bindings::export!(AbuseProtection with_types_in bindings);
