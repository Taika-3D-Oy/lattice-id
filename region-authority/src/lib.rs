#[allow(dead_code)]
mod bindings {
    wit_bindgen::generate!({
        world: "region-authority",
        path: "wit",
        async: [
            "import:wasi:sockets/types@0.3.0-rc-2026-03-15#[method]tcp-socket.connect",
            "export:taika3d:lid/authority#lookup",
        ],
        generate_all,
    });
}

use bindings::exports::taika3d::lid::authority::{Guest, LookupResult};

use std::cell::RefCell;
use std::collections::HashMap;

struct RegionAuthority;

thread_local! {
    static SESSION_REVISIONS: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
}

fn user_idx_table() -> String {
    "user-idx".to_string()
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

/// Check lattice-db for the email index entry.
async fn email_exists_in_db(email_hash: &str) -> bool {
    let key = format!("email:{email_hash}");
    let table = user_idx_table();
    let payload = serde_json::json!({
        "table": table,
        "key": key,
    });
    match ldb_request("exists", &payload).await {
        Ok(resp) => resp
            .get("exists")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        Err(_) => false,
    }
}

impl Guest for RegionAuthority {
    async fn lookup(email_hash: String) -> Result<LookupResult, String> {
        if email_exists_in_db(&email_hash).await {
            Ok(LookupResult {
                found: true,
                region: Some("local".to_string()),
            })
        } else {
            Ok(LookupResult {
                found: false,
                region: None,
            })
        }
    }
}

bindings::export!(RegionAuthority with_types_in bindings);
