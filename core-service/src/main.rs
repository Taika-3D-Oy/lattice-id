mod bindings {
    wit_bindgen::generate!({
        world: "service",
        path: "wit",
        generate_all,
    });
}

// JWT verification is handled by oidc-gateway; this module is kept for reference.
// mod jwt;

mod logger;
mod metrics;

mod store;

use metrics::Metrics;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

trait ReadExt: wstd::io::AsyncRead + Unpin {
    async fn read_exact(&mut self, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            let n = wstd::io::AsyncRead::read(self, buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            let (_, rest) = std::mem::take(&mut buf).split_at_mut(n);
            buf = rest;
        }
        Ok(())
    }
}
impl<T: wstd::io::AsyncRead + Unpin> ReadExt for T {}

trait WriteExt: wstd::io::AsyncWrite + Unpin {
    async fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            let n = wstd::io::AsyncWrite::write(self, buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            buf = &buf[n..];
        }
        Ok(())
    }
}
impl<T: wstd::io::AsyncWrite + Unpin> WriteExt for T {}
use wstd::iter::AsyncIterator;
use wstd::net::TcpListener;

struct ServiceState {
    metrics: Metrics,
}

impl ServiceState {
    fn new() -> Result<Self, String> {
        Ok(Self {
            metrics: Metrics::new(),
        })
    }
}

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(flatten)]
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

#[wstd::main]
async fn main() -> std::io::Result<()> {
    let state = Arc::new(Mutex::new(ServiceState::new().map_err(|e| std::io::Error::other(e))?));
    
    logger::info(
        "server.listening",
        None,
        serde_json::json!({ "address": "127.0.0.1:7899" }),
    );
    let listener = TcpListener::bind("127.0.0.1:7899").await?;
    let mut incoming = listener.incoming();

    // Background tasks: CAS-guarded GC (10 min) + config sync (5 min).
    // Only one instance across all replicas wins each CAS claim per interval.
    wstd::runtime::spawn(async {
        use wstd::iter::AsyncIterator;
        let mut tick = wstd::time::interval(wstd::time::Duration::from_secs(60));
        loop {
            tick.next().await;
            if store::try_claim_task("gc", 600) {
                logger::info("task.gc.claimed", None, serde_json::json!({}));
                store::gc_expired_entries();
            }
            if store::try_claim_task("config_sync", 300) {
                logger::info("task.config_sync.claimed", None, serde_json::json!({}));
                store::sync_remote_config().await;
            }
        }
    })
    .detach();

    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        let state = state.clone();
        wstd::runtime::spawn(async move {
            if let Err(e) = handle_connection(stream, &state).await {
                logger::error_message("tcp.connection_failed", None, e);
            }
        })
        .detach();
    }
    Ok(())
}

async fn handle_connection(
    mut stream: wstd::net::TcpStream,
    state: &Mutex<ServiceState>,
) -> std::io::Result<()> {
    // Auth
    if let Some(auth_key) = store::core_service_auth_key() {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;

        let mut nonce = [0u8; 16];
        store::fill_random(&mut nonce);
        stream.write_all(&nonce).await?;

        let mut response = [0u8; 32];
        stream.read_exact(&mut response).await?;

        let mut hasher = Sha256::new();
        hasher.update(&nonce);
        hasher.update(auth_key.as_bytes());
        let expected = hasher.finalize();

        let is_ok: bool = response.ct_eq(&expected).into();
        if !is_ok {
            return Err(std::io::Error::other("Handshake failed"));
        }
    }

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(std::io::Error::other("Request too large"));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let response = dispatch(&buf, state);

    let resp_bytes = serde_json::to_vec(&response).unwrap_or_default();
    let resp_len = (resp_bytes.len() as u32).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(&resp_bytes).await?;

    Ok(())
}

fn dispatch(data: &[u8], state: &Mutex<ServiceState>) -> Response {
    let started_at = Instant::now();
    let req: Request = match serde_json::from_slice(data) {
        Ok(r) => r,
        Err(e) => {
            logger::warn(
                "core.request.parse_failed",
                None,
                serde_json::json!({ "error": e.to_string() }),
            );
            return Response::err(format!("parse error: {e}"));
        }
    };
    let trace_id = req.trace_id.as_deref();
    let op = req.op.clone();

    logger::info(
        "core.request.started",
        trace_id,
        serde_json::json!({ "op": op }),
    );

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(e) => return Response::err(format!("state lock failed: {e}")),
    };

    let response = match req.op.as_str() {
        "health_status" => Response::success(serde_json::json!({
            "status": "ok",
            "keys_loaded": true,
            "current_kid": "dev",
            "current_key_age_secs": 0,
            "rate_limiter_size": 0,
        })),

        "metric_increment" => {
            let name = req.payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let labels: Vec<(&str, &str)> = req
                .payload
                .get("labels")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or("")))
                        .collect()
                })
                .unwrap_or_default();
            st.metrics.increment_counter(name, &labels);
            Response::success(serde_json::json!({}))
        }

        "metrics_render" => Response::success(serde_json::json!({
            "text": st.metrics.render_prometheus(),
        })),

        _ => Response::err(format!("unknown op: {}", req.op)),
    };

    let duration_ms = started_at.elapsed().as_millis() as u64;
    st.metrics.observe_core_request(&op, duration_ms, response.ok);

    logger::info(
        "core.request.completed",
        trace_id,
        serde_json::json!({
            "op": op,
            "ok": response.ok,
            "duration_ms": duration_ms,
            "error": response.error,
        }),
    );

    response
}
