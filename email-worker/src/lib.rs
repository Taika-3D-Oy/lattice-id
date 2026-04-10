wit_bindgen::generate!({
    path: "wit",
    world: "worker",
    generate_all,
});

#[allow(unused)]
use wstd::prelude::*;

struct Component;
export!(Component);

/// Email event — reconstructed from the WIT parameters.
struct EmailEvent {
    event_type: String,
    to: String,
    name: String,
    action_url: String,
    metadata: serde_json::Value,
}

/// Read a config value from wasi:config/store, returning empty string on miss.
fn cfg(key: &str) -> String {
    wasi::config::store::get(key)
        .ok()
        .flatten()
        .unwrap_or_default()
}

impl exports::lattice_id::notify::email::Guest for Component {
    fn send(
        event_type: String,
        to: String,
        name: String,
        action_url: String,
        metadata: String,
    ) -> Result<(), String> {
        eprintln!(
            "email-worker: received event={} to={} url={}",
            event_type, to, action_url
        );

        let metadata_val: serde_json::Value = serde_json::from_str(&metadata)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let event = EmailEvent {
            event_type,
            to,
            name,
            action_url,
            metadata: metadata_val,
        };

        let provider = cfg("email_provider");

        match provider.as_str() {
            "log" | "" => deliver_log(&event),
            "http" => deliver_http(&event),
            "ses" => deliver_ses(&event),
            other => Err(format!("unknown email_provider: {other}")),
        }
    }
}

// ── Log provider (default / dev) ────────────────────────────────────────

/// Just logs the email — useful for development and integration tests.
fn deliver_log(event: &EmailEvent) -> Result<(), String> {
    eprintln!(
        "email-worker [LOG]: type={} to={} name={} url={}",
        event.event_type, event.to, event.name, event.action_url
    );

    // If there's a reply_to, respond with a simple ack so request() callers
    // don't time out.  For publish()-based fire-and-forget the runtime
    // ignores this.
    Ok(())
}

// ── HTTP provider (production) ──────────────────────────────────────────

/// Sends email via an external HTTP API (SES, SendGrid, Mailgun, etc.).
///
/// Configuration via wasi:config/store:
///   email_http_url     — full endpoint URL (e.g. https://api.sendgrid.com/v3/mail/send)
///   email_http_api_key — Bearer token or API key
///   email_from         — sender address (e.g. noreply@example.com)
fn deliver_http(event: &EmailEvent) -> Result<(), String> {
    let url = cfg("email_http_url");
    let api_key = cfg("email_http_api_key");
    let from = cfg("email_from");

    if url.is_empty() || api_key.is_empty() {
        return Err("email_http_url and email_http_api_key must be configured".into());
    }

    let subject = match event.event_type.as_str() {
        "verify_email" => "Verify your email address",
        "password_reset" => "Reset your password",
        "invitation" => "You've been invited",
        _ => "Notification",
    };

    // Build a simple JSON payload compatible with SendGrid v3 API.
    // For other providers, adjust the payload format via config or
    // add provider-specific branches.
    let payload = serde_json::json!({
        "personalizations": [{
            "to": [{ "email": event.to, "name": event.name }],
            "dynamic_template_data": {
                "action_url": event.action_url,
                "event_type": event.event_type,
                "metadata": event.metadata,
            }
        }],
        "from": { "email": from },
        "subject": subject,
        "content": [{
            "type": "text/plain",
            "value": format!(
                "Hello{},\n\n{}\n\nLink: {}\n",
                if event.name.is_empty() { String::new() } else { format!(" {}", event.name) },
                match event.event_type.as_str() {
                    "verify_email" => "Please verify your email address by clicking the link below.",
                    "password_reset" => "A password reset was requested for your account.",
                    "invitation" => "You've been invited to join a team.",
                    _ => "You have a new notification.",
                },
                event.action_url,
            ),
        }],
    });

    let body_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize email payload: {e}"))?;

    // Use wasi:http/outgoing-handler to POST to the email API
    use wasi::http::outgoing_handler;
    use wasi::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme};

    let headers = Fields::new();
    let _ = headers.set(
        "content-type",
        &[b"application/json".to_vec()],
    );
    let _ = headers.set(
        "authorization",
        &[format!("Bearer {api_key}").into_bytes()],
    );

    let request = OutgoingRequest::new(headers);
    request.set_method(&Method::Post).map_err(|_| "set method")?;
    request.set_scheme(Some(&Scheme::Https)).map_err(|_| "set scheme")?;

    // Parse URL into authority + path
    let url_no_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);
    let (authority, path) = match url_no_scheme.find('/') {
        Some(i) => (&url_no_scheme[..i], &url_no_scheme[i..]),
        None => (url_no_scheme, "/"),
    };
    request
        .set_authority(Some(authority))
        .map_err(|_| "set authority")?;
    request
        .set_path_with_query(Some(path))
        .map_err(|_| "set path")?;

    let body_handle = request.body().map_err(|_| "get body handle")?;
    {
        let stream = body_handle.write().map_err(|_| "get body stream")?;
        stream
            .blocking_write_and_flush(&body_bytes)
            .map_err(|e| format!("write body: {e:?}"))?;
        drop(stream);
    }
    OutgoingBody::finish(body_handle, None).map_err(|_| "finish body")?;

    let future_resp = outgoing_handler::handle(request, None)
        .map_err(|e| format!("outgoing request failed: {e:?}"))?;

    // Block on the response
    let incoming = future_resp
        .get()
        .ok_or("response future not ready")?
        .map_err(|_| "response future error")?
        .map_err(|e| format!("HTTP error: {e:?}"))?;

    let status = incoming.status();
    // Consume and drop the body so the response resources are freed
    let resp_body = incoming.consume().map_err(|_| "consume response body")?;
    let resp_stream = resp_body.stream().map_err(|_| "response body stream")?;
    let mut resp_bytes = Vec::new();
    loop {
        match resp_stream.read(4096) {
            Ok(chunk) => resp_bytes.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    drop(resp_stream);

    if status >= 200 && status < 300 {
        eprintln!(
            "email-worker: sent {} to {} (HTTP {})",
            event.event_type, event.to, status
        );
        Ok(())
    } else {
        let body_str = String::from_utf8_lossy(&resp_bytes);
        Err(format!(
            "email API returned HTTP {}: {}",
            status,
            &body_str[..body_str.len().min(500)]
        ))
    }
}

// ── SES provider (AWS SES v2 with SigV4 signing) ───────────────────────

/// Sends email via AWS SES v2 `SendEmail` API.
///
/// Configuration via wasi:config/store:
///   email_ses_region            — AWS region (e.g. "eu-north-1")
///   email_ses_access_key_id     — IAM access key ID
///   email_ses_secret_access_key — IAM secret access key
///   email_from                  — sender address (must be SES-verified)
fn deliver_ses(event: &EmailEvent) -> Result<(), String> {
    let region = cfg("email_ses_region");
    let access_key = cfg("email_ses_access_key_id");
    let secret_key = cfg("email_ses_secret_access_key");
    let from = cfg("email_from");

    if region.is_empty() || access_key.is_empty() || secret_key.is_empty() {
        return Err(
            "email_ses_region, email_ses_access_key_id, and email_ses_secret_access_key must be configured"
                .into(),
        );
    }

    let subject = match event.event_type.as_str() {
        "verify_email" => "Verify your email address",
        "password_reset" => "Reset your password",
        "invitation" => "You've been invited",
        _ => "Notification",
    };

    let text_body = format!(
        "Hello{},\n\n{}\n\nLink: {}\n",
        if event.name.is_empty() {
            String::new()
        } else {
            format!(" {}", event.name)
        },
        match event.event_type.as_str() {
            "verify_email" => "Please verify your email address by clicking the link below.",
            "password_reset" => "A password reset was requested for your account.",
            "invitation" => "You've been invited to join a team.",
            _ => "You have a new notification.",
        },
        event.action_url,
    );

    // SES v2 SendEmail payload
    let payload = serde_json::json!({
        "Content": {
            "Simple": {
                "Subject": { "Data": subject, "Charset": "UTF-8" },
                "Body": {
                    "Text": { "Data": text_body, "Charset": "UTF-8" }
                }
            }
        },
        "Destination": {
            "ToAddresses": [event.to]
        },
        "FromEmailAddress": from
    });

    let body_bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize SES payload: {e}"))?;

    let host = format!("email.{region}.amazonaws.com");
    let path = "/v2/email/outbound-emails";

    // Get current UTC time for signing
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock error")?;
    let secs = now.as_secs();
    let (date_stamp, amz_date) = format_sigv4_dates(secs);

    // Build and sign the request
    let signed_headers = sigv4_sign(
        "POST",
        path,
        &host,
        &body_bytes,
        &date_stamp,
        &amz_date,
        &region,
        "ses",
        &access_key,
        &secret_key,
    );

    // Fire HTTP request via wasi:http/outgoing-handler
    use wasi::http::outgoing_handler;
    use wasi::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme};

    let headers = Fields::new();
    for (k, v) in &signed_headers {
        let _ = headers.set(k, &[v.as_bytes().to_vec()]);
    }

    let request = OutgoingRequest::new(headers);
    request.set_method(&Method::Post).map_err(|_| "set method")?;
    request
        .set_scheme(Some(&Scheme::Https))
        .map_err(|_| "set scheme")?;
    request
        .set_authority(Some(&host))
        .map_err(|_| "set authority")?;
    request
        .set_path_with_query(Some(path))
        .map_err(|_| "set path")?;

    let body_handle = request.body().map_err(|_| "get body handle")?;
    {
        let stream = body_handle.write().map_err(|_| "get body stream")?;
        stream
            .blocking_write_and_flush(&body_bytes)
            .map_err(|e| format!("write body: {e:?}"))?;
        drop(stream);
    }
    OutgoingBody::finish(body_handle, None).map_err(|_| "finish body")?;

    let future_resp = outgoing_handler::handle(request, None)
        .map_err(|e| format!("SES request failed: {e:?}"))?;

    let incoming = future_resp
        .get()
        .ok_or("response future not ready")?
        .map_err(|_| "response future error")?
        .map_err(|e| format!("SES HTTP error: {e:?}"))?;

    let status = incoming.status();
    let resp_body = incoming.consume().map_err(|_| "consume response body")?;
    let resp_stream = resp_body.stream().map_err(|_| "response body stream")?;
    let mut resp_bytes = Vec::new();
    loop {
        match resp_stream.read(4096) {
            Ok(chunk) => resp_bytes.extend_from_slice(&chunk),
            Err(_) => break,
        }
    }
    drop(resp_stream);

    if status >= 200 && status < 300 {
        eprintln!(
            "email-worker: SES sent {} to {} (HTTP {})",
            event.event_type, event.to, status
        );
        Ok(())
    } else {
        let body_str = String::from_utf8_lossy(&resp_bytes);
        Err(format!(
            "SES returned HTTP {}: {}",
            status,
            &body_str[..body_str.len().min(500)]
        ))
    }
}

// ── AWS SigV4 signing helpers ───────────────────────────────────────────

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Format seconds-since-epoch into SigV4 date strings.
/// Returns (date_stamp "20260407", amz_date "20260407T120000Z").
fn format_sigv4_dates(epoch_secs: u64) -> (String, String) {
    // Manual UTC date calculation (no chrono needed)
    let secs_per_day: u64 = 86400;
    let days = epoch_secs / secs_per_day;
    let day_secs = epoch_secs % secs_per_day;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);

    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_date = format!("{year:04}{month:02}{day:02}T{hours:02}{minutes:02}{seconds:02}Z");
    (date_stamp, amz_date)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Compute AWS SigV4 signature and return all headers needed for the request.
fn sigv4_sign(
    method: &str,
    path: &str,
    host: &str,
    body: &[u8],
    date_stamp: &str,
    amz_date: &str,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
) -> Vec<(String, String)> {
    let payload_hash = hex_encode(&sha256(body));

    // Canonical request
    let canonical_headers = format!(
        "content-type:application/json\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    // String to sign
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        hex_encode(&sha256(canonical_request.as_bytes()))
    );

    // Signing key
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    vec![
        ("content-type".into(), "application/json".into()),
        ("host".into(), host.into()),
        ("x-amz-date".into(), amz_date.into()),
        ("x-amz-content-sha256".into(), payload_hash),
        ("authorization".into(), authorization),
    ]
}
