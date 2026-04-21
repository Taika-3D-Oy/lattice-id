wit_bindgen::generate!({
    path: "wit",
    world: "worker",
    async: [
        "export:lattice-id:notify/email#send",
    ],
    generate_all,
});

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
    async fn send(
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
            "ses" => ses::deliver(&event).await,
            "log" | "" => deliver_log(&event),
            other => Err(format!("unknown email provider: '{other}'")),
        }
    }
}

// ── Log provider (default / dev) ────────────────────────────────────────

fn deliver_log(event: &EmailEvent) -> Result<(), String> {
    eprintln!(
        "email-worker [LOG]: type={} to={} name={} url={}",
        event.event_type, event.to, event.name, event.action_url
    );
    Ok(())
}

// ── HTML email templates ────────────────────────────────────────────────

mod templates {
    use super::EmailEvent;

    pub fn subject(event: &EmailEvent) -> String {
        match event.event_type.as_str() {
            "verify_email" => "Verify your email address".into(),
            "password_reset" => "Reset your password".into(),
            "invitation" => {
                let tenant = event
                    .metadata
                    .get("tenant_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("the platform");
                format!("You've been invited to {tenant}")
            }
            other => format!("Notification: {other}"),
        }
    }

    pub fn html_body(event: &EmailEvent) -> String {
        let name = if event.name.is_empty() {
            "there"
        } else {
            &event.name
        };
        let button_text = match event.event_type.as_str() {
            "verify_email" => "Verify Email",
            "password_reset" => "Reset Password",
            "invitation" => "Accept Invitation",
            _ => "Take Action",
        };
        let message = match event.event_type.as_str() {
            "verify_email" => "Please verify your email address by clicking the button below.",
            "password_reset" => {
                "You requested a password reset. Click below to set a new password."
            }
            "invitation" => "You've been invited to join. Click below to accept.",
            _ => "An action is required.",
        };
        let action_url = html_escape(&event.action_url);

        format!(
            r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
.card {{ max-width: 480px; margin: 40px auto; background: #fff; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
h1 {{ font-size: 20px; color: #333; margin: 0 0 16px; }}
p {{ font-size: 15px; color: #555; line-height: 1.6; }}
.btn {{ display: inline-block; padding: 12px 32px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 24px 0; }}
.footer {{ font-size: 12px; color: #999; margin-top: 32px; }}
</style></head><body>
<div class="card">
  <h1>Hi {name},</h1>
  <p>{message}</p>
  <a class="btn" href="{action_url}">{button_text}</a>
  <p class="footer">If you didn't request this, you can safely ignore this email.<br>
  This link expires in 24 hours.</p>
</div></body></html>"#
        )
    }

    pub fn text_body(event: &EmailEvent) -> String {
        let name = if event.name.is_empty() {
            "there"
        } else {
            &event.name
        };
        format!(
            "Hi {},\n\n{}\n\n{}\n\nIf you didn't request this, you can safely ignore this email.\n",
            name,
            match event.event_type.as_str() {
                "verify_email" => "Please verify your email address by visiting the link below.",
                "password_reset" =>
                    "You requested a password reset. Visit the link below to set a new password.",
                "invitation" => "You've been invited. Visit the link below to accept.",
                _ => "An action is required.",
            },
            event.action_url
        )
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

// ── AWS SES v2 provider ─────────────────────────────────────────────────

mod ses {
    use super::{EmailEvent, cfg, templates};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Deliver an email via SES v2 SendEmail API.
    pub async fn deliver(event: &EmailEvent) -> Result<(), String> {
        let region = cfg("ses_region");
        let access_key = cfg("ses_access_key_id");
        let secret_key = cfg("ses_secret_access_key");
        let from_addr = cfg("ses_from_address");

        if access_key.is_empty() || secret_key.is_empty() || from_addr.is_empty() {
            return Err("SES not configured: set ses_access_key_id, ses_secret_access_key, ses_from_address".into());
        }
        let region = if region.is_empty() {
            "eu-west-1".to_string()
        } else {
            region
        };

        let subject = templates::subject(event);
        let html = templates::html_body(event);
        let text = templates::text_body(event);

        let body = serde_json::json!({
            "Content": {
                "Simple": {
                    "Subject": { "Data": subject, "Charset": "UTF-8" },
                    "Body": {
                        "Html": { "Data": html, "Charset": "UTF-8" },
                        "Text": { "Data": text, "Charset": "UTF-8" }
                    }
                }
            },
            "Destination": {
                "ToAddresses": [event.to]
            },
            "FromEmailAddress": from_addr
        });
        let payload = serde_json::to_string(&body).map_err(|e| format!("json: {e}"))?;

        let host = format!("email.{region}.amazonaws.com");
        let url = format!("https://{host}/v2/email/outbound-emails");

        let now = chrono::DateTime::from_timestamp(
            crate::wasi::clocks::wall_clock::now().seconds as i64,
            0,
        )
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
        let datestamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // AWS SigV4 signing
        let payload_hash = hex_sha256(payload.as_bytes());
        let canonical_headers =
            format!("content-type:application/json\nhost:{host}\nx-amz-date:{amz_date}\n");
        let signed_headers = "content-type;host;x-amz-date";
        let canonical_request = format!(
            "POST\n/v2/email/outbound-emails\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let credential_scope = format!("{datestamp}/{region}/ses/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(&secret_key, &datestamp, &region, "ses");
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&url)
            .header("content-type", "application/json")
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", &authorization)
            .body(payload)
            .map_err(|e| format!("build request: {e}"))?;

        let wasi_request = wasip3::http_compat::http_into_wasi_request(request)
            .map_err(|e| format!("build wasi request: {e:?}"))?;
        let wasi_response = wasip3::http::client::send(wasi_request)
            .await
            .map_err(|e| format!("SES request failed: {e:?}"))?;
        let response = wasip3::http_compat::http_from_wasi_response(wasi_response)
            .map_err(|e| format!("parse response: {e:?}"))?;

        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            eprintln!(
                "email-worker [SES]: sent {} to {}",
                event.event_type, event.to
            );
            Ok(())
        } else {
            // Read error body for diagnostics
            let body_bytes = read_body(response.into_body()).await;
            let detail = String::from_utf8_lossy(&body_bytes);
            Err(format!("SES returned HTTP {status}: {detail}"))
        }
    }

    async fn read_body<B>(mut body: B) -> Vec<u8>
    where
        B: http_body::Body<Data = bytes::Bytes> + Unpin,
        B::Error: std::fmt::Debug,
    {
        use std::future::poll_fn;
        use std::pin::Pin;

        let mut bytes = Vec::new();
        while let Some(Ok(frame)) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
            if let Some(data) = frame.data_ref() {
                bytes.extend_from_slice(data);
            }
        }
        bytes
    }

    fn hex_sha256(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn derive_signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> Vec<u8> {
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}
