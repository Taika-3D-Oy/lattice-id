//! Send email notifications via lattice-id:notify/email interface.
//!
//! The gateway calls the email-worker component directly through the
//! custom WIT interface.  Errors are logged but never propagated —
//! email delivery is best-effort from the gateway's perspective.

use crate::bindings::lattice_id::notify::email;

/// Send an email notification.  Errors are logged but never propagated.
pub async fn publish_email_event(
    event_type: &str,
    to: &str,
    name: &str,
    action_url: &str,
    metadata: serde_json::Value,
) {
    let metadata_str = match serde_json::to_string(&metadata) {
        Ok(s) => s,
        Err(e) => {
            crate::logger::error_message("email.serialize_failed", e.to_string());
            return;
        }
    };

    if let Err(e) = email::send(event_type, to, name, action_url, &metadata_str) {
        crate::logger::error_message("email.send_failed", e);
    }
}

/// Convenience: publish a "verify_email" event with a pre-built URL.
pub async fn send_verification_email(issuer: &str, to: &str, name: &str, token: &str) {
    let url = format!("{issuer}/verify/email?token={token}");
    publish_email_event("verify_email", to, name, &url, serde_json::json!({})).await;
}

/// Convenience: publish a "password_reset" event.
pub async fn send_password_reset_email(issuer: &str, to: &str, name: &str, token: &str) {
    let url = format!("{issuer}/password-reset/complete?token={token}");
    publish_email_event("password_reset", to, name, &url, serde_json::json!({})).await;
}

/// Convenience: publish an "invitation" event.
pub async fn send_invitation_email(
    issuer: &str,
    to: &str,
    token: &str,
    tenant_name: &str,
    role: &str,
) {
    let url = format!("{issuer}/api/invitations/accept?token={token}");
    publish_email_event(
        "invitation",
        to,
        "",
        &url,
        serde_json::json!({
            "tenant_name": tenant_name,
            "role": role,
        }),
    )
    .await;
}
