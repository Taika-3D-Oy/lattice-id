use leptos::prelude::*;
use crate::api::{self, PasskeyInfo, MfaSetup, MfaConfirm};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};
use crate::util::copy_text;
use crate::webauthn::{webauthn_create_account, webauthn_available};

// ── JWT claim extraction ─────────────────────────────────────
fn get_user_id_from_token(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    let payload = parts.get(1)?;
    let decoded = {
        let mut s = payload.replace('-', "+").replace('_', "/");
        while s.len() % 4 != 0 { s.push('='); }
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s).ok()?
    };
    let val: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    val.get("sub").and_then(|v| v.as_str()).map(|s| s.to_string())
}

#[derive(Clone, Copy, PartialEq)]
enum AccTab { Passkeys, Mfa, Password }

#[component]
pub fn AccountView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();

    let (tab, set_tab) = signal(AccTab::Passkeys);

    // Derive user_id from JWT
    let user_id = Memo::new(move |_| {
        get_user_id_from_token(&auth.token.get()).unwrap_or_default()
    });

    // ── Passkeys state ──
    let (passkeys, set_passkeys)     = signal(Vec::<PasskeyInfo>::new());
    let (pk_loading, set_pk_loading) = signal(true);
    let (pk_name, set_pk_name)       = signal(String::new());
    let (registering, set_registering) = signal(false);

    // ── MFA state ──
    let (mfa_setup, set_mfa_setup)     = signal(None::<MfaSetup>);
    let (mfa_confirm, set_mfa_confirm) = signal(None::<MfaConfirm>);
    let (mfa_code, set_mfa_code)       = signal(String::new());
    let (mfa_loading, set_mfa_loading) = signal(false);
    let (mfa_enabled, set_mfa_enabled) = signal(false);

    // Load passkeys on mount
    Effect::new(move |_| {
        let uid = user_id.get();
        if uid.is_empty() { return; }
        let tok = auth.token.get_untracked();
        let st  = toasts.set_toasts;
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_passkeys(&tok, &uid).await {
                Ok(list) => { set_passkeys.set(list); set_pk_loading.set(false); }
                Err(e)   => { show_toast(st, ToastKind::Error, e.to_string()); set_pk_loading.set(false); }
            }
        });
    });

    let refresh_passkeys = {
        let st = toasts.set_toasts;
        move || {
            let tok = auth.token.get_untracked();
            let uid = user_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(list) = api::fetch_passkeys(&tok, &uid).await {
                    set_passkeys.set(list);
                } else {
                    show_toast(st, ToastKind::Error, "Failed to refresh passkeys");
                }
            });
        }
    };

    let on_delete_passkey = {
        let st = toasts.set_toasts;
        move |cred_id: String| {
            let tok = auth.token.get_untracked();
            let uid = user_id.get_untracked();
            let rf  = refresh_passkeys;
            wasm_bindgen_futures::spawn_local(async move {
                match api::delete_passkey(&tok, &uid, &cred_id).await {
                    Ok(()) => { show_toast(st, ToastKind::Success, "Passkey deleted"); rf(); }
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
            });
        }
    };

    let on_register_passkey = {
        let st = toasts.set_toasts;
        move |_| {
            if !webauthn_available() {
                show_toast(st, ToastKind::Error, "WebAuthn not supported in this browser");
                return;
            }
            set_registering.set(true);
            let tok  = auth.token.get_untracked();
            let uid  = user_id.get_untracked();
            let name = pk_name.get_untracked();
            let rf   = refresh_passkeys;
            wasm_bindgen_futures::spawn_local(async move {
                let result = async {
                    let opts = api::passkey_register_options(&tok, &uid).await?;
                    let reg_token = opts.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let pk = opts.get("publicKey").cloned().unwrap_or_default();
                    let full = serde_json::json!({ "publicKey": pk });
                    let js = webauthn_create_account(&serde_json::to_string(&full).unwrap_or_default())
                        .await
                        .map_err(|e| api::ApiError(format!("{:?}", e)))?;
                    let s = js.as_string().ok_or_else(|| api::ApiError("bad JS result".into()))?;
                    let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| api::ApiError(e.to_string()))?;
                    let cdj = v.get("clientDataJSON").and_then(|x| x.as_str()).unwrap_or("");
                    let att = v.get("attestationObject").and_then(|x| x.as_str()).unwrap_or("");
                    api::passkey_register_complete(&tok, &uid, &reg_token, cdj, att, &name).await?;
                    Ok::<_, api::ApiError>(())
                }.await;
                set_registering.set(false);
                match result {
                    Ok(()) => { show_toast(st, ToastKind::Success, "Passkey registered"); set_pk_name.set(String::new()); rf(); }
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
            });
        }
    };

    // MFA setup
    let on_start_mfa = {
        let st = toasts.set_toasts;
        move |_| {
            set_mfa_loading.set(true);
            let tok = auth.token.get_untracked();
            let uid = user_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::get_mfa_setup(&tok, &uid).await {
                    Ok(s)  => { set_mfa_setup.set(Some(s)); set_mfa_loading.set(false); }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_mfa_loading.set(false); }
                }
            });
        }
    };

    let on_confirm_mfa = {
        let st = toasts.set_toasts;
        move |_| {
            set_mfa_loading.set(true);
            let tok  = auth.token.get_untracked();
            let uid  = user_id.get_untracked();
            let code = mfa_code.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::confirm_mfa(&tok, &uid, &code).await {
                    Ok(c)  => {
                        set_mfa_confirm.set(Some(c));
                        set_mfa_enabled.set(true);
                        set_mfa_setup.set(None);
                        show_toast(st, ToastKind::Success, "TOTP enabled");
                        set_mfa_loading.set(false);
                    }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_mfa_loading.set(false); }
                }
            });
        }
    };

    let on_disable_mfa = {
        let st = toasts.set_toasts;
        move |_| {
            let tok = auth.token.get_untracked();
            let uid = user_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::disable_user_mfa(&tok, &uid).await {
                    Ok(()) => { show_toast(st, ToastKind::Success, "TOTP disabled"); set_mfa_enabled.set(false); set_mfa_confirm.set(None); }
                    Err(e) => show_toast(st, ToastKind::Error, e.to_string()),
                }
            });
        }
    };

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"My Account"</div>
                <div class="page-subtitle">"Manage your credentials and security settings"</div>
            </div>
        </div>

        <div class="tabs">
            <button class=move || if tab.get()==AccTab::Passkeys { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(AccTab::Passkeys)>"Passkeys"</button>
            <button class=move || if tab.get()==AccTab::Mfa { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(AccTab::Mfa)>"Two-Factor Auth"</button>
            <button class=move || if tab.get()==AccTab::Password { "tab active" } else { "tab" }
                on:click=move |_| set_tab.set(AccTab::Password)>"Password"</button>
        </div>

        // ── Passkeys tab ──
        {move || (tab.get()==AccTab::Passkeys).then(|| view! {
            <div>
                <div class="card" style="max-width:640px;">
                    <div class="card-header">
                        <span class="card-title">"Your Passkeys"</span>
                    </div>
                    {move || if pk_loading.get() {
                        view! { <div class="spinner"></div> }.into_any()
                    } else if passkeys.get().is_empty() {
                        view! {
                            <div class="empty-state">
                                <div class="empty-icon">"🔑"</div>
                                <h3>"No passkeys registered"</h3>
                                <p>"Add a passkey to enable passwordless login."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="table-wrap" style="margin-bottom:16px;">
                                <table>
                                    <thead><tr><th>"Name"</th><th>"Added"</th><th>"Uses"</th><th></th></tr></thead>
                                    <tbody>
                                        {move || {
                                            let on_del = on_delete_passkey;
                                            passkeys.get().into_iter().map(move |pk| {
                                                let cid = pk.credential_id.clone();
                                                view! {
                                                    <tr>
                                                        <td style="font-weight:500">{pk.name.clone()}</td>
                                                        <td class="text-muted">{api::format_timestamp(pk.created_at)}</td>
                                                        <td class="text-muted">{pk.sign_count}</td>
                                                        <td class="actions">
                                                            <button class="btn btn-sm btn-danger"
                                                                on:click=move |_| on_del(cid.clone())>"Remove"</button>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()
                                        }}
                                    </tbody>
                                </table>
                            </div>
                        }.into_any()
                    }}
                    <div style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap;">
                        <div class="form-group" style="margin:0; flex:1; min-width:180px;">
                            <label>"Passkey name"</label>
                            <input type="text" placeholder="e.g. MacBook Touch ID"
                                prop:value=pk_name
                                on:input=move |ev| set_pk_name.set(event_target_value(&ev))/>
                        </div>
                        <button class="btn btn-primary"
                            disabled=move || pk_name.get().is_empty() || registering.get()
                            on:click=on_register_passkey>
                            {move || if registering.get() { "Registering…" } else { "Register Passkey" }}
                        </button>
                    </div>
                </div>
            </div>
        })}

        // ── MFA tab ──
        {move || (tab.get()==AccTab::Mfa).then(|| view! {
            <div>
                <div class="card" style="max-width:480px;">
                    <div class="card-header">
                        <span class="card-title">"Two-Factor Authentication (TOTP)"</span>
                        {move || if mfa_enabled.get() {
                            view! { <span class="badge badge-success">"enabled"</span> }.into_any()
                        } else {
                            view! { <span class="badge badge-muted">"disabled"</span> }.into_any()
                        }}
                    </div>

                    // Show recovery codes after setup
                    {move || mfa_confirm.get().map(|c| view! {
                        <div>
                            <p class="msg-success">"TOTP enabled successfully!"</p>
                            <p style="font-size:12px; color:var(--muted); margin-bottom:8px;">
                                "Save these recovery codes — they will not be shown again."
                            </p>
                            <div class="recovery-codes">
                                {c.recovery_codes.iter().map(|code| view! {
                                    <span>{code.clone()}</span>
                                }).collect_view()}
                            </div>
                        </div>
                    })}

                    // Setup flow
                    {move || mfa_setup.get().map(|s| view! {
                        <div>
                            <p style="font-size:13px; margin-bottom:12px;">
                                "Open your authenticator app and scan the QR code, or enter the key manually."
                            </p>
                            <div class="form-group">
                                <label>"Manual key"</label>
                                <div style="display:flex; gap:8px; align-items:center;">
                                    <code class="mono">{s.secret.clone()}</code>
                                    <button class="btn btn-sm" on:click=move |_| copy_text(&s.secret)>"Copy"</button>
                                </div>
                            </div>
                            <div class="form-group">
                                <label>"Authenticator URI (tap to open app)"</label>
                                <a href={s.otpauth_uri.clone()} class="mono-sm" style="word-break:break-all;">{s.otpauth_uri.clone()}</a>
                            </div>
                            <div class="form-group">
                                <label>"Verify code"</label>
                                <input type="text" placeholder="6-digit code" maxlength="6"
                                    prop:value=mfa_code
                                    on:input=move |ev| set_mfa_code.set(event_target_value(&ev))/>
                            </div>
                            <button class="btn btn-primary"
                                disabled=move || mfa_code.get().len()!=6 || mfa_loading.get()
                                on:click=on_confirm_mfa>
                                {move || if mfa_loading.get() { "Verifying…" } else { "Enable TOTP" }}
                            </button>
                        </div>
                    })}

                    // Idle state
                    {move || (mfa_setup.get().is_none() && mfa_confirm.get().is_none()).then(|| view! {
                        <div style="display:flex; gap:8px;">
                            {move || if !mfa_enabled.get() {
                                view! {
                                    <button class="btn btn-primary" disabled=move || mfa_loading.get() on:click=on_start_mfa>
                                        {move || if mfa_loading.get() { "Loading…" } else { "Set Up TOTP" }}
                                    </button>
                                }.into_any()
                            } else {
                                view! {
                                    <button class="btn btn-danger" on:click=on_disable_mfa>"Disable TOTP"</button>
                                }.into_any()
                            }}
                        </div>
                    })}
                </div>
            </div>
        })}

        // ── Password tab ──
        {move || (tab.get()==AccTab::Password).then(|| view! {
            <div>
                <div class="card" style="max-width:480px;">
                    <div class="card-header">
                        <span class="card-title">"Password Reset"</span>
                    </div>
                    <p style="font-size:13px; color:var(--muted); margin-bottom:16px;">
                        "Send a password reset email to your registered address."
                    </p>
                    <PasswordResetButton/>
                </div>
            </div>
        })}
    }
}

#[component]
fn PasswordResetButton() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();
    let (sending, set_sending) = signal(false);

    let user_id = Memo::new(move |_| {
        get_user_id_from_token(&auth.token.get()).unwrap_or_default()
    });

    let on_reset = {
        let st = toasts.set_toasts;
        move |_| {
            set_sending.set(true);
            let tok = auth.token.get_untracked();
            let uid = user_id.get_untracked();
            wasm_bindgen_futures::spawn_local(async move {
                match api::send_password_reset(&tok, &uid).await {
                    Ok(()) => { show_toast(st, ToastKind::Success, "Password reset email sent"); set_sending.set(false); }
                    Err(e) => { show_toast(st, ToastKind::Error, e.to_string()); set_sending.set(false); }
                }
            });
        }
    };

    view! {
        <button class="btn btn-primary" disabled=move || sending.get() on:click=on_reset>
            {move || if sending.get() { "Sending…" } else { "Send Password Reset Email" }}
        </button>
    }
}
