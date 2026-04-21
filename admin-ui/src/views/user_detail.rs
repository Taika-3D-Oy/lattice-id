use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use crate::api::{self, User, PasskeyInfo};
use crate::auth::AuthContext;
use crate::webauthn::{webauthn_create, webauthn_available};

#[component]
pub fn UserDetailView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let params = use_params_map();
    let (user, set_user) = signal(Option::<User>::None);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);
    let (passkeys, set_passkeys) = signal(Vec::<PasskeyInfo>::new());
    let (passkey_name, set_passkey_name) = signal(String::new());
    let (registering, set_registering) = signal(false);

    // Load user
    Effect::new(move |_| {
        let id = params.read().get("id").unwrap_or_default();
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_users(&tok).await {
                Ok(list) => {
                    let found = list.into_iter().find(|u| u.id == id);
                    set_user.set(found);
                    set_loading.set(false);
                }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    });

    // Load passkeys when user is available
    Effect::new(move |_| {
        let Some(u) = user.get() else { return };
        let tok = auth_ctx.token.get_untracked();
        let uid = u.id.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(list) = api::fetch_passkeys(&tok, &uid).await {
                set_passkeys.set(list);
            }
        });
    });

    let on_disable_mfa = move |_| {
        set_error.set(None);
        set_success.set(None);
        let tok = auth_ctx.token.get_untracked();
        let uid = user.get_untracked().map(|u| u.id.clone()).unwrap_or_default();
        wasm_bindgen_futures::spawn_local(async move {
            match api::disable_user_mfa(&tok, &uid).await {
                Ok(()) => {
                    set_user.update(|u| { if let Some(u) = u { u.totp_enabled = false; } });
                    set_success.set(Some("MFA disabled".into()));
                }
                Err(e) => set_error.set(Some(e.0)),
            }
        });
    };

    let on_register_passkey = move |_| {
        set_error.set(None);
        set_success.set(None);
        set_registering.set(true);
        let tok = auth_ctx.token.get_untracked();
        let uid = user.get_untracked().map(|u| u.id.clone()).unwrap_or_default();
        let name = passkey_name.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            let result = async {
                // 1. Get registration options from server
                let opts = api::passkey_register_options(&tok, &uid).await?;
                let reg_token = opts.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let pk = opts.get("publicKey").cloned().unwrap_or_default();

                // Build the full options with publicKey wrapper
                let full_opts = serde_json::json!({ "publicKey": pk });

                // 2. Call WebAuthn API via JS interop
                let result_js = webauthn_create(&serde_json::to_string(&full_opts).unwrap_or_default())
                    .await
                    .map_err(|e| api::ApiError(format!("{:?}", e)))?;
                let result_str = result_js.as_string().ok_or_else(|| api::ApiError("invalid JS result".into()))?;
                let result_val: serde_json::Value = serde_json::from_str(&result_str)
                    .map_err(|e| api::ApiError(e.to_string()))?;

                let cdj = result_val.get("clientDataJSON").and_then(|v| v.as_str()).unwrap_or("");
                let att = result_val.get("attestationObject").and_then(|v| v.as_str()).unwrap_or("");

                // 3. Complete registration on server
                api::passkey_register_complete(&tok, &uid, &reg_token, cdj, att, &name).await?;

                // 4. Refresh passkey list
                let list = api::fetch_passkeys(&tok, &uid).await?;
                Ok::<Vec<PasskeyInfo>, api::ApiError>(list)
            }.await;

            set_registering.set(false);
            match result {
                Ok(list) => {
                    set_passkeys.set(list);
                    set_passkey_name.set(String::new());
                    set_success.set(Some("Passkey registered successfully".into()));
                }
                Err(e) => set_error.set(Some(e.0)),
            }
        });
    };

    let on_delete_passkey = move |cred_id: String| {
        set_error.set(None);
        set_success.set(None);
        let tok = auth_ctx.token.get_untracked();
        let uid = user.get_untracked().map(|u| u.id.clone()).unwrap_or_default();
        wasm_bindgen_futures::spawn_local(async move {
            match api::delete_passkey(&tok, &uid, &cred_id).await {
                Ok(()) => {
                    set_passkeys.update(|list| list.retain(|p| p.credential_id != cred_id));
                    set_success.set(Some("Passkey removed".into()));
                }
                Err(e) => set_error.set(Some(e.0)),
            }
        });
    };

    view! {
        <div>
            <a href="/users" style="color: var(--primary); text-decoration: none;">"\u{2190} Back to users"</a>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}
        {move || success.get().map(|m| view! { <p class="msg-success">{m}</p> })}

        {move || {
            if loading.get() {
                return view! { <div class="spinner"></div> }.into_any();
            }
            match user.get() {
                None => view! { <p>"User not found."</p> }.into_any(),
                Some(u) => {
                    let ts = crate::api::format_timestamp(u.created_at);
                    view! {
                        <h1>{u.name.clone()}</h1>
                        <div class="card">
                            <div class="detail-grid">
                                <span class="label">"ID"</span>
                                <span class="value mono">{u.id.clone()}</span>

                                <span class="label">"Email"</span>
                                <span class="value">{u.email.clone()}</span>

                                <span class="label">"Status"</span>
                                <span class="value">
                                    <span class={if u.status == "active" { "badge badge-success" } else { "badge badge-muted" }}>
                                        {u.status.clone()}
                                    </span>
                                </span>

                                <span class="label">"Created"</span>
                                <span class="value">{ts}</span>

                                <span class="label">"MFA"</span>
                                <span class="value">
                                    {if u.totp_enabled {
                                        view! {
                                            <span class="badge badge-success">"TOTP enabled"</span>
                                            " "
                                            <button class="btn-danger btn-sm" on:click=on_disable_mfa>"Disable MFA"</button>
                                        }.into_any()
                                    } else {
                                        view! { <span>"Not enrolled"</span> }.into_any()
                                    }}
                                </span>
                            </div>
                        </div>

                        // Passkey management section
                        <h2 style="margin-top:24px">"Passkeys"</h2>
                        <div class="card">
                            {move || {
                                let pk_list = passkeys.get();
                                if pk_list.is_empty() {
                                    view! { <p style="color:#64748b">"No passkeys registered."</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="data-table" style="width:100%">
                                            <thead><tr>
                                                <th>"Name"</th>
                                                <th>"Created"</th>
                                                <th>"Uses"</th>
                                                <th></th>
                                            </tr></thead>
                                            <tbody>
                                                {pk_list.into_iter().map(|pk| {
                                                    let cred_id = pk.credential_id.clone();
                                                    let del = on_delete_passkey.clone();
                                                    view! {
                                                        <tr>
                                                            <td>{pk.name.clone()}</td>
                                                            <td>{crate::api::format_timestamp(pk.created_at)}</td>
                                                            <td>{pk.sign_count}</td>
                                                            <td>
                                                                <button class="btn-danger btn-sm"
                                                                    on:click=move |_| del(cred_id.clone())>
                                                                    "Remove"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect::<Vec<_>>()}
                                            </tbody>
                                        </table>
                                    }.into_any()
                                }
                            }}

                            {move || {
                                if webauthn_available() {
                                    view! {
                                        <div style="margin-top:16px;display:flex;gap:8px;align-items:center">
                                            <input type="text"
                                                placeholder="Passkey name (e.g. MacBook Touch ID)"
                                                style="flex:1;padding:8px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px"
                                                prop:value=move || passkey_name.get()
                                                on:input=move |ev| set_passkey_name.set(leptos::prelude::event_target_value(&ev))
                                            />
                                            <button class="btn-primary"
                                                disabled=move || registering.get()
                                                on:click=on_register_passkey>
                                                {move || if registering.get() { "Registering\u{2026}" } else { "Add Passkey" }}
                                            </button>
                                        </div>
                                    }.into_any()
                                } else {
                                    view! { <p style="color:#94a3b8;margin-top:12px;font-size:13px">"Passkeys are not supported in this browser."</p> }.into_any()
                                }
                            }}
                        </div>
                    }.into_any()
                }
            }
        }}
    }
}
