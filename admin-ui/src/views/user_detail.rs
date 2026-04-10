use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use crate::api::{self, User};
use crate::auth::AuthContext;

#[component]
pub fn UserDetailView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let params = use_params_map();
    let (user, set_user) = signal(Option::<User>::None);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);

    Effect::new(move |_| {
        let id = params.read().get("id").unwrap_or_default();
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_users(&tok).await {
                Ok(list) => {
                    set_user.set(list.into_iter().find(|u| u.id == id));
                    set_loading.set(false);
                }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
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
                    }.into_any()
                }
            }
        }}
    }
}
