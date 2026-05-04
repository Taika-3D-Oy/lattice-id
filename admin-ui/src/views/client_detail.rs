use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use crate::api::{self, OidcClient};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

#[component]
pub fn ClientDetailView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let toast_ctx = expect_context::<ToastCtx>();
    let params = use_params_map();
    let (client, set_client) = signal(Option::<OidcClient>::None);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    // Edit state for redirect URIs
    let (edit_uris, set_edit_uris) = signal(String::new());
    let (saving, set_saving) = signal(false);

    // Fetch client by ID
    Effect::new(move |_| {
        let id = params.read().get("id").unwrap_or_default();
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_clients(&tok).await {
                Ok(list) => {
                    let found = list.into_iter().find(|c| c.client_id == id);
                    if let Some(ref c) = found {
                        set_edit_uris.set(c.redirect_uris.join("\n"));
                    }
                    set_client.set(found);
                    set_loading.set(false);
                }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    });

    let save_uris = move |_| {
        let Some(c) = client.get() else { return };
        let raw = edit_uris.get();
        let uris: Vec<String> = raw.lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let tok = auth_ctx.token.get_untracked();
        let st = toast_ctx.set_toasts;
        set_saving.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match api::update_client_redirect_uris(&tok, &c.client_id, uris.clone()).await {
                Ok(()) => {
                    set_client.update(|opt| {
                        if let Some(cl) = opt { cl.redirect_uris = uris; }
                    });
                    show_toast(st, ToastKind::Success, "Redirect URIs saved.");
                }
                Err(e) => show_toast(st, ToastKind::Error, format!("Save failed: {}", e.0)),
            }
            set_saving.set(false);
        });
    };

    view! {
        <div>
            <a href="/admin/clients" style="color: var(--primary); text-decoration: none;">"\u{2190} Back to clients"</a>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}

        {move || {
            if loading.get() {
                return view! { <div class="spinner"></div> }.into_any();
            }
            match client.get() {
                None => view! { <p>"Client not found."</p> }.into_any(),
                Some(c) => {
                    let theme = c.theme.clone();
                    view! {
                        <h1>{c.name.clone()}</h1>
                        <div class="card">
                            <div class="detail-grid">
                                <span class="label">"Client ID"</span>
                                <span class="value mono">{c.client_id.clone()}</span>

                                <span class="label">"Name"</span>
                                <span class="value">{c.name.clone()}</span>

                                <span class="label">"Secret"</span>
                                <span class="value mono">{c.client_secret.clone().unwrap_or_else(|| "(none \u{2014} public client)".to_string())}</span>

                                <span class="label">"Grant Types"</span>
                                <span class="value">{c.grant_types.join(", ")}</span>
                            </div>
                        </div>

                        <h2>"Redirect URIs"</h2>
                        <div class="card">
                            <p class="text-muted" style="margin:0 0 8px;font-size:13px">"One URI per line. Must start with http:// or https://"</p>
                            <textarea
                                rows="6"
                                style="width:100%;font-family:monospace;font-size:13px;box-sizing:border-box"
                                prop:value=move || edit_uris.get()
                                on:input=move |ev| {
                                    use wasm_bindgen::JsCast;
                                    let val = ev.target()
                                        .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
                                        .map(|el| el.value())
                                        .unwrap_or_default();
                                    set_edit_uris.set(val);
                                }
                            ></textarea>
                            <div style="margin-top:8px">
                                <button
                                    class="btn btn-primary"
                                    on:click=save_uris
                                    disabled=move || saving.get()
                                >
                                    {move || if saving.get() { "Saving…" } else { "Save" }}
                                </button>
                            </div>
                        </div>

                        {theme.map(|t| {
                            let pc = t.primary_color.clone();
                            let bg = t.background_color.clone();
                            let logo = t.logo_url.clone().unwrap_or_else(|| "(none)".to_string());
                            view! {
                                <h2>"Theme"</h2>
                                <div class="card">
                                    <div class="detail-grid">
                                        <span class="label">"App Name"</span>
                                        <span class="value">{t.app_name.clone()}</span>

                                        <span class="label">"Logo URL"</span>
                                        <span class="value">{logo}</span>

                                        <span class="label">"Primary Color"</span>
                                        <span class="value">
                                            {pc.as_ref().map(|c| view! {
                                                <span class="swatch" style=format!("background:{}",c)></span>
                                                {c.clone()}
                                            })}
                                            {pc.is_none().then(|| "(default)")}
                                        </span>

                                        <span class="label">"Background"</span>
                                        <span class="value">
                                            {bg.as_ref().map(|c| view! {
                                                <span class="swatch" style=format!("background:{}",c)></span>
                                                {c.clone()}
                                            })}
                                            {bg.is_none().then(|| "(default)")}
                                        </span>
                                    </div>
                                </div>
                            }
                        })}
                    }.into_any()
                }
            }
        }}
    }
}
