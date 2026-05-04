use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use crate::api::{self, OidcClient};
use crate::auth::AuthContext;

#[component]
pub fn ClientDetailView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let params = use_params_map();
    let (client, set_client) = signal(Option::<OidcClient>::None);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);

    // Fetch clients and find by ID
    Effect::new(move |_| {
        let id = params.read().get("id").unwrap_or_default();
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_clients(&tok).await {
                Ok(list) => {
                    set_client.set(list.into_iter().find(|c| c.client_id == id));
                    set_loading.set(false);
                }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    });

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

                                <span class="label">"Redirect URIs"</span>
                                <span class="value mono-sm">{c.redirect_uris.join(", ")}</span>

                                <span class="label">"Grant Types"</span>
                                <span class="value">{c.grant_types.join(", ")}</span>
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
