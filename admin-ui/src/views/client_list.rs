use leptos::prelude::*;
use leptos_router::components::A;
use crate::api::{self, OidcClient, CreateClientRequest, ClientTheme};
use crate::auth::AuthContext;

#[component]
pub fn ClientListView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let (clients, set_clients) = signal(Vec::<OidcClient>::new());
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);
    let (show_form, set_show_form) = signal(false);

    // Form fields
    let (f_name, set_f_name) = signal(String::new());
    let (f_redirect, set_f_redirect) = signal(String::new());
    let (f_app_name, set_f_app_name) = signal(String::new());
    let (f_color, set_f_color) = signal(String::new());

    // Fetch on mount
    let fetch = move || {
        set_loading.set(true);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_clients(&tok).await {
                Ok(list) => { set_clients.set(list); set_loading.set(false); }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    };
    fetch();

    let on_create = move |_| {
        set_success.set(None);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        let name = f_name.get_untracked();
        let redirect = f_redirect.get_untracked();
        let app_name = f_app_name.get_untracked();
        let color = f_color.get_untracked();

        let theme = if app_name.is_empty() {
            None
        } else {
            Some(ClientTheme {
                app_name,
                logo_url: None,
                primary_color: if color.is_empty() { None } else { Some(color) },
                background_color: None,
            })
        };
        let req = CreateClientRequest {
            name,
            redirect_uris: redirect.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            theme,
        };

        wasm_bindgen_futures::spawn_local(async move {
            match api::create_client(&tok, &req).await {
                Ok(client) => {
                    set_clients.update(|v| v.push(client));
                    set_success.set(Some("Client created".into()));
                    set_show_form.set(false);
                    set_f_name.set(String::new());
                    set_f_redirect.set(String::new());
                    set_f_app_name.set(String::new());
                    set_f_color.set(String::new());
                }
                Err(e) => set_error.set(Some(e.0)),
            }
        });
    };

    let form_valid = Memo::new(move |_| !f_name.get().is_empty() && !f_redirect.get().is_empty());

    view! {
        <div class="page-header">
            <h1>"OIDC Clients"</h1>
            <button on:click=move |_| set_show_form.set(true)>"+ New Client"</button>
            <button on:click=move |_| fetch()>"\u{21bb} Refresh"</button>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}
        {move || success.get().map(|m| view! { <p class="msg-success">{m}</p> })}

        // New client form
        {move || show_form.get().then(|| view! {
            <div class="card">
                <h2>"Register New Client"</h2>
                <div class="form-row">
                    <label>"Name"</label>
                    <input type="text" prop:value=f_name
                        on:input=move |ev| set_f_name.set(event_target_value(&ev))/>
                </div>
                <div class="form-row">
                    <label>"Redirect URI"</label>
                    <input type="text" placeholder="comma-separated" prop:value=f_redirect
                        on:input=move |ev| set_f_redirect.set(event_target_value(&ev))/>
                </div>
                <div class="form-row">
                    <label>"App Name"</label>
                    <input type="text" prop:value=f_app_name
                        on:input=move |ev| set_f_app_name.set(event_target_value(&ev))/>
                </div>
                <div class="form-row">
                    <label>"Primary Color"</label>
                    <input type="text" placeholder="#3b82f6" prop:value=f_color
                        on:input=move |ev| set_f_color.set(event_target_value(&ev))/>
                </div>
                <div class="form-actions">
                    <button class="btn-primary" disabled=move || !form_valid.get()
                        on:click=on_create>"Create"</button>
                    <button on:click=move |_| set_show_form.set(false)>"Cancel"</button>
                </div>
            </div>
        })}

        {move || {
            if loading.get() {
                view! { <div class="spinner"></div> }.into_any()
            } else if clients.get().is_empty() {
                view! { <p>"No OIDC clients registered."</p> }.into_any()
            } else {
                view! {
                    <table>
                        <thead>
                            <tr>
                                <th>"Client ID"</th>
                                <th>"Name"</th>
                                <th>"Redirect URIs"</th>
                                <th>"Secret"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || clients.get().into_iter().map(|c| {
                                let cid = c.client_id.clone();
                                view! {
                                    <tr>
                                        <td class="mono">{c.client_id.clone()}</td>
                                        <td>{c.name.clone()}</td>
                                        <td class="mono-sm">{c.redirect_uris.join(", ")}</td>
                                        <td>{if c.client_secret.is_some() { "Yes" } else { "No" }}</td>
                                        <td>
                                            <A href=format!("clients/{}", cid) attr:class="btn btn-sm">"View"</A>
                                        </td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                }.into_any()
            }
        }}
    }
}
