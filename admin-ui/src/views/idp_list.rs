use leptos::prelude::*;
use crate::api::{self, IdentityProvider, CreateIdpRequest};
use crate::auth::AuthContext;

#[component]
pub fn IdpListView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let (idps, set_idps) = signal(Vec::<IdentityProvider>::new());
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    let (success, set_success) = signal(Option::<String>::None);
    let (show_form, set_show_form) = signal(false);

    // Form fields
    let (f_type, set_f_type) = signal("google".to_string());
    let (f_cid, set_f_cid) = signal(String::new());
    let (f_secret, set_f_secret) = signal(String::new());

    let fetch = move || {
        set_loading.set(true);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_identity_providers(&tok).await {
                Ok(list) => { set_idps.set(list); set_loading.set(false); }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    };
    fetch();

    let on_create = move |_| {
        set_success.set(None);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        let req = CreateIdpRequest {
            provider_type: f_type.get_untracked(),
            client_id: f_cid.get_untracked(),
            client_secret: f_secret.get_untracked(),
            enabled: true,
        };
        wasm_bindgen_futures::spawn_local(async move {
            match api::create_identity_provider(&tok, &req).await {
                Ok(idp) => {
                    set_idps.update(|v| v.push(idp));
                    set_success.set(Some("Identity provider created".into()));
                    set_show_form.set(false);
                    set_f_cid.set(String::new());
                    set_f_secret.set(String::new());
                }
                Err(e) => set_error.set(Some(e.0)),
            }
        });
    };

    let form_valid = Memo::new(move |_| !f_cid.get().is_empty() && !f_secret.get().is_empty());

    view! {
        <div class="page-header">
            <h1>"Identity Providers"</h1>
            <button on:click=move |_| set_show_form.set(true)>"+ Add Provider"</button>
            <button on:click=move |_| fetch()>"\u{21bb} Refresh"</button>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}
        {move || success.get().map(|m| view! { <p class="msg-success">{m}</p> })}

        {move || show_form.get().then(|| view! {
            <div class="card">
                <h2>"Add Identity Provider"</h2>
                <div class="form-row">
                    <label>"Type"</label>
                    <select on:change=move |ev| set_f_type.set(event_target_value(&ev))>
                        <option value="google" selected=move || f_type.get() == "google">"Google"</option>
                        <option value="github" selected=move || f_type.get() == "github">"GitHub"</option>
                    </select>
                </div>
                <div class="form-row">
                    <label>"Client ID"</label>
                    <input type="text" prop:value=f_cid
                        on:input=move |ev| set_f_cid.set(event_target_value(&ev))/>
                </div>
                <div class="form-row">
                    <label>"Client Secret"</label>
                    <input type="password" prop:value=f_secret
                        on:input=move |ev| set_f_secret.set(event_target_value(&ev))/>
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
            } else if idps.get().is_empty() {
                view! { <p>"No identity providers configured. Add one to enable social login."</p> }.into_any()
            } else {
                view! {
                    <table>
                        <thead>
                            <tr>
                                <th>"ID"</th>
                                <th>"Type"</th>
                                <th>"Client ID"</th>
                                <th>"Enabled"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || idps.get().into_iter().map(|idp| {
                                let id_for_delete = idp.id.clone();
                                let enabled_class = if idp.enabled { "badge badge-success" } else { "badge badge-muted" };
                                view! {
                                    <tr>
                                        <td class="mono-sm">{idp.id.clone()}</td>
                                        <td>{idp.provider_type.clone()}</td>
                                        <td class="mono-sm">{idp.client_id.clone()}</td>
                                        <td><span class=enabled_class>{if idp.enabled { "Yes" } else { "No" }}</span></td>
                                        <td>
                                            <button class="btn-danger btn-sm" on:click=move |_| {
                                                let tok = auth_ctx.token.get_untracked();
                                                let id = id_for_delete.clone();
                                                let set_idps = set_idps;
                                                let set_error = set_error;
                                                wasm_bindgen_futures::spawn_local(async move {
                                                    match api::delete_identity_provider(&tok, &id).await {
                                                        Ok(()) => set_idps.update(|v| v.retain(|p| p.id != id)),
                                                        Err(e) => set_error.set(Some(e.0)),
                                                    }
                                                });
                                            }>"\u{1f5d1} Delete"</button>
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
