use leptos::prelude::*;
use crate::auth::AuthContext;

#[component]
pub fn LoginView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let (client_id, set_client_id) = signal(crate::auth::default_client_id());
    let (redirect_uri, set_redirect_uri) = signal(crate::auth::default_redirect_uri());
    let (error, _set_error) = signal(Option::<String>::None);

    let on_login = move |_| {
        let issuer = auth_ctx.issuer_url.get_untracked();
        let cid = client_id.get_untracked();
        let ruri = redirect_uri.get_untracked();
        crate::auth::login_redirect(&issuer, &cid, &ruri);
    };

    let oidc_ready = Memo::new(move |_| {
        !auth_ctx.issuer_url.get().is_empty() && !client_id.get().is_empty()
    });

    view! {
        <div class="center-screen">
            <div class="login-box">
                <h1>"Lattice-ID Admin"</h1>
                <p>"Identity provider management console"</p>

                {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}

                <button
                    class="btn-primary"
                    style="width:100%; justify-content:center; margin-bottom: 16px;"
                    disabled=move || !oidc_ready.get()
                    on:click=on_login
                >
                    "\u{1f510} Login with Lattice-ID"
                </button>

                <details>
                    <summary>"OIDC Configuration"</summary>
                    <div class="form-group">
                        <label>"Issuer URL"</label>
                        <input type="text"
                            prop:value=move || auth_ctx.issuer_url.get()
                            on:input=move |ev| auth_ctx.set_issuer_url.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="form-group">
                        <label>"Client ID"</label>
                        <input type="text"
                            prop:value=client_id
                            on:input=move |ev| set_client_id.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="form-group">
                        <label>"Redirect URI"</label>
                        <input type="text"
                            prop:value=redirect_uri
                            on:input=move |ev| set_redirect_uri.set(event_target_value(&ev))
                        />
                    </div>
                </details>
            </div>
        </div>
    }
}
