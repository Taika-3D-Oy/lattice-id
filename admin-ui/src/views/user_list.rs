use leptos::prelude::*;
use leptos_router::components::A;
use crate::api::{self, User};
use crate::auth::AuthContext;

#[component]
pub fn UserListView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let (users, set_users) = signal(Vec::<User>::new());
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);

    let fetch = move || {
        set_loading.set(true);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_users(&tok).await {
                Ok(list) => { set_users.set(list); set_loading.set(false); }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    };
    fetch();

    view! {
        <div class="page-header">
            <h1>"Users"</h1>
            <button on:click=move |_| fetch()>"\u{21bb} Refresh"</button>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}

        {move || {
            if loading.get() {
                view! { <div class="spinner"></div> }.into_any()
            } else if users.get().is_empty() {
                view! { <p>"No users found."</p> }.into_any()
            } else {
                view! {
                    <table>
                        <thead>
                            <tr>
                                <th>"Email"</th>
                                <th>"Name"</th>
                                <th>"Status"</th>
                                <th>"MFA"</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || users.get().into_iter().map(|u| {
                                let uid = u.id.clone();
                                let status_class = if u.status == "active" { "badge badge-success" } else { "badge badge-muted" };
                                view! {
                                    <tr>
                                        <td>{u.email.clone()}</td>
                                        <td>{u.name.clone()}</td>
                                        <td><span class=status_class>{u.status.clone()}</span></td>
                                        <td>{if u.totp_enabled {
                                            view! { <span class="badge badge-success">"\u{2713} TOTP"</span> }.into_any()
                                        } else {
                                            view! { <span>"\u{2014}"</span> }.into_any()
                                        }}</td>
                                        <td>
                                            <A href=format!("/users/{}", uid) attr:class="btn btn-sm">"View"</A>
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
