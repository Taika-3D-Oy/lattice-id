use leptos::prelude::*;
use crate::api::{self, AuditEntry};
use crate::auth::AuthContext;

#[component]
pub fn AuditLogView() -> impl IntoView {
    let auth_ctx = expect_context::<AuthContext>();
    let (entries, set_entries) = signal(Vec::<AuditEntry>::new());
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);
    let (filter, set_filter) = signal(String::new());

    let fetch = move || {
        set_loading.set(true);
        set_error.set(None);
        let tok = auth_ctx.token.get_untracked();
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_audit_log(&tok).await {
                Ok(mut list) => {
                    list.reverse(); // newest first
                    set_entries.set(list);
                    set_loading.set(false);
                }
                Err(e) => { set_error.set(Some(e.0)); set_loading.set(false); }
            }
        });
    };
    fetch();

    let filtered = Memo::new(move |_| {
        let f = filter.get().to_lowercase();
        if f.is_empty() {
            entries.get()
        } else {
            entries.get().into_iter().filter(|e| {
                e.event_type.to_lowercase().contains(&f)
                    || e.actor.to_lowercase().contains(&f)
                    || e.detail.to_lowercase().contains(&f)
            }).collect()
        }
    });

    view! {
        <div class="page-header">
            <h1>"Audit Log"</h1>
            <button on:click=move |_| fetch()>"\u{21bb} Refresh"</button>
        </div>

        <div class="form-group" style="max-width:300px; margin-bottom:16px;">
            <input type="text" placeholder="Filter events..."
                prop:value=filter
                on:input=move |ev| set_filter.set(event_target_value(&ev))/>
        </div>

        {move || error.get().map(|e| view! { <p class="msg-error">{e}</p> })}

        {move || {
            if loading.get() {
                view! { <div class="spinner"></div> }.into_any()
            } else if filtered.get().is_empty() {
                view! { <p>"No audit entries found."</p> }.into_any()
            } else {
                view! {
                    <div class="scroll-y">
                        <table>
                            <thead>
                                <tr>
                                    <th>"Time"</th>
                                    <th>"Event"</th>
                                    <th>"Actor"</th>
                                    <th>"Detail"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {move || filtered.get().into_iter().map(|e| {
                                    let badge_class = match e.event_type.as_str() {
                                        "login_success" => "badge badge-success",
                                        "login_failure" | "account_locked" => "badge badge-danger",
                                        "mfa_failure" => "badge badge-warning",
                                        _ => "badge badge-muted",
                                    };
                                    view! {
                                        <tr>
                                            <td class="mono-sm">{crate::api::format_timestamp(e.timestamp)}</td>
                                            <td><span class=badge_class>{e.event_type.clone()}</span></td>
                                            <td>{e.actor.clone()}</td>
                                            <td>{e.detail.clone()}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any()
            }
        }}
    }
}
