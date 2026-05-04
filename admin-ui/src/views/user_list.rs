use leptos::prelude::*;
use leptos_router::components::A;
use crate::api::{self, TenantMember};
use crate::auth::AuthContext;
use crate::app::{TenantCtx, ToastCtx, ToastKind, show_toast};

/// User list is scoped to the current tenant (from TenantCtx).
#[component]
pub fn UserListView() -> impl IntoView {
    let auth       = expect_context::<AuthContext>();
    let tenant_ctx = expect_context::<TenantCtx>();
    let toasts     = expect_context::<ToastCtx>();

    let (members, set_members)   = signal(Vec::<TenantMember>::new());
    let (loading, set_loading)   = signal(false);
    let (filter, set_filter)     = signal(String::new());

    Effect::new(move |_| {
        let tid = tenant_ctx.current_id.get();
        if tid.is_empty() { return; }
        set_loading.set(true);
        let tok = auth.token.get_untracked();
        let st  = toasts.set_toasts;
        wasm_bindgen_futures::spawn_local(async move {
            match api::fetch_tenant_members(&tok, &tid).await {
                Ok(list) => { set_members.set(list); set_loading.set(false); }
                Err(e)   => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
            }
        });
    });

    let filtered = Memo::new(move |_| {
        let f = filter.get().to_lowercase();
        if f.is_empty() { return members.get(); }
        members.get().into_iter().filter(|m| {
            m.email.to_lowercase().contains(&f) || m.name.to_lowercase().contains(&f)
        }).collect()
    });

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Users"</div>
                {move || {
                    let ts = tenant_ctx.tenants.get();
                    let cur = tenant_ctx.current_id.get();
                    let name = ts.iter().find(|t| t.id==cur).map(|t| t.display_name.clone()).unwrap_or_default();
                    view! { <div class="page-subtitle">"Members of "{name}</div> }
                }}
            </div>
        </div>

        {move || if tenant_ctx.current_id.get().is_empty() {
            view! {
                <div class="empty-state">
                    <div class="empty-icon">"🏢"</div>
                    <h3>"No tenant selected"</h3>
                    <p>"Select a tenant from the switcher at the top, or create one first."</p>
                </div>
            }.into_any()
        } else { view! {
            <div>
                <div style="display:flex; gap:8px; margin-bottom:16px;">
                    <input type="text" placeholder="Filter by email or name…"
                        style="max-width:280px;"
                        prop:value=filter
                        on:input=move |ev| set_filter.set(event_target_value(&ev))/>
                    {move || {
                        let tid = tenant_ctx.current_id.get();
                        view! { <A href=format!("/admin/tenants/{tid}") attr:class="btn btn-primary">"+ Invite User"</A> }
                    }}
                </div>

                {move || if loading.get() {
                    view! { <div class="spinner"></div> }.into_any()
                } else if filtered.get().is_empty() {
                    view! {
                        <div class="empty-state">
                            <div class="empty-icon">"👥"</div>
                            <h3>"No members found"</h3>
                            <p>"Invite users to this tenant from the Tenants section."</p>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="table-wrap">
                            <table>
                                <thead><tr>
                                    <th>"Email"</th><th>"Name"</th><th>"Role"</th><th>"Joined"</th><th></th>
                                </tr></thead>
                                <tbody>
                                    {move || filtered.get().into_iter().map(|m| {
                                        let uid = m.id.clone();
                                        view! {
                                            <tr>
                                                <td>{m.email.clone()}</td>
                                                <td>{m.name.clone()}</td>
                                                <td><span class="badge badge-accent">{m.role.clone()}</span></td>
                                                <td class="text-muted">{api::relative_time(m.joined_at)}</td>
                                                <td class="actions">
                                                    <A href=format!("/admin/users/{uid}") attr:class="btn btn-sm">"Detail"</A>
                                                </td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>
                        </div>
                    }.into_any()
                }}
            </div>
        }.into_any()}}
    }
}

