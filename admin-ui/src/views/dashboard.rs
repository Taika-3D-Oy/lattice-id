use leptos::prelude::*;
use leptos_router::components::A;
use crate::api;
use crate::auth::AuthContext;
use crate::app::{TenantCtx, ToastCtx, show_toast, ToastKind};

#[component]
pub fn DashboardView() -> impl IntoView {
    let auth = expect_context::<AuthContext>();
    let tenant_ctx = expect_context::<TenantCtx>();
    let toast_ctx = expect_context::<ToastCtx>();

    let (tenant_count, set_tenant_count) = signal(0usize);
    let (member_count, set_member_count) = signal(0usize);
    let (hook_count, set_hook_count)     = signal(0usize);
    let (recent, set_recent) = signal(Vec::<api::AuditEntry>::new());
    let (loading, set_loading) = signal(true);

    Effect::new(move |_| {
        let tok = auth.token.get_untracked();
        let cur = tenant_ctx.current_id.get_untracked();
        let st  = toast_ctx.set_toasts;
        wasm_bindgen_futures::spawn_local(async move {
            // Tenants
            if let Ok(ts) = api::fetch_tenants(&tok).await {
                set_tenant_count.set(ts.len());
            }
            // Hooks
            if let Ok(hs) = api::fetch_hooks(&tok).await {
                set_hook_count.set(hs.len());
            }
            // Members of current tenant
            if !cur.is_empty() {
                if let Ok(ms) = api::fetch_tenant_members(&tok, &cur).await {
                    set_member_count.set(ms.len());
                }
            }
            // Recent audit
            let filters = api::AuditFilters { limit: Some(8), ..Default::default() };
            match api::fetch_audit_log_filtered(&tok, &filters).await {
                Ok(mut es) => { es.reverse(); set_recent.set(es); }
                Err(e) => show_toast(st, ToastKind::Error, format!("Audit: {e}")),
            }
            set_loading.set(false);
        });
    });

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Dashboard"</div>
                <div class="page-subtitle">"System overview and quick actions"</div>
            </div>
        </div>

        {move || if loading.get() {
            view! {
                <div class="stats-grid">
                    {(0..4).map(|_| view! {
                        <div class="stat-tile">
                            <div class="skeleton skeleton-line w-50"></div>
                            <div class="skeleton skeleton-line w-30" style="height:28px; margin-top:8px;"></div>
                        </div>
                    }).collect_view()}
                </div>
            }.into_any()
        } else {
            view! {
                <div class="stats-grid">
                    <div class="stat-tile">
                        <div class="stat-tile-label">"Tenants"</div>
                        <div class="stat-tile-value">{tenant_count.get()}</div>
                        <div class="stat-tile-sub">"total"</div>
                    </div>
                    <div class="stat-tile">
                        <div class="stat-tile-label">"Members"</div>
                        <div class="stat-tile-value">{member_count.get()}</div>
                        <div class="stat-tile-sub">"in current tenant"</div>
                    </div>
                    <div class="stat-tile">
                        <div class="stat-tile-label">"Hooks"</div>
                        <div class="stat-tile-value">{hook_count.get()}</div>
                        <div class="stat-tile-sub">"active scripts"</div>
                    </div>
                </div>
            }.into_any()
        }}

        <div class="quick-actions">
            <A href="/tenants" attr:class="btn btn-primary">"+ New Tenant"</A>
            <A href="/clients" attr:class="btn">"+ New Client"</A>
            <A href="/hooks"   attr:class="btn">"+ New Hook"</A>
        </div>

        <div class="card">
            <div class="card-header">
                <span class="card-title">"Recent Activity"</span>
                <span class="card-spacer"></span>
                <A href="/audit" attr:class="btn btn-sm btn-ghost">"View all →"</A>
            </div>
            {move || if recent.get().is_empty() {
                view! { <p class="text-muted" style="font-size:13px">"No recent events."</p> }.into_any()
            } else {
                view! {
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>"Time"</th>
                                    <th>"Event"</th>
                                    <th>"Actor"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {move || recent.get().into_iter().map(|e| {
                                    let bc = match e.event_type.as_str() {
                                        "login_success" => "badge badge-success",
                                        s if s.contains("failure") || s.contains("locked") => "badge badge-danger",
                                        s if s.contains("mfa") => "badge badge-warning",
                                        _ => "badge badge-muted",
                                    };
                                    view! {
                                        <tr>
                                            <td class="mono-sm">{api::relative_time(e.timestamp)}</td>
                                            <td><span class=bc>{e.event_type.clone()}</span></td>
                                            <td class="text-muted">{e.actor.clone()}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any()
            }}
        </div>
    }
}
