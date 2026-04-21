use leptos::prelude::*;
use crate::api::{self, AuditEntry, AuditFilters};
use crate::auth::AuthContext;
use crate::app::{ToastCtx, ToastKind, show_toast};

#[component]
pub fn AuditLogView() -> impl IntoView {
    let auth   = expect_context::<AuthContext>();
    let toasts = expect_context::<ToastCtx>();

    let (entries, set_entries)       = signal(Vec::<AuditEntry>::new());
    let (loading, set_loading)       = signal(true);
    let (search, set_search)         = signal(String::new());
    let (f_event, set_f_event)       = signal(String::new());
    let (f_actor, set_f_actor)       = signal(String::new());
    let (expanded_idx, set_expanded) = signal(Option::<usize>::None);

    let fetch = {
        let st = toasts.set_toasts;
        move || {
            set_loading.set(true);
            let tok     = auth.token.get_untracked();
            let filters = AuditFilters {
                event_type: { let v = f_event.get_untracked(); if v.is_empty() { None } else { Some(v) } },
                actor_id:   { let v = f_actor.get_untracked(); if v.is_empty() { None } else { Some(v) } },
                limit: Some(200),
                ..Default::default()
            };
            wasm_bindgen_futures::spawn_local(async move {
                match api::fetch_audit_log_filtered(&tok, &filters).await {
                    Ok(mut list) => { list.reverse(); set_entries.set(list); set_loading.set(false); }
                    Err(e)       => { show_toast(st, ToastKind::Error, e.to_string()); set_loading.set(false); }
                }
            });
        }
    };
    fetch();

    let filtered = Memo::new(move |_| {
        let f = search.get().to_lowercase();
        if f.is_empty() { return entries.get(); }
        entries.get().into_iter().filter(|e| {
            e.event_type.to_lowercase().contains(&f)
                || e.actor.to_lowercase().contains(&f)
                || e.detail.to_lowercase().contains(&f)
        }).collect()
    });

    view! {
        <div class="page-header">
            <div class="page-header-text">
                <div class="page-title">"Audit Log"</div>
                <div class="page-subtitle">"Security events and administrative actions"</div>
            </div>
            <div class="page-actions">
                <button class="btn" on:click=move |_| fetch()>"↻ Refresh"</button>
            </div>
        </div>

        <div class="audit-layout">
            // ── Filter panel ──
            <div class="filter-panel">
                <h3>"Filters"</h3>
                <div class="form-group">
                    <label>"Event type"</label>
                    <select on:change=move |ev| set_f_event.set(event_target_value(&ev))>
                        <option value="">"All events"</option>
                        <option value="login_success">"login_success"</option>
                        <option value="login_failure">"login_failure"</option>
                        <option value="account_locked">"account_locked"</option>
                        <option value="mfa_failure">"mfa_failure"</option>
                        <option value="mfa_enabled">"mfa_enabled"</option>
                        <option value="mfa_disabled">"mfa_disabled"</option>
                        <option value="passkey_registered">"passkey_registered"</option>
                        <option value="tenant_created">"tenant_created"</option>
                        <option value="tenant_deleted">"tenant_deleted"</option>
                        <option value="user_invited">"user_invited"</option>
                        <option value="hook_executed">"hook_executed"</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>"Actor ID"</label>
                    <input type="text" placeholder="user UUID"
                        prop:value=f_actor
                        on:input=move |ev| set_f_actor.set(event_target_value(&ev))/>
                </div>
                <button class="btn btn-primary" style="width:100%; justify-content:center;"
                    on:click=move |_| fetch()>
                    "Apply Filters"
                </button>
                <div class="form-group" style="margin-top:12px;">
                    <label>"Search results"</label>
                    <input type="text" placeholder="Filter visible rows…"
                        prop:value=search
                        on:input=move |ev| set_search.set(event_target_value(&ev))/>
                </div>
                {move || {
                    let total = entries.get().len();
                    let shown = filtered.get().len();
                    view! {
                        <div class="text-muted" style="font-size:11px; margin-top:8px;">
                            {shown}" of "{total}" events"
                        </div>
                    }
                }}
            </div>

            // ── Events table ──
            <div>
                {move || if loading.get() {
                    view! {
                        <div class="table-wrap">
                            <table>
                                <thead><tr><th>"Time"</th><th>"Event"</th><th>"Actor"</th><th>"Detail"</th></tr></thead>
                                <tbody>
                                    {(0..5).map(|_| view! {
                                        <tr>
                                            {(0..4).map(|_| view! { <td><div class="skeleton skeleton-line w-75"></div></td> }).collect_view()}
                                        </tr>
                                    }).collect_view()}
                                </tbody>
                            </table>
                        </div>
                    }.into_any()
                } else if filtered.get().is_empty() {
                    view! {
                        <div class="empty-state">
                            <div class="empty-icon">"📋"</div>
                            <h3>"No events found"</h3>
                            <p>"Try adjusting your filters."</p>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="table-wrap">
                            <table>
                                <thead><tr>
                                    <th>"Time"</th>
                                    <th>"Event"</th>
                                    <th>"Actor"</th>
                                    <th>"Detail"</th>
                                </tr></thead>
                                <tbody>
                                    {move || {
                                        filtered.get().into_iter().enumerate().map(|(idx, e)| {
                                            let badge_class = match e.event_type.as_str() {
                                                "login_success" | "mfa_enabled" | "passkey_registered" => "badge badge-success",
                                                s if s.contains("failure") || s.contains("locked") => "badge badge-danger",
                                                s if s.contains("mfa") => "badge badge-warning",
                                                s if s.contains("tenant") || s.contains("hook") => "badge badge-info",
                                                _ => "badge badge-muted",
                                            };
                                            let detail_short = if e.detail.len() > 60 {
                                                format!("{}…", &e.detail[..60])
                                            } else {
                                                e.detail.clone()
                                            };
                                            let is_expanded = move || expanded_idx.get() == Some(idx);
                                            view! {
                                                <tr style="cursor:pointer;" on:click=move |_| {
                                                    set_expanded.update(|v| {
                                                        *v = if *v == Some(idx) { None } else { Some(idx) };
                                                    });
                                                }>
                                                    <td class="mono-sm" title=api::format_timestamp(e.timestamp)>
                                                        {api::relative_time(e.timestamp)}
                                                    </td>
                                                    <td><span class=badge_class>{e.event_type.clone()}</span></td>
                                                    <td class="text-muted">{e.actor.clone()}</td>
                                                    <td class="text-muted">
                                                        {move || if is_expanded() {
                                                            view! { <pre class="mono-sm" style="white-space:pre-wrap;">{e.detail.clone()}</pre> }.into_any()
                                                        } else {
                                                            view! { <span>{detail_short.clone()}</span> }.into_any()
                                                        }}
                                                    </td>
                                                </tr>
                                            }
                                        }).collect_view()
                                    }}
                                </tbody>
                            </table>
                        </div>
                    }.into_any()
                }}
            </div>
        </div>
    }
}


